"""基于 LangChain v1、但仍受 TunnelMinion 策略控制的只读 Agent。"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Callable
from datetime import UTC, datetime
from enum import StrEnum
from ipaddress import IPv6Address, ip_address
from time import perf_counter
from typing import Any, Literal, Protocol, cast

from langchain.agents import create_agent  # pyright: ignore[reportUnknownVariableType]
from langchain.agents.middleware import (  # pyright: ignore[reportUnknownVariableType]
    AgentState,
    ModelCallLimitMiddleware,
    ToolCallLimitMiddleware,
    after_model,
)
from langchain_core.messages import AIMessage, BaseMessage, HumanMessage, ToolMessage
from langchain_core.tools import StructuredTool
from pydantic import BaseModel, ConfigDict, Field, JsonValue

from tunnelminion.agent.context_contracts import (
    FailureRecord,
    HistoryContext,
    RedactedContextRecord,
)
from tunnelminion.agent.langchain_model import ModelRunMetrics, TunnelMinionChatModel
from tunnelminion.agent.policy import evaluate_request_policy
from tunnelminion.agent.prompts import READONLY_AGENT_PROMPT
from tunnelminion.agent.remote import AgentRemoteToolPreparer, RemoteToolExecutor
from tunnelminion.agent.service_observation import compute_observed_service_id
from tunnelminion.agent.task_progress import TaskProgress
from tunnelminion.coordinator.contracts import ServiceProtocol
from tunnelminion.domain.delegation import DELEGATE_TOOL_NAME
from tunnelminion.domain.identifiers import NodeId, ServiceId
from tunnelminion.domain.tools import Platform
from tunnelminion.incident.contracts import EvidenceExecution
from tunnelminion.incident.skills import InvestigationTopology, available_investigation_skills
from tunnelminion.memory.contracts import LongTermMemory
from tunnelminion.model.contracts import CancellationToken
from tunnelminion.platforms.windows.models import Availability, CollectionResult, NetworkListener
from tunnelminion.tools.contracts import (
    ToolCallContext,
    ToolCancellationToken,
    ToolExecutionRequest,
    ToolExecutionResult,
    ToolExecutionStatus,
)
from tunnelminion.tools.registry import RegisteredTool, ToolRegistry


class _AgentGraph(Protocol):
    """隔离 LangChain 当前尚未完全标注的图返回类型。"""

    async def ainvoke(self, value: dict[str, object]) -> dict[str, Any]:
        """运行一次 Agent 图。"""
        ...


class AgentToolExecutor(Protocol):
    """Agent 可调用的本地或远端结构化执行边界。"""

    async def execute(
        self,
        request: ToolExecutionRequest,
        cancellation: ToolCancellationToken | None = None,
    ) -> ToolExecutionResult: ...


class AgentStopReason(StrEnum):
    """用户可理解且可持久化的 Agent 停止原因。"""

    COMPLETED = "completed"
    MODEL_LIMIT = "model-limit"
    TOOL_LIMIT = "tool-limit"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"


class AgentRunLimits(BaseModel):
    """每个 run 必须具备的硬预算。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    max_model_rounds: int = Field(default=8, ge=1, le=64)
    max_tool_calls: int = Field(default=12, ge=1, le=256)
    timeout_seconds: float = Field(default=120, ge=0.01, le=3600)


class AgentUsage(BaseModel):
    """Provider 可获得的模型使用量；未知成本不做猜测。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    input_tokens: int = Field(ge=0)
    output_tokens: int = Field(ge=0)
    total_tokens: int = Field(ge=0)
    estimated_cost: None = None


class AgentToolEvent(BaseModel):
    """可安全流向本机面板的工具公开状态。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    target_node_id: str
    tool_name: str
    status: str
    elapsed_ms: float = Field(ge=0)
    tool_run_id: str | None = None


class EvidenceReference(BaseModel):
    """最终回答引用的一次真实工具执行。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    tool_run_id: str
    tool_name: str
    status: str


class ConfirmedFact(BaseModel):
    """必须带工具证据引用的已确认事实。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    statement: str
    evidence_refs: tuple[str, ...] = Field(min_length=1)


class EvidenceAnswer(BaseModel):
    """区分事实、模型推测、未知与停止原因的回答信封。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    summary: str
    confirmed_facts: tuple[ConfirmedFact, ...]
    inferences: tuple[str, ...]
    unknowns: tuple[str, ...]
    evidence: tuple[EvidenceReference, ...]
    stop_reason: AgentStopReason


class ServiceCheckTarget(BaseModel):
    """由当前服务清单解析的调查对象，不从模型正文或端口号猜身份。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    service_id: ServiceId
    node_id: NodeId
    display_name: str = Field(min_length=1, max_length=80)
    protocol: ServiceProtocol
    port: int = Field(ge=1, le=65535)
    application_kind: Literal["python", "docker", "model", "program"] | None = None


class AgentTurnResult(BaseModel):
    """一次本地只读 Agent 调用的最小公开结果。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    answer: str
    model_rounds: int = Field(ge=0)
    tool_calls: int = Field(ge=0)
    tool_run_ids: tuple[str, ...] = ()
    selected_tools: tuple[str, ...]
    stop_reason: AgentStopReason
    elapsed_ms: float = Field(ge=0)
    usage: AgentUsage
    limits: AgentRunLimits
    evidence_answer: EvidenceAnswer
    context_records: tuple[RedactedContextRecord, ...] = ()
    failures: tuple[FailureRecord, ...] = ()


class CheckedAgentTurnResult(AgentTurnResult):
    """内部与工作台保留核对状态，既有公开结果契约不增加字段。"""

    answer_checked: bool = Field(
        default=False, description="公开回答已核对事实边界，不代表所问的全部情况已验证"
    )
    answer_basis: Literal["checked", "inferred", "none"] = Field(
        default="checked",
        description=(
            "checked=程序已核对事实边界；"
            "inferred=模型依据本次检查记录的推断，未逐条核对；none=没有可显示的结论"
        ),
    )
    checked_service_id: ServiceId | None = None


class AgentCancellationToken:
    """由聊天 API 触发并传播到模型与工具的 run 取消信号。"""

    def __init__(self) -> None:
        self._event = asyncio.Event()

    def cancel(self) -> None:
        """请求停止当前 run。"""
        self._event.set()

    @property
    def cancelled(self) -> bool:
        """返回用户是否已经请求取消。"""
        return self._event.is_set()

    async def wait(self) -> None:
        """等待取消请求。"""
        await self._event.wait()


class TaskAgent(Protocol):
    """聊天检查与事件调查共用的任务执行接口。"""

    @property
    def supports_remote(self) -> bool: ...

    async def run(
        self,
        question: str,
        context: ToolCallContext,
        tool_names: tuple[str, ...],
        limits: AgentRunLimits | None = None,
        cancellation: AgentCancellationToken | None = None,
        tool_event_sink: Callable[[AgentToolEvent], None] | None = None,
        history_context: HistoryContext | None = None,
        memories: tuple[LongTermMemory, ...] = (),
        target: ServiceCheckTarget | None = None,
        progress: TaskProgress | None = None,
        progress_sink: Callable[[TaskProgress], None] | None = None,
    ) -> CheckedAgentTurnResult: ...


class LangChainReadOnlyAgent:
    """每个 run 动态注入允许工具，而不是持有固定全量工具集。"""

    def __init__(
        self,
        model: TunnelMinionChatModel,
        registry: ToolRegistry,
        runtime: AgentToolExecutor,
        platform: Platform,
        *,
        remote_tools: AgentRemoteToolPreparer | None = None,
    ) -> None:
        self._model = model
        self._registry = registry
        self._runtime = runtime
        self._platform = platform
        self._remote_tools = remote_tools

    @property
    def supports_remote(self) -> bool:
        """是否已接入每次运行重新校验的远端能力准备器。"""
        return self._remote_tools is not None or isinstance(self._runtime, RemoteToolExecutor)

    async def run(
        self,
        question: str,
        context: ToolCallContext,
        tool_names: tuple[str, ...],
        limits: AgentRunLimits | None = None,
        cancellation: AgentCancellationToken | None = None,
        tool_event_sink: Callable[[AgentToolEvent], None] | None = None,
        history_context: HistoryContext | None = None,
        memories: tuple[LongTermMemory, ...] = (),
        target: ServiceCheckTarget | None = None,
        progress: TaskProgress | None = None,
        progress_sink: Callable[[TaskProgress], None] | None = None,
    ) -> CheckedAgentTurnResult:
        """用本次显式选择的只读工具运行标准 Agent 循环。"""
        budget = limits or AgentRunLimits()
        started = perf_counter()
        policy = evaluate_request_policy(question)
        if policy is not None:
            return CheckedAgentTurnResult(
                answer=policy.answer,
                answer_checked=True,
                model_rounds=0,
                tool_calls=0,
                selected_tools=tool_names,
                stop_reason=AgentStopReason.COMPLETED,
                elapsed_ms=round((perf_counter() - started) * 1000, 2),
                usage=AgentUsage(input_tokens=0, output_tokens=0, total_tokens=0),
                limits=budget,
                evidence_answer=EvidenceAnswer(
                    summary=policy.answer,
                    confirmed_facts=(),
                    inferences=(),
                    unknowns=(),
                    evidence=(),
                    stop_reason=AgentStopReason.COMPLETED,
                ),
            )
        model_token = CancellationToken()
        tool_token = ToolCancellationToken()
        metrics = ModelRunMetrics()
        model = self._model.model_copy(
            update={
                "run_metrics": metrics,
                "provider": self._model.provider,
                "cancellation_token": model_token,
                "thread_id": context.thread_id,
                "run_id": context.run_id,
                "history_context": history_context,
                "memories": memories,
            }
        )
        evidence: list[EvidenceReference] = []
        results: list[tuple[ToolExecutionRequest, ToolExecutionResult]] = []
        saved_progress = progress or TaskProgress()

        def save_observation(request: ToolExecutionRequest, result: ToolExecutionResult) -> None:
            nonlocal saved_progress
            saved_progress = saved_progress.record(request, result, datetime.now(UTC))
            if progress_sink is not None:
                progress_sink(saved_progress)

        selected_tools = tool_names

        async def invoke() -> dict[str, Any]:
            nonlocal selected_tools
            active = self
            current_question = question
            target_platform = (
                self._platform.value
                if context.execution_node_id == context.caller_node_id
                else None
            )
            if context.execution_node_id != context.caller_node_id and not isinstance(
                self._runtime, RemoteToolExecutor
            ):
                if self._remote_tools is None:
                    raise ValueError("目标节点没有可用的远端只读能力准备器")
                prepared = await self._remote_tools.prepare(
                    context.execution_node_id, context, tool_names, tool_token
                )
                active = LangChainReadOnlyAgent(
                    model, prepared.registry, prepared.executor, self._platform
                )
                selected_tools = prepared.tool_names
                target_platform = prepared.node_summary.platform
                summary_request = ToolExecutionRequest(
                    context=context, tool_name="get_node_summary"
                )
                summary_result = ToolExecutionResult(
                    tool_run_id=prepared.summary_tool_run_id,
                    status=ToolExecutionStatus.SUCCESS,
                    output=prepared.node_summary.model_dump(mode="json"),
                )
                save_observation(summary_request, summary_result)
                evidence.append(
                    EvidenceReference(
                        tool_run_id=str(summary_result.tool_run_id),
                        tool_name="get_node_summary",
                        status=summary_result.status.value,
                    )
                )
                if tool_event_sink is not None:
                    tool_event_sink(
                        AgentToolEvent(
                            target_node_id=str(context.execution_node_id),
                            tool_name="get_node_summary",
                            status=summary_result.status.value,
                            elapsed_ms=round((perf_counter() - started) * 1000, 2),
                            tool_run_id=str(summary_result.tool_run_id),
                        )
                    )
                current_question = prepared.augment_question(question)
            tools = tuple(
                active._build_tool(
                    entry, context, tool_token, evidence, tool_event_sink, results, save_observation
                )
                for entry in active._validate_tools(selected_tools)
            ) + self._skill_tools(context, selected_tools, target_platform)
            delegate = active._delegate_tool(selected_tools)
            if active is self and delegate is not None:
                # 本机对话总能把问题交给别的电脑；委派方自己的工具集里没有这个工具，不会转手。
                tools += (
                    active._build_tool(
                        delegate,
                        context,
                        tool_token,
                        evidence,
                        tool_event_sink,
                        results,
                        save_observation,
                    ),
                )
            historical_messages = saved_progress.messages(context, selected_tools)
            requires_current_check = bool(
                progress
                and progress.current_listener_check_required
                and progress.messages(context, selected_tools)
            )

            @after_model(can_jump_to=["model"])
            def verify_current_check(state: AgentState, runtime: object) -> dict[str, Any] | None:
                """续办的服务检查不能用历史观察或技能说明代替本轮工具执行。"""
                del runtime
                if (
                    target is None
                    or not requires_current_check
                    or "list_network_listeners" not in selected_tools
                    or cast(AIMessage, state["messages"][-1]).tool_calls
                    or any(request.tool_name == "list_network_listeners" for request, _ in results)
                ):
                    return None
                return {
                    "messages": [
                        HumanMessage(
                            "任务尚缺少所选入口的本轮监听检查。请使用本次允许的检查工具重新核对；"
                            "技能说明和历史记录不能代替这次检查。若检查失败，保留未知并说明原因。"
                        )
                    ],
                    "jump_to": "model",
                }

            factory = cast(Callable[..., _AgentGraph], create_agent)
            graph = factory(
                model=model,
                tools=tools,
                system_prompt=READONLY_AGENT_PROMPT.template,
                middleware=[
                    # after_model 按逆序运行，必须先计入预算再决定是否继续。
                    verify_current_check,
                    ModelCallLimitMiddleware(
                        run_limit=budget.max_model_rounds, exit_behavior="end"
                    ),
                    ToolCallLimitMiddleware(
                        run_limit=budget.max_tool_calls - len(evidence), exit_behavior="end"
                    ),
                ],
                name="tunnelminion-read-only",
            )
            input_messages: list[dict[str, object]] = []
            if target is not None:
                location = "这台电脑" if target.node_id == context.caller_node_id else "另一台电脑"
                input_messages.append(
                    {
                        "role": "user",
                        "content": (
                            f"用户选择了{location}上的“{target.display_name}”（类型："
                            f"{target.application_kind or '未知'}；{target.protocol.value.upper()} "
                            f"{target.port}）。名称来自当前程序清单，连接事实必须用工具核对。"
                        ),
                    }
                )
            input_messages.extend(historical_messages)
            input_messages.append({"role": "user", "content": current_question})
            return await graph.ainvoke({"messages": input_messages})

        graph_task = asyncio.create_task(invoke())
        cancel_task = asyncio.create_task(cancellation.wait()) if cancellation is not None else None
        waiters: set[asyncio.Task[Any]] = {graph_task}
        if cancel_task is not None:
            waiters.add(cancel_task)
        done, _ = await asyncio.wait(
            waiters,
            timeout=budget.timeout_seconds,
            return_when=asyncio.FIRST_COMPLETED,
        )
        if cancel_task is not None and cancel_task in done:
            return await self._stop(
                graph_task,
                cancel_task,
                model_token,
                tool_token,
                metrics,
                evidence,
                selected_tools,
                budget,
                started,
                AgentStopReason.CANCELLED,
            )
        if graph_task not in done:
            return await self._stop(
                graph_task,
                cancel_task,
                model_token,
                tool_token,
                metrics,
                evidence,
                selected_tools,
                budget,
                started,
                AgentStopReason.TIMEOUT,
            )
        if cancel_task is not None:
            cancel_task.cancel()
            await asyncio.gather(cancel_task, return_exceptions=True)
        state = await graph_task
        messages = cast(list[BaseMessage], state["messages"])
        answer = self._answer(messages)
        stop_reason = self._limit_reason(answer)
        checked_answer = (
            self._connection_evidence(target, results, answer, evidence)
            if stop_reason is AgentStopReason.COMPLETED and target is not None
            else None
        )
        if checked_answer is not None:
            answer = checked_answer.summary
        if stop_reason is AgentStopReason.COMPLETED:
            answer = self._attach_evidence_index(answer, evidence)
        executed_ids = [item.tool_run_id for item in evidence]
        return CheckedAgentTurnResult(
            answer=self._bounded_answer(stop_reason, answer, executed_ids),
            answer_checked=target is not None or stop_reason is not AgentStopReason.COMPLETED,
            checked_service_id=target.service_id
            if checked_answer is not None and target is not None
            else None,
            model_rounds=metrics.model_rounds,
            tool_calls=len(executed_ids),
            tool_run_ids=tuple(executed_ids),
            selected_tools=selected_tools,
            stop_reason=stop_reason,
            elapsed_ms=round((perf_counter() - started) * 1000, 2),
            usage=self._usage(metrics),
            limits=budget,
            evidence_answer=checked_answer or self._evidence_answer(stop_reason, answer, evidence),
            context_records=tuple(metrics.context_records),
            failures=tuple(metrics.failures),
        )

    def _validate_tools(self, tool_names: tuple[str, ...]) -> tuple[RegisteredTool, ...]:
        if not tool_names:
            raise ValueError("每个 Agent run 必须显式选择至少一个工具")
        if len(tool_names) != len(set(tool_names)):
            raise ValueError("Agent 工具集合不得包含重复名称")
        allowed = {item.name for item in self._registry.model_tools(self._platform)}
        selected: list[RegisteredTool] = []
        for name in tool_names:
            entry = self._registry.lookup(name)
            if entry is None or name not in allowed:
                raise ValueError(f"工具 {name} 未注册或不允许向模型暴露")
            selected.append(entry)
        return tuple(selected)

    def _delegate_tool(self, tool_names: tuple[str, ...]) -> RegisteredTool | None:
        """配置了可委派的对端时注册了委派工具；已经显式选中的不重复加入。"""
        if DELEGATE_TOOL_NAME in tool_names:
            return None
        entry = self._registry.lookup(DELEGATE_TOOL_NAME)
        allowed = {item.name for item in self._registry.model_tools(self._platform)}
        return entry if entry is not None and DELEGATE_TOOL_NAME in allowed else None

    def _skill_tools(
        self,
        context: ToolCallContext,
        tool_names: tuple[str, ...],
        target_platform: str | None,
    ) -> tuple[StructuredTool, ...]:
        remote = context.execution_node_id != context.caller_node_id
        skills = tuple(
            skill
            for skill in available_investigation_skills(
                topology=InvestigationTopology.REMOTE if remote else InvestigationTopology.LOCAL,
                request_platform=self._platform,
                target_platform=target_platform,
            )
            if any(step.tool_name in tool_names for step in skill.steps)
        )
        if not skills:
            return ()
        catalogue = tuple(
            {
                "skill_id": skill.skill_id,
                "version": skill.version,
                "title": skill.title,
                "description": skill.description,
            }
            for skill in skills
        )

        async def read_skill(skill_id: str, version: str) -> str:
            skill = next(
                (item for item in skills if item.skill_id == skill_id and item.version == version),
                None,
            )
            if skill is None:
                return json.dumps({"available": False, "reason": "技能或版本不在本次目录中"})
            return json.dumps(
                {
                    "kind": "investigation-method-not-evidence",
                    "grants_permissions": False,
                    "skill": skill.model_dump(mode="json"),
                    "missing_checks": [
                        {"tool_name": step.tool_name, "execution": step.execution.value}
                        for step in skill.steps
                        if step.tool_name not in tool_names
                        or (remote and step.execution is EvidenceExecution.REQUESTER)
                    ],
                },
                ensure_ascii=False,
            )

        return (
            StructuredTool.from_function(
                coroutine=read_skill,
                name="read_investigation_skill",
                description="按需查阅调查方法；不执行检查、不生成事实证据、不扩大权限。目录："
                + json.dumps(catalogue, ensure_ascii=False),
            ),
        )

    def _build_tool(
        self,
        entry: RegisteredTool,
        context: ToolCallContext,
        cancellation: ToolCancellationToken,
        evidence: list[EvidenceReference],
        event_sink: Callable[[AgentToolEvent], None] | None,
        results: list[tuple[ToolExecutionRequest, ToolExecutionResult]],
        observation_sink: Callable[[ToolExecutionRequest, ToolExecutionResult], None],
    ) -> StructuredTool:
        async def execute(**arguments: Any) -> str:
            started = perf_counter()
            if event_sink is not None:
                event_sink(
                    AgentToolEvent(
                        target_node_id=str(context.execution_node_id),
                        tool_name=entry.definition.name,
                        status="started",
                        elapsed_ms=0,
                    )
                )
            request = ToolExecutionRequest(
                context=context,
                tool_name=entry.definition.name,
                arguments=cast(dict[str, JsonValue], arguments),
            )
            result = await self._runtime.execute(request, cancellation)
            observation_sink(request, result)
            results.append((request, result))
            evidence.append(
                EvidenceReference(
                    tool_run_id=str(result.tool_run_id),
                    tool_name=entry.definition.name,
                    status=result.status.value,
                )
            )
            if event_sink is not None:
                event_sink(
                    AgentToolEvent(
                        target_node_id=str(context.execution_node_id),
                        tool_name=entry.definition.name,
                        status=result.status.value,
                        elapsed_ms=round((perf_counter() - started) * 1000, 2),
                        tool_run_id=str(result.tool_run_id),
                    )
                )
            envelope = {
                "trust": "untrusted-tool-data",
                "result": result.model_dump(mode="json"),
            }
            return json.dumps(envelope, ensure_ascii=False, separators=(",", ":"))

        return StructuredTool.from_function(
            coroutine=execute,
            name=entry.definition.name,
            description=entry.definition.description,
            args_schema=cast(Any, entry.definition.input_schema),
        )

    async def _stop(
        self,
        graph_task: asyncio.Task[dict[str, Any]],
        cancel_task: asyncio.Task[None] | None,
        model_token: CancellationToken,
        tool_token: ToolCancellationToken,
        metrics: ModelRunMetrics,
        evidence: list[EvidenceReference],
        tool_names: tuple[str, ...],
        limits: AgentRunLimits,
        started: float,
        reason: AgentStopReason,
    ) -> CheckedAgentTurnResult:
        model_token.cancel()
        tool_token.cancel()
        graph_task.cancel()
        await asyncio.gather(graph_task, return_exceptions=True)
        if cancel_task is not None:
            cancel_task.cancel()
            await asyncio.gather(cancel_task, return_exceptions=True)
        executed_ids = [item.tool_run_id for item in evidence]
        answer = self._bounded_answer(reason, "", executed_ids)
        return CheckedAgentTurnResult(
            answer=answer,
            answer_checked=True,
            model_rounds=metrics.model_rounds,
            tool_calls=len(executed_ids),
            tool_run_ids=tuple(executed_ids),
            selected_tools=tool_names,
            stop_reason=reason,
            elapsed_ms=round((perf_counter() - started) * 1000, 2),
            usage=self._usage(metrics),
            limits=limits,
            evidence_answer=self._evidence_answer(reason, answer, evidence),
            context_records=tuple(metrics.context_records),
            failures=tuple(metrics.failures),
        )

    @staticmethod
    def _limit_reason(answer: str) -> AgentStopReason:
        if answer.startswith("Model call limits exceeded:"):
            return AgentStopReason.MODEL_LIMIT
        if answer.startswith("Tool call limit reached:"):
            return AgentStopReason.TOOL_LIMIT
        return AgentStopReason.COMPLETED

    @staticmethod
    def _bounded_answer(reason: AgentStopReason, answer: str, tool_run_ids: list[str]) -> str:
        if reason is AgentStopReason.COMPLETED:
            return answer
        labels = {
            AgentStopReason.MODEL_LIMIT: "已达到本次调查次数上限，暂时没能查完。",
            AgentStopReason.TOOL_LIMIT: "已达到本次检查次数上限，暂时没能查完。",
            AgentStopReason.TIMEOUT: "这次检查等待太久，已停止，还没有完整结论。",
            AgentStopReason.CANCELLED: "已按你的要求停止检查。",
        }
        evidence = (
            f"已保留 {len(tool_run_ids)} 项检查记录，可展开查看。"
            if tool_run_ids
            else "还没有取得工具检查记录。"
        )
        return f"{labels[reason]}{evidence}未查明的部分仍不能确认。"

    @staticmethod
    def _usage(metrics: ModelRunMetrics) -> AgentUsage:
        return AgentUsage(
            input_tokens=metrics.input_tokens,
            output_tokens=metrics.output_tokens,
            total_tokens=metrics.total_tokens,
        )

    @staticmethod
    def _connection_evidence(
        target: ServiceCheckTarget,
        results: list[tuple[ToolExecutionRequest, ToolExecutionResult]],
        draft: str,
        evidence: list[EvidenceReference],
    ) -> EvidenceAnswer:
        """只核对最新完整监听中的同一节点和入口，模型草稿不参与事实判定。"""
        facts: list[ConfirmedFact] = []
        unknowns = (
            "网页是否正常、另一台电脑能否实际打开，还没有验证。",
            "这次只核对了所选连接入口，程序的其他状态和其他入口还不能确认。",
        )
        for request, result in reversed(results):
            if request.tool_name != "list_network_listeners":
                continue
            if (
                request.context.execution_node_id != target.node_id
                or result.status is not ToolExecutionStatus.SUCCESS
                or result.truncated
            ):
                break
            try:
                collection = CollectionResult.model_validate(result.output)
                if collection.availability is not Availability.AVAILABLE:
                    break
                listeners = [NetworkListener.model_validate(item) for item in collection.items]
                matching = [
                    item
                    for item in listeners
                    if compute_observed_service_id(
                        target.node_id, ServiceProtocol(item.protocol), item.address, item.port
                    )
                    == target.service_id
                ]
                if not matching:
                    break
                addresses = [ip_address(item.address) for item in matching]
                local_only = all(
                    (address.ipv4_mapped or address).is_loopback
                    if isinstance(address, IPv6Address)
                    else address.is_loopback
                    for address in addresses
                )
            except ValueError:
                break
            if matching[0].protocol == "udp":
                statement = (
                    f"已记录你选中的“{target.display_name}”的消息传送入口；"
                    "它还不是已验证的网页入口。"
                )
            elif local_only:
                statement = (
                    f"你选中的“{target.display_name}”这个连接入口，目前只允许这台电脑自己连接，"
                    "另一台电脑不能直接使用这个入口。"
                )
            else:
                statement = (
                    f"你选中的“{target.display_name}”这个连接入口不只限这台电脑自身；"
                    "能否从另一台电脑连上，还没有验证。"
                )
            facts.append(
                ConfirmedFact(statement=statement, evidence_refs=(str(result.tool_run_id),))
            )
            break
        summary = (
            facts[0].statement if facts else "这次还没有取得能核对所选程序连接入口的完整记录。"
        )
        return EvidenceAnswer(
            summary="\n\n".join((summary, *unknowns)),
            confirmed_facts=tuple(facts),
            inferences=(draft,) if draft else (),
            unknowns=unknowns,
            evidence=tuple(evidence),
            stop_reason=AgentStopReason.COMPLETED,
        )

    @staticmethod
    def _attach_evidence_index(answer: str, evidence: list[EvidenceReference]) -> str:
        """由确定性代码附加精确 ID，避免模型转抄证据编号时出错。"""
        if not evidence:
            return answer
        lines = [f"- {item.tool_name}: {item.tool_run_id} ({item.status})" for item in evidence]
        return f"{answer}\n\n证据索引（程序生成）：\n" + "\n".join(lines)

    @staticmethod
    def _evidence_answer(
        reason: AgentStopReason,
        answer: str,
        evidence: list[EvidenceReference],
    ) -> EvidenceAnswer:
        facts = tuple(
            ConfirmedFact(
                statement=f"工具 {item.tool_name} 已以 {item.status} 状态结束。",
                evidence_refs=(item.tool_run_id,),
            )
            for item in evidence
        )
        unknowns: list[str] = []
        if reason is not AgentStopReason.COMPLETED:
            unknowns.append("运行未正常完成，未覆盖的问题无法确认。")
        if any(item.status != "success" for item in evidence):
            unknowns.append("至少一个必要工具未成功，相关实时状态无法确认。")
        if not evidence:
            unknowns.append("本次没有工具证据，无法确认实时系统状态。")
        return EvidenceAnswer(
            summary=answer,
            confirmed_facts=facts,
            inferences=(answer,) if answer else (),
            unknowns=tuple(unknowns),
            evidence=tuple(evidence),
            stop_reason=reason,
        )

    @staticmethod
    def _answer(messages: list[BaseMessage]) -> str:
        for message in reversed(messages):
            if isinstance(message, AIMessage):
                if isinstance(message.content, str):
                    return message.content
                return json.dumps(message.content, ensure_ascii=False)
        raise ValueError("Agent 没有返回回答")

    @staticmethod
    def _tool_run_ids(messages: list[BaseMessage]) -> tuple[str, ...]:
        values: list[str] = []
        for message in messages:
            if not isinstance(message, ToolMessage) or not isinstance(message.content, str):
                continue
            try:
                payload = cast(dict[str, Any], json.loads(message.content))
                result = cast(dict[str, Any], payload["result"])
                values.append(str(result["tool_run_id"]))
            except (KeyError, TypeError, ValueError, json.JSONDecodeError):
                continue
        return tuple(values)
