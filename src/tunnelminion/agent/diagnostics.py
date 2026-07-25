"""跨节点服务采集、A 侧探测和证据报告工作流。"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from time import perf_counter
from typing import Protocol

from pydantic import BaseModel, ConfigDict, JsonValue

from tunnelminion.agent.context_contracts import (
    ContextContentKind,
    ContextFact,
    ContextRequest,
    ContextTaskType,
    ContextTrust,
    FactSource,
)
from tunnelminion.agent.context_runtime import ContextModelRuntime, make_context_reference
from tunnelminion.agent.planning import CandidateOperationPlanner, CandidatePlanIntent
from tunnelminion.agent.prompts import CROSS_NODE_DIAGNOSTIC_PROMPT
from tunnelminion.agent.remote import RemotePreparationError
from tunnelminion.agent.runtime import AgentToolExecutor
from tunnelminion.agent.services import (
    CrossNodeReachability,
    CrossNodeReachabilityAnalyzer,
    CrossNodeServiceDiagnostic,
    RemoteServiceInventory,
    RemoteServiceInventoryBuilder,
    ToolObservation,
)
from tunnelminion.domain.identifiers import NodeId, ToolRunId
from tunnelminion.model.contracts import (
    CancellationToken,
    ModelMessage,
    ModelProvider,
    ModelUsage,
    ProviderError,
)
from tunnelminion.operation.contracts import (
    OperationPlan,
    PlanFailureAttribution,
    PlanGenerationTrace,
)
from tunnelminion.tools.contracts import (
    ToolCallContext,
    ToolCancellationToken,
    ToolExecutionRequest,
    ToolExecutionResult,
    ToolExecutionStatus,
)


class PreparedRemoteToolSet(Protocol):
    """诊断工作流实际需要的预检结果子集。"""

    @property
    def summary_tool_run_id(self) -> ToolRunId: ...

    @property
    def executor(self) -> AgentToolExecutor: ...

    @property
    def tool_names(self) -> tuple[str, ...]: ...


class RemoteToolPreparer(Protocol):
    """隔离真实网关和确定性测试的远端预检边界。"""

    async def prepare(
        self,
        context: ToolCallContext,
        requested_tools: tuple[str, ...],
        cancellation: ToolCancellationToken | None = None,
    ) -> PreparedRemoteToolSet: ...


class CrossNodeDiagnosticReport(BaseModel):
    """可供 Agent 解释、但本身由确定性代码生成的证据报告。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    local_node_id: NodeId
    remote_node_id: NodeId
    target_host: str
    node_summary_tool_run_id: ToolRunId
    inventory: RemoteServiceInventory
    diagnostics: tuple[CrossNodeServiceDiagnostic, ...]

    def untrusted_context(self) -> str:
        """以明确不可信数据标签序列化，不包含认证材料。"""
        return json.dumps(
            {"trust": "untrusted-tool-data", "report": self.model_dump(mode="json")},
            ensure_ascii=False,
            separators=(",", ":"),
        )

    def evidence_answer(self, port: int | None = None) -> str:
        """生成不依赖模型的保底答案，避免在关键证据缺失时编造。"""
        selected = tuple(
            item for item in self.diagnostics if port is None or item.service.port == port
        )
        if not selected:
            return "没有获得匹配服务的监听证据，当前无法确认。"
        lines: list[str] = []
        for item in selected:
            refs = "、".join(str(evidence.tool_run_id) for evidence in item.evidence)
            lines.append(
                f"{item.service.protocol.upper()} {item.service.address}:{item.service.port}："
                f"{item.reachability.value}；{item.explanation}。证据：{refs}"
            )
        if any(item.reachability is CrossNodeReachability.LOCAL_ONLY for item in selected):
            lines.append("这是只读诊断；系统没有开放端口、修改监听地址或重启服务。")
        return "\n".join(lines)


class CrossNodeAgentAnswer(BaseModel):
    """模型解释与确定性证据结论分离的最终回答。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    answer: str
    model_explanation: str | None = None
    model_error_code: str | None = None
    remote_error_code: str | None = None
    report: CrossNodeDiagnosticReport | None = None
    elapsed_ms: float = 0.0
    model_usage: ModelUsage | None = None
    candidate_plan: OperationPlan | None = None
    plan_trace: PlanGenerationTrace | None = None
    plan_error_code: str | None = None
    plan_failure_attribution: PlanFailureAttribution | None = None


class CrossNodeDiagnosticAgent:
    """先运行确定性诊断，再让模型解释，不允许模型新增系统动作。"""

    def __init__(
        self,
        workflow: CrossNodeDiagnosticWorkflow,
        provider: ModelProvider,
        planner: CandidateOperationPlanner | None = None,
    ) -> None:
        self._workflow = workflow
        self._provider = provider
        self._planner = planner or CandidateOperationPlanner(provider)

    async def answer(
        self,
        question: str,
        context: ToolCallContext,
        target_host: str,
        *,
        port: int | None = None,
        plan_intent: CandidatePlanIntent | None = None,
        tool_cancellation: ToolCancellationToken | None = None,
        model_cancellation: CancellationToken | None = None,
    ) -> CrossNodeAgentAnswer:
        """回答服务发现或单端口故障问题，并始终附加程序生成的证据结论。"""
        started_at = perf_counter()
        try:
            report = await self._workflow.inspect(
                context,
                target_host,
                tool_cancellation,
                target_port=port,
            )
        except RemotePreparationError as exc:
            return CrossNodeAgentAnswer(
                answer=(
                    f"远端节点或工具网关不可用（{exc.code.value}），无法取得 B 的当前端口、"
                    "进程或 Docker 证据；因此不能确认 B 当前运行的服务。"
                ),
                remote_error_code=exc.code.value,
                elapsed_ms=(perf_counter() - started_at) * 1000,
            )
        fallback = report.evidence_answer(port)
        report_context = report.untrusted_context()
        request = ContextRequest(
            task_type=ContextTaskType.CROSS_NODE_DIAGNOSTIC,
            current_intent=question,
            thread_id=context.thread_id,
            run_id=context.run_id,
            prompt_id=CROSS_NODE_DIAGNOSTIC_PROMPT.prompt_id,
            prompt_version=CROSS_NODE_DIAGNOSTIC_PROMPT.version,
            messages=(
                ModelMessage(
                    role="system",
                    content=CROSS_NODE_DIAGNOSTIC_PROMPT.template,
                ),
                ModelMessage(
                    role="user",
                    content=f"用户问题：{question}\n诊断报告：{report_context}",
                ),
            ),
            evidence=(
                make_context_reference(
                    ContextContentKind.EVIDENCE,
                    f"diagnostic:{report.node_summary_tool_run_id}",
                    report_context,
                    ContextTrust.VERIFIED_EVIDENCE,
                ),
            ),
            facts=self._diagnostic_facts(report),
        )
        explanation: str | None = None
        model_error_code: str | None = None
        model_usage: ModelUsage | None = None
        if plan_intent is None:
            try:
                invocation = await ContextModelRuntime(
                    self._provider,
                    tool_schema_version="cross-node-diagnostic/v1",
                ).invoke(request, model_cancellation)
                response = invocation.response
                explanation = response.content.strip() if response.content else None
                model_usage = response.usage
            except ProviderError as exc:
                model_error_code = exc.code.value

        candidate_plan: OperationPlan | None = None
        plan_trace: PlanGenerationTrace | None = None
        plan_error_code: str | None = None
        plan_failure_attribution: PlanFailureAttribution | None = None
        if plan_intent is not None:
            generated = await self._planner.generate(
                question=question,
                report=report,
                context=context,
                intent=plan_intent,
                cancellation=model_cancellation,
            )
            candidate_plan = generated.plan
            if generated.plan is not None:
                plan_trace = generated.plan.generation_trace
            elif generated.failure is not None:
                plan_error_code = generated.failure.code
                plan_failure_attribution = generated.failure.attribution

        if explanation:
            answer = f"{explanation}\n\n确定性证据结论：\n{fallback}"
        elif model_error_code is not None:
            answer = f"模型解释不可用（{model_error_code}）。\n\n确定性证据结论：\n{fallback}"
        else:
            answer = fallback
        if candidate_plan is not None:
            answer += "\n\n已生成无权限的 L2 候选计划；仍需目标节点策略校验与本地授权。"
        elif plan_error_code is not None:
            answer += f"\n\n候选计划未生成（{plan_error_code}），只读诊断结果仍然有效。"
        return CrossNodeAgentAnswer(
            answer=answer,
            model_explanation=explanation,
            model_error_code=model_error_code,
            report=report,
            elapsed_ms=(perf_counter() - started_at) * 1000,
            model_usage=model_usage,
            candidate_plan=candidate_plan,
            plan_trace=plan_trace,
            plan_error_code=plan_error_code,
            plan_failure_attribution=plan_failure_attribution,
        )

    @staticmethod
    def _diagnostic_facts(
        report: CrossNodeDiagnosticReport,
    ) -> tuple[ContextFact, ...]:
        facts: list[ContextFact] = []
        for item in report.diagnostics:
            owner = item.service.container_name or item.service.process_name or item.service.address
            latest = (
                max(item.evidence, key=lambda value: value.observed_at) if item.evidence else None
            )
            facts.append(
                ContextFact(
                    key=f"service:{item.service.node_id}:{owner}:port",
                    value=str(item.service.port),
                    source=FactSource.REALTIME_EVIDENCE,
                    source_id=(
                        f"toolrun:{latest.tool_run_id}"
                        if latest is not None
                        else f"diagnostic:{report.node_summary_tool_run_id}"
                    ),
                    observed_at=latest.observed_at if latest is not None else None,
                )
            )
        return tuple(facts)


class CrossNodeDiagnosticWorkflow:
    """按固定顺序采集 B，再使用 A 的工具验证可达性。"""

    _REMOTE_TOOLS = (
        "list_network_listeners",
        "get_process_summary",
        "list_docker_services",
    )

    def __init__(
        self,
        remote: RemoteToolPreparer,
        local_executor: AgentToolExecutor,
        local_node_id: NodeId,
        *,
        max_probes: int = 32,
    ) -> None:
        if max_probes < 1:
            raise ValueError("跨节点探测预算必须至少为 1")
        self._remote = remote
        self._local = local_executor
        self._local_node_id = local_node_id
        self._max_probes = max_probes

    async def inspect(
        self,
        context: ToolCallContext,
        target_host: str,
        cancellation: ToolCancellationToken | None = None,
        *,
        target_port: int | None = None,
    ) -> CrossNodeDiagnosticReport:
        """完成远端能力预检、三类采集、A 侧 WireGuard 与 TCP 探测。"""
        if context.caller_node_id != self._local_node_id:
            raise ValueError("跨节点诊断 caller 必须是当前本地节点")
        prepared = await self._remote.prepare(context, self._REMOTE_TOOLS, cancellation)
        remote_observations: dict[str, ToolObservation] = {}
        for name in self._REMOTE_TOOLS:
            if name not in prepared.tool_names:
                remote_observations[name] = self._missing_observation(name)
                continue
            arguments: dict[str, JsonValue] = (
                {"limit": 200} if name == "get_process_summary" else {}
            )
            result = await prepared.executor.execute(
                ToolExecutionRequest(
                    context=context,
                    tool_name=name,
                    arguments=arguments,
                ),
                cancellation,
            )
            remote_observations[name] = self._observation(name, result)

        inventory = RemoteServiceInventoryBuilder().build(
            context.execution_node_id,
            remote_observations["list_network_listeners"],
            remote_observations["get_process_summary"],
            remote_observations["list_docker_services"],
        )
        local_context = context.model_copy(update={"execution_node_id": self._local_node_id})
        wireguard = await self._local.execute(
            ToolExecutionRequest(context=local_context, tool_name="get_wireguard_status"),
            cancellation,
        )
        probe_observations: list[ToolObservation] = []
        discovered_ports = tuple(
            dict.fromkeys(item.port for item in inventory.services if item.protocol == "tcp")
        )
        ports = (
            (target_port,)
            if target_port is not None and target_port in discovered_ports
            else ()
            if target_port is not None
            else discovered_ports[: self._max_probes]
        )
        for port in ports:
            result = await self._local.execute(
                ToolExecutionRequest(
                    context=local_context,
                    tool_name="probe_service_reachability",
                    arguments={"host": target_host, "port": port, "timeout_seconds": 2.0},
                ),
                cancellation,
            )
            probe_observations.append(self._observation("probe_service_reachability", result))
        diagnostics = CrossNodeReachabilityAnalyzer().analyze(
            inventory,
            target_host,
            self._observation("get_wireguard_status", wireguard),
            tuple(probe_observations),
            remote_node_observed=True,
        )
        return CrossNodeDiagnosticReport(
            local_node_id=self._local_node_id,
            remote_node_id=context.execution_node_id,
            target_host=target_host,
            node_summary_tool_run_id=prepared.summary_tool_run_id,
            inventory=inventory,
            diagnostics=diagnostics,
        )

    @staticmethod
    def _observation(name: str, result: ToolExecutionResult) -> ToolObservation:
        return ToolObservation(
            tool_name=name,
            tool_run_id=result.tool_run_id,
            observed_at=datetime.now(UTC),
            status=result.status,
            output=result.output,
        )

    @staticmethod
    def _missing_observation(name: str) -> ToolObservation:
        return ToolObservation(
            tool_name=name,
            tool_run_id=ToolRunId.new(),
            observed_at=datetime.now(UTC),
            status=ToolExecutionStatus.FAILED,
        )
