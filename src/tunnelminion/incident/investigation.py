"""单 Investigation Agent 的假设、只读工具、证据与停止循环。"""

from __future__ import annotations

import asyncio
import hashlib
import json
from collections.abc import Callable
from datetime import UTC, datetime
from ipaddress import ip_address
from typing import Protocol

from pydantic import BaseModel, ConfigDict, Field, JsonValue, ValidationError

from tunnelminion.agent.context_contracts import (
    ContextContentKind,
    ContextRequest,
    ContextTaskType,
    ContextTrust,
)
from tunnelminion.agent.context_runtime import (
    ContextInvocation,
    ContextModelRuntime,
    make_context_reference,
)
from tunnelminion.agent.prompts import INCIDENT_INVESTIGATION_PROMPT
from tunnelminion.domain.identifiers import RunId, ThreadId
from tunnelminion.domain.tools import Platform
from tunnelminion.incident.contracts import (
    EvidenceReference,
    HypothesisStatus,
    Incident,
    IncidentEventType,
    IncidentHypothesis,
    IncidentReport,
    IncidentStatus,
    InvestigationStopReason,
    PublicTraceEntry,
    SnapshotObjectKind,
    SnapshotSource,
)
from tunnelminion.incident.storage import SQLiteIncidentStore
from tunnelminion.memory.context import ContextBudgets, ToolResultContext
from tunnelminion.model.contracts import (
    CancellationToken,
    ModelMessage,
    ModelProvider,
    ProviderError,
    ProviderErrorCode,
    ToolCall,
)
from tunnelminion.model.contracts import (
    ToolDefinition as ModelToolDefinition,
)
from tunnelminion.tools.contracts import (
    ToolCallContext,
    ToolCancellationToken,
    ToolExecutionRequest,
    ToolExecutionResult,
    ToolExecutionStatus,
)
from tunnelminion.tools.registry import ToolRegistry

READ_ONLY_INVESTIGATION_TOOLS = (
    "get_node_summary",
    "get_wireguard_status",
    "list_network_listeners",
    "get_process_summary",
    "list_docker_services",
    "probe_service_reachability",
)

_LOCAL_EVIDENCE_PATHS = {
    IncidentEventType.SERVICE_ADDED: (
        "list_network_listeners",
        "get_process_summary",
    ),
    IncidentEventType.SERVICE_REMOVED: (
        "get_process_summary",
        "list_docker_services",
    ),
    IncidentEventType.NODE_OFFLINE: (
        "get_node_summary",
        "get_wireguard_status",
    ),
    IncidentEventType.LOCAL_ONLY: (
        "get_node_summary",
        "list_network_listeners",
        "probe_service_reachability",
    ),
    IncidentEventType.REMOTE_UNREACHABLE: (
        "get_node_summary",
        "get_wireguard_status",
        "probe_service_reachability",
    ),
    IncidentEventType.STATE_STALE: (),
}

_EVIDENCE_GAP_LABELS = {
    "get_node_summary": "节点与可用地址",
    "get_wireguard_status": "WireGuard 当前状态",
    "list_network_listeners": "监听地址与端口",
    "get_process_summary": "监听进程归属",
    "list_docker_services": "Docker 服务生命周期",
    "probe_service_reachability": "目标端口可达性",
}


class InvestigationToolExecutor(Protocol):
    """复用 Tool Runtime 的结构化执行边界。"""

    async def execute(
        self,
        request: ToolExecutionRequest,
        cancellation: ToolCancellationToken | None = None,
    ) -> ToolExecutionResult: ...


class InvestigationModelRuntime(Protocol):
    """复用 Context Runtime 的唯一模型调用边界。"""

    async def invoke(
        self,
        request: ContextRequest,
        cancellation: CancellationToken | None = None,
    ) -> ContextInvocation: ...


class InvestigationLimits(BaseModel):
    """单次调查的模型、工具、墙钟和上下文硬预算。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    max_model_rounds: int = Field(default=6, ge=1, le=16)
    max_tool_calls: int = Field(default=8, ge=1, le=24)
    timeout_seconds: float = Field(default=90, ge=0.1, le=600)
    context: ContextBudgets = Field(default_factory=ContextBudgets)


class InvestigationCancellation:
    """同时传播到 Provider 和 Tool Runtime 的取消信号。"""

    def __init__(self) -> None:
        self.model = CancellationToken()
        self.tool = ToolCancellationToken()

    def cancel(self) -> None:
        self.model.cancel()
        self.tool.cancel()

    @property
    def cancelled(self) -> bool:
        return self.model.cancelled or self.tool.cancelled


class _DecisionHypothesis(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    summary: str = Field(min_length=1, max_length=320)
    status: HypothesisStatus
    evidence_refs: tuple[str, ...] = Field(default=(), max_length=24)


class _DecisionFact(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    statement: str = Field(min_length=1, max_length=320)
    evidence_refs: tuple[str, ...] = Field(min_length=1, max_length=24)


class _InvestigationDecision(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    hypotheses: tuple[_DecisionHypothesis, ...] = Field(default=(), max_length=12)
    facts: tuple[_DecisionFact, ...] = Field(default=(), max_length=24)
    unknowns: tuple[str, ...] = Field(default=(), max_length=12)
    conclusion: str | None = Field(default=None, min_length=1, max_length=320)
    stop_reason: InvestigationStopReason


class IncidentInvestigator:
    """每轮只允许一次模型决定或一个只读工具调用。"""

    def __init__(
        self,
        model: InvestigationModelRuntime,
        registry: ToolRegistry,
        tools: InvestigationToolExecutor,
        store: SQLiteIncidentStore,
        platform: Platform,
        *,
        limits: InvestigationLimits | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._model = model
        self._registry = registry
        self._tools = tools
        self._store = store
        self._platform = platform
        self._limits = limits or InvestigationLimits()
        self._clock = clock or (lambda: datetime.now(UTC))

    async def run(
        self,
        incident: Incident,
        *,
        cancellation: InvestigationCancellation | None = None,
    ) -> Incident:
        """调查一个 incident，并在任意停止路径保存公开状态。"""
        if incident.status not in {
            IncidentStatus.PENDING,
            IncidentStatus.INTERRUPTED,
            IncidentStatus.INVESTIGATION_UNAVAILABLE,
        }:
            raise ValueError("只有待调查、中断或模型不可用的 incident 可以启动调查")
        token = cancellation or InvestigationCancellation()
        run_id = RunId.new()
        thread_id = ThreadId.new()
        started = self._now()
        current = self._with_initial_hypothesis(incident).transition(
            IncidentStatus.INVESTIGATING,
            at=started,
            run_id=run_id,
        )
        self._store.put_incident(current)
        try:
            async with asyncio.timeout(self._limits.timeout_seconds):
                return await self._run_loop(current, thread_id, run_id, token)
        except TimeoutError:
            token.cancel()
            return self._finish(
                current,
                IncidentStatus.BUDGET_EXHAUSTED,
                InvestigationStopReason.BUDGET_EXHAUSTED,
                "调查达到墙钟时间上限",
            )
        except (TypeError, ValueError, ValidationError):
            return self._finish(
                current,
                IncidentStatus.FAILED,
                InvestigationStopReason.FAILED,
                "调查返回无效结构",
            )

    async def _run_loop(
        self,
        incident: Incident,
        thread_id: ThreadId,
        run_id: RunId,
        cancellation: InvestigationCancellation,
    ) -> Incident:
        if (
            incident.event.source is SnapshotSource.LOCAL_OBSERVATION
            and incident.event.event_type is IncidentEventType.STATE_STALE
        ):
            return self._finish(
                incident,
                IncidentStatus.INSUFFICIENT_EVIDENCE,
                InvestigationStopReason.INSUFFICIENT_EVIDENCE,
                "当前状态已经陈旧，无法用它确认实时根因",
                evidence=tuple(self._snapshot_evidence(incident).values()),
            )
        messages = [
            ModelMessage(role="system", content=INCIDENT_INVESTIGATION_PROMPT.template),
            ModelMessage(role="user", content=self._incident_context(incident)),
        ]
        tool_results: list[ToolResultContext] = []
        evidence = self._snapshot_evidence(incident)
        local = incident.event.source is SnapshotSource.LOCAL_OBSERVATION
        available_tools = {item.name: item for item in self._model_tools()} if local else {}
        evidence_path = _LOCAL_EVIDENCE_PATHS[incident.event.event_type] if local else ()
        current = incident
        tool_calls = 0
        attempted_tools: set[str] = set()
        successful_tools: dict[str, EvidenceReference] = {}
        tool_outputs: dict[str, JsonValue] = {}
        tool_contract_repaired = False
        report_repaired = False
        evidence_conflict = False
        last_gap_signature: tuple[str, ...] | None = None
        for _ in range(self._limits.max_model_rounds):
            if cancellation.cancelled:
                return self._finish(
                    current,
                    IncidentStatus.CANCELLED,
                    InvestigationStopReason.CANCELLED,
                    "调查已取消",
                    evidence=tuple(successful_tools.values()),
                )
            remaining_tools = tuple(name for name in evidence_path if name not in attempted_tools)
            if (
                remaining_tools
                and not evidence_conflict
                and tool_calls >= self._limits.max_tool_calls
            ):
                return self._finish(
                    current,
                    IncidentStatus.BUDGET_EXHAUSTED,
                    InvestigationStopReason.BUDGET_EXHAUSTED,
                    "调查工具调用达到上限，仍有信息缺口",
                    evidence=tuple(successful_tools.values()),
                )
            probe_arguments = self._probe_arguments(
                incident,
                tool_outputs.get("get_node_summary"),
            )
            round_tools = (
                ()
                if evidence_conflict
                else self._eligible_tools(
                    incident,
                    remaining_tools,
                    available_tools,
                    probe_ready=probe_arguments is not None,
                )
            )
            gap_signature = (
                ("evidence_conflict",)
                if evidence_conflict
                else remaining_tools
                if evidence_path
                else ()
            )
            if local and evidence_path and gap_signature != last_gap_signature:
                summary = (
                    "实时只读证据与触发快照冲突，停止追加取证"
                    if evidence_conflict
                    else "剩余信息缺口："
                    + "、".join(_EVIDENCE_GAP_LABELS[name] for name in remaining_tools)
                    if remaining_tools
                    else "事件证据路径已完整，等待模型生成证据化报告"
                )
                current = self._append_trace(
                    current,
                    PublicTraceEntry(
                        occurred_at=self._now(),
                        kind="status",
                        summary=summary,
                        evidence=tuple(successful_tools.values()),
                    ),
                )
                self._store.put_incident(current)
                last_gap_signature = gap_signature
            if remaining_tools and not evidence_conflict and not round_tools:
                return self._finish(
                    current,
                    IncidentStatus.INSUFFICIENT_EVIDENCE,
                    InvestigationStopReason.INSUFFICIENT_EVIDENCE,
                    "当前节点缺少填补信息缺口所需的只读工具或安全参数",
                    evidence=tuple(successful_tools.values()),
                )
            round_messages = tuple(messages)
            if local:
                constraint = self._evidence_gap_message(
                    incident,
                    attempted_tools,
                    successful_tools,
                    remaining_tools,
                    round_tools,
                    tool_contract_repaired=tool_contract_repaired,
                    report_repaired=report_repaired,
                    evidence_conflict=evidence_conflict,
                )
                round_messages = (
                    ModelMessage(
                        role="system",
                        content=f"{messages[0].content}\n\n{constraint.content}",
                    ),
                    *messages[1:],
                )
            try:
                invocation = await self._model.invoke(
                    ContextRequest(
                        task_type=ContextTaskType.INCIDENT_INVESTIGATION,
                        current_intent="调查当前 incident 并收敛证据",
                        thread_id=thread_id,
                        run_id=run_id,
                        prompt_id=INCIDENT_INVESTIGATION_PROMPT.prompt_id,
                        prompt_version=INCIDENT_INVESTIGATION_PROMPT.version,
                        messages=round_messages,
                        tools=round_tools,
                        tool_results=tuple(tool_results),
                        require_tool_call=bool(round_tools),
                        response_schema=(
                            _InvestigationDecision.model_json_schema() if not round_tools else None
                        ),
                        evidence=(
                            make_context_reference(
                                kind=ContextContentKind.EVIDENCE,
                                source_id=f"incident:{incident.incident_id}",
                                content=incident.event.model_dump_json(),
                                trust=ContextTrust.VERIFIED_EVIDENCE,
                                observed_at=incident.event.observed_at,
                            ),
                        ),
                        budgets=self._limits.context,
                    ),
                    cancellation.model,
                )
            except ProviderError as exc:
                return self._provider_failure(
                    current,
                    exc,
                    evidence=tuple(successful_tools.values()),
                )
            response = invocation.response
            if not response.tool_calls and round_tools:
                if not tool_contract_repaired:
                    tool_contract_repaired = True
                    current = self._append_trace(
                        current,
                        PublicTraceEntry(
                            occurred_at=self._now(),
                            kind="status",
                            summary="模型未按当前信息缺口选择工具，Runtime 已请求一次纠正",
                        ),
                    )
                    self._store.put_incident(current)
                    continue
                fallback = self._fallback_call(
                    run_id,
                    round_tools,
                    probe_arguments,
                )
                current = self._append_trace(
                    current,
                    PublicTraceEntry(
                        occurred_at=self._now(),
                        kind="status",
                        summary=(
                            "模型纠正后仍未选择工具，Runtime 执行受控只读 fallback："
                            f"{fallback.name}"
                        ),
                    ),
                )
                self._store.put_incident(current)
                response = response.model_copy(update={"content": "", "tool_calls": (fallback,)})
            if response.tool_calls:
                if len(response.tool_calls) != 1 or tool_calls >= self._limits.max_tool_calls:
                    return self._finish(
                        current,
                        IncidentStatus.BUDGET_EXHAUSTED,
                        InvestigationStopReason.BUDGET_EXHAUSTED,
                        "调查工具调用达到上限或单轮请求过多",
                        evidence=tuple(successful_tools.values()),
                    )
                call = response.tool_calls[0]
                if call.name not in {item.name for item in round_tools}:
                    return self._finish(
                        current,
                        IncidentStatus.FAILED,
                        InvestigationStopReason.FAILED,
                        "模型请求了未允许的工具",
                        evidence=tuple(successful_tools.values()),
                    )
                messages.append(
                    ModelMessage(
                        role="assistant",
                        content=response.content or "",
                        tool_calls=response.tool_calls,
                    )
                )
                result = await self._tools.execute(
                    ToolExecutionRequest(
                        context=ToolCallContext(
                            thread_id=thread_id,
                            run_id=run_id,
                            caller_node_id=incident.event.target_node_id,
                            execution_node_id=incident.event.target_node_id,
                        ),
                        tool_name=call.name,
                        arguments=call.arguments,
                        required_arguments=(
                            probe_arguments
                            if call.name == "probe_service_reachability"
                            and probe_arguments is not None
                            else {}
                        ),
                    ),
                    cancellation.tool,
                )
                tool_calls += 1
                attempted_tools.add(call.name)
                reference = EvidenceReference(
                    tool_run_id=result.tool_run_id,
                    observed_at=self._now(),
                    summary=f"只读工具 {call.name} 以 {result.status.value} 状态结束",
                )
                if result.status in {
                    ToolExecutionStatus.SUCCESS,
                    ToolExecutionStatus.PARTIAL,
                }:
                    evidence[str(result.tool_run_id)] = reference
                    successful_tools[call.name] = reference
                    tool_outputs[call.name] = result.output
                tool_results.append(
                    ToolResultContext(
                        tool_run_id=result.tool_run_id,
                        content=self._tool_result_content(result),
                        artifact_id=result.artifact_id,
                        tool_call_id=call.call_id,
                        tool_name=call.name,
                        content_bytes=result.content_bytes or 0,
                        content_type=result.content_type or "application/json",
                        truncated=result.truncated,
                    )
                )
                current = self._append_trace(
                    current,
                    PublicTraceEntry(
                        occurred_at=self._now(),
                        kind="tool",
                        summary=reference.summary,
                        tool_name=call.name,
                        evidence=(reference,),
                    ),
                )
                self._store.put_incident(current)
                if result.status not in {
                    ToolExecutionStatus.SUCCESS,
                    ToolExecutionStatus.PARTIAL,
                }:
                    return self._finish(
                        current,
                        IncidentStatus.INSUFFICIENT_EVIDENCE,
                        InvestigationStopReason.INSUFFICIENT_EVIDENCE,
                        f"必要只读工具 {call.name} 不可用",
                        evidence=tuple(successful_tools.values()),
                    )
                evidence_conflict = evidence_conflict or self._is_snapshot_conflict(
                    incident,
                    call.name,
                    result.output,
                )
                continue
            try:
                decision = self._parse_decision(response.structured_output, response.content)
            except (TypeError, ValueError, ValidationError):
                return self._finish(
                    current,
                    IncidentStatus.FAILED,
                    InvestigationStopReason.FAILED,
                    "调查返回无效结构",
                    evidence=tuple(successful_tools.values()),
                )
            required_evidence = tuple(
                successful_tools[name] for name in evidence_path if name in successful_tools
            )
            if (
                not evidence_conflict
                and evidence_path
                and decision.stop_reason is InvestigationStopReason.EVIDENCE_SUFFICIENT
                and not self._decision_covers_required_evidence(decision, required_evidence)
                and not report_repaired
            ):
                report_repaired = True
                current = self._append_trace(
                    current,
                    PublicTraceEntry(
                        occurred_at=self._now(),
                        kind="status",
                        summary="模型终态未完整引用现有证据，Runtime 已请求一次报告纠正",
                        evidence=required_evidence,
                    ),
                )
                self._store.put_incident(current)
                continue
            return self._apply_decision(
                current,
                decision,
                evidence,
                required_evidence=required_evidence,
                evidence_conflict=evidence_conflict,
            )
        return self._finish(
            current,
            IncidentStatus.BUDGET_EXHAUSTED,
            InvestigationStopReason.BUDGET_EXHAUSTED,
            "调查达到模型轮次上限",
            evidence=tuple(successful_tools.values()),
        )

    def _apply_decision(
        self,
        incident: Incident,
        decision: _InvestigationDecision,
        evidence: dict[str, EvidenceReference],
        *,
        required_evidence: tuple[EvidenceReference, ...] = (),
        evidence_conflict: bool = False,
    ) -> Incident:
        hypotheses: list[IncidentHypothesis] = []
        cited: dict[str, EvidenceReference] = {}
        supporting_cited: dict[str, EvidenceReference] = {}
        for item in decision.hypotheses:
            refs = tuple(evidence[key] for key in item.evidence_refs if key in evidence)
            status = (
                HypothesisStatus.CANDIDATE
                if item.status is HypothesisStatus.SUPPORTED and not refs
                else item.status
            )
            hypotheses.append(
                IncidentHypothesis(
                    hypothesis_id=_hypothesis_id(item.summary),
                    summary=item.summary,
                    status=status,
                    evidence=refs,
                )
            )
            cited.update((key, evidence[key]) for key in item.evidence_refs if key in evidence)
            if status is HypothesisStatus.SUPPORTED:
                supporting_cited.update(
                    (key, evidence[key]) for key in item.evidence_refs if key in evidence
                )
        facts: list[str] = []
        for item in decision.facts:
            refs = tuple(evidence[key] for key in item.evidence_refs if key in evidence)
            if refs:
                facts.append(item.statement)
                cited.update((key, evidence[key]) for key in item.evidence_refs if key in evidence)
                supporting_cited.update(
                    (key, evidence[key]) for key in item.evidence_refs if key in evidence
                )
        supported = any(item.status is HypothesisStatus.SUPPORTED for item in hypotheses)
        has_tool_evidence = any(item.tool_run_id is not None for item in supporting_cited.values())
        required_ids = {
            str(item.tool_run_id) for item in required_evidence if item.tool_run_id is not None
        }
        confirmed = (
            decision.stop_reason is InvestigationStopReason.EVIDENCE_SUFFICIENT
            and decision.conclusion is not None
            and bool(supporting_cited)
            and supported
            and has_tool_evidence
            and required_ids.issubset(supporting_cited)
            and not evidence_conflict
        )
        unknowns = list(decision.unknowns)
        if not confirmed and decision.stop_reason is InvestigationStopReason.EVIDENCE_SUFFICIENT:
            unknowns.append("模型没有提供足以确认根因的有效证据引用；至少需要一项只读工具证据")
        report = IncidentReport(
            facts=tuple(facts),
            candidate_explanations=tuple(
                item.summary for item in hypotheses if item.status is not HypothesisStatus.REJECTED
            ),
            unknowns=tuple(unknowns),
            conclusion=decision.conclusion if confirmed else None,
            stop_reason=(
                InvestigationStopReason.EVIDENCE_SUFFICIENT
                if confirmed
                else InvestigationStopReason.INSUFFICIENT_EVIDENCE
            ),
            evidence=tuple(cited.values()),
        )
        current = Incident.model_validate(
            incident.model_dump()
            | {
                "hypotheses": tuple(hypotheses) or incident.hypotheses,
                "report": report,
            }
        )
        current = self._append_trace(
            current,
            PublicTraceEntry(
                occurred_at=self._now(),
                kind="report",
                summary=report.conclusion or "调查因证据不足停止",
                evidence=report.evidence,
            ),
        )
        current = current.transition(
            IncidentStatus.CONFIRMED if confirmed else IncidentStatus.INSUFFICIENT_EVIDENCE,
            at=self._now(),
            report=report,
        )
        self._store.put_incident(current)
        return current

    def _finish(
        self,
        incident: Incident,
        status: IncidentStatus,
        reason: InvestigationStopReason,
        unknown: str,
        *,
        evidence: tuple[EvidenceReference, ...] = (),
    ) -> Incident:
        report = IncidentReport(unknowns=(unknown,), stop_reason=reason, evidence=evidence)
        current = incident.transition(status, at=self._now(), report=report)
        current = self._append_trace(
            current,
            PublicTraceEntry(
                occurred_at=self._now(),
                kind="report",
                summary=unknown,
            ),
        )
        self._store.put_incident(current)
        return current

    def _provider_failure(
        self,
        incident: Incident,
        error: ProviderError,
        *,
        evidence: tuple[EvidenceReference, ...] = (),
    ) -> Incident:
        status = (
            IncidentStatus.INVESTIGATION_UNAVAILABLE
            if error.code
            in {
                ProviderErrorCode.AUTHENTICATION_FAILED,
                ProviderErrorCode.NETWORK_UNREACHABLE,
                ProviderErrorCode.TIMEOUT,
                ProviderErrorCode.MODEL_NOT_FOUND,
                ProviderErrorCode.CAPABILITY_INCOMPATIBLE,
            }
            else IncidentStatus.CANCELLED
            if error.code is ProviderErrorCode.CANCELLED
            else IncidentStatus.FAILED
        )
        reason = (
            InvestigationStopReason.MODEL_UNAVAILABLE
            if status is IncidentStatus.INVESTIGATION_UNAVAILABLE
            else InvestigationStopReason.CANCELLED
            if status is IncidentStatus.CANCELLED
            else InvestigationStopReason.FAILED
        )
        return self._finish(incident, status, reason, "模型调查不可用", evidence=evidence)

    @staticmethod
    def _eligible_tools(
        incident: Incident,
        remaining_tools: tuple[str, ...],
        available_tools: dict[str, ModelToolDefinition],
        *,
        probe_ready: bool,
    ) -> tuple[ModelToolDefinition, ...]:
        names = remaining_tools
        if incident.event.event_type is IncidentEventType.SERVICE_ADDED:
            names = names[:1]
        if not probe_ready:
            names = tuple(name for name in names if name != "probe_service_reachability")
        return tuple(available_tools[name] for name in names if name in available_tools)

    @staticmethod
    def _evidence_gap_message(
        incident: Incident,
        attempted_tools: set[str],
        successful_tools: dict[str, EvidenceReference],
        remaining_tools: tuple[str, ...],
        round_tools: tuple[ModelToolDefinition, ...],
        *,
        tool_contract_repaired: bool,
        report_repaired: bool,
        evidence_conflict: bool,
    ) -> ModelMessage:
        if evidence_conflict:
            instruction = "实时证据与触发快照冲突；返回 insufficient_evidence，不得确认根因。"
        elif remaining_tools:
            instruction = "本轮必须调用 allowed_tools_this_round 中恰好一个工具，不得返回终态。"
        else:
            instruction = "证据路径已完成；返回终态 JSON，并逐字引用 successful_evidence 中的 ID。"
        payload = {
            "event_type": incident.event.event_type.value,
            "attempted_tools": sorted(attempted_tools),
            "successful_evidence": {
                name: str(reference.tool_run_id)
                for name, reference in successful_tools.items()
                if reference.tool_run_id is not None
            },
            "information_gaps": [_EVIDENCE_GAP_LABELS[name] for name in remaining_tools],
            "allowed_tools_this_round": [item.name for item in round_tools],
            "tool_contract_correction_used": tool_contract_repaired,
            "report_correction_used": report_repaired,
            "evidence_conflict": evidence_conflict,
            "instruction": instruction,
        }
        return ModelMessage(
            role="system",
            content="以下是 Runtime 维护的当前只读调查约束："
            + json.dumps(payload, ensure_ascii=False, separators=(",", ":")),
        )

    def _fallback_call(
        self,
        run_id: RunId,
        round_tools: tuple[ModelToolDefinition, ...],
        probe_arguments: dict[str, JsonValue] | None,
    ) -> ToolCall:
        name = round_tools[0].name
        arguments = probe_arguments or {} if name == "probe_service_reachability" else {}
        return ToolCall(
            call_id=f"fallback-{run_id}-{name}",
            name=name,
            arguments=arguments,
        )

    def _probe_arguments(
        self,
        incident: Incident,
        node_summary: JsonValue | None,
    ) -> dict[str, JsonValue] | None:
        if not isinstance(node_summary, dict):
            return None
        wireguard = node_summary.get("wireguard")
        addresses = wireguard.get("addresses") if isinstance(wireguard, dict) else None
        affected = self._affected_object_context(incident)
        port = affected.get("port") if affected is not None else None
        if not isinstance(addresses, list) or not isinstance(port, int):
            return None
        for value in addresses:
            if not isinstance(value, str):
                continue
            try:
                address = ip_address(value.split("/", maxsplit=1)[0].split("%", maxsplit=1)[0])
            except ValueError:
                continue
            if (
                address.version == 4
                and address.is_private
                and not address.is_loopback
                and not address.is_link_local
                and not address.is_unspecified
            ):
                return {"host": str(address), "port": port}
        return None

    @staticmethod
    def _is_snapshot_conflict(
        incident: Incident,
        tool_name: str,
        output: JsonValue | None,
    ) -> bool:
        return bool(
            tool_name == "probe_service_reachability"
            and isinstance(output, dict)
            and output.get("reachable") is True
            and incident.event.event_type
            in {IncidentEventType.LOCAL_ONLY, IncidentEventType.REMOTE_UNREACHABLE}
        )

    @staticmethod
    def _decision_covers_required_evidence(
        decision: _InvestigationDecision,
        required_evidence: tuple[EvidenceReference, ...],
    ) -> bool:
        required_ids = {
            str(item.tool_run_id) for item in required_evidence if item.tool_run_id is not None
        }
        cited = {
            reference
            for item in decision.hypotheses
            if item.status is HypothesisStatus.SUPPORTED
            for reference in item.evidence_refs
        } | {reference for item in decision.facts for reference in item.evidence_refs}
        return bool(
            decision.conclusion
            and any(item.status is HypothesisStatus.SUPPORTED for item in decision.hypotheses)
            and required_ids.issubset(cited)
        )

    def _model_tools(self) -> tuple[ModelToolDefinition, ...]:
        available = {item.name: item for item in self._registry.model_tools(self._platform)}
        return tuple(
            ModelToolDefinition(
                name=available[name].name,
                description=available[name].description,
                input_schema=available[name].input_schema,
            )
            for name in READ_ONLY_INVESTIGATION_TOOLS
            if name in available
        )

    def _with_initial_hypothesis(self, incident: Incident) -> Incident:
        if incident.hypotheses:
            return incident
        labels = {
            "service_added": "服务已稳定新增，原因仍待确认",
            "service_removed": "服务已稳定消失，原因仍待确认",
            "node_offline": "节点离线可能导致服务不可用",
            "state_stale": "目录或观察证据已经陈旧",
            "local_only": "服务可能仅监听本机地址",
            "remote_unreachable": "服务可能无法从远端访问",
        }
        summary = labels[incident.event.event_type.value]
        reference = self._snapshot_evidence(incident)[str(incident.event.current_snapshot_id)]
        return Incident.model_validate(
            incident.model_dump()
            | {
                "hypotheses": (
                    IncidentHypothesis(
                        hypothesis_id=_hypothesis_id(summary),
                        summary=summary,
                        evidence=(reference,),
                    ),
                )
            }
        )

    @staticmethod
    def _snapshot_evidence(incident: Incident) -> dict[str, EvidenceReference]:
        return {
            str(incident.event.baseline_snapshot_id): EvidenceReference(
                snapshot_id=incident.event.baseline_snapshot_id,
                observed_at=incident.event.observed_at,
                summary="incident 基线快照",
            ),
            str(incident.event.current_snapshot_id): EvidenceReference(
                snapshot_id=incident.event.current_snapshot_id,
                observed_at=incident.event.observed_at,
                summary=f"确定性差异：{incident.event.event_type.value}",
            ),
        }

    def _incident_context(self, incident: Incident) -> str:
        payload = {
            "event": incident.event.model_dump(mode="json"),
            "affected_object": self._affected_object_context(incident),
        }
        return "以下是已脱敏的确定性 incident：" + json.dumps(
            payload,
            ensure_ascii=False,
            separators=(",", ":"),
        )

    def _affected_object_context(self, incident: Incident) -> dict[str, JsonValue] | None:
        for snapshot_id in (
            incident.event.current_snapshot_id,
            incident.event.baseline_snapshot_id,
        ):
            snapshot = self._store.get_snapshot(snapshot_id)
            if snapshot is None:
                continue
            if incident.event.object_kind is SnapshotObjectKind.SERVICE:
                match = next(
                    (
                        item
                        for item in snapshot.services
                        if str(item.service_id) == incident.event.object_id
                    ),
                    None,
                )
            else:
                match = next(
                    (
                        item
                        for item in snapshot.nodes
                        if str(item.node_id) == incident.event.object_id
                    ),
                    None,
                )
            if match is not None:
                return {
                    "snapshot_id": str(snapshot.snapshot_id),
                    **match.model_dump(mode="json"),
                }
        return None

    @staticmethod
    def _tool_result_content(result: ToolExecutionResult) -> str:
        return json.dumps(
            {"trust": "untrusted-tool-data", "result": result.model_dump(mode="json")},
            ensure_ascii=False,
            separators=(",", ":"),
        )

    @staticmethod
    def _parse_decision(value: JsonValue | None, content: str | None) -> _InvestigationDecision:
        if value is not None:
            return _InvestigationDecision.model_validate(value)
        if content is None:
            raise ValueError("模型没有返回调查决定")
        text = content.strip()
        if text.startswith("```"):
            lines = text.splitlines()
            text = "\n".join(lines[1:-1])
        return _InvestigationDecision.model_validate_json(text)

    @staticmethod
    def _append_trace(incident: Incident, entry: PublicTraceEntry) -> Incident:
        return Incident.model_validate(incident.model_dump() | {"trace": (*incident.trace, entry)})

    def _now(self) -> datetime:
        value = self._clock()
        if value.tzinfo is None:
            raise ValueError("调查时钟必须包含时区")
        return value


class ConfiguredIncidentRunner:
    """按 incident 惰性读取当前模型；未配置时只保存降级状态。"""

    def __init__(
        self,
        provider_factory: Callable[[], ModelProvider],
        registry: ToolRegistry,
        tools: InvestigationToolExecutor,
        store: SQLiteIncidentStore,
        platform: Platform,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._provider_factory = provider_factory
        self._registry = registry
        self._tools = tools
        self._store = store
        self._platform = platform
        self._clock = clock or (lambda: datetime.now(UTC))

    async def run(self, incident: Incident) -> Incident:
        try:
            provider = self._provider_factory()
        except (ProviderError, OSError, ValueError):
            report = IncidentReport(
                unknowns=("模型调查不可用",),
                stop_reason=InvestigationStopReason.MODEL_UNAVAILABLE,
            )
            updated = incident.transition(
                IncidentStatus.INVESTIGATION_UNAVAILABLE,
                at=self._clock(),
                report=report,
            )
            self._store.put_incident(updated)
            return updated
        return await IncidentInvestigator(
            ContextModelRuntime(
                provider,
                provider_name="configured-provider",
                model_name="configured-model",
                tool_schema_version="incident-tools/v1",
            ),
            self._registry,
            self._tools,
            self._store,
            self._platform,
            clock=self._clock,
        ).run(incident)


def _hypothesis_id(summary: str) -> str:
    return f"hypothesis_{hashlib.sha256(summary.encode()).hexdigest()[:16]}"
