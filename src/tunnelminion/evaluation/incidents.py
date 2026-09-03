"""固定 incident 故障矩阵、真实 Runtime 执行与六项价值指标。"""

from __future__ import annotations

import json
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from time import perf_counter
from typing import Literal, Self, cast

from pydantic import BaseModel, ConfigDict, Field, JsonValue, model_validator

from tunnelminion.agent.context_runtime import ContextModelRuntime
from tunnelminion.coordinator.contracts import ServiceAccessibility, ServiceLifecycle
from tunnelminion.domain.identifiers import NodeId, ServiceId, SnapshotId
from tunnelminion.domain.tools import (
    DataSensitivity,
    Platform,
    RiskLevel,
    ToolDefinition,
)
from tunnelminion.domain.versioning import ProtocolVersion
from tunnelminion.incident.contracts import (
    IncidentEventType,
    IncidentStatus,
    InvestigationStopReason,
    NormalizedSnapshot,
    SnapshotFreshness,
    SnapshotNode,
    SnapshotNodeState,
    SnapshotService,
    SnapshotServiceState,
    SnapshotSource,
)
from tunnelminion.incident.investigation import (
    READ_ONLY_INVESTIGATION_TOOLS,
    IncidentInvestigator,
    InvestigationLimits,
)
from tunnelminion.incident.snapshot import SnapshotDiffDetector
from tunnelminion.incident.storage import SQLiteIncidentStore
from tunnelminion.model.contracts import (
    CancellationToken,
    ModelCapabilities,
    ModelRequest,
    ModelResponse,
    ProviderError,
    ProviderErrorCode,
    ToolCall,
)
from tunnelminion.tools.audit import InMemoryAuditSink
from tunnelminion.tools.contracts import ToolCancellationToken
from tunnelminion.tools.registry import ToolRegistry
from tunnelminion.tools.runtime import ToolRuntime

_NODE = NodeId("node_0123456789abcdef0123456789abcdef")
_SERVICE = ServiceId("service_0123456789abcdef0123456789abcdef")
_OBSERVED_AT = datetime(2026, 9, 3, 0, tzinfo=UTC)
_REQUIRED_CATEGORIES = frozenset(
    {
        "normal",
        "service_added",
        "service_removed",
        "node_offline",
        "state_stale",
        "local_only",
        "remote_unreachable",
        "docker_unavailable",
        "tool_failure",
        "model_failure",
        "budget_exhausted",
    }
)


class IncidentSnapshotInput(BaseModel):
    """一个节点和一个可选服务组成的紧凑输入快照。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    node_state: SnapshotNodeState = SnapshotNodeState.ONLINE
    node_freshness: SnapshotFreshness = SnapshotFreshness.FRESH
    service_present: bool = True
    service_state: SnapshotServiceState = SnapshotServiceState.AVAILABLE
    service_freshness: SnapshotFreshness = SnapshotFreshness.FRESH
    accessibility: ServiceAccessibility = ServiceAccessibility.NETWORK


class IncidentEvaluationScenario(BaseModel):
    """每个固定场景同时声明输入、期望、工具边界和失败分类。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    scenario_id: str = Field(pattern=r"^[a-z][a-z0-9_-]{2,63}$")
    category: str = Field(min_length=3, max_length=40)
    baseline: IncidentSnapshotInput
    current: IncidentSnapshotInput
    expected_event: IncidentEventType | None
    expected_root_cause: str | None = Field(default=None, min_length=1, max_length=320)
    tool_sequence: tuple[str, ...] = Field(default=(), max_length=8)
    failing_tools: frozenset[str] = frozenset()
    required_tools: frozenset[str] = frozenset()
    forbidden_tools: frozenset[str] = frozenset()
    minimum_evidence: int = Field(default=0, ge=0, le=24)
    expected_status: IncidentStatus | None
    expected_stop_reason: InvestigationStopReason | None
    outcome: Literal["confirmed", "insufficient", "model_failure", "budget", "none"]
    failure_class: str | None = Field(default=None, min_length=1, max_length=80)

    @model_validator(mode="after")
    def validate_expectations(self) -> Self:
        if self.required_tools & self.forbidden_tools:
            raise ValueError("必要工具与禁止工具不得重叠")
        if set(self.tool_sequence) - set(READ_ONLY_INVESTIGATION_TOOLS):
            raise ValueError("脚本只能选择既有六个只读工具")
        if not self.required_tools.issubset(self.tool_sequence):
            raise ValueError("必要工具必须出现在脚本序列")
        if self.expected_event is None and self.outcome != "none":
            raise ValueError("无事件场景不得运行调查")
        if self.expected_event is not None and (
            self.expected_status is None or self.expected_stop_reason is None
        ):
            raise ValueError("事件场景必须声明终态和停止原因")
        return self


class IncidentEvaluationDataset(BaseModel):
    """可版本比较的固定 incident 数据集。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["incident-evaluation/v1"] = "incident-evaluation/v1"
    dataset_id: str = Field(pattern=r"^[a-z][a-z0-9_-]{2,63}$")
    dataset_version: str = Field(pattern=r"^v[1-9][0-9]*$")
    model_name: str = Field(min_length=1)
    provider_name: str = Field(min_length=1)
    prompt_version: str = Field(min_length=1)
    tool_versions: dict[str, str] = Field(min_length=6, max_length=6)
    scenarios: tuple[IncidentEvaluationScenario, ...] = Field(min_length=11)

    @model_validator(mode="after")
    def validate_matrix(self) -> Self:
        identifiers = [item.scenario_id for item in self.scenarios]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("incident 场景 ID 必须唯一")
        categories = {item.category for item in self.scenarios}
        if not _REQUIRED_CATEGORIES.issubset(categories):
            raise ValueError("incident 矩阵缺少必要故障类别")
        if set(self.tool_versions) != set(READ_ONLY_INVESTIGATION_TOOLS):
            raise ValueError("数据集必须固定全部六个只读工具版本")
        return self


class IncidentScenarioResult(BaseModel):
    """一个场景的可审计输出。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    scenario_id: str
    category: str
    incident_count: int = Field(ge=0)
    model_calls: int = Field(ge=0)
    observed_event: IncidentEventType | None
    status: IncidentStatus | None
    stop_reason: InvestigationStopReason | None
    conclusion: str | None
    selected_tools: tuple[str, ...]
    executed_tools: tuple[str, ...]
    evidence_count: int = Field(ge=0)
    root_cause_success: bool | None
    tool_selection_success: bool
    unnecessary_tool_calls: int = Field(ge=0)
    unsupported_assertion: bool
    failure_recovered: bool | None
    failure_class: str | None
    latency_ms: float = Field(ge=0)


class IncidentEvaluationMetrics(BaseModel):
    """产品价值与安全的六项核心指标及硬边界。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    scenario_count: int
    root_cause_success_rate: float
    tool_selection_rate: float
    unnecessary_tool_call_rate: float
    unsupported_assertion_rate: float
    failure_recovery_rate: float
    average_latency_ms: float
    maximum_latency_ms: float
    normal_incident_count: int
    normal_model_calls: int
    forbidden_tool_executions: int


class IncidentEvaluationReport(BaseModel):
    """包含版本、逐场景失败分类与聚合指标的离线报告。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["incident-evaluation-report/v1"] = "incident-evaluation-report/v1"
    dataset_id: str
    dataset_version: str
    model_name: str
    provider_name: str
    prompt_version: str
    tool_versions: dict[str, str]
    generated_at: datetime
    scope: Literal["offline-scripted-local-runtime"] = "offline-scripted-local-runtime"
    scenarios: tuple[IncidentScenarioResult, ...]
    metrics: IncidentEvaluationMetrics
    gate_violations: tuple[str, ...]


class _FixtureAdapter:
    def __init__(self, name: str, *, fail: bool) -> None:
        self.name = name
        self.fail = fail

    async def execute(
        self,
        arguments: dict[str, JsonValue],
        cancellation: ToolCancellationToken,
    ) -> JsonValue:
        if cancellation.cancelled:
            raise RuntimeError("cancelled")
        if self.fail:
            raise RuntimeError("fixture failure")
        return {"tool": self.name, "observed": True}


class _FixtureProvider:
    def __init__(self, scenario: IncidentEvaluationScenario, current: NormalizedSnapshot) -> None:
        self.scenario = scenario
        self.current = current
        self.calls = 0

    @property
    def capabilities(self) -> ModelCapabilities:
        return ModelCapabilities(tool_calls=True, structured_output=True)

    async def complete(
        self,
        request: ModelRequest,
        cancellation: CancellationToken | None = None,
    ) -> ModelResponse:
        self.calls += 1
        if self.scenario.outcome == "model_failure":
            raise ProviderError(ProviderErrorCode.NETWORK_UNREACHABLE, "fixture unavailable")
        sequence = self.scenario.tool_sequence
        if self.scenario.outcome == "budget":
            name = sequence[0]
            return ModelResponse(
                tool_calls=(ToolCall(call_id=f"call-{self.calls}", name=name, arguments={}),)
            )
        if self.calls <= len(sequence):
            name = sequence[self.calls - 1]
            return ModelResponse(
                tool_calls=(ToolCall(call_id=f"call-{self.calls}", name=name, arguments={}),)
            )
        evidence_refs = self._evidence_refs(request)
        if not evidence_refs:
            evidence_refs = [str(self.current.snapshot_id)]
        confirmed = self.scenario.outcome == "confirmed"
        return ModelResponse(
            structured_output=cast(
                JsonValue,
                {
                    "hypotheses": [
                        {
                            "summary": self.scenario.expected_root_cause or "证据仍不足",
                            "status": "supported" if confirmed else "candidate",
                            "evidence_refs": evidence_refs,
                        }
                    ],
                    "facts": [
                        {
                            "statement": "固定矩阵获得了结构化证据",
                            "evidence_refs": evidence_refs,
                        }
                    ],
                    "unknowns": [] if confirmed else ["必要证据不可获得"],
                    "conclusion": self.scenario.expected_root_cause if confirmed else None,
                    "stop_reason": (
                        "evidence_sufficient" if confirmed else "insufficient_evidence"
                    ),
                },
            )
        )

    @staticmethod
    def _evidence_refs(request: ModelRequest) -> list[str]:
        values: list[str] = []
        for message in request.messages:
            if message.role != "tool":
                continue
            payload = json.loads(message.content)
            values.append(str(payload["result"]["tool_run_id"]))
        return values


def _snapshot(value: IncidentSnapshotInput, *, revision: int) -> NormalizedSnapshot:
    node = SnapshotNode(
        node_id=_NODE,
        state=value.node_state,
        source=SnapshotSource.LOCAL_OBSERVATION,
        freshness=value.node_freshness,
        evidence_at=_OBSERVED_AT + timedelta(seconds=revision),
    )
    services = (
        (
            SnapshotService(
                service_id=_SERVICE,
                node_id=_NODE,
                state=value.service_state,
                source=SnapshotSource.LOCAL_OBSERVATION,
                freshness=value.service_freshness,
                evidence_at=_OBSERVED_AT + timedelta(seconds=revision),
                accessibility=value.accessibility,
                lifecycle=ServiceLifecycle.ACTIVE,
            ),
        )
        if value.service_present
        else ()
    )
    return NormalizedSnapshot(
        snapshot_id=SnapshotId(f"snapshot_{revision:032x}"),
        observed_at=_OBSERVED_AT + timedelta(seconds=revision),
        revision=revision,
        nodes=(node,),
        services=services,
    )


def _runtime(
    scenario: IncidentEvaluationScenario,
) -> tuple[ToolRegistry, ToolRuntime, InMemoryAuditSink]:
    registry = ToolRegistry()
    audit = InMemoryAuditSink()
    for name in READ_ONLY_INVESTIGATION_TOOLS:
        registry.register(
            ToolDefinition(
                name=name,
                version=ProtocolVersion(major=1, minor=0),
                description=f"固定离线工具 {name}",
                input_schema={"type": "object", "additionalProperties": False},
                output_schema={
                    "type": "object",
                    "properties": {
                        "tool": {"type": "string"},
                        "observed": {"type": "boolean"},
                    },
                    "required": ["tool", "observed"],
                    "additionalProperties": False,
                },
                risk_level=RiskLevel.READ_ONLY,
                platforms=frozenset({Platform.WINDOWS}),
                timeout_seconds=1,
                max_result_bytes=1024,
                data_sensitivity=DataSensitivity.SYSTEM_METADATA,
            ),
            _FixtureAdapter(name, fail=name in scenario.failing_tools),
        )
    return registry, ToolRuntime(registry, Platform.WINDOWS, audit), audit


async def run_incident_scenario(
    scenario: IncidentEvaluationScenario,
    store: SQLiteIncidentStore,
    *,
    revision_offset: int = 0,
) -> IncidentScenarioResult:
    """运行真实 detector、Context Runtime、Tool Runtime 与报告收敛链。"""
    started = perf_counter()
    baseline = _snapshot(scenario.baseline, revision=revision_offset + 1)
    current = _snapshot(scenario.current, revision=revision_offset + 2)
    events = SnapshotDiffDetector(confirmations_required=1).compare(baseline, current)
    event = next((item for item in events if item.event_type == scenario.expected_event), None)
    if scenario.expected_event is None:
        return IncidentScenarioResult(
            scenario_id=scenario.scenario_id,
            category=scenario.category,
            incident_count=len(events),
            model_calls=0,
            observed_event=None,
            status=None,
            stop_reason=None,
            conclusion=None,
            selected_tools=(),
            executed_tools=(),
            evidence_count=0,
            root_cause_success=None,
            tool_selection_success=True,
            unnecessary_tool_calls=0,
            unsupported_assertion=False,
            failure_recovered=None,
            failure_class=scenario.failure_class,
            latency_ms=(perf_counter() - started) * 1000,
        )
    if event is None:
        raise ValueError(f"场景 {scenario.scenario_id} 未产生期望事件")
    incident = store.record_event(event)
    registry, tools, audit = _runtime(scenario)
    provider = _FixtureProvider(scenario, current)
    investigator = IncidentInvestigator(
        ContextModelRuntime(
            provider,
            provider_name="offline-script",
            model_name="fixed-incident-model-v1",
            tool_schema_version="incident-tools/v1",
        ),
        registry,
        tools,
        store,
        Platform.WINDOWS,
        limits=InvestigationLimits(max_tool_calls=1 if scenario.outcome == "budget" else 8),
        clock=lambda: _OBSERVED_AT + timedelta(days=1),
    )
    final = await investigator.run(incident)
    selected = tuple(
        item.tool_name for item in final.trace if item.kind == "tool" and item.tool_name is not None
    )
    executed = tuple(item.tool_name for item in audit.records)
    report = final.report
    evidence_count = len(report.evidence) if report is not None else 0
    root_success = (
        final.status is IncidentStatus.CONFIRMED
        and report is not None
        and report.conclusion == scenario.expected_root_cause
        and evidence_count >= scenario.minimum_evidence
        if scenario.expected_root_cause is not None
        else None
    )
    unsupported = bool(
        final.status is IncidentStatus.CONFIRMED
        and (report is None or report.conclusion is None or not report.evidence)
    )
    tool_success = scenario.required_tools.issubset(selected) and not (
        set(selected) & scenario.forbidden_tools
    )
    recovered = (
        final.status is scenario.expected_status
        and report is not None
        and report.stop_reason is scenario.expected_stop_reason
        and not unsupported
        if scenario.failure_class is not None
        else None
    )
    return IncidentScenarioResult(
        scenario_id=scenario.scenario_id,
        category=scenario.category,
        incident_count=len(events),
        model_calls=provider.calls,
        observed_event=event.event_type,
        status=final.status,
        stop_reason=report.stop_reason if report is not None else None,
        conclusion=report.conclusion if report is not None else None,
        selected_tools=selected,
        executed_tools=executed,
        evidence_count=evidence_count,
        root_cause_success=root_success,
        tool_selection_success=tool_success,
        unnecessary_tool_calls=sum(name not in scenario.required_tools for name in selected),
        unsupported_assertion=unsupported,
        failure_recovered=recovered,
        failure_class=scenario.failure_class,
        latency_ms=(perf_counter() - started) * 1000,
    )


def _ratio(values: Sequence[bool]) -> float:
    return sum(values) / len(values) if values else 1.0


async def run_incident_dataset(
    dataset: IncidentEvaluationDataset,
    store: SQLiteIncidentStore,
) -> IncidentEvaluationReport:
    """运行固定矩阵并计算六项核心指标和零容忍门禁。"""
    results = tuple(
        [
            await run_incident_scenario(scenario, store, revision_offset=index * 2)
            for index, scenario in enumerate(dataset.scenarios)
        ]
    )
    roots = [item.root_cause_success for item in results if item.root_cause_success is not None]
    recoveries = [item.failure_recovered for item in results if item.failure_recovered is not None]
    selected_count = sum(len(item.selected_tools) for item in results)
    normal = [item for item in results if item.category == "normal"]
    forbidden_executions = sum(
        len(set(result.executed_tools) & scenario.forbidden_tools)
        for result, scenario in zip(results, dataset.scenarios, strict=True)
    )
    metrics = IncidentEvaluationMetrics(
        scenario_count=len(results),
        root_cause_success_rate=_ratio(roots),
        tool_selection_rate=_ratio([item.tool_selection_success for item in results]),
        unnecessary_tool_call_rate=(
            sum(item.unnecessary_tool_calls for item in results) / selected_count
            if selected_count
            else 0.0
        ),
        unsupported_assertion_rate=sum(item.unsupported_assertion for item in results)
        / len(results),
        failure_recovery_rate=_ratio(recoveries),
        average_latency_ms=sum(item.latency_ms for item in results) / len(results),
        maximum_latency_ms=max(item.latency_ms for item in results),
        normal_incident_count=sum(item.incident_count for item in normal),
        normal_model_calls=sum(item.model_calls for item in normal),
        forbidden_tool_executions=forbidden_executions,
    )
    violations = tuple(
        name
        for name, failed in {
            "root_cause_success_rate": metrics.root_cause_success_rate != 1.0,
            "tool_selection_rate": metrics.tool_selection_rate != 1.0,
            "unnecessary_tool_call_rate": metrics.unnecessary_tool_call_rate != 0.0,
            "unsupported_assertion_rate": metrics.unsupported_assertion_rate != 0.0,
            "failure_recovery_rate": metrics.failure_recovery_rate != 1.0,
            "normal_refresh": bool(metrics.normal_incident_count or metrics.normal_model_calls),
            "forbidden_tool_execution": metrics.forbidden_tool_executions != 0,
        }.items()
        if failed
    )
    return IncidentEvaluationReport(
        dataset_id=dataset.dataset_id,
        dataset_version=dataset.dataset_version,
        model_name=dataset.model_name,
        provider_name=dataset.provider_name,
        prompt_version=dataset.prompt_version,
        tool_versions=dataset.tool_versions,
        generated_at=datetime.now(UTC),
        scenarios=results,
        metrics=metrics,
        gate_violations=violations,
    )
