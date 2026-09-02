"""单 Agent 调查、只读工具边界、预算和后台触发测试。"""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from pathlib import Path

from pydantic import JsonValue

from tunnelminion.agent.context_runtime import ContextModelRuntime
from tunnelminion.coordinator.contracts import ServiceAccessibility
from tunnelminion.domain.identifiers import NodeId, ServiceId, SnapshotId
from tunnelminion.domain.tools import (
    DataSensitivity,
    Platform,
    RiskLevel,
    ToolDefinition,
)
from tunnelminion.domain.versioning import ProtocolVersion
from tunnelminion.incident.contracts import (
    Incident,
    IncidentEventType,
    IncidentStatus,
    InvestigationStopReason,
    SnapshotDiffEvent,
    SnapshotObjectKind,
    SnapshotSource,
)
from tunnelminion.incident.investigation import (
    IncidentInvestigator,
    InvestigationCancellation,
    InvestigationLimits,
)
from tunnelminion.incident.observer import IncidentObservationService
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
from tunnelminion.web.overview import (
    KnownNodeOverview,
    KnownNodesOverview,
    KnownNodeState,
    KnownServiceOverview,
    KnownServicesOverview,
    KnownServiceState,
    OverviewFreshness,
    OverviewService,
    OverviewSource,
    ResourceOverview,
)

NOW = datetime(2026, 9, 3, 9, tzinfo=UTC)
NODE = NodeId("node_0123456789abcdef0123456789abcdef")
SERVICE = ServiceId("service_0123456789abcdef0123456789abcdef")


class RecordingAdapter:
    """只记录真正通过 schema 和策略的调用。"""

    def __init__(self, *, fail: bool = False) -> None:
        self.calls: list[dict[str, JsonValue]] = []
        self.fail = fail

    async def execute(
        self,
        arguments: dict[str, JsonValue],
        cancellation: ToolCancellationToken,
    ) -> JsonValue:
        assert not cancellation.cancelled
        self.calls.append(arguments)
        if self.fail:
            raise RuntimeError("fixture tool failure")
        return {"status": "network-listening"}


class ScriptedProvider:
    """根据模式返回工具选择、最终报告或稳定 Provider 失败。"""

    def __init__(self, mode: str) -> None:
        self.mode = mode
        self.requests: list[ModelRequest] = []

    @property
    def capabilities(self) -> ModelCapabilities:
        return ModelCapabilities(tool_calls=True, structured_output=True)

    async def complete(
        self,
        request: ModelRequest,
        cancellation: CancellationToken | None = None,
    ) -> ModelResponse:
        assert cancellation is None or not cancellation.cancelled
        self.requests.append(request)
        if self.mode == "unavailable":
            raise ProviderError(
                ProviderErrorCode.NETWORK_UNREACHABLE,
                "provider unavailable",
                retryable=True,
            )
        if self.mode == "unknown_tool":
            return ModelResponse(
                tool_calls=(ToolCall(call_id="call-1", name="shell", arguments={}),)
            )
        if self.mode == "endless" or len(self.requests) == 1:
            arguments: dict[str, JsonValue] = (
                {"unexpected": True} if self.mode == "invalid_arguments" else {}
            )
            return ModelResponse(
                tool_calls=(
                    ToolCall(
                        call_id=f"call-{len(self.requests)}",
                        name="list_network_listeners",
                        arguments=arguments,
                    ),
                )
            )
        tool_run_id = self._latest_tool_run_id(request)
        if self.mode == "unsupported_claim":
            tool_run_id = "toolrun_ffffffffffffffffffffffffffffffff"
        return ModelResponse(
            content=json.dumps(
                {
                    "hypotheses": [
                        {
                            "summary": "服务仅监听本机地址",
                            "status": "supported",
                            "evidence_refs": [tool_run_id],
                        }
                    ],
                    "facts": [
                        {
                            "statement": "监听工具已返回结构化结果",
                            "evidence_refs": [tool_run_id],
                        }
                    ],
                    "unknowns": [],
                    "conclusion": "服务仅监听本机地址",
                    "stop_reason": "evidence_sufficient",
                }
            )
        )

    @staticmethod
    def _latest_tool_run_id(request: ModelRequest) -> str:
        message = next(item for item in reversed(request.messages) if item.role == "tool")
        payload = json.loads(message.content)
        return str(payload["result"]["tool_run_id"])


def _incident(store: SQLiteIncidentStore) -> Incident:
    event = SnapshotDiffEvent(
        event_type=IncidentEventType.LOCAL_ONLY,
        object_kind=SnapshotObjectKind.SERVICE,
        object_id=str(SERVICE),
        target_node_id=NODE,
        baseline_snapshot_id=SnapshotId("snapshot_00000000000000000000000000000001"),
        current_snapshot_id=SnapshotId("snapshot_00000000000000000000000000000002"),
        baseline_revision=1,
        current_revision=2,
        observed_at=NOW,
        source=SnapshotSource.COORDINATOR_DIRECTORY,
        before_state="network",
        after_state="loopback",
        dedup_key=f"sha256:{'a' * 64}",
    )
    return store.record_event(event)


def _runtime(
    tmp_path: Path,
    mode: str,
    *,
    limits: InvestigationLimits | None = None,
) -> tuple[IncidentInvestigator, SQLiteIncidentStore, RecordingAdapter, ScriptedProvider]:
    registry = ToolRegistry()
    adapter = RecordingAdapter(fail=mode == "tool_failure")
    registry.register(
        ToolDefinition(
            name="list_network_listeners",
            version=ProtocolVersion(major=1, minor=0),
            description="列出网络监听",
            input_schema={"type": "object", "additionalProperties": False},
            output_schema={
                "type": "object",
                "properties": {"status": {"type": "string"}},
                "required": ["status"],
                "additionalProperties": False,
            },
            risk_level=RiskLevel.READ_ONLY,
            platforms=frozenset({Platform.WINDOWS}),
            timeout_seconds=1,
            max_result_bytes=1024,
            data_sensitivity=DataSensitivity.SYSTEM_METADATA,
        ),
        adapter,
    )
    store = SQLiteIncidentStore(tmp_path / f"{mode}.sqlite3")
    provider = ScriptedProvider(mode)
    investigator = IncidentInvestigator(
        ContextModelRuntime(
            provider,
            provider_name="scripted",
            model_name="fixture",
            tool_schema_version="incident-tools/v1",
        ),
        registry,
        ToolRuntime(registry, Platform.WINDOWS, InMemoryAuditSink()),
        store,
        Platform.WINDOWS,
        limits=limits,
        clock=lambda: NOW,
    )
    return investigator, store, adapter, provider


def test_investigator_selects_one_read_only_tool_and_confirms_cited_root_cause(
    tmp_path: Path,
) -> None:
    investigator, store, adapter, provider = _runtime(tmp_path, "success")

    result = asyncio.run(investigator.run(_incident(store)))

    assert result.status is IncidentStatus.CONFIRMED
    assert result.report is not None
    assert result.report.conclusion == "服务仅监听本机地址"
    assert result.report.stop_reason is InvestigationStopReason.EVIDENCE_SUFFICIENT
    assert len(result.report.evidence) == 1
    assert adapter.calls == [{}]
    assert len(provider.requests) == 2
    assert {item.name for item in provider.requests[0].tools} == {"list_network_listeners"}
    assert store.get(result.incident_id) == result


def test_unknown_tool_is_rejected_without_tool_runtime_execution(tmp_path: Path) -> None:
    investigator, store, adapter, _ = _runtime(tmp_path, "unknown_tool")

    result = asyncio.run(investigator.run(_incident(store)))

    assert result.status is IncidentStatus.FAILED
    assert result.report is not None
    assert result.report.stop_reason is InvestigationStopReason.FAILED
    assert adapter.calls == []


def test_invalid_arguments_do_not_reach_adapter_and_finish_without_evidence(
    tmp_path: Path,
) -> None:
    investigator, store, adapter, _ = _runtime(tmp_path, "invalid_arguments")

    result = asyncio.run(investigator.run(_incident(store)))

    assert result.status is IncidentStatus.INSUFFICIENT_EVIDENCE
    assert result.report is not None
    assert result.report.conclusion is None
    assert adapter.calls == []


def test_tool_failure_is_preserved_but_cannot_support_a_root_cause(tmp_path: Path) -> None:
    investigator, store, adapter, _ = _runtime(tmp_path, "tool_failure")

    result = asyncio.run(investigator.run(_incident(store)))

    assert result.status is IncidentStatus.INSUFFICIENT_EVIDENCE
    assert result.report is not None
    assert result.report.conclusion is None
    assert adapter.calls == [{}]


def test_unproven_model_conclusion_is_downgraded_to_insufficient_evidence(
    tmp_path: Path,
) -> None:
    investigator, store, _, _ = _runtime(tmp_path, "unsupported_claim")

    result = asyncio.run(investigator.run(_incident(store)))

    assert result.status is IncidentStatus.INSUFFICIENT_EVIDENCE
    assert result.report is not None
    assert result.report.conclusion is None
    assert "有效证据引用" in result.report.unknowns[-1]


def test_model_failure_budget_and_cancellation_have_explicit_stop_reasons(
    tmp_path: Path,
) -> None:
    unavailable, unavailable_store, _, _ = _runtime(tmp_path, "unavailable")
    unavailable_result = asyncio.run(unavailable.run(_incident(unavailable_store)))
    assert unavailable_result.status is IncidentStatus.INVESTIGATION_UNAVAILABLE
    assert unavailable_result.report is not None
    assert unavailable_result.report.stop_reason is InvestigationStopReason.MODEL_UNAVAILABLE

    limited, limited_store, adapter, _ = _runtime(
        tmp_path,
        "endless",
        limits=InvestigationLimits(max_model_rounds=1, max_tool_calls=1),
    )
    limited_result = asyncio.run(limited.run(_incident(limited_store)))
    assert limited_result.status is IncidentStatus.BUDGET_EXHAUSTED
    assert adapter.calls == [{}]

    cancelled, cancelled_store, cancelled_adapter, _ = _runtime(tmp_path, "cancelled")
    token = InvestigationCancellation()
    token.cancel()
    cancelled_result = asyncio.run(cancelled.run(_incident(cancelled_store), cancellation=token))
    assert cancelled_result.status is IncidentStatus.CANCELLED
    assert cancelled_adapter.calls == []


class MutableOverview:
    """生成正常或仅本机可用的同一服务快照。"""

    def __init__(self) -> None:
        self.local_only = False

    def __call__(self) -> ResourceOverview:
        return OverviewService(
            nodes=lambda: KnownNodesOverview(
                source=OverviewSource.COORDINATOR_DIRECTORY,
                evidence_at=NOW,
                freshness=OverviewFreshness.FRESH,
                items=(
                    KnownNodeOverview(
                        node_id=NODE,
                        display_name="node",
                        state=KnownNodeState.ONLINE,
                        source=OverviewSource.COORDINATOR_DIRECTORY,
                        evidence_at=NOW,
                        freshness=OverviewFreshness.FRESH,
                    ),
                ),
            ),
            services=lambda: KnownServicesOverview(
                source=OverviewSource.COORDINATOR_DIRECTORY,
                evidence_at=NOW,
                freshness=OverviewFreshness.FRESH,
                items=(
                    KnownServiceOverview(
                        service_id=SERVICE,
                        node_id=NODE,
                        protocol=None,
                        port=8080,
                        accessibility=(
                            ServiceAccessibility.LOOPBACK
                            if self.local_only
                            else ServiceAccessibility.NETWORK
                        ),
                        state=KnownServiceState.AVAILABLE,
                        source=OverviewSource.COORDINATOR_DIRECTORY,
                        evidence_at=NOW,
                        freshness=OverviewFreshness.FRESH,
                    ),
                ),
            ),
            clock=lambda: NOW,
        ).view()


class CountingRunner:
    def __init__(self) -> None:
        self.calls = 0

    async def run(self, incident: Incident) -> Incident:
        self.calls += 1
        return incident


def test_background_observer_calls_no_model_on_normal_refresh_and_one_run_per_incident(
    tmp_path: Path,
) -> None:
    overview = MutableOverview()
    runner = CountingRunner()
    service = IncidentObservationService(
        overview,
        SQLiteIncidentStore(tmp_path / "observer.sqlite3"),
        detector=SnapshotDiffDetector(confirmations_required=2),
        investigator=runner,
    )

    assert asyncio.run(service.observe_once()).incidents == ()
    assert asyncio.run(service.observe_once()).incidents == ()
    assert runner.calls == 0
    overview.local_only = True
    assert asyncio.run(service.observe_once()).incidents == ()
    confirmed = asyncio.run(service.observe_once())
    assert len(confirmed.incidents) == 1
    assert runner.calls == 1
    assert asyncio.run(service.observe_once()).incidents == ()
    assert runner.calls == 1
