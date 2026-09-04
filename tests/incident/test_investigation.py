"""单 Agent 调查、只读工具边界、预算和后台触发测试。"""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path

import pytest
from fastapi import FastAPI
from pydantic import JsonValue

from tunnelminion.agent.context_contracts import ContextRequest
from tunnelminion.agent.context_runtime import ContextInvocation, ContextModelRuntime
from tunnelminion.coordinator.contracts import (
    ServiceAccessibility,
    ServiceProtocol,
)
from tunnelminion.domain.identifiers import NodeId, RunId, ServiceId, SnapshotId
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
    NormalizedSnapshot,
    SnapshotDiffEvent,
    SnapshotFreshness,
    SnapshotObjectKind,
    SnapshotService,
    SnapshotServiceState,
    SnapshotSource,
)
from tunnelminion.incident.investigation import (
    ConfiguredIncidentRunner,
    IncidentInvestigator,
    InvestigationCancellation,
    InvestigationLimits,
)
from tunnelminion.incident.observer import (
    IncidentObservationService,
    incident_observation_lifespan,
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
        if self.mode == "invalid_response":
            return ModelResponse()
        if self.mode == "snapshot_only":
            snapshot_id = "snapshot_00000000000000000000000000000002"
            return ModelResponse(
                content=json.dumps(
                    {
                        "hypotheses": [
                            {
                                "summary": "服务已经新增",
                                "status": "supported",
                                "evidence_refs": [snapshot_id],
                            }
                        ],
                        "facts": [
                            {
                                "statement": "快照记录了新增服务",
                                "evidence_refs": [snapshot_id],
                            }
                        ],
                        "unknowns": [],
                        "conclusion": "服务新增就是根因",
                        "stop_reason": "evidence_sufficient",
                    }
                )
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
        content = json.dumps(
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
        return ModelResponse(
            content=f"```json\n{content}\n```" if self.mode == "fenced" else content
        )

    @staticmethod
    def _latest_tool_run_id(request: ModelRequest) -> str:
        message = next(item for item in reversed(request.messages) if item.role == "tool")
        payload = json.loads(message.content)
        return str(payload["result"]["tool_run_id"])


class RaisingRuntime:
    def __init__(self, error: Exception) -> None:
        self.error = error

    async def invoke(
        self,
        request: ContextRequest,
        cancellation: CancellationToken | None = None,
    ) -> ContextInvocation:
        del request, cancellation
        raise self.error


class SlowRuntime:
    async def invoke(
        self,
        request: ContextRequest,
        cancellation: CancellationToken | None = None,
    ) -> ContextInvocation:
        del request, cancellation
        await asyncio.sleep(1)
        raise AssertionError("墙钟上限没有取消慢模型")


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


def _runtime_with_model(
    tmp_path: Path,
    name: str,
    model: RaisingRuntime | SlowRuntime,
    *,
    limits: InvestigationLimits | None = None,
    clock: object | None = None,
) -> tuple[IncidentInvestigator, SQLiteIncidentStore]:
    base, store, _, _ = _runtime(tmp_path, name)
    investigator = IncidentInvestigator(
        model,
        base._registry,  # pyright: ignore[reportPrivateUsage]
        base._tools,  # pyright: ignore[reportPrivateUsage]
        store,
        Platform.WINDOWS,
        limits=limits,
        clock=clock,  # type: ignore[arg-type]
    )
    return investigator, store


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


def test_investigator_context_includes_affected_service_details(tmp_path: Path) -> None:
    investigator, store, _, provider = _runtime(tmp_path, "success")
    service = SnapshotService(
        service_id=SERVICE,
        node_id=NODE,
        state=SnapshotServiceState.AVAILABLE,
        source=SnapshotSource.COORDINATOR_DIRECTORY,
        freshness=SnapshotFreshness.FRESH,
        evidence_at=NOW,
        protocol=ServiceProtocol.HTTP,
        port=54123,
        accessibility=ServiceAccessibility.NETWORK,
    )
    store.put_snapshot(
        NormalizedSnapshot(
            snapshot_id=SnapshotId("snapshot_00000000000000000000000000000001"),
            observed_at=NOW,
            revision=1,
            services=(service,),
        )
    )
    store.put_snapshot(
        NormalizedSnapshot(
            snapshot_id=SnapshotId("snapshot_00000000000000000000000000000002"),
            observed_at=NOW,
            revision=2,
            services=(service.model_copy(update={"accessibility": ServiceAccessibility.LOOPBACK}),),
        )
    )

    asyncio.run(investigator.run(_incident(store)))

    message = next(
        item.content
        for item in provider.requests[0].messages
        if item.content.startswith("以下是已脱敏的确定性 incident：")
    )
    payload = json.loads(message.partition("：")[2])
    affected = payload["affected_object"]
    assert affected["snapshot_id"] == "snapshot_00000000000000000000000000000002"
    assert affected["service_id"] == str(SERVICE)
    assert affected["protocol"] == "http"
    assert affected["port"] == 54123
    assert affected["accessibility"] == "loopback"


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


def test_snapshot_alone_cannot_confirm_root_cause(tmp_path: Path) -> None:
    investigator, store, adapter, _ = _runtime(tmp_path, "snapshot_only")

    result = asyncio.run(investigator.run(_incident(store)))

    assert result.status is IncidentStatus.INSUFFICIENT_EVIDENCE
    assert result.report is not None
    assert result.report.conclusion is None
    assert "至少需要一项只读工具证据" in result.report.unknowns[-1]
    assert adapter.calls == []


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


def test_configured_runner_marks_unavailable_without_starting_tools(tmp_path: Path) -> None:
    store = SQLiteIncidentStore(tmp_path / "configured-unavailable.sqlite3")
    registry = ToolRegistry()
    audit = InMemoryAuditSink()

    def unavailable() -> ScriptedProvider:
        raise ProviderError(ProviderErrorCode.MODEL_NOT_FOUND, "not configured")

    runner = ConfiguredIncidentRunner(
        unavailable,
        registry,
        ToolRuntime(registry, Platform.WINDOWS, audit),
        store,
        Platform.WINDOWS,
        clock=lambda: NOW,
    )

    result = asyncio.run(runner.run(_incident(store)))

    assert result.status is IncidentStatus.INVESTIGATION_UNAVAILABLE
    assert result.report is not None
    assert result.report.stop_reason is InvestigationStopReason.MODEL_UNAVAILABLE
    assert audit.records == []


def test_investigator_rejects_invalid_lifecycle_and_model_outputs(tmp_path: Path) -> None:
    successful, store, _, _ = _runtime(tmp_path, "success-state")
    finished = asyncio.run(successful.run(_incident(store)))
    with pytest.raises(ValueError, match="可以启动调查"):
        asyncio.run(successful.run(finished))
    assert (
        successful._with_initial_hypothesis(  # pyright: ignore[reportPrivateUsage]
            finished
        )
        is finished
    )

    invalid, invalid_store, _, _ = _runtime(tmp_path, "invalid_response")
    invalid_result = asyncio.run(invalid.run(_incident(invalid_store)))
    assert invalid_result.status is IncidentStatus.FAILED

    fenced, fenced_store, _, _ = _runtime(tmp_path, "fenced")
    fenced_result = asyncio.run(fenced.run(_incident(fenced_store)))
    assert fenced_result.status is IncidentStatus.CONFIRMED

    naive, naive_store, _, _ = _runtime(tmp_path, "naive-clock")
    naive._clock = lambda: datetime(2026, 9, 3, 9)  # pyright: ignore[reportPrivateUsage]
    with pytest.raises(ValueError, match="时区"):
        asyncio.run(naive.run(_incident(naive_store)))


def test_investigator_outer_failures_and_wall_clock_limit(tmp_path: Path) -> None:
    provider_error = ProviderError(ProviderErrorCode.NETWORK_UNREACHABLE, "offline")
    unavailable, unavailable_store = _runtime_with_model(
        tmp_path, "outer-provider", RaisingRuntime(provider_error), clock=lambda: NOW
    )
    assert (
        asyncio.run(unavailable.run(_incident(unavailable_store))).status
        is IncidentStatus.INVESTIGATION_UNAVAILABLE
    )

    malformed, malformed_store = _runtime_with_model(
        tmp_path, "outer-invalid", RaisingRuntime(ValueError("bad")), clock=lambda: NOW
    )
    assert asyncio.run(malformed.run(_incident(malformed_store))).status is IncidentStatus.FAILED

    slow, slow_store = _runtime_with_model(
        tmp_path,
        "wall-clock",
        SlowRuntime(),
        limits=InvestigationLimits(timeout_seconds=0.1),
        clock=lambda: NOW,
    )
    assert asyncio.run(slow.run(_incident(slow_store))).status is IncidentStatus.BUDGET_EXHAUSTED


def test_configured_runner_uses_provider_when_available(tmp_path: Path) -> None:
    base, store, _, provider = _runtime(tmp_path, "configured-success")
    runner = ConfiguredIncidentRunner(
        lambda: provider,
        base._registry,  # pyright: ignore[reportPrivateUsage]
        base._tools,  # pyright: ignore[reportPrivateUsage]
        store,
        Platform.WINDOWS,
        clock=lambda: NOW,
    )

    assert asyncio.run(runner.run(_incident(store))).status is IncidentStatus.CONFIRMED


def test_observer_guard_loop_and_duplicate_run_shortcuts(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="观察周期"):
        IncidentObservationService(
            MutableOverview(),
            SQLiteIncidentStore(tmp_path / "invalid-interval.sqlite3"),
            interval_seconds=0,
        )

    store = SQLiteIncidentStore(tmp_path / "observer-branches.sqlite3")
    service = IncidentObservationService(MutableOverview(), store)
    incident = _incident(store)
    assert asyncio.run(service._investigate_once(incident)) is incident  # pyright: ignore[reportPrivateUsage]
    service._investigator = CountingRunner()  # pyright: ignore[reportPrivateUsage]
    service._active.add(str(incident.incident_id))  # pyright: ignore[reportPrivateUsage]
    assert asyncio.run(service._investigate_once(incident)) is incident  # pyright: ignore[reportPrivateUsage]

    loop_store = SQLiteIncidentStore(tmp_path / "observer-loop.sqlite3")
    stop = asyncio.Event()
    overview = MutableOverview()
    observations = 0

    def stop_after_second_observation() -> ResourceOverview:
        nonlocal observations
        observations += 1
        if observations == 2:
            stop.set()
        return overview()

    looping = IncidentObservationService(stop_after_second_observation, loop_store)
    looping._interval_seconds = 0  # pyright: ignore[reportPrivateUsage]

    async def run_loop() -> None:
        await looping.run(stop)

    asyncio.run(run_loop())
    assert loop_store.latest_snapshot() is not None


def test_observation_lifespan_recovers_interrupted_and_stops_background_task(
    tmp_path: Path,
) -> None:
    store = SQLiteIncidentStore(tmp_path / "lifespan.sqlite3")
    running = _incident(store).transition(
        IncidentStatus.INVESTIGATING,
        at=NOW,
        run_id=RunId.new(),
    )
    store.put_incident(running)
    overview = MutableOverview()
    observer = IncidentObservationService(overview, store, interval_seconds=1)
    entered = False
    exited = False

    @asynccontextmanager
    async def base(_app: FastAPI) -> AsyncGenerator[None, None]:
        nonlocal entered, exited
        entered = True
        try:
            yield
        finally:
            exited = True

    async def scenario() -> None:
        lifespan = incident_observation_lifespan(
            base,
            observer,
            store,
            clock=lambda: NOW,
        )
        async with lifespan(FastAPI()):
            for _ in range(10):
                if store.latest_snapshot() is not None:
                    break
                await asyncio.sleep(0)

    asyncio.run(scenario())

    recovered = store.get(running.incident_id)
    assert entered and exited
    assert recovered is not None and recovered.status is IncidentStatus.INTERRUPTED
    assert store.latest_snapshot() is not None
