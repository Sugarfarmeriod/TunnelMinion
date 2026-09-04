"""规范化快照、固定差异、去重和重启恢复测试。"""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

from tunnelminion.coordinator.contracts import (
    ServiceAccessibility,
    ServiceLifecycle,
    ServiceProtocol,
)
from tunnelminion.domain.identifiers import (
    IncidentId,
    NodeId,
    RunId,
    ServiceId,
    SnapshotId,
    ThreadId,
    ToolRunId,
)
from tunnelminion.incident import snapshot as snapshot_module
from tunnelminion.incident.contracts import (
    EvidenceReference,
    Incident,
    IncidentEventType,
    IncidentHypothesis,
    IncidentReport,
    IncidentStatus,
    InvestigationStopReason,
    NormalizedSnapshot,
    SnapshotDiffEvent,
    SnapshotFreshness,
    SnapshotNode,
    SnapshotNodeState,
    SnapshotService,
    SnapshotServiceState,
    SnapshotSource,
)
from tunnelminion.incident.snapshot import SnapshotDiffDetector, assemble_overview_snapshot
from tunnelminion.incident.storage import SQLiteIncidentStore
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
)

NOW = datetime(2026, 9, 3, 8, tzinfo=UTC)
NODE = NodeId("node_0123456789abcdef0123456789abcdef")
NODE_TWO = NodeId("node_fedcba9876543210fedcba9876543210")
SERVICE = ServiceId("service_0123456789abcdef0123456789abcdef")
REMOVED = ServiceId("service_11111111111111111111111111111111")
ADDED = ServiceId("service_22222222222222222222222222222222")


def _snapshot(
    revision: int,
    *,
    nodes: tuple[SnapshotNode, ...],
    services: tuple[SnapshotService, ...],
    observed_at: datetime | None = None,
) -> NormalizedSnapshot:
    return NormalizedSnapshot(
        snapshot_id=SnapshotId(f"snapshot_{revision:032x}"),
        observed_at=observed_at or NOW,
        revision=revision,
        nodes=nodes,
        services=services,
    )


def _node(
    node_id: NodeId,
    state: SnapshotNodeState = SnapshotNodeState.ONLINE,
    freshness: SnapshotFreshness = SnapshotFreshness.FRESH,
) -> SnapshotNode:
    return SnapshotNode(
        node_id=node_id,
        state=state,
        source=SnapshotSource.COORDINATOR_DIRECTORY,
        freshness=freshness,
        evidence_at=NOW,
    )


def _service(
    service_id: ServiceId,
    *,
    state: SnapshotServiceState = SnapshotServiceState.AVAILABLE,
    freshness: SnapshotFreshness = SnapshotFreshness.FRESH,
    accessibility: ServiceAccessibility = ServiceAccessibility.NETWORK,
) -> SnapshotService:
    return SnapshotService(
        service_id=service_id,
        node_id=NODE,
        state=state,
        source=SnapshotSource.COORDINATOR_DIRECTORY,
        freshness=freshness,
        evidence_at=NOW,
        protocol=ServiceProtocol.HTTP,
        port=8080,
        accessibility=accessibility,
        lifecycle=ServiceLifecycle.ACTIVE,
    )


def _changed_pair() -> tuple[NormalizedSnapshot, NormalizedSnapshot]:
    baseline = _snapshot(
        1,
        nodes=(_node(NODE), _node(NODE_TWO)),
        services=(_service(SERVICE), _service(REMOVED)),
    )
    current = _snapshot(
        2,
        observed_at=NOW + timedelta(seconds=10),
        nodes=(
            _node(NODE, SnapshotNodeState.OFFLINE, SnapshotFreshness.STALE),
            _node(NODE_TWO),
        ),
        services=(
            _service(
                SERVICE,
                state=SnapshotServiceState.UNAVAILABLE,
                freshness=SnapshotFreshness.STALE,
                accessibility=ServiceAccessibility.LOOPBACK,
            ),
            _service(ADDED),
        ),
    )
    return baseline, current


def test_overview_snapshot_is_bounded_and_excludes_names_addresses_and_model_state() -> None:
    service = OverviewService(
        nodes=lambda: KnownNodesOverview(
            source=OverviewSource.COORDINATOR_DIRECTORY,
            evidence_at=NOW,
            freshness=OverviewFreshness.FRESH,
            items=(
                KnownNodeOverview(
                    node_id=NODE,
                    display_name="含业务名称的节点",
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
                    display_name="私有业务服务",
                    protocol=ServiceProtocol.HTTP,
                    port=8080,
                    access_address="http://private.example:8080/secret",
                    accessibility=ServiceAccessibility.NETWORK,
                    lifecycle=ServiceLifecycle.ACTIVE,
                    state=KnownServiceState.AVAILABLE,
                    source=OverviewSource.COORDINATOR_DIRECTORY,
                    evidence_at=NOW,
                    freshness=OverviewFreshness.FRESH,
                ),
            ),
        ),
        clock=lambda: NOW,
    )

    snapshot = assemble_overview_snapshot(service.view(), revision=7)
    payload = snapshot.model_dump_json()

    assert snapshot.revision == 7
    assert snapshot.services[0].port == 8080
    assert "私有业务" not in payload
    assert "private.example" not in payload
    assert "model_configuration" not in payload
    with pytest.raises(ValidationError):
        SnapshotService.model_validate(
            {**snapshot.services[0].model_dump(), "response_body": "secret"}
        )


def test_six_fixed_differences_require_confirmation_and_deduplicate() -> None:
    baseline, current = _changed_pair()
    detector = SnapshotDiffDetector(confirmations_required=2)

    assert detector.compare(baseline, baseline) == ()
    assert detector.compare(baseline, current) == ()
    events = detector.compare(baseline, current)

    assert {item.event_type for item in events} == set(IncidentEventType)
    assert len({item.dedup_key for item in events}) == len(events)
    assert detector.compare(baseline, current) == ()


def test_transient_change_does_not_create_incident() -> None:
    baseline, current = _changed_pair()
    detector = SnapshotDiffDetector(confirmations_required=2)

    assert detector.compare(baseline, current) == ()
    assert detector.compare(baseline, baseline) == ()
    assert detector.compare(baseline, current) == ()


def test_public_contract_redacts_credentials_and_rejects_unproven_conclusion() -> None:
    evidence = EvidenceReference(
        snapshot_id=SnapshotId("snapshot_00000000000000000000000000000001"),
        observed_at=NOW,
        summary="authorization:top-secret 已被读取",
    )
    hypothesis = IncidentHypothesis(
        hypothesis_id="hypothesis_0123456789abcdef",
        summary="可能原因 api_key=hidden",
        evidence=(evidence,),
    )

    assert "top-secret" not in evidence.summary
    assert "hidden" not in hypothesis.summary
    with pytest.raises(ValidationError, match="确认结论必须引用有效证据"):
        IncidentReport(
            conclusion="这是根因",
            stop_reason=InvestigationStopReason.EVIDENCE_SUFFICIENT,
        )


def test_store_persists_deduplicates_and_marks_running_investigation_interrupted(
    tmp_path: Path,
) -> None:
    path = tmp_path / "incidents.sqlite3"
    store = SQLiteIncidentStore(path)
    baseline, current = _changed_pair()
    store.put_snapshot(baseline)
    store.put_snapshot(current)
    event = SnapshotDiffDetector(confirmations_required=1).compare(baseline, current)[0]
    first = store.record_event(event)
    same = store.record_event(event)
    running = first.transition(
        IncidentStatus.INVESTIGATING,
        at=NOW + timedelta(seconds=20),
        run_id=RunId("run_0123456789abcdef0123456789abcdef"),
    )
    store.put_incident(running)

    reopened = SQLiteIncidentStore(path)
    recovered = reopened.recover_interrupted(at=NOW + timedelta(minutes=1))

    assert first.incident_id == same.incident_id
    assert len(reopened.list_recent()) == 1
    assert reopened.get_snapshot(baseline.snapshot_id) == baseline
    assert reopened.latest_snapshot() == current
    assert reopened.next_revision() == 3
    assert recovered[0].status is IncidentStatus.INTERRUPTED
    assert recovered[0].run_id == running.run_id
    assert recovered[0].report is not None
    assert recovered[0].report.stop_reason is InvestigationStopReason.INTERRUPTED
    reopened.assert_no_secret_material()
    assert Incident.model_validate_json(reopened.list_recent()[0].model_dump_json())


def test_incident_rejects_invalid_state_transition() -> None:
    baseline, current = _changed_pair()
    event = SnapshotDiffDetector(confirmations_required=1).compare(baseline, current)[0]
    incident = Incident(
        incident_id=IncidentId("incident_0123456789abcdef0123456789abcdef"),
        dedup_key=event.dedup_key,
        event=event,
        created_at=NOW,
        last_observed_at=NOW,
    )

    with pytest.raises(ValueError, match="不允许"):
        incident.transition(
            IncidentStatus.CONFIRMED,
            at=NOW + timedelta(seconds=1),
        )


def test_incident_thread_binding_is_separate_and_stable(tmp_path: Path) -> None:
    store = SQLiteIncidentStore(tmp_path / "threads.sqlite3")
    baseline, current = _changed_pair()
    event = SnapshotDiffDetector(confirmations_required=1).compare(baseline, current)[0]
    incident = store.record_event(event)
    thread = ThreadId("thread_0123456789abcdef0123456789abcdef")

    store.bind_thread(incident.incident_id, thread)
    store.bind_thread(incident.incident_id, thread)

    assert store.thread_for(incident.incident_id) == thread
    assert store.get(incident.incident_id) == incident
    with pytest.raises(ValueError, match="另一追问线程"):
        store.bind_thread(incident.incident_id, ThreadId.new())


def test_contract_and_storage_guards_reject_invalid_public_state(tmp_path: Path) -> None:
    baseline, current = _changed_pair()
    event = SnapshotDiffDetector(confirmations_required=1).compare(baseline, current)[0]
    incident = Incident(
        incident_id=IncidentId("incident_0123456789abcdef0123456789abcdef"),
        dedup_key=event.dedup_key,
        event=event,
        created_at=NOW,
        last_observed_at=NOW,
    )

    with pytest.raises(ValidationError, match="节点身份不得重复"):
        NormalizedSnapshot.model_validate(
            baseline.model_dump() | {"nodes": (*baseline.nodes, baseline.nodes[0])}
        )
    with pytest.raises(ValidationError, match="服务身份不得重复"):
        NormalizedSnapshot.model_validate(
            baseline.model_dump() | {"services": (*baseline.services, baseline.services[0])}
        )
    with pytest.raises(ValidationError, match="身份与类型不匹配"):
        SnapshotDiffEvent.model_validate(event.model_dump() | {"object_id": str(NODE)})
    with pytest.raises(ValidationError, match="必须且只能"):
        EvidenceReference(observed_at=NOW, summary="无引用")
    with pytest.raises(ValidationError, match="必须且只能"):
        EvidenceReference(
            snapshot_id=baseline.snapshot_id,
            tool_run_id=ToolRunId.new(),
            observed_at=NOW,
            summary="双引用",
        )
    with pytest.raises(ValidationError, match="不得早于"):
        Incident.model_validate(
            incident.model_dump() | {"last_observed_at": NOW - timedelta(seconds=1)}
        )
    with pytest.raises(ValidationError, match="去重键"):
        Incident.model_validate(incident.model_dump() | {"dedup_key": f"sha256:{'b' * 64}"})
    with pytest.raises(ValidationError, match="证据化结论"):
        Incident.model_validate(incident.model_dump() | {"status": "confirmed"})
    with pytest.raises(ValueError, match="迁移时间"):
        incident.transition(IncidentStatus.INVESTIGATING, at=datetime(2026, 9, 3, 9))
    with pytest.raises(ValueError, match="run ID"):
        incident.transition(IncidentStatus.INVESTIGATING, at=NOW)

    secret_event = event.model_copy(update={"object_id": "service_api_key=hidden"})
    with pytest.raises(ValueError, match="包含禁止"):
        incident.model_copy(update={"event": secret_event}).assert_no_secret_material()

    store = SQLiteIncidentStore(tmp_path / "guards.sqlite3")
    with pytest.raises(ValueError, match="列表上限"):
        store.list_recent(limit=0)
    with pytest.raises(KeyError, match="incident_not_found"):
        store.bind_thread(IncidentId.new(), ThreadId.new())
    with pytest.raises(ValueError, match="恢复时间"):
        store.recover_interrupted(at=datetime(2026, 9, 3, 9))
    with sqlite3.connect(store.path) as connection:
        connection.execute(
            "INSERT INTO incident_snapshots VALUES (?, ?, ?, ?)",
            ("snapshot_bad", 1, NOW.isoformat(), '{"api_key":"hidden"}'),
        )
    with pytest.raises(ValueError, match="包含禁止字段"):
        store.assert_no_secret_material()


def test_snapshot_fallbacks_and_confirmation_bounds() -> None:
    with pytest.raises(ValueError, match="确认次数"):
        SnapshotDiffDetector(confirmations_required=0)
    assert (
        snapshot_module._source("future-source")  # pyright: ignore[reportPrivateUsage]
        is SnapshotSource.UNKNOWN
    )
    assert (
        snapshot_module._freshness("future-freshness")  # pyright: ignore[reportPrivateUsage]
        is SnapshotFreshness.UNKNOWN
    )
