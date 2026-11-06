"""事件库保留规则、旧数据清理、文件整理和后台清理循环。"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from tunnelminion.domain.identifiers import NodeId, ServiceId, SnapshotId, ThreadId
from tunnelminion.incident import maintenance as maintenance_module
from tunnelminion.incident import storage as storage_module
from tunnelminion.incident.contracts import (
    Incident,
    IncidentEventType,
    IncidentStatus,
    NormalizedSnapshot,
    SnapshotDiffEvent,
    SnapshotFreshness,
    SnapshotNode,
    SnapshotNodeState,
    SnapshotObjectKind,
    SnapshotService,
    SnapshotServiceState,
    SnapshotSource,
)
from tunnelminion.incident.maintenance import maintain_incident_store
from tunnelminion.incident.storage import SQLiteIncidentStore

NOW = datetime(2026, 11, 5, 12, tzinfo=UTC)
NODE = NodeId("node_0123456789abcdef0123456789abcdef")


def _service_id(index: int) -> ServiceId:
    return ServiceId(f"service_{index:032x}")


def _snapshot(revision: int, *, at: datetime = NOW, services: int = 1) -> NormalizedSnapshot:
    return NormalizedSnapshot(
        snapshot_id=SnapshotId(f"snapshot_{revision:032x}"),
        observed_at=at,
        revision=revision,
        nodes=(
            SnapshotNode(
                node_id=NODE,
                state=SnapshotNodeState.ONLINE,
                source=SnapshotSource.LOCAL_OBSERVATION,
                freshness=SnapshotFreshness.FRESH,
            ),
        ),
        services=tuple(
            SnapshotService(
                service_id=_service_id(index),
                node_id=NODE,
                state=SnapshotServiceState.AVAILABLE,
                source=SnapshotSource.LOCAL_OBSERVATION,
                freshness=SnapshotFreshness.FRESH,
                port=60000 + index % 5000,
            )
            for index in range(services)
        ),
    )


def _event(
    index: int,
    *,
    at: datetime = NOW,
    event_type: IncidentEventType = IncidentEventType.SERVICE_ADDED,
    baseline: int = 1,
    current: int = 2,
) -> SnapshotDiffEvent:
    node = event_type is IncidentEventType.NODE_OFFLINE
    return SnapshotDiffEvent(
        event_type=event_type,
        object_kind=SnapshotObjectKind.NODE if node else SnapshotObjectKind.SERVICE,
        object_id=str(NODE) if node else str(_service_id(index)),
        target_node_id=NODE,
        baseline_snapshot_id=SnapshotId(f"snapshot_{baseline:032x}"),
        current_snapshot_id=SnapshotId(f"snapshot_{current:032x}"),
        baseline_revision=baseline,
        current_revision=current,
        observed_at=at,
        source=SnapshotSource.LOCAL_OBSERVATION,
        dedup_key=f"sha256:{hashlib.sha256(f'{index}:{event_type}'.encode()).hexdigest()}",
        port=None if node else 60000 + index,
    )


def _record(
    store: SQLiteIncidentStore,
    index: int,
    *,
    status: IncidentStatus = IncidentStatus.PENDING,
    **event: object,
) -> Incident:
    incident = store.record_event(_event(index, **event))  # pyright: ignore[reportArgumentType]
    if status is not IncidentStatus.PENDING:
        incident = incident.model_copy(update={"status": status})
        store.put_incident(incident)
    return incident


def _prune_all(store: SQLiteIncidentStore, *, batch: int = 500) -> int:
    total = 0
    while deleted := store.prune_batch(batch=batch):
        total += deleted
    return total


def _count(path: Path, table: str) -> int:
    with sqlite3.connect(path) as connection:
        return int(connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])


def test_upgrade_removes_old_uninvestigated_service_events_only(tmp_path: Path) -> None:
    path = tmp_path / "incidents.sqlite3"
    old = SQLiteIncidentStore(path)
    with sqlite3.connect(path) as connection:
        # 模拟旧版本留下的库：没有版本号。
        connection.execute("PRAGMA user_version=0")
    for index in range(30):
        _record(old, index, at=NOW - timedelta(hours=1))
    _record(old, 100, event_type=IncidentEventType.SERVICE_REMOVED, at=NOW - timedelta(hours=1))
    kept_node = _record(old, 101, event_type=IncidentEventType.NODE_OFFLINE)
    kept_report = _record(old, 102, status=IncidentStatus.CLOSED)

    upgraded = SQLiteIncidentStore(path)
    # 升级后新出现的服务事件不受影响。
    later = _record(upgraded, 103, at=NOW + timedelta(minutes=1))
    assert upgraded.prune_batch(batch=10) == 10
    assert _prune_all(upgraded, batch=10) == 21
    remaining = {str(item.incident_id) for item in upgraded.list_recent(limit=100)}
    assert remaining == {
        str(kept_node.incident_id),
        str(kept_report.incident_id),
        str(later.incident_id),
    }
    with sqlite3.connect(path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM incident_store_meta").fetchone()[0] == 0
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 1
    # 再打开不会重新标记：以后的服务事件按普通保留规则处理。
    reopened = SQLiteIncidentStore(path)
    assert reopened.prune_batch() == 0
    assert str(later.incident_id) in {str(item.incident_id) for item in reopened.list_recent()}


def test_new_and_empty_stores_have_nothing_to_clean(tmp_path: Path) -> None:
    store = SQLiteIncidentStore(tmp_path / "fresh.sqlite3")
    assert store.prune_batch() == 0
    old_empty = tmp_path / "old-empty.sqlite3"
    SQLiteIncidentStore(old_empty)
    with sqlite3.connect(old_empty) as connection:
        connection.execute("PRAGMA user_version=0")
    SQLiteIncidentStore(old_empty)
    assert _count(old_empty, "incident_store_meta") == 0


def test_old_events_stay_until_pushed_beyond_the_count_limit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(storage_module, "INCIDENT_RETENTION_MAX", 5)
    path = tmp_path / "incidents.sqlite3"
    store = SQLiteIncidentStore(path)
    # 很久以前调查过的事件不因为时间久就删，条数没超上限时一直留在页面上。
    concluded = _record(store, 1, status=IncidentStatus.CLOSED, at=NOW - timedelta(days=90))
    running = _record(store, 2, status=IncidentStatus.INVESTIGATING, at=NOW - timedelta(days=120))
    store.bind_thread(concluded.incident_id, ThreadId("thread_" + "1" * 32))
    store.bind_thread(running.incident_id, ThreadId("thread_" + "2" * 32))
    recent = [_record(store, 10 + index, at=NOW - timedelta(minutes=index)) for index in range(3)]
    assert _prune_all(store) == 0
    assert len(store.list_recent()) == 5

    later = [
        _record(store, 20 + index, at=NOW + timedelta(minutes=index + 1)) for index in range(5)
    ]
    assert _prune_all(store) == 4
    remaining = {str(item.incident_id) for item in store.list_recent()}
    # 留下最新的 5 条，加上不删的调查中事件；排在 5 条之外的从最旧的删起。
    assert remaining == {str(running.incident_id)} | {str(item.incident_id) for item in later}
    assert all(str(item.incident_id) not in remaining for item in recent)
    assert store.thread_for(concluded.incident_id) is None
    assert store.thread_for(running.incident_id) == ThreadId("thread_" + "2" * 32)
    assert _count(path, "incident_threads") == 1


def test_snapshots_keep_latest_and_those_referenced_by_visible_or_running_events(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(storage_module, "SNAPSHOT_REFERENCED_RECENT", 2)
    path = tmp_path / "incidents.sqlite3"
    store = SQLiteIncidentStore(path)
    for revision in range(1, 21):
        store.put_snapshot(_snapshot(revision))
    _record(store, 1, baseline=3, current=4, at=NOW - timedelta(hours=3))
    _record(store, 2, baseline=5, current=6, at=NOW - timedelta(hours=2))
    _record(store, 3, baseline=7, current=8, at=NOW - timedelta(hours=1))
    _record(
        store,
        4,
        status=IncidentStatus.INVESTIGATING,
        baseline=9,
        current=10,
        at=NOW - timedelta(days=2),
    )

    assert store.prune_batch(batch=3) == 3
    assert _prune_all(store) == 10
    with sqlite3.connect(path) as connection:
        revisions = [
            row[0]
            for row in connection.execute(
                "SELECT revision FROM incident_snapshots ORDER BY revision"
            )
        ]
    # 最近 2 条事件（5..8）、调查中的事件（9、10）和最新一份（20）。
    assert revisions == [5, 6, 7, 8, 9, 10, 20]
    assert store.latest_snapshot() == _snapshot(20)
    assert store.next_revision() == 21
    assert store.get_snapshot(SnapshotId(f"snapshot_{3:032x}")) is None


def test_prune_rejects_bad_batch(tmp_path: Path) -> None:
    store = SQLiteIncidentStore(tmp_path / "incidents.sqlite3")
    with pytest.raises(ValueError, match="每批"):
        store.prune_batch(batch=0)


def test_reclaim_space_shrinks_file_only_when_much_is_free(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(storage_module, "RECLAIM_MIN_FREE_BYTES", 256 * 1024)
    path = tmp_path / "incidents.sqlite3"
    store = SQLiteIncidentStore(path)
    for revision in range(1, 31):
        store.put_snapshot(_snapshot(revision, services=200))
    assert store.reclaim_space() is False
    size = path.stat().st_size
    assert size > 1024 * 1024

    assert _prune_all(store) == 29
    assert store.reclaim_space() is True
    assert path.stat().st_size < size / 5
    assert not (tmp_path / "incidents.sqlite3-wal").exists() or (
        (tmp_path / "incidents.sqlite3-wal").stat().st_size == 0
    )
    assert store.latest_snapshot() == _snapshot(30, services=200)
    store.assert_no_secret_material()


def test_maintenance_cleans_in_batches_reclaims_and_stops(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.INFO, logger="tunnelminion.incident.maintenance")
    store = SQLiteIncidentStore(tmp_path / "incidents.sqlite3")
    for revision in range(1, 6):
        store.put_snapshot(_snapshot(revision))
    stop = asyncio.Event()
    batches: list[int] = []
    prune = store.prune_batch

    def counting_prune(*, batch: int = 2) -> int:
        deleted = prune(batch=2)
        batches.append(deleted)
        return deleted

    store.prune_batch = counting_prune  # type: ignore[method-assign]
    reclaimed: list[bool] = []

    def recording_reclaim() -> bool:
        reclaimed.append(True)
        stop.set()
        return False

    store.reclaim_space = recording_reclaim  # type: ignore[method-assign]
    asyncio.run(asyncio.wait_for(maintain_incident_store(store, stop, pause_seconds=0), timeout=5))
    assert batches == [2, 2, 0] and reclaimed == [True]
    assert "事件库清理删除 4 行，未整理文件" in caplog.text

    # 什么都没删、也没整理时不记日志。
    caplog.clear()
    stop.clear()
    asyncio.run(asyncio.wait_for(maintain_incident_store(store, stop, pause_seconds=0), timeout=5))
    assert caplog.text == ""


def test_maintenance_stops_between_batches_without_reclaiming(tmp_path: Path) -> None:
    store = SQLiteIncidentStore(tmp_path / "incidents.sqlite3")
    stop = asyncio.Event()

    def prune_then_stop() -> int:
        stop.set()
        return 1

    def unexpected_reclaim() -> bool:
        raise AssertionError("停止后不再整理文件")

    store.prune_batch = prune_then_stop  # type: ignore[method-assign]
    store.reclaim_space = unexpected_reclaim  # type: ignore[method-assign]
    asyncio.run(asyncio.wait_for(maintain_incident_store(store, stop, pause_seconds=0), timeout=5))


def test_maintenance_failure_is_logged_without_details_and_retried(
    tmp_path: Path, caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = SQLiteIncidentStore(tmp_path / "incidents.sqlite3")
    stop = asyncio.Event()
    calls = 0
    error_message = "fixture-private-path"

    def failing_prune() -> int:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise sqlite3.OperationalError(error_message)
        stop.set()
        return 0

    store.prune_batch = failing_prune  # type: ignore[method-assign]
    store.reclaim_space = lambda: False  # type: ignore[method-assign]
    monkeypatch.setattr(maintenance_module, "MAINTENANCE_PAUSE_SECONDS", 0)
    asyncio.run(
        asyncio.wait_for(maintain_incident_store(store, stop, interval_seconds=0), timeout=5)
    )
    assert calls == 2
    [record] = caplog.records
    assert record.getMessage() == "事件库清理失败，下一轮再试"
    assert "OperationalError" in caplog.text and "fixture-private" not in caplog.text
