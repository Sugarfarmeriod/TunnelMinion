"""事件检测只盯首页显示、且连续出现满稳定门槛的服务，口径与巡检一致。"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from tunnelminion.coordinator.contracts import ServiceAccessibility
from tunnelminion.domain.identifiers import NodeId, ServiceId
from tunnelminion.incident.contracts import IncidentEventType, SnapshotDiffEvent
from tunnelminion.incident.observer import IncidentObservationService
from tunnelminion.incident.storage import SQLiteIncidentStore
from tunnelminion.patrol.contracts import PATROL_STABLE_SECONDS
from tunnelminion.web.incidents import incidents_overview
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

START = datetime(2026, 11, 5, 8, tzinfo=UTC)
NODE = NodeId("node_0123456789abcdef0123456789abcdef")
STABLE = timedelta(seconds=PATROL_STABLE_SECONDS)
ROUND = timedelta(seconds=30)


def _service(index: int) -> str:
    return f"service_{index:032x}"


class TimedOverview:
    """时间可推进的服务清单；`shown` 为 False 表示首页不显示（分档隐藏）。"""

    def __init__(self) -> None:
        self.now = START
        self.services: dict[str, tuple[int, bool]] = {}
        self.local_only: set[str] = set()

    def __call__(self) -> ResourceOverview:
        return OverviewService(
            nodes=lambda: KnownNodesOverview(
                source=OverviewSource.LOCAL_OBSERVATION,
                evidence_at=self.now,
                freshness=OverviewFreshness.FRESH,
                items=(
                    KnownNodeOverview(
                        node_id=NODE,
                        display_name="node",
                        state=KnownNodeState.ONLINE,
                        source=OverviewSource.LOCAL_OBSERVATION,
                        evidence_at=self.now,
                        freshness=OverviewFreshness.FRESH,
                    ),
                ),
            ),
            services=lambda: KnownServicesOverview(
                source=OverviewSource.LOCAL_OBSERVATION,
                evidence_at=self.now,
                freshness=OverviewFreshness.FRESH,
                items=tuple(
                    KnownServiceOverview(
                        service_id=ServiceId(service_id),
                        node_id=NODE,
                        display_name=f"服务 {port}" if shown else None,
                        port=port,
                        accessibility=(
                            ServiceAccessibility.LOOPBACK
                            if service_id in self.local_only
                            else ServiceAccessibility.NETWORK
                        ),
                        state=KnownServiceState.AVAILABLE,
                        source=OverviewSource.LOCAL_OBSERVATION,
                        evidence_at=self.now,
                        freshness=OverviewFreshness.FRESH,
                    )
                    for service_id, (port, shown) in self.services.items()
                ),
            ),
            clock=lambda: self.now,
        ).view()


def _rounds(
    observer: IncidentObservationService, overview: TimedOverview, count: int
) -> list[SnapshotDiffEvent]:
    events: list[SnapshotDiffEvent] = []
    for _ in range(count):
        overview.now += ROUND
        events.extend(item.event for item in asyncio.run(observer.observe_once()).incidents)
    return events


def _observer(
    tmp_path: Path, overview: TimedOverview
) -> tuple[IncidentObservationService, SQLiteIncidentStore]:
    store = SQLiteIncidentStore(tmp_path / "incidents.sqlite3")
    return IncidentObservationService(overview, store), store


def _kinds(events: list[SnapshotDiffEvent]) -> list[tuple[IncidentEventType, str]]:
    return [(item.event_type, item.object_id) for item in events]


def test_short_lived_and_hidden_ports_never_become_events(tmp_path: Path) -> None:
    overview = TimedOverview()
    overview.services = {_service(1): (8080, True)}
    observer, store = _observer(tmp_path, overview)
    assert _rounds(observer, overview, 3) == []

    # 临时程序每半分钟开关一个随机端口，有的首页显示，有的被分档隐藏；都不满稳定门槛。
    for index in range(40):
        overview.services[_service(100 + index)] = (60000 + index, index % 2 == 0)
        assert _rounds(observer, overview, 2) == []
        overview.services.pop(_service(100 + index))
        assert _rounds(observer, overview, 1) == []
    # 被隐藏的服务一直在、后来消失，也不记事件。
    overview.services[_service(2)] = (9000, False)
    assert _rounds(observer, overview, int(STABLE / ROUND) + 3) == []
    overview.services.pop(_service(2))
    assert _rounds(observer, overview, 3) == []
    assert store.list_recent() == ()


def test_stable_shown_service_is_added_once_and_removed_with_its_port(tmp_path: Path) -> None:
    overview = TimedOverview()
    overview.services = {_service(1): (8080, True)}
    observer, store = _observer(tmp_path, overview)
    assert _rounds(observer, overview, 3) == []

    overview.services[_service(5)] = (61234, True)
    events = _rounds(observer, overview, int(STABLE / ROUND) + 4)
    assert _kinds(events) == [(IncidentEventType.SERVICE_ADDED, _service(5))]
    assert events[0].port == 61234

    overview.services.pop(_service(5))
    events = _rounds(observer, overview, 3)
    assert _kinds(events) == [(IncidentEventType.SERVICE_REMOVED, _service(5))]
    # 服务已不在清单里，网页仍能用事件记下的端口说清是哪个服务。
    [removed, _added] = incidents_overview(store).items
    assert removed.port == 61234


def test_services_present_at_start_are_not_new_and_are_watched_once_stable(
    tmp_path: Path,
) -> None:
    overview = TimedOverview()
    overview.services = {_service(1): (8080, True), _service(2): (8081, True)}
    observer, _store = _observer(tmp_path, overview)
    # 启动时就在的服务满门槛后不算新出现。
    assert _rounds(observer, overview, int(STABLE / ROUND) + 4) == []

    overview.local_only.add(_service(1))
    overview.services.pop(_service(2))
    events = _rounds(observer, overview, 3)
    assert sorted(_kinds(events)) == sorted(
        [
            (IncidentEventType.LOCAL_ONLY, _service(1)),
            (IncidentEventType.SERVICE_REMOVED, _service(2)),
        ]
    )


def test_changes_before_start_services_are_stable_are_not_events(tmp_path: Path) -> None:
    overview = TimedOverview()
    overview.services = {_service(1): (8080, True)}
    observer, store = _observer(tmp_path, overview)
    assert _rounds(observer, overview, 3) == []
    overview.services.pop(_service(1))
    assert _rounds(observer, overview, 3) == []
    assert store.list_recent() == ()


def test_hiding_or_showing_a_long_running_service_is_not_an_event(tmp_path: Path) -> None:
    overview = TimedOverview()
    overview.services = {_service(1): (8080, True)}
    observer, store = _observer(tmp_path, overview)
    assert _rounds(observer, overview, 3) == []
    # 启动后才出现、一直隐藏的服务，满门槛后被标成“是我的服务”：不算新出现。
    overview.services[_service(3)] = (7000, False)
    assert _rounds(observer, overview, int(STABLE / ROUND) + 4) == []
    overview.services[_service(3)] = (7000, True)
    assert _rounds(observer, overview, 3) == []
    # 再标成隐藏：服务还在，不算消失；之后真的关掉也不再记。
    overview.services[_service(3)] = (7000, False)
    assert _rounds(observer, overview, 3) == []
    overview.services.pop(_service(3))
    assert _rounds(observer, overview, 3) == []
    assert store.list_recent() == ()


def test_stable_threshold_is_bounded(tmp_path: Path) -> None:
    store = SQLiteIncidentStore(tmp_path / "incidents.sqlite3")
    with pytest.raises(ValueError, match="稳定门槛"):
        IncidentObservationService(TimedOverview(), store, stable_seconds=-1)
