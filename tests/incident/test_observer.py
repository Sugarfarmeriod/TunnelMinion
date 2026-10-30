"""观察轮次恢复、自动调查分层、并发和冷却测试。"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from datetime import timedelta
from pathlib import Path

import pytest
from fastapi import FastAPI
from tests.incident.test_investigation import NODE, NOW, SERVICE, MutableOverview

from tunnelminion.agent.service_marks import ServiceMark, service_mark_keys
from tunnelminion.agent.service_observation import (
    compute_observed_service_id,
    select_service_presentations,
)
from tunnelminion.agent.services import (
    EvidenceConfidence,
    RemoteServiceSummary,
    ServiceAccessibility,
)
from tunnelminion.coordinator.contracts import ServiceProtocol
from tunnelminion.incident import observer as observer_module
from tunnelminion.incident.contracts import Incident, IncidentStatus
from tunnelminion.incident.observer import (
    IncidentObservationService,
    incident_observation_lifespan,
)
from tunnelminion.incident.snapshot import SnapshotDiffDetector
from tunnelminion.incident.storage import SQLiteIncidentStore
from tunnelminion.platforms.process_origin import ProcessOrigin
from tunnelminion.web.overview import OverviewSource, ResourceOverview


class Runner:
    """只记录调用，可阻塞或失败。"""

    def __init__(self, *, blocked: bool = False, fail: bool = False) -> None:
        self.calls: list[Incident] = []
        self.entered = asyncio.Event()
        self.release = asyncio.Event()
        self.finished = asyncio.Event()
        self.blocked = blocked
        self.fail = fail
        self.error_message = "fixture-private-error"

    async def run(self, incident: Incident) -> Incident:
        self.calls.append(incident)
        self.entered.set()
        try:
            if self.blocked:
                await self.release.wait()
            if self.fail:
                raise RuntimeError(self.error_message)
            return incident
        finally:
            self.finished.set()


def test_failed_round_logs_sanitized_exception_and_refreshes_next_interval(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    store = SQLiteIncidentStore(tmp_path / "round.sqlite3")
    stop = asyncio.Event()
    refreshes = 0
    error_message = "fixture-private-error"

    async def refresh() -> None:
        nonlocal refreshes
        refreshes += 1
        if refreshes == 1:
            try:
                raise ValueError("fixture-private-cause")
            except ValueError as exc:
                raise RuntimeError(error_message) from exc
        stop.set()

    observer = IncidentObservationService(MutableOverview(), store, before_snapshot=refresh)
    observer._interval_seconds = 0  # pyright: ignore[reportPrivateUsage]
    asyncio.run(asyncio.wait_for(observer.run(stop), timeout=1))

    assert refreshes == 2 and store.latest_snapshot() is not None
    [record] = caplog.records
    assert record.name == "tunnelminion.incident.observer"
    assert record.exc_info is not None and record.exc_info[2] is not None
    assert "RuntimeError" in caplog.text and "fixture-private" not in caplog.text


def test_warm_up_refreshes_services_at_once_without_taking_a_snapshot(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    store = SQLiteIncidentStore(tmp_path / "warm.sqlite3")
    stop = asyncio.Event()
    refreshes = 0
    error_message = "fixture-private-error"

    async def refresh() -> None:
        nonlocal refreshes
        refreshes += 1
        if refreshes == 1:
            raise RuntimeError(error_message)

    observer = IncidentObservationService(MutableOverview(), store, before_snapshot=refresh)

    async def scenario() -> None:
        task = asyncio.create_task(observer.run(stop, warm_up=True))
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        # 刚启动就刷新了一次服务清单，事件快照仍等一个周期后的第一轮。
        assert refreshes == 1 and store.latest_snapshot() is None
        stop.set()
        await task

    asyncio.run(scenario())
    [record] = caplog.records
    assert record.getMessage().startswith("启动时刷新服务失败")
    assert "fixture-private" not in caplog.text

    # 没有刷新动作或已经要停时不做预热。
    idle = IncidentObservationService(MutableOverview(), store)
    asyncio.run(idle.run(stop, warm_up=True))
    stopped = IncidentObservationService(MutableOverview(), store, before_snapshot=refresh)
    asyncio.run(stopped.run(stop, warm_up=True))
    assert refreshes == 1


@pytest.mark.parametrize(("failures", "expected_calls"), [(1, 2), (5, 3)])
def test_warm_up_retries_after_seconds_instead_of_a_whole_cycle(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
    failures: int,
    expected_calls: int,
) -> None:
    """刚开机第一次扫描超时后几秒内再试，最多试三次；周期本身仍是 30 秒。"""
    monkeypatch.setattr(observer_module, "_WARM_UP_RETRY_SECONDS", 0)
    stop = asyncio.Event()
    calls = 0
    error_message = "fixture-private-error"

    async def refresh() -> None:
        nonlocal calls
        calls += 1
        if calls <= failures:
            raise RuntimeError(error_message)

    observer = IncidentObservationService(
        MutableOverview(), SQLiteIncidentStore(tmp_path / "retry.sqlite3"), before_snapshot=refresh
    )

    async def scenario() -> None:
        task = asyncio.create_task(observer.run(stop, warm_up=True))
        for _ in range(50):
            await asyncio.sleep(0)
        stop.set()
        await task

    asyncio.run(scenario())
    assert calls == expected_calls
    messages = [record.getMessage() for record in caplog.records]
    assert len(messages) == min(failures, expected_calls)
    assert messages[-1].endswith("下个周期重试" if failures >= expected_calls else "稍后再试")
    assert "fixture-private" not in caplog.text


def test_cancelling_refresh_stops_promptly_without_error_log(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    entered = asyncio.Event()

    async def refresh() -> None:
        entered.set()
        await asyncio.Event().wait()

    observer = IncidentObservationService(
        MutableOverview(), SQLiteIncidentStore(tmp_path / "cancel.sqlite3"), before_snapshot=refresh
    )
    observer._interval_seconds = 0  # pyright: ignore[reportPrivateUsage]

    async def scenario() -> None:
        task = asyncio.create_task(observer.run(asyncio.Event()))
        await asyncio.wait_for(entered.wait(), timeout=1)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, timeout=1)

    asyncio.run(scenario())
    assert caplog.records == []


@pytest.mark.parametrize("shutdown", ["stop", "cancel", "lifespan"])
def test_blocked_investigation_allows_refresh_and_is_awaited_on_shutdown(
    tmp_path: Path, shutdown: str
) -> None:
    overview = MutableOverview()
    runner = Runner(blocked=True)
    store = SQLiteIncidentStore(tmp_path / "background.sqlite3")
    refreshes = 0

    async def refresh() -> None:
        nonlocal refreshes
        refreshes += 1

    observer = IncidentObservationService(
        overview,
        store,
        investigator=runner,
        before_snapshot=refresh,
        detector=SnapshotDiffDetector(confirmations_required=1),
    )

    @asynccontextmanager
    async def base(_app: FastAPI) -> AsyncGenerator[None, None]:
        yield

    async def observe() -> None:
        await observer.observe_once()
        await observer.observe_once()
        overview.local_only = True
        result = await asyncio.wait_for(observer.observe_once(), timeout=1)
        assert len(result.incidents) == 1
        assert result.incidents[0].status is IncidentStatus.PENDING
        await asyncio.wait_for(runner.entered.wait(), timeout=1)
        refreshed = await asyncio.wait_for(observer.observe_once(), timeout=1)
        assert refreshed.snapshot.revision == result.snapshot.revision + 1
        # 由 lifespan 托管时，后台循环启动后先预热刷新一次。
        assert refreshes == 4 + (shutdown == "lifespan") and not runner.finished.is_set()

    async def scenario() -> None:
        if shutdown == "lifespan":
            async with incident_observation_lifespan(base, observer, store)(FastAPI()):
                await observe()
        else:
            await observe()
            stop = asyncio.Event()
            task = asyncio.create_task(observer.run(stop))
            await asyncio.sleep(0)
            if shutdown == "stop":
                stop.set()
                await asyncio.wait_for(task, timeout=1)
            else:
                task.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await asyncio.wait_for(task, timeout=1)
        assert runner.finished.is_set()
        assert observer._active == {}  # pyright: ignore[reportPrivateUsage]

    asyncio.run(scenario())


def test_only_map_show_and_mine_services_are_investigated(tmp_path: Path) -> None:
    origins = (
        ProcessOrigin.TERMINAL,
        ProcessOrigin.UNKNOWN,
        ProcessOrigin.SYSTEM,
        ProcessOrigin.UNKNOWN,
        ProcessOrigin.TERMINAL,
    )
    inventory = tuple(
        RemoteServiceSummary(
            node_id=NODE,
            protocol="tcp",
            address="127.0.0.1",
            port=18080 + index,
            process_pid=100 + index,
            process_name=f"fixture{index}",
            origin=origin,
            accessibility=ServiceAccessibility.LOCAL_ONLY,
            confidence=EvidenceConfidence.HIGH,
            evidence=(),
        )
        for index, origin in enumerate(origins)
    )
    keys = service_mark_keys(inventory)
    names, _ = select_service_presentations(
        NODE, inventory, marks={keys[3]: ServiceMark.MINE, keys[4]: ServiceMark.HIDDEN}
    )
    mutable = MutableOverview()
    mutable.services = ()

    def overview() -> ResourceOverview:
        value = mutable()
        return value.model_copy(
            update={
                "services": value.services.model_copy(
                    update={
                        "items": tuple(
                            item.model_copy(
                                update={
                                    "display_name": names.get(str(item.service_id)),
                                    "source": OverviewSource.LOCAL_OBSERVATION,
                                }
                            )
                            for item in value.services.items
                        )
                    }
                )
            }
        )

    runner = Runner()
    store = SQLiteIncidentStore(tmp_path / "tiers.sqlite3")
    observer = IncidentObservationService(
        overview,
        store,
        investigator=runner,
        detector=SnapshotDiffDetector(confirmations_required=1),
    )

    async def scenario() -> None:
        await observer.observe_once()
        await observer.observe_once()
        mutable.services = tuple(
            (
                compute_observed_service_id(NODE, ServiceProtocol.TCP, item.address, item.port),
                item.port,
            )
            for item in inventory
        )
        result = await observer.observe_once()
        await asyncio.sleep(0)
        assert len(result.incidents) == len(store.list_recent()) == 5
        assert {item.event.object_id for item in runner.calls} == set(names)
        assert len(runner.calls) == 2

    asyncio.run(scenario())


def test_service_cooldown_counts_all_event_types_and_expires_at_one_hour(tmp_path: Path) -> None:
    overview = MutableOverview()
    runner = Runner()
    now = NOW
    observer = IncidentObservationService(
        overview,
        SQLiteIncidentStore(tmp_path / "cooldown.sqlite3"),
        investigator=runner,
        detector=SnapshotDiffDetector(confirmations_required=2),
        clock=lambda: now,
    )

    async def change() -> Incident:
        assert (await observer.observe_once()).incidents == ()
        [incident] = (await observer.observe_once()).incidents
        await asyncio.sleep(0)
        return incident

    async def scenario() -> None:
        nonlocal now
        await observer.observe_once()
        await observer.observe_once()
        overview.services = ()
        removed = await change()
        assert removed.event.event_type == "service_removed" and len(runner.calls) == 1
        now += timedelta(seconds=3599)
        overview.services = ((SERVICE, 8080),)
        await change()
        assert len(runner.calls) == 1
        now += timedelta(seconds=1)
        overview.local_only = True
        await change()
        assert len(runner.calls) == 2
        assert len(observer._store.list_recent()) == 3  # pyright: ignore[reportPrivateUsage]

    asyncio.run(scenario())


def test_investigation_failure_is_logged_without_stopping_refresh(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    overview = MutableOverview()
    runner = Runner(fail=True)
    observer = IncidentObservationService(
        overview,
        SQLiteIncidentStore(tmp_path / "failure.sqlite3"),
        investigator=runner,
        detector=SnapshotDiffDetector(confirmations_required=1),
    )

    async def scenario() -> None:
        await observer.observe_once()
        await observer.observe_once()
        overview.local_only = True
        await observer.observe_once()
        await asyncio.sleep(0)
        assert observer._active == {}  # pyright: ignore[reportPrivateUsage]
        assert (await observer.observe_once()).snapshot.revision == 4

    asyncio.run(scenario())
    [record] = caplog.records
    assert record.exc_info is not None
    assert "fixture-private" not in caplog.text


def test_events_covered_elsewhere_are_recorded_without_investigation(tmp_path: Path) -> None:
    overview = MutableOverview()
    runner = Runner()
    store = SQLiteIncidentStore(tmp_path / "covered.sqlite3")
    observer = IncidentObservationService(
        overview,
        store,
        investigator=runner,
        detector=SnapshotDiffDetector(confirmations_required=1),
        skip_investigation=lambda event: event.event_type == "service_removed",
    )

    async def scenario() -> None:
        await observer.observe_once()
        await observer.observe_once()
        overview.services = ()
        [removed] = (await observer.observe_once()).incidents
        await asyncio.sleep(0)
        assert removed.event.event_type == "service_removed"
        assert runner.calls == [] and len(store.list_recent()) == 1
        overview.services = ((SERVICE, 8080),)
        await observer.observe_once()
        await asyncio.sleep(0)
        assert len(runner.calls) == 1

    asyncio.run(scenario())
