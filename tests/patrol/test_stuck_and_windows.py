"""巡检：只拿服务自己以前的样子判断卡住；卡住的自动修单独打开；Windows 服务的启停授权。"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
from tests.patrol.fakes import PHOTOS, PROGRAM, PatrolHarness, entry
from tests.repair.factories import NOW

from tunnelminion.domain.service_marks import ServiceMark
from tunnelminion.operation.contracts import OperationStatus
from tunnelminion.patrol.contracts import PatrolReason, PatrolStatus
from tunnelminion.repair.contracts import (
    ProgramLaunchRecord,
    RepairKind,
    WindowsServiceRecord,
)


def test_port_that_used_to_talk_and_goes_silent_is_stuck(tmp_path: Path) -> None:
    h = PatrolHarness(tmp_path)
    h.entries = (entry(PROGRAM, ports=(22, 2222), web=False),)
    h.talk[22] = True

    async def scenario() -> None:
        await h.rounds(1)
        record = h.store.get(PROGRAM)
        assert record is not None
        assert record.talk_ports == (22,) and record.quiet_ports == (2222,)
        # 本来就不说话的端口之后不再探。
        h.talk_probed.clear()
        await h.rounds(1)
        assert h.talk_probed == [22]
        h.talk[22] = TimeoutError()
        await h.rounds(3)

    asyncio.run(scenario())
    view = h.view_of(PROGRAM)
    assert view.status is PatrolStatus.DOWN and view.reason is PatrolReason.STUCK


def test_quiet_service_is_never_stuck(tmp_path: Path) -> None:
    h = PatrolHarness(tmp_path)
    h.entries = (entry(PROGRAM, ports=(9000,), web=False),)
    asyncio.run(h.rounds(6))
    assert h.view_of(PROGRAM).status is PatrolStatus.OK


def test_without_talk_probe_only_web_is_checked(tmp_path: Path) -> None:
    h = PatrolHarness(tmp_path)
    h.patrol._talks_first = None  # pyright: ignore[reportPrivateUsage]
    h.entries = (entry(PROGRAM, ports=(9000,), web=False),)
    asyncio.run(h.rounds(2))
    assert h.talk_probed == [] and h.view_of(PROGRAM).status is PatrolStatus.OK


@pytest.mark.parametrize("stuck_enabled", [False, True])
def test_stuck_auto_repair_needs_its_own_switch(tmp_path: Path, stuck_enabled: bool) -> None:
    h = PatrolHarness(tmp_path)

    async def scenario() -> None:
        await h.rounds(1)
        view = h.patrol.set_auto_repair(PHOTOS, enabled=True, stuck=stuck_enabled)
        auto = next(item for item in view.services if item.key == PHOTOS).auto_repair
        assert auto.stuck_available and auto.stuck_enabled is stuck_enabled
        h.web[8080] = None
        await h.rounds(3)

    asyncio.run(scenario())
    [repair] = h.repairs.store.list_all()
    assert repair.plan.kind is RepairKind.RESTART_CONTAINERS
    if stuck_enabled:
        assert repair.status is OperationStatus.SUCCEEDED
    else:
        assert repair.status is OperationStatus.AWAITING_AUTHORIZATION
        assert h.conversations.texts()[-1] == "卡住了要不要自动修需要单独打开，这次等你批准。"
    # 关掉"挂了可以自动修"时一并关掉"卡住了也自动修"；不给 stuck 时保持原样。
    view = h.patrol.set_auto_repair(PHOTOS, enabled=False)
    assert not next(item for item in view.services if item.key == PHOTOS).auto_repair.stuck_enabled


def test_port_identity_has_no_fix(tmp_path: Path) -> None:
    h = PatrolHarness(tmp_path)
    key = "port:tcp:9000"
    h.entries = (entry(key, ports=(9000,), web=False),)

    async def scenario() -> None:
        await h.rounds(1)
        h.entries = ()
        await h.rounds(3)

    asyncio.run(scenario())
    assert h.conversations.texts()[-1] == "这个服务没有现成的修法，需要你手动处理。"


def test_refusal_with_steps_is_kept_for_the_service_box(tmp_path: Path) -> None:
    h = PatrolHarness(tmp_path)
    h.repairs.launch_records.put(
        ProgramLaunchRecord(
            service_key=PROGRAM,
            ports=(9000,),
            elevated=True,
            rule_shown=True,
            process_id=5,
            process_started_at=NOW,
            recorded_at=NOW,
        )
    )
    h.entries = (entry(PROGRAM, ports=(9000,), web=False),)

    async def scenario() -> None:
        await h.rounds(1)
        assert not h.view_of(PROGRAM).auto_repair.available
        h.entries = (entry(PROGRAM, state="stopped", ports=(9000,)),)
        await h.rounds(3)

    asyncio.run(scenario())
    view = h.view_of(PROGRAM)
    assert view.reason is PatrolReason.PROGRAM_EXITED
    assert view.repair_refusal is not None and "管理员" in view.repair_refusal
    assert view.manual_steps and h.conversations.steps[-1] == view.manual_steps


def windows_harness(tmp_path: Path) -> PatrolHarness:
    h = PatrolHarness(tmp_path)
    h.repairs.launch_records.put(
        WindowsServiceRecord(
            service_key=PROGRAM,
            service_name="SunshineService",
            ports=(9000,),
            rule_shown=False,
            recorded_at=NOW,
        )
    )
    h.repairs.marks[PROGRAM] = ServiceMark.MINE
    h.entries = (entry(PROGRAM, ports=(9000,), web=False, windows_service=True),)
    return h


def test_windows_service_grant_controls_auto_repair(tmp_path: Path) -> None:
    h = windows_harness(tmp_path)
    services = h.repairs.windows_services

    async def scenario() -> None:
        await h.rounds(1)
        view = h.view_of(PROGRAM)
        assert view.windows_service is not None and view.windows_service.granted
        assert view.auto_repair.kind is RepairKind.RESTART_WINDOWS_SERVICE
        h.patrol.set_auto_repair(PROGRAM, enabled=True)
        revoked = await h.patrol.set_windows_service_grant(PROGRAM, granted=False)
        item = next(value for value in revoked.services if value.key == PROGRAM)
        assert item.windows_service is not None and not item.windows_service.granted
        assert not item.auto_repair.available and not item.auto_repair.enabled
        await h.patrol.set_windows_service_grant(PROGRAM, granted=True)
        services.grant_result = False
        with pytest.raises(PermissionError):
            await h.patrol.set_windows_service_grant(PROGRAM, granted=False)
        with pytest.raises(KeyError):
            await h.patrol.set_windows_service_grant(PHOTOS, granted=True)

    asyncio.run(scenario())
    assert services.calls == [
        ("revoke", "SunshineService"),
        ("grant", "SunshineService"),
        ("revoke", "SunshineService"),
    ]


def test_stopped_windows_service_is_auto_started(tmp_path: Path) -> None:
    h = windows_harness(tmp_path)

    async def scenario() -> None:
        await h.rounds(1)
        h.patrol.set_auto_repair(PROGRAM, enabled=True)
        h.entries = (entry(PROGRAM, state="stopped", ports=(9000,), windows_service=True),)
        await h.rounds(3)

    asyncio.run(scenario())
    assert h.view_of(PROGRAM).reason is PatrolReason.SERVICE_STOPPED
    [repair] = h.repairs.store.list_all()
    assert repair.plan.kind is RepairKind.RESTART_WINDOWS_SERVICE
    assert repair.status is OperationStatus.SUCCEEDED


def test_no_windows_runtime_means_no_service_view(tmp_path: Path) -> None:
    h = windows_harness(tmp_path)
    h.patrol._windows_services = None  # pyright: ignore[reportPrivateUsage]
    asyncio.run(h.rounds(1))
    view = h.view_of(PROGRAM)
    assert view.windows_service is None and not view.auto_repair.available
    with pytest.raises(KeyError):
        asyncio.run(h.patrol.set_windows_service_grant(PROGRAM, granted=True))
