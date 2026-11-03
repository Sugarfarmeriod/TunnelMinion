"""巡检只盯稳定运行的服务：临时程序停了不算挂了，真正长期运行的服务挂了照样提醒。"""

from __future__ import annotations

import asyncio
from datetime import timedelta
from pathlib import Path

from tests.patrol.fakes import PHOTOS, SCRIPT, PatrolHarness, entry
from tests.repair.factories import NOW
from tests.repair.fakes import local_launch

from tunnelminion.operation.contracts import OperationStatus
from tunnelminion.patrol.contracts import (
    PATROL_STABLE_SECONDS,
    PatrolReason,
    PatrolRecord,
    PatrolStatus,
)
from tunnelminion.repair.contracts import RepairKind, RepairOrigin, RepairOriginKind

STABLE = timedelta(seconds=PATROL_STABLE_SECONDS)


def _harness(tmp_path: Path) -> PatrolHarness:
    """一个规则直接显示、没标过的脚本；清掉记录时一并删掉启动记录。"""
    h = PatrolHarness(tmp_path, stable_seconds=PATROL_STABLE_SECONDS)
    h.entries = (entry(SCRIPT),)
    h.patrol._forget_records = h.repairs.launch_records.delete  # pyright: ignore[reportPrivateUsage]
    return h


def _record(h: PatrolHarness, key: str = SCRIPT) -> PatrolRecord:
    record = h.store.get(key)
    assert record is not None
    return record


def test_short_lived_script_that_stops_is_not_reported(tmp_path: Path) -> None:
    """跑了一两分钟就被主人关掉的测试服务：不标红、不开对话、不提修法。"""
    h = _harness(tmp_path)

    h.repairs.launch_records.put(local_launch(tmp_path))

    async def scenario() -> None:
        await h.rounds(1)
        h.repairs.clock.now += timedelta(minutes=2)
        await h.rounds(1)
        h.entries = (entry(SCRIPT, state="stopped"),)
        await h.rounds(2)
        assert h.view_of(SCRIPT).status is PatrolStatus.OK
        record = _record(h)
        assert record.running_since is None and not record.established
        assert h.repairs.launch_records.get(SCRIPT) is not None
        await h.rounds(1)

    asyncio.run(scenario())
    assert h.conversations.notes == [] and h.repairs.store.list_all() == ()
    # 连续 3 轮确认停了：像主人点了"从地图上移除"一样清掉启动记录和巡检记录。
    assert h.store.get(SCRIPT) is None and h.repairs.launch_records.get(SCRIPT) is None


def test_stopped_script_is_kept_while_a_repair_still_needs_it(tmp_path: Path) -> None:
    """主人让 Agent 重新拉起、修复还在等批准时，启动记录先留着。"""
    h = _harness(tmp_path)
    h.repairs.launch_records.put(local_launch(tmp_path))
    h.entries = (entry(SCRIPT, state="stopped", ports=(8765,)),)

    async def scenario() -> None:
        await h.repairs.service.propose(
            SCRIPT,
            RepairKind.RELAUNCH_PYTHON,
            "主人让我重新拉起",
            RepairOrigin(kind=RepairOriginKind.CONVERSATION),
            actor="agent",
        )
        await h.rounds(4)

    asyncio.run(scenario())
    [repair] = h.repairs.store.list_all()
    assert repair.status is OperationStatus.AWAITING_AUTHORIZATION
    assert h.repairs.launch_records.get(SCRIPT) is not None


def test_stopped_container_that_is_not_watched_is_left_alone(tmp_path: Path) -> None:
    """停掉的容器还留在 Docker 里，清掉记录也会马上重新出现，不清。"""
    h = _harness(tmp_path)
    other = "docker:compose:scratch"
    h.entries = (entry(other),)

    async def scenario() -> None:
        await h.rounds(1)
        h.entries = (entry(other, state="stopped"),)
        await h.rounds(4)

    asyncio.run(scenario())
    assert _record(h, other).status is PatrolStatus.OK
    assert h.conversations.notes == []


def test_script_running_for_thirty_minutes_is_watched_and_reported(tmp_path: Path) -> None:
    h = _harness(tmp_path)

    async def scenario() -> None:
        await h.rounds(1)
        assert not _record(h).established
        h.repairs.clock.now += STABLE
        await h.rounds(1)
        assert _record(h).established
        h.entries = (entry(SCRIPT, state="stopped"),)
        await h.rounds(3)

    asyncio.run(scenario())
    view = h.view_of(SCRIPT)
    assert view.status is PatrolStatus.DOWN and view.reason is PatrolReason.SCRIPT_EXITED
    record = _record(h)
    assert record.established and record.running_since == NOW


def test_process_start_time_counts_towards_the_stable_run(tmp_path: Path) -> None:
    """TunnelMinion 刚启动时，早就在跑的脚本按它的进程启动时间算，不用再等 30 分钟。"""
    h = _harness(tmp_path)
    launch = local_launch(tmp_path)
    h.repairs.launch_records.put(
        launch.model_copy(update={"process_started_at": NOW - STABLE - timedelta(minutes=1)})
    )

    async def scenario() -> None:
        await h.rounds(1)
        h.entries = (entry(SCRIPT, state="stopped"),)
        await h.rounds(3)

    asyncio.run(scenario())
    assert h.view_of(SCRIPT).status is PatrolStatus.DOWN
    assert _record(h).running_since == NOW - STABLE - timedelta(minutes=1)


def test_owner_marked_service_is_watched_as_soon_as_it_runs(tmp_path: Path) -> None:
    """标成"是我的服务"的（相册）见过一次正常就盯，停了照样提醒。"""
    h = _harness(tmp_path)
    h.entries = (entry(),)

    async def scenario() -> None:
        await h.rounds(1)
        h.entries = (entry(state="stopped"),)
        await h.rounds(3)

    asyncio.run(scenario())
    assert h.view_of(PHOTOS).status is PatrolStatus.DOWN
    assert not _record(h, PHOTOS).established


def test_auto_repair_switch_means_the_owner_wants_it_watched(tmp_path: Path) -> None:
    h = _harness(tmp_path)
    h.repairs.launch_records.put(local_launch(tmp_path))

    async def scenario() -> None:
        await h.rounds(1)
        h.patrol.set_auto_repair(SCRIPT, enabled=True)
        h.entries = (entry(SCRIPT, state="stopped"),)
        await h.rounds(3)

    asyncio.run(scenario())
    assert h.view_of(SCRIPT).status is PatrolStatus.DOWN


def test_unwatched_service_that_vanishes_is_forgotten(tmp_path: Path) -> None:
    """没有启动记录、进程退出后从地图上彻底消失的临时服务，巡检记录直接清掉。"""
    h = _harness(tmp_path)

    async def scenario() -> None:
        await h.rounds(1)
        assert h.store.get(SCRIPT) is not None
        h.entries = ()
        await h.rounds(1)

    asyncio.run(scenario())
    assert h.store.get(SCRIPT) is None
    assert all(item.key != SCRIPT for item in h.patrol.view().services)


def test_web_trouble_does_not_restart_the_stable_clock(tmp_path: Path) -> None:
    """进程一直在跑、只是网页偶尔打不开：不提醒，也不从头计时。"""
    h = _harness(tmp_path)

    async def scenario() -> None:
        await h.rounds(1)
        h.web[8080] = 500
        await h.rounds(3)
        assert h.view_of(SCRIPT).status is PatrolStatus.OK
        assert _record(h).running_since == NOW
        h.web[8080] = 200
        h.repairs.clock.now += STABLE
        await h.rounds(1)

    asyncio.run(scenario())
    assert _record(h).established


def test_restarted_script_starts_counting_again(tmp_path: Path) -> None:
    h = _harness(tmp_path)

    async def scenario() -> None:
        await h.rounds(1)
        h.repairs.clock.now += timedelta(minutes=20)
        h.entries = (entry(SCRIPT, state="stopped"),)
        await h.rounds(1)
        h.repairs.clock.now += timedelta(minutes=5)
        h.entries = (entry(SCRIPT),)
        await h.rounds(1)

    asyncio.run(scenario())
    record = _record(h)
    assert record.running_since == NOW + timedelta(minutes=25) and not record.established


def test_old_down_records_of_short_lived_services_are_withdrawn(tmp_path: Path) -> None:
    """旧版本按"见过一次正常"记下的挂了：没跑满门槛的撤掉，彻底消失的清掉，都不发通知。"""
    h = _harness(tmp_path)
    gone = "python:pytest.exe@9201"
    for key in (SCRIPT, gone):
        h.store.put(
            PatrolRecord(
                key=key,
                name="app.py",
                seen_running=True,
                status=PatrolStatus.DOWN,
                reason=PatrolReason.SCRIPT_EXITED,
                down_since=NOW - timedelta(days=1),
                confirmed_at=NOW - timedelta(days=1),
            )
        )
    h.entries = (entry(SCRIPT, state="stopped"),)
    launch = local_launch(tmp_path)
    h.repairs.launch_records.put(
        launch.model_copy(update={"process_started_at": NOW - timedelta(days=1, minutes=2)})
    )

    asyncio.run(h.rounds(1))
    record = _record(h)
    assert record.status is PatrolStatus.OK and record.reason is None
    assert record.down_since is None and record.confirmed_at is None
    assert h.store.get(gone) is None
    assert h.conversations.notes == []


def test_old_down_record_of_a_long_running_service_stays_down(tmp_path: Path) -> None:
    """旧记录里跑了很久才停的服务（进程启动到开始异常超过门槛）仍算挂了，并记成已盯上。"""
    h = _harness(tmp_path)
    down_since = NOW - timedelta(hours=2)
    h.store.put(
        PatrolRecord(
            key=SCRIPT,
            name="app.py",
            seen_running=True,
            status=PatrolStatus.DOWN,
            reason=PatrolReason.SCRIPT_EXITED,
            down_since=down_since,
            confirmed_at=down_since,
        )
    )
    h.entries = (entry(SCRIPT, state="stopped"),)
    launch = local_launch(tmp_path)
    h.repairs.launch_records.put(
        launch.model_copy(update={"process_started_at": down_since - timedelta(hours=69)})
    )

    asyncio.run(h.rounds(2))
    record = _record(h)
    assert record.status is PatrolStatus.DOWN and record.established


def test_old_suspect_record_of_a_long_running_service_is_still_confirmed(tmp_path: Path) -> None:
    h = _harness(tmp_path)
    h.store.put(
        PatrolRecord(
            key=SCRIPT,
            name="app.py",
            seen_running=True,
            status=PatrolStatus.SUSPECT,
            reason=PatrolReason.SCRIPT_EXITED,
            down_since=NOW,
        )
    )
    h.entries = (entry(SCRIPT, state="stopped"),)
    launch = local_launch(tmp_path)
    h.repairs.launch_records.put(launch.model_copy(update={"process_started_at": NOW - STABLE}))

    asyncio.run(h.rounds(3))
    assert h.view_of(SCRIPT).status is PatrolStatus.DOWN
