"""巡检：判定、防抖、提醒、调查一次、补提修法、自动修和限次。"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from datetime import date, timedelta
from pathlib import Path

import pytest
from fastapi import FastAPI
from tests.patrol.fakes import AGENT, PHOTOS, PROGRAM, SCRIPT, PatrolHarness, entry
from tests.repair.factories import launch_agent_record
from tests.repair.fakes import local_launch

from tunnelminion.domain.identifiers import OperationId, ThreadId
from tunnelminion.model.contracts import ProviderError, ProviderErrorCode
from tunnelminion.operation.contracts import OperationStatus
from tunnelminion.patrol.contracts import (
    PATROL_DAILY_INVESTIGATIONS,
    AutoRepairResult,
    PatrolReason,
    PatrolRecord,
    PatrolStatus,
    repair_kind_for,
)
from tunnelminion.patrol.service import (
    PATROL_TOOL_NAMES,
    _Checks,  # pyright: ignore[reportPrivateUsage]
    classify,
    patrol_lifespan,
)
from tunnelminion.repair.contracts import (
    RepairError,
    RepairErrorCode,
    RepairKind,
    RepairOrigin,
    RepairOriginKind,
    RepairRecord,
)
from tunnelminion.repair.service import OwnerPreapproval
from tunnelminion.web.service_map import LocalServiceMap


async def _go_down(h: PatrolHarness, *, rounds: int = 3, **changes: object) -> None:
    """先见到正常一次，再连续异常若干轮。"""
    await h.rounds(1)
    h.entries = (entry(**changes),)  # type: ignore[arg-type]
    await h.rounds(rounds)


def test_container_exit_is_confirmed_on_third_round_and_gets_a_pending_repair(
    tmp_path: Path,
) -> None:
    h = PatrolHarness(tmp_path)

    async def scenario() -> None:
        await h.rounds(1)
        assert h.view_of().status is PatrolStatus.OK and h.probed == [8080]
        h.entries = (entry(state="stopped"),)
        await h.rounds(2)
        view = h.view_of()
        assert view.status is PatrolStatus.SUSPECT and view.reason is PatrolReason.CONTAINER_EXITED
        assert h.conversations.notes == [] and h.repairs.store.list_all() == ()
        await h.rounds(1)

    asyncio.run(scenario())
    view = h.view_of()
    assert view.status is PatrolStatus.DOWN and view.reason_text == "容器已退出"
    [thread] = h.conversations.threads
    assert view.thread_id == ThreadId(thread)
    context = h.conversations.threads[thread]
    assert context is not None and context.service_key == PHOTOS and context.service_name == "相册"
    alert = h.conversations.texts()[0]
    assert alert.startswith("巡检发现 相册 挂了：容器已退出。") and "连续 3 次" in alert
    [(_, question, line)] = h.conversations.questions
    assert (
        question.question == "巡检自动提问：相册 挂了（容器已退出），请查明原因；能修的话提出修法。"
    )
    assert question.tool_names == PATROL_TOOL_NAMES
    assert line is not None and PHOTOS in line
    [repair] = h.repairs.store.list_all()
    assert repair.status is OperationStatus.AWAITING_AUTHORIZATION
    assert repair.plan.origin.kind is RepairOriginKind.PATROL
    assert repair.plan.origin.thread_id == view.thread_id
    assert repair.plan.reason == "巡检确认它挂了：容器已退出。"
    assert view.repair_id == repair.plan.operation_id
    assert not h.repairs.containers.calls
    assert h.patrol.view().investigations_left_today == PATROL_DAILY_INVESTIGATIONS - 1


def test_healthy_round_resets_count_and_recovery_needs_two_rounds(tmp_path: Path) -> None:
    h = PatrolHarness(tmp_path)

    async def scenario() -> None:
        await _go_down(h, rounds=2, state="stopped")
        h.entries = (entry(),)
        await h.rounds(1)
        assert h.view_of().status is PatrolStatus.OK
        h.entries = (entry(state="stopped"),)
        await h.rounds(2)
        assert h.view_of().status is PatrolStatus.SUSPECT
        await h.rounds(5)
        assert h.view_of().status is PatrolStatus.DOWN
        assert len(h.conversations.threads) == 1
        h.entries = (entry(),)
        await h.rounds(1)
        assert h.view_of().status is PatrolStatus.DOWN
        await h.rounds(1)

    asyncio.run(scenario())
    view = h.view_of()
    assert view.status is PatrolStatus.OK and view.repair_id is None and view.reason is None
    assert h.conversations.texts()[-1] == "巡检确认 相册 已恢复正常。"


def test_services_never_seen_running_or_not_shown_are_not_patrolled(tmp_path: Path) -> None:
    h = PatrolHarness(tmp_path)
    h.entries = (entry(state="stopped"), entry(SCRIPT, tier="review"))

    async def scenario() -> None:
        await h.rounds(5)
        assert h.store.list_all() == ()
        h.entries = (entry(),)
        await h.rounds(1)
        assert h.store.get(PHOTOS) is not None
        h.entries = (entry(tier="hidden"),)
        await h.rounds(1)

    asyncio.run(scenario())
    assert h.store.get(PHOTOS) is None
    assert h.conversations.notes == []
    assert [item.key for item in h.patrol.view().services] == []


def test_no_observation_yet_skips_the_round(tmp_path: Path) -> None:
    h = PatrolHarness(tmp_path)
    h.observed = None
    asyncio.run(h.rounds(1))
    assert h.patrol.view().checked_at is None and h.store.list_all() == ()


@pytest.mark.parametrize(
    ("record_ports", "current", "checks", "expected"),
    [
        ((8080,), None, None, PatrolReason.PORT_CLOSED),
        ((8080,), entry(state="stopped"), None, PatrolReason.CONTAINER_EXITED),
        ((8765,), entry(SCRIPT, state="stopped"), None, PatrolReason.SCRIPT_EXITED),
        ((9000,), entry(PROGRAM, state="stopped"), None, PatrolReason.PROGRAM_EXITED),
        (
            (9000,),
            entry(PROGRAM, state="stopped", windows_service=True),
            None,
            PatrolReason.SERVICE_STOPPED,
        ),
        ((8765,), entry(AGENT, state="stopped"), None, PatrolReason.AGENT_EXITED),
        ((8080,), entry(ports=(9090,)), None, PatrolReason.PORT_CLOSED),
        ((8080,), entry(), _Checks(web={8080: False}), PatrolReason.WEB_FAILED),
        ((8080,), entry(), _Checks(web={8080: None}), PatrolReason.STUCK),
        ((8080,), entry(), _Checks(web={9090: None}), PatrolReason.WEB_FAILED),
        ((8080,), entry(), _Checks(web={8080: True, 9090: None}), None),
        ((8080,), entry(), _Checks(talk={22: False}), PatrolReason.STUCK),
        ((8080,), entry(), _Checks(talk={23: False}), None),
        ((), entry(ports=()), None, None),
    ],
)
def test_classify_fixed_rules(
    record_ports: tuple[int, ...],
    current: object,
    checks: _Checks | None,
    expected: PatrolReason | None,
) -> None:
    record = PatrolRecord(
        key=PHOTOS,
        name="相册",
        seen_running=True,
        ports=record_ports,
        web_ports=(8080,),
        talk_ports=(22,),
    )
    assert classify(record, current, checks) is expected  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("failure", "reason"),
    [
        (500, PatrolReason.WEB_FAILED),
        (None, PatrolReason.STUCK),
        (TimeoutError(), None),
        (ConnectionError(), None),
    ],
)
def test_web_page_failures_confirm_down(
    tmp_path: Path, failure: int | None | Exception, reason: PatrolReason | None
) -> None:
    """以前能打开的首页连上后不回应算卡住；返回服务器错误算网页打不开。

    连不上或探测超时只是这一轮看不清，不算异常。
    """
    h = PatrolHarness(tmp_path)

    async def scenario() -> None:
        await h.rounds(1)
        h.web[8080] = failure
        await h.rounds(3)

    asyncio.run(scenario())
    assert h.view_of().reason is reason


def test_slow_probe_times_out(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    h = PatrolHarness(tmp_path)
    monkeypatch.setattr("tunnelminion.patrol.service.PATROL_PROBE_TIMEOUT_SECONDS", 0.01)

    async def never(port: int) -> int | None:
        await asyncio.Event().wait()
        return None

    h.patrol._web_status = never  # pyright: ignore[reportPrivateUsage]
    asyncio.run(h.rounds(1))
    # 等不到探测结果只算看不清：服务照常算在运行，不算异常。
    [record] = h.store.list_all()
    assert record.status is PatrolStatus.OK and record.seen_running


def test_remembered_web_port_is_kept_when_title_probe_misses(tmp_path: Path) -> None:
    h = PatrolHarness(tmp_path)

    async def scenario() -> None:
        await h.rounds(1)
        h.entries = (entry(web=None),)
        await h.rounds(1)
        stored = h.store.get(PHOTOS)
        assert stored is not None and stored.web_ports == (8080,)
        h.web[8080] = 503
        await h.rounds(3)

    asyncio.run(scenario())
    assert h.view_of().reason is PatrolReason.WEB_FAILED


def test_probes_are_capped_per_round(tmp_path: Path) -> None:
    h = PatrolHarness(tmp_path)
    h.entries = (entry(ports=tuple(range(9000, 9020))),)
    asyncio.run(h.rounds(1))
    assert len(h.probed) == 16


def test_vanished_service_is_port_closed_and_program_has_no_fix(tmp_path: Path) -> None:
    h = PatrolHarness(tmp_path)
    h.entries = (entry(PROGRAM, ports=(9000,), web=False),)

    async def scenario() -> None:
        await h.rounds(1)
        h.entries = ()
        await h.rounds(3)

    asyncio.run(scenario())
    view = h.view_of(PROGRAM)
    assert view.status is PatrolStatus.DOWN and view.reason is PatrolReason.PORT_CLOSED
    assert not view.auto_repair.available and view.auto_repair.kind is None
    assert h.conversations.texts()[-1].startswith("巡检想提出修法，但我不知道它原来是怎么启动的。")
    assert view.repair_refusal is not None and view.manual_steps == ()
    assert h.repairs.store.list_all() == ()


def test_agent_proposed_repair_is_used_instead_of_a_second_one(tmp_path: Path) -> None:
    h = PatrolHarness(tmp_path)

    async def propose(thread_id: ThreadId) -> None:
        await h.repairs.service.propose(
            PHOTOS,
            RepairKind.RESTART_CONTAINERS,
            "日志里看到正常退出",
            RepairOrigin(kind=RepairOriginKind.CONVERSATION, thread_id=thread_id),
            actor="agent",
        )

    h.conversations.during_run = propose
    asyncio.run(_go_down(h, state="stopped"))
    [repair] = h.repairs.store.list_all()
    assert repair.plan.origin.kind is RepairOriginKind.CONVERSATION
    assert h.view_of().repair_id == repair.plan.operation_id


def test_model_unavailable_still_alerts_and_proposes(tmp_path: Path) -> None:
    h = PatrolHarness(tmp_path)
    h.conversations.start_error = ProviderError(ProviderErrorCode.NETWORK_UNREACHABLE, "没有模型")
    asyncio.run(_go_down(h, state="stopped"))
    assert "模型现在用不了，这次没有查原因。" in h.conversations.texts()
    assert len(h.repairs.store.list_all()) == 1


def test_slow_investigation_is_cancelled(tmp_path: Path) -> None:
    h = PatrolHarness(tmp_path)
    h.conversations.hang = True
    asyncio.run(_go_down(h, state="stopped"))
    assert len(h.conversations.cancelled) == 1
    assert len(h.repairs.store.list_all()) == 1


def test_investigation_cooldown_and_daily_limit(tmp_path: Path) -> None:
    h = PatrolHarness(tmp_path)

    async def episode() -> None:
        h.entries = (entry(),)
        await h.rounds(2)
        h.entries = (entry(state="stopped"),)
        await h.rounds(3)

    async def scenario() -> None:
        await episode()
        assert len(h.conversations.questions) == 1
        h.repairs.clock.now += timedelta(minutes=30)
        await episode()
        assert len(h.conversations.questions) == 1
        assert "1 小时内已经自动查过一次" in h.conversations.texts()[-1]
        h.repairs.clock.now += timedelta(hours=1)
        today = h.repairs.clock.now.astimezone().date()
        for _ in range(PATROL_DAILY_INVESTIGATIONS):
            h.store.take_investigation(today, limit=PATROL_DAILY_INVESTIGATIONS)
        await episode()

    asyncio.run(scenario())
    assert len(h.conversations.questions) == 1
    assert "今天的自动调查次数已经用完" in "".join(h.conversations.texts())
    assert h.patrol.view().investigations_left_today == 0


def test_auto_repair_approves_on_owner_behalf_and_verifies(tmp_path: Path) -> None:
    h = PatrolHarness(tmp_path)

    async def scenario() -> None:
        await h.rounds(1)
        view = h.patrol.set_auto_repair(PHOTOS, enabled=True)
        auto = next(item for item in view.services if item.key == PHOTOS).auto_repair
        assert auto.enabled and auto.enabled_on == date(2026, 10, 25)
        assert auto.kind is RepairKind.RESTART_CONTAINERS
        h.entries = (entry(state="stopped"),)
        await h.rounds(3)

    asyncio.run(scenario())
    [repair] = h.repairs.store.list_all()
    assert repair.status is OperationStatus.SUCCEEDED
    assert repair.authorization is not None
    assert repair.authorization.operator == "patrol"
    assert repair.authorization.basis == "按主人 2026-10-25 的预先允许自动执行"
    approved = next(item for item in repair.audit if item.action == "approved")
    assert approved.actor == "patrol"
    assert approved.detail == (
        "按主人 2026年10月25日 打开的“挂了可以自动修”自动执行（巡检确认：容器已退出）。"
    )
    assert [action for action, _ in h.repairs.containers.calls] == ["start"]
    auto = h.view_of().auto_repair
    assert auto.last_result is AutoRepairResult.SUCCEEDED and not auto.paused
    assert auto.last_attempt_at is not None


def test_auto_repair_once_per_hour(tmp_path: Path) -> None:
    h = PatrolHarness(tmp_path)

    async def episode() -> None:
        h.entries = (entry(),)
        await h.rounds(2)
        h.entries = (entry(state="stopped"),)
        h.repairs.containers.items = tuple(
            item.model_copy(update={"running": False}) for item in h.repairs.containers.items or ()
        )
        await h.rounds(3)

    async def scenario() -> None:
        await h.rounds(1)
        h.patrol.set_auto_repair(PHOTOS, enabled=True)
        await episode()
        h.repairs.clock.now += timedelta(minutes=20)
        await episode()

    asyncio.run(scenario())
    statuses = [item.status for item in h.repairs.store.list_all()]
    assert statuses.count(OperationStatus.SUCCEEDED) == 1
    assert OperationStatus.AWAITING_AUTHORIZATION in statuses
    assert "1 小时内已经自动修过一次" in h.conversations.texts()[-1]


def test_failed_auto_repair_pauses_until_owner_turns_it_back_on(tmp_path: Path) -> None:
    h = PatrolHarness(tmp_path)
    h.repairs.containers.stay_stopped = True

    async def scenario() -> None:
        await h.rounds(1)
        h.patrol.set_auto_repair(PHOTOS, enabled=True)
        h.entries = (entry(state="stopped"),)
        await h.rounds(3)
        auto = h.view_of().auto_repair
        assert auto.paused and auto.last_result is AutoRepairResult.FAILED
        assert "已经暂停这个服务的自动修" in h.conversations.texts()[-1]
        h.repairs.clock.now += timedelta(hours=2)
        h.entries = (entry(),)
        await h.rounds(2)
        h.entries = (entry(state="stopped"),)
        await h.rounds(3)
        assert "自动修已暂停（上次没修好）" in h.conversations.texts()[-1]
        h.patrol.set_auto_repair(PHOTOS, enabled=True)

    asyncio.run(scenario())
    assert not h.view_of().auto_repair.paused
    assert len(h.repairs.containers.calls) == 1


class _Repairs:
    """在真实修复服务外面注入少见的失败。"""

    def __init__(self, h: PatrolHarness) -> None:
        self.inner = h.repairs.service
        self.propose_error: Exception | None = None
        self.approve_error: Exception | None = None
        self.result_code: RepairErrorCode | None = None
        self.kind: RepairKind | None = None

    async def propose(
        self,
        service_key: str,
        kind: RepairKind,
        reason: str,
        origin: RepairOrigin,
        *,
        actor: str,
    ) -> RepairRecord:
        if self.propose_error is not None:
            raise self.propose_error
        record = await self.inner.propose(service_key, kind, reason, origin, actor=actor)
        if self.kind is not None:
            return record.model_copy(
                update={"plan": record.plan.model_copy(update={"kind": self.kind})}
            )
        return record

    def list(self) -> tuple[RepairRecord, ...]:
        return self.inner.list()

    def approve_preauthorized(
        self, operation_id: OperationId, *, preapproval: OwnerPreapproval
    ) -> RepairRecord:
        if self.approve_error is not None:
            raise self.approve_error
        return self.inner.approve_preauthorized(operation_id, preapproval=preapproval)

    def reject(
        self, operation_id: OperationId, *, operator: str, reason: str | None
    ) -> RepairRecord:
        return self.inner.reject(operation_id, operator=operator, reason=reason)

    async def execute(self, operation_id: OperationId) -> RepairRecord:
        record = await self.inner.execute(operation_id)
        if self.result_code is not None:
            return record.model_copy(
                update={
                    "status": OperationStatus.CANCELLED,
                    "error": RepairError(code=self.result_code, message="忙"),
                }
            )
        return record


def _with(h: PatrolHarness) -> _Repairs:
    repairs = _Repairs(h)
    h.patrol._repairs = repairs  # pyright: ignore[reportPrivateUsage]
    return repairs


@pytest.mark.parametrize("code", [RepairErrorCode.BUSY, RepairErrorCode.RATE_LIMITED])
def test_busy_or_rate_limited_does_not_pause(tmp_path: Path, code: RepairErrorCode) -> None:
    h = PatrolHarness(tmp_path)
    _with(h).result_code = code

    async def scenario() -> None:
        await h.rounds(1)
        h.patrol.set_auto_repair(PHOTOS, enabled=True)
        h.entries = (entry(state="stopped"),)
        await h.rounds(3)

    asyncio.run(scenario())
    auto = h.view_of().auto_repair
    assert not auto.paused and auto.last_result is None


@pytest.mark.parametrize("error", [ValueError("这个修复现在不等批准"), KeyError("x")])
def test_approval_race_leaves_repair_waiting(tmp_path: Path, error: Exception) -> None:
    h = PatrolHarness(tmp_path)
    _with(h).approve_error = error

    async def scenario() -> None:
        await h.rounds(1)
        h.patrol.set_auto_repair(PHOTOS, enabled=True)
        h.entries = (entry(state="stopped"),)
        await h.rounds(3)

    asyncio.run(scenario())
    [repair] = h.repairs.store.list_all()
    assert repair.status is OperationStatus.AWAITING_AUTHORIZATION
    assert h.view_of().auto_repair.last_attempt_at is None


def test_mismatched_repair_kind_is_never_auto_approved(tmp_path: Path) -> None:
    h = PatrolHarness(tmp_path)
    _with(h).kind = RepairKind.RELAUNCH_PYTHON

    async def scenario() -> None:
        await h.rounds(1)
        h.patrol.set_auto_repair(PHOTOS, enabled=True)
        h.entries = (entry(state="stopped"),)
        await h.rounds(3)

    asyncio.run(scenario())
    assert h.repairs.containers.calls == []


def test_unexpected_propose_error_is_reported(tmp_path: Path) -> None:
    h = PatrolHarness(tmp_path)
    _with(h).propose_error = ValueError("reason")
    asyncio.run(_go_down(h, state="stopped"))
    assert h.conversations.texts()[-1] == "巡检没能为它生成修法，需要你手动处理。"


def test_script_without_launch_record_reports_refusal(tmp_path: Path) -> None:
    h = PatrolHarness(tmp_path)
    h.entries = (entry(SCRIPT, ports=(8765,)),)

    async def scenario() -> None:
        await h.rounds(1)
        assert not h.view_of(SCRIPT).auto_repair.available
        with pytest.raises(LookupError):
            h.patrol.set_auto_repair(SCRIPT, enabled=True)
        h.entries = (entry(SCRIPT, state="stopped", ports=(8765,)),)
        await h.rounds(3)

    asyncio.run(scenario())
    assert h.conversations.texts()[-1] == (
        "巡检想提出修法，但我不知道它原来是怎么启动的。请在终端里自己重新运行一次，之后我就记住了。"
    )


def test_script_with_launch_record_can_be_auto_relaunched(tmp_path: Path) -> None:
    h = PatrolHarness(tmp_path)
    h.repairs.launch_records.put(local_launch(tmp_path))
    h.entries = (entry(SCRIPT, ports=(8765,)),)

    async def scenario() -> None:
        await h.rounds(1)
        h.patrol.set_auto_repair(SCRIPT, enabled=True)
        h.entries = (entry(SCRIPT, state="stopped", ports=(8765,)),)
        await h.rounds(3)

    asyncio.run(scenario())
    [repair] = h.repairs.store.list_all()
    assert repair.plan.kind is RepairKind.RELAUNCH_PYTHON
    assert repair.status is OperationStatus.SUCCEEDED
    assert h.view_of(SCRIPT).auto_repair.kind is RepairKind.RELAUNCH_PYTHON


def test_launch_agent_with_record_can_be_auto_restarted(tmp_path: Path) -> None:
    h = PatrolHarness(tmp_path)
    h.entries = (entry(AGENT, ports=(8765,)),)

    async def scenario() -> None:
        await h.rounds(1)
        assert not h.view_of(AGENT).auto_repair.available
        h.repairs.launch_records.put(launch_agent_record())
        h.patrol.set_auto_repair(AGENT, enabled=True)
        h.entries = (entry(AGENT, state="stopped", ports=(8765,)),)
        await h.rounds(3)

    asyncio.run(scenario())
    assert h.conversations.texts()[0].startswith("巡检发现 笔记 挂了：后台服务已退出。")
    [repair] = h.repairs.store.list_all()
    assert repair.plan.kind is RepairKind.RESTART_LAUNCH_AGENT
    assert repair.status is OperationStatus.SUCCEEDED
    assert h.repairs.launch_agents.kickstarts == ["local.photos.web"]
    assert h.view_of(AGENT).auto_repair.kind is RepairKind.RESTART_LAUNCH_AGENT


def test_acknowledge_silences_until_running_again(tmp_path: Path) -> None:
    h = PatrolHarness(tmp_path)

    async def scenario() -> None:
        await _go_down(h, rounds=1, state="stopped")
        with pytest.raises(KeyError):
            h.patrol.acknowledge("docker:other")
        view = h.patrol.acknowledge(PHOTOS)
        assert next(item for item in view.services if item.key == PHOTOS).status == "acknowledged"
        await h.rounds(5)
        assert h.view_of().status is PatrolStatus.ACKNOWLEDGED
        with pytest.raises(ValueError):
            h.patrol.acknowledge(PHOTOS)
        h.entries = (entry(),)
        await h.rounds(1)
        assert h.view_of().status is PatrolStatus.OK
        with pytest.raises(ValueError):
            h.patrol.acknowledge(PHOTOS)

    asyncio.run(scenario())
    assert h.conversations.threads == {}


def test_acknowledge_after_confirm_writes_to_thread(tmp_path: Path) -> None:
    h = PatrolHarness(tmp_path)
    asyncio.run(_go_down(h, state="stopped"))
    h.patrol.acknowledge(PHOTOS)
    assert h.conversations.texts()[-1].startswith("主人说这次是有意停的")


def test_auto_repair_switch_rules(tmp_path: Path) -> None:
    h = PatrolHarness(tmp_path)
    h.entries = (entry(), entry(PROGRAM, ports=(9000,)))
    with pytest.raises(KeyError):
        h.patrol.set_auto_repair("docker:missing", enabled=True)
    with pytest.raises(LookupError):
        h.patrol.set_auto_repair(PROGRAM, enabled=True)
    h.patrol.set_auto_repair(PHOTOS, enabled=True)
    view = h.patrol.set_auto_repair(PHOTOS, enabled=False)
    auto = next(item for item in view.services if item.key == PHOTOS).auto_repair
    assert not auto.enabled and auto.enabled_on is None


def test_handle_skips_when_status_changed_before_task_runs(tmp_path: Path) -> None:
    h = PatrolHarness(tmp_path)
    asyncio.run(h.patrol._handle_down("docker:missing"))  # pyright: ignore[reportPrivateUsage]
    assert h.conversations.threads == {}


def test_handling_errors_are_logged(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    h = PatrolHarness(tmp_path)
    _with(h).propose_error = RuntimeError("fixture-private")
    asyncio.run(_go_down(h, state="stopped"))
    assert [item.getMessage() for item in caplog.records] == ["巡检处理失败"]
    assert "fixture-private" not in caplog.text


def test_run_loop_survives_failed_round_and_lifespan_stops(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    h = PatrolHarness(tmp_path)
    stop = asyncio.Event()
    calls = 0
    original = h.services
    secret = "fixture-private"

    def services() -> LocalServiceMap:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise RuntimeError(secret)
        stop.set()
        return original()

    h.patrol._services = services  # pyright: ignore[reportPrivateUsage]
    h.patrol._interval_seconds = 0  # pyright: ignore[reportPrivateUsage]
    asyncio.run(asyncio.wait_for(h.patrol.run(stop), timeout=2))
    [record] = caplog.records
    assert calls == 2 and record.getMessage() == "巡检轮次失败，下个周期重试"
    assert secret not in caplog.text

    entered: list[str] = []

    @asynccontextmanager
    async def base(app: FastAPI) -> AsyncGenerator[None, None]:
        entered.append("in")
        yield
        entered.append("out")

    async def scenario() -> None:
        async with patrol_lifespan(base, h.patrol)(FastAPI()):
            await asyncio.sleep(0)

    asyncio.run(scenario())
    assert entered == ["in", "out"]


def test_repair_kind_for_each_key_type() -> None:
    stuck = PatrolReason.STUCK
    assert repair_kind_for(PHOTOS) is RepairKind.RESTART_CONTAINERS
    assert repair_kind_for(PHOTOS, stuck) is RepairKind.RESTART_CONTAINERS
    assert repair_kind_for(SCRIPT) is RepairKind.RELAUNCH_PYTHON
    assert repair_kind_for(SCRIPT, stuck) is RepairKind.RESTART_STUCK_PROGRAM
    assert repair_kind_for(PROGRAM) is RepairKind.RELAUNCH_PROGRAM
    assert repair_kind_for(PROGRAM, stuck) is RepairKind.RESTART_STUCK_PROGRAM
    assert repair_kind_for(PROGRAM, windows_service=True) is RepairKind.RESTART_WINDOWS_SERVICE
    assert repair_kind_for(AGENT, stuck) is RepairKind.RESTART_LAUNCH_AGENT
    assert repair_kind_for("port:tcp:22") is None


def test_second_confirm_while_handling_does_not_start_another_and_close_cancels(
    tmp_path: Path,
) -> None:
    h = PatrolHarness(tmp_path)
    release = asyncio.Event()
    entered = asyncio.Event()

    async def block(thread_id: ThreadId) -> None:
        entered.set()
        await release.wait()

    h.conversations.during_run = block
    h.conversations.hang = False

    async def observe(count: int) -> None:
        for _ in range(count):
            await h.patrol.observe_once()

    async def scenario() -> None:
        await observe(1)
        h.entries = (entry(state="stopped"),)
        await observe(3)
        await asyncio.wait_for(entered.wait(), timeout=1)
        h.entries = (entry(),)
        await observe(2)
        h.entries = (entry(state="stopped"),)
        await observe(3)
        assert len(h.conversations.threads) == 1
        await h.patrol.aclose()

    asyncio.run(scenario())
    assert h.repairs.store.list_all() == ()


def test_recovery_without_thread_writes_nothing(tmp_path: Path) -> None:
    h = PatrolHarness(tmp_path)
    h.store.put(
        PatrolRecord(
            key=PHOTOS,
            name="相册",
            seen_running=True,
            status=PatrolStatus.DOWN,
            reason=PatrolReason.CONTAINER_EXITED,
            ports=(8080,),
        )
    )
    asyncio.run(h.rounds(2))
    assert h.view_of().status is PatrolStatus.OK and h.conversations.notes == []
