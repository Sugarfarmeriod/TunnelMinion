"""执行和失败收场只操作批准目标，不重试修法。"""

from __future__ import annotations

import asyncio
from datetime import timedelta
from pathlib import Path

import pytest
from tests.repair.factories import NOW, container, plan
from tests.repair.fakes import RepairHarness, at_status, local_launch

from tunnelminion.domain.identifiers import OperationId
from tunnelminion.domain.service_marks import ServiceMark
from tunnelminion.operation.contracts import OperationStatus, transition_operation
from tunnelminion.repair.contracts import (
    ContainerRepairTarget,
    ContainerSnapshot,
    PortOwner,
    PythonRepairTarget,
    RepairAuditAction,
    RepairCheckName,
    RepairCleanupResult,
    RepairErrorCode,
    RepairKind,
    RepairOrigin,
    RepairOriginKind,
    RepairRecord,
    RepairSummary,
)


def python_authorized(h: RepairHarness, tmp_path: Path) -> RepairRecord:
    launch = local_launch(tmp_path)
    return h.authorized(
        RepairRecord.planned(plan(PythonRepairTarget(launch=launch)), actor="local-cli")
    )


def test_only_authorized_records_execute(tmp_path: Path) -> None:
    h = RepairHarness(tmp_path)
    record = RepairRecord.planned(plan(), actor="local-cli")
    h.store.put(record)
    assert asyncio.run(h.workflow.execute(record.plan.operation_id)) == record
    assert not h.containers.queries and not h.containers.calls
    with pytest.raises(KeyError):
        asyncio.run(h.workflow.execute(OperationId.new()))


def test_expired_approval_does_nothing(tmp_path: Path) -> None:
    h = RepairHarness(tmp_path)
    record = h.authorized()
    h.clock.now += timedelta(minutes=10)
    result = asyncio.run(h.workflow.execute(record.plan.operation_id))
    assert result.status is OperationStatus.AUTHORIZATION_EXPIRED
    assert result.error is not None
    assert result.error.code is RepairErrorCode.AUTHORIZATION_EXPIRED
    assert result.audit[-1].action is RepairAuditAction.EXPIRED
    assert not h.containers.queries and not h.launcher.calls


@pytest.mark.parametrize("case", ["changed", "unavailable", "missing", "hidden"])
def test_container_precheck_cancels_without_commands(tmp_path: Path, case: str) -> None:
    h = RepairHarness(tmp_path)
    record = h.authorized()
    if case == "changed":
        h.containers.items = (container("b"),)
        code = RepairErrorCode.SERVICE_CHANGED
    elif case == "unavailable":
        h.containers.items = None
        code = RepairErrorCode.DOCKER_UNAVAILABLE
    elif case == "missing":
        h.containers.items = ()
        code = RepairErrorCode.CONTAINER_MISSING
    else:
        h.marks[record.plan.service_key] = ServiceMark.HIDDEN
        code = RepairErrorCode.NOT_ELIGIBLE
    result = asyncio.run(h.workflow.execute(record.plan.operation_id))
    assert result.status is OperationStatus.CANCELLED
    assert result.error is not None and result.error.code is code
    assert result.error.next_step == "情况变了，让 Agent 重新看一下。"
    assert result.audit[-1].action is RepairAuditAction.PRECHECK_FAILED
    assert not h.containers.calls


@pytest.mark.parametrize("matches", [False, True])
def test_python_precheck_existing_listener_does_not_launch(tmp_path: Path, matches: bool) -> None:
    h = RepairHarness(tmp_path)
    record = python_authorized(h, tmp_path)
    h.host.owners[8765] = PortOwner(pid=99, process_name="other", matches_launch=matches)
    result = asyncio.run(h.workflow.execute(record.plan.operation_id))
    assert result.status is OperationStatus.CANCELLED
    assert result.error is not None
    assert result.error.code is (
        RepairErrorCode.ALREADY_RUNNING if matches else RepairErrorCode.PORT_IN_USE
    )
    assert not h.launcher.calls and not h.launcher.stopped


def test_container_start_then_restart_and_persist_every_step(tmp_path: Path) -> None:
    h = RepairHarness(tmp_path)
    items = (
        container("a"),
        container("b", name="photos-db-1", running=True),
        container("c", name="photos-extra-1"),
    )
    h.containers.items = items
    p = plan(ContainerRepairTarget(compose_project="photos", containers=items))
    record = h.authorized(RepairRecord.planned(p, actor="local-cli"))
    result = asyncio.run(h.workflow.execute(p.operation_id))
    assert result.status is OperationStatus.SUCCEEDED
    assert h.containers.calls == [("start", ("a" * 64, "c" * 64)), ("restart", ("b" * 64,))]
    assert result.execution is not None
    assert len(result.execution.commands) == 2
    assert result.execution.finished_at is not None
    assert result.verification is not None and result.verification.passed
    assert [item.to_status for item in result.transitions] == [
        OperationStatus.PLANNED,
        OperationStatus.AWAITING_AUTHORIZATION,
        OperationStatus.AUTHORIZED,
        OperationStatus.EXECUTING,
        OperationStatus.VERIFYING,
        OperationStatus.SUCCEEDED,
    ]
    actions = [event.action for event in result.audit]
    for action in (
        RepairAuditAction.PRECHECK_PASSED,
        RepairAuditAction.COMMAND_EXECUTED,
        RepairAuditAction.VERIFIED,
        RepairAuditAction.FINISHED,
    ):
        assert action in actions
    # 验证只记一条，不在进入验证和验证完成时各记一次。
    assert actions.count(RepairAuditAction.VERIFIED) == 1
    for command in result.execution.commands:
        assert " ".join(command.argv) in [event.detail for event in result.audit]
    assert all(event.actor == "repair-workflow" for event in result.audit[len(record.audit) :])
    assert h.store.get(p.operation_id) == result
    assert {item.status for item in h.store.history} >= {
        OperationStatus.EXECUTING,
        OperationStatus.VERIFYING,
        OperationStatus.SUCCEEDED,
    }
    assert asyncio.run(h.workflow.execute(p.operation_id)) == result
    assert len(h.containers.calls) == 2


def test_compose_running_group_uses_one_restart(tmp_path: Path) -> None:
    h = RepairHarness(tmp_path)
    items = (container(running=True), container("b", name="photos-db-1", running=True))
    h.containers.items = items
    p = plan(ContainerRepairTarget(compose_project="photos", containers=items))
    h.authorized(RepairRecord.planned(p, actor="local-cli"))
    assert asyncio.run(h.workflow.execute(p.operation_id)).status is OperationStatus.SUCCEEDED
    assert h.containers.calls == [("restart", ("a" * 64, "b" * 64))]


def compose_items(*, all_running: bool = False) -> tuple[ContainerSnapshot, ...]:
    return (
        container("a", service="web", depends_on=("db",), running=all_running),
        container("b", name="photos-db-1", service="db", running=all_running, health="healthy"),
        container("c", name="photos-cache-1", service="cache", running=True),
    )


def test_compose_starts_only_stopped_containers_in_dependency_order(tmp_path: Path) -> None:
    h = RepairHarness(tmp_path)
    items = compose_items()
    h.containers.items = items
    h.containers.start_health = "starting"
    p = plan(ContainerRepairTarget(compose_project="photos", containers=items))
    h.authorized(RepairRecord.planned(p, actor="local-cli"))

    def turn_healthy() -> None:
        h.containers.items = tuple(
            item.model_copy(update={"health": "healthy"}) for item in h.containers.items or ()
        )

    h.clock.on_sleep = turn_healthy
    result = asyncio.run(h.workflow.execute(p.operation_id))
    assert result.status is OperationStatus.SUCCEEDED
    assert h.containers.calls == [("start", ("b" * 64,)), ("start", ("a" * 64,))]
    assert h.clock.sleeps == [1]
    assert result.execution is not None and len(result.execution.commands) == 2
    details = [event.detail for event in result.audit]
    for command in result.execution.commands:
        assert " ".join(command.argv) in details


def test_compose_all_running_restarts_in_reverse_then_forward_order(tmp_path: Path) -> None:
    h = RepairHarness(tmp_path)
    items = compose_items(all_running=True)
    h.containers.items = items
    p = plan(ContainerRepairTarget(compose_project="photos", containers=items))
    h.authorized(RepairRecord.planned(p, actor="local-cli"))
    result = asyncio.run(h.workflow.execute(p.operation_id))
    assert result.status is OperationStatus.SUCCEEDED
    assert h.containers.calls == [
        ("stop", ("a" * 64,)),
        ("stop", ("c" * 64, "b" * 64)),
        ("start", ("c" * 64, "b" * 64)),
        ("start", ("a" * 64,)),
    ]
    assert h.clock.sleeps == []


def test_compose_stop_failure_stops_before_next_command(tmp_path: Path) -> None:
    h = RepairHarness(tmp_path)
    items = compose_items(all_running=True)
    h.containers.items = items
    h.containers.exit_codes = [1]
    p = plan(ContainerRepairTarget(compose_project="photos", containers=items))
    h.authorized(RepairRecord.planned(p, actor="local-cli"))
    result = asyncio.run(h.workflow.execute(p.operation_id))
    assert result.status is OperationStatus.ROLLED_BACK
    assert result.error is not None and result.error.message == "Docker 没能停下这些容器。"
    assert h.containers.calls == [("stop", ("a" * 64,))]


def test_compose_dependency_never_ready_stops_without_starting_dependents(
    tmp_path: Path,
) -> None:
    h = RepairHarness(tmp_path)
    items = compose_items()
    h.containers.items = items
    h.containers.start_health = "unhealthy"
    p = plan(ContainerRepairTarget(compose_project="photos", containers=items))
    h.authorized(RepairRecord.planned(p, actor="local-cli"))
    result = asyncio.run(h.workflow.execute(p.operation_id))
    assert result.status is OperationStatus.ROLLED_BACK
    assert h.containers.calls == [("start", ("b" * 64,))]
    assert sum(h.clock.sleeps) == 60
    assert result.error is not None
    assert result.error.code is RepairErrorCode.EXECUTION_FAILED
    assert result.error.message == (
        "photos-db-1 等了 60 秒还没准备好（unhealthy），没有接着启动依赖它的容器。"
    )
    assert result.cleanup is not None and result.cleanup.detail == "容器修复失败后不再动它。"
    assert result.verification is None


@pytest.mark.parametrize("exit_code", [1, None])
def test_command_failure_stops_before_next_command(tmp_path: Path, exit_code: int | None) -> None:
    h = RepairHarness(tmp_path)
    items = (container(), container("b", name="photos-db-1", running=True))
    h.containers.items = items
    h.containers.exit_codes = [exit_code]
    p = plan(ContainerRepairTarget(compose_project="photos", containers=items))
    h.authorized(RepairRecord.planned(p, actor="local-cli"))
    result = asyncio.run(h.workflow.execute(p.operation_id))
    assert result.status is OperationStatus.ROLLED_BACK
    assert (
        result.cleanup is not None and result.cleanup.result is RepairCleanupResult.NOTHING_TO_UNDO
    )
    assert result.cleanup.detail == "容器修复失败后不再动它。"
    assert result.error is not None and result.error.code is RepairErrorCode.EXECUTION_FAILED
    assert result.verification is None
    assert (
        result.execution is not None
        and result.execution.commands[0].output_excerpt == "docker failed"
    )
    assert len(h.containers.calls) == 1
    assert not h.containers.log_calls and not h.verifier.ports


def test_container_exits_immediately_returns_logs_without_retry(tmp_path: Path) -> None:
    h = RepairHarness(tmp_path)
    record = h.authorized()
    h.containers.stay_stopped = True
    h.containers.log = "x" * 5_000
    result = asyncio.run(h.workflow.execute(record.plan.operation_id))
    assert result.status is OperationStatus.ROLLED_BACK
    assert result.verification is not None and not result.verification.passed
    assert result.verification.log_excerpt == "x" * 4_000
    assert (
        result.verification.checks[0].detail
        == "photos-web-1 没在运行（Exited (1) 13 minutes ago）。"
    )
    assert h.clock.sleeps == [1, 1]
    assert len(h.containers.calls) == 1
    assert h.containers.log_calls == [("a" * 64, 40)]
    assert result.error is not None and result.error.message == "容器重启了，但服务还是没起来。"
    assert (
        result.cleanup is not None
        and result.cleanup.detail == "容器修复失败后不再动它，保持现在的状态。"
    )


@pytest.mark.parametrize("observed", [None, ()])
def test_container_disappears_during_verification(
    tmp_path: Path, observed: tuple[()] | None
) -> None:
    h = RepairHarness(tmp_path)
    record = h.authorized()
    h.containers.responses = [(container(),), observed, observed, observed]
    result = asyncio.run(h.workflow.execute(record.plan.operation_id))
    assert result.status is OperationStatus.ROLLED_BACK
    assert result.verification is not None and not result.verification.checks[0].passed
    assert h.containers.log_calls == [("a" * 64, 40)]


def test_containers_without_ports_need_no_web_probe(tmp_path: Path) -> None:
    h = RepairHarness(tmp_path)
    items = (container(ports=()),)
    h.containers.items = items
    record = h.authorized(
        RepairRecord.planned(
            plan(ContainerRepairTarget(compose_project="photos", containers=items)),
            actor="local-cli",
        )
    )
    result = asyncio.run(h.workflow.execute(record.plan.operation_id))
    assert result.status is OperationStatus.SUCCEEDED
    assert result.verification is not None and len(result.verification.checks) == 1
    assert not h.verifier.ports and not h.verifier.web_ports


@pytest.mark.parametrize("status", [None, 200, 499, 500, 503])
def test_http_status_is_probed_once_per_port(tmp_path: Path, status: int | None) -> None:
    h = RepairHarness(tmp_path)
    h.verifier.status = status
    record = h.authorized()
    result = asyncio.run(h.workflow.execute(record.plan.operation_id))
    assert (result.status is OperationStatus.SUCCEEDED) == (status is None or status < 500)
    assert h.verifier.web_ports == [8080]
    assert result.verification is not None
    assert result.verification.checks[-1].name is RepairCheckName.WEB_PAGE
    if status is not None and status >= 500:
        assert result.verification.checks[-1].detail == f"首页返回错误（HTTP {status}）。"


def test_all_ports_must_listen_before_web_probe(tmp_path: Path) -> None:
    h = RepairHarness(tmp_path)
    h.verifier.listening = False
    record = h.authorized()
    result = asyncio.run(h.workflow.execute(record.plan.operation_id))
    assert result.status is OperationStatus.ROLLED_BACK
    assert not h.verifier.web_ports
    assert result.verification is not None
    assert result.verification.checks[-1].detail == "端口 8080 没在听。"


def test_python_uses_approved_record_even_if_store_has_changed(tmp_path: Path) -> None:
    h = RepairHarness(tmp_path)
    launch = local_launch(tmp_path, arguments=("app.py", "--title", "original"))
    p = plan(PythonRepairTarget(launch=launch))
    h.authorized(RepairRecord.planned(p, actor="local-cli"))
    h.launch_records.put(launch.model_copy(update={"arguments": ("other.py",)}))
    result = asyncio.run(h.workflow.execute(p.operation_id))
    assert result.status is OperationStatus.SUCCEEDED
    assert h.launcher.calls == [(launch, tmp_path / "repair-logs" / f"{p.operation_id}.log")]
    assert result.execution is not None and result.execution.spawned is not None
    assert RepairAuditAction.PROCESS_SPAWNED in {event.action for event in result.audit}
    assert not h.launcher.stopped
    encoded = RepairSummary.from_record(result).model_dump_json()
    assert launch.interpreter not in encoded
    assert "original" not in encoded
    assert "working_directory" not in encoded


@pytest.mark.parametrize("cleanup", ["stopped", "failed", "exited", "exit_during_wait"])
def test_python_verification_failure_stops_only_spawned_process(
    tmp_path: Path, cleanup: str
) -> None:
    h = RepairHarness(tmp_path)
    record = python_authorized(h, tmp_path)
    h.verifier.listening = False
    h.launcher.stop_result = cleanup != "failed"
    h.launcher.alive = cleanup != "exited"
    if cleanup == "exit_during_wait":
        h.clock.on_sleep = lambda: setattr(h.launcher, "alive", False)
    result = asyncio.run(h.workflow.execute(record.plan.operation_id))
    assert result.status is (
        OperationStatus.CLEANUP_FAILED if cleanup == "failed" else OperationStatus.ROLLED_BACK
    )
    assert result.cleanup is not None
    if cleanup in {"exited", "exit_during_wait"}:
        assert result.cleanup.result is RepairCleanupResult.SPAWNED_ALREADY_EXITED
        assert not h.launcher.stopped
        assert len(h.clock.sleeps) <= 1
    else:
        assert result.cleanup.result is (
            RepairCleanupResult.STOP_FAILED
            if cleanup == "failed"
            else RepairCleanupResult.STOPPED_SPAWNED
        )
        assert result.execution is not None
        assert h.launcher.stopped == [result.execution.spawned]
    assert len(h.launcher.calls) == 1
    assert result.verification is not None and result.verification.log_excerpt == "startup failed"
    assert h.launcher.log_calls[0][1] == 40
    assert result.error is not None and result.error.message == "程序拉起来了，但端口一直没起来。"


def test_python_exited_process_cannot_pass_due_to_another_listener(tmp_path: Path) -> None:
    h = RepairHarness(tmp_path)
    record = python_authorized(h, tmp_path)
    h.launcher.alive = False
    result = asyncio.run(h.workflow.execute(record.plan.operation_id))
    assert result.status is OperationStatus.ROLLED_BACK
    assert result.verification is not None and not result.verification.passed


def test_python_spawn_oserror_needs_no_cleanup(tmp_path: Path) -> None:
    h = RepairHarness(tmp_path)
    record = python_authorized(h, tmp_path)
    h.launcher.error = OSError("private path")
    result = asyncio.run(h.workflow.execute(record.plan.operation_id))
    assert result.status is OperationStatus.ROLLED_BACK
    assert result.cleanup is not None and result.cleanup.detail == "程序没有启动，不需要收场。"
    assert result.execution is not None and result.execution.spawned is None
    assert result.error is not None and "private" not in result.error.model_dump_json()
    assert not h.launcher.stopped


@pytest.mark.parametrize(
    "case", ["list", "command", "verify", "logs", "spawn", "stop", "no_authorization", "no_expiry"]
)
def test_unexpected_errors_are_recorded_as_uncertain(tmp_path: Path, case: str) -> None:
    h = RepairHarness(tmp_path)
    record = python_authorized(h, tmp_path) if case in {"spawn", "stop"} else h.authorized()
    if case in {"list", "command", "logs"}:
        h.containers.error_on = case
        h.containers.stay_stopped = True
    elif case == "verify":
        h.verifier.error = True
    elif case == "spawn":
        h.launcher.error = RuntimeError("private path")
    elif case == "stop":
        h.verifier.listening = False
        h.launcher.error_on_stop = True
    elif case == "no_authorization":
        h.store.put(record.model_copy(update={"authorization": None}))
    else:
        assert record.authorization is not None
        h.store.put(
            record.model_copy(
                update={
                    "authorization": record.authorization.model_copy(update={"expires_at": None})
                }
            )
        )
    result = asyncio.run(h.workflow.execute(record.plan.operation_id))
    assert result.status is OperationStatus.CLEANUP_FAILED
    assert result.error is not None and result.error.code is RepairErrorCode.EXECUTION_FAILED
    assert result.error.message == "修复中途出错了，结果不确定。"
    assert result.error.next_step == "请检查一下这个服务现在的状态。"


def test_busy_and_hourly_limit(tmp_path: Path) -> None:
    h = RepairHarness(tmp_path)
    busy = at_status(RepairRecord.planned(plan(), actor="local-cli"), OperationStatus.EXECUTING)
    h.store.put(busy)
    record = h.authorized(
        RepairRecord.planned(plan(service_key="docker:compose:other"), actor="local-cli")
    )
    result = asyncio.run(h.workflow.execute(record.plan.operation_id))
    assert result.error is not None and result.error.code is RepairErrorCode.BUSY
    assert not h.containers.calls
    h.store.records.clear()
    for _ in range(3):
        record = h.authorized()
        assert (
            asyncio.run(h.workflow.execute(record.plan.operation_id)).status
            is OperationStatus.SUCCEEDED
        )
    fourth = h.authorized()
    limited = asyncio.run(h.workflow.execute(fourth.plan.operation_id))
    assert limited.status is OperationStatus.CANCELLED
    assert limited.error is not None and limited.error.code is RepairErrorCode.RATE_LIMITED
    assert len(h.containers.calls) == 3
    h.clock.now += timedelta(hours=1, seconds=1)
    record = h.authorized()
    assert (
        asyncio.run(h.workflow.execute(record.plan.operation_id)).status
        is OperationStatus.SUCCEEDED
    )
    assert len(h.containers.calls) == 4


@pytest.mark.parametrize(
    "status", [OperationStatus.EXECUTING, OperationStatus.VERIFYING, OperationStatus.ROLLING_BACK]
)
def test_recover_interrupted_follows_legal_transitions(
    tmp_path: Path, status: OperationStatus
) -> None:
    h = RepairHarness(tmp_path)
    record = at_status(RepairRecord.planned(plan(), actor="local-cli"), status)
    h.store.put(record)
    h.clock.now = NOW + timedelta(minutes=15)
    h.workflow.recover_interrupted(h.clock())
    assert h.store.get(record.plan.operation_id) == record
    h.clock.now += timedelta(seconds=1)
    h.workflow.recover_interrupted(h.clock())
    recovered = h.store.get(record.plan.operation_id)
    assert recovered is not None and recovered.status is OperationStatus.CLEANUP_FAILED
    assert recovered.error is not None and recovered.error.code is RepairErrorCode.INTERRUPTED
    assert recovered.transitions[-1].from_status is OperationStatus.ROLLING_BACK
    assert not h.containers.calls and not h.launcher.calls


def test_reason_never_reaches_commands_or_launch_parameters(tmp_path: Path) -> None:
    h = RepairHarness(tmp_path)
    reason = "rm -rf / && docker compose up"
    origin = RepairOrigin(kind=RepairOriginKind.LOCAL_CLI)
    for key, kind in (
        ("docker:compose:photos", RepairKind.RESTART_CONTAINERS),
        ("python:app.py@8765", RepairKind.RELAUNCH_PYTHON),
    ):
        h.launch_records.put(local_launch(tmp_path))
        record = asyncio.run(h.service.propose(key, kind, reason, origin, actor="local-cli"))
        h.service.approve(record.plan.operation_id, operator="local-cli")
        result = asyncio.run(h.service.execute(record.plan.operation_id))
        assert result.status is OperationStatus.SUCCEEDED
        assert reason not in result.model_dump_json(exclude={"plan"})
    assert all(reason not in str(call) for call in h.containers.calls)
    assert all(
        reason not in launch.model_dump_json() and reason not in str(path)
        for launch, path in h.launcher.calls
    )


def test_concurrent_execute_only_runs_once(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    h = RepairHarness(tmp_path)
    record = h.authorized()
    original = h.containers.list_containers
    arrived = 0

    async def run_both() -> tuple[RepairRecord, RepairRecord]:
        gate = asyncio.Event()

        async def list_containers(
            *, compose_project: str | None, container_name: str | None
        ) -> tuple[ContainerSnapshot, ...] | None:
            nonlocal arrived
            arrived += 1
            if arrived <= 2:
                if arrived == 2:
                    gate.set()
                await gate.wait()
            return await original(compose_project=compose_project, container_name=container_name)

        monkeypatch.setattr(h.containers, "list_containers", list_containers)
        first, second = await asyncio.gather(
            h.workflow.execute(record.plan.operation_id),
            h.workflow.execute(record.plan.operation_id),
        )
        return first, second

    first, second = asyncio.run(run_both())
    assert first.status is OperationStatus.SUCCEEDED and second.status is OperationStatus.SUCCEEDED
    assert len(h.containers.calls) == 1


@pytest.mark.parametrize("unexpected", [False, True])
def test_concurrent_state_change_is_not_overwritten_on_precheck_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, unexpected: bool
) -> None:
    h = RepairHarness(tmp_path)
    record = h.authorized()
    cancelled = transition_operation(
        record, OperationStatus.CANCELLED, reason="测试", occurred_at=NOW
    )

    async def changed(*, compose_project: str | None, container_name: str | None) -> None:
        h.store.put(cancelled)
        if unexpected:
            raise RuntimeError("fake")
        return None

    monkeypatch.setattr(h.containers, "list_containers", changed)
    assert asyncio.run(h.workflow.execute(record.plan.operation_id)) == cancelled
    assert not h.containers.calls


def test_persistence_failure_does_not_escape_execution(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    h = RepairHarness(tmp_path)
    record = h.authorized()

    def unavailable(record: RepairRecord) -> None:
        raise OSError("fake database")

    monkeypatch.setattr(h.store, "put", unavailable)
    result = asyncio.run(h.workflow.execute(record.plan.operation_id))
    assert result.error is not None and result.error.code is RepairErrorCode.EXECUTION_FAILED
    assert not h.containers.calls


def test_storage_read_failure_during_execution_does_not_escape(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    h = RepairHarness(tmp_path)
    record = h.authorized()
    original_get = h.store.get
    reads = 0

    def read(operation_id: OperationId) -> RepairRecord | None:
        nonlocal reads
        reads += 1
        if reads > 1:
            raise OSError("fake database")
        return original_get(operation_id)

    monkeypatch.setattr(h.store, "get", read)
    result = asyncio.run(h.workflow.execute(record.plan.operation_id))
    assert result.status is OperationStatus.CLEANUP_FAILED
    assert result.error is not None and result.error.code is RepairErrorCode.EXECUTION_FAILED
    assert not h.containers.calls


def test_approval_expiring_during_precheck_does_not_execute(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    h = RepairHarness(tmp_path)
    record = h.authorized()

    async def slow_read(
        *, compose_project: str | None, container_name: str | None
    ) -> tuple[ContainerSnapshot, ...]:
        h.clock.now += timedelta(minutes=10)
        return (container(),)

    monkeypatch.setattr(h.containers, "list_containers", slow_read)
    result = asyncio.run(h.workflow.execute(record.plan.operation_id))
    assert result.status is OperationStatus.AUTHORIZATION_EXPIRED
    assert not h.containers.calls
