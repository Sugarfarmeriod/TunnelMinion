"""新修法：重新运行普通程序、结束卡住的程序再运行、重启 Windows 服务、卡住的后台服务。"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
from tests.repair.factories import NODE, NOW, launch_agent_job, launch_agent_record
from tests.repair.fakes import RepairHarness, local_launch

from tunnelminion.domain.identifiers import DelegationId
from tunnelminion.domain.service_marks import ServiceMark
from tunnelminion.operation.contracts import OperationStatus
from tunnelminion.repair.contracts import (
    ManualStep,
    PortOwner,
    ProcessLaunchRecord,
    ProgramLaunchRecord,
    ProgramRepairTarget,
    RepairCleanupResult,
    RepairErrorCode,
    RepairKind,
    RepairOrigin,
    RepairOriginKind,
    RepairRecord,
    SpawnedProcess,
    StuckProgramRepairTarget,
    WindowsServiceRecord,
    WindowsServiceRepairTarget,
)
from tunnelminion.repair.eligibility import RepairRefusal, check_windows_service_protected

PROGRAM = "program:gost@805"
SERVICE = "program:sunshine@47984"
ORIGIN = RepairOrigin(kind=RepairOriginKind.LOCAL_CLI)


def program_record(tmp_path: Path, **update: object) -> ProgramLaunchRecord:
    binary = tmp_path / "gost.exe"
    if not binary.exists():
        binary.write_bytes(b"gost")
    stat = binary.stat()
    return ProgramLaunchRecord(
        service_key=PROGRAM,
        executable=str(binary),
        executable_size=stat.st_size,
        executable_mtime_ns=stat.st_mtime_ns,
        arguments=("-L", ":805", "--token=s3cret-zq"),
        working_directory=str(tmp_path),
        ports=(805,),
        username="me",
        rule_shown=True,
        process_id=42,
        process_started_at=NOW,
        recorded_at=NOW,
    ).model_copy(update=update)


def service_record() -> WindowsServiceRecord:
    return WindowsServiceRecord(
        service_key=SERVICE,
        service_name="SunshineService",
        ports=(47984,),
        rule_shown=False,
        recorded_at=NOW,
    )


def owner(*, matches: bool = True, started: datetime = NOW, pid: int | None = 42) -> PortOwner:
    return PortOwner(pid=pid, process_name="gost", matches_launch=matches, started_at=started)


async def approve_and_run(h: RepairHarness, key: str, kind: RepairKind) -> RepairRecord:
    record = await h.service.propose(key, kind, "测试", ORIGIN, actor="test")
    h.service.approve(record.plan.operation_id, operator="me")
    return await h.service.execute(record.plan.operation_id)


def refusal(h: RepairHarness, key: str, kind: RepairKind) -> RepairErrorCode:
    with pytest.raises(RepairRefusal) as caught:
        asyncio.run(h.service.propose(key, kind, "测试", ORIGIN, actor="test"))
    return caught.value.error.code


# ---- 重新运行普通程序 ----


def test_relaunch_program_runs_with_record_and_verifies(tmp_path: Path) -> None:
    h = RepairHarness(tmp_path)
    h.launch_records.put(program_record(tmp_path))
    result = asyncio.run(approve_and_run(h, PROGRAM, RepairKind.RELAUNCH_PROGRAM))
    assert result.status is OperationStatus.SUCCEEDED
    assert isinstance(result.plan.target, ProgramRepairTarget)
    assert result.plan.action_summary == "按上次的启动方式在后台重新运行 gost（端口 805）"
    [(record, _)] = h.launcher.calls
    assert record == program_record(tmp_path)
    assert "s3cret-zq" not in result.plan.model_dump_json(exclude={"target"})


def listen_on_launch(h: RepairHarness, listener: PortOwner) -> None:
    """程序被拉起以后才出现在端口上。"""
    launch = h.launcher.launch

    def launched(record: ProcessLaunchRecord, *, log_path: Path) -> SpawnedProcess:
        h.host.owners[805] = listener
        return launch(record, log_path=log_path)

    h.launcher.launch = launched  # type: ignore[method-assign]


def test_relaunched_program_is_written_back_so_it_can_be_ended_later(tmp_path: Path) -> None:
    """重新运行后的进程不是从终端起来的；写回新的进程号，之后卡住了才认得出它。"""
    h = RepairHarness(tmp_path)
    h.launch_records.put(program_record(tmp_path))
    later = NOW + timedelta(minutes=5)

    async def scenario() -> RepairRecord:
        record = await h.service.propose(
            PROGRAM, RepairKind.RELAUNCH_PROGRAM, "退出了", ORIGIN, actor="t"
        )
        h.service.approve(record.plan.operation_id, operator="me")
        listen_on_launch(h, owner(pid=77, started=later))
        return await h.service.execute(record.plan.operation_id)

    assert asyncio.run(scenario()).status is OperationStatus.SUCCEEDED
    stored = h.launch_records.get(PROGRAM)
    assert isinstance(stored, ProgramLaunchRecord)
    assert stored.process_id == 77 and stored.process_started_at == later
    assert stored.model_dump(exclude={"process_id", "process_started_at", "recorded_at"}) == (
        program_record(tmp_path).model_dump(
            exclude={"process_id", "process_started_at", "recorded_at"}
        )
    )
    h.stuck.add(PROGRAM)
    record = asyncio.run(
        h.service.propose(PROGRAM, RepairKind.RESTART_STUCK_PROGRAM, "卡住", ORIGIN, actor="t")
    )
    target = record.plan.target
    assert isinstance(target, StuckProgramRepairTarget) and target.process_id == 77


@pytest.mark.parametrize("change", ["owner_differs", "record_changed", "no_owner"])
def test_relaunch_writeback_skips_when_unsure(tmp_path: Path, change: str) -> None:
    h = RepairHarness(tmp_path)
    h.launch_records.put(program_record(tmp_path))

    async def scenario() -> RepairRecord:
        record = await h.service.propose(
            PROGRAM, RepairKind.RELAUNCH_PROGRAM, "退出了", ORIGIN, actor="t"
        )
        h.service.approve(record.plan.operation_id, operator="me")
        if change == "owner_differs":
            listen_on_launch(h, owner(matches=False, pid=77))
        elif change == "record_changed":
            listen_on_launch(h, owner(pid=77))
            h.launch_records.put(program_record(tmp_path, arguments=("-L", ":806")))
        return await h.service.execute(record.plan.operation_id)

    assert asyncio.run(scenario()).status is OperationStatus.SUCCEEDED
    stored = h.launch_records.get(PROGRAM)
    assert isinstance(stored, ProgramLaunchRecord) and stored.process_id == 42


def test_relaunch_program_failure_stops_spawned(tmp_path: Path) -> None:
    h = RepairHarness(tmp_path)
    h.launch_records.put(program_record(tmp_path))
    h.verifier.listening = False
    result = asyncio.run(approve_and_run(h, PROGRAM, RepairKind.RELAUNCH_PROGRAM))
    assert result.error is not None and result.error.message == "程序拉起来了，但端口一直没起来。"
    assert (
        result.cleanup is not None and result.cleanup.result is RepairCleanupResult.STOPPED_SPAWNED
    )


@pytest.mark.parametrize(
    ("case", "code"),
    [
        ("none", RepairErrorCode.NO_LAUNCH_RECORD),
        ("windows", RepairErrorCode.NOT_ELIGIBLE),
        ("not_mine", RepairErrorCode.NOT_ELIGIBLE),
        ("elevated", RepairErrorCode.NEEDS_ADMIN),
        ("other", RepairErrorCode.OTHER_ACCOUNT),
        ("changed", RepairErrorCode.EXECUTABLE_CHANGED),
        ("missing", RepairErrorCode.EXECUTABLE_CHANGED),
        ("directory", RepairErrorCode.WORKING_DIRECTORY_MISSING),
        ("running", RepairErrorCode.ALREADY_RUNNING),
        ("squatter", RepairErrorCode.PORT_IN_USE),
        ("protected", RepairErrorCode.PROTECTED_TARGET),
    ],
)
def test_relaunch_program_refusals(tmp_path: Path, case: str, code: RepairErrorCode) -> None:
    h = RepairHarness(tmp_path)
    key = PROGRAM
    record = program_record(tmp_path)
    if case == "windows":
        h.launch_records.put(service_record())
        key = SERVICE
    elif case == "not_mine":
        h.launch_records.put(record.model_copy(update={"rule_shown": False}))
    elif case == "elevated":
        h.launch_records.put(
            ProgramLaunchRecord(
                service_key=PROGRAM,
                ports=(805,),
                elevated=True,
                rule_shown=True,
                process_id=1,
                process_started_at=NOW,
                recorded_at=NOW,
            )
        )
    elif case == "other":
        h.launch_records.put(record.model_copy(update={"username": "root"}))
    elif case == "changed":
        h.launch_records.put(record.model_copy(update={"executable_size": 999}))
    elif case == "missing":
        h.launch_records.put(record.model_copy(update={"executable": str(tmp_path / "x.exe")}))
    elif case == "directory":
        h.launch_records.put(record.model_copy(update={"working_directory": str(tmp_path / "x")}))
    elif case == "running":
        h.launch_records.put(record)
        h.host.owners[805] = owner()
    elif case == "squatter":
        h.launch_records.put(record)
        h.host.owners[805] = owner(matches=False)
    elif case == "protected":
        key = "program:wireguard@51820"
    assert refusal(h, key, RepairKind.RELAUNCH_PROGRAM) is code


def test_elevated_and_squatter_refusals_carry_redacted_steps(tmp_path: Path) -> None:
    h = RepairHarness(tmp_path)
    h.launch_records.put(program_record(tmp_path))
    h.host.owners[805] = owner(matches=False)
    with pytest.raises(RepairRefusal) as caught:
        asyncio.run(
            h.service.propose(PROGRAM, RepairKind.RELAUNCH_PROGRAM, "测试", ORIGIN, actor="t")
        )
    commands = [step.command or "" for step in caught.value.error.manual_steps]
    assert len(commands) == 2 and "s3cret-zq" not in "".join(commands)
    assert "（原来的值）" in commands[1]


def test_relaunch_program_precheck_cancels_when_file_changed(tmp_path: Path) -> None:
    h = RepairHarness(tmp_path)
    h.launch_records.put(program_record(tmp_path))

    async def scenario() -> RepairRecord:
        record = await h.service.propose(
            PROGRAM, RepairKind.RELAUNCH_PROGRAM, "测试", ORIGIN, actor="t"
        )
        h.service.approve(record.plan.operation_id, operator="me")
        (tmp_path / "gost.exe").write_bytes(b"new version")
        return await h.service.execute(record.plan.operation_id)

    result = asyncio.run(scenario())
    assert result.status is OperationStatus.CANCELLED and not h.launcher.calls


# ---- 结束卡住的程序再运行 ----


def stuck_harness(tmp_path: Path, *, python: bool = False) -> tuple[RepairHarness, str]:
    h = RepairHarness(tmp_path)
    if python:
        record = local_launch(tmp_path)
        key = record.service_key
        h.launch_records.put(record)
        h.host.owners[8765] = owner()
    else:
        key = PROGRAM
        h.launch_records.put(program_record(tmp_path))
        h.host.owners[805] = owner()
    h.stuck.add(key)
    return h, key


@pytest.mark.parametrize("python", [False, True])
@pytest.mark.parametrize("forcibly", [False, True])
def test_stuck_program_is_ended_then_relaunched(
    tmp_path: Path, python: bool, forcibly: bool
) -> None:
    h, key = stuck_harness(tmp_path, python=python)
    h.launcher.end_result = forcibly

    async def scenario() -> RepairRecord:
        record = await h.service.propose(
            key, RepairKind.RESTART_STUCK_PROGRAM, "卡住", ORIGIN, actor="t"
        )
        h.service.approve(record.plan.operation_id, operator="me")
        # 结束以后端口空出来。
        h.host.owners.clear()
        h.host.owners.update({805: owner(), 8765: owner()})
        return await h.service.execute(record.plan.operation_id)

    result = asyncio.run(scenario())
    assert result.status is OperationStatus.SUCCEEDED
    assert isinstance(result.plan.target, StuckProgramRepairTarget)
    assert h.launcher.ended == [42] and len(h.launcher.calls) == 1
    assert result.execution is not None and result.execution.ended_forcibly is forcibly
    assert result.plan.service_name.startswith("Python 脚本" if python else "程序")


def test_stuck_program_that_cannot_be_ended_is_not_relaunched(tmp_path: Path) -> None:
    h, key = stuck_harness(tmp_path)
    h.launcher.end_result = None
    result = asyncio.run(approve_and_run(h, key, RepairKind.RESTART_STUCK_PROGRAM))
    assert result.status is OperationStatus.ROLLED_BACK and not h.launcher.calls
    assert result.error is not None and result.error.code is RepairErrorCode.EXECUTION_FAILED


@pytest.mark.parametrize(
    ("case", "code"),
    [
        ("not_confirmed", RepairErrorCode.NOT_STUCK),
        ("exited", RepairErrorCode.NOT_STUCK),
        ("other_program", RepairErrorCode.PORT_IN_USE),
        ("restarted", RepairErrorCode.PORT_IN_USE),
        ("no_pid", RepairErrorCode.PORT_IN_USE),
        ("no_record", RepairErrorCode.NO_LAUNCH_RECORD),
        ("not_mine", RepairErrorCode.NOT_ELIGIBLE),
    ],
)
def test_stuck_program_refusals(tmp_path: Path, case: str, code: RepairErrorCode) -> None:
    h, key = stuck_harness(tmp_path)
    if case == "not_confirmed":
        h.stuck.clear()
    elif case == "exited":
        h.host.owners.clear()
    elif case == "other_program":
        h.host.owners[805] = owner(matches=False)
    elif case == "restarted":
        h.host.owners[805] = owner(started=NOW + timedelta(minutes=5))
    elif case == "no_pid":
        h.host.owners[805] = owner(pid=None)
    elif case == "no_record":
        h.launch_records.records.clear()
    else:
        h.launch_records.put(program_record(tmp_path, rule_shown=False))
    assert refusal(h, key, RepairKind.RESTART_STUCK_PROGRAM) is code


@pytest.mark.parametrize("change", ["recovered", "other_process"])
def test_stuck_precheck_cancels_when_situation_changed(tmp_path: Path, change: str) -> None:
    h, key = stuck_harness(tmp_path)

    async def scenario() -> RepairRecord:
        record = await h.service.propose(
            key, RepairKind.RESTART_STUCK_PROGRAM, "卡住", ORIGIN, actor="t"
        )
        h.service.approve(record.plan.operation_id, operator="me")
        if change == "recovered":
            h.stuck.clear()
        else:
            h.host.owners[805] = owner(pid=43)
        return await h.service.execute(record.plan.operation_id)

    result = asyncio.run(scenario())
    assert result.status is OperationStatus.CANCELLED and not h.launcher.ended


def test_stuck_python_script_precheck(tmp_path: Path) -> None:
    h, key = stuck_harness(tmp_path, python=True)
    result = asyncio.run(approve_and_run(h, key, RepairKind.RESTART_STUCK_PROGRAM))
    assert result.status is OperationStatus.SUCCEEDED


# ---- Windows 服务 ----


def windows_harness(tmp_path: Path, **info: object) -> RepairHarness:
    h = RepairHarness(tmp_path)
    h.launch_records.put(service_record())
    h.marks[SERVICE] = ServiceMark.MINE
    assert h.windows_services.info is not None
    h.windows_services.info = h.windows_services.info.model_copy(update=info)
    return h


def test_stopped_windows_service_is_started_and_verified(tmp_path: Path) -> None:
    h = windows_harness(tmp_path)
    result = asyncio.run(approve_and_run(h, SERVICE, RepairKind.RESTART_WINDOWS_SERVICE))
    assert result.status is OperationStatus.SUCCEEDED
    assert h.windows_services.calls == [("start", "SunshineService")]
    assert isinstance(result.plan.target, WindowsServiceRepairTarget)
    assert result.plan.action_summary.startswith("启动已停止的 Windows 服务 Sunshine")


def test_stuck_windows_service_is_stopped_then_started(tmp_path: Path) -> None:
    h = windows_harness(tmp_path, running=True)
    h.stuck.add(SERVICE)
    result = asyncio.run(approve_and_run(h, SERVICE, RepairKind.RESTART_WINDOWS_SERVICE))
    assert result.status is OperationStatus.SUCCEEDED
    assert h.windows_services.calls == [("stop", "SunshineService"), ("start", "SunshineService")]
    assert result.plan.action_summary.startswith("重启卡住的 Windows 服务")


@pytest.mark.parametrize("failure", ["stop_code", "stop_timeout", "start_code", "verify"])
def test_windows_service_failures_leave_it_alone(tmp_path: Path, failure: str) -> None:
    h = windows_harness(tmp_path, running=failure != "start_code" and failure != "verify")
    if failure in {"stop_code", "stop_timeout"}:
        h.stuck.add(SERVICE)
    if failure == "stop_code":
        h.windows_services.exit_codes = [1]
    elif failure == "stop_timeout":
        h.windows_services.stay_running = True
    elif failure == "start_code":
        h.windows_services.exit_codes = [1056]
    else:
        h.windows_services.stay_stopped = True
    result = asyncio.run(approve_and_run(h, SERVICE, RepairKind.RESTART_WINDOWS_SERVICE))
    assert result.status is OperationStatus.ROLLED_BACK
    assert result.cleanup is not None
    assert result.cleanup.result is RepairCleanupResult.NOTHING_TO_UNDO
    if failure == "verify":
        assert result.verification is not None and result.verification.log_excerpt is None


@pytest.mark.parametrize(
    ("case", "code"),
    [
        ("unsupported", RepairErrorCode.NOT_ELIGIBLE),
        ("no_record", RepairErrorCode.NO_LAUNCH_RECORD),
        ("not_mine", RepairErrorCode.NOT_ELIGIBLE),
        ("uninstalled", RepairErrorCode.NOT_ELIGIBLE),
        ("system", RepairErrorCode.PROTECTED_TARGET),
        ("svchost", RepairErrorCode.PROTECTED_TARGET),
        ("antivirus", RepairErrorCode.PROTECTED_TARGET),
        ("disabled", RepairErrorCode.SERVICE_DISABLED),
        ("running", RepairErrorCode.ALREADY_RUNNING),
        ("not_granted", RepairErrorCode.NOT_AUTHORIZED),
        ("port", RepairErrorCode.PORT_IN_USE),
    ],
)
def test_windows_service_refusals(tmp_path: Path, case: str, code: RepairErrorCode) -> None:
    h = windows_harness(tmp_path)
    info = h.windows_services.info
    assert info is not None
    if case == "unsupported":
        h.windows_services.reason = "只有 Windows 上才有 Windows 服务这种修法。"
    elif case == "no_record":
        h.launch_records.records.clear()
    elif case == "not_mine":
        h.marks.clear()
    elif case == "uninstalled":
        h.windows_services.info = None
    elif case == "system":
        h.windows_services.info = info.model_copy(update={"binary_path": "C:\\Windows\\x.exe"})
    elif case == "svchost":
        h.windows_services.info = info.model_copy(update={"binary_path": "D:/x/svchost.exe"})
    elif case == "antivirus":
        h.windows_services.info = info.model_copy(update={"display_name": "Kaspersky Agent"})
    elif case == "disabled":
        h.windows_services.info = info.model_copy(update={"start_type": "disabled"})
    elif case == "running":
        h.windows_services.info = info.model_copy(update={"running": True})
    elif case == "not_granted":
        h.windows_services.info = info.model_copy(update={"granted": False})
    else:
        h.host.owners[47984] = owner(matches=False)
    assert refusal(h, SERVICE, RepairKind.RESTART_WINDOWS_SERVICE) is code


@pytest.mark.parametrize(
    ("update", "protected"),
    [
        ({}, False),
        ({"binary_path": r"%SystemRoot%\System32\spoolsv.exe"}, True),
        ({"binary_path": r"\??\C:\Windows\system32\drivers\x.sys"}, True),
        ({"binary_path": r"\SystemRoot\System32\x.exe"}, True),
        ({"binary_path": r"system32\x.exe"}, True),
        ({"binary_path": r"C:\Program Files\Microsoft Office\root\x.exe"}, True),
        ({"name": "clash_verge_service"}, True),
        ({"name": "WSLService"}, True),
        ({"name": "SunloginService"}, True),
        ({"display_name": "Parsec"}, True),
        ({"name": "edgeupdate"}, True),
        ({"name": "GamingServices"}, True),
        ({"display_name": "Docker Desktop Service"}, True),
        ({"binary_path": r"D:\Tools\frp\frpc.exe"}, True),
    ],
)
def test_windows_service_protection_list(
    tmp_path: Path, update: dict[str, str], protected: bool
) -> None:
    info = windows_harness(tmp_path).windows_services.info
    assert info is not None
    changed = info.model_copy(update=update)
    if protected:
        with pytest.raises(RepairRefusal) as caught:
            check_windows_service_protected(changed)
        assert caught.value.error.code is RepairErrorCode.PROTECTED_TARGET
    else:
        check_windows_service_protected(changed)


@pytest.mark.parametrize("change", ["started", "binary", "recovered", "gone"])
def test_windows_service_precheck_cancels(tmp_path: Path, change: str) -> None:
    h = windows_harness(tmp_path, running=change == "recovered")
    if change == "recovered":
        h.stuck.add(SERVICE)

    async def scenario() -> RepairRecord:
        record = await h.service.propose(
            SERVICE, RepairKind.RESTART_WINDOWS_SERVICE, "测试", ORIGIN, actor="t"
        )
        h.service.approve(record.plan.operation_id, operator="me")
        info = h.windows_services.info
        assert info is not None
        if change == "started":
            h.windows_services.info = info.model_copy(update={"running": True})
        elif change == "binary":
            h.windows_services.info = info.model_copy(update={"binary_path": "D:/other.exe"})
        elif change == "recovered":
            h.stuck.clear()
        else:
            h.windows_services.info = None
        return await h.service.execute(record.plan.operation_id)

    result = asyncio.run(scenario())
    assert result.status is OperationStatus.CANCELLED and h.windows_services.calls == []


# ---- 卡住的 macOS 后台服务 ----


def test_stuck_launch_agent_uses_kickstart_k(tmp_path: Path) -> None:
    h = RepairHarness(tmp_path)
    key = "launchd:local.photos.web"
    h.launch_records.put(launch_agent_record())
    h.launch_agents.job = launch_agent_job(pid=555)
    h.stuck.add(key)
    result = asyncio.run(approve_and_run(h, key, RepairKind.RESTART_LAUNCH_AGENT))
    assert result.status is OperationStatus.SUCCEEDED
    assert h.launch_agents.killed == [True]
    assert result.plan.action_summary.startswith("结束卡住的后台服务")


def test_stuck_launch_agent_precheck_cancels_after_recovery(tmp_path: Path) -> None:
    h = RepairHarness(tmp_path)
    key = "launchd:local.photos.web"
    h.launch_records.put(launch_agent_record())
    h.launch_agents.job = launch_agent_job(pid=555)
    h.stuck.add(key)

    async def scenario() -> RepairRecord:
        record = await h.service.propose(
            key, RepairKind.RESTART_LAUNCH_AGENT, "卡住", ORIGIN, actor="t"
        )
        h.service.approve(record.plan.operation_id, operator="me")
        h.stuck.clear()
        return await h.service.execute(record.plan.operation_id)

    assert asyncio.run(scenario()).status is OperationStatus.CANCELLED
    assert h.launch_agents.kickstarts == []


# ---- 启动记录校验、给模型的摘要、巡检的卡住判断 ----


def test_new_records_validate_their_identity(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        program_record(tmp_path).model_validate(
            {**program_record(tmp_path).model_dump(), "service_key": "python:x@1"}
        )
    with pytest.raises(ValueError):
        ProgramLaunchRecord.model_validate(
            {**program_record(tmp_path).model_dump(), "executable": None}
        )
    with pytest.raises(ValueError):
        WindowsServiceRecord.model_validate(
            {**service_record().model_dump(), "service_key": "python:a.py@1"}
        )


def test_launch_record_summaries_cover_programs_and_windows_services(tmp_path: Path) -> None:
    from tests.repair.test_agent_tools import call, runtime

    h = RepairHarness(tmp_path)
    h.launch_records.put(program_record(tmp_path))
    h.launch_records.put(
        ProgramLaunchRecord(
            service_key="program:admin@9000",
            ports=(9000,),
            elevated=True,
            rule_shown=True,
            process_id=1,
            process_started_at=NOW,
            recorded_at=NOW + timedelta(seconds=1),
        )
    )
    h.launch_records.put(service_record().model_copy(update={"recorded_at": NOW + timedelta(2)}))
    h.host.owners[47984] = owner(matches=False)
    output = call(runtime(h, tmp_path), "list_launch_records")
    records = output["records"]
    assert isinstance(records, list)
    summaries = {item["service_key"]: item for item in records if isinstance(item, dict)}
    assert summaries[SERVICE]["kind"] == "windows_service" and summaries[SERVICE]["running"]
    assert "管理员" in str(summaries["program:admin@9000"]["summary"])
    assert summaries[PROGRAM]["kind"] == "program"
    assert "s3cret-zq" not in str(output) and "gost.exe" not in str(output)


def test_refusal_steps_are_kept_for_the_answer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from tests.repair.test_agent_tools import call, runtime

    kept: list[tuple[str, tuple[ManualStep, ...]]] = []

    def remember(run_id: str, steps: tuple[ManualStep, ...]) -> None:
        kept.append((run_id, steps))

    monkeypatch.setattr("tunnelminion.repair.agent_tools.remember_run_steps", remember)
    h = RepairHarness(tmp_path)
    h.launch_records.put(program_record(tmp_path))
    h.host.owners[805] = owner(matches=False)
    executor = runtime(h, tmp_path)
    output = call(
        executor,
        "propose_repair",
        {"service_key": PROGRAM, "kind": "relaunch_program", "reason": "退出了"},
    )
    # 模型只知道有现成步骤；完整路径和参数只交给本机界面。
    assert output["proposed"] is False and output["has_manual_steps"] is True
    assert "manual_steps" not in output
    assert "gost.exe" not in str(output) and str(tmp_path) not in str(output)
    [(run_id, steps)] = kept
    assert run_id.startswith("run_") and len(steps) == 2 and "s3cret-zq" not in str(steps)

    # 委派时既不给标记，也不把步骤留在这台电脑的对话里。
    class Delegated:
        def get(self) -> SimpleNamespace:
            return SimpleNamespace(delegation_id=DelegationId.new(), caller_node_id=NODE)

    monkeypatch.setattr("tunnelminion.repair.agent_tools.current_delegation", Delegated())
    output = call(
        executor,
        "propose_repair",
        {"service_key": PROGRAM, "kind": "relaunch_program", "reason": "退出了"},
    )
    assert output["proposed"] is False and output["code"] == "port_in_use"
    assert "has_manual_steps" not in output and "manual_steps" not in output
    assert len(kept) == 1


def test_stuck_checker_reads_patrol_records(tmp_path: Path) -> None:
    from tunnelminion.patrol.contracts import PatrolReason, PatrolRecord, PatrolStatus
    from tunnelminion.patrol.local import patrol_store
    from tunnelminion.repair.local import stuck_checker

    is_stuck = stuck_checker(tmp_path)
    assert not is_stuck(PROGRAM)
    store = patrol_store(tmp_path)
    store.put(
        PatrolRecord(key=PROGRAM, name="gost", status=PatrolStatus.DOWN, reason=PatrolReason.STUCK)
    )
    store.put(
        PatrolRecord(
            key=SERVICE, name="s", status=PatrolStatus.DOWN, reason=PatrolReason.PORT_CLOSED
        )
    )
    assert is_stuck(PROGRAM) and not is_stuck(SERVICE)
