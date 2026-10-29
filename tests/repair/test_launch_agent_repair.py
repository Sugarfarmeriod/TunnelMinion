"""第三种修法：重新启动用户后台服务的计划、资格、执行前核对、执行和验证。"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
from pydantic import ValidationError
from tests.repair.factories import (
    NOW,
    launch_agent_job,
    launch_agent_record,
    launch_agent_target,
    launch_record,
    plan,
)
from tests.repair.fakes import RepairHarness

from tunnelminion.domain.service_marks import ServiceMark
from tunnelminion.operation.contracts import OperationLevel, OperationStatus
from tunnelminion.repair.contracts import (
    REPAIR_TOOL_NAMES,
    LaunchAgentProblem,
    LaunchAgentRecord,
    LaunchAgentRepairTarget,
    PortOwner,
    RepairCheckName,
    RepairCleanupResult,
    RepairErrorCode,
    RepairKind,
    RepairOrigin,
    RepairOriginKind,
    RepairRecord,
)
from tunnelminion.repair.eligibility import RepairRefusal

KEY = "launchd:local.photos.web"
ORIGIN = RepairOrigin(kind=RepairOriginKind.LOCAL_CLI)


def harness(tmp_path: Path) -> RepairHarness:
    h = RepairHarness(tmp_path)
    h.launch_records.put(launch_agent_record())
    return h


def propose(h: RepairHarness, key: str = KEY) -> RepairRecord:
    return asyncio.run(
        h.service.propose(key, RepairKind.RESTART_LAUNCH_AGENT, "后台服务退出了", ORIGIN, actor="t")
    )


def refusal(h: RepairHarness, key: str = KEY) -> RepairRefusal:
    with pytest.raises(RepairRefusal) as caught:
        propose(h, key)
    return caught.value


def test_plan_is_fixed_and_uses_recorded_ports(tmp_path: Path) -> None:
    h = harness(tmp_path)
    record = propose(h)
    plan_ = record.plan
    assert record.status is OperationStatus.AWAITING_AUTHORIZATION
    assert plan_.kind is RepairKind.RESTART_LAUNCH_AGENT
    assert plan_.tool_name == "repair_restart_launch_agent" and plan_.level is OperationLevel.L2
    assert plan_.service_name == "后台服务 local.photos.web"
    assert plan_.action_summary == "重新启动后台服务 local.photos.web（端口 8765）"
    assert "不改配置文件" in plan_.impact_summary
    assert "端口 8765 在听" in plan_.verification_summary
    assert "不会反复重启" in plan_.failure_summary
    target = plan_.target
    assert isinstance(target, LaunchAgentRepairTarget)
    assert target.uid == 501 and target.plist_sha256 == "a" * 64 and target.ports == (8765,)
    assert h.host.calls == [(8765, None)]


def test_identity_and_record_refusals(tmp_path: Path) -> None:
    h = RepairHarness(tmp_path)
    error = refusal(h).error
    assert error.code is RepairErrorCode.NO_LAUNCH_RECORD and "没见过" in error.message
    # 同一身份下是 Python 启动记录时也不算后台服务记录。
    h.launch_records.records[KEY] = launch_record()
    assert refusal(h).error.code is RepairErrorCode.NO_LAUNCH_RECORD
    with pytest.raises(RepairRefusal) as caught:
        asyncio.run(
            h.service.propose(
                "python:app.py@8000", RepairKind.RESTART_LAUNCH_AGENT, "x", ORIGIN, actor="t"
            )
        )
    assert caught.value.error.message == "这种修法不适用于这个服务。"
    h.launch_records.put(launch_agent_record(rule_shown=False))
    assert refusal(h).error.message.startswith('这个服务还不是"是我的服务"')
    h.marks[KEY] = ServiceMark.MINE
    assert propose(h).plan.service_key == KEY
    h.marks[KEY] = ServiceMark.HIDDEN
    assert "隐藏" in refusal(h).error.message


@pytest.mark.parametrize(
    ("label", "message"),
    [
        ("com.apple.Safari.web", "系统、组网或 Docker"),
        ("COM.Docker.helper", "系统、组网或 Docker"),
        ("io.tailscale.ipn", "系统、组网或 Docker"),
        ("local.TunnelMinion.web", "TunnelMinion 自己"),
    ],
)
def test_protected_labels(tmp_path: Path, label: str, message: str) -> None:
    h = RepairHarness(tmp_path)
    h.launch_records.put(launch_agent_record(label))
    h.marks[f"launchd:{label}"] = ServiceMark.MINE
    error = refusal(h, f"launchd:{label}").error
    assert error.code is RepairErrorCode.PROTECTED_TARGET and message in error.message


@pytest.mark.parametrize(
    ("job", "code", "text"),
    [
        (LaunchAgentProblem.MISSING, RepairErrorCode.NOT_ELIGIBLE, "~/Library/LaunchAgents"),
        (LaunchAgentProblem.UNSAFE, RepairErrorCode.PROTECTED_TARGET, "别人也能改"),
        (LaunchAgentProblem.INVALID, RepairErrorCode.NOT_ELIGIBLE, "读不懂"),
        (
            launch_agent_job(program="/Applications/Foo.app/Contents/MacOS/agent"),
            RepairErrorCode.PROTECTED_TARGET,
            "应用自带",
        ),
        (
            launch_agent_job(loaded=False, loaded_path=None),
            RepairErrorCode.NOT_LOADED,
            "已经被卸载",
        ),
        (launch_agent_job(loaded_path=None), RepairErrorCode.NOT_ELIGIBLE, "加载的不是"),
        (
            launch_agent_job(loaded_path="/Library/LaunchAgents/local.photos.web.plist"),
            RepairErrorCode.NOT_ELIGIBLE,
            "加载的不是",
        ),
        (launch_agent_job(pid=88), RepairErrorCode.ALREADY_RUNNING, "还在运行"),
    ],
)
def test_runtime_refusals(tmp_path: Path, job: object, code: RepairErrorCode, text: str) -> None:
    h = harness(tmp_path)
    h.launch_agents.job = job  # type: ignore[assignment]
    error = refusal(h).error
    assert error.code is code and text in error.message
    assert not h.launch_agents.kickstarts


def test_unsupported_platform_and_program_without_path(tmp_path: Path) -> None:
    h = harness(tmp_path)
    h.launch_agents.reason = "只有 macOS 上才有后台服务（LaunchAgent）这种修法。"
    assert refusal(h).error.message.startswith("只有 macOS")
    h.launch_agents.reason = None
    h.launch_agents.job = launch_agent_job(program=None)
    assert propose(h).plan.kind is RepairKind.RESTART_LAUNCH_AGENT


def test_port_taken_by_another_program(tmp_path: Path) -> None:
    h = harness(tmp_path)
    h.host.owners[8765] = PortOwner(pid=9, process_name="nginx", matches_launch=False)
    error = refusal(h).error
    assert error.code is RepairErrorCode.PORT_IN_USE and "nginx" in error.message


def authorized(h: RepairHarness) -> RepairRecord:
    record = propose(h)
    return h.service.approve(record.plan.operation_id, operator="local-web")


def test_execute_kickstarts_and_verifies(tmp_path: Path) -> None:
    h = harness(tmp_path)
    record = authorized(h)
    result = asyncio.run(h.service.execute(record.plan.operation_id))
    assert result.status is OperationStatus.SUCCEEDED
    assert h.launch_agents.kickstarts == ["local.photos.web"]
    assert result.execution is not None
    assert result.execution.commands[0].argv == (
        "/bin/launchctl",
        "kickstart",
        "gui/501/local.photos.web",
    )
    assert result.verification is not None
    names = [item.name for item in result.verification.checks]
    assert names == [
        RepairCheckName.LAUNCH_AGENT_RUNNING,
        RepairCheckName.PORT_LISTENING,
        RepairCheckName.WEB_PAGE,
    ]
    assert result.verification.checks[0].detail == "后台服务在运行。"


def test_precheck_cancels_when_plist_changed(tmp_path: Path) -> None:
    h = harness(tmp_path)
    record = authorized(h)
    h.launch_agents.job = launch_agent_job(plist_sha256="b" * 64)
    result = asyncio.run(h.service.execute(record.plan.operation_id))
    assert result.status is OperationStatus.CANCELLED
    assert result.error is not None and result.error.code is RepairErrorCode.SERVICE_CHANGED
    assert "配置文件和批准时不一样" in result.error.message
    assert not h.launch_agents.kickstarts


@pytest.mark.parametrize(
    "job",
    [launch_agent_job(pid=5), launch_agent_job(loaded=False), LaunchAgentProblem.MISSING],
)
def test_precheck_cancels_when_state_changed(tmp_path: Path, job: object) -> None:
    h = harness(tmp_path)
    record = authorized(h)
    h.launch_agents.job = job  # type: ignore[assignment]
    result = asyncio.run(h.service.execute(record.plan.operation_id))
    assert result.status is OperationStatus.CANCELLED
    assert result.error is not None and result.error.next_step == "情况变了，让 Agent 重新看一下。"
    assert not h.launch_agents.kickstarts


def test_kickstart_failure_is_left_alone(tmp_path: Path) -> None:
    h = harness(tmp_path)
    record = authorized(h)
    h.launch_agents.exit_code = 5
    result = asyncio.run(h.service.execute(record.plan.operation_id))
    assert result.status is OperationStatus.ROLLED_BACK
    assert result.error is not None and result.error.code is RepairErrorCode.EXECUTION_FAILED
    assert result.cleanup is not None
    assert result.cleanup.result is RepairCleanupResult.NOTHING_TO_UNDO
    assert "不会再动它" in result.cleanup.detail
    assert result.verification is None


def test_verification_failure_reports_log_and_exit_code(tmp_path: Path) -> None:
    h = harness(tmp_path)
    record = authorized(h)
    h.launch_agents.stay_stopped = True
    result = asyncio.run(h.service.execute(record.plan.operation_id))
    assert result.status is OperationStatus.ROLLED_BACK
    assert result.error is not None and result.error.code is RepairErrorCode.VERIFICATION_FAILED
    assert result.verification is not None and not result.verification.passed
    assert result.verification.checks[0].detail == "后台服务没在运行。"
    assert result.verification.log_excerpt == ("address already in use\nlaunchd 记的上次退出码：1")
    assert h.launch_agents.kickstarts == ["local.photos.web"]
    assert h.clock.sleeps  # 等过一阵才放弃，不重试 kickstart。


def test_verification_without_readable_job(tmp_path: Path) -> None:
    h = harness(tmp_path)
    record = authorized(h)
    h.launch_agents.stay_stopped = True
    h.launch_agents.log = ""
    h.launch_agents.responses = [
        launch_agent_job(),
        *([LaunchAgentProblem.MISSING] * 10),
    ]
    result = asyncio.run(h.service.execute(record.plan.operation_id))
    assert result.verification is not None and result.verification.log_excerpt == ""
    h.launch_agents.responses = []
    record = authorized(h)
    h.launch_agents.responses = [
        launch_agent_job(),
        *([launch_agent_job(last_exit_code=None)] * 10),
    ]
    result = asyncio.run(h.service.execute(record.plan.operation_id))
    assert result.verification is not None and result.verification.log_excerpt == ""


def test_contract_validation() -> None:
    with pytest.raises(ValidationError):
        LaunchAgentRecord(
            service_key="launchd:other",
            label="local.a",
            ports=(1,),
            rule_shown=True,
            recorded_at=NOW,
        )
    with pytest.raises(ValidationError):
        plan(launch_agent_target(), service_key="launchd:other")
    assert (
        plan(launch_agent_target()).tool_name == REPAIR_TOOL_NAMES[RepairKind.RESTART_LAUNCH_AGENT]
    )
    target = launch_agent_target()
    assert target.fingerprint != launch_agent_target("local.other").fingerprint
