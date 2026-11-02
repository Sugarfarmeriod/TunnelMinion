"""服务还在启动时（端口在听、首页返回 503 之类的服务器错误）多等一会儿，不把刚拉起的进程停掉。

真机上用户的大模型服务从外接盘加载模型要一两分钟，期间所有请求都返回 503；以前首页只探测一次，
30 秒一到就判失败并停掉刚拉起的进程。这组测试覆盖所有走同一套验证的修法。
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Coroutine
from pathlib import Path
from typing import Any

import pytest
from tests.repair.fakes import RepairHarness
from tests.repair.test_launch_agent_repair import authorized as launch_agent_authorized
from tests.repair.test_launch_agent_repair import harness as launch_agent_harness
from tests.repair.test_new_repair_kinds import (
    ORIGIN,
    PROGRAM,
    SERVICE,
    approve_and_run,
    owner,
    program_record,
    stuck_harness,
    windows_harness,
)
from tests.repair.test_workflow import python_authorized

from tunnelminion.operation.contracts import OperationStatus
from tunnelminion.repair.contracts import (
    RepairCheckName,
    RepairCleanupResult,
    RepairKind,
    RepairRecord,
)

Run = Callable[[], Coroutine[Any, Any, RepairRecord]]


def _container(tmp_path: Path) -> tuple[RepairHarness, Run]:
    h = RepairHarness(tmp_path)
    record = h.authorized()
    return h, lambda: h.service.execute(record.plan.operation_id)


def _python(tmp_path: Path) -> tuple[RepairHarness, Run]:
    h = RepairHarness(tmp_path)
    record = python_authorized(h, tmp_path)
    return h, lambda: h.service.execute(record.plan.operation_id)


def _program(tmp_path: Path) -> tuple[RepairHarness, Run]:
    h = RepairHarness(tmp_path)
    h.launch_records.put(program_record(tmp_path))
    return h, lambda: approve_and_run(h, PROGRAM, RepairKind.RELAUNCH_PROGRAM)


def _stuck(tmp_path: Path) -> tuple[RepairHarness, Run]:
    h, key = stuck_harness(tmp_path)

    async def run() -> RepairRecord:
        record = await h.service.propose(
            key, RepairKind.RESTART_STUCK_PROGRAM, "卡住", ORIGIN, actor="t"
        )
        h.service.approve(record.plan.operation_id, operator="me")
        h.host.owners.clear()
        h.host.owners.update({805: owner(), 8765: owner()})
        return await h.service.execute(record.plan.operation_id)

    return h, run


def _launch_agent(tmp_path: Path) -> tuple[RepairHarness, Run]:
    h = launch_agent_harness(tmp_path)
    record = launch_agent_authorized(h)
    return h, lambda: h.service.execute(record.plan.operation_id)


def _windows_service(tmp_path: Path) -> tuple[RepairHarness, Run]:
    h = windows_harness(tmp_path)
    return h, lambda: approve_and_run(h, SERVICE, RepairKind.RESTART_WINDOWS_SERVICE)


KINDS = {
    "container": (_container, "容器重启了"),
    "python": (_python, "程序拉起来了"),
    "program": (_program, "程序拉起来了"),
    "stuck": (_stuck, "程序拉起来了"),
    "launch_agent": (_launch_agent, "后台服务重新启动了"),
    "windows_service": (_windows_service, "Windows 服务启动了"),
}


def _loading_for(h: RepairHarness, rounds: int) -> None:
    """首页先返回 503（加载中），等过 `rounds` 次以后变成 200。"""
    h.verifier.status = 503
    waited = 0

    def tick() -> None:
        nonlocal waited
        waited += 1
        if waited >= rounds:
            h.verifier.status = 200

    h.clock.on_sleep = tick


@pytest.mark.parametrize("kind", KINDS)
def test_503_while_loading_then_200_is_a_success(tmp_path: Path, kind: str) -> None:
    build, _ = KINDS[kind]
    h, run = build(tmp_path)
    # 测试替身里普通上限是 2 秒、“还在启动”的上限是 5 秒；第 4 秒才加载完。
    _loading_for(h, 4)
    result = asyncio.run(run())
    assert result.status is OperationStatus.SUCCEEDED, result.error
    assert result.verification is not None and result.verification.waited_seconds == 4
    assert not h.launcher.stopped
    assert result.verification.checks[-1].detail == "首页能打开（HTTP 200）。"


@pytest.mark.parametrize("kind", KINDS)
def test_503_until_the_startup_limit_fails_with_an_honest_message(
    tmp_path: Path, kind: str
) -> None:
    build, done = KINDS[kind]
    h, run = build(tmp_path)
    h.verifier.status = 503
    result = asyncio.run(run())
    assert result.status in {OperationStatus.ROLLED_BACK, OperationStatus.CLEANUP_FAILED}
    assert result.verification is not None and result.verification.waited_seconds == 5
    # 端口在听，不能说“端口一直没起来”。
    assert result.error is not None
    assert result.error.message == (
        f"{done}，端口也在听，但等了 5 秒，首页返回错误（HTTP 503），一直没好。"
    )
    port = next(c for c in result.verification.checks if c.name is RepairCheckName.PORT_LISTENING)
    assert port.passed


def test_a_process_that_dies_while_loading_is_not_waited_for(tmp_path: Path) -> None:
    h, run = _program(tmp_path)
    h.verifier.status = 503
    h.clock.on_sleep = lambda: setattr(h.launcher, "alive", False)
    result = asyncio.run(run())
    assert result.status is OperationStatus.ROLLED_BACK
    assert result.error is not None and result.error.message == "程序拉起来以后自己退出了。"
    assert result.cleanup is not None
    assert result.cleanup.result is RepairCleanupResult.SPAWNED_ALREADY_EXITED
    assert len(h.clock.sleeps) == 1


def test_port_not_listening_still_uses_the_normal_limit(tmp_path: Path) -> None:
    """端口都没在听不算“还在启动”，仍按普通上限判失败。"""
    h, run = _program(tmp_path)
    h.verifier.listening = False
    result = asyncio.run(run())
    assert result.verification is not None and result.verification.waited_seconds == 2
    assert result.error is not None and result.error.message == "程序拉起来了，但端口一直没起来。"
    assert result.cleanup is not None
    assert result.cleanup.result is RepairCleanupResult.STOPPED_SPAWNED
