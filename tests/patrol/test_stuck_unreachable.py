"""巡检：卡住以后排队的探测占满接收队列、变成"连不上"时，仍然能确认卡住，且不误判别的情况。"""

from __future__ import annotations

import asyncio
from pathlib import Path

from tests.patrol.fakes import PROGRAM, PatrolHarness, entry

from tunnelminion.patrol.contracts import PatrolReason, PatrolStatus
from tunnelminion.repair.contracts import PortUnreachableError
from tunnelminion.web.service_map import ServiceEntry


def ssh_and_web() -> ServiceEntry:
    """22 是先回话的非网页端口，8080 是网页。"""
    base = entry(PROGRAM, ports=(22, 8080), web=True)
    ssh, web = base.endpoints
    return base.model_copy(
        update={"endpoints": (ssh.model_copy(update={"has_web_page": False}), web)}
    )


def test_silent_web_page_that_becomes_unreachable_is_confirmed_stuck(tmp_path: Path) -> None:
    h = PatrolHarness(tmp_path)

    async def scenario() -> None:
        await h.rounds(1)
        # 第一轮还能连上但不回应；之后接收队列满了，连都连不上。
        h.web[8080] = None
        await h.rounds(1)
        assert h.view_of().status is PatrolStatus.SUSPECT
        h.web[8080] = PortUnreachableError(8080)
        await h.rounds(2)

    asyncio.run(scenario())
    view = h.view_of()
    assert view.status is PatrolStatus.DOWN and view.reason is PatrolReason.STUCK


def test_silent_talk_port_that_becomes_unreachable_is_confirmed_stuck(tmp_path: Path) -> None:
    h = PatrolHarness(tmp_path)
    h.entries = (entry(PROGRAM, ports=(22,), web=False),)
    h.talk[22] = True

    async def scenario() -> None:
        await h.rounds(1)
        h.talk[22] = False
        await h.rounds(1)
        h.talk[22] = PortUnreachableError(22)
        await h.rounds(2)

    asyncio.run(scenario())
    view = h.view_of(PROGRAM)
    assert view.status is PatrolStatus.DOWN and view.reason is PatrolReason.STUCK


def test_confirmed_stuck_service_is_not_reported_recovered_while_unreachable(
    tmp_path: Path,
) -> None:
    h = PatrolHarness(tmp_path)

    async def scenario() -> None:
        await h.rounds(1)
        h.web[8080] = None
        await h.rounds(3)
        assert h.view_of().status is PatrolStatus.DOWN
        h.web[8080] = PortUnreachableError(8080)
        await h.rounds(4)

    asyncio.run(scenario())
    assert h.view_of().status is PatrolStatus.DOWN
    assert not any("已恢复正常" in text for text in h.conversations.texts())


def test_unreachable_without_earlier_silence_is_only_unclear(tmp_path: Path) -> None:
    """只听组网地址、或端口刚好没人听：从来没见过不回应，连不上只算看不清。"""
    h = PatrolHarness(tmp_path)
    h.entries = (ssh_and_web(),)
    h.talk[22] = True

    async def scenario() -> None:
        await h.rounds(1)
        h.web[8080] = PortUnreachableError(8080)
        h.talk[22] = PortUnreachableError(22)
        await h.rounds(5)

    asyncio.run(scenario())
    assert h.view_of(PROGRAM).status is PatrolStatus.OK


def test_unreachable_port_does_not_count_while_another_entry_answers(tmp_path: Path) -> None:
    h = PatrolHarness(tmp_path)
    h.entries = (ssh_and_web(),)
    h.talk[22] = True

    async def scenario() -> None:
        await h.rounds(1)
        h.web[8080] = None
        await h.rounds(1)
        assert h.view_of(PROGRAM).status is PatrolStatus.SUSPECT
        # 另一个入口还在正常回话：程序没卡住，网页入口连不上只算看不清。
        h.web[8080] = PortUnreachableError(8080)
        await h.rounds(3)

    asyncio.run(scenario())
    assert h.view_of(PROGRAM).status is PatrolStatus.OK


def test_service_that_exits_after_going_silent_is_reported_as_exited(tmp_path: Path) -> None:
    h = PatrolHarness(tmp_path)
    h.entries = (entry(PROGRAM, ports=(9000,), web=True),)

    async def scenario() -> None:
        await h.rounds(1)
        h.web[9000] = None
        await h.rounds(1)
        h.web[9000] = PortUnreachableError(9000)
        await h.rounds(1)
        # 程序真的退出：地图显示已停止，按"程序退出"确认，不说成卡住。
        h.entries = (entry(PROGRAM, ports=(9000,), web=True, state="stopped"),)
        await h.rounds(1)

    asyncio.run(scenario())
    view = h.view_of(PROGRAM)
    assert view.status is PatrolStatus.DOWN and view.reason is PatrolReason.PROGRAM_EXITED
