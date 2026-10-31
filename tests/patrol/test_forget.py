"""从地图上移除已停止的服务：清掉启动记录、标记和巡检记录，作废待批准修复，保留对话和审计。"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import cast

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from tests.patrol.fakes import PHOTOS, SCRIPT, PatrolHarness, entry
from tests.patrol.test_routes import ApiClient
from tests.repair.fakes import local_launch

from tunnelminion.domain.service_marks import ServiceMark
from tunnelminion.operation.contracts import OperationStatus
from tunnelminion.patrol.contracts import PatrolStatus
from tunnelminion.patrol.local import build_local_patrol
from tunnelminion.repair.contracts import RepairAuditAction
from tunnelminion.web.patrol import create_patrol_router
from tunnelminion.web.request_guard import install_local_request_guard

SAME_ORIGIN = {"origin": "http://127.0.0.1", "x-tunnelminion-request": "same-origin"}


def _harness(tmp_path: Path) -> PatrolHarness:
    """一个有启动记录、标成“是我的服务”的脚本；移除时一并清掉启动记录和标记。"""
    h = PatrolHarness(tmp_path)
    h.repairs.launch_records.put(local_launch(tmp_path))
    h.repairs.marks[SCRIPT] = ServiceMark.MINE
    h.entries = (entry(SCRIPT, ports=(8765,)),)

    def forget_records(key: str) -> None:
        h.repairs.launch_records.delete(key)
        h.repairs.marks.pop(key, None)

    h.patrol._forget_records = forget_records  # pyright: ignore[reportPrivateUsage]
    return h


async def _stopped_with_pending_repair(h: PatrolHarness) -> None:
    await h.rounds(1)
    h.entries = (entry(SCRIPT, state="stopped", ports=(8765,)),)
    await h.rounds(3)


def test_forgetting_a_stopped_script_clears_records_and_voids_its_pending_repair(
    tmp_path: Path,
) -> None:
    h = _harness(tmp_path)
    asyncio.run(_stopped_with_pending_repair(h))
    down = h.view_of(SCRIPT)
    assert down.status is PatrolStatus.DOWN and down.thread_id is not None
    [pending] = h.repairs.store.list_all()
    assert pending.status is OperationStatus.AWAITING_AUTHORIZATION

    asyncio.run(h.patrol.forget(SCRIPT))

    # 巡检、启动记录和标记都不再有它；地图随之不再列出它（这里由测试替身模拟）。
    assert h.store.get(SCRIPT) is None
    assert h.repairs.launch_records.get(SCRIPT) is None
    assert SCRIPT not in h.repairs.marks
    h.entries = ()
    assert SCRIPT not in [item.key for item in h.patrol.view().services]
    # 待批准的修复作废，审计里写明原因；修复记录本身保留。
    [voided] = h.repairs.store.list_all()
    assert voided.status is OperationStatus.REJECTED
    last = voided.audit[-1]
    assert last.action is RepairAuditAction.REJECTED
    assert last.actor == "local-web"
    assert last.detail == "主人把已停止的 app.py 从地图上移除了，这条修复不再需要。"
    # 巡检对话保留，并补一句说明。
    assert h.conversations.notes[-1] == (
        down.thread_id,
        "主人把 app.py 从地图上移除了，巡检不再跟踪它。",
    )

    # 之后的巡检不再把它当成挂了，也不再提出修复。
    asyncio.run(h.rounds(3))
    assert h.store.list_all() == ()
    assert len(h.repairs.store.list_all()) == 1


def test_a_forgotten_service_that_runs_again_reappears(tmp_path: Path) -> None:
    h = _harness(tmp_path)
    asyncio.run(_stopped_with_pending_repair(h))
    asyncio.run(h.patrol.forget(SCRIPT))
    h.repairs.launch_records.put(local_launch(tmp_path))
    h.entries = (entry(SCRIPT, ports=(8765,)),)
    asyncio.run(h.rounds(1))
    assert h.view_of(SCRIPT).status is PatrolStatus.OK

    # 又挂了还会照常巡检；再移除时只作废新的待批准修复，已作废的那条不动。
    h.entries = (entry(SCRIPT, state="stopped", ports=(8765,)),)
    asyncio.run(h.rounds(3))
    statuses = sorted(item.status.value for item in h.repairs.store.list_all())
    assert statuses == ["awaiting_authorization", "rejected"]
    asyncio.run(h.patrol.forget(SCRIPT))
    assert [item.status for item in h.repairs.store.list_all()] == [OperationStatus.REJECTED] * 2


def test_running_docker_unknown_services_are_refused_without_changes(tmp_path: Path) -> None:
    h = _harness(tmp_path)
    asyncio.run(h.rounds(1))
    with pytest.raises(ValueError):
        asyncio.run(h.patrol.forget(SCRIPT))
    assert h.repairs.launch_records.get(SCRIPT) is not None
    assert h.repairs.marks[SCRIPT] is ServiceMark.MINE
    assert h.store.get(SCRIPT) is not None

    h.entries = (entry(state="stopped"),)
    with pytest.raises(LookupError):
        asyncio.run(h.patrol.forget(PHOTOS))
    assert h.repairs.marks[PHOTOS] is ServiceMark.MINE

    with pytest.raises(KeyError):
        asyncio.run(h.patrol.forget("program:nothing@1"))


def test_a_patrol_record_without_a_map_entry_can_be_forgotten(tmp_path: Path) -> None:
    """地图上已经没有、只剩巡检记录（一直报端口关了）的服务也能移除；没有回调时只清巡检。"""
    h = _harness(tmp_path)
    h.patrol._forget_records = None  # pyright: ignore[reportPrivateUsage]
    asyncio.run(h.rounds(1))
    h.entries = ()
    asyncio.run(h.rounds(1))
    assert h.view_of(SCRIPT).status is PatrolStatus.SUSPECT
    asyncio.run(h.patrol.forget(SCRIPT))
    assert h.store.get(SCRIPT) is None
    assert h.repairs.launch_records.get(SCRIPT) is not None
    # 这条记录还没开过巡检对话，不补说明。
    assert h.conversations.notes == []


def test_forgetting_stops_the_running_down_handling_without_bringing_it_back(
    tmp_path: Path,
) -> None:
    h = _harness(tmp_path)
    h.conversations.hang = True
    h.patrol._investigation_wait_seconds = 60  # pyright: ignore[reportPrivateUsage]

    async def scenario() -> None:
        await h.rounds(1)
        h.entries = (entry(SCRIPT, state="stopped", ports=(8765,)),)
        for _ in range(3):
            await h.patrol.observe_once()
        # 让后台处理进入调查，卡在等模型回答。
        for _ in range(20):
            await asyncio.sleep(0)
        assert h.conversations.questions
        await h.patrol.forget(SCRIPT)
        await h.patrol.wait_idle()

    asyncio.run(scenario())
    assert h.store.get(SCRIPT) is None
    assert h.repairs.store.list_all() == ()


def test_forget_route_answers_like_the_other_patrol_routes(tmp_path: Path) -> None:
    h = _harness(tmp_path)
    asyncio.run(h.rounds(1))
    app = FastAPI()
    app.include_router(create_patrol_router(h.patrol))
    install_local_request_guard(app, read_only_preview=False)
    client = cast(ApiClient, TestClient(app, base_url="http://127.0.0.1"))
    url = f"/api/patrol/services/{SCRIPT}/forget"

    # 只认本机同源请求。
    other = {"origin": "http://other.example", "x-tunnelminion-request": "same-origin"}
    assert client.post(url, headers=other).status_code == 403
    running = client.post(url, headers=SAME_ORIGIN)
    assert running.status_code == 409
    assert running.json()["detail"] == "这个服务还在运行，不能从地图上移除"
    assert (
        client.post("/api/patrol/services/bad key/forget", headers=SAME_ORIGIN).status_code == 404
    )
    assert (
        client.post("/api/patrol/services/program:none@1/forget", headers=SAME_ORIGIN).status_code
        == 404
    )
    h.entries = (entry(SCRIPT, state="stopped", ports=(8765,)), entry(state="stopped"))
    docker = client.post(f"/api/patrol/services/{PHOTOS}/forget", headers=SAME_ORIGIN)
    assert docker.status_code == 422

    response = client.post(url, headers=SAME_ORIGIN)
    assert response.status_code == 200
    assert h.repairs.launch_records.get(SCRIPT) is None


def test_read_only_preview_cannot_forget(tmp_path: Path) -> None:
    """预览模式不允许任何改动，这个接口也一样被拒绝。"""
    h = _harness(tmp_path)
    h.entries = (entry(SCRIPT, state="stopped", ports=(8765,)),)
    app = FastAPI()
    app.include_router(create_patrol_router(h.patrol))
    install_local_request_guard(app, read_only_preview=True)
    client = cast(ApiClient, TestClient(app, base_url="http://127.0.0.1"))
    response = client.post(f"/api/patrol/services/{SCRIPT}/forget", headers=SAME_ORIGIN)
    assert response.status_code == 403
    assert h.repairs.launch_records.get(SCRIPT) is not None


def test_local_patrol_forgets_launch_record_and_mark(tmp_path: Path) -> None:
    h = PatrolHarness(tmp_path)
    h.repairs.launch_records.put(local_launch(tmp_path))
    h.repairs.marks[SCRIPT] = ServiceMark.MINE
    h.entries = (entry(SCRIPT, state="stopped", ports=(8765,)),)
    cleared: list[str] = []
    patrol = build_local_patrol(
        root=tmp_path / "data",
        node_id=h.patrol._node_id,  # pyright: ignore[reportPrivateUsage]
        services=h.services,
        conversations=h.conversations,
        repairs=h.repairs.service,
        launch_records=h.repairs.launch_records,
        clear_mark=cleared.append,
    )
    asyncio.run(patrol.forget(SCRIPT))
    assert h.repairs.launch_records.get(SCRIPT) is None
    assert cleared == [SCRIPT]

    # 不传清标记的回调时只删启动记录。
    h.repairs.launch_records.put(local_launch(tmp_path))
    plain = build_local_patrol(
        root=tmp_path / "data2",
        node_id=h.patrol._node_id,  # pyright: ignore[reportPrivateUsage]
        services=h.services,
        conversations=h.conversations,
        repairs=h.repairs.service,
        launch_records=h.repairs.launch_records,
    )
    asyncio.run(plain.forget(SCRIPT))
    assert h.repairs.launch_records.get(SCRIPT) is None
