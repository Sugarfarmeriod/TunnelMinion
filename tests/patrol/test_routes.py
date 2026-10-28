"""巡检接口只认本机同源请求；开关接口拒绝没有现成修法或不在地图上的服务。"""

from __future__ import annotations

import asyncio
import inspect
from pathlib import Path
from typing import Protocol, cast

import httpx
from fastapi import FastAPI
from fastapi.testclient import TestClient
from tests.patrol.fakes import PHOTOS, PROGRAM, PatrolHarness, entry
from tests.repair.factories import NODE, NOW

from tunnelminion.domain.identifiers import NodeId, SnapshotId
from tunnelminion.gateway import api as gateway_api
from tunnelminion.incident.contracts import (
    IncidentEventType,
    SnapshotDiffEvent,
    SnapshotObjectKind,
    SnapshotSource,
)
from tunnelminion.patrol.local import build_local_patrol, patrol_covers
from tunnelminion.patrol.storage import SQLitePatrolStore
from tunnelminion.web.patrol import create_patrol_router
from tunnelminion.web.request_guard import install_local_request_guard

SAME_ORIGIN = {"origin": "http://127.0.0.1", "x-tunnelminion-request": "same-origin"}


class ApiClient(Protocol):
    def get(self, url: str) -> httpx.Response: ...

    def put(
        self, url: str, *, json: object = None, headers: dict[str, str] | None = None
    ) -> httpx.Response: ...

    def post(self, url: str, *, headers: dict[str, str] | None = None) -> httpx.Response: ...


def client_for(h: PatrolHarness) -> ApiClient:
    app = FastAPI()
    app.include_router(create_patrol_router(h.patrol))
    install_local_request_guard(app, read_only_preview=False)
    return cast(ApiClient, TestClient(app, base_url="http://127.0.0.1"))


def test_view_switch_and_acknowledge(tmp_path: Path) -> None:
    h = PatrolHarness(tmp_path)
    h.entries = (entry(), entry(PROGRAM, ports=(9000,)))
    client = client_for(h)
    body = client.get("/api/patrol").json()
    assert body["investigations_left_today"] == 12
    assert [item["key"] for item in body["services"]] == [PHOTOS, PROGRAM]
    assert body["services"][0]["auto_repair"]["available"] is True

    url = f"/api/patrol/services/{PHOTOS}/auto-repair"
    assert (
        client.put(
            url,
            json={"enabled": True},
            headers={"origin": "http://other.example", "x-tunnelminion-request": "same-origin"},
        ).status_code
        == 403
    )
    response = client.put(url, json={"enabled": True}, headers=SAME_ORIGIN)
    assert response.status_code == 200
    assert response.json()["services"][0]["auto_repair"]["enabled"] is True
    assert (
        client.put(
            f"/api/patrol/services/{PROGRAM}/auto-repair",
            json={"enabled": True},
            headers=SAME_ORIGIN,
        ).status_code
        == 422
    )
    assert (
        client.put(
            "/api/patrol/services/docker:missing/auto-repair",
            json={"enabled": True},
            headers=SAME_ORIGIN,
        ).status_code
        == 404
    )
    assert (
        client.put(
            "/api/patrol/services/bad key/auto-repair",
            json={"enabled": True},
            headers=SAME_ORIGIN,
        ).status_code
        == 404
    )

    ack = f"/api/patrol/services/{PHOTOS}/acknowledge"
    assert client.post(ack, headers=SAME_ORIGIN).status_code == 409
    assert (
        client.post("/api/patrol/services/docker:x/acknowledge", headers=SAME_ORIGIN).status_code
        == 404
    )

    async def down() -> None:
        await h.rounds(1)
        h.entries = (entry(state="stopped"), entry(PROGRAM, ports=(9000,)))
        await h.rounds(1)

    asyncio.run(down())
    response = client.post(ack, headers=SAME_ORIGIN)
    assert response.status_code == 200
    assert response.json()["services"][0]["status"] == "acknowledged"


def test_gateway_has_no_patrol_routes() -> None:
    # 开关只能在本机网页改：跨电脑的 Gateway 不挂任何巡检路由。
    source = inspect.getsource(gateway_api)
    assert "patrol" not in source


def _event(event_type: IncidentEventType, node: NodeId) -> SnapshotDiffEvent:
    return SnapshotDiffEvent(
        event_type=event_type,
        object_kind=SnapshotObjectKind.SERVICE,
        object_id="service_" + "a" * 32,
        target_node_id=node,
        baseline_snapshot_id=SnapshotId("snapshot_" + "a" * 32),
        current_snapshot_id=SnapshotId("snapshot_" + "b" * 32),
        baseline_revision=1,
        current_revision=2,
        observed_at=NOW,
        source=SnapshotSource.LOCAL_OBSERVATION,
        dedup_key="sha256:" + "0" * 64,
    )


def test_patrol_covers_only_local_down_events() -> None:
    covers = patrol_covers(NODE)
    other = NodeId("node_" + "2" * 32)
    assert covers(_event(IncidentEventType.SERVICE_REMOVED, NODE))
    assert covers(_event(IncidentEventType.REMOTE_UNREACHABLE, NODE))
    assert not covers(_event(IncidentEventType.SERVICE_ADDED, NODE))
    assert not covers(_event(IncidentEventType.SERVICE_REMOVED, other))


def test_build_local_patrol_uses_data_dir(tmp_path: Path) -> None:
    h = PatrolHarness(tmp_path)
    patrol = build_local_patrol(
        root=tmp_path / "data",
        node_id=NODE,
        services=h.services,
        conversations=h.conversations,
        repairs=h.repairs.service,
        launch_records=h.repairs.launch_records,
    )
    view = patrol.view()
    assert [item.auto_repair.available for item in view.services] == [True]
    assert not (tmp_path / "data" / "patrol.sqlite3").exists()
    patrol.set_auto_repair("docker:compose:photos", enabled=True)
    assert (tmp_path / "data" / "patrol.sqlite3").exists()
    # 重新打开已有的库也能读到。
    reopened = SQLitePatrolStore(tmp_path / "data" / "patrol.sqlite3")
    assert reopened.get("docker:compose:photos") is not None
    assert SQLitePatrolStore(tmp_path / "none.sqlite3").get("x") is None
