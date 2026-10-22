"""本机服务清单与标记 API。"""

from __future__ import annotations

import os
from datetime import UTC, datetime
from typing import Any, Protocol, cast

import httpx
from fastapi import FastAPI
from fastapi.testclient import TestClient

from tunnelminion.agent.service_marks import InMemoryServiceMarkStore, ServiceMark
from tunnelminion.agent.service_observation import (
    ServiceObservationSnapshot,
    apply_service_marks,
)
from tunnelminion.agent.services import (
    EvidenceConfidence,
    RemoteServiceSummary,
    ServiceAccessibility,
    ServiceEvidence,
)
from tunnelminion.domain.identifiers import NodeId, ToolRunId
from tunnelminion.platforms.process_origin import ProcessOrigin
from tunnelminion.web.service_map import build_local_service_map, create_service_map_router

NODE = NodeId("node_0123456789abcdef0123456789abcdef")
NOW = datetime(2026, 10, 22, tzinfo=UTC)


def item(**values: object) -> RemoteServiceSummary:
    base: dict[str, object] = {
        "node_id": NODE,
        "protocol": "tcp",
        "address": "0.0.0.0",
        "port": 8000,
        "process_pid": 100,
        "process_name": "server",
        "accessibility": ServiceAccessibility.NETWORK_LISTENING,
        "confidence": EvidenceConfidence.MEDIUM,
        "evidence": (
            ServiceEvidence(
                tool_name="list_network_listeners", tool_run_id=ToolRunId.new(), observed_at=NOW
            ),
        ),
    }
    base.update(values)
    return RemoteServiceSummary.model_validate(base)


INVENTORY = (
    # 一个 compose 项目的两个容器 → 一项
    item(
        port=9001,
        process_name="OrbStack Helper",
        origin=ProcessOrigin.CONTAINER_RUNTIME,
        container_id="a",
        container_name="penpot-web-1",
        compose_project="penpot",
        container_running=True,
        has_web_page=True,
        web_title="Penpot",
    ),
    item(
        port=1080,
        address="127.0.0.1",
        process_name="OrbStack Helper",
        origin=ProcessOrigin.CONTAINER_RUNTIME,
        container_id="b",
        container_name="penpot-mail-1",
        compose_project="penpot",
        container_running=True,
    ),
    # 同一个脚本的两个监听地址 → 一项、两个入口
    item(
        port=8787,
        address="127.0.0.1",
        process_pid=200,
        process_name="python",
        python_entrypoint="app.py",
        origin=ProcessOrigin.TERMINAL,
        has_web_page=True,
        web_title="WireGuard Panel",
    ),
    item(
        port=8787,
        address="::1",
        process_pid=200,
        process_name="python",
        python_entrypoint="app.py",
        origin=ProcessOrigin.TERMINAL,
    ),
    # 可能是服务
    item(
        port=47990,
        process_pid=300,
        process_name="sunshine.exe",
        origin=ProcessOrigin.APP_SERVICE,
        has_web_page=True,
    ),
    item(
        port=47984,
        process_pid=300,
        process_name="sunshine.exe",
        origin=ProcessOrigin.APP_SERVICE,
        has_web_page=False,
    ),
    # 读不到进程号：只能按端口识别
    item(port=9000, process_pid=None, process_name="mystery"),
    # 默认不显示
    item(port=27036, process_pid=400, process_name="steam.exe", origin=ProcessOrigin.DESKTOP_APP),
    item(
        protocol="udp",
        port=5353,
        process_pid=500,
        process_name="mdns",
        origin=ProcessOrigin.TERMINAL,
    ),
    # TunnelMinion 自己
    item(port=8765, process_pid=os.getpid(), process_name="python", origin=ProcessOrigin.TERMINAL),
)


class ApiClient(Protocol):
    """屏蔽 TestClient 当前缺失的严格类型标注。"""

    def get(self, url: str) -> httpx.Response: ...

    def put(self, url: str, *, json: Any | None = None) -> httpx.Response: ...

    def delete(self, url: str) -> httpx.Response: ...


class Cache:
    """模拟服务快照缓存。"""

    def __init__(self, snapshot: ServiceObservationSnapshot | None) -> None:
        self.snapshot = snapshot
        self.replaced = 0

    def read(self) -> ServiceObservationSnapshot | None:
        return self.snapshot

    def replace(self, snapshot: ServiceObservationSnapshot) -> None:
        self.snapshot = snapshot
        self.replaced += 1


def snapshot() -> ServiceObservationSnapshot:
    return apply_service_marks(
        NODE,
        ServiceObservationSnapshot(observed_at=NOW, services=(), inventory=INVENTORY),
        {},
        excluded_pid=os.getpid(),
    )


def client(cache: Cache, marks: InMemoryServiceMarkStore) -> ApiClient:
    app = FastAPI()
    app.include_router(create_service_map_router(NODE, marks, cache.read, cache.replace))
    return cast(ApiClient, TestClient(app))


def summary(body: dict[str, Any]) -> list[tuple[str, str, str, str | None, list[int]]]:
    return [
        (
            entry["key"],
            entry["name"],
            entry["tier"],
            entry["mark"],
            [e["port"] for e in entry["endpoints"]],
        )
        for entry in body["services"]
    ]


def test_list_merges_ports_by_service_and_orders_by_tier() -> None:
    body = client(Cache(snapshot()), InMemoryServiceMarkStore()).get("/api/services/local").json()
    assert body["node_id"] == str(NODE) and body["observed_at"].startswith("2026-10-22")
    assert summary(body) == [
        ("docker:compose:penpot", "penpot", "show", None, [1080, 9001]),
        ("python:app.py", "WireGuard Panel", "show", None, [8787, 8787]),
        ("port:tcp:9000", "mystery", "review", None, [9000]),
        ("program:sunshine", "sunshine", "review", None, [47990]),
    ]
    penpot, panel = body["services"][0], body["services"][1]
    assert penpot["kind"] == "docker" and penpot["web_title"] == "Penpot"
    assert panel["kind"] == "python" and {e["address"] for e in panel["endpoints"]} == {
        "127.0.0.1",
        "::1",
    }


def test_marking_moves_service_and_updates_the_home_page_immediately() -> None:
    cache = Cache(snapshot())
    marks = InMemoryServiceMarkStore()
    api = client(cache, marks)
    before = dict(cache.snapshot.display_names) if cache.snapshot else {}

    mine = api.put("/api/services/marks/program:sunshine", json={"mark": "mine"}).json()
    entry = next(e for e in mine["services"] if e["key"] == "program:sunshine")
    assert entry["tier"] == "show" and entry["mark"] == "mine"
    assert [e["port"] for e in entry["endpoints"]] == [47984, 47990]
    assert cache.replaced == 1 and cache.snapshot is not None
    assert len(cache.snapshot.display_names) == len(before) + 2

    hidden = api.put("/api/services/marks/docker:compose:penpot", json={"mark": "hidden"}).json()
    assert summary(hidden)[-1] == (
        "docker:compose:penpot",
        "penpot",
        "hidden",
        "hidden",
        [1080, 9001],
    )

    steam = api.put("/api/services/marks/program:steam", json={"mark": "hidden"}).json()
    assert summary(steam)[-1] == ("program:steam", "steam", "hidden", "hidden", [27036])
    udp_only = api.put("/api/services/marks/program:mdns", json={"mark": "hidden"}).json()
    assert ("program:mdns", "mdns", "hidden", "hidden", [5353]) in summary(udp_only)

    cleared = api.delete("/api/services/marks/program:sunshine").json()
    assert (
        next(e for e in cleared["services"] if e["key"] == "program:sunshine")["tier"] == "review"
    )
    assert marks.all() == {
        "docker:compose:penpot": ServiceMark.HIDDEN,
        "program:steam": ServiceMark.HIDDEN,
        "program:mdns": ServiceMark.HIDDEN,
    }


def test_invalid_keys_and_marks_are_rejected() -> None:
    api = client(Cache(snapshot()), InMemoryServiceMarkStore())
    assert api.put("/api/services/marks/whatever", json={"mark": "mine"}).status_code == 404
    assert api.delete("/api/services/marks/program:").status_code == 404
    assert api.put("/api/services/marks/program:x", json={"mark": "maybe"}).status_code == 422


def test_before_the_first_observation_the_list_is_empty() -> None:
    cache = Cache(None)
    api = client(cache, InMemoryServiceMarkStore())
    assert api.get("/api/services/local").json() == {
        "node_id": str(NODE),
        "observed_at": None,
        "services": [],
    }
    assert api.put("/api/services/marks/program:x", json={"mark": "mine"}).status_code == 200
    assert cache.replaced == 0
    assert build_local_service_map(NODE, None, {}).services == ()
