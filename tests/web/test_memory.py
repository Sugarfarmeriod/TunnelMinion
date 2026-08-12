"""长期记忆 API 与管理页面测试。"""

from __future__ import annotations

from pathlib import Path
from typing import Protocol, cast

import httpx
from fastapi import FastAPI
from fastapi.testclient import TestClient

from tunnelminion.domain.identifiers import NodeId
from tunnelminion.memory.service import LongTermMemoryService
from tunnelminion.memory.sqlite import SQLiteStores
from tunnelminion.web.memory import create_memory_router


class ApiClient(Protocol):
    """屏蔽 TestClient 当前缺失的严格类型标注。"""

    def get(self, url: str, *, params: dict[str, str] | None = None) -> httpx.Response: ...

    def post(self, url: str, *, json: object) -> httpx.Response: ...

    def put(self, url: str, *, json: object) -> httpx.Response: ...

    def delete(self, url: str, *, params: dict[str, str] | None = None) -> httpx.Response: ...


def client(tmp_path: Path) -> ApiClient:
    """创建独立 SQLite 记忆 API。"""
    service = LongTermMemoryService(SQLiteStores.open(tmp_path / "web.sqlite3").memories)
    app = FastAPI()
    app.include_router(create_memory_router(service))
    return cast(ApiClient, TestClient(app))


def payload(node_id: NodeId, **updates: object) -> dict[str, object]:
    """创建用户确认的稳定记忆请求。"""
    value: dict[str, object] = {
        "namespace": {"user": "local-user", "network": "home", "node_id": str(node_id)},
        "kind": "node-alias",
        "content": "B 是家里的 Mac",
        "source": "用户确认",
        "origin": "user-statement",
        "user_confirmed": True,
    }
    value.update(updates)
    return value


def test_memory_api_full_management_flow(tmp_path: Path) -> None:
    """API 支持确认、查看、修正、单条删除和按作用域清空。"""
    web = client(tmp_path)
    node_id = NodeId.new()
    query = {"user": "local-user", "network": "home", "node_id": str(node_id)}
    first = web.post("/api/memories/confirm", json=payload(node_id))
    second = web.post(
        "/api/memories/confirm",
        json=payload(node_id, content="偏好中文", kind="preference"),
    )
    assert first.status_code == second.status_code == 200

    listed = web.get("/api/memories", params=query)
    listed_body = cast(list[dict[str, object]], listed.json())
    assert [item["content"] for item in listed_body] == ["B 是家里的 Mac", "偏好中文"]
    memory_id = cast(dict[str, object], first.json())["memory_id"]
    sensitive_revision = web.put(
        f"/api/memories/{memory_id}",
        json={"content": "Bearer abcdefghijklmnop", "source": "用户修正"},
    )
    assert sensitive_revision.status_code == 400
    revised = web.put(
        f"/api/memories/{memory_id}",
        json={"content": "B 是书房 Mac", "source": "用户修正"},
    )
    assert revised.status_code == 200
    assert cast(dict[str, object], revised.json())["content"] == "B 是书房 Mac"
    assert web.delete(f"/api/memories/{memory_id}").status_code == 204
    assert len(cast(list[object], web.get("/api/memories", params=query).json())) == 1
    assert web.delete("/api/memories/scope", params=query).status_code == 204
    assert cast(list[object], web.get("/api/memories", params=query).json()) == []


def test_memory_api_rejections_and_page(tmp_path: Path) -> None:
    """管理页可发现，非法作用域、秘密和未知 ID 返回稳定错误。"""
    web = client(tmp_path)
    node_id = NodeId.new()
    page = web.get("/memories")
    assert page.status_code == 200
    assert "长期记忆" in page.text
    assert "保存修正" in page.text
    assert "清空此作用域" in page.text
    assert "X-TunnelMinion-Request" in page.text
    assert web.get("/legacy/memories").text == page.text

    rejected = web.post(
        "/api/memories/confirm",
        json=payload(node_id, content="api_key=forbidden"),
    )
    assert rejected.status_code == 400
    assert cast(dict[str, object], rejected.json())["detail"] == "sensitive_content_forbidden"
    assert (
        web.get(
            "/api/memories",
            params={"user": "u", "network": "n", "node_id": "bad"},
        ).status_code
        == 422
    )
    assert (
        web.put(
            "/api/memories/not-a-memory",
            json={"content": "x", "source": "user"},
        ).status_code
        == 404
    )
    unknown = f"memory_{'0' * 32}"
    assert (
        web.put(
            f"/api/memories/{unknown}",
            json={"content": "x", "source": "user"},
        ).status_code
        == 404
    )
    assert web.delete(f"/api/memories/{unknown}").status_code == 404
