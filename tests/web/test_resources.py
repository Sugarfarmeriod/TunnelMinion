"""本机资源 API 和基础页面测试。"""

from __future__ import annotations

from typing import Protocol, cast

import httpx
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import JsonValue
from tests.tools.test_registry import definition

from tunnelminion.domain.identifiers import NodeId
from tunnelminion.domain.tools import Platform
from tunnelminion.tools.audit import InMemoryAuditSink
from tunnelminion.tools.fakes import FakeToolAdapter
from tunnelminion.tools.registry import ToolRegistry
from tunnelminion.tools.runtime import ToolRuntime
from tunnelminion.web.resources import create_resource_router


class ApiClient(Protocol):
    """屏蔽 TestClient 当前缺失的严格类型标注。"""

    def get(self, url: str, *, params: dict[str, object] | None = None) -> httpx.Response: ...

    def post(self, url: str, *, json: object) -> httpx.Response: ...


def test_resource_routes_work_without_model_provider() -> None:
    registry = ToolRegistry()
    for name in (
        "get_wireguard_status",
        "list_network_listeners",
        "get_process_summary",
        "list_docker_services",
        "probe_service_reachability",
        "get_node_summary",
    ):
        schema: dict[str, JsonValue] | None = (
            {"type": "object"}
            if name in {"get_process_summary", "probe_service_reachability"}
            else None
        )
        registry.register(definition(name, input_schema=schema), FakeToolAdapter())
    runtime = ToolRuntime(registry, Platform.WINDOWS, InMemoryAuditSink())
    app = FastAPI()
    app.include_router(create_resource_router(runtime, NodeId.new()))
    client = cast(ApiClient, TestClient(app))

    for path in ("wireguard", "listeners", "processes", "docker", "node-summary"):
        response = client.get(f"/api/resources/{path}")
        assert response.status_code == 200
        assert response.json()["status"] == "success"
    limited = client.get("/api/resources/processes", params={"limit": 2})
    assert limited.status_code == 200
    probe = client.post(
        "/api/resources/probe",
        json={"host": "127.0.0.1", "port": 8080},
    )
    assert probe.status_code == 200
    assert probe.json()["status"] == "success"

    page = client.get("/resources")
    assert page.status_code == 200
    assert "即使模型不可用" in page.text
    assert "refreshAll" in page.text
