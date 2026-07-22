"""本机 thread/run HTTP 与 SSE 路由测试。"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Protocol, Self, cast

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from tests.agent.test_langchain_agent import build_agent

from tunnelminion.agent.conversation import InMemoryConversationService, RunEvent
from tunnelminion.agent.runtime import LangChainReadOnlyAgent
from tunnelminion.domain.identifiers import NodeId, RunId, ThreadId
from tunnelminion.model.contracts import ProviderError, ProviderErrorCode
from tunnelminion.web.conversation import create_conversation_router


class ApiClient(Protocol):
    """屏蔽 TestClient 当前缺失的严格类型标注。"""

    def __enter__(self) -> Self: ...

    def __exit__(self, *args: object) -> None: ...

    def get(self, url: str) -> httpx.Response: ...

    def post(self, url: str, *, json: object | None = None) -> httpx.Response: ...

    def delete(self, url: str) -> httpx.Response: ...


def build_client(
    service: InMemoryConversationService | None = None,
) -> tuple[ApiClient, InMemoryConversationService]:
    """组装只包含会话路由的测试应用。"""
    value = service or InMemoryConversationService(NodeId.new(), lambda: build_agent()[0])
    app = FastAPI()
    app.include_router(create_conversation_router(value))
    return cast(ApiClient, TestClient(app)), value


def test_conversation_http_and_sse_success(monkeypatch: pytest.MonkeyPatch) -> None:
    """HTTP 可创建线程/run、读取终态并流出无隐藏推理的 SSE。"""
    client, service = build_client()
    with client:
        created = client.post("/api/threads")
        assert created.status_code == 200
        thread_id = cast(dict[str, object], created.json())["thread_id"]
        threads = cast(list[dict[str, object]], client.get("/api/threads").json())
        assert threads[0]["thread_id"] == thread_id

        started = client.post(
            f"/api/threads/{thread_id}/runs",
            json={"question": "检查服务", "tool_names": ["probe_service"]},
        )
        assert started.status_code == 200
        run_id = cast(dict[str, object], started.json())["run_id"]
        streamed = client.get(f"/api/runs/{run_id}/events")
        assert streamed.status_code == 200
        assert streamed.headers["content-type"].startswith("text/event-stream")
        assert "event: goal" in streamed.text
        assert "event: tool" in streamed.text
        assert "event: finished" in streamed.text
        assert "hidden_reasoning" not in streamed.text

        final = client.get(f"/api/runs/{run_id}")
        assert cast(dict[str, object], final.json())["status"] == "completed"
        detail = cast(dict[str, object], client.get(f"/api/threads/{thread_id}").json())
        assert len(cast(list[object], detail["messages"])) == 2
        cancelled = cast(dict[str, object], client.post(f"/api/runs/{run_id}/cancel").json())
        assert cancelled["status"] == "completed"

        async def vanished(_run_id: RunId, _after: int = 0) -> AsyncIterator[RunEvent]:
            if False:
                yield RunEvent.model_validate({})
            raise KeyError("run_not_found")

        monkeypatch.setattr(service, "stream_events", vanished)
        assert client.get(f"/api/runs/{run_id}/events").text == ""
        page = client.get("/chat")
        assert page.status_code == 200
        assert "TunnelMinion 只读诊断" in page.text
        assert "EventSource" in page.text
        assert client.delete(f"/api/threads/{thread_id}").status_code == 204


def test_conversation_routes_map_invalid_and_missing_ids() -> None:
    """畸形与不存在的 thread/run ID 都稳定映射为 404。"""
    client, _ = build_client()
    with client:
        valid_body = {"question": "x", "tool_names": ["probe_service"]}
        assert client.post("/api/threads/bad/runs", json=valid_body).status_code == 404
        missing_thread = ThreadId.new()
        assert (
            client.post(
                f"/api/threads/{missing_thread}/runs",
                json=valid_body,
            ).status_code
            == 404
        )
        missing_run = RunId.new()
        assert client.get("/api/runs/bad").status_code == 404
        assert client.get(f"/api/runs/{missing_run}").status_code == 404
        assert client.post(f"/api/runs/{missing_run}/cancel").status_code == 404
        assert client.get(f"/api/runs/{missing_run}/events").status_code == 404
        assert client.get(f"/api/threads/{missing_thread}").status_code == 404
        assert client.delete(f"/api/threads/{missing_thread}").status_code == 404


def test_model_unavailable_maps_to_service_unavailable() -> None:
    """模型门卫失败时不创建 run，并向本机调用者返回 503。"""

    def unavailable_agent() -> LangChainReadOnlyAgent:
        raise ProviderError(ProviderErrorCode.MODEL_NOT_FOUND, "模型未配置")

    service = InMemoryConversationService(NodeId.new(), unavailable_agent)
    client, _ = build_client(service)
    with client:
        thread_id = cast(dict[str, object], client.post("/api/threads").json())["thread_id"]
        response = client.post(
            f"/api/threads/{thread_id}/runs",
            json={"question": "x", "tool_names": ["probe_service"]},
        )
        assert response.status_code == 503
        assert cast(dict[str, object], response.json())["detail"] == "模型未配置"
