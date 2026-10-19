"""既有事件追问入口实际运行共享任务，不回退到无关联的本机聊天。"""

from __future__ import annotations

from pathlib import Path
from typing import cast

import httpx
from fastapi import FastAPI
from fastapi.testclient import TestClient
from tests.incident.test_investigation import (
    ScriptedProvider,
    _incident,  # pyright: ignore[reportPrivateUsage]
)
from tests.incident.test_tasks import task_harness

from tunnelminion.incident.contracts import IncidentEventType
from tunnelminion.model.contracts import (
    CancellationToken,
    ModelRequest,
    ModelResponse,
    ProviderError,
    ProviderErrorCode,
)
from tunnelminion.web.conversation import create_conversation_router
from tunnelminion.web.incidents import create_incident_router


def test_existing_follow_up_route_returns_same_task_thread_and_streams_real_checks(
    tmp_path: Path,
) -> None:
    harness, provider, follow_up_provider, _ = task_harness(tmp_path)
    incident = _incident(harness.store, event_type=IncidentEventType.SERVICE_ADDED)
    app = FastAPI()
    app.include_router(create_incident_router(harness.store, harness.conversations, tasks=harness))
    app.include_router(create_conversation_router(harness.conversations))
    route = f"/api/incidents/{incident.incident_id}"
    with TestClient(app) as raw_client:
        client = cast(httpx.Client, raw_client)
        started = client.post(route + "/follow-up", json={"question": "查清这个变化"})
        assert started.status_code == 200
        run_id = started.json()["run_id"]
        stream = client.get(f"/api/runs/{run_id}/events")
        assert "event: tool" in stream.text and "event: finished" in stream.text
        detail = client.get(route).json()
        assert detail["incident"]["run_id"] == run_id
        assert detail["thread_id"] == started.json()["thread_id"]
        follow_up = client.post(route + "/follow-up", json={"question": "解释这些记录"})
        assert follow_up.status_code == 200
        assert follow_up.json()["thread_id"] == detail["thread_id"]
        assert client.get(f"/api/runs/{follow_up.json()['run_id']}/events").status_code == 200
        assert (
            client.post(
                route + "/follow-up", json={"question": "检查", "node_id": "另一个节点"}
            ).status_code
            == 422
        )
    assert len(provider.requests) == 3 and len(follow_up_provider.requests) == 1


def test_running_and_deleted_incident_thread_get_clear_conflict_result(tmp_path: Path) -> None:
    class WaitingProvider(ScriptedProvider):
        async def complete(
            self, request: ModelRequest, cancellation: CancellationToken | None = None
        ) -> ModelResponse:
            del request
            assert cancellation is not None
            await cancellation.wait()
            raise ProviderError(ProviderErrorCode.CANCELLED, "已停止")

    harness, _, _, _ = task_harness(tmp_path, provider=WaitingProvider("valid"))
    incident = _incident(harness.store, event_type=IncidentEventType.SERVICE_ADDED)
    app = FastAPI()
    app.include_router(create_incident_router(harness.store, harness.conversations, tasks=harness))
    app.include_router(create_conversation_router(harness.conversations))
    route = f"/api/incidents/{incident.incident_id}/follow-up"
    with TestClient(app) as raw_client:
        client = cast(httpx.Client, raw_client)
        started = client.post(route, json={"question": "检查"}).json()
        assert client.post(route, json={"question": "重复调查"}).status_code == 409
        assert client.post(f"/api/runs/{started['run_id']}/cancel").status_code == 200
        assert client.get(f"/api/runs/{started['run_id']}/events").status_code == 200
        assert client.delete(f"/api/threads/{started['thread_id']}").status_code == 204
        response = client.post(route, json={"question": "继续旧调查"})
        assert response.status_code == 409
        assert "已删除" in response.json()["detail"]
