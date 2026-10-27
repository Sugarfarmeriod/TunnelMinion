"""远端地图对象只使用已知目录与进程内缓存。"""

import asyncio
from pathlib import Path
from typing import cast

import httpx
import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
from tests.agent.test_langchain_agent import ScriptedProvider, build_agent
from tests.agent.test_remote_service_presentation import cache, node
from tests.gateway.test_services import LOCAL, REMOTE
from tests.web.test_conversation import ApiClient
from tests.web.test_peers import configuration, peer, snapshot

from tunnelminion.agent.conversation import InMemoryConversationService
from tunnelminion.domain.identifiers import NodeId
from tunnelminion.tools.audit import InMemoryAuditSink
from tunnelminion.web.conversation import create_conversation_router
from tunnelminion.web.peers import PeerCache, PeerServicePoller, PeerServicesView


@pytest.mark.parametrize(
    "mode", ["known", "offline", "coordinator", "unknown", "service", "hidden"]
)
@pytest.mark.parametrize("service_key", [None, "python:app.py@8080"])
def test_peer_about_uses_cached_identity_without_network(
    tmp_path: Path, mode: str, service_key: str | None
) -> None:
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        return snapshot()

    poller = PeerServicePoller(
        configuration(tmp_path, peer(name="测试对端")),
        LOCAL,
        InMemoryAuditSink(),
        transport=httpx.MockTransport(handler),
    )
    asyncio.run(poller.refresh())
    if mode in {"offline", "hidden"}:
        previous = poller.read(REMOTE)
        poller._cache[str(REMOTE)] = PeerCache(  # pyright: ignore[reportPrivateUsage]
            snapshot=previous.snapshot,
            reachable=mode != "offline",
            services_visible=mode != "hidden",
        )
    other = NodeId("node_" + "c" * 32)
    directory = cache(node(other))
    provider = ScriptedProvider()
    conversations = InMemoryConversationService(LOCAL, lambda: build_agent(provider)[0])
    app = FastAPI()
    app.include_router(
        create_conversation_router(
            conversations, peer_services=lambda value: poller.services_view(value, directory)
        )
    )
    about = {
        "node_id": str(other if mode == "coordinator" else LOCAL if mode == "unknown" else REMOTE),
        "service_key": "missing" if mode == "service" else service_key,
    }
    if mode == "unknown":
        about["node_id"] = "node_" + "d" * 32
    accepted = mode not in {"unknown", "service"} and not (
        service_key and mode in {"coordinator", "hidden"}
    )
    with cast(ApiClient, TestClient(app, base_url="http://127.0.0.1")) as client:
        identifier = client.post("/api/threads").json()["thread_id"]
        path = f"/api/threads/{identifier}/runs"
        response = client.post(
            path, json={"question": "怎么打不开？", "tool_names": ["probe_service"], "about": about}
        )
        assert response.status_code == (200 if accepted else 422)
        if accepted:
            client.get(f"/api/runs/{response.json()['run_id']}/events")
            goal = "\n".join(item.content for item in provider.requests[0].messages)
            assert '"location":"另一台电脑"' in goal and "请委派" in goal
            assert str(about["node_id"]) in goal
            if service_key:
                assert '"service_name":"示例服务"' in goal and "tcp/8080" in goal
            assert (
                client.post(
                    path, json={"question": "接着问", "tool_names": ["probe_service"]}
                ).status_code
                == 200
            )
        else:
            assert provider.requests == []
    assert len(calls) == 1


def test_peer_context_propagates_non_directory_errors() -> None:
    def unavailable(_value: str) -> PeerServicesView:
        raise HTTPException(503, "缓存暂不可用")

    app = FastAPI()
    conversations = InMemoryConversationService(LOCAL, lambda: build_agent(ScriptedProvider())[0])
    app.include_router(create_conversation_router(conversations, peer_services=unavailable))
    with cast(ApiClient, TestClient(app, base_url="http://127.0.0.1")) as client:
        identifier = client.post("/api/threads").json()["thread_id"]
        response = client.post(
            f"/api/threads/{identifier}/runs",
            json={
                "question": "看看",
                "tool_names": ["probe_service"],
                "about": {"node_id": str(REMOTE)},
            },
        )
        assert response.status_code == 503
