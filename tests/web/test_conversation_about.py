"""地图对话使用当前本机服务清单并保留用户原文。"""

from pathlib import Path
from typing import cast

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from tests.agent.test_langchain_agent import ScriptedProvider, build_agent
from tests.web.test_conversation import ApiClient
from tests.web.test_service_map import NODE, Cache, snapshot

from tunnelminion.agent.conversation import InMemoryConversationService
from tunnelminion.agent.service_marks import InMemoryServiceMarkStore, ServiceMark
from tunnelminion.domain.identifiers import NodeId, RunId
from tunnelminion.memory.sqlite import SQLiteStores
from tunnelminion.web.conversation import create_conversation_router
from tunnelminion.web.service_map import build_local_service_map


def client_for(
    conversations: InMemoryConversationService, *, local: bool = True, hidden: bool = False
) -> ApiClient:
    """挂载与首页相同的假清单。"""
    app = FastAPI()
    cache = Cache(snapshot())
    marks = InMemoryServiceMarkStore()
    if hidden:
        marks.set("docker:compose:penpot", ServiceMark.HIDDEN)
    app.include_router(
        create_conversation_router(
            conversations,
            local_services=(
                (lambda: build_local_service_map(NODE, cache.read(), marks.all()))
                if local
                else None
            ),
        )
    )
    return cast(ApiClient, TestClient(app))


@pytest.mark.parametrize("ui", [False, True])
@pytest.mark.parametrize("service_key", [None, "docker:compose:penpot"])
def test_about_title_context_and_goal_persist(
    tmp_path: Path, ui: bool, service_key: str | None
) -> None:
    provider = ScriptedProvider()
    agent = build_agent(provider)[0]
    stores = SQLiteStores.open(tmp_path / "about.sqlite3")
    conversations = InMemoryConversationService(NODE, lambda: agent, stores.checkpoints)
    with client_for(conversations) as client:
        created = client.post("/api/threads").json()
        identifier = created["thread_id"]
        assert created["title"] is None and created["context"] is None
        question = "  " + "我的问题很长" * 12 + "  "
        about = {"node_id": str(NODE), "service_key": service_key}
        path = f"/api/{'ui/' if ui else ''}threads/{identifier}/runs"
        response = client.post(
            path, json={"question": question, "tool_names": ["probe_service"], "about": about}
        )
        assert response.status_code == 200
        client.get(f"/api/runs/{response.json()['run_id']}/events")
        context = {**about, "service_name": "penpot" if service_key else None}
        summary = client.get("/api/threads").json()[0]
        assert summary["title"] == question.strip()[:40]
        assert summary["context"] == context
        detail = client.get(f"/api/threads/{identifier}").json()
        assert detail["context"] == detail["thread"]["context"] == context
        assert detail["messages"][0]["content"] == question
        goal = "\n".join(item.content for item in provider.requests[0].messages)
        assert '关于：{"node_id":' in goal
        if service_key:
            assert '"service_name":"penpot"' in goal
            assert '"kind":"docker"' in goal
            assert service_key in goal and "tcp/9001" in goal and "tcp/1080" in goal
        followup = client.post(path, json={"question": "接着问", "tool_names": ["probe_service"]})
        assert followup.status_code == 200
        client.get(f"/api/runs/{followup.json()['run_id']}/events")
        assert client.get("/api/threads").json()[0]["title"] == summary["title"]
        changed = client.post(
            path,
            json={
                "question": "换个对象",
                "tool_names": ["probe_service"],
                "about": {
                    "node_id": str(NODE),
                    "service_key": None if service_key else "docker:compose:penpot",
                },
            },
        )
        assert changed.status_code == 422

    restored = InMemoryConversationService(NODE, lambda: agent, stores.checkpoints)
    restored_context = restored.list_threads()[0].context
    assert restored_context is not None
    assert restored_context.model_dump() == context
    assert restored.list_threads()[0].title == summary["title"]


@pytest.mark.parametrize("invalid", ["unknown", "hidden", "other-node", "extra", "no-source"])
@pytest.mark.parametrize("ui", [False, True])
def test_invalid_about_never_starts_agent(invalid: str, ui: bool) -> None:
    provider = ScriptedProvider()
    conversations = InMemoryConversationService(NODE, lambda: build_agent(provider)[0])
    with client_for(
        conversations, local=invalid != "no-source", hidden=invalid == "hidden"
    ) as client:
        identifier = client.post("/api/threads").json()["thread_id"]
        about: dict[str, object] = {"node_id": str(NODE), "service_key": "docker:compose:penpot"}
        if invalid == "unknown":
            about["service_key"] = "docker:compose:missing"
        elif invalid == "other-node":
            about["node_id"] = str(NodeId.new())
        elif invalid == "extra":
            about["service_name"] = "不能由用户指定名称"
        response = client.post(
            f"/api/{'ui/' if ui else ''}threads/{identifier}/runs",
            json={"question": "怎么打不开？", "tool_names": ["probe_service"], "about": about},
        )
        assert response.status_code == 422
        if invalid != "extra":
            assert isinstance(response.json()["detail"], str)
        assert provider.requests == []
        detail = client.get(f"/api/threads/{identifier}").json()
        assert detail["messages"] == [] and detail["context"] is None


@pytest.mark.parametrize("existing_about", [False, True])
def test_first_about_on_interrupted_legacy_thread(tmp_path: Path, existing_about: bool) -> None:
    """中断任务续办时首次关联或沿用地图对象。"""
    provider = ScriptedProvider()
    agent = build_agent(provider)[0]
    stores = SQLiteStores.open(tmp_path / "interrupted-about.sqlite3")
    original = InMemoryConversationService(NODE, lambda: agent, stores.checkpoints)
    with client_for(original) as client:
        thread_id = client.post("/api/threads").json()["thread_id"]
        started = client.post(
            f"/api/threads/{thread_id}/runs",
            json={
                "question": "旧问题",
                "tool_names": ["probe_service"],
                "about": {"node_id": str(NODE), "service_key": None} if existing_about else None,
            },
        ).json()
        client.get(f"/api/runs/{started['run_id']}/events")
    checkpoint = stores.checkpoints.get(RunId(started["run_id"]))
    assert checkpoint is not None
    public = dict(checkpoint.public_state)
    run = public["run"]
    assert isinstance(run, dict)
    run.update(status="running", result=None, finished_at=None)
    stores.checkpoints.put(checkpoint.model_copy(update={"public_state": public}))
    restored = InMemoryConversationService(NODE, lambda: agent, stores.checkpoints)
    with client_for(restored) as client:
        response = client.post(
            f"/api/threads/{thread_id}/runs",
            json={
                "question": "继续原问题",
                "tool_names": ["probe_service"],
                "about": {"node_id": str(NODE), "service_key": None},
            },
        )
        assert response.status_code == 200
        client.get(f"/api/runs/{response.json()['run_id']}/events")
        detail = client.get(f"/api/threads/{thread_id}").json()
        assert detail["context"] == {
            "node_id": str(NODE),
            "service_key": None,
            "service_name": None,
        }
        assert detail["messages"][-2]["content"] == "继续原问题"
        assert any('关于：{"node_id":' in item.content for item in provider.requests[-1].messages)
