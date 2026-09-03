"""Overview incident 投影、详情与上下文追问 API 测试。"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol, cast
from unittest.mock import AsyncMock

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from tests.agent.test_langchain_agent import build_agent

from tunnelminion.agent.conversation import InMemoryConversationService, RunStatus, RunView
from tunnelminion.domain.identifiers import NodeId, RunId, ServiceId, SnapshotId
from tunnelminion.incident.contracts import (
    IncidentEventType,
    IncidentReport,
    InvestigationStopReason,
    SnapshotDiffEvent,
    SnapshotObjectKind,
    SnapshotSource,
)
from tunnelminion.incident.investigation import READ_ONLY_INVESTIGATION_TOOLS
from tunnelminion.incident.storage import SQLiteIncidentStore
from tunnelminion.model.contracts import ProviderError, ProviderErrorCode
from tunnelminion.web.incidents import (
    create_incident_router,
    incidents_overview,
    suggested_questions,
)

NOW = datetime(2026, 9, 3, 9, tzinfo=UTC)
NODE = NodeId("node_0123456789abcdef0123456789abcdef")
SERVICE = ServiceId("service_0123456789abcdef0123456789abcdef")


class ApiClient(Protocol):
    def get(self, url: str) -> httpx.Response: ...

    def post(self, url: str, *, json: object) -> httpx.Response: ...


def _store(tmp_path: Path) -> SQLiteIncidentStore:
    store = SQLiteIncidentStore(tmp_path / "incidents.sqlite3")
    store.record_event(
        SnapshotDiffEvent(
            event_type=IncidentEventType.LOCAL_ONLY,
            object_kind=SnapshotObjectKind.SERVICE,
            object_id=str(SERVICE),
            target_node_id=NODE,
            baseline_snapshot_id=SnapshotId("snapshot_" + "1" * 32),
            current_snapshot_id=SnapshotId("snapshot_" + "2" * 32),
            baseline_revision=1,
            current_revision=2,
            observed_at=NOW,
            source=SnapshotSource.LOCAL_OBSERVATION,
            before_state="network",
            after_state="loopback",
            dedup_key="sha256:" + "a" * 64,
        )
    )
    return store


def test_overview_and_detail_share_bounded_public_incident(tmp_path: Path) -> None:
    store = _store(tmp_path)
    incident = store.list_recent()[0]
    conversations = InMemoryConversationService(NODE, lambda: build_agent()[0])
    app = FastAPI()
    app.include_router(create_incident_router(store, conversations))
    client = cast(ApiClient, TestClient(app))

    overview = incidents_overview(store)
    response = client.get(f"/api/incidents/{incident.incident_id}")

    assert overview.items[0].incident_id == incident.incident_id
    assert overview.items[0].severity.value == "warning"
    assert response.status_code == 200
    assert response.json()["incident"]["event"]["event_type"] == "local_only"
    assert response.json()["suggested_questions"] == ["为什么这个服务只能从本机访问？"]
    assert response.json()["thread_id"] is None
    assert client.get("/api/incidents/not-an-id").status_code == 404
    assert client.get(f"/api/incidents/incident_{'f' * 32}").status_code == 404

    with_unknown = incident.model_copy(
        update={
            "report": IncidentReport(
                unknowns=("还不知道监听进程",),
                stop_reason=InvestigationStopReason.INSUFFICIENT_EVIDENCE,
            )
        }
    )
    assert suggested_questions(with_unknown) == (
        "关于“还不知道监听进程”，还缺少什么只读证据？",
        "为什么这个服务只能从本机访问？",
    )


def test_follow_up_reuses_conversation_with_fixed_read_only_tools_without_mutating_incident(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(tmp_path)
    incident = store.list_recent()[0]
    conversations = InMemoryConversationService(NODE, lambda: build_agent()[0])
    run = RunView(
        run_id=RunId("run_" + "3" * 32),
        thread_id=conversations.create_thread().thread_id,
        status=RunStatus.RUNNING,
        created_at=NOW,
    )
    start = AsyncMock(return_value=run)
    monkeypatch.setattr(conversations, "start_incident_run", start)
    app = FastAPI()
    app.include_router(create_incident_router(store, conversations))
    client = cast(ApiClient, TestClient(app))
    before = incident.model_dump_json()

    response = client.post(
        f"/api/incidents/{incident.incident_id}/follow-up",
        json={"question": "还缺什么证据？"},
    )

    assert response.status_code == 200
    assert start.await_args is not None
    _thread_id, value, context = start.await_args.args
    assert value.tool_names == READ_ONLY_INVESTIGATION_TOOLS
    assert value.question == "还缺什么证据？"
    assert "local_only" in context
    assert len(context) <= 12_000
    stored = store.get(incident.incident_id)
    assert stored is not None and stored.model_dump_json() == before
    assert store.thread_for(incident.incident_id) is not None

    start.side_effect = ProviderError(
        ProviderErrorCode.NETWORK_UNREACHABLE,
        "secret provider message",
    )
    unavailable = client.post(
        f"/api/incidents/{incident.incident_id}/follow-up",
        json={"question": "再试一次"},
    )
    assert unavailable.status_code == 503
    assert unavailable.json()["detail"] == "模型调查当前不可用"
    assert "secret provider message" not in unavailable.text
