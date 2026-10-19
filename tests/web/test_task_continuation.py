"""续办 API 使用当前清单核对对象，保持既有公开 run 契约。"""

from pathlib import Path

import pytest
from tests.agent.test_langchain_agent import build_agent
from tests.agent.test_task_continuation import ContinueProvider, interrupted_task
from tests.web.test_conversation import build_client, program_overview, selected_program

from tunnelminion.agent.conversation import InMemoryConversationService
from tunnelminion.agent.runtime import LangChainReadOnlyAgent, ServiceCheckTarget
from tunnelminion.domain.identifiers import RunId
from tunnelminion.model.contracts import ProviderError, ProviderErrorCode
from tunnelminion.web.overview import OverviewFreshness


def test_resume_api_preserves_public_contract_and_rejects_completed_task(tmp_path: Path) -> None:
    stores, node, identifier = interrupted_task(tmp_path)
    provider = ContinueProvider()
    restored = InMemoryConversationService(
        node, lambda: build_agent(provider)[0], stores.checkpoints
    )
    client, _ = build_client(restored)
    with client:
        response = client.post(f"/api/ui/runs/{identifier}/resume", json={"question": "继续整理"})
        assert response.status_code == 200
        resumed = response.json()["run_id"]
        assert client.get(f"/api/runs/{resumed}/events").status_code == 200
        assert set(response.json()) == {
            "run_id",
            "thread_id",
            "status",
            "created_at",
            "finished_at",
            "result",
            "error_code",
            "error_message",
            "failure",
        }
        assert client.post(f"/api/ui/runs/{resumed}/resume").status_code == 422
        assert client.post(f"/api/ui/runs/{identifier}/resume").json()["run_id"] == resumed
        assert client.post("/api/ui/runs/bad/resume").status_code == 404
        assert client.post(f"/api/ui/runs/{RunId.new()}/resume").status_code == 404
        assert (
            client.post(f"/api/ui/runs/{identifier}/resume", json={"question": ""}).status_code
            == 422
        )


@pytest.mark.parametrize("invalid", ["stale", "missing", "identity", "legacy"])
def test_resume_requires_current_matching_program(tmp_path: Path, invalid: str) -> None:
    item = selected_program()
    assert item.protocol is not None and item.port is not None
    target = ServiceCheckTarget(
        service_id=item.service_id,
        node_id=item.node_id,
        display_name="原名称",
        protocol=item.protocol,
        port=item.port,
    )
    stores, node, identifier = interrupted_task(tmp_path, target)
    if invalid == "legacy":
        record = stores.checkpoints.get(identifier)
        assert record is not None
        public = dict(record.public_state)
        public.pop("continuation")
        stores.checkpoints.put(record.model_copy(update={"public_state": public}))
    selected = (
        item.model_copy(update={"freshness": OverviewFreshness.STALE})
        if invalid == "stale"
        else item
    )
    if invalid == "identity":
        selected = item.model_copy(update={"port": item.port + 1})
    provider = ContinueProvider()
    restored = InMemoryConversationService(
        node, lambda: build_agent(provider)[0], stores.checkpoints
    )
    client, _ = build_client(restored, None if invalid == "missing" else program_overview(selected))
    with client:
        assert client.post(f"/api/ui/runs/{identifier}/resume").status_code == 422
    assert provider.requests == []


def test_resume_re_resolves_name_and_reports_unavailable_model(tmp_path: Path) -> None:
    item = selected_program()
    assert item.protocol is not None and item.port is not None
    target = ServiceCheckTarget(
        service_id=item.service_id,
        node_id=item.node_id,
        display_name="旧名称",
        protocol=item.protocol,
        port=item.port,
    )
    stores, node, identifier = interrupted_task(tmp_path, target)

    def unavailable() -> LangChainReadOnlyAgent:
        raise ProviderError(ProviderErrorCode.MODEL_NOT_FOUND, "未配置")

    restored = InMemoryConversationService(node, unavailable, stores.checkpoints)
    client, _ = build_client(restored, program_overview(item))
    with client:
        assert client.post(f"/api/ui/runs/{identifier}/resume").status_code == 503
