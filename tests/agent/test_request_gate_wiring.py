"""本机用户入口接把关，收到的委派任务与真机评测入口复用同一模型边界。"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from pathlib import Path
from typing import cast

import httpx
import pytest
from tests.agent.test_langchain_agent import context
from tests.agent.test_request_gate import FakeProvider

from tunnelminion.agent.request_gate import RequestGate, RequestGateOutcome
from tunnelminion.agent.runtime import LangChainReadOnlyAgent
from tunnelminion.app import build_windows_application, build_windows_node
from tunnelminion.domain.identifiers import RunId, ThreadId
from tunnelminion.macos_app import (
    _create_macos_read_only_agent,  # pyright: ignore[reportPrivateUsage]
    build_macos_local_application,
)
from tunnelminion.model.configuration import (
    FileModelConfigurationRepository,
    ModelConfigurationService,
)
from tunnelminion.model.contracts import ModelResponse
from tunnelminion.model.openai_compatible import OpenAICompatibleConfig
from tunnelminion.model.secrets import KeyringSecretStore


@pytest.mark.parametrize("platform", ["windows", "macos"])
def test_only_local_user_agents_receive_the_gate(
    tmp_path: Path, platform: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    provider = FakeProvider(ModelResponse(structured_output={"category": "off_topic"}))

    def create_provider(_self: ModelConfigurationService) -> FakeProvider:
        return provider

    def reject_secret_read(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("生产接线测试不得读取真实秘密")

    monkeypatch.setattr(ModelConfigurationService, "create_provider", create_provider)
    monkeypatch.setattr("keyring.get_password", reject_secret_read)
    if platform == "windows":
        application = build_windows_application(tmp_path / platform)
        delegated = build_windows_node(tmp_path / "delegated").create_read_only_agent()
    else:
        application = build_macos_local_application(tmp_path / platform)
        delegated = _create_macos_read_only_agent(application.node)
    factory = cast(
        Callable[[], LangChainReadOnlyAgent],
        application.conversation_service._agent_factory,  # pyright: ignore[reportPrivateUsage]
    )
    for agent in (application.create_read_only_agent(), factory()):
        request_gate = agent._request_gate  # pyright: ignore[reportPrivateUsage]
        assert isinstance(request_gate, RequestGate)
        assert request_gate._provider is provider  # pyright: ignore[reportPrivateUsage]
        result = asyncio.run(agent.run("Write a poem.", context(), ("get_node_summary",)))
        assert result.model_rounds == result.tool_calls == 0
        assert result.answer.startswith("这个问题超出了我的范围")
    assert len(provider.requests) == 2
    assert delegated._request_gate is None  # pyright: ignore[reportPrivateUsage]


def test_real_evaluation_entry_works_with_file_configuration_and_keyring_adapter(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = FileModelConfigurationRepository(tmp_path / "model.json")
    repository.save(OpenAICompatibleConfig(endpoint="http://127.0.0.1/v1", model="test"))

    def no_key(_self: KeyringSecretStore, _name: str) -> None:
        return None

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.host == "127.0.0.1"
        assert "Authorization" not in request.headers
        return httpx.Response(
            200,
            json={"choices": [{"message": {"content": '{"category":"allowed"}'}}]},
        )

    original_client = httpx.AsyncClient

    def client(*, transport: httpx.AsyncBaseTransport | None = None) -> httpx.AsyncClient:
        del transport
        return original_client(transport=httpx.MockTransport(handler))

    monkeypatch.setattr(KeyringSecretStore, "get", no_key)
    monkeypatch.setattr("tunnelminion.model.openai_compatible.httpx.AsyncClient", client)
    provider = ModelConfigurationService(repository, KeyringSecretStore()).create_provider()
    request_gate = RequestGate(provider, provider_name="test", model_name="test")
    result = asyncio.run(
        request_gate.evaluate("服务为什么打不开？", thread_id=ThreadId.new(), run_id=RunId.new())
    )
    assert result.outcome is RequestGateOutcome.ALLOWED
