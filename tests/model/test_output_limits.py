"""单次输出上限、旧配置兼容与借用方不能放大额度的测试。"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import httpx
import pytest
from pydantic import BaseModel, ConfigDict, JsonValue, ValidationError
from tests.gateway.test_model_client import LOCAL, model_client
from tests.gateway.test_model_lending import PROVIDER, peer
from tests.model.test_configuration import MemorySecrets, ValidationProvider

from tunnelminion.agent.model_lending import InMemoryModelUsageStore, ModelLendingService
from tunnelminion.domain.identifiers import NodeId
from tunnelminion.domain.model_borrowing import (
    MAX_BORROWED_OUTPUT_TOKENS,
    BorrowedMessage,
    BorrowedModelCall,
)
from tunnelminion.gateway.contracts import GatewayError, GatewayErrorCode, GatewayErrorResponse
from tunnelminion.model.configuration import (
    FileModelConfigurationRepository,
    ModelConfigurationInput,
    ModelConfigurationProfileView,
    ModelConfigurationService,
    ModelConfigurationView,
)
from tunnelminion.model.contracts import (
    ModelMessage,
    ModelRequest,
    ProviderError,
    ProviderErrorCode,
)
from tunnelminion.model.openai_compatible import OpenAICompatibleConfig, OpenAICompatibleProvider
from tunnelminion.model.remote import RemoteModelProvider


@pytest.mark.parametrize("configured", [16, 2048, 32768])
@pytest.mark.parametrize("requested", [None, 1, 64, 100000])
def test_payload_always_uses_the_smaller_output_limit(
    configured: int, requested: int | None
) -> None:
    config = OpenAICompatibleConfig(
        endpoint="http://127.0.0.1/v1", model="test", max_output_tokens=configured
    )

    def handler(request: httpx.Request) -> httpx.Response:
        assert json.loads(request.content)["max_tokens"] == min(configured, requested or configured)
        return httpx.Response(200, json={"choices": [{"message": {"content": "完成"}}]})

    provider = OpenAICompatibleProvider(config, transport=httpx.MockTransport(handler))
    response = asyncio.run(
        provider.complete(
            ModelRequest(
                messages=(ModelMessage(role="user", content="检查服务"),),
                max_output_tokens=requested,
            )
        )
    )
    assert response.content == "完成"


@pytest.mark.parametrize("limit", [0, 15, 32769])
def test_configuration_limits_are_validated(limit: int) -> None:
    for schema in (OpenAICompatibleConfig, ModelConfigurationInput, ModelConfigurationProfileView):
        with pytest.raises(ValidationError):
            schema(
                endpoint="http://127.0.0.1/v1",
                model="test",
                timeout_seconds=1,
                max_output_tokens=limit,
            )
    with pytest.raises(ValidationError):
        ModelConfigurationView(status="available", max_output_tokens=limit)


def test_per_call_limit_must_be_positive() -> None:
    with pytest.raises(ValidationError):
        ModelRequest(messages=(ModelMessage(role="user", content="检查"),), max_output_tokens=0)
    with pytest.raises(ValidationError):
        BorrowedModelCall(
            caller_node_id=LOCAL,
            messages=(BorrowedMessage(role="user", content="检查"),),
            max_output_tokens=0,
        )


@pytest.mark.parametrize(
    ("message", "structured"),
    [
        ({"content": "还没有写完的正文"}, False),
        ({"content": '{"status":'}, True),
        (
            {
                "content": None,
                "tool_calls": [
                    {"id": "call-1", "function": {"name": "check", "arguments": '{"port":'}}
                ],
            },
            False,
        ),
    ],
)
def test_length_finish_reason_discards_text_json_and_tools(
    message: dict[str, JsonValue], structured: bool
) -> None:
    provider = OpenAICompatibleProvider(
        OpenAICompatibleConfig(endpoint="http://127.0.0.1/v1", model="test"),
        transport=httpx.MockTransport(
            lambda _: httpx.Response(
                200,
                json={
                    "choices": [{"finish_reason": "length", "message": message}],
                    "usage": {"prompt_tokens": 10, "completion_tokens": 2048, "total_tokens": 2058},
                },
            )
        ),
    )
    with pytest.raises(ProviderError) as caught:
        asyncio.run(
            provider.complete(
                ModelRequest(
                    messages=(ModelMessage(role="user", content="检查"),),
                    response_schema={"type": "object"} if structured else None,
                )
            )
        )
    assert caught.value.code is ProviderErrorCode.OUTPUT_TRUNCATED
    assert str(caught.value) == "模型回答超过单次长度上限被截断，这次结果没有采用"
    assert caught.value.retryable is False
    assert caught.value.usage is not None and caught.value.usage.total_tokens == 2058


@pytest.mark.parametrize("version", [None, 2, 3])
def test_legacy_persisted_config_uses_default_limit(tmp_path: Path, version: int | None) -> None:
    config = {"endpoint": "http://127.0.0.1/v1", "model": "test", "timeout_seconds": 1}
    value = (
        config if version is None else {"version": version, "active": config, "profiles": [config]}
    )
    path = tmp_path / "model.json"
    path.write_text(json.dumps(value), encoding="utf-8")
    repository = FileModelConfigurationRepository(path)
    loaded = repository.load()
    assert loaded is not None and loaded.max_output_tokens == 2048
    assert repository.profiles()[0].max_output_tokens == 2048
    service = ModelConfigurationService(repository, MemorySecrets())
    assert service.view().max_output_tokens == 2048
    assert service.view().profiles[0].max_output_tokens == 2048


def test_configuration_input_persists_and_exposes_custom_limit(tmp_path: Path) -> None:
    repository = FileModelConfigurationRepository(tmp_path / "model.json")
    service = ModelConfigurationService(
        repository, MemorySecrets(), lambda _config, _key: ValidationProvider()
    )
    value = ModelConfigurationInput(
        endpoint="http://127.0.0.1/v1", model="test", max_output_tokens=1024
    )
    assert value.provider_config().max_output_tokens == 1024
    view = asyncio.run(service.configure(value))
    assert view.max_output_tokens == view.profiles[0].max_output_tokens == 1024
    loaded = repository.load()
    assert loaded is not None and loaded.max_output_tokens == 1024
    assert (
        ModelConfigurationInput(endpoint=value.endpoint, model=value.model).max_output_tokens
        == 2048
    )


@pytest.mark.parametrize("limit", [None, 64, 100000])
def test_borrowed_call_serializes_optional_limit_without_breaking_legacy_provider(
    limit: int | None,
) -> None:
    request = ModelRequest(
        messages=(ModelMessage(role="user", content="检查"),), max_output_tokens=limit
    )
    call = BorrowedModelCall.from_request(LOCAL, request)
    assert call.to_request() == request
    serialized = json.loads(call.model_dump_json())
    assert ("max_output_tokens" in serialized) is (limit is not None)
    assert ("max_output_tokens" in call.model_dump()) is (limit is not None)
    if limit is None:

        class LegacyCall(BaseModel):
            model_config = ConfigDict(extra="forbid")

            caller_node_id: NodeId
            messages: tuple[dict[str, JsonValue], ...]
            tools: tuple[dict[str, JsonValue], ...] = ()
            require_tool_call: bool = False
            response_schema: dict[str, JsonValue] | None = None

        LegacyCall.model_validate_json(call.model_dump_json())
    else:
        assert serialized["max_output_tokens"] == limit
    assert "max_output_tokens" not in call.model_dump(exclude={"max_output_tokens"})


@pytest.mark.parametrize("configured", [1024, 8192])
@pytest.mark.parametrize("requested", [None, 32, 100000])
def test_lending_clamps_output_before_the_provider_applies_its_own_limit(
    configured: int, requested: int | None
) -> None:
    payloads: list[dict[str, JsonValue]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        payloads.append(json.loads(request.content))
        return httpx.Response(200, json={"choices": [{"message": {"content": "完成"}}]})

    provider = OpenAICompatibleProvider(
        OpenAICompatibleConfig(
            endpoint="http://127.0.0.1/v1", model="test", max_output_tokens=configured
        ),
        transport=httpx.MockTransport(handler),
    )
    service = ModelLendingService(PROVIDER, lambda: provider, InMemoryModelUsageStore())
    borrower = peer()
    call = BorrowedModelCall.from_request(
        borrower.node_id,
        ModelRequest(
            messages=(ModelMessage(role="user", content="检查"),), max_output_tokens=requested
        ),
    )
    assert asyncio.run(service.complete(borrower, call)).content == "完成"
    assert payloads[0]["max_tokens"] == min(
        requested or MAX_BORROWED_OUTPUT_TOKENS, MAX_BORROWED_OUTPUT_TOKENS, configured
    )


def test_remote_provider_preserves_truncation_code() -> None:
    response = httpx.Response(
        502,
        content=GatewayErrorResponse(
            error=GatewayError(
                code=GatewayErrorCode.MODEL_CALL_FAILED,
                message=ProviderErrorCode.OUTPUT_TRUNCATED.value,
            )
        ).model_dump_json(),
    )
    provider = RemoteModelProvider(model_client(httpx.MockTransport(lambda _: response)), LOCAL)
    with pytest.raises(ProviderError) as caught:
        asyncio.run(
            provider.complete(ModelRequest(messages=(ModelMessage(role="user", content="检查"),)))
        )
    assert caught.value.code is ProviderErrorCode.OUTPUT_TRUNCATED
    assert caught.value.retryable is False
    assert str(caught.value) == "模型这次回答太长被截断了，可以把问题问得更具体一些再试"
