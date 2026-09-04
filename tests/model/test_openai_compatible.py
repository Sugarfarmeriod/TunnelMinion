"""OpenAI-compatible Provider 契约测试。"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Callable, Coroutine
from typing import Any, TypeVar, cast

import httpx
import pytest

from tunnelminion.model.contracts import (
    CancellationToken,
    ModelMessage,
    ModelRequest,
    ProviderError,
    ProviderErrorCode,
    ToolCall,
    ToolDefinition,
)
from tunnelminion.model.openai_compatible import (
    OpenAICompatibleConfig,
    OpenAICompatibleProvider,
)


def config(timeout: float = 1.0) -> OpenAICompatibleConfig:
    """返回标准测试配置。"""
    return OpenAICompatibleConfig(
        endpoint="http://model.test/v1/", model="qwen-test", timeout_seconds=timeout
    )


def request(*, structured: bool = False) -> ModelRequest:
    """返回覆盖工具和可选结构化输出的请求。"""
    return ModelRequest(
        messages=(ModelMessage(role="user", content="检查能力"),),
        tools=(
            ToolDefinition(
                name="check",
                description="检查模型能力",
                input_schema={"type": "object", "properties": {}},
            ),
        ),
        require_tool_call=True,
        response_schema={"type": "object"} if structured else None,
    )


T = TypeVar("T")


def run(coroutine: Coroutine[Any, Any, T]) -> T:
    """在同步 pytest 用例中运行异步 Provider。"""
    return asyncio.run(coroutine)


def test_normalizes_config_and_rejects_invalid_endpoint() -> None:
    assert config().endpoint == "http://model.test/v1"
    with pytest.raises(ValueError, match="http"):
        OpenAICompatibleConfig(endpoint="model.test", model="qwen")


def test_parses_tool_calls_usage_and_authorization() -> None:
    async def handler(http_request: httpx.Request) -> httpx.Response:
        payload = json.loads(http_request.content)
        assert http_request.url.path == "/v1/chat/completions"
        assert http_request.headers["Authorization"] == "Bearer secret-value"
        assert payload["tool_choice"] == "required"
        assert payload["tools"][0]["function"]["name"] == "check"
        return httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "message": {
                            "content": None,
                            "tool_calls": [
                                {
                                    "id": "call-1",
                                    "function": {"name": "check", "arguments": '{"ok":true}'},
                                }
                            ],
                        }
                    }
                ],
                "usage": {
                    "prompt_tokens": 7,
                    "completion_tokens": 3,
                    "total_tokens": 10,
                },
            },
        )

    provider = OpenAICompatibleProvider(
        config(), "secret-value", transport=httpx.MockTransport(handler)
    )
    response = run(provider.complete(request(), CancellationToken()))
    assert response.tool_calls[0].arguments == {"ok": True}
    assert response.usage.total_tokens == 10
    assert provider.capabilities.tool_calls


def test_parses_structured_output_without_api_key() -> None:
    async def handler(http_request: httpx.Request) -> httpx.Response:
        payload = json.loads(http_request.content)
        assert "Authorization" not in http_request.headers
        assert payload["response_format"]["type"] == "json_schema"
        return httpx.Response(
            200,
            json={"choices": [{"message": {"content": '{"status":"ok"}'}}]},
        )

    provider = OpenAICompatibleProvider(config(), transport=httpx.MockTransport(handler))
    response = run(provider.complete(request(structured=True)))
    assert response.structured_output == {"status": "ok"}
    assert response.usage.input_tokens is None


def test_supports_requests_without_tools_and_optional_tool_choice() -> None:
    transport = httpx.MockTransport(
        lambda _: httpx.Response(
            200,
            json={"choices": [{"message": {"content": "ok", "tool_calls": None}}]},
        )
    )
    provider = OpenAICompatibleProvider(config(), transport=transport)
    without_tools = ModelRequest(messages=(ModelMessage(role="user", content="你好"),))
    optional_tools = ModelRequest(messages=without_tools.messages, tools=request().tools)
    assert run(provider.complete(without_tools)).content == "ok"
    assert run(provider.complete(optional_tools)).content == "ok"


def test_serializes_assistant_tool_calls_and_tool_results() -> None:
    """多轮 Agent 协议保留 call ID、工具名和结构化参数。"""
    captured: dict[str, object] = {}

    def handler(request_value: httpx.Request) -> httpx.Response:
        captured.update(cast(dict[str, object], json.loads(request_value.content)))
        return httpx.Response(200, json={"choices": [{"message": {"content": "完成"}}]})

    provider = OpenAICompatibleProvider(config(), transport=httpx.MockTransport(handler))
    response = run(
        provider.complete(
            ModelRequest(
                messages=(
                    ModelMessage(
                        role="assistant",
                        content="",
                        tool_calls=(
                            ToolCall(
                                call_id="call-1",
                                name="probe_service",
                                arguments={"port": 8082},
                            ),
                        ),
                    ),
                    ModelMessage(
                        role="tool",
                        content='{"reachable":true}',
                        tool_call_id="call-1",
                        name="probe_service",
                    ),
                )
            )
        )
    )

    messages = cast(list[dict[str, object]], captured["messages"])
    calls = cast(list[dict[str, object]], messages[0]["tool_calls"])
    assert calls[0]["id"] == "call-1"
    assert messages[1]["tool_call_id"] == "call-1"
    assert messages[1]["name"] == "probe_service"
    assert response.content == "完成"


@pytest.mark.parametrize(
    ("status_code", "expected", "retryable"),
    [
        (401, ProviderErrorCode.AUTHENTICATION_FAILED, False),
        (403, ProviderErrorCode.AUTHENTICATION_FAILED, False),
        (404, ProviderErrorCode.MODEL_NOT_FOUND, False),
        (429, ProviderErrorCode.INVALID_RESPONSE, False),
        (500, ProviderErrorCode.INVALID_RESPONSE, True),
    ],
)
def test_classifies_http_errors(
    status_code: int, expected: ProviderErrorCode, retryable: bool
) -> None:
    transport = httpx.MockTransport(lambda _: httpx.Response(status_code))
    provider = OpenAICompatibleProvider(config(), transport=transport)
    with pytest.raises(ProviderError) as caught:
        run(provider.complete(request()))
    assert caught.value.code == expected
    assert caught.value.retryable is retryable


def connect_error(request_value: httpx.Request) -> Exception:
    return httpx.ConnectError("secret-value", request=request_value)


def timeout_error(request_value: httpx.Request) -> Exception:
    return httpx.ReadTimeout("secret-value", request=request_value)


@pytest.mark.parametrize(
    ("exception_factory", "expected"),
    [
        (connect_error, ProviderErrorCode.NETWORK_UNREACHABLE),
        (timeout_error, ProviderErrorCode.TIMEOUT),
    ],
)
def test_classifies_transport_errors(
    exception_factory: Callable[[httpx.Request], Exception], expected: ProviderErrorCode
) -> None:
    def handler(http_request: httpx.Request) -> httpx.Response:
        raise exception_factory(http_request)

    provider = OpenAICompatibleProvider(config(), transport=httpx.MockTransport(handler))
    with pytest.raises(ProviderError) as caught:
        run(provider.complete(request()))
    assert caught.value.code == expected
    assert "secret-value" not in str(caught.value)


def test_supports_pre_cancel_active_cancel_and_wall_clock_timeout() -> None:
    async def slow_handler(_: httpx.Request) -> httpx.Response:
        await asyncio.sleep(1)
        return httpx.Response(200)

    provider = OpenAICompatibleProvider(config(0.1), transport=httpx.MockTransport(slow_handler))
    pre_cancelled = CancellationToken()
    pre_cancelled.cancel()
    with pytest.raises(ProviderError) as caught:
        run(provider.complete(request(), pre_cancelled))
    assert caught.value.code == ProviderErrorCode.CANCELLED

    async def cancel_during_request() -> None:
        token = CancellationToken()
        task = asyncio.create_task(provider.complete(request(), token))
        await asyncio.sleep(0)
        token.cancel()
        with pytest.raises(ProviderError) as active:
            await task
        assert active.value.code == ProviderErrorCode.CANCELLED

    run(cancel_during_request())
    with pytest.raises(ProviderError) as timed_out:
        run(provider.complete(request()))
    assert timed_out.value.code == ProviderErrorCode.TIMEOUT


MALFORMED_BODIES: list[dict[str, object]] = [
    {},
    {"choices": []},
    cast(
        dict[str, object],
        {"choices": [{"message": {"tool_calls": [{"id": "x", "function": {}}]}}]},
    ),
    cast(dict[str, object], {"choices": [{"message": {"content": "not-json"}}]}),
]


@pytest.mark.parametrize("body", MALFORMED_BODIES)
def test_rejects_malformed_responses(body: dict[str, object]) -> None:
    provider = OpenAICompatibleProvider(
        config(),
        transport=httpx.MockTransport(lambda _: httpx.Response(200, json=body)),
    )
    with pytest.raises(ProviderError) as caught:
        run(provider.complete(request(structured=True)))
    assert caught.value.code == ProviderErrorCode.INVALID_RESPONSE
