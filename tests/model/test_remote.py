"""远端模型的线上往返、错误映射与取消测试。"""

from __future__ import annotations

import asyncio

import httpx
import pytest
from tests.gateway.test_model_client import LOCAL, REMOTE, error_response, model_client

from tunnelminion.domain.model_borrowing import BorrowedModelCall, BorrowedModelResult
from tunnelminion.gateway.contracts import GatewayErrorCode
from tunnelminion.model.contracts import (
    CancellationToken,
    ModelMessage,
    ModelRequest,
    ModelResponse,
    ModelUsage,
    ProviderError,
    ProviderErrorCode,
    ToolCall,
    ToolDefinition,
)
from tunnelminion.model.remote import RemoteModelProvider

REQUEST = ModelRequest(messages=(ModelMessage(role="user", content="问题"),))


def test_remote_model_round_trips_reasoning_tools_schema_and_usage() -> None:
    tool = ToolCall(call_id="call-1", name="read_status", arguments={"port": 8080})
    request = ModelRequest(
        messages=(
            ModelMessage(role="user", content="检查服务"),
            ModelMessage(
                role="assistant", content="", reasoning_content="推理记录", tool_calls=(tool,)
            ),
            ModelMessage(role="tool", content="可达", tool_call_id=tool.call_id, name=tool.name),
        ),
        tools=(
            ToolDefinition(name=tool.name, description="读取状态", input_schema={"type": "object"}),
        ),
        require_tool_call=True,
        response_schema={"type": "object"},
    )
    expected = ModelResponse(
        content="结果",
        reasoning_content="下一段推理",
        tool_calls=(tool,),
        structured_output={"status": "ok"},
        usage=ModelUsage(input_tokens=13, output_tokens=7, total_tokens=20),
    )

    def handler(http_request: httpx.Request) -> httpx.Response:
        call = BorrowedModelCall.model_validate_json(http_request.content)
        assert call.caller_node_id == LOCAL
        assert call.to_request() == request
        assert call.messages[1].reasoning_content == "推理记录"
        return httpx.Response(
            200, content=BorrowedModelResult.from_response(REMOTE, expected).model_dump_json()
        )

    provider = RemoteModelProvider(model_client(httpx.MockTransport(handler)), LOCAL)
    assert provider.capabilities.tool_calls and provider.capabilities.structured_output
    response = asyncio.run(provider.complete(request))
    assert response == expected
    assert response.reasoning_content == "下一段推理"


@pytest.mark.parametrize(
    ("status", "code", "expected", "message", "retryable"),
    [
        (
            403,
            GatewayErrorCode.MODEL_BORROWING_NOT_ALLOWED,
            ProviderErrorCode.AUTHENTICATION_FAILED,
            "对方电脑没有允许借用模型",
            False,
        ),
        (
            401,
            GatewayErrorCode.UNAUTHENTICATED,
            ProviderErrorCode.AUTHENTICATION_FAILED,
            "对方电脑没有允许借用模型",
            False,
        ),
        (
            403,
            GatewayErrorCode.FORBIDDEN,
            ProviderErrorCode.AUTHENTICATION_FAILED,
            "对方电脑没有允许借用模型",
            False,
        ),
        (
            429,
            GatewayErrorCode.MODEL_QUOTA_EXCEEDED,
            ProviderErrorCode.QUOTA_EXCEEDED,
            "今天借用的额度已用完",
            False,
        ),
        (
            429,
            GatewayErrorCode.MODEL_BUSY,
            ProviderErrorCode.BUSY,
            "对方电脑的模型正忙，请稍后再试",
            True,
        ),
        (
            429,
            GatewayErrorCode.RATE_LIMITED,
            ProviderErrorCode.BUSY,
            "对方电脑的模型正忙，请稍后再试",
            True,
        ),
        (
            503,
            GatewayErrorCode.MODEL_BORROWING_UNAVAILABLE,
            ProviderErrorCode.MODEL_NOT_FOUND,
            "对方电脑还没有配置模型",
            False,
        ),
        (
            502,
            GatewayErrorCode.MODEL_CALL_FAILED,
            ProviderErrorCode.INVALID_RESPONSE,
            "对方电脑的模型调用失败",
            False,
        ),
        (
            504,
            GatewayErrorCode.MODEL_CALL_FAILED,
            ProviderErrorCode.INVALID_RESPONSE,
            "对方电脑的模型调用失败",
            False,
        ),
    ],
)
def test_remote_model_maps_gateway_errors_without_exposing_remote_messages(
    status: int, code: GatewayErrorCode, expected: ProviderErrorCode, message: str, retryable: bool
) -> None:
    provider = RemoteModelProvider(
        model_client(httpx.MockTransport(lambda _request: error_response(status, code))), LOCAL
    )
    with pytest.raises(ProviderError) as caught:
        asyncio.run(provider.complete(REQUEST))
    assert caught.value.code is expected
    assert str(caught.value) == message
    assert caught.value.retryable is retryable


@pytest.mark.parametrize(
    ("error", "expected"),
    [
        (httpx.ReadTimeout, ProviderErrorCode.TIMEOUT),
        (httpx.ConnectError, ProviderErrorCode.NETWORK_UNREACHABLE),
    ],
)
def test_remote_model_maps_transport_errors(
    error: type[httpx.RequestError], expected: ProviderErrorCode
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise error("private-network-message", request=request)

    provider = RemoteModelProvider(model_client(httpx.MockTransport(handler)), LOCAL)
    with pytest.raises(ProviderError) as caught:
        asyncio.run(provider.complete(REQUEST))
    assert caught.value.code is expected
    assert str(caught.value) == "连不上对方电脑"
    assert caught.value.retryable


def test_remote_model_maps_invalid_response() -> None:
    provider = RemoteModelProvider(
        model_client(httpx.MockTransport(lambda _request: httpx.Response(200, content="invalid"))),
        LOCAL,
    )
    with pytest.raises(ProviderError) as caught:
        asyncio.run(provider.complete(REQUEST))
    assert caught.value.code is ProviderErrorCode.INVALID_RESPONSE


def test_remote_model_honours_cancellation_before_sending() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError(f"取消后不得发送：{request.url}")

    token = CancellationToken()
    token.cancel()
    provider = RemoteModelProvider(model_client(httpx.MockTransport(handler)), LOCAL)
    with pytest.raises(ProviderError) as caught:
        asyncio.run(provider.complete(REQUEST, token))
    assert caught.value.code is ProviderErrorCode.CANCELLED


@pytest.mark.parametrize("cancel_parent", [False, True])
def test_remote_model_cleans_up_http_and_waiter_on_cancellation(cancel_parent: bool) -> None:
    async def scenario() -> None:
        started = asyncio.Event()
        finished = asyncio.Event()

        async def handler(request: httpx.Request) -> httpx.Response:
            del request
            started.set()
            try:
                await asyncio.Future[None]()
            finally:
                finished.set()
            raise AssertionError("请求应被取消")

        token = CancellationToken()
        provider = RemoteModelProvider(model_client(httpx.MockTransport(handler)), LOCAL)
        task = asyncio.create_task(provider.complete(REQUEST, token))
        await asyncio.wait_for(started.wait(), timeout=1)
        if cancel_parent:
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
        else:
            token.cancel()
            with pytest.raises(ProviderError) as caught:
                await asyncio.wait_for(task, timeout=1)
            assert caught.value.code is ProviderErrorCode.CANCELLED
        assert finished.is_set()
        assert asyncio.all_tasks() == {asyncio.current_task()}

    asyncio.run(scenario())
