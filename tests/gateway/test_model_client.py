"""借用模型的固定网关客户端测试。"""

from __future__ import annotations

import asyncio
from pathlib import Path

import httpx
import pytest
from tests.model.test_configuration import MemorySecrets

from tunnelminion.domain.errors import ErrorCode
from tunnelminion.domain.identifiers import NodeId
from tunnelminion.domain.model_borrowing import (
    MAX_MODEL_CALL_SECONDS,
    BorrowedMessage,
    BorrowedModelCall,
    BorrowedModelResult,
)
from tunnelminion.domain.tools import Platform
from tunnelminion.gateway.client import FixedGatewayClient, RemoteGatewayError
from tunnelminion.gateway.configuration import (
    FileGatewayConfigurationRepository,
    GatewayConfigurationService,
    GatewayPeerConfig,
    GatewayPeerInput,
    generate_gateway_token,
)
from tunnelminion.gateway.contracts import GatewayError, GatewayErrorCode, GatewayErrorResponse
from tunnelminion.gateway.security import GatewayBindConfig
from tunnelminion.tools.audit import InMemoryAuditSink

LOCAL = NodeId("node_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
REMOTE = NodeId("node_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
TOKEN = "tmn_" + "m" * 40
CALL = BorrowedModelCall(
    caller_node_id=LOCAL, messages=(BorrowedMessage(role="user", content="问题"),)
)


def model_client(transport: httpx.AsyncBaseTransport) -> FixedGatewayClient:
    return FixedGatewayClient(
        "http://10.77.0.2:8787", TOKEN, LOCAL, REMOTE, InMemoryAuditSink(), transport=transport
    )


def error_response(status: int, code: GatewayErrorCode) -> httpx.Response:
    return httpx.Response(
        status,
        content=GatewayErrorResponse(
            error=GatewayError(code=code, message="private-provider-message")
        ).model_dump_json(),
    )


def test_model_client_accepts_long_replies_and_uses_model_timeout() -> None:
    expected = BorrowedModelResult(provider_node_id=REMOTE, content="x" * 600_000)

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        assert str(request.url) == "http://10.77.0.2:8787/v1/model:complete"
        assert request.headers["Authorization"] == f"Bearer {TOKEN}"
        assert request.headers["Content-Type"] == "application/json"
        assert request.extensions["timeout"] == {
            key: MAX_MODEL_CALL_SECONDS + 10 for key in ("connect", "read", "write", "pool")
        }
        assert BorrowedModelCall.model_validate_json(request.content) == CALL
        return httpx.Response(200, content=expected.model_dump_json())

    assert asyncio.run(model_client(httpx.MockTransport(handler)).complete_model(CALL)) == expected


@pytest.mark.parametrize(
    ("status", "code", "expected"),
    [
        (403, GatewayErrorCode.MODEL_BORROWING_NOT_ALLOWED, ErrorCode.FORBIDDEN),
        (503, GatewayErrorCode.MODEL_BORROWING_UNAVAILABLE, ErrorCode.OPERATION_NOT_SUPPORTED),
        (429, GatewayErrorCode.MODEL_QUOTA_EXCEEDED, ErrorCode.RATE_LIMITED),
        (429, GatewayErrorCode.MODEL_BUSY, ErrorCode.RATE_LIMITED),
        (502, GatewayErrorCode.MODEL_CALL_FAILED, ErrorCode.INTERNAL),
        (504, GatewayErrorCode.MODEL_CALL_FAILED, ErrorCode.INTERNAL),
        (401, GatewayErrorCode.UNAUTHENTICATED, ErrorCode.UNAUTHENTICATED),
        (429, GatewayErrorCode.RATE_LIMITED, ErrorCode.RATE_LIMITED),
        (403, GatewayErrorCode.FORBIDDEN, ErrorCode.FORBIDDEN),
    ],
)
def test_model_client_preserves_gateway_error_codes(
    status: int, code: GatewayErrorCode, expected: ErrorCode
) -> None:
    client = model_client(httpx.MockTransport(lambda _request: error_response(status, code)))
    with pytest.raises(RemoteGatewayError) as caught:
        asyncio.run(client.complete_model(CALL))
    assert caught.value.code is expected
    assert caught.value.gateway_code is code


@pytest.mark.parametrize(
    ("response", "expected"),
    [
        (httpx.Response(200, json={"provider_node_id": str(LOCAL)}), ErrorCode.FORBIDDEN),
        (
            httpx.Response(200, json={"provider_node_id": str(REMOTE), "tool_calls": "x"}),
            ErrorCode.INTERNAL,
        ),
        (httpx.Response(200, content="not-json"), ErrorCode.INTERNAL),
        (httpx.Response(502, content="private-invalid-error"), ErrorCode.INTERNAL),
        (httpx.Response(200, content=b"x" * 2_000_001), ErrorCode.RESULT_TOO_LARGE),
    ],
)
def test_model_client_rejects_mismatched_invalid_and_oversized_responses(
    response: httpx.Response, expected: ErrorCode
) -> None:
    client = model_client(httpx.MockTransport(lambda _request: response))
    with pytest.raises(RemoteGatewayError) as caught:
        asyncio.run(client.complete_model(CALL))
    assert caught.value.code is expected
    assert "private-invalid-error" not in str(caught.value)


@pytest.mark.parametrize(
    ("error", "expected"),
    [
        (httpx.ReadTimeout, ErrorCode.REMOTE_TIMEOUT),
        (httpx.ConnectError, ErrorCode.NODE_UNREACHABLE),
    ],
)
def test_model_client_maps_transport_failures(
    error: type[httpx.RequestError], expected: ErrorCode
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise error("private-network-message", request=request)

    with pytest.raises(RemoteGatewayError) as caught:
        asyncio.run(model_client(httpx.MockTransport(handler)).complete_model(CALL))
    assert caught.value.code is expected
    assert str(caught.value) == "连不上对方电脑"


def test_model_client_rejects_forged_caller_without_sending() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError(f"不得发送冒用身份的请求：{request.url}")

    forged = BorrowedModelCall(
        caller_node_id=REMOTE, messages=(BorrowedMessage(role="user", content="问题"),)
    )
    with pytest.raises(ValueError, match="caller"):
        asyncio.run(model_client(httpx.MockTransport(handler)).complete_model(forged))


def test_model_peer_resolution_rejects_unknown_platform_and_missing_credentials(
    tmp_path: Path,
) -> None:
    secrets = MemorySecrets()
    service = GatewayConfigurationService(
        FileGatewayConfigurationRepository(tmp_path / "gateway.json"), secrets
    )
    service.configure_local(GatewayBindConfig(host="10.77.0.1"))
    provider = GatewayPeerConfig(
        node_id=REMOTE,
        platform=Platform.MACOS,
        host="10.77.0.2",
        allowed_tools=frozenset({"get_node_summary"}),
    )
    token = generate_gateway_token()
    service.provision_peer(GatewayPeerInput(peer=provider, token=token))
    resolved = service.resolve_model_peer(provider.node_id)
    assert resolved.node_id == provider.node_id
    assert resolved.endpoint == provider.endpoint()
    assert resolved.allowed_tools == () and resolved.token == token
    assert token not in repr(resolved)
    with pytest.raises(KeyError, match="gateway_model_peer_not_found"):
        service.resolve_model_peer(NodeId.new())
    legacy = provider.model_copy(update={"node_id": NodeId.new(), "platform": None})
    service.provision_peer(GatewayPeerInput(peer=legacy, token=generate_gateway_token()))
    with pytest.raises(KeyError, match="gateway_model_peer_not_found"):
        service.resolve_model_peer(legacy.node_id)
    secrets.values.clear()
    with pytest.raises(RuntimeError, match="缺少网关凭据"):
        service.resolve_model_peer(provider.node_id)
