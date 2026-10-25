"""邀请码握手的固定协议与失败映射。"""

from __future__ import annotations

import asyncio

import httpx
import pytest
from tests.gateway.test_model_client import error_response
from tests.test_invite_codes import CODE

from tunnelminion.domain.identifiers import NodeId
from tunnelminion.domain.invites import InviteAcceptance, InviteAccepted, InvitePermissions
from tunnelminion.domain.tools import Platform
from tunnelminion.gateway.client import InviteHandshakeError, accept_invite
from tunnelminion.gateway.contracts import GatewayErrorCode

ACCEPTANCE = InviteAcceptance(
    node_id=NodeId("node_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
    platform=Platform.WINDOWS,
    host="10.77.0.2",
    port=8788,
)
ACCEPTED = InviteAccepted(
    inviter_node_id=CODE.node_id,
    permissions=InvitePermissions(allow_delegation=True, daily_quota=1234),
)


def test_accept_invite_sends_token_identity_and_fifteen_second_timeout() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        assert str(request.url) == "http://10.77.0.1:8787/v1/invites:accept"
        assert request.headers["Authorization"] == f"Bearer {CODE.token}"
        assert request.headers["Content-Type"] == "application/json"
        assert request.extensions["timeout"] == {
            key: 15 for key in ("connect", "read", "write", "pool")
        }
        assert InviteAcceptance.model_validate_json(request.content) == ACCEPTANCE
        return httpx.Response(200, content=ACCEPTED.model_dump_json())

    result = asyncio.run(accept_invite(CODE, ACCEPTANCE, transport=httpx.MockTransport(handler)))
    assert result == ACCEPTED
    assert result.permissions != CODE.permissions


@pytest.mark.parametrize(
    ("status", "code", "reason"),
    [
        (401, GatewayErrorCode.INVITE_INVALID, "invalid"),
        (429, GatewayErrorCode.RATE_LIMITED, "rate_limited"),
        (401, GatewayErrorCode.RATE_LIMITED, "bad_response"),
        (429, GatewayErrorCode.INVITE_INVALID, "bad_response"),
        (500, GatewayErrorCode.INVITE_INVALID, "bad_response"),
    ],
)
def test_accept_invite_maps_only_matching_rejections(
    status: int, code: GatewayErrorCode, reason: str
) -> None:
    response = error_response(status, code)
    with pytest.raises(InviteHandshakeError) as caught:
        asyncio.run(
            accept_invite(
                CODE, ACCEPTANCE, transport=httpx.MockTransport(lambda _request: response)
            )
        )
    assert caught.value.reason == reason
    assert "private-provider-message" not in str(caught.value)
    assert CODE.token not in str(caught.value)


@pytest.mark.parametrize(
    "response",
    [
        httpx.Response(200, content="private-not-json"),
        httpx.Response(200, json={"inviter_node_id": str(CODE.node_id)}),
        httpx.Response(
            200,
            content=ACCEPTED.model_copy(
                update={"inviter_node_id": ACCEPTANCE.node_id}
            ).model_dump_json(),
        ),
        httpx.Response(401, content="private-not-json"),
        httpx.Response(302, headers={"location": "http://10.77.0.3:8787"}),
        httpx.Response(201, content=ACCEPTED.model_dump_json()),
        httpx.Response(200, content=b"x" * 512_001),
    ],
)
def test_accept_invite_rejects_bad_mismatched_and_oversized_responses(
    response: httpx.Response,
) -> None:
    with pytest.raises(InviteHandshakeError) as caught:
        asyncio.run(
            accept_invite(
                CODE, ACCEPTANCE, transport=httpx.MockTransport(lambda _request: response)
            )
        )
    assert caught.value.reason == "bad_response"
    assert "private-not-json" not in str(caught.value)


@pytest.mark.parametrize("error", [httpx.ConnectError, httpx.ConnectTimeout, httpx.ReadTimeout])
def test_accept_invite_maps_transport_errors(error: type[httpx.RequestError]) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise error("private-network-error", request=request)

    with pytest.raises(InviteHandshakeError) as caught:
        asyncio.run(accept_invite(CODE, ACCEPTANCE, transport=httpx.MockTransport(handler)))
    assert caught.value.reason == "unreachable"
    assert "private-network-error" not in str(caught.value)


def test_accept_invite_rejects_invalid_url_without_network() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        raise AssertionError("无效地址不得联网")

    with pytest.raises(InviteHandshakeError) as caught:
        asyncio.run(
            accept_invite(
                CODE.model_copy(update={"host": "\x00"}),
                ACCEPTANCE,
                transport=httpx.MockTransport(handler),
            )
        )
    assert caught.value.reason == "bad_response"
