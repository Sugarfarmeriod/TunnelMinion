"""固定对端的修复请求校验编号、来源、响应预算和旧版本路由。"""

from __future__ import annotations

import asyncio

import httpx
import pytest
from tests.gateway.test_proxy_repairs import NODE, PEER, TOKEN
from tests.repair.factories import plan

from tunnelminion.domain.errors import ErrorCode
from tunnelminion.domain.identifiers import OperationId
from tunnelminion.gateway.client import FixedGatewayClient, RemoteGatewayError
from tunnelminion.gateway.contracts import GatewayErrorCode, GatewayErrorResponse, PeerRepairView
from tunnelminion.repair.contracts import RepairRecord
from tunnelminion.repair.peer_view import peer_repair_view
from tunnelminion.tools.audit import InMemoryAuditSink


def view() -> PeerRepairView:
    return peer_repair_view(RepairRecord.planned(plan(), actor="agent"))


@pytest.mark.parametrize("action", ["get", "approve", "reject"])
def test_requests_have_only_a_valid_id_and_validate_response_identity(action: str) -> None:
    result = view()
    calls: list[httpx.Request] = []
    mode = "ok"

    def response(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        data = result.model_dump(mode="json")
        data["unknown_future_field"] = "可忽略"
        if mode == "node":
            data["node_id"] = str(PEER)
        if mode == "id":
            data["repair_id"] = str(OperationId.new())
        return httpx.Response(200, json=data)

    client = FixedGatewayClient(
        "http://127.0.0.1",
        TOKEN,
        PEER,
        NODE,
        InMemoryAuditSink(),
        transport=httpx.MockTransport(response),
    )
    request = {
        "get": client.get_repair,
        "approve": client.approve_repair,
        "reject": client.reject_repair,
    }[action]
    assert asyncio.run(request(result.repair_id)) == result
    assert len(calls) == 1
    assert calls[0].method == ("GET" if action == "get" else "POST")
    assert calls[0].url.path == f"/v1/repairs/{result.repair_id}" + (
        "" if action == "get" else f":{action}"
    )
    assert calls[0].content == b""
    for mismatch in ("node", "id"):
        mode = mismatch
        with pytest.raises(RemoteGatewayError) as caught:
            asyncio.run(request(result.repair_id))
        assert caught.value.code is ErrorCode.FORBIDDEN
    count = len(calls)
    with pytest.raises(ValueError):
        asyncio.run(request("invalid/approve"))
    assert len(calls) == count


@pytest.mark.parametrize(
    ("mode", "code", "gateway_code"),
    [
        ("timeout", ErrorCode.REMOTE_TIMEOUT, None),
        ("unreachable", ErrorCode.NODE_UNREACHABLE, None),
        ("invalid", ErrorCode.INTERNAL, None),
        ("large", ErrorCode.RESULT_TOO_LARGE, None),
        ("legacy", ErrorCode.FORBIDDEN, GatewayErrorCode.REPAIR_APPROVAL_NOT_ALLOWED),
        (
            "repair_approval_not_allowed",
            ErrorCode.FORBIDDEN,
            GatewayErrorCode.REPAIR_APPROVAL_NOT_ALLOWED,
        ),
        ("repair_not_found", ErrorCode.INVALID_ARGUMENT, GatewayErrorCode.REPAIR_NOT_FOUND),
        (
            "repair_state_conflict",
            ErrorCode.INVALID_ARGUMENT,
            GatewayErrorCode.REPAIR_STATE_CONFLICT,
        ),
        (
            "repair_unavailable",
            ErrorCode.OPERATION_NOT_SUPPORTED,
            GatewayErrorCode.REPAIR_UNAVAILABLE,
        ),
    ],
)
def test_repair_failures_keep_gateway_codes(
    mode: str, code: ErrorCode, gateway_code: GatewayErrorCode | None
) -> None:
    def response(request: httpx.Request) -> httpx.Response:
        if mode == "timeout":
            raise httpx.ReadTimeout("fake", request=request)
        if mode == "unreachable":
            raise httpx.ConnectError("fake", request=request)
        if mode == "invalid":
            return httpx.Response(200, text="invalid")
        if mode == "large":
            return httpx.Response(200, text="x" * 513)
        if mode == "legacy":
            return httpx.Response(404, json={"detail": "Not Found"})
        return httpx.Response(
            403,
            content=GatewayErrorResponse.model_validate(
                {"error": {"code": mode, "message": "拒绝"}}
            ).model_dump_json(),
        )

    client = FixedGatewayClient(
        "http://127.0.0.1",
        TOKEN,
        PEER,
        NODE,
        InMemoryAuditSink(),
        max_response_bytes=512,
        transport=httpx.MockTransport(response),
    )
    with pytest.raises(RemoteGatewayError) as caught:
        asyncio.run(client.get_repair(OperationId.new()))
    assert caught.value.code is code
    assert caught.value.gateway_code is gateway_code
