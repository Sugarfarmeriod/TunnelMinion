"""A 的本机接口只访问已配置对端，并把权限、进度和失败转成页面状态。"""

from __future__ import annotations

import asyncio
from pathlib import Path
from unittest.mock import Mock

import httpx
import pytest
from fastapi import FastAPI
from tests.agent.test_remote_service_presentation import cache, node
from tests.gateway.test_proxy_repair_client import view
from tests.gateway.test_proxy_repairs import NODE, PEER
from tests.web.test_peers import configuration, peer
from tests.web.test_remote_repairs import repair

from tunnelminion.agent.coordinator import CoordinatorCache
from tunnelminion.domain.identifiers import NodeId
from tunnelminion.domain.tools import Platform
from tunnelminion.gateway.contracts import GatewayErrorCode, GatewayErrorResponse
from tunnelminion.tools.audit import InMemoryAuditSink
from tunnelminion.web.peers import PeerServicePoller, create_peers_router
from tunnelminion.web.request_guard import install_local_request_guard
from tunnelminion.web.service_map import LocalServiceMap

PATH = f"/api/peers/{NODE}/repairs/{repair().repair_id}"
SAME_ORIGIN = {"origin": "http://127.0.0.1:8765", "x-tunnelminion-request": "same-origin"}


def local_app(
    poller: PeerServicePoller, coordinator_cache: CoordinatorCache | None = None
) -> FastAPI:
    app = FastAPI()
    app.include_router(
        create_peers_router(
            PEER,
            Platform.WINDOWS,
            lambda: "本机",
            poller,
            lambda: LocalServiceMap(node_id=PEER),
            coordinator_cache,
        )
    )
    install_local_request_guard(app)
    return app


def test_directory_only_node_cannot_use_proxy_repair_routes(tmp_path: Path) -> None:
    handler = Mock(side_effect=AssertionError("目录中的电脑不应获得代批准入口"))
    poller = PeerServicePoller(
        configuration(tmp_path), PEER, InMemoryAuditSink(), transport=httpx.MockTransport(handler)
    )
    app = local_app(poller, cache(node(NODE)))

    async def scenario() -> None:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app), base_url="http://127.0.0.1:8765"
        ) as client:
            peers = (await client.get("/api/peers")).json()["peers"]
            assert peers[1]["source"] == "coordinator" and peers[1]["node_id"] == str(NODE)
            for action in (None, "approve", "reject"):
                response = await client.request(
                    "POST" if action else "GET",
                    PATH + (f"/{action}" if action else ""),
                    headers=SAME_ORIGIN,
                )
                assert response.status_code == 404
        handler.assert_not_called()

    asyncio.run(scenario())


def error_response(code: GatewayErrorCode) -> httpx.Response:
    statuses = {
        GatewayErrorCode.REPAIR_APPROVAL_NOT_ALLOWED: 403,
        GatewayErrorCode.REPAIR_NOT_FOUND: 404,
        GatewayErrorCode.REPAIR_STATE_CONFLICT: 409,
        GatewayErrorCode.RATE_LIMITED: 429,
    }
    return httpx.Response(
        statuses.get(code, 503),
        content=GatewayErrorResponse.model_validate(
            {"error": {"code": code, "message": "示例拒绝"}}
        ).model_dump_json(),
    )


@pytest.mark.parametrize(
    ("mode", "access"),
    [
        ("ok", "allowed"),
        ("repair_approval_not_allowed", "not_allowed"),
        ("legacy", "not_allowed"),
        ("repair_not_found", "not_found"),
        ("unreachable", "unreachable"),
        ("timeout", "unreachable"),
        ("rate_limited", "unreachable"),
        ("repair_unavailable", "unreachable"),
        ("other404", "unreachable"),
        ("invalid", "unreachable"),
    ],
)
def test_get_access_mapping(tmp_path: Path, mode: str, access: str) -> None:
    result = view().model_copy(update={"repair_id": repair().repair_id})

    def response(request: httpx.Request) -> httpx.Response:
        if mode == "ok":
            return httpx.Response(200, content=result.model_dump_json())
        if mode == "legacy":
            return httpx.Response(404, text="old route")
        if mode == "invalid":
            return httpx.Response(200, json={})
        if mode == "unreachable":
            raise httpx.ConnectError("fake", request=request)
        if mode == "timeout":
            raise httpx.ReadTimeout("fake", request=request)
        if mode == "other404":
            return httpx.Response(
                404, json={"error": {"code": "tool_not_found", "message": "示例"}}
            )
        return error_response(GatewayErrorCode(mode))

    poller = PeerServicePoller(
        configuration(tmp_path, peer(NODE)),
        PEER,
        InMemoryAuditSink(),
        transport=httpx.MockTransport(response),
    )

    async def scenario() -> None:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(local_app(poller)), base_url="http://127.0.0.1:8765"
        ) as client:
            response = await client.get(PATH)
            assert response.status_code == 200
            assert response.json() == {
                "node_id": str(NODE),
                "repair_id": str(result.repair_id),
                "access": access,
                "repair": result.model_dump(mode="json") if access == "allowed" else None,
            }

    asyncio.run(scenario())


@pytest.mark.parametrize("action", ["approve", "reject"])
@pytest.mark.parametrize(
    ("code", "status", "message"),
    [
        (GatewayErrorCode.REPAIR_APPROVAL_NOT_ALLOWED, 403, "Mac 没有允许这台电脑替它批准修复"),
        (GatewayErrorCode.REPAIR_NOT_FOUND, 404, "修复不存在"),
        (GatewayErrorCode.REPAIR_STATE_CONFLICT, 409, "这个修复已经不等批准了"),
        (GatewayErrorCode.RATE_LIMITED, 502, "连不上 Mac，稍后再试"),
        (GatewayErrorCode.REPAIR_UNAVAILABLE, 502, "连不上 Mac，稍后再试"),
    ],
)
def test_decision_errors_keep_pending_summary(
    tmp_path: Path, action: str, code: GatewayErrorCode, status: int, message: str
) -> None:
    poller = PeerServicePoller(
        configuration(tmp_path, peer(NODE)),
        PEER,
        InMemoryAuditSink(),
        transport=httpx.MockTransport(lambda _: error_response(code)),
    )
    summary = repair()
    poller.remember_repairs(NODE, (summary,))

    async def scenario() -> None:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(local_app(poller)), base_url="http://127.0.0.1:8765"
        ) as client:
            response = await client.post(f"{PATH}/{action}", headers=SAME_ORIGIN)
            assert response.status_code == status
            assert response.json() == {"detail": message}
            assert poller.pending_repairs(NODE) == (summary,)

    asyncio.run(scenario())


@pytest.mark.parametrize("action", ["approve", "reject"])
def test_success_removes_only_the_decided_repair(tmp_path: Path, action: str) -> None:
    summary = repair()
    result = view().model_copy(
        update={
            "repair_id": summary.repair_id,
            "status": "authorized" if action == "approve" else "rejected",
        }
    )

    def response(request: httpx.Request) -> httpx.Response:
        assert request.url.path == f"/v1/repairs/{summary.repair_id}:{action}"
        assert request.method == "POST" and request.content == b""
        return httpx.Response(202 if action == "approve" else 200, content=result.model_dump_json())

    poller = PeerServicePoller(
        configuration(tmp_path, peer(NODE, "本机起的远端名")),
        PEER,
        InMemoryAuditSink(),
        transport=httpx.MockTransport(response),
    )
    other = repair(2)
    poller.remember_repairs(NODE, (summary, other))
    poller.remember_repairs(PEER, (summary,))

    async def scenario() -> None:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(local_app(poller)), base_url="http://127.0.0.1:8765"
        ) as client:
            response = await client.post(
                f"{PATH}/{action}", headers=SAME_ORIGIN, json={"command": "ignored"}
            )
            assert response.status_code == (202 if action == "approve" else 200)
            assert response.json()["access"] == "allowed"
            assert response.json()["repair"] == result.model_dump(mode="json")
            assert poller.pending_repairs(NODE) == (other,)
            assert poller.pending_repairs(PEER) == (summary,)
            peers = (await client.get("/api/peers")).json()["peers"]
            assert peers[1]["pending_repairs"] == [other.model_dump(mode="json")]

    asyncio.run(scenario())


@pytest.mark.parametrize("action", [None, "approve", "reject"])
@pytest.mark.parametrize("mode", ["bad_node", "unknown_node", "bad_id"])
def test_unknown_or_invalid_targets_never_contact_gateway(
    tmp_path: Path, action: str | None, mode: str
) -> None:
    handler = Mock(side_effect=AssertionError("不应访问远端"))
    poller = PeerServicePoller(
        configuration(tmp_path, peer(NODE)),
        PEER,
        InMemoryAuditSink(),
        transport=httpx.MockTransport(handler),
    )
    target = (
        "invalid"
        if mode == "bad_node"
        else str(NodeId.new())
        if mode == "unknown_node"
        else str(NODE)
    )
    identifier = "invalid" if mode == "bad_id" else str(repair().repair_id)

    async def scenario() -> None:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(local_app(poller)), base_url="http://127.0.0.1:8765"
        ) as client:
            response = await client.request(
                "POST" if action else "GET",
                f"/api/peers/{target}/repairs/{identifier}" + (f"/{action}" if action else ""),
                headers=SAME_ORIGIN,
            )
            assert response.status_code == 404
        handler.assert_not_called()

    asyncio.run(scenario())


@pytest.mark.parametrize("action", [None, "approve"])
def test_missing_local_credentials_are_unreachable(
    tmp_path: Path, action: str | None, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = configuration(tmp_path, peer(NODE, "书房电脑"))
    monkeypatch.setattr(config, "resolve_service_peer", Mock(side_effect=RuntimeError("secret")))
    poller = PeerServicePoller(config, PEER, InMemoryAuditSink())

    async def scenario() -> None:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(local_app(poller)), base_url="http://127.0.0.1:8765"
        ) as client:
            response = await client.request(
                "POST" if action else "GET",
                PATH + (f"/{action}" if action else ""),
                headers=SAME_ORIGIN,
            )
            assert response.status_code == (502 if action else 200)
            if action:
                assert response.json()["detail"] == "连不上 书房电脑，稍后再试"
            else:
                assert response.json()["access"] == "unreachable"

    asyncio.run(scenario())


def test_local_request_guard_rejects_cross_origin_decisions(tmp_path: Path) -> None:
    handler = Mock(side_effect=AssertionError("不应访问远端"))
    poller = PeerServicePoller(
        configuration(tmp_path, peer(NODE)),
        PEER,
        InMemoryAuditSink(),
        transport=httpx.MockTransport(handler),
    )

    async def scenario() -> None:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(local_app(poller)), base_url="http://127.0.0.1:8765"
        ) as client:
            for action in ("approve", "reject"):
                response = await client.post(
                    f"{PATH}/{action}", headers={**SAME_ORIGIN, "origin": "https://other.invalid"}
                )
                assert response.status_code == 403
        handler.assert_not_called()

    asyncio.run(scenario())
