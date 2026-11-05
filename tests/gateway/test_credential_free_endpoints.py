"""网关上不带节点凭据就能访问的接口，只能是登记过的那几个，且回的内容不超出登记的字段。"""

from __future__ import annotations

import asyncio
from pathlib import Path
from uuid import uuid4

import httpx
from fastapi import FastAPI
from fastapi.routing import APIRoute
from pydantic import BaseModel
from tests.gateway.test_api import call_payload
from tests.gateway.test_model_lending import call
from tests.gateway.test_operations import (
    _execute_payload,  # pyright: ignore[reportPrivateUsage]
    _payload,  # pyright: ignore[reportPrivateUsage]
    _remote_plan,  # pyright: ignore[reportPrivateUsage]
)
from tests.trust.test_friends import pair
from tests.trust.test_own_devices import NOW, Computer, computer, request_for

from tunnelminion.agent.invites import InMemoryInviteStore, InviteService
from tunnelminion.domain.identifiers import NodeId, OperationId
from tunnelminion.domain.invites import InviteAcceptance, InvitePermissions
from tunnelminion.domain.tools import Platform
from tunnelminion.domain.trust import PassScope, RequestPassClaims
from tunnelminion.gateway.api import CREDENTIAL_FREE_ENDPOINTS, create_gateway_router
from tunnelminion.gateway.audit import InMemoryGatewaySecurityAuditSink
from tunnelminion.gateway.contracts import GatewayErrorCode, GatewayErrorResponse
from tunnelminion.tools.audit import InMemoryAuditSink
from tunnelminion.tools.registry import ToolRegistry
from tunnelminion.tools.runtime import ToolRuntime
from tunnelminion.trust.friends import FriendsService

# 路径参数的合法样例；新接口用了新的路径参数时要在这里补上。
PATH_VALUES = {
    "tool_name": "get_node_summary",
    "value": "dlg_" + "1" * 32,
    "operation_id": str(OperationId.new()),
    "repair_id": str(OperationId.new()),
}


def gateway(a: Computer) -> tuple[FastAPI, list[tuple[str, str]], InviteService]:
    """正式运行时的网关应用只挂这一个路由器；返回应用、全部路由和邀请服务。"""
    invites = InviteService(
        a.service.node_id,
        Platform.WINDOWS,
        a.config,
        InMemoryInviteStore(),
        a.policy,
        clock=lambda: NOW,
    )
    registry = ToolRegistry()
    router = create_gateway_router(
        a.service.node_id,
        Platform.WINDOWS,
        registry,
        ToolRuntime(registry, Platform.WINDOWS, InMemoryAuditSink()),
        a.policy,
        InMemoryGatewaySecurityAuditSink(),
        owner_devices=a.service,
        invite_service=invites,
    )
    app = FastAPI()
    app.include_router(router)
    assert all(isinstance(route, APIRoute) for route in router.routes)
    routes = sorted(
        (method, route.path)
        for route in router.routes
        if isinstance(route, APIRoute)
        for method in route.methods or ()
    )
    return app, routes, invites


def exposed(body: dict[str, object]) -> set[str]:
    """响应里真正带了内容的顶层字段。"""
    return {key for key, value in body.items() if value not in (None, [], {})}


def stranger_pass(x: Computer, a: Computer) -> str:
    """没配对过的电脑自己签的、格式完整的通行证。"""
    return x.key.request_pass(
        RequestPassClaims(
            iss=x.service.node_id,
            aud=a.service.node_id,
            scope=PassScope.TOOL_GATEWAY,
            iat=int(NOW.timestamp()),
            exp=int(NOW.timestamp()) + 60,
            jti=uuid4().hex,
            owner_fingerprint=x.service.roster().owner_fingerprint,
            roster_version=x.service.roster().version,
        )
    )


def test_every_route_without_credentials_is_rejected_unless_registered(tmp_path: Path) -> None:
    apps: dict[str, FastAPI] = {}
    a = computer(tmp_path / "a", 1, apps)
    b = computer(tmp_path / "b", 2, apps, a)
    x = computer(tmp_path / "x", 4, apps)
    app, found, _invites = gateway(a)
    apps[a.host] = app
    assert set(CREDENTIAL_FREE_ENDPOINTS) <= set(found)
    plan = _remote_plan(x.service.node_id, a.service.node_id)
    # 有请求体模型的接口给一份能通过校验的请求体，确认挡住请求的是认证而不是请求体校验。
    bodies: dict[tuple[str, str], object] = {
        ("POST", "/v1/tools/{tool_name}:call"): call_payload(x.service.node_id)[0],
        ("POST", "/v1/operations:submit"): _payload(plan),
        ("POST", "/v1/operations:execute"): _execute_payload(plan),
        ("POST", "/v1/model:complete"): call(x.service.node_id).model_dump(mode="json"),
        ("POST", "/v1/delegations"): {"caller_node_id": str(x.service.node_id), "question": "?"},
    }
    credentials: tuple[dict[str, str], ...] = (
        {},
        {"Authorization": "Bearer forged"},
        {"Authorization": "Basic forged"},
    )

    async def scenario() -> None:
        for source in (x, b):
            headers = (*credentials, {"Authorization": f"Bearer {stranger_pass(x, a)}"})
            async with httpx.AsyncClient(
                transport=source.mesh, base_url=f"http://{a.host}"
            ) as client:
                for method, path in found:
                    url = path.format(**PATH_VALUES)
                    for header in headers:
                        response = await client.request(
                            method, url, json=bodies.get((method, path), {}), headers=header
                        )
                        where = f"{method} {path} 来自 {source.host} 带 {sorted(header)}"
                        assert response.status_code == 401, where
                        if (method, path) in CREDENTIAL_FREE_ENDPOINTS:
                            continue
                        assert GatewayErrorResponse.model_validate_json(
                            response.content
                        ).error.code in {
                            GatewayErrorCode.UNAUTHENTICATED,
                            GatewayErrorCode.TRUST_SYNC_REQUIRED,
                        }, where

    asyncio.run(scenario())


def test_registered_endpoints_return_only_registered_fields(tmp_path: Path) -> None:
    apps: dict[str, FastAPI] = {}
    a = computer(tmp_path / "a", 1, apps)
    b = computer(tmp_path / "b", 2, apps, a)
    f = computer(tmp_path / "f", 3, apps)
    g = computer(tmp_path / "g", 5, apps)
    pair(a, f)
    app, _routes, invites = gateway(a)
    apps[a.host] = app
    joining = computer(tmp_path / "n", 6, apps, uninitialized=True)
    newcomer = computer(tmp_path / "i", 7, apps, uninitialized=True)
    join_code = a.service.invite()
    pair_code = FriendsService(a.service).invite("小明")
    invite_code = invites.create(InvitePermissions())
    # 每个登记接口不带节点凭据时的合法用法：来源电脑、请求体、一次性码。
    cases: dict[tuple[str, str], list[tuple[Computer, BaseModel, dict[str, str]]]] = {
        ("POST", "/v1/owner:join"): [
            (
                joining,
                request_for(join_code, joining.service.node_id, joining.key, joining.host),
                {"Authorization": f"Bearer {join_code.token}"},
            )
        ],
        ("POST", "/v1/friends:pair"): [
            (
                g,
                FriendsService(g.service).pairing("小林"),
                {"Authorization": f"Bearer {pair_code.token}"},
            )
        ],
        ("POST", "/v1/invites:accept"): [
            (
                newcomer,
                InviteAcceptance(
                    node_id=NodeId.new(), platform=Platform.MACOS, host=newcomer.host, port=9000
                ),
                {"Authorization": f"Bearer {invite_code.token}"},
            )
        ],
        ("POST", "/v1/trust:sync"): [
            (b, b.service.message(include_private=False), {}),
            (f, f.service.message(include_private=False), {}),
        ],
    }
    assert set(cases) == set(CREDENTIAL_FREE_ENDPOINTS)

    async def scenario() -> None:
        for (method, path), uses in cases.items():
            for source, body, headers in uses:
                async with httpx.AsyncClient(
                    transport=source.mesh, base_url=f"http://{a.host}"
                ) as client:
                    response = await client.request(
                        method, path, content=body.model_dump_json(), headers=headers
                    )
                assert response.is_success, (path, response.text)
                assert exposed(response.json()) <= CREDENTIAL_FREE_ENDPOINTS[method, path], path

    asyncio.run(scenario())
