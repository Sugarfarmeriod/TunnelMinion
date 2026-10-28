"""我的电脑网关的来源、限流、同步和代批准验收。"""

from __future__ import annotations

import asyncio
from datetime import timedelta
from pathlib import Path
from typing import cast

import httpx
import pytest
from fastapi import FastAPI
from tests.gateway.test_api import call_payload
from tests.operation.factories import plan as operation_plan
from tests.repair.factories import plan
from tests.repair.fakes import RepairHarness
from tests.trust.test_own_devices import NOW, Computer, computer, request_for, signed_claims

from tunnelminion.domain.identifiers import DelegationId, NodeId, OperationId
from tunnelminion.domain.tools import Platform
from tunnelminion.domain.trust import PassScope, SignaturePurpose, TrustList
from tunnelminion.gateway.api import create_gateway_router
from tunnelminion.gateway.audit import InMemoryGatewaySecurityAuditSink
from tunnelminion.gateway.client import RemoteGatewayError
from tunnelminion.gateway.contracts import GATEWAY_PROTOCOL, GatewayErrorCode, GatewayErrorResponse
from tunnelminion.memory.sqlite import SQLiteStores
from tunnelminion.repair.contracts import RepairRecord
from tunnelminion.tools.audit import InMemoryAuditSink
from tunnelminion.tools.registry import ToolRegistry
from tunnelminion.tools.runtime import ToolRuntime
from tunnelminion.trust.contracts import DevicePermissions, IdentityError, TrustSyncMessage
from tunnelminion.trust.keys import DEVICE_KEY_NAME, PrivateKey
from tunnelminion.trust.passes import RequestPassVerifier, issue_pass
from tunnelminion.trust.signatures import seal


def gateway(c: Computer, *, enabled: bool = True, repairs: RepairHarness | None = None) -> FastAPI:
    app = FastAPI()
    registry = ToolRegistry()
    app.include_router(
        create_gateway_router(
            c.service.node_id,
            Platform.WINDOWS,
            registry,
            ToolRuntime(registry, Platform.WINDOWS, InMemoryAuditSink()),
            c.policy,
            InMemoryGatewaySecurityAuditSink(),
            owner_devices=c.service if enabled else None,
            repair_service=repairs.service if repairs else None,
        )
    )
    return app


@pytest.mark.parametrize(
    "fault",
    ["no_service", "no_auth", "bad_auth", "large", "malformed", "no_source", "self", "public"],
)
def test_join_api_uniform_failures(tmp_path: Path, fault: str) -> None:
    a = computer(tmp_path / "a", 1, {})
    code = a.service.invite()
    node_id = a.service.node_id if fault == "self" else NodeId.new()
    host = "8.8.8.8" if fault == "public" else "10.20.0.2"
    body = request_for(code, node_id, PrivateKey.generate(), host).model_dump_json()
    if fault == "large":
        body = "x" * 512_001
    elif fault == "malformed":
        body = "invalid"
    headers = (
        {}
        if fault == "no_auth"
        else {"Authorization": "Basic bad" if fault == "bad_auth" else f"Bearer {code.token}"}
    )
    source = cast(tuple[str, int], None) if fault == "no_source" else (host, 1234)

    async def scenario() -> None:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(gateway(a, enabled=fault != "no_service"), client=source),
            base_url="http://127.0.0.1",
        ) as client:
            response = await client.post("/v1/owner:join", content=body, headers=headers)
        assert response.status_code == 401
        error = GatewayErrorResponse.model_validate_json(response.content).error
        assert error.code is GatewayErrorCode.INVITE_INVALID
        assert error.message == "邀请码无效、已过期或已被使用"
        assert code.token not in response.text

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "fault",
    [
        "public",
        "unspecified",
        "multicast",
        "no_source",
        "no_service",
        "large",
        "malformed",
        "roster_kind",
        "trust_kind",
        "other_owner",
        "bad_signature",
    ],
)
def test_sync_rejects_untrusted_sources_and_documents(tmp_path: Path, fault: str) -> None:
    a = computer(tmp_path / "a", 1, {})
    source = {"public": "8.8.8.8", "unspecified": "0.0.0.0", "multicast": "239.1.1.1"}.get(
        fault, "127.0.0.1"
    )
    message = a.service.message()
    if fault == "roster_kind":
        message = TrustSyncMessage(roster=message.trust_list)
    elif fault == "trust_kind":
        message = TrustSyncMessage(trust_list=message.roster)
    elif fault == "other_owner":
        message = computer(tmp_path / "other", 4, {}).service.message()
    elif fault == "bad_signature":
        assert message.roster is not None
        message = TrustSyncMessage(
            roster=seal(
                SignaturePurpose.OWNER_ROSTER, message.roster.payload, PrivateKey.generate()
            )
        )
    body = (
        "x" * 512_001
        if fault == "large"
        else "invalid"
        if fault == "malformed"
        else message.model_dump_json()
    )
    address = cast(tuple[str, int], None) if fault == "no_source" else (source, 1234)

    async def scenario() -> None:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(
                gateway(a, enabled=fault != "no_service"), client=address
            ),
            base_url="http://127.0.0.1",
        ) as client:
            response = await client.post("/v1/trust:sync", content=body)
        assert response.status_code == 401

    asyncio.run(scenario())


@pytest.mark.parametrize(("path", "count"), [("/v1/owner:join", 10), ("/v1/trust:sync", 60)])
def test_public_trust_endpoints_are_rate_limited_and_recover(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, path: str, count: int
) -> None:
    a = computer(tmp_path / "a", 1, {})
    tick = 100.0
    monkeypatch.setattr("tunnelminion.gateway.api.monotonic", lambda: tick)

    async def scenario() -> None:
        nonlocal tick
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(gateway(a)), base_url="http://127.0.0.1"
        ) as client:
            for _ in range(count):
                assert (await client.post(path, content="{}")).status_code != 429
            assert (await client.post(path, content="{}")).status_code == 429
            tick += 60
            assert (await client.post(path, content="{}")).status_code != 429
        # 另一台机器有自己的计数，不受前面刷请求的影响。
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(gateway(a), client=("10.0.0.9", 50000)),
            base_url="http://127.0.0.1",
        ) as other:
            for _ in range(count):
                assert (await other.post(path, content="{}")).status_code != 429

    asyncio.run(scenario())


def test_trust_sync_rejects_public_source_before_counting(tmp_path: Path) -> None:
    a = computer(tmp_path / "a", 1, {})

    async def scenario() -> None:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(gateway(a), client=("8.8.8.8", 50000)),
            base_url="http://127.0.0.1",
        ) as client:
            for _ in range(70):
                assert (await client.post("/v1/trust:sync", content="{}")).status_code == 401

    asyncio.run(scenario())


def test_startup_push_failure_is_logged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    a = computer(tmp_path / "a", 1, {})

    async def broken(*_args: object) -> tuple[NodeId, ...]:
        raise IdentityError("本机身份记录不完整")

    monkeypatch.setattr(a.service, "push", broken)
    app = gateway(a)

    async def scenario() -> None:
        async with app.router.lifespan_context(app):
            for _ in range(100):
                if "启动时同步名单失败" in caplog.text:
                    break
                await asyncio.sleep(0.01)

    asyncio.run(scenario())
    assert "启动时同步名单失败" in caplog.text


def test_startup_sync_accepts_new_roster_and_trust_list(tmp_path: Path) -> None:
    apps: dict[str, FastAPI] = {}
    a = computer(tmp_path / "a", 1, apps)
    b = computer(tmp_path / "b", 2, apps, a)
    c = computer(tmp_path / "c", 3, apps, a)
    a.service.store.accept(
        seal(
            SignaturePurpose.TRUST_LIST,
            TrustList(
                owner_fingerprint=a.service.roster().owner_fingerprint,
                version=2,
                issued_at=NOW,
            ),
            a.service.owner_key(),
        ),
        "本机更新信任名单",
    )
    app = gateway(b)

    async def scenario() -> None:
        async with app.router.lifespan_context(app):
            # 启动同步在后台进行，等它把新名单拿回来。
            for _ in range(200):
                if b.service.roster().device(c.service.node_id) is not None:
                    break
                await asyncio.sleep(0.01)
            assert b.service.roster().device(c.service.node_id) is not None
            # 我的电脑之间同步时带通行证，"我信任的人"名单也一并同步。
            assert b.service.message().trust_list == a.service.message().trust_list
        assert b.service.receive(TrustSyncMessage(), "空消息") == b.service.message()

    asyncio.run(scenario())
    assert "同步名单" in SQLiteStores.open(b.root / "runtime.sqlite3").trust.audits()[-1].reason


def test_owner_device_can_proxy_approve_until_locally_restricted(tmp_path: Path) -> None:
    apps: dict[str, FastAPI] = {}
    a = computer(tmp_path / "a", 1, apps)
    b = computer(tmp_path / "b", 2, apps, a)
    h = RepairHarness(tmp_path / "repair")
    record = h.authorization.submit(RepairRecord.planned(plan(), actor="agent"), at=h.clock())
    apps[a.host] = gateway(a, repairs=h)

    async def scenario() -> None:
        result = await b.client(a).approve_repair(record.plan.operation_id)
        assert result.approved_by_peer
        a.service.restrict(b.service.node_id, DevicePermissions(allow_proxy_repair_approval=False))
        with pytest.raises(RemoteGatewayError) as caught:
            await b.client(a).get_repair(record.plan.operation_id)
        assert caught.value.gateway_code is GatewayErrorCode.REPAIR_APPROVAL_NOT_ALLOWED

    asyncio.run(scenario())


def test_unpaired_unknown_computer_cannot_access_gateway_interfaces(tmp_path: Path) -> None:
    a = computer(tmp_path / "a", 1, {})
    unknown = NodeId.new()
    tool_body, _, _ = call_payload(unknown)
    operation = operation_plan()
    operation_id = str(operation.operation_id)
    delegation_id = str(DelegationId.new())
    paths: list[tuple[str, str, object]] = [
        ("GET", "/v1/capabilities", None),
        ("GET", "/v1/services", None),
        ("GET", f"/v1/repairs/{OperationId.new()}", None),
        ("POST", f"/v1/repairs/{OperationId.new()}:approve", None),
        ("POST", f"/v1/repairs/{OperationId.new()}:reject", None),
        ("GET", f"/v1/delegations/{delegation_id}", None),
        ("DELETE", f"/v1/delegations/{delegation_id}", None),
        ("POST", "/v1/delegations", {"caller_node_id": str(unknown), "question": "检查服务"}),
        (
            "POST",
            "/v1/model:complete",
            {"caller_node_id": str(unknown), "messages": [{"role": "user", "content": "你好"}]},
        ),
        ("POST", "/v1/tools/get_node_summary:call", tool_body),
        ("GET", f"/v1/operations/{operation_id}", None),
        (
            "POST",
            "/v1/operations:submit",
            {"protocol": GATEWAY_PROTOCOL.model_dump(), "plan": operation.model_dump(mode="json")},
        ),
        (
            "POST",
            "/v1/operations:execute",
            {
                "protocol": GATEWAY_PROTOCOL.model_dump(),
                **operation.model_dump(
                    mode="json",
                    include={
                        "operation_id",
                        "plan_version",
                        "idempotency_key",
                        "request_node_id",
                        "target_node_id",
                        "thread_id",
                        "run_id",
                        "tool_run_ids",
                    },
                ),
            },
        ),
    ]

    async def scenario() -> None:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(gateway(a)), base_url="http://127.0.0.1"
        ) as client:
            for method, path, body in paths:
                response = await client.request(
                    method, path, json=body, headers={"Authorization": "Bearer " + "x" * 40}
                )
                assert response.status_code == 401, (path, response.text)

    asyncio.run(scenario())


def test_replay_cache_clock_leeway_and_missing_local_credentials(tmp_path: Path) -> None:
    apps: dict[str, FastAPI] = {}
    a = computer(tmp_path / "a", 1, apps)
    b = computer(tmp_path / "b", 2, apps, a)
    verifier = RequestPassVerifier(a.service)
    token = signed_claims(b, a, {"iat": int(NOW.timestamp()) - 64, "exp": int(NOW.timestamp()) - 4})
    peer = verifier.authenticate(token, "tool-gateway", b.host)
    assert peer is not None
    assert verifier.authenticate(token, "tool-gateway", b.host) is None
    a.service.clock = lambda: NOW + timedelta(seconds=62)
    b.service.clock = a.service.clock
    assert (
        verifier.authenticate(
            issue_pass(b.service, a.service.node_id, PassScope.TOOL_GATEWAY), "tool-gateway", b.host
        )
        is not None
    )
    assert verifier.authenticate("broken", "tool-gateway", b.host) is None
    assert verifier.authenticate("e30.e30.e30", "tool-gateway", b.host) is None
    for target in (a.service.node_id, NodeId.new()):
        if target == a.service.node_id:
            b.secrets.delete(DEVICE_KEY_NAME)
        with pytest.raises(IdentityError, match="不能使用通行证"):
            issue_pass(b.service, target, PassScope.TOOL_GATEWAY)


@pytest.mark.parametrize("fault", ["status", "large", "malformed", "unreachable"])
def test_sync_failure_is_safe_and_does_not_block_startup(
    tmp_path: Path, fault: str, caplog: pytest.LogCaptureFixture
) -> None:
    apps: dict[str, FastAPI] = {}
    a = computer(tmp_path / "a", 1, apps)
    b = computer(tmp_path / "b", 2, apps, a)

    def handler(request: httpx.Request) -> httpx.Response:
        if fault == "unreachable":
            raise httpx.ConnectError("秘密不能进入报错", request=request)
        return httpx.Response(
            500 if fault == "status" else 200,
            content="x" * 512_001 if fault == "large" else "invalid",
        )

    b.service.transport = httpx.MockTransport(handler)
    app = gateway(b)

    async def scenario() -> None:
        async with app.router.lifespan_context(app):
            pass
        assert await b.service.push() == (a.service.node_id,)

    asyncio.run(scenario())
    assert "秘密不能进入报错" not in caplog.text


def test_rate_limit_window_slides_per_request(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    a = computer(tmp_path / "a", 1, {})
    tick = 100.0
    monkeypatch.setattr("tunnelminion.gateway.api.monotonic", lambda: tick)

    async def scenario() -> None:
        nonlocal tick
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(gateway(a)), base_url="http://127.0.0.1"
        ) as client:
            for _ in range(9):
                assert (await client.post("/v1/owner:join", content="{}")).status_code != 429
            tick += 30
            assert (await client.post("/v1/owner:join", content="{}")).status_code != 429
            assert (await client.post("/v1/owner:join", content="{}")).status_code == 429
            # 一分钟前的 9 次滑出窗口，30 秒前那次还在。
            tick += 35
            for _ in range(9):
                assert (await client.post("/v1/owner:join", content="{}")).status_code != 429
            assert (await client.post("/v1/owner:join", content="{}")).status_code == 429

    asyncio.run(scenario())
