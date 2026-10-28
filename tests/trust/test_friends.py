"""朋友按人配对、名单隐私和三台电脑之间的权限验收。"""

from __future__ import annotations

import asyncio
import hashlib
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from contextlib import suppress
from datetime import timedelta
from pathlib import Path
from typing import cast
from uuid import uuid4

import httpx
import pytest
from fastapi import FastAPI
from tests.gateway.test_api import call_payload
from tests.gateway.test_delegation import real_agent
from tests.gateway.test_model_lending import StubProvider, call
from tests.operation.factories import plan as operation_plan
from tests.repair.factories import plan
from tests.repair.fakes import RepairHarness
from tests.tools.test_registry import definition
from tests.trust.test_own_devices import NOW, Computer, computer, signed_claims
from tests.trust.test_owner_gateway import gateway

from tunnelminion.agent.delegation import DelegationService
from tunnelminion.agent.model_lending import InMemoryModelUsageStore, ModelLendingService
from tunnelminion.domain.delegation import DelegationStatus
from tunnelminion.domain.identifiers import NodeId, OperationId
from tunnelminion.domain.tools import Platform
from tunnelminion.domain.trust import (
    FriendPermissions,
    JoinCode,
    JoinCodeKind,
    OwnerRoster,
    PassScope,
    RequestPassClaims,
    SignaturePurpose,
    key_fingerprint,
)
from tunnelminion.gateway.api import create_gateway_router
from tunnelminion.gateway.audit import InMemoryGatewaySecurityAuditSink
from tunnelminion.gateway.client import FixedGatewayClient, RemoteGatewayError
from tunnelminion.gateway.configuration import (
    GatewayPeerConfig,
    GatewayPeerInput,
    gateway_token_name,
)
from tunnelminion.gateway.contracts import GATEWAY_PROTOCOL, GatewayErrorCode, GatewayServices
from tunnelminion.gateway.security import GatewayAuthenticationKind, GatewayPeerPolicy
from tunnelminion.memory.sqlite import SQLiteStores
from tunnelminion.repair.contracts import RepairRecord, compute_repair_idempotency_key
from tunnelminion.tools.audit import InMemoryAuditSink
from tunnelminion.tools.fakes import FakeToolAdapter
from tunnelminion.tools.registry import ToolRegistry
from tunnelminion.tools.runtime import ToolRuntime
from tunnelminion.trust.contracts import (
    IdentityError,
    TrustSyncMessage,
    VersionRejectedError,
)
from tunnelminion.trust.devices import INVALID_INVITE
from tunnelminion.trust.friends import FriendsService
from tunnelminion.trust.keys import PrivateKey
from tunnelminion.trust.passes import RequestPassVerifier
from tunnelminion.trust.signatures import VerificationError, seal


def pair(a: Computer, friend: Computer) -> JoinCode:
    inviter = FriendsService(a.service)
    joining = FriendsService(friend.service)
    code = inviter.invite("小明")
    response = inviter.accept_pair(code.token, joining.pairing("小林"), friend.host)
    joining.install_pair(code, response)
    return code


def token(source: Computer, target: Computer, scope: PassScope = PassScope.TOOL_GATEWAY) -> str:
    return source.key.request_pass(
        RequestPassClaims(
            iss=source.service.node_id,
            aud=target.service.node_id,
            scope=scope,
            iat=int(NOW.timestamp()),
            exp=int(NOW.timestamp()) + 60,
            jti=uuid4().hex,
            owner_fingerprint=source.service.roster().owner_fingerprint,
            roster_version=source.service.roster().version,
        )
    )


async def request(
    source: Computer,
    target: Computer,
    method: str,
    path: str,
    body: object = None,
    *,
    credential: str | None = None,
) -> httpx.Response:
    scope = (
        PassScope.OPERATION_GATEWAY if path.startswith("/v1/operations") else PassScope.TOOL_GATEWAY
    )
    async with httpx.AsyncClient(transport=source.mesh, base_url=f"http://{target.host}") as client:
        return await client.request(
            method,
            path,
            json=body,
            headers={"Authorization": f"Bearer {credential or token(source, target, scope)}"},
        )


def friend_gateway(
    c: Computer,
    repairs: RepairHarness | None = None,
) -> tuple[FastAPI, DelegationService, InMemoryModelUsageStore, StubProvider]:
    app = FastAPI()
    registry = ToolRegistry()
    registry.register(definition("get_node_summary"), FakeToolAdapter())
    stores = SQLiteStores.open(c.root / "runtime.sqlite3")
    delegation = DelegationService(
        c.service.node_id, stores.delegations, real_agent, lambda: ("probe_service",)
    )
    usage = InMemoryModelUsageStore()
    provider = StubProvider()
    lending = ModelLendingService(
        c.service.node_id, lambda: provider, usage, clock=lambda: NOW.date()
    )

    async def services() -> GatewayServices:
        return GatewayServices(node_id=c.service.node_id, display_name="我的电脑", observed_at=NOW)

    app.include_router(
        create_gateway_router(
            c.service.node_id,
            Platform.WINDOWS,
            registry,
            ToolRuntime(registry, Platform.WINDOWS, InMemoryAuditSink()),
            c.policy,
            InMemoryGatewaySecurityAuditSink(),
            owner_devices=c.service,
            delegation_service=delegation,
            service_reader=services,
            model_lending_service=lending,
            repair_service=repairs.service if repairs else None,
        )
    )
    return app, delegation, usage, provider


def test_pair_once_for_all_my_computers_delegate_and_refuse_repair(tmp_path: Path) -> None:
    apps: dict[str, FastAPI] = {}
    a = computer(tmp_path / "a", 1, apps)
    b = computer(tmp_path / "b", 2, apps, a)
    f = computer(tmp_path / "f", 3, apps)
    h = RepairHarness(tmp_path / "repairs")
    repair_plan = plan()
    repair_plan = repair_plan.model_copy(
        update={
            "node_id": b.service.node_id,
            "idempotency_key": compute_repair_idempotency_key(
                node_id=b.service.node_id,
                service_key=repair_plan.service_key,
                kind=repair_plan.kind,
                target_fingerprint=repair_plan.target.fingerprint,
            ),
        }
    )
    record = h.authorization.submit(
        RepairRecord.planned(repair_plan, actor="agent"),
        at=h.clock(),
    )
    app, delegation, _, _ = friend_gateway(b, h)
    apps[b.host] = app

    async def scenario() -> None:
        code = FriendsService(a.service).invite("小明")
        assert code.encode().startswith("tmf1_") and code.kind is JoinCodeKind.FRIEND
        assert code.expires_at - NOW == timedelta(hours=24)
        await FriendsService(f.service).join(code, "小林")
        assert b.service.trust_list() == a.service.trust_list()
        assert b.service.store.friend_rosters() == a.service.store.friend_rosters()
        assert a.service.trust_list().people[0].display_name == "小林"
        assert f.service.trust_list().people[0].display_name == "小明"
        peer = next(peer for peer in b.config.view().peers if peer.node_id == f.service.node_id)
        assert peer.relationship == "friend" and "小林" in (peer.display_name or "")
        assert not peer.allowed_tools and not peer.allowed_operations
        endpoint, credentials = f.config.resolve_service_peer(b.service.node_id)
        client = FixedGatewayClient(
            endpoint,
            credentials,
            f.service.node_id,
            b.service.node_id,
            InMemoryAuditSink(),
            transport=f.mesh,
        )
        assert (await client.get_services()).node_id == b.service.node_id
        task = await client.submit_delegation("8082 服务是否存在？")
        await delegation.wait(task.delegation_id)
        finished = await client.get_delegation(task.delegation_id)
        assert finished.status is DelegationStatus.COMPLETED
        assert finished.result is not None and finished.result.summary
        with pytest.raises(RemoteGatewayError) as denied:
            await client.approve_repair(record.plan.operation_id)
        assert denied.value.gateway_code is GatewayErrorCode.REPAIR_APPROVAL_NOT_ALLOWED
        assert h.service.get(record.plan.operation_id) == record
        FriendsService(a.service).remove("小林")
        await a.service.push()
        assert not b.service.trust_list().people and not b.service.store.friend_rosters()
        assert (await request(f, b, "GET", "/v1/services")).status_code == 401

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "fault", ["expired", "source", "signature", "owner", "recovery", "self", "duplicate"]
)
def test_pairing_rejects_invalid_material_without_consuming_valid_code(
    tmp_path: Path, fault: str
) -> None:
    a = computer(tmp_path / "a", 1, {})
    f = computer(tmp_path / "f", 3, {})
    service = FriendsService(a.service)
    joining = FriendsService(f.service)
    code = service.invite()
    pairing = joining.pairing()
    if fault == "expired":
        a.service.clock = lambda: NOW + timedelta(hours=24)
    elif fault == "signature":
        pairing = pairing.model_copy(
            update={
                "roster": seal(
                    SignaturePurpose.OWNER_ROSTER, f.service.roster(), PrivateKey.generate()
                )
            }
        )
    elif fault == "owner":
        pairing = pairing.model_copy(update={"owner_public_key": PrivateKey.generate().public_key})
    elif fault == "recovery":
        pairing = pairing.model_copy(
            update={"recovery_fingerprint": key_fingerprint(PrivateKey.generate().public_key)}
        )
    elif fault == "self":
        pairing = service.pairing()
    elif fault == "duplicate":
        pair(a, f)
    before = a.service.message()
    with pytest.raises(IdentityError, match=INVALID_INVITE):
        service.accept_pair(code.token, pairing, "10.20.0.99" if fault == "source" else f.host)
    assert a.service.message() == before
    if fault not in ("expired", "duplicate"):
        service.accept_pair(code.token, joining.pairing(), f.host)
        with pytest.raises(IdentityError, match=INVALID_INVITE):
            service.accept_pair(code.token, joining.pairing(), f.host)


def test_friend_invite_digest_atomic_consumption_and_owner_key_requirement(tmp_path: Path) -> None:
    apps: dict[str, FastAPI] = {}
    a = computer(tmp_path / "a", 1, apps)
    b = computer(tmp_path / "b", 2, apps, a)
    service = FriendsService(a.service)
    code = service.invite("我的名字")
    digest = hashlib.sha256(code.token.encode()).digest()

    def consume(_index: int) -> str | None:
        return a.service.store.consume_friend_invite(digest, b.service.node_id, NOW)

    with ThreadPoolExecutor(max_workers=2) as executor:
        consumed = tuple(executor.map(consume, range(2)))
    assert sorted(consumed, key=lambda item: item or "") == [None, "我的名字"]
    raw = (a.root / "runtime.sqlite3").read_bytes()
    assert code.token.encode() not in raw and code.encode().encode() not in raw
    assert (
        a.key.seed_text().encode() not in raw
        and a.service.owner_key().seed_text().encode() not in raw
    )
    with pytest.raises(IdentityError, match="持有机主密钥"):
        FriendsService(b.service).invite()
    with pytest.raises(IdentityError, match="持有机主密钥"):
        asyncio.run(FriendsService(b.service).join(code))


def test_join_checks_pinned_owner_and_inviter_before_saving(tmp_path: Path) -> None:
    a = computer(tmp_path / "a", 1, {})
    f = computer(tmp_path / "f", 3, {})
    code = FriendsService(a.service).invite()
    for bad in (
        code.model_copy(update={"owner_fingerprint": f.service.roster().owner_fingerprint}),
        code.model_copy(update={"inviter_node_id": NodeId.new()}),
        code.model_copy(update={"host": "10.30.0.1"}),
        code.model_copy(update={"port": 9999}),
    ):
        with pytest.raises(VerificationError, match="机主身份不符"):
            FriendsService(f.service).install_pair(bad, FriendsService(a.service).pairing())
    assert not f.service.trust_list().people


@pytest.mark.parametrize(
    "fault", ["rate", "status", "large", "malformed", "connection", "kind", "expired", "naive"]
)
def test_join_failures_hide_network_errors_and_leave_no_friend(tmp_path: Path, fault: str) -> None:
    a = computer(tmp_path / "a", 1, {})
    f = computer(tmp_path / "f", 3, {})
    code = FriendsService(a.service).invite()
    if fault == "kind":
        code = a.service.invite()
    elif fault == "expired":
        code = code.model_copy(update={"expires_at": NOW})
    elif fault == "naive":
        code = code.model_copy(update={"expires_at": NOW.replace(tzinfo=None)})

    def handler(request: httpx.Request) -> httpx.Response:
        if fault == "connection":
            raise httpx.ConnectError(code.token, request=request)
        return httpx.Response(
            429 if fault == "rate" else 401 if fault == "status" else 200,
            content="x" * 512_001 if fault == "large" else "invalid",
        )

    f.service.transport = httpx.MockTransport(handler)
    with pytest.raises(IdentityError) as caught:
        asyncio.run(FriendsService(f.service).join(code))
    assert code.token not in str(caught.value) and not f.service.trust_list().people


def test_trust_sync_privacy_requires_a_fresh_pass_from_my_computer(tmp_path: Path) -> None:
    apps: dict[str, FastAPI] = {}
    a = computer(tmp_path / "a", 1, apps)
    b = computer(tmp_path / "b", 2, apps, a)
    f = computer(tmp_path / "f", 3, apps)
    pair(a, f)
    credentials = (
        None,
        "Bearer bad",
        f"Bearer {token(b, a)}",
        f"Bearer {token(f, a, PassScope.TRUST_SYNC)}",
        f"Bearer {token(b, a, PassScope.TRUST_SYNC)}",
    )

    async def scenario() -> None:
        for index, auth in enumerate(credentials):
            source = f if index == 3 else b
            async with httpx.AsyncClient(
                transport=source.mesh, base_url=f"http://{a.host}"
            ) as client:
                response = await client.post(
                    "/v1/trust:sync", json={}, headers={"Authorization": auth} if auth else {}
                )
                result = TrustSyncMessage.model_validate_json(response.content)
                assert result.roster == a.service.message().roster
                assert (result.trust_list is not None) == (index == 4)
                assert bool(result.friend_rosters) == (index == 4)
                if index == 4:
                    replay = await client.post(
                        "/v1/trust:sync", json={}, headers={"Authorization": auth or ""}
                    )
                    replayed = TrustSyncMessage.model_validate_json(replay.content)
                    assert replayed.trust_list is None and not replayed.friend_rosters

    asyncio.run(scenario())


def test_friend_permissions_cap_legacy_token_tools_operations_and_model_quota(
    tmp_path: Path,
) -> None:
    apps: dict[str, FastAPI] = {}
    a = computer(tmp_path / "a", 1, apps)
    f = computer(tmp_path / "f", 3, apps)
    pair(a, f)
    legacy_token = "tmn_" + "f" * 40
    a.config.provision_peer(
        GatewayPeerInput(
            peer=GatewayPeerConfig(
                node_id=f.service.node_id,
                platform=Platform.WINDOWS,
                host=f.host,
                allowed_tools=frozenset({"get_node_summary"}),
                allowed_operations=frozenset({"share_local_http_service"}),
                allow_proxy_repair_approval=True,
                allow_delegation=True,
                allow_model_borrowing=True,
                daily_quota=80,
            ),
            token=legacy_token,
        )
    )
    a.policy = a.config.build_security_policy()
    apps[a.host], _, usage, provider = friend_gateway(a)
    friends = FriendsService(a.service)

    async def scenario() -> None:
        for credential in (
            token(f, a),
            legacy_token,
            signed_claims(
                f, a, {"owner_fingerprint": a.service.roster().owner_fingerprint, "is_owner": True}
            ),
        ):
            peer = a.policy.authenticate(f"Bearer {credential}", source_host=f.host)
            assert (
                peer is not None
                and peer.authentication_kind is GatewayAuthenticationKind.FRIEND_DEVICE
            )
            assert (
                not peer.allow_proxy_repair_approval
                and not peer.allowed_tools
                and not peer.allowed_operations
            )
        for method, path, body in (
            ("POST", "/v1/tools/get_node_summary:call", call_payload(f.service.node_id)[0]),
            (
                "POST",
                "/v1/operations:submit",
                {
                    "protocol": GATEWAY_PROTOCOL.model_dump(),
                    "plan": operation_plan().model_dump(mode="json"),
                },
            ),
            (
                "POST",
                "/v1/operations:execute",
                {
                    "protocol": GATEWAY_PROTOCOL.model_dump(),
                    **operation_plan().model_dump(
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
            ("GET", f"/v1/operations/{OperationId.new()}", None),
            ("POST", f"/v1/repairs/{OperationId.new()}:approve", None),
        ):
            assert (
                await request(f, a, method, path, body, credential=legacy_token)
            ).status_code == 403
        assert (
            await request(
                f, a, "POST", "/v1/model:complete", call(f.service.node_id).model_dump(mode="json")
            )
        ).status_code == 403
        friends.permissions("小林", FriendPermissions(allow_model_borrowing=True, daily_quota=100))
        friends.restrict("小林", FriendPermissions(allow_model_borrowing=True, daily_quota=40))
        assert (
            next(
                peer for peer in a.config.view().peers if peer.node_id == f.service.node_id
            ).daily_quota
            == 40
        )
        response = await request(
            f, a, "POST", "/v1/model:complete", call(f.service.node_id).model_dump(mode="json")
        )
        assert response.status_code == 200 and len(provider.requests) == 1
        usage.add(f.service.node_id, NOW.date(), 0, 23)
        assert (
            await request(
                f, a, "POST", "/v1/model:complete", call(f.service.node_id).model_dump(mode="json")
            )
        ).status_code == 429
        friends.restrict(
            "小林",
            FriendPermissions(allow_delegation=False, allow_model_borrowing=False, daily_quota=20),
        )
        assert (await request(f, a, "GET", "/v1/services")).status_code == 403
        friends.remove("小林")
        assert (
            await request(f, a, "GET", "/v1/capabilities", credential=legacy_token)
        ).status_code == 401
        assert a.config.view().peers[0].credential_configured is False
        assert a.secrets.get(gateway_token_name(f.service.node_id)) == legacy_token

    asyncio.run(scenario())


def test_friends_friend_cannot_authenticate_any_gateway_interface(tmp_path: Path) -> None:
    apps: dict[str, FastAPI] = {}
    a = computer(tmp_path / "a", 1, apps)
    f = computer(tmp_path / "f", 3, apps)
    x = computer(tmp_path / "x", 4, apps)
    pair(a, f)
    pair(f, x)

    async def scenario() -> None:
        await f.service.push()
        assert len(a.service.trust_list().people) == 1
        paths = [
            "/v1/capabilities",
            "/v1/services",
            f"/v1/delegations/dlg_{'1' * 32}",
            f"/v1/operations/{OperationId.new()}",
            f"/v1/repairs/{OperationId.new()}",
        ]
        for path in paths:
            assert (await request(x, a, "GET", path)).status_code == 401
        assert (
            await request(
                x, a, "POST", "/v1/tools/get_node_summary:call", call_payload(x.service.node_id)[0]
            )
        ).status_code == 401
        assert (
            await request(
                x, a, "POST", "/v1/model:complete", call(x.service.node_id).model_dump(mode="json")
            )
        ).status_code == 401
        assert (
            await request(
                x,
                a,
                "POST",
                "/v1/delegations",
                {"caller_node_id": str(x.service.node_id), "question": "能看吗"},
            )
        ).status_code == 401
        own = a.service.message()
        assert own.trust_list is not None
        with pytest.raises(VerificationError):
            a.service.receive(TrustSyncMessage(roster=x.service.message().roster), "朋友的朋友")

    asyncio.run(scenario())


def test_friend_roster_updates_sync_to_my_other_computer_and_retry_new_device(
    tmp_path: Path,
) -> None:
    apps: dict[str, FastAPI] = {}
    a = computer(tmp_path / "a", 1, apps)
    b = computer(tmp_path / "b", 2, apps, a)
    f = computer(tmp_path / "f", 3, apps)
    pair(a, f)

    async def scenario() -> None:
        await a.service.push()
        g = computer(tmp_path / "g", 4, apps, f)
        await g.service.push()
        assert b.service.known_device(g.service.node_id) is None
        client = g.client(b)
        result = await client.discover()
        assert result.node_id == b.service.node_id and not result.tools
        assert g.mesh.paths[-3:] == ["/v1/capabilities", "/v1/trust:sync", "/v1/capabilities"]
        assert b.service.known_device(g.service.node_id) is not None
        await b.service.push()
        assert a.service.store.friend_rosters() == b.service.store.friend_rosters()
        assert "同步名单" in SQLiteStores.open(a.root / "runtime.sqlite3").trust.audits()[-1].reason
        f.service.remove(g.service.node_id)
        await f.service.push()
        await a.service.push()
        assert b.service.known_device(g.service.node_id) is None
        assert (await request(g, b, "GET", "/v1/capabilities")).status_code == 401

    asyncio.run(scenario())


def test_friend_roster_requires_trusted_owner_signature_recovery_and_newer_version(
    tmp_path: Path,
) -> None:
    a = computer(tmp_path / "a", 1, {})
    f = computer(tmp_path / "f", 3, {})
    pair(a, f)
    roster = f.service.roster()
    envelope = f.service.message().roster
    assert envelope is not None
    with pytest.raises(VersionRejectedError):
        a.service.store.accept(envelope, "重复")
    for bad in (
        seal(SignaturePurpose.OWNER_ROSTER, roster, PrivateKey.generate()),
        seal(
            SignaturePurpose.OWNER_ROSTER,
            roster.model_copy(
                update={"recovery_fingerprint": a.service.roster().recovery_fingerprint}
            ),
            f.service.owner_key(),
        ),
        seal(
            SignaturePurpose.OWNER_ROSTER,
            roster.model_copy(update={"owner_public_key": roster.owner_public_key + "="}),
            f.service.owner_key(),
        ),
    ):
        with pytest.raises(VerificationError):
            a.service.store.accept(bad, "无效名单")
    with ThreadPoolExecutor(max_workers=2) as executor:

        def update(version: int) -> None:
            with suppress(VersionRejectedError):
                a.service.store.accept(
                    seal(
                        SignaturePurpose.OWNER_ROSTER,
                        roster.model_copy(update={"version": version}),
                        f.service.owner_key(),
                    ),
                    "并发新名单",
                )

        tuple(executor.map(update, (2, 3)))
    assert OwnerRoster.model_validate(a.service.store.friend_rosters()[0].payload).version == 3
    FriendsService(a.service).remove("小林")
    assert not a.service.store.friend_rosters()
    with pytest.raises(VerificationError):
        a.service.store.accept(envelope, "移除后重放")


@pytest.mark.parametrize(
    "fault", ["no_service", "no_auth", "bad_auth", "large", "malformed", "no_source"]
)
def test_pair_api_uniform_errors_never_echo_tokens(tmp_path: Path, fault: str) -> None:
    a = computer(tmp_path / "a", 1, {})
    f = computer(tmp_path / "f", 3, {})
    code = FriendsService(a.service).invite()
    body = FriendsService(f.service).pairing().model_dump_json()
    if fault == "large":
        body = "x" * 512_001
    elif fault == "malformed":
        body = "invalid"
    headers = (
        {}
        if fault == "no_auth"
        else {"Authorization": "Basic bad" if fault == "bad_auth" else f"Bearer {code.token}"}
    )
    address = cast(tuple[str, int], None) if fault == "no_source" else (f.host, 1234)

    async def scenario() -> None:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(
                gateway(a, enabled=fault != "no_service"), client=address
            ),
            base_url="http://127.0.0.1",
        ) as client:
            response = await client.post("/v1/friends:pair", content=body, headers=headers)
        assert response.status_code == 401 and INVALID_INVITE in response.text
        assert code.token not in response.text and a.key.seed_text() not in response.text

    asyncio.run(scenario())


def test_pair_api_rate_limit_recovers_after_a_minute(
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
            for _ in range(10):
                assert (await client.post("/v1/friends:pair", json={})).status_code == 401
            assert (await client.post("/v1/friends:pair", json={})).status_code == 429
            tick += 60
            assert (await client.post("/v1/friends:pair", json={})).status_code == 401

    asyncio.run(scenario())


def test_permission_limits_cannot_be_reopened_and_names_must_be_unique(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    a = computer(tmp_path / "a", 1, {})
    f = computer(tmp_path / "f", 3, {})
    g = computer(tmp_path / "g", 4, {})
    code = pair(a, f)
    friends = FriendsService(a.service)
    with pytest.raises(IdentityError, match=r"已经.*配对"):
        FriendsService(f.service).install_pair(code, friends.pairing())
    friends.permissions("小林", FriendPermissions(allow_model_borrowing=True, daily_quota=500_000))
    peer = RequestPassVerifier(a.service).friend_peer(f.service.node_id)
    assert peer is not None and peer.daily_quota == 500_000
    friends.restrict("小林", FriendPermissions(allow_model_borrowing=True, daily_quota=250_000))
    friends.restrict("小林", FriendPermissions(allow_model_borrowing=False, daily_quota=100))
    for permissions in (
        FriendPermissions(allow_model_borrowing=True, daily_quota=100),
        FriendPermissions(daily_quota=101),
    ):
        with pytest.raises(IdentityError, match="只能关闭或调小"):
            friends.restrict("小林", permissions)
    friends.permissions("小林", FriendPermissions(allow_delegation=False))
    with pytest.raises(IdentityError, match="只能关闭或调小"):
        friends.restrict("小林", FriendPermissions())
    pair(a, g)
    with pytest.raises(IdentityError, match="显示名重复"):
        friends.resolve("小林")
    assert (
        friends.resolve(f.service.roster().owner_fingerprint).owner_public_key
        == f.service.roster().owner_public_key
    )
    monkeypatch.setattr(a.service, "active", lambda: False)
    legacy = GatewayPeerPolicy.from_token(
        f.service.node_id, "tmn_" + "x" * 40, ("get_node_summary",)
    )
    assert RequestPassVerifier(a.service).static_peer(legacy, f.host) is None
    with pytest.raises(IdentityError, match="本机已被移出"):
        friends.pairing()


def test_join_uses_local_address_without_connecting_to_another_computer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    apps: dict[str, FastAPI] = {}
    a = computer(tmp_path / "a", 1, apps)
    f = computer(tmp_path / "f", 3, apps)
    f.service.transport = None

    def transport(*, local_address: str) -> httpx.AsyncBaseTransport:
        assert local_address == f.host
        return f.mesh

    monkeypatch.setattr(httpx, "AsyncHTTPTransport", transport)
    asyncio.run(FriendsService(f.service).join(FriendsService(a.service).invite()))
    assert (
        f.service.trust_list().people[0].owner_fingerprint == a.service.roster().owner_fingerprint
    )


def test_missing_local_trust_list_is_rejected(tmp_path: Path) -> None:
    a = computer(tmp_path / "a", 1, {})
    with sqlite3.connect(a.root / "runtime.sqlite3") as connection:
        connection.execute(
            "DELETE FROM trust_documents WHERE kind=?", (SignaturePurpose.TRUST_LIST.value,)
        )
    with pytest.raises(IdentityError, match="本机身份记录不完整"):
        a.service.trust_list()


def test_friend_cannot_override_my_computers_identity_by_reusing_a_node_id(tmp_path: Path) -> None:
    apps: dict[str, FastAPI] = {}
    a = computer(tmp_path / "a", 1, apps)
    b = computer(tmp_path / "b", 2, apps, a)
    f = computer(tmp_path / "f", 3, apps)
    pair(a, f)
    roster = f.service.roster()
    impostor = roster.devices[0].model_copy(
        update={
            "node_id": b.service.node_id,
            "device_public_key": PrivateKey.generate().public_key,
        }
    )
    a.service.store.accept(
        seal(
            SignaturePurpose.OWNER_ROSTER,
            roster.model_copy(update={"version": 2, "devices": (*roster.devices, impostor)}),
            f.service.owner_key(),
        ),
        "朋友名单更新",
    )
    peer = a.policy.authenticate(f"Bearer {token(b, a)}", source_host=b.host)
    assert peer is not None and peer.authentication_kind is GatewayAuthenticationKind.OWNER_DEVICE
    assert (
        next(
            peer for peer in a.config.view().peers if peer.node_id == b.service.node_id
        ).relationship
        == "mine"
    )
