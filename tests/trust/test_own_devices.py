"""我的电脑从报到到撤销的内存网关验收和认证边界。"""

from __future__ import annotations

import asyncio
import hashlib
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast
from uuid import uuid4

import httpx
import jwt
import pytest
from fastapi import FastAPI
from pydantic import JsonValue
from tests.tools.test_registry import definition
from tests.trust.test_identity import MemorySecrets

from tunnelminion.domain.identifiers import NodeId
from tunnelminion.domain.tools import Platform
from tunnelminion.domain.trust import (
    REQUEST_PASS_TYPE,
    DeviceCertificate,
    JoinCode,
    JoinProof,
    PassScope,
    RequestPassClaims,
    SignaturePurpose,
)
from tunnelminion.gateway.api import create_gateway_router
from tunnelminion.gateway.audit import InMemoryGatewaySecurityAuditSink
from tunnelminion.gateway.client import FixedGatewayClient
from tunnelminion.gateway.configuration import (
    DEFAULT_GATEWAY_TOOLS,
    FileGatewayConfigurationRepository,
    GatewayConfigurationService,
    GatewayPeerConfig,
    GatewayPeerInput,
)
from tunnelminion.gateway.contracts import GatewayErrorCode, GatewayErrorResponse
from tunnelminion.gateway.credentials import GatewayCredentials
from tunnelminion.gateway.security import (
    GatewayAuthenticationKind,
    GatewayBindConfig,
    GatewaySecurityPolicy,
)
from tunnelminion.memory.sqlite import SQLiteStores
from tunnelminion.model.secrets import SecretStoreError
from tunnelminion.tools.audit import InMemoryAuditSink
from tunnelminion.tools.fakes import FakeToolAdapter
from tunnelminion.tools.registry import ToolRegistry
from tunnelminion.tools.runtime import ToolRuntime
from tunnelminion.trust.contracts import (
    AlreadyInitializedError,
    DevicePermissions,
    IdentityError,
    OwnerJoinRequest,
)
from tunnelminion.trust.devices import INVALID_INVITE, OwnDevicesService
from tunnelminion.trust.keys import OWNER_KEY_NAME, InitializationKeys, PrivateKey
from tunnelminion.trust.passes import TrustSyncRequired, issue_pass
from tunnelminion.trust.service import OwnerIdentityService
from tunnelminion.trust.signatures import VerificationError, seal

NOW = datetime(2026, 10, 28, tzinfo=UTC)


class Mesh(httpx.AsyncBaseTransport):
    """所有地址只在内存里分发，不建立网络连接。"""

    def __init__(self, source: str, apps: dict[str, FastAPI]) -> None:
        self.source = source
        self.apps = apps
        self.offline: set[str] = set()
        self.paths: list[str] = []

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.paths.append(request.url.path)
        if request.url.host in self.offline or request.url.host not in self.apps:
            raise httpx.ConnectError("内存中的电脑离线", request=request)
        return await httpx.ASGITransport(
            self.apps[request.url.host], client=(self.source, 1234)
        ).handle_async_request(request)


@dataclass
class Computer:
    root: Path
    service: OwnDevicesService
    secrets: MemorySecrets
    key: PrivateKey
    host: str
    mesh: Mesh
    config: GatewayConfigurationService
    policy: GatewaySecurityPolicy

    def client(self, target: Computer) -> FixedGatewayClient:
        endpoint, credential = self.config.resolve_service_peer(target.service.node_id)
        return FixedGatewayClient(
            endpoint,
            credential,
            self.service.node_id,
            target.service.node_id,
            InMemoryAuditSink(),
            transport=self.mesh,
        )


def request_for(code: JoinCode, node_id: NodeId, key: PrivateKey, host: str) -> OwnerJoinRequest:
    return OwnerJoinRequest(
        node_id=node_id,
        platform=Platform.WINDOWS,
        display_name="测试电脑",
        host=host,
        port=8787,
        device_public_key=key.public_key,
        proof=seal(
            SignaturePurpose.JOIN_PROOF,
            JoinProof(
                token_digest=hashlib.sha256(code.token.encode()).hexdigest(),
                inviter_node_id=code.inviter_node_id,
                node_id=node_id,
                device_public_key=key.public_key,
                host=host,
                port=8787,
                issued_at=NOW,
            ),
            key,
        ),
    )


def computer(
    root: Path,
    index: int,
    apps: dict[str, FastAPI],
    master: Computer | None = None,
    *,
    uninitialized: bool = False,
) -> Computer:
    root.mkdir(parents=True)
    node_id = NodeId("node_" + str(index) * 32)
    host = f"10.20.0.{index}"
    (root / "node-id").write_text(str(node_id), encoding="utf-8")
    secrets = MemorySecrets()
    store = SQLiteStores.open(root / "runtime.sqlite3").trust
    mesh = Mesh(host, apps)
    service = OwnDevicesService(node_id, store, secrets, transport=mesh, clock=lambda: NOW)
    if uninitialized:
        key = PrivateKey.generate()
    elif master is None:
        keys = InitializationKeys.generate()
        key = keys.device
        OwnerIdentityService(store, secrets).init(
            node_id, GatewayBindConfig(host=host), "主电脑", keys, Platform.WINDOWS
        )
    else:
        key = PrivateKey.generate()
        code = master.service.invite()
        response = master.service.accept_join(
            code.token, request_for(code, node_id, key, host), host
        )
        service.install_join(code, response, key)
    config = GatewayConfigurationService(
        FileGatewayConfigurationRepository(root / "gateway.json"), secrets, owner_devices=service
    )
    config.configure_local(GatewayBindConfig(host=host))
    policy = config.build_security_policy()
    registry = ToolRegistry()
    registry.register(definition("get_node_summary"), FakeToolAdapter())
    app = FastAPI()
    app.include_router(
        create_gateway_router(
            node_id,
            Platform.WINDOWS,
            registry,
            ToolRuntime(registry, Platform.WINDOWS, InMemoryAuditSink()),
            policy,
            InMemoryGatewaySecurityAuditSink(),
            owner_devices=service,
        )
    )
    apps[host] = app
    return Computer(root, service, secrets, key, host, mesh, config, policy)


def test_three_gateways_join_without_pairing_sync_retry_and_revoke(tmp_path: Path) -> None:
    apps: dict[str, FastAPI] = {}
    a = computer(tmp_path / "a", 1, apps)
    b = computer(tmp_path / "b", 2, apps, a)

    async def scenario() -> None:
        # C 只向 A 报到；B 此刻仍只有版本 2 的名单。
        c = computer(tmp_path / "c", 3, apps, uninitialized=True)
        code = a.service.invite()
        request = request_for(code, c.service.node_id, c.key, c.host)
        a.mesh.offline.add(b.host)
        async with httpx.AsyncClient(transport=c.mesh, base_url=f"http://{a.host}") as client:
            response = await client.post(
                "/v1/owner:join",
                content=request.model_dump_json(),
                headers={"Authorization": f"Bearer {code.token}"},
            )
        from tunnelminion.trust.contracts import OwnerJoinResponse

        assert response.status_code == 200
        c.service.install_join(code, OwnerJoinResponse.model_validate_json(response.content), c.key)
        assert b.service.roster().device(c.service.node_id) is None
        assert OWNER_KEY_NAME not in b.secrets.values and OWNER_KEY_NAME not in c.secrets.values
        assert (await c.client(b).discover()).node_id == b.service.node_id
        assert c.mesh.paths[-3:] == ["/v1/capabilities", "/v1/trust:sync", "/v1/capabilities"]
        assert b.service.roster().device(c.service.node_id) is not None
        assert len(b.config.view().peers) == 2
        # B 离线错过移除；以后和 A 接触时双向同步，C 的旧凭据随即失效。
        targets = a.service.remove(c.service.node_id)
        assert await a.service.push(targets) == (b.service.node_id,)
        assert not c.service.active()
        assert OwnerIdentityService(c.service.store, c.secrets).status().removed
        with pytest.raises(IdentityError, match="已被移出"):
            issue_pass(c.service, b.service.node_id, PassScope.TOOL_GATEWAY)
        a.mesh.offline.clear()
        assert (await b.client(a).discover()).node_id == a.service.node_id
        assert b.service.roster().device(c.service.node_id) is None
        claims = RequestPassClaims(
            iss=c.service.node_id,
            aud=b.service.node_id,
            scope=PassScope.TOOL_GATEWAY,
            iat=int(NOW.timestamp()),
            exp=int(NOW.timestamp()) + 60,
            jti=uuid4().hex,
            owner_fingerprint=c.service.roster().owner_fingerprint,
            roster_version=3,
        )
        async with httpx.AsyncClient(transport=c.mesh, base_url=f"http://{b.host}") as client:
            refused = await client.get(
                "/v1/capabilities",
                headers={"Authorization": f"Bearer {c.key.request_pass(claims)}"},
            )
        assert refused.status_code == 401
        assert (
            GatewayErrorResponse.model_validate_json(refused.content).error.code
            is GatewayErrorCode.TRUST_SYNC_REQUIRED
        )
        assert "移除电脑" in SQLiteStores.open(a.root / "runtime.sqlite3").trust.audits()[-1].reason

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "fault",
    ["expired", "source", "digest", "signature", "node", "inviter", "public_key", "duplicate"],
)
def test_join_rejects_invalid_proofs_without_leaking_secrets(tmp_path: Path, fault: str) -> None:
    a = computer(tmp_path / "a", 1, {})
    key = PrivateKey.generate()
    code = a.service.invite()
    node_id = NodeId.new()
    request = request_for(code, node_id, key, "10.20.0.2")
    proof = JoinProof.model_validate(request.proof.payload)
    if fault == "expired":
        a.service.clock = lambda: NOW + timedelta(days=2)
    elif fault == "digest":
        request = request.model_copy(
            update={
                "proof": seal(
                    SignaturePurpose.JOIN_PROOF,
                    proof.model_copy(update={"token_digest": "0" * 64}),
                    key,
                )
            }
        )
    elif fault == "signature":
        request = request.model_copy(
            update={"proof": seal(SignaturePurpose.JOIN_PROOF, proof, PrivateKey.generate())}
        )
    elif fault in ("node", "inviter"):
        field = "node_id" if fault == "node" else "inviter_node_id"
        request = request.model_copy(
            update={
                "proof": seal(
                    SignaturePurpose.JOIN_PROOF, proof.model_copy(update={field: NodeId.new()}), key
                )
            }
        )
    elif fault == "public_key":
        request = request.model_copy(
            update={
                "proof": seal(
                    SignaturePurpose.JOIN_PROOF,
                    proof.model_copy(
                        update={"device_public_key": PrivateKey.generate().public_key}
                    ),
                    key,
                )
            }
        )
    elif fault == "duplicate":
        a.service.accept_join(code.token, request, request.host)
    with pytest.raises(IdentityError, match=INVALID_INVITE) as caught:
        a.service.accept_join(
            code.token, request, "10.20.0.99" if fault == "source" else request.host
        )
    assert code.token not in str(caught.value) and key.seed_text() not in str(caught.value)
    data = (a.root / "runtime.sqlite3").read_bytes()
    assert code.token.encode() not in data and key.seed_text().encode() not in data


def test_invite_atomic_consumption_and_owner_key_requirement(tmp_path: Path) -> None:
    apps: dict[str, FastAPI] = {}
    a = computer(tmp_path / "a", 1, apps)
    code = a.service.invite()
    digest = hashlib.sha256(code.token.encode()).digest()

    def consume(_index: int) -> bool:
        return a.service.store.consume_invite(digest, NodeId.new(), NOW)

    with ThreadPoolExecutor(max_workers=4) as pool:
        consumed = tuple(pool.map(consume, range(4)))
    assert consumed.count(True) == 1
    b = computer(tmp_path / "b", 2, apps, a)
    with pytest.raises(IdentityError, match="持有机主密钥"):
        b.service.invite()
    with pytest.raises(IdentityError, match="不能移除本机"):
        a.service.remove(a.service.node_id)
    with pytest.raises(IdentityError, match="没有这个节点"):
        a.service.remove(NodeId.new())
    for permission in (
        DevicePermissions(allow_delegation=False),
        DevicePermissions(allow_delegation=False, daily_quota=100),
    ):
        a.service.restrict(b.service.node_id, permission)
        with pytest.raises(IdentityError, match="只能关闭或调小"):
            a.service.restrict(b.service.node_id, DevicePermissions())


def signed_claims(
    b: Computer,
    a: Computer,
    changes: dict[str, JsonValue] | None = None,
    typ: str = REQUEST_PASS_TYPE,
    key: PrivateKey | None = None,
) -> str:
    claims = cast(
        dict[str, JsonValue],
        jwt.decode(
            issue_pass(b.service, a.service.node_id, PassScope.TOOL_GATEWAY),
            options={"verify_signature": False},
        ),
    )
    claims.update(changes or {})
    # 测试需要构造格式错误的声明，因此用测试内存里的私钥种子。
    import base64

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    private = Ed25519PrivateKey.from_private_bytes(
        base64.urlsafe_b64decode((key or b.key).seed_text() + "=")
    )
    return jwt.encode(claims, private, algorithm="EdDSA", headers={"typ": typ})


@pytest.mark.parametrize(
    "fault",
    [
        "expired",
        "future",
        "audience",
        "scope",
        "typ",
        "signature",
        "source",
        "purpose",
        "lifetime",
        "issuer",
        "owner_claim",
    ],
)
def test_request_pass_trusts_only_local_roster(tmp_path: Path, fault: str) -> None:
    apps: dict[str, FastAPI] = {}
    a = computer(tmp_path / "a", 1, apps)
    b = computer(tmp_path / "b", 2, apps, a)
    changes: dict[str, JsonValue] = {}
    if fault == "expired":
        changes.update(iat=int(NOW.timestamp()) - 200, exp=int(NOW.timestamp()) - 140)
    elif fault == "future":
        changes.update(iat=int(NOW.timestamp()) + 140, exp=int(NOW.timestamp()) + 200)
    elif fault == "audience":
        changes["aud"] = str(NodeId.new())
    elif fault == "scope":
        changes["scope"] = "operation-gateway"
    elif fault == "purpose":
        changes["purpose"] = "tm-roster"
    elif fault == "lifetime":
        changes["exp"] = int(NOW.timestamp()) + 61
    elif fault == "issuer":
        changes["iss"] = str(NodeId.new())
    elif fault == "owner_claim":
        changes.update(owner_fingerprint="sha256:" + "f" * 64, is_owner=True)
    token = signed_claims(
        b,
        a,
        changes,
        typ="JWT" if fault == "typ" else REQUEST_PASS_TYPE,
        key=PrivateKey.generate() if fault == "signature" else None,
    )
    a.service.receive(b.service.message(), "测试同步")
    if fault == "issuer":
        with pytest.raises(TrustSyncRequired):
            a.policy.authenticate(f"Bearer {token}", source_host=b.host)
    else:
        peer = a.policy.authenticate(
            f"Bearer {token}", source_host="10.20.0.99" if fault == "source" else b.host
        )
        assert (peer is not None) == (fault == "owner_claim")
        if peer is not None:
            assert peer.authentication_kind is GatewayAuthenticationKind.OWNER_DEVICE
            assert (
                peer.allow_proxy_repair_approval
                and peer.allow_delegation
                and peer.allow_model_borrowing
            )
            assert a.policy.authenticate(f"Bearer {token}", source_host=b.host) is None


def test_permissions_are_live_and_static_pairing_remains_available(tmp_path: Path) -> None:
    apps: dict[str, FastAPI] = {}
    a = computer(tmp_path / "a", 1, apps)
    b = computer(tmp_path / "b", 2, apps, a)
    a.config.provision_peer(
        GatewayPeerInput(
            peer=GatewayPeerConfig(
                node_id=b.service.node_id,
                host=b.host,
                display_name="旧名字",
                platform=Platform.WINDOWS,
                allowed_tools=frozenset(DEFAULT_GATEWAY_TOOLS),
                allowed_operations=frozenset({"share_local_http_service"}),
            ),
            token="tmn_" + "a" * 40,
        )
    )
    policy = a.config.build_security_policy()
    assert len(a.config.view().peers) == 1
    assert a.config.view().peers[0].display_name == "测试电脑"
    assert isinstance(a.config.resolve_service_peer(b.service.node_id)[1], GatewayCredentials)
    assert isinstance(a.config.resolve_model_peer(b.service.node_id).token, GatewayCredentials)
    assert isinstance(a.config.resolve_delegation_peer(b.service.node_id).token, GatewayCredentials)
    assert isinstance(
        a.config.resolve_tool_peer(b.service.node_id, ("get_node_summary",)).token,
        GatewayCredentials,
    )
    assert isinstance(
        a.config.resolve_operation_peer(b.service.node_id, "share_local_http_service").token,
        GatewayCredentials,
    )
    assert policy.authenticate("Bearer tmn_" + "a" * 40) is not None
    a.service.restrict(
        b.service.node_id,
        DevicePermissions(
            allow_proxy_repair_approval=False,
            allow_delegation=False,
            allow_model_borrowing=False,
            daily_quota=100,
        ),
    )
    token = issue_pass(b.service, a.service.node_id, PassScope.TOOL_GATEWAY)
    peer = policy.authenticate(f"Bearer {token}", source_host=b.host)
    assert peer is not None and not peer.allow_proxy_repair_approval and peer.daily_quota == 100


def test_join_response_checks_owner_local_key_and_cleans_failed_keys(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    a = computer(tmp_path / "a", 1, {})
    store = SQLiteStores.open(tmp_path / "new.sqlite3").trust
    secrets = MemorySecrets()
    local = OwnDevicesService(NodeId.new(), store, secrets)
    key = PrivateKey.generate()
    code = a.service.invite()
    accepted = a.service.accept_join(
        code.token, request_for(code, local.node_id, key, "10.20.0.2"), "10.20.0.2"
    )
    with pytest.raises(VerificationError):
        local.install_join(
            code.model_copy(update={"owner_fingerprint": "sha256:" + "f" * 64}), accepted, key
        )
    with pytest.raises(VerificationError, match="本机身份不符"):
        local.install_join(code, accepted, PrivateKey.generate())
    with pytest.raises(VerificationError, match="本机身份不符"):
        local.install_join(
            code,
            accepted.model_copy(
                update={
                    "certificate": seal(
                        SignaturePurpose.DEVICE_CERTIFICATE,
                        DeviceCertificate(
                            owner_fingerprint=code.owner_fingerprint,
                            node_id=NodeId.new(),
                            device_public_key=key.public_key,
                            issued_at=NOW,
                        ),
                        a.service.owner_key(),
                    )
                }
            ),
            key,
        )

    def fail(name: str, value: str) -> None:
        secrets.values[name] = value
        raise RuntimeError(value)

    monkeypatch.setattr(secrets, "set", fail)
    with pytest.raises(SecretStoreError):
        local.install_join(code, accepted, key)
    assert secrets.values == {} and store.owner_fingerprint() is None
    monkeypatch.undo()
    local.install_join(code, accepted, key)
    with pytest.raises(AlreadyInitializedError):
        local.install_join(code, accepted, key)
