"""按请求签凭据和只同步重试一次的客户端边界。"""

from __future__ import annotations

import asyncio
from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI
from tests.trust.test_identity import MemorySecrets
from tests.trust.test_own_devices import computer

from tunnelminion.domain.errors import ErrorCode
from tunnelminion.domain.identifiers import NodeId
from tunnelminion.domain.trust import PassScope, SignaturePurpose
from tunnelminion.gateway.client import FixedGatewayClient, RemoteGatewayError
from tunnelminion.gateway.configuration import GatewayPeerConfig, GatewayPeerInput
from tunnelminion.gateway.credentials import (
    GatewayCredentialError,
    GatewayCredentials,
    GatewayRequestAuth,
)
from tunnelminion.memory.sqlite import SQLiteStores
from tunnelminion.tools.audit import InMemoryAuditSink
from tunnelminion.trust.contracts import (
    DevicePermissions,
    IdentityError,
    OwnerJoinResponse,
    TrustSyncMessage,
)
from tunnelminion.trust.devices import OwnDevicesService
from tunnelminion.trust.keys import PrivateKey
from tunnelminion.trust.signatures import VerificationError


@pytest.mark.parametrize(
    "mode", ["ok", "malformed", "large", "other", "sync", "twice", "sync_fail"]
)
def test_per_request_auth_scope_and_single_retry(mode: str) -> None:
    issued: list[PassScope] = []
    synced: list[bool] = []
    headers: list[str] = []

    def provide(scope: PassScope) -> str:
        issued.append(scope)
        return f"fresh-{len(issued)}"

    async def synchronize() -> None:
        synced.append(True)
        if mode == "sync_fail":
            raise IdentityError("名单同步失败")

    def handler(request: httpx.Request) -> httpx.Response:
        headers.append(request.headers["Authorization"])
        if mode == "ok" or (mode == "sync" and len(headers) > 1):
            return httpx.Response(200)
        if mode in ("malformed", "large"):
            return httpx.Response(401, content="x" * 512_001 if mode == "large" else "invalid")
        return httpx.Response(
            401,
            json={
                "error": {
                    "code": "unauthenticated" if mode == "other" else "trust_sync_required",
                    "message": "需要同步名单",
                }
            },
        )

    async def scenario() -> None:
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(handler),
            auth=GatewayRequestAuth(GatewayCredentials(provide, synchronize)),
            base_url="http://127.0.0.1",
        ) as client:
            # 同步失败时保留第一次的 401，不把内部异常抛给调用方。
            response = await client.get("/v1/operations/example")
            assert response.status_code == (200 if mode in ("ok", "sync") else 401)

    asyncio.run(scenario())
    assert synced == ([True] if mode in ("sync", "twice", "sync_fail") else [])
    count = 2 if mode in ("sync", "twice") else 1
    assert issued == [PassScope.OPERATION_GATEWAY] * count
    assert headers == [f"Bearer fresh-{index + 1}" for index in range(count)]


def test_device_service_handles_uninitialized_missing_local_and_invalid_restriction(
    tmp_path: Path,
) -> None:
    store = SQLiteStores.open(tmp_path / "empty.sqlite3").trust
    local = OwnDevicesService(NodeId.new(), store, MemorySecrets())
    with pytest.raises(IdentityError, match="尚未初始化"):
        local.roster()
    a = computer(tmp_path / "a", 1, {})
    wrong_node = OwnDevicesService(NodeId.new(), a.service.store, a.secrets)
    with pytest.raises(IdentityError, match="已被移出"):
        wrong_node.invite()
    for node_id in (a.service.node_id, NodeId.new()):
        with pytest.raises(IdentityError, match="其他电脑"):
            a.service.restrict(node_id, DevicePermissions())
    entry = a.service.roster().device(a.service.node_id)
    assert entry is not None
    assert wrong_node.credentials(entry).source_host is None
    assert a.service.credentials(entry).source_host == a.host
    assert a.service.receive(TrustSyncMessage(), "空消息").roster is not None


def test_join_install_fails_before_persisting_keys(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    apps: dict[str, FastAPI] = {}
    a = computer(tmp_path / "a", 1, apps)
    b = computer(tmp_path / "b", 2, apps, a)
    fresh = OwnDevicesService(
        NodeId.new(), SQLiteStores.open(tmp_path / "fresh.sqlite3").trust, MemorySecrets()
    )
    message = b.service.message()
    assert message.roster is not None and message.trust_list is not None
    certificate = b.service.store.load(SignaturePurpose.DEVICE_CERTIFICATE)
    assert certificate is not None
    response = OwnerJoinResponse(
        certificate=certificate, roster=message.roster, trust_list=message.trust_list
    )
    with pytest.raises(VerificationError):
        fresh.install_join(a.service.invite(), response, PrivateKey.generate())

    def fail(*args: object, **kwargs: object) -> None:
        raise IdentityError("未写入密钥")

    monkeypatch.setattr(fresh.store, "initialize", fail)
    fresh.node_id = b.service.node_id
    with pytest.raises(IdentityError, match="未写入密钥"):
        fresh.install_join(a.service.invite(), response, b.key)


def test_requests_and_sync_bind_the_local_roster_address(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    apps: dict[str, FastAPI] = {}
    a = computer(tmp_path / "a", 1, apps)
    b = computer(tmp_path / "b", 2, apps, a)
    mesh = b.mesh
    addresses: list[object] = []

    def transport(*args: object, **kwargs: object) -> httpx.AsyncBaseTransport:
        addresses.append(kwargs.get("local_address"))
        return mesh

    monkeypatch.setattr(httpx, "AsyncHTTPTransport", transport)
    endpoint, credentials = b.config.resolve_service_peer(a.service.node_id)
    client = FixedGatewayClient(
        endpoint, credentials, b.service.node_id, a.service.node_id, InMemoryAuditSink()
    )
    target = a.service.roster().device(a.service.node_id)
    assert target is not None
    b.service.transport = None
    unknown_local = OwnDevicesService(NodeId.new(), b.service.store, b.secrets)

    async def scenario() -> None:
        assert (await client.discover()).node_id == a.service.node_id
        await b.service.sync(target)
        await unknown_local.sync(target)

    asyncio.run(scenario())
    assert addresses == [b.host, b.host, None]


def test_removed_computer_can_sync_later_versions_without_recreating_certificate(
    tmp_path: Path,
) -> None:
    apps: dict[str, FastAPI] = {}
    a = computer(tmp_path / "a", 1, apps)
    b = computer(tmp_path / "b", 2, apps, a)
    c = computer(tmp_path / "c", 3, apps, a)
    a.service.remove(c.service.node_id)
    c.service.receive(a.service.message(), str(a.service.node_id))
    assert not c.service.active()
    a.service.remove(b.service.node_id)
    c.service.receive(a.service.message(), str(a.service.node_id))
    assert c.service.roster().version == a.service.roster().version
    assert not c.service.active()
    a.config.provision_peer(
        GatewayPeerInput(
            peer=GatewayPeerConfig(
                node_id=a.service.node_id,
                host=a.host,
                allowed_tools=frozenset({"get_node_summary"}),
            ),
            token="tmn_" + "x" * 40,
        )
    )
    assert a.config.resolve_service_peer(a.service.node_id)[1] == "tmn_" + "x" * 40


@pytest.mark.parametrize("fail_on", [1, 2])
def test_pass_signing_failure_becomes_request_error(fail_on: int) -> None:
    issued: list[int] = []

    def provide(_scope: PassScope) -> str:
        issued.append(1)
        if len(issued) == fail_on:
            raise IdentityError("本机已被移出我的电脑，不能使用通行证")
        return "fresh"

    async def synchronize() -> None:
        return None

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            401, json={"error": {"code": "trust_sync_required", "message": "需要同步名单"}}
        )

    async def scenario() -> None:
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(handler),
            auth=GatewayRequestAuth(GatewayCredentials(provide, synchronize)),
            base_url="http://127.0.0.1",
        ) as client:
            with pytest.raises(GatewayCredentialError) as caught:
                await client.get("/v1/services")
            assert isinstance(caught.value, httpx.RequestError)
            assert "移出" not in str(caught.value)

    asyncio.run(scenario())


@pytest.mark.parametrize("failure", ["sign", "sync"])
def test_client_reports_credential_failures_as_gateway_errors(failure: str) -> None:
    def provide(_scope: PassScope) -> str:
        if failure == "sign":
            raise IdentityError("本机已被移出我的电脑，不能使用通行证")
        return "fresh"

    async def synchronize() -> None:
        raise IdentityError("名单同步失败")

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            401, json={"error": {"code": "trust_sync_required", "message": "需要同步名单"}}
        )

    client = FixedGatewayClient(
        "http://10.0.0.1:8787",
        GatewayCredentials(provide, synchronize),
        NodeId.new(),
        NodeId.new(),
        InMemoryAuditSink(),
        transport=httpx.MockTransport(handler),
    )

    async def scenario() -> None:
        with pytest.raises(RemoteGatewayError) as caught:
            await client.get_services()
        expected = ErrorCode.NODE_UNREACHABLE if failure == "sign" else ErrorCode.UNAUTHENTICATED
        assert caught.value.code is expected

    asyncio.run(scenario())
