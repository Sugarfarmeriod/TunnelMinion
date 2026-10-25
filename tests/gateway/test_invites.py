"""邀请码的摘要存储、一次性接纳与运行中授权。"""

from __future__ import annotations

import asyncio
import hashlib
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from threading import Barrier
from typing import Protocol, cast

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from starlette.types import Receive, Scope, Send
from tests.gateway.test_configuration import MemorySecrets
from tests.tools.test_registry import definition

from tunnelminion.agent.invites import InMemoryInviteStore, InviteService, InviteStore
from tunnelminion.domain.identifiers import NodeId
from tunnelminion.domain.invites import (
    INVITE_LIFETIME,
    InvalidInviteCodeError,
    InviteAcceptance,
    InviteAccepted,
    InviteCode,
    InvitePermissions,
)
from tunnelminion.domain.tools import Platform
from tunnelminion.gateway.api import create_gateway_router
from tunnelminion.gateway.audit import InMemoryGatewaySecurityAuditSink
from tunnelminion.gateway.configuration import (
    DEFAULT_GATEWAY_TOOLS,
    FileGatewayConfigurationRepository,
    GatewayConfigurationService,
    gateway_token_name,
)
from tunnelminion.gateway.contracts import (
    GatewayCapabilities,
    GatewayErrorCode,
    GatewayErrorResponse,
)
from tunnelminion.gateway.security import GatewayBindConfig, GatewaySecurityPolicy
from tunnelminion.memory.sqlite import SQLiteStores
from tunnelminion.tools.audit import InMemoryAuditSink
from tunnelminion.tools.fakes import FakeToolAdapter
from tunnelminion.tools.registry import ToolRegistry
from tunnelminion.tools.runtime import ToolRuntime

NOW = datetime(2026, 10, 25, 10, tzinfo=UTC)
LOCAL = NodeId("node_" + "a" * 32)
JOINER = NodeId("node_" + "b" * 32)
ACCEPTANCE = InviteAcceptance(node_id=JOINER, platform=Platform.MACOS, host="10.77.0.2", port=9000)
PERMISSIONS = InvitePermissions(
    allow_delegation=True, allow_model_borrowing=True, daily_quota=12345
)
INVALID = GatewayErrorResponse.model_validate(
    {"error": {"code": "invite_invalid", "message": "邀请码无效、已过期或已被使用"}}
)


class InviteClient(Protocol):
    """TestClient 的严格类型边界。"""

    def get(self, url: str, *, headers: dict[str, str] | None = None) -> httpx.Response: ...

    def post(
        self,
        url: str,
        *,
        json: object = None,
        headers: dict[str, str] | None = None,
        content: bytes | None = None,
    ) -> httpx.Response: ...


@dataclass
class Clock:
    now: datetime = NOW
    tick: float = 100.0

    def wall(self) -> datetime:
        return self.now

    def monotonic(self) -> float:
        return self.tick


@dataclass
class InviteHarness:
    service: InviteService
    store: InviteStore
    configuration: GatewayConfigurationService
    secrets: MemorySecrets
    policy: GatewaySecurityPolicy
    audit: InMemoryGatewaySecurityAuditSink
    clock: Clock
    app: FastAPI
    client: InviteClient


@pytest.fixture(params=[False, True], ids=["memory", "sqlite"])
def harness(
    request: pytest.FixtureRequest, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> InviteHarness:
    store = (
        SQLiteStores.open(tmp_path / "runtime.sqlite3").invites
        if request.param
        else InMemoryInviteStore()
    )
    secrets = MemorySecrets()
    configuration = GatewayConfigurationService(
        FileGatewayConfigurationRepository(tmp_path / "gateway.json"), secrets
    )
    configuration.configure_local(GatewayBindConfig(host="10.77.0.1", port=8788))
    clock = Clock()
    monkeypatch.setattr("tunnelminion.gateway.api.monotonic", clock.monotonic)
    policy = configuration.build_security_policy()
    service = InviteService(LOCAL, Platform.WINDOWS, configuration, store, policy, clock=clock.wall)
    registry = ToolRegistry()
    registry.register(definition("get_node_summary"), FakeToolAdapter())
    runtime = ToolRuntime(registry, Platform.WINDOWS, InMemoryAuditSink())
    audit = InMemoryGatewaySecurityAuditSink()
    app = FastAPI()
    app.include_router(
        create_gateway_router(
            LOCAL, Platform.WINDOWS, registry, runtime, policy, audit, invite_service=service
        )
    )
    client = cast(InviteClient, TestClient(app, client=(ACCEPTANCE.host, 1234)))
    return InviteHarness(service, store, configuration, secrets, policy, audit, clock, app, client)


def test_create_round_trip_and_accept_updates_the_running_gateway(harness: InviteHarness) -> None:
    code = harness.service.create(PERMISSIONS)
    assert InviteCode.decode(f"  {code.encode()}\n") == code
    assert code.node_id == LOCAL and code.platform is Platform.WINDOWS
    assert (code.host, code.port) == ("10.77.0.1", 8788)
    assert code.token.startswith("tmn_") and code.expires_at == NOW + INVITE_LIFETIME
    with pytest.raises(InvalidInviteCodeError):
        InviteCode.decode(code.encode()[:-12])
    headers = {"Authorization": f"Bearer {code.token}"}
    assert harness.client.get("/v1/capabilities", headers=headers).status_code == 401
    response = harness.client.post(
        "/v1/invites:accept", json=ACCEPTANCE.model_dump(mode="json"), headers=headers
    )
    assert response.status_code == 200
    assert InviteAccepted.model_validate(response.json()) == InviteAccepted(
        inviter_node_id=LOCAL, permissions=PERMISSIONS
    )
    peer = harness.configuration.view().peers[0]
    assert (peer.node_id, peer.platform, peer.host, peer.port) == (
        JOINER,
        ACCEPTANCE.platform,
        ACCEPTANCE.host,
        ACCEPTANCE.port,
    )
    assert peer.allowed_tools == frozenset(DEFAULT_GATEWAY_TOOLS) and not peer.allowed_operations
    assert peer.allow_delegation and peer.allow_model_borrowing and peer.daily_quota == 12345
    assert harness.secrets.get(gateway_token_name(JOINER)) == code.token
    live = harness.policy.authenticate(headers["Authorization"])
    assert live is not None and live.allow_delegation and live.allow_model_borrowing
    assert live.daily_quota == peer.daily_quota and live.source_host == ACCEPTANCE.host
    capabilities = harness.client.get("/v1/capabilities", headers=headers)
    assert capabilities.status_code == 200
    assert [
        tool.name for tool in GatewayCapabilities.model_validate(capabilities.json()).tools
    ] == ["get_node_summary"]
    assert (
        harness.configuration.build_security_policy().authenticate(headers["Authorization"]) == live
    )
    used = harness.client.post(
        "/v1/invites:accept", json=ACCEPTANCE.model_dump(mode="json"), headers=headers
    )
    assert used.status_code == 401 and GatewayErrorResponse.model_validate(used.json()) == INVALID


@pytest.mark.parametrize(
    "failure",
    ["missing", "basic", "empty", "wrong", "expired", "host", "self", "body", "json", "extra"],
)
def test_accept_failures_have_the_same_response_and_safe_audit(
    harness: InviteHarness, failure: str
) -> None:
    code = harness.service.create(PERMISSIONS)
    headers = {"Authorization": f"Bearer {code.token}"}
    body = ACCEPTANCE.model_dump(mode="json")
    if failure == "missing":
        headers = {}
    elif failure == "basic":
        headers = {"Authorization": f"Basic {code.token}"}
    elif failure == "empty":
        headers = {"Authorization": "Bearer "}
    elif failure == "wrong":
        headers = {"Authorization": "Bearer tmn_" + "x" * 40}
    elif failure == "expired":
        harness.clock.now = code.expires_at
    elif failure == "host":
        body["host"] = "10.77.0.9"
    elif failure == "self":
        body["node_id"] = str(LOCAL)
    elif failure == "body":
        body["port"] = 1
    elif failure == "extra":
        body["permissions"] = PERMISSIONS.model_dump(mode="json")
    response = (
        harness.client.post("/v1/invites:accept", content=b"{", headers=headers)
        if failure == "json"
        else harness.client.post("/v1/invites:accept", json=body, headers=headers)
    )
    assert response.status_code == 401
    assert GatewayErrorResponse.model_validate(response.json()) == INVALID
    assert not harness.configuration.view().peers and not harness.secrets.values
    record = harness.audit.records[-1]
    assert record.action == "invite_accept" and record.error_code is GatewayErrorCode.INVITE_INVALID
    assert record.peer_node_id is None
    assert code.token not in response.text + repr(record)


@pytest.mark.parametrize("failure", ["host", "self", "public"])
def test_invalid_identity_or_address_does_not_consume_invite(
    harness: InviteHarness, failure: str
) -> None:
    code = harness.service.create(InvitePermissions())
    acceptance = ACCEPTANCE
    client_host = ACCEPTANCE.host
    if failure == "host":
        client_host = "10.77.0.9"
    elif failure == "self":
        acceptance = acceptance.model_copy(update={"node_id": LOCAL})
    else:
        acceptance = acceptance.model_copy(update={"host": "8.8.8.8"})
        client_host = acceptance.host
    with pytest.raises(ValueError):
        harness.service.accept(code.token, acceptance, client_host)
    accepted = harness.service.accept(code.token, ACCEPTANCE, ACCEPTANCE.host)
    assert accepted.permissions == InvitePermissions()


def test_accept_limit_is_global_and_recovers_at_the_minute_boundary(harness: InviteHarness) -> None:
    other = cast(InviteClient, TestClient(harness.app, client=("10.77.0.3", 1234)))
    body = ACCEPTANCE.model_dump(mode="json")
    for index in range(10):
        client = harness.client if index % 2 else other
        assert client.post("/v1/invites:accept", json=body).status_code == 401
    harness.clock.tick += 59.99
    limited = other.post("/v1/invites:accept", json=body)
    assert limited.status_code == 429
    assert (
        GatewayErrorResponse.model_validate(limited.json()).error.code
        is GatewayErrorCode.RATE_LIMITED
    )
    assert harness.audit.records[-1].action == "invite_accept"
    harness.clock.tick = 160.0
    code = harness.service.create(InvitePermissions())
    accepted = harness.client.post(
        "/v1/invites:accept", json=body, headers={"Authorization": f"Bearer {code.token}"}
    )
    assert accepted.status_code == 200


def test_no_client_address_is_rejected(harness: InviteHarness) -> None:
    code = harness.service.create(PERMISSIONS)

    async def without_client(scope: Scope, receive: Receive, send: Send) -> None:
        scope["client"] = None
        await harness.app(scope, receive, send)

    async def scenario() -> None:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=without_client), base_url="http://gateway"
        ) as client:
            response = await client.post(
                "/v1/invites:accept",
                json=ACCEPTANCE.model_dump(mode="json"),
                headers={"Authorization": f"Bearer {code.token}"},
            )
        assert response.status_code == 401
        assert GatewayErrorResponse.model_validate(response.json()) == INVALID

    asyncio.run(scenario())


def test_router_without_invite_service_rejects_with_the_same_error() -> None:
    registry = ToolRegistry()
    app = FastAPI()
    audit = InMemoryGatewaySecurityAuditSink()
    app.include_router(
        create_gateway_router(
            LOCAL,
            Platform.WINDOWS,
            registry,
            ToolRuntime(registry, Platform.WINDOWS, InMemoryAuditSink()),
            GatewaySecurityPolicy([]),
            audit,
        )
    )
    response = cast(InviteClient, TestClient(app)).post(
        "/v1/invites:accept",
        json=ACCEPTANCE.model_dump(mode="json"),
        headers={"Authorization": "Bearer tmn_" + "z" * 40},
    )
    assert (
        response.status_code == 401
        and GatewayErrorResponse.model_validate(response.json()) == INVALID
    )
    assert audit.records[-1].action == "invite_accept"


def test_failed_provision_does_not_authorize_the_running_gateway(
    harness: InviteHarness, monkeypatch: pytest.MonkeyPatch
) -> None:
    code = harness.service.create(PERMISSIONS)

    def unavailable(_value: object) -> None:
        raise RuntimeError(code.token)

    monkeypatch.setattr(harness.configuration, "provision_peer", unavailable)
    response = harness.client.post(
        "/v1/invites:accept",
        json=ACCEPTANCE.model_dump(mode="json"),
        headers={"Authorization": f"Bearer {code.token}"},
    )
    assert response.status_code == 401 and code.token not in response.text
    assert harness.policy.authenticate(f"Bearer {code.token}") is None


@pytest.mark.parametrize("sqlite", [False, True], ids=["memory", "sqlite"])
def test_invite_store_is_atomic_and_checks_expiry(tmp_path: Path, sqlite: bool) -> None:
    path = tmp_path / "runtime.sqlite3"
    first = SQLiteStores.open(path).invites if sqlite else InMemoryInviteStore()
    second = SQLiteStores.open(path).invites if sqlite else first
    digest = hashlib.sha256(b"tmn_test_atomic_invite_token_with_at_least_32_characters").digest()
    offset_now = NOW.astimezone(timezone(timedelta(hours=8)))
    first.create(digest, PERMISSIONS, offset_now, offset_now + INVITE_LIFETIME)
    barrier = Barrier(2)

    def accept(store: InviteStore) -> InvitePermissions | None:
        barrier.wait()
        return store.accept(digest, JOINER, NOW)

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = tuple(executor.map(accept, (first, second)))
    assert outcomes.count(PERMISSIONS) == 1 and outcomes.count(None) == 1
    assert first.accept(digest, LOCAL, NOW) is None
    assert first.accept(b"unknown", JOINER, NOW) is None
    expired = hashlib.sha256(b"expired").digest()
    first.create(expired, PERMISSIONS, NOW, NOW)
    assert first.accept(expired, JOINER, NOW) is None
    if sqlite:
        with closing(sqlite3.connect(path)) as connection:
            row = connection.execute(
                "SELECT accepted_at, accepted_node_id FROM gateway_invites WHERE token_digest=?",
                (digest,),
            ).fetchone()
        assert row == (NOW.isoformat(), str(JOINER))


def test_sqlite_persists_only_digest_before_and_after_acceptance(tmp_path: Path) -> None:
    path = tmp_path / "runtime.sqlite3"
    secrets = MemorySecrets()
    configuration = GatewayConfigurationService(
        FileGatewayConfigurationRepository(tmp_path / "gateway.json"), secrets
    )
    service = InviteService(LOCAL, Platform.WINDOWS, configuration, SQLiteStores.open(path).invites)
    with pytest.raises(RuntimeError, match="本机网关还没有配置"):
        service.create(PERMISSIONS)
    configuration.configure_local(GatewayBindConfig(host="10.77.0.1"))
    code = service.create(PERMISSIONS)
    for accepted in (False, True):
        if accepted:
            result = service.accept(code.token, ACCEPTANCE, ACCEPTANCE.host)
            assert result.permissions == PERMISSIONS
        with closing(sqlite3.connect(path)) as connection:
            row = connection.execute(
                "SELECT token_digest, permissions_json, accepted_node_id FROM gateway_invites"
            ).fetchone()
        assert row == (
            hashlib.sha256(code.token.encode()).digest(),
            PERMISSIONS.model_dump_json(),
            str(JOINER) if accepted else None,
        )
        for database_file in tmp_path.glob("runtime.sqlite3*"):
            assert code.token.encode() not in database_file.read_bytes()
        assert code.token not in (tmp_path / "gateway.json").read_text(encoding="utf-8")
