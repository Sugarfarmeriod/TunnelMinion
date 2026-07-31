"""受管网络配置同步、验签、full sync、退避与恢复测试。"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import sqlite3
from collections.abc import Coroutine
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, TypeVar

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError
from tests.network.factories import NETWORK_ID, NODE_A, NODE_B, desired, peer

from tunnelminion.agent.coordinator import CoordinatorClientConfig, CoordinatorClientError
from tunnelminion.agent.network_sync import (
    CredentialedNetworkAcknowledgementSink,
    HttpManagedNetworkSyncTransport,
    ManagedNetworkSyncCheckpoint,
    ManagedNetworkSyncConfig,
    ManagedNetworkSyncError,
    ManagedNetworkSynchronizer,
    ManagedNetworkSyncPhase,
    SQLiteManagedNetworkSyncStore,
)
from tunnelminion.coordinator.client_credentials import (
    AgentRefreshCredentialStore,
    coordinator_refresh_name,
)
from tunnelminion.coordinator.contracts import (
    RefreshAuthentication,
    VerificationKeySet,
    VerificationKeyView,
)
from tunnelminion.network.contracts import (
    AcknowledgementStage,
    NetworkAcknowledgement,
    SignedDesiredConfig,
)
from tunnelminion.network.governance import NetworkPathStatus
from tunnelminion.network.signing import desired_config_payload
from tunnelminion.tools.contracts import ToolCancellationToken

T = TypeVar("T")
NOW = datetime(2026, 7, 26, 12, 0, tzinfo=UTC)


def run(coroutine: Coroutine[Any, Any, T]) -> T:
    return asyncio.run(coroutine)


def http_config() -> CoordinatorClientConfig:
    return CoordinatorClientConfig(
        endpoint="http://10.77.0.1:8790",
        network_id=NETWORK_ID,
        node_id=NODE_A,
        pinned_fingerprints=frozenset({"a" * 64}),
        request_timeout_seconds=1,
    )


class MemorySecrets:
    """进程内测试秘密后端。"""

    def __init__(self) -> None:
        self.values: dict[str, str] = {}

    def get(self, name: str) -> str | None:
        return self.values.get(name)

    def set(self, name: str, value: str) -> None:
        self.values[name] = value

    def delete(self, name: str) -> None:
        self.values.pop(name, None)


class FakeNetworkSyncTransport:
    """可注入响应、阻塞和错误的 Coordinator transport。"""

    def __init__(
        self,
        key: VerificationKeyView,
        incremental: tuple[SignedDesiredConfig, ...] = (),
        full: tuple[SignedDesiredConfig, ...] = (),
    ) -> None:
        self.key = key
        self.incremental = incremental
        self.full = full
        self.acknowledgements: list[NetworkAcknowledgement] = []
        self.path_statuses: list[dict[str, object]] = []
        self.pull_calls: list[tuple[int, bool]] = []
        self.error: CoordinatorClientError | ManagedNetworkSyncError | None = None
        self.block: asyncio.Event | None = None
        self.delay = 0.0

    async def verification_keys(self) -> tuple[VerificationKeyView, ...]:
        return (self.key,)

    async def pull_desired_configs(
        self,
        authentication: RefreshAuthentication,
        *,
        after_revision: int,
        full_sync: bool,
    ) -> tuple[SignedDesiredConfig, ...]:
        assert authentication.network_id == NETWORK_ID
        assert authentication.node_id == NODE_A
        self.pull_calls.append((after_revision, full_sync))
        if self.block is not None:
            await self.block.wait()
        if self.delay:
            await asyncio.sleep(self.delay)
        if self.error is not None:
            raise self.error
        return self.full if full_sync else self.incremental

    async def acknowledge(
        self,
        authentication: RefreshAuthentication,
        acknowledgement: NetworkAcknowledgement,
    ) -> None:
        assert authentication.node_id == NODE_A
        self.acknowledgements.append(acknowledgement)

    async def report_path_status(
        self,
        authentication: RefreshAuthentication,
        payload: dict[str, object],
    ) -> None:
        assert authentication.node_id == NODE_A
        self.path_statuses.append(payload)


def signed(
    *,
    revision: int = 1,
    parent_revision: int = 0,
    target_node_id: object = NODE_A,
) -> tuple[SignedDesiredConfig, VerificationKeyView]:
    private = Ed25519PrivateKey.generate()
    public_raw = private.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    public_key = base64.urlsafe_b64encode(public_raw).rstrip(b"=").decode()
    fingerprint = hashlib.sha256(public_raw).hexdigest()
    config_updates: dict[str, object] = {
        "revision": revision,
        "parent_revision": parent_revision,
        "target_node_id": target_node_id,
    }
    if target_node_id == NODE_B:
        config_updates["peers"] = (peer(node_id=NODE_A),)
    config = desired(**config_updates)
    expires_at = NOW + timedelta(minutes=10)
    signature = private.sign(desired_config_payload(config, NOW, expires_at))
    envelope = SignedDesiredConfig(
        config=config,
        key_id="sync-test-key",
        key_fingerprint=f"sha256:{fingerprint}",
        issued_at=NOW,
        expires_at=expires_at,
        signature=base64.urlsafe_b64encode(signature).rstrip(b"=").decode(),
    )
    key = VerificationKeyView(
        key_id="sync-test-key",
        public_key=public_key,
        fingerprint=fingerprint,
        activates_at=NOW,
    )
    return envelope, key


def build(
    tmp_path: Path,
    transport: FakeNetworkSyncTransport,
    *,
    credential: bool = True,
    timeout: float = 1,
    sync_interval: float = 30,
    max_configs: int = 32,
    max_config_bytes: int = 262_144,
) -> tuple[ManagedNetworkSynchronizer, SQLiteManagedNetworkSyncStore, MemorySecrets]:
    secrets = MemorySecrets()
    if credential:
        secrets.set(coordinator_refresh_name(NETWORK_ID, NODE_A), "r" * 43)
    credentials = AgentRefreshCredentialStore(secrets)
    store = SQLiteManagedNetworkSyncStore(tmp_path / "network-sync.sqlite3")
    config = ManagedNetworkSyncConfig(
        network_id=NETWORK_ID,
        node_id=NODE_A,
        pinned_fingerprints=frozenset({f"sha256:{transport.key.fingerprint}"}),
        request_timeout_seconds=timeout,
        sync_interval_seconds=sync_interval,
        base_backoff_seconds=1,
        max_backoff_seconds=4,
        max_configs=max_configs,
        max_config_bytes=max_config_bytes,
    )
    return (
        ManagedNetworkSynchronizer(
            config,
            transport,
            credentials,
            store,
            clock=lambda: NOW,
            jitter=lambda: 1,
        ),
        store,
        secrets,
    )


def test_sync_saves_pending_acknowledges_and_commits_last_known_good(
    tmp_path: Path,
) -> None:
    envelope, key = signed()
    transport = FakeNetworkSyncTransport(key, (envelope,))
    synchronizer, store, _ = build(tmp_path, transport)

    status = run(synchronizer.sync_once())
    assert status.phase is ManagedNetworkSyncPhase.PENDING
    assert status.pending_revision == 1
    assert transport.acknowledgements[0].stage.value == "pending"
    assert store.load(NETWORK_ID, NODE_A, now=NOW).pending_config == envelope

    checkpoint = synchronizer.mark_verified(envelope)
    assert checkpoint.applied_revision == 1
    assert checkpoint.last_known_good == envelope
    assert checkpoint.pending_config is None
    assert synchronizer.status.phase is ManagedNetworkSyncPhase.IDLE
    store.assert_no_secret_material()

    reopened, _, _ = build(tmp_path, transport)
    assert reopened.checkpoint.last_known_good == envelope
    assert reopened.checkpoint.applied_revision == 1
    with pytest.raises(ManagedNetworkSyncError, match="pending"):
        reopened.mark_verified(envelope)


def test_out_of_order_incremental_uses_bounded_full_sync(tmp_path: Path) -> None:
    skipped, _ = signed(revision=3, parent_revision=2)
    recovered, key = signed(revision=1, parent_revision=0)
    transport = FakeNetworkSyncTransport(key, (skipped,), (recovered,))
    synchronizer, _, _ = build(tmp_path, transport)

    status = run(synchronizer.sync_once())
    assert status.pending_revision == 1
    assert status.full_sync_count == 1
    assert transport.pull_calls == [(0, False), (0, True)]


def test_full_sync_without_parent_enters_backoff(tmp_path: Path) -> None:
    skipped, key = signed(revision=3, parent_revision=2)
    transport = FakeNetworkSyncTransport(key, (skipped,), (skipped,))
    synchronizer, _, _ = build(tmp_path, transport)

    first = run(synchronizer.sync_once())
    second = run(synchronizer.sync_once())
    assert first.phase is ManagedNetworkSyncPhase.BACKOFF
    assert first.last_error_code == "full_sync_required"
    assert first.next_backoff_seconds == 1
    assert second.next_backoff_seconds == 2


def test_empty_sync_is_idle_and_missing_credentials_are_bounded(tmp_path: Path) -> None:
    _, key = signed()
    transport = FakeNetworkSyncTransport(key)
    synchronizer, _, _ = build(tmp_path, transport)
    assert run(synchronizer.sync_once()).phase is ManagedNetworkSyncPhase.IDLE

    missing, _, _ = build(tmp_path / "missing", transport, credential=False)
    status = run(missing.sync_once())
    assert status.phase is ManagedNetworkSyncPhase.BACKOFF
    assert status.last_error_code == "unauthenticated"


def test_invalid_signature_target_and_budget_never_become_pending(tmp_path: Path) -> None:
    envelope, key = signed()
    tampered = envelope.model_copy(update={"signature": "A" * len(envelope.signature)})
    invalid_transport = FakeNetworkSyncTransport(key, (tampered,))
    invalid, _, _ = build(tmp_path / "invalid", invalid_transport)
    assert run(invalid.sync_once()).last_error_code == "invalid_signed_config"
    assert invalid.checkpoint.pending_config is None

    wrong_target, wrong_key = signed(target_node_id=NODE_B)
    target_transport = FakeNetworkSyncTransport(wrong_key, (wrong_target,))
    target, _, _ = build(tmp_path / "target", target_transport)
    assert run(target.sync_once()).last_error_code == "invalid_signed_config"

    budget_transport = FakeNetworkSyncTransport(key, (envelope, envelope))
    budget, _, _ = build(tmp_path / "budget", budget_transport, max_configs=1)
    assert run(budget.sync_once()).last_error_code == "config_too_large"

    bytes_transport = FakeNetworkSyncTransport(key, (envelope,))
    byte_limited, _, _ = build(
        tmp_path / "bytes",
        bytes_transport,
        max_config_bytes=256,
    )
    assert run(byte_limited.sync_once()).last_error_code == "config_too_large"


def test_cancellation_timeout_and_single_concurrency_are_bounded(tmp_path: Path) -> None:
    envelope, key = signed()
    transport = FakeNetworkSyncTransport(key, (envelope,))
    synchronizer, _, _ = build(tmp_path / "cancel", transport)
    cancellation = ToolCancellationToken()
    cancellation.cancel()
    cancelled = run(synchronizer.sync_once(cancellation=cancellation))
    assert cancelled.last_error_code == "cancelled"

    timeout_transport = FakeNetworkSyncTransport(key, (envelope,))
    timeout_transport.delay = 0.05
    timed, _, _ = build(tmp_path / "timeout", timeout_transport, timeout=0.01)
    assert run(timed.sync_once()).last_error_code == "timeout"

    async def concurrent_scenario() -> None:
        blocking_transport = FakeNetworkSyncTransport(key, (envelope,))
        blocking_transport.block = asyncio.Event()
        concurrent, _, _ = build(tmp_path / "concurrent", blocking_transport)
        first = asyncio.create_task(concurrent.sync_once())
        await asyncio.sleep(0)
        with pytest.raises(ManagedNetworkSyncError, match="已在运行"):
            await concurrent.sync_once()
        blocking_transport.block.set()
        await first

    run(concurrent_scenario())


def test_coordinator_failure_keeps_last_known_good_and_marks_stale(tmp_path: Path) -> None:
    envelope, key = signed()
    transport = FakeNetworkSyncTransport(key, (envelope,))
    synchronizer, _, _ = build(tmp_path, transport)
    run(synchronizer.sync_once())
    synchronizer.mark_verified(envelope)
    transport.error = CoordinatorClientError("offline", "Coordinator 离线")

    status = run(synchronizer.sync_once())
    assert status.phase is ManagedNetworkSyncPhase.STALE
    assert status.control_plane_stale
    assert status.applied_revision == 1
    assert synchronizer.checkpoint.last_known_good == envelope


def test_credentialed_governance_ack_and_redacted_path_status(tmp_path: Path) -> None:
    envelope, key = signed()
    transport = FakeNetworkSyncTransport(key, (envelope,))
    synchronizer, _, secrets = build(tmp_path, transport)
    sink = CredentialedNetworkAcknowledgementSink(
        synchronizer.config,
        transport,
        AgentRefreshCredentialStore(secrets),
    )
    acknowledgement = NetworkAcknowledgement(
        network_id=NETWORK_ID,
        node_id=NODE_A,
        revision=1,
        stage=AcknowledgementStage.APPLYING,
        acknowledged_at=NOW,
    )
    run(sink.acknowledge(acknowledgement))
    status = NetworkPathStatus(
        network_id=NETWORK_ID,
        node_id=NODE_A,
        revision=1,
        path_type="direct",
        candidate_count=1,
    )
    run(sink.report_path_status(status))
    assert transport.acknowledgements == [acknowledgement]
    assert transport.path_statuses[0]["candidate_count"] == 1
    assert "endpoint" not in transport.path_statuses[0]

    wrong = acknowledgement.model_copy(update={"node_id": NODE_B})
    with pytest.raises(ValueError, match="不属于"):
        run(sink.acknowledge(wrong))
    wrong_status = status.model_copy(update={"node_id": NODE_B})
    with pytest.raises(ValueError, match="不属于"):
        run(sink.report_path_status(wrong_status))

    secrets.delete(coordinator_refresh_name(NETWORK_ID, NODE_A))
    with pytest.raises(ManagedNetworkSyncError, match="refresh"):
        run(sink.acknowledge(acknowledgement))


def test_run_loop_stops_without_model_or_provider(tmp_path: Path) -> None:
    _, key = signed()
    transport = FakeNetworkSyncTransport(key)
    synchronizer, _, _ = build(tmp_path, transport)

    async def scenario() -> None:
        task = asyncio.create_task(synchronizer.run())
        await asyncio.sleep(0)
        synchronizer.stop()
        await task

    run(scenario())
    assert synchronizer.status.phase is ManagedNetworkSyncPhase.STOPPED


def test_run_loop_retries_after_interval_without_model(tmp_path: Path) -> None:
    _, key = signed()
    transport = FakeNetworkSyncTransport(key)
    synchronizer, _, _ = build(tmp_path, transport, sync_interval=0.01)

    async def scenario() -> None:
        task = asyncio.create_task(synchronizer.run())
        await asyncio.sleep(0.1)
        synchronizer.stop()
        await task

    run(scenario())
    assert len(transport.pull_calls) >= 2


def test_sync_contracts_reject_invalid_scope_clock_and_secret_checkpoint(
    tmp_path: Path,
) -> None:
    envelope, key = signed()
    with pytest.raises(ValidationError):
        ManagedNetworkSyncConfig(
            network_id=NETWORK_ID,
            node_id=NODE_A,
            pinned_fingerprints=frozenset({"bad"}),
        )
    with pytest.raises(ValidationError):
        ManagedNetworkSyncConfig(
            network_id=NETWORK_ID,
            node_id=NODE_A,
            pinned_fingerprints=frozenset({envelope.key_fingerprint}),
            base_backoff_seconds=2,
            max_backoff_seconds=1,
        )
    with pytest.raises(ValidationError):
        ManagedNetworkSyncCheckpoint(
            network_id=NETWORK_ID,
            node_id=NODE_B,
            pending_config=envelope,
            updated_at=NOW,
        )
    inherited, _ = signed(revision=2, parent_revision=1)
    with pytest.raises(ValidationError, match="直接继承"):
        ManagedNetworkSyncCheckpoint(
            network_id=NETWORK_ID,
            node_id=NODE_A,
            applied_revision=0,
            pending_config=inherited,
            updated_at=NOW,
        )
    with pytest.raises(ValidationError):
        ManagedNetworkSyncCheckpoint(
            network_id=NETWORK_ID,
            node_id=NODE_A,
            applied_revision=2,
            last_known_good=envelope,
            updated_at=NOW,
        )

    transport = FakeNetworkSyncTransport(key)
    secrets = MemorySecrets()
    secrets.set(coordinator_refresh_name(NETWORK_ID, NODE_A), "r" * 43)
    with pytest.raises(ValueError, match="时区"):
        ManagedNetworkSynchronizer(
            ManagedNetworkSyncConfig(
                network_id=NETWORK_ID,
                node_id=NODE_A,
                pinned_fingerprints=frozenset({envelope.key_fingerprint}),
            ),
            transport,
            AgentRefreshCredentialStore(secrets),
            SQLiteManagedNetworkSyncStore(tmp_path / "naive.sqlite3"),
            clock=lambda: NOW.replace(tzinfo=None),
        )

    store = SQLiteManagedNetworkSyncStore(tmp_path / "corrupt.sqlite3")
    checkpoint = ManagedNetworkSyncCheckpoint(
        network_id=NETWORK_ID,
        node_id=NODE_A,
        updated_at=NOW,
    )
    store.save(checkpoint)
    with sqlite3.connect(store.path) as connection:
        connection.execute(
            "UPDATE managed_network_sync SET payload=?",
            ('{"refresh_credential":"forbidden"}',),
        )
    with pytest.raises(ValueError, match="秘密字段"):
        store.assert_no_secret_material()


def test_http_managed_network_transport_uses_agent_api_without_echoing_secrets() -> None:
    envelope, key = signed()
    authentication = RefreshAuthentication(
        network_id=NETWORK_ID,
        node_id=NODE_A,
        refresh_credential="r" * 43,
    )
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.url.path.endswith("verification-keys"):
            return httpx.Response(
                200,
                json=VerificationKeySet(generated_at=NOW, keys=(key,)).model_dump(mode="json"),
            )
        if request.url.path.endswith("desired-configs/query"):
            return httpx.Response(200, json=[envelope.model_dump(mode="json")])
        return httpx.Response(200, json={"status": "accepted"})

    transport = HttpManagedNetworkSyncTransport(
        http_config(), transport=httpx.MockTransport(handler)
    )
    assert run(transport.verification_keys()) == (key,)
    assert run(
        transport.pull_desired_configs(
            authentication,
            after_revision=0,
            full_sync=False,
        )
    ) == (envelope,)
    acknowledgement = NetworkAcknowledgement(
        network_id=NETWORK_ID,
        node_id=NODE_A,
        revision=1,
        stage=AcknowledgementStage.PENDING,
        acknowledged_at=NOW,
    )
    run(transport.acknowledge(authentication, acknowledgement))
    path = NetworkPathStatus(
        network_id=NETWORK_ID,
        node_id=NODE_A,
        revision=1,
        path_type="pending",
        candidate_count=0,
    )
    run(transport.report_path_status(authentication, path.model_dump(mode="python")))
    assert [request.url.path for request in requests] == [
        "/api/v1/agent/verification-keys",
        "/api/v1/agent/network/desired-configs/query",
        "/api/v1/agent/network/acknowledgements",
        "/api/v1/agent/network/path-status",
    ]
    assert authentication.refresh_credential not in repr(requests)


def test_http_managed_network_transport_maps_invalid_offline_and_timeout_responses() -> None:
    authentication = RefreshAuthentication(
        network_id=NETWORK_ID,
        node_id=NODE_A,
        refresh_credential="r" * 43,
    )

    def invalid_list(request: httpx.Request) -> httpx.Response:
        del request
        return httpx.Response(200, json={})

    invalid = HttpManagedNetworkSyncTransport(
        http_config(), transport=httpx.MockTransport(invalid_list)
    )
    with pytest.raises(CoordinatorClientError) as invalid_error:
        run(invalid.pull_desired_configs(authentication, after_revision=0, full_sync=False))
    assert invalid_error.value.code == "invalid_response"

    def rejected(request: httpx.Request) -> httpx.Response:
        del request
        return httpx.Response(403, json={"detail": {"code": "forbidden"}})

    forbidden = HttpManagedNetworkSyncTransport(
        http_config(), transport=httpx.MockTransport(rejected)
    )
    with pytest.raises(CoordinatorClientError) as rejected_error:
        run(forbidden.verification_keys())
    assert rejected_error.value.code == "forbidden"

    def rejected_without_json(request: httpx.Request) -> httpx.Response:
        del request
        return httpx.Response(502, content=b"not-json")

    bad_gateway = HttpManagedNetworkSyncTransport(
        http_config(), transport=httpx.MockTransport(rejected_without_json)
    )
    with pytest.raises(CoordinatorClientError) as bad_gateway_error:
        run(bad_gateway.verification_keys())
    assert bad_gateway_error.value.code == "http_502"

    def invalid_json(request: httpx.Request) -> httpx.Response:
        del request
        return httpx.Response(200, content=b"not-json")

    malformed = HttpManagedNetworkSyncTransport(
        http_config(), transport=httpx.MockTransport(invalid_json)
    )
    with pytest.raises(CoordinatorClientError) as malformed_error:
        run(malformed.verification_keys())
    assert malformed_error.value.code == "invalid_response"

    def timeout(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("timeout", request=request)

    timed_out = HttpManagedNetworkSyncTransport(
        http_config(), transport=httpx.MockTransport(timeout)
    )
    with pytest.raises(CoordinatorClientError) as timeout_error:
        run(timed_out.verification_keys())
    assert timeout_error.value.code == "timeout"

    def offline(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("offline", request=request)

    unavailable = HttpManagedNetworkSyncTransport(
        http_config(), transport=httpx.MockTransport(offline)
    )
    with pytest.raises(CoordinatorClientError) as offline_error:
        run(unavailable.verification_keys())
    assert offline_error.value.code == "offline"
