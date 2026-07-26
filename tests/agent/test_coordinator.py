"""Agent Coordinator enrollment、同步、缓存、退避与最小化渲染测试。"""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Coroutine, Mapping
from datetime import timedelta
from functools import wraps
from pathlib import Path
from typing import Any, ParamSpec, cast

import httpx
import pytest
from pydantic import JsonValue, ValidationError
from tests.coordinator.test_directory import capability_snapshot, service_snapshot
from tests.coordinator.test_registry import (
    NETWORK,
    NOW,
    MemorySecrets,
    authentication,
    identity,
)

from tunnelminion.agent.coordinator import (
    AgentCoordinatorSynchronizer,
    CoordinatorAuthorizationView,
    CoordinatorCache,
    CoordinatorCheckpoint,
    CoordinatorCheckpointStore,
    CoordinatorClientConfig,
    CoordinatorClientError,
    CoordinatorEnrollmentClient,
    CoordinatorSyncStatus,
    CoordinatorTransport,
    HttpCoordinatorTransport,
    SyncPhase,
    render_capabilities,
    render_service_observations,
)
from tunnelminion.coordinator.client_credentials import AgentRefreshCredentialStore
from tunnelminion.coordinator.contracts import (
    AccessAssertionRequest,
    AccessAssertionResponse,
    CapabilitySnapshot,
    CapabilitySummary,
    DirectoryPage,
    DirectoryQuery,
    HeartbeatRequest,
    HeartbeatResponse,
    NodeRegistrationRequest,
    NodeRegistrationResponse,
    NodeStatus,
    RefreshAuthentication,
    ServiceSnapshot,
    ServiceSummary,
    SnapshotReceipt,
    VerificationKeySet,
    VerificationKeyView,
)
from tunnelminion.domain.identifiers import RefreshCredentialId, ServiceId, SnapshotId
from tunnelminion.domain.tools import (
    DataSensitivity,
    Platform,
    RiskLevel,
    ToolDefinition,
)
from tunnelminion.domain.versioning import ProtocolVersion

FINGERPRINT = "f" * 64
P = ParamSpec("P")


def async_test(
    function: Callable[P, Coroutine[Any, Any, None]],
) -> Callable[P, None]:
    """用项目现有 asyncio.run 方式执行异步场景。"""

    @wraps(function)
    def wrapper(*args: P.args, **kwargs: P.kwargs) -> None:
        asyncio.run(function(*args, **kwargs))

    return wrapper


def config(**updates: object) -> CoordinatorClientConfig:
    payload: dict[str, object] = {
        "endpoint": "http://10.77.0.1:8790",
        "network_id": NETWORK,
        "node_id": identity().node_id,
        "pinned_fingerprints": frozenset({FINGERPRINT}),
        "request_timeout_seconds": 1,
    }
    payload.update(updates)
    return CoordinatorClientConfig.model_validate(payload)


def key_set(fingerprint: str = FINGERPRINT) -> VerificationKeySet:
    return VerificationKeySet(
        generated_at=NOW,
        keys=(
            VerificationKeyView(
                key_id="key-test",
                public_key="A" * 43,
                fingerprint=fingerprint,
                activates_at=NOW,
            ),
        ),
    )


def registration_response(client_config: CoordinatorClientConfig) -> NodeRegistrationResponse:
    return NodeRegistrationResponse(
        identity=identity(
            node_id=client_config.node_id,
            network_id=client_config.network_id,
        ),
        credential_id=RefreshCredentialId.new(),
        refresh_credential=f"tmnr_{'r' * 43}",
        server_revision=1,
        issued_at=NOW,
    )


def capability_summary() -> CapabilitySummary:
    from tests.coordinator.test_directory import capability

    return capability()


def service_summary() -> ServiceSummary:
    from tests.coordinator.test_directory import service_summary as build

    return build(ServiceId.new())


class FakeTransport:
    def __init__(self, client_config: CoordinatorClientConfig) -> None:
        self.config = client_config
        self.keys = key_set()
        self.fail: CoordinatorClientError | None = None
        self.full_sync_once = False
        self.query_count = 0
        self.capability_sequences: list[int] = []
        self.service_sequences: list[int] = []
        self.capability_ids: list[SnapshotId] = []
        self.service_ids: list[SnapshotId] = []
        self.lose_capability_response = False
        self.lose_service_response = False
        self.registration_keys: list[str] = []

    def _raise(self) -> None:
        if self.fail is not None:
            raise self.fail

    async def register(self, request: NodeRegistrationRequest) -> NodeRegistrationResponse:
        self._raise()
        self.registration_keys.append(request.idempotency_key)
        return registration_response(self.config)

    async def verification_keys(self) -> VerificationKeySet:
        self._raise()
        return self.keys

    async def heartbeat(
        self,
        authentication: RefreshAuthentication,
        request: HeartbeatRequest,
    ) -> HeartbeatResponse:
        self._raise()
        return HeartbeatResponse(
            received_at=NOW,
            node_status=NodeStatus.ONLINE,
            server_revision=1,
        )

    async def replace_capabilities(
        self,
        authentication: RefreshAuthentication,
        snapshot: CapabilitySnapshot,
    ) -> SnapshotReceipt:
        self._raise()
        self.capability_sequences.append(snapshot.sequence)
        self.capability_ids.append(snapshot.snapshot_id)
        if self.lose_capability_response:
            self.lose_capability_response = False
            raise CoordinatorClientError("response_lost", "response lost")
        return SnapshotReceipt(
            snapshot_id=snapshot.snapshot_id,
            sequence=snapshot.sequence,
            server_revision=2,
            received_at=NOW,
        )

    async def replace_services(
        self,
        authentication: RefreshAuthentication,
        snapshot: ServiceSnapshot,
    ) -> SnapshotReceipt:
        self._raise()
        self.service_sequences.append(snapshot.sequence)
        self.service_ids.append(snapshot.snapshot_id)
        if self.lose_service_response:
            self.lose_service_response = False
            raise CoordinatorClientError("response_lost", "response lost")
        return SnapshotReceipt(
            snapshot_id=snapshot.snapshot_id,
            sequence=snapshot.sequence,
            server_revision=3,
            received_at=NOW,
        )

    async def query(
        self,
        authentication: RefreshAuthentication,
        query: DirectoryQuery,
    ) -> DirectoryPage:
        self._raise()
        self.query_count += 1
        if self.full_sync_once and self.query_count == 1:
            return DirectoryPage(
                server_revision=3,
                generated_at=NOW,
                nodes=(),
                full_sync_required=True,
            )
        return DirectoryPage(server_revision=3, generated_at=NOW, nodes=())


def saved_credentials(
    client_config: CoordinatorClientConfig,
) -> tuple[AgentRefreshCredentialStore, MemorySecrets]:
    secrets_store = MemorySecrets()
    credentials = AgentRefreshCredentialStore(secrets_store)
    credentials.save(registration_response(client_config))
    return credentials, secrets_store


def test_client_config_rejects_public_loopback_invalid_url_and_fingerprint() -> None:
    for endpoint in (
        "ftp://10.77.0.1",
        "http://127.0.0.1",
        "http://0.0.0.0",
        "http://224.0.0.1",
        "http://8.8.8.8",
    ):
        with pytest.raises(ValidationError):
            config(endpoint=endpoint)
    with pytest.raises(ValidationError, match="指纹"):
        config(pinned_fingerprints={"bad"})
    assert config(endpoint="https://10.77.0.1/").endpoint == "https://10.77.0.1"


@async_test
async def test_enrollment_confirms_fingerprint_and_saves_only_refresh() -> None:
    client_config = config()
    transport = FakeTransport(client_config)
    secrets_store = MemorySecrets()
    credentials = AgentRefreshCredentialStore(secrets_store)
    enrollment = CoordinatorEnrollmentClient(client_config, transport, credentials)
    response = await enrollment.enroll(
        registration_response(client_config).identity,
        device_identity_hash="a" * 64,
        enrollment_token=f"tmne_{'e' * 43}",
    )
    assert credentials.load(NETWORK, client_config.node_id) == response.refresh_credential
    assert response.refresh_credential not in repr(response)
    await enrollment.enroll(
        response.identity,
        device_identity_hash="a" * 64,
        enrollment_token=f"tmne_{'e' * 43}",
    )
    assert transport.registration_keys[0] == transport.registration_keys[1]

    transport.keys = key_set("e" * 64)
    with pytest.raises(CoordinatorClientError) as mismatch:
        await enrollment.enroll(
            response.identity,
            device_identity_hash="a" * 64,
            enrollment_token=f"tmne_{'e' * 43}",
        )
    assert mismatch.value.code == "fingerprint_mismatch"
    with pytest.raises(CoordinatorClientError) as forbidden:
        await enrollment.enroll(
            response.identity.model_copy(update={"node_id": identity().node_id}),
            device_identity_hash="a" * 64,
            enrollment_token=f"tmne_{'e' * 43}",
        )
    assert forbidden.value.code == "forbidden"


@async_test
async def test_sync_success_full_sync_checkpoint_and_cache(tmp_path: Path) -> None:
    client_config = config()
    transport = FakeTransport(client_config)
    transport.full_sync_once = True
    credentials, _ = saved_credentials(client_config)
    checkpoint_store = CoordinatorCheckpointStore(tmp_path / "sync.json")
    cache = CoordinatorCache()
    synchronizer = AgentCoordinatorSynchronizer(
        client_config,
        cast(CoordinatorTransport, transport),
        credentials,
        checkpoint_store,
        cache,
        clock=lambda: NOW,
        jitter=lambda: 1,
    )
    status = await synchronizer.sync_once((capability_summary(),), (service_summary(),))
    assert status.phase is SyncPhase.IDLE
    assert status.server_revision == 3
    assert transport.query_count == 2
    assert transport.capability_sequences == [1]
    assert CoordinatorCheckpointStore(tmp_path / "sync.json").load().server_revision == 3
    view = cache.read()
    assert view is not None and view.is_fresh(NOW)
    assert not view.is_fresh(NOW + timedelta(seconds=121))

    second = AgentCoordinatorSynchronizer(
        client_config,
        cast(CoordinatorTransport, transport),
        credentials,
        checkpoint_store,
        cache,
        clock=lambda: NOW,
    )
    await second.sync_once((), ())
    assert transport.capability_sequences[-1] == 2


@async_test
async def test_sync_failure_backoff_budget_missing_auth_and_concurrency(
    tmp_path: Path,
) -> None:
    client_config = config(max_capabilities=1, max_snapshot_bytes=1024)
    transport = FakeTransport(client_config)
    empty_credentials = AgentRefreshCredentialStore(MemorySecrets())
    sync = AgentCoordinatorSynchronizer(
        client_config,
        cast(CoordinatorTransport, transport),
        empty_credentials,
        CoordinatorCheckpointStore(tmp_path / "missing.json"),
        CoordinatorCache(),
        jitter=lambda: 1,
    )
    missing = await sync.sync_once((), ())
    assert missing.last_error_code == "unauthenticated"
    assert missing.next_backoff_seconds == 1

    credentials, _ = saved_credentials(client_config)
    failing = AgentCoordinatorSynchronizer(
        client_config,
        cast(CoordinatorTransport, transport),
        credentials,
        CoordinatorCheckpointStore(tmp_path / "failure.json"),
        CoordinatorCache(),
        jitter=lambda: 1,
    )
    transport.fail = CoordinatorClientError("offline", "offline")
    first = await failing.sync_once((), ())
    second = await failing.sync_once((), ())
    assert (first.next_backoff_seconds, second.next_backoff_seconds) == (1, 2)

    oversized = await failing.sync_once(
        (capability_summary(), capability_summary()),
        (),
    )
    assert oversized.last_error_code == "snapshot_too_large"
    byte_oversized = await failing.sync_once(
        (),
        tuple(service_summary() for _ in range(20)),
    )
    assert byte_oversized.last_error_code == "snapshot_too_large"

    transport.fail = None
    gate = asyncio.Event()

    async def blocked_heartbeat(
        authentication: RefreshAuthentication,
        request: HeartbeatRequest,
    ) -> HeartbeatResponse:
        await gate.wait()
        return HeartbeatResponse(
            received_at=NOW,
            node_status=NodeStatus.ONLINE,
            server_revision=1,
        )

    transport.heartbeat = blocked_heartbeat  # type: ignore[method-assign]
    running = asyncio.create_task(failing.sync_once((), ()))
    await asyncio.sleep(0)
    with pytest.raises(CoordinatorClientError) as concurrent:
        await failing.sync_once((), ())
    assert concurrent.value.code == "concurrency_limited"
    gate.set()
    await running


@async_test
async def test_sync_retries_exact_pending_snapshots_after_response_loss(
    tmp_path: Path,
) -> None:
    client_config = config()
    transport = FakeTransport(client_config)
    credentials, _ = saved_credentials(client_config)
    checkpoint_store = CoordinatorCheckpointStore(tmp_path / "pending.json")
    sync = AgentCoordinatorSynchronizer(
        client_config,
        cast(CoordinatorTransport, transport),
        credentials,
        checkpoint_store,
        CoordinatorCache(),
        clock=lambda: NOW,
        jitter=lambda: 1,
    )
    transport.lose_capability_response = True
    assert (await sync.sync_once((capability_summary(),), ())).phase is SyncPhase.BACKOFF
    pending_capability = checkpoint_store.load().pending_capability
    assert pending_capability is not None
    assert (await sync.sync_once((capability_summary(),), ())).phase is SyncPhase.IDLE
    assert transport.capability_ids[:2] == [
        pending_capability.snapshot_id,
        pending_capability.snapshot_id,
    ]

    transport.lose_service_response = True
    assert (await sync.sync_once((), (service_summary(),))).phase is SyncPhase.BACKOFF
    pending_service = checkpoint_store.load().pending_service
    assert pending_service is not None
    assert (await sync.sync_once((), (service_summary(),))).phase is SyncPhase.IDLE
    assert transport.service_ids[-2:] == [
        pending_service.snapshot_id,
        pending_service.snapshot_id,
    ]


@async_test
async def test_run_can_stop_without_blocking_local_work(tmp_path: Path) -> None:
    client_config = config(sync_interval_seconds=0.01)
    transport = FakeTransport(client_config)
    credentials, _ = saved_credentials(client_config)
    sync = AgentCoordinatorSynchronizer(
        client_config,
        cast(CoordinatorTransport, transport),
        credentials,
        CoordinatorCheckpointStore(tmp_path / "run.json"),
        CoordinatorCache(),
        clock=lambda: NOW,
    )
    task = asyncio.create_task(sync.run(lambda: (), lambda: ()))
    await asyncio.sleep(0.02)
    sync.stop()
    await task
    assert sync.status.phase is SyncPhase.STOPPED


def test_checkpoint_cache_status_and_renderers_minimize_metadata(tmp_path: Path) -> None:
    store = CoordinatorCheckpointStore(tmp_path / "nested" / "checkpoint.json")
    assert store.load() == CoordinatorCheckpoint()
    checkpoint = CoordinatorCheckpoint(
        capability_sequence=2,
        service_sequence=3,
        server_revision=4,
    )
    store.save(checkpoint)
    assert store.load() == checkpoint
    assert CoordinatorSyncStatus().phase is SyncPhase.IDLE
    assert CoordinatorCache().read() is None

    definition = ToolDefinition(
        name="safe_tool",
        version=ProtocolVersion(major=1, minor=0),
        description="safe",
        input_schema={
            "type": "object",
            "properties": {
                "token": {
                    "type": "string",
                    "example": "must-not-leak",
                    "description": "secret",
                }
            },
        },
        output_schema={"type": "object"},
        risk_level=RiskLevel.READ_ONLY,
        platforms=frozenset({Platform.MACOS}),
        timeout_seconds=1,
        max_result_bytes=100,
        data_sensitivity=DataSensitivity.SYSTEM_METADATA,
    )
    changed_example = definition.model_copy(
        update={
            "input_schema": {
                "type": "object",
                "properties": {"token": {"type": "string", "example": "different-secret"}},
            }
        }
    )
    rendered = render_capabilities((definition,), Platform.MACOS)
    assert (
        rendered[0].schema_hash
        == render_capabilities((changed_example,), Platform.MACOS)[0].schema_hash
    )
    assert render_capabilities((definition,), Platform.WINDOWS) == ()
    list_schema = definition.model_copy(
        update={"input_schema": {"type": "array", "items": [{"type": "string"}]}}
    )
    assert render_capabilities((list_schema,), Platform.MACOS)

    observations: tuple[Mapping[str, JsonValue], ...] = (
        {
            "service_id": str(ServiceId.new()),
            "protocol": "http",
            "host": "127.0.0.1",
            "port": 8082,
            "accessibility": "loopback",
            "source": "listener",
            "confidence": 1,
            "observed_at": NOW.isoformat(),
            "environment": {"API_KEY": "must-not-leak"},
            "command_line": "secret",
            "response_body": "secret",
        },
    )
    service = render_service_observations(observations)[0]
    assert not hasattr(service, "environment")

    view = CoordinatorAuthorizationView(
        network_id=NETWORK,
        generated_at=NOW,
        expires_at=NOW + timedelta(seconds=1),
        nodes=(),
        verification_keys=key_set(),
    )
    cache = CoordinatorCache()
    cache.replace(view)
    assert cache.read() == view


@async_test
async def test_http_transport_success_errors_timeout_and_invalid_json() -> None:
    client_config = config()
    response = registration_response(client_config)
    snapshot_id = SnapshotId.new()

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("registrations"):
            return httpx.Response(200, json=response.model_dump(mode="json"))
        if request.url.path.endswith("verification-keys"):
            return httpx.Response(200, json=key_set().model_dump(mode="json"))
        if request.url.path.endswith("assertions"):
            return httpx.Response(
                200,
                json=AccessAssertionResponse(
                    assertion="x" * 80,
                    key_id="key-test",
                    expires_at=NOW + timedelta(seconds=120),
                ).model_dump(mode="json"),
            )
        if request.url.path.endswith("heartbeat"):
            return httpx.Response(
                200,
                json=HeartbeatResponse(
                    received_at=NOW,
                    node_status=NodeStatus.ONLINE,
                    server_revision=1,
                ).model_dump(mode="json"),
            )
        if "snapshots" in request.url.path:
            return httpx.Response(
                200,
                json=SnapshotReceipt(
                    snapshot_id=snapshot_id,
                    sequence=1,
                    server_revision=2,
                    received_at=NOW,
                ).model_dump(mode="json"),
            )
        return httpx.Response(
            200,
            json=DirectoryPage(
                server_revision=2,
                generated_at=NOW,
                nodes=(),
            ).model_dump(mode="json"),
        )

    transport = HttpCoordinatorTransport(
        client_config,
        transport=httpx.MockTransport(handler),
    )
    auth = authentication(response)
    registration_request = NodeRegistrationRequest(
        identity=response.identity,
        device_identity_hash="a" * 64,
        enrollment_token=f"tmne_{'e' * 43}",
        idempotency_key=f"regkey_{'a' * 64}",
    )
    assert (await transport.register(registration_request)).identity.node_id
    assert (await transport.verification_keys()).keys
    assert (
        await transport.issue_assertion(
            AccessAssertionRequest(authentication=auth, audience="tool-gateway")
        )
    ).key_id == "key-test"
    heartbeat = HeartbeatRequest(
        network_id=auth.network_id,
        node_id=auth.node_id,
        sent_at=NOW,
    )
    assert (await transport.heartbeat(auth, heartbeat)).server_revision == 1
    assert (
        await transport.replace_capabilities(auth, capability_snapshot(auth))
    ).server_revision == 2
    assert (await transport.replace_services(auth, service_snapshot(auth))).server_revision == 2
    assert (await transport.query(auth, DirectoryQuery(network_id=NETWORK))).server_revision == 2

    rejected = HttpCoordinatorTransport(
        client_config,
        transport=httpx.MockTransport(
            lambda _: httpx.Response(
                403,
                json={"detail": {"code": "forbidden", "message": "no"}},
            )
        ),
    )
    with pytest.raises(CoordinatorClientError) as error:
        await rejected.verification_keys()
    assert error.value.code == "forbidden"

    invalid = HttpCoordinatorTransport(
        client_config,
        transport=httpx.MockTransport(lambda _: httpx.Response(200, text="invalid")),
    )
    with pytest.raises(CoordinatorClientError) as bad:
        await invalid.verification_keys()
    assert bad.value.code == "invalid_response"

    async def timeout_handler(_: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("timeout")

    timeout = HttpCoordinatorTransport(
        client_config,
        transport=httpx.MockTransport(timeout_handler),
    )
    with pytest.raises(CoordinatorClientError) as timed_out:
        await timeout.verification_keys()
    assert timed_out.value.code == "timeout"

    async def offline_handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("offline", request=request)

    offline = HttpCoordinatorTransport(
        client_config,
        transport=httpx.MockTransport(offline_handler),
    )
    with pytest.raises(CoordinatorClientError) as unreachable:
        await offline.verification_keys()
    assert unreachable.value.code == "offline"

    rejected_invalid = HttpCoordinatorTransport(
        client_config,
        transport=httpx.MockTransport(lambda _: httpx.Response(500, text="invalid")),
    )
    with pytest.raises(CoordinatorClientError) as generic:
        await rejected_invalid.verification_keys()
    assert generic.value.code == "http_500"


@async_test
async def test_sync_rejects_naive_clock(tmp_path: Path) -> None:
    client_config = config()
    transport = FakeTransport(client_config)
    credentials, _ = saved_credentials(client_config)
    sync = AgentCoordinatorSynchronizer(
        client_config,
        cast(CoordinatorTransport, transport),
        credentials,
        CoordinatorCheckpointStore(tmp_path / "naive.json"),
        CoordinatorCache(),
        clock=lambda: NOW.replace(tzinfo=None),
    )
    with pytest.raises(ValueError, match="时区"):
        await sync.sync_once((), ())
