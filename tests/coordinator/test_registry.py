"""Coordinator enrollment、节点身份、refresh 与 SQLite 恢复测试。"""

from __future__ import annotations

import sqlite3
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from tunnelminion.coordinator.client_credentials import (
    AgentRefreshCredentialStore,
    coordinator_refresh_name,
)
from tunnelminion.coordinator.contracts import (
    CoordinatorAuditAction,
    CoordinatorErrorCode,
    EnrollmentTokenRequest,
    GatewayEndpoint,
    HeartbeatRequest,
    NodeIdentity,
    NodeRegistrationRequest,
    NodeStatus,
    RefreshAuthentication,
    SigningKeyMetadata,
)
from tunnelminion.coordinator.registry import (
    SCHEMA_VERSION,
    CoordinatorRegistryService,
    HeartbeatPolicy,
    RegistryError,
    SQLiteCoordinatorStore,
)
from tunnelminion.domain.identifiers import NetworkId, NodeId
from tunnelminion.domain.tools import Platform
from tunnelminion.domain.versioning import ProtocolVersion

NETWORK = NetworkId("network_0123456789abcdef0123456789abcdef")
OTHER_NETWORK = NetworkId("network_ffffffffffffffffffffffffffffffff")
NOW = datetime(2026, 7, 26, 8, 0, tzinfo=UTC)
PROTOCOL = ProtocolVersion(major=1, minor=0)


class MutableClock:
    def __init__(self) -> None:
        self.now = NOW
        self.monotonic = 0.0

    def utcnow(self) -> datetime:
        return self.now

    def monotonic_now(self) -> float:
        return self.monotonic


class MemorySecrets:
    def __init__(self) -> None:
        self.values: dict[str, str] = {}

    def get(self, name: str) -> str | None:
        return self.values.get(name)

    def set(self, name: str, value: str) -> None:
        self.values[name] = value

    def delete(self, name: str) -> None:
        self.values.pop(name, None)


def identity(
    node_id: NodeId | None = None,
    *,
    network_id: NetworkId = NETWORK,
    display_name: str = "HomeMac",
    protocol: ProtocolVersion = PROTOCOL,
) -> NodeIdentity:
    return NodeIdentity(
        network_id=network_id,
        node_id=node_id or NodeId.new(),
        display_name=display_name,
        platform=Platform.MACOS,
        gateway_endpoint=GatewayEndpoint(host="10.77.0.1"),
        protocol=protocol,
    )


def registration(
    token: str,
    node_identity: NodeIdentity | None = None,
    *,
    device: str = "a" * 64,
    key: str = "b" * 64,
) -> NodeRegistrationRequest:
    return NodeRegistrationRequest(
        identity=node_identity or identity(),
        device_identity_hash=device,
        enrollment_token=token,
        idempotency_key=f"regkey_{key}",
    )


def service(
    tmp_path: Path,
    clock: MutableClock | None = None,
    *,
    limit: int = 30,
) -> CoordinatorRegistryService:
    value = clock or MutableClock()
    return CoordinatorRegistryService(
        SQLiteCoordinatorStore(tmp_path / "coordinator.sqlite3"),
        clock=value.utcnow,
        monotonic_clock=value.monotonic_now,
        refresh_attempts_per_minute=limit,
    )


def enrollment(
    registry: CoordinatorRegistryService,
    *,
    network_id: NetworkId = NETWORK,
    ttl: int = 600,
    max_uses: int = 1,
) -> tuple[str, object]:
    created = registry.create_enrollment_token(
        EnrollmentTokenRequest(
            network_id=network_id,
            expires_in_seconds=ttl,
            max_uses=max_uses,
        )
    )
    return created.token, created.token_id


def authentication(response: object) -> RefreshAuthentication:
    from tunnelminion.coordinator.contracts import NodeRegistrationResponse

    assert isinstance(response, NodeRegistrationResponse)
    return RefreshAuthentication(
        network_id=response.identity.network_id,
        node_id=response.identity.node_id,
        refresh_credential=response.refresh_credential,
    )


def heartbeat_for(
    auth: RefreshAuthentication,
    *,
    sent_at: datetime = NOW,
    protocol: ProtocolVersion = PROTOCOL,
) -> HeartbeatRequest:
    return HeartbeatRequest(
        protocol=protocol,
        network_id=auth.network_id,
        node_id=auth.node_id,
        sent_at=sent_at,
    )


def test_store_schema_is_versioned_complete_and_reopens(tmp_path: Path) -> None:
    store = SQLiteCoordinatorStore(tmp_path / "nested" / "coordinator.sqlite3")
    expected = {
        "schema_metadata",
        "networks",
        "enrollment_tokens",
        "nodes",
        "refresh_credentials",
        "signing_keys",
        "revocations",
        "revisions",
        "coordinator_audit",
        "registration_idempotency",
    }
    assert store.schema_version() == SCHEMA_VERSION
    assert expected <= store.table_names()
    assert SQLiteCoordinatorStore(store.path).schema_version() == SCHEMA_VERSION
    first_key = SigningKeyMetadata(
        key_id="coord-2026-07",
        private_key_reference="keyring:coordinator-signing:coord-2026-07",
        public_key="A" * 43,
        fingerprint="1" * 64,
        activates_at=NOW,
    )
    second_key = SigningKeyMetadata(
        key_id="coord-2026-08",
        private_key_reference="keyring:coordinator-signing:coord-2026-08",
        public_key="B" * 43,
        fingerprint="2" * 64,
        activates_at=NOW + timedelta(days=1),
        retires_at=NOW + timedelta(days=31),
        destroyed_at=NOW + timedelta(days=32),
    )
    store.put_signing_key(first_key)
    store.put_signing_key(second_key)
    updated = first_key.model_copy(update={"retires_at": NOW + timedelta(days=2)})
    store.put_signing_key(updated)
    assert store.list_signing_keys() == (updated, second_key)

    with store.connect() as connection:
        connection.execute("UPDATE schema_metadata SET version=99")
    with pytest.raises(RuntimeError, match="版本"):
        SQLiteCoordinatorStore(store.path)
    with store.connect() as connection:
        connection.execute("UPDATE schema_metadata SET version=2")
        connection.execute("DELETE FROM schema_metadata")
    with pytest.raises(RuntimeError, match="metadata"):
        store.schema_version()


def test_network_and_enrollment_store_only_hash_and_revoke_safely(tmp_path: Path) -> None:
    registry = service(tmp_path)
    registry.create_network(NETWORK)
    registry.create_network(NETWORK)
    token, token_id = enrollment(registry)

    with registry.store.connect() as connection:
        row = connection.execute(
            "SELECT salt, digest FROM enrollment_tokens WHERE token_id=?",
            (str(token_id),),
        ).fetchone()
    assert row is not None
    assert token.encode() not in (bytes(row["salt"]), bytes(row["digest"]))
    assert token not in repr(registry.audit_records(NETWORK))

    registry.revoke_enrollment_token(token_id)  # type: ignore[arg-type]
    with pytest.raises(RegistryError) as caught:
        registry.revoke_enrollment_token(token_id)  # type: ignore[arg-type]
    assert caught.value.code is CoordinatorErrorCode.UNAUTHENTICATED

    with pytest.raises(RegistryError) as missing:
        registry.create_enrollment_token(EnrollmentTokenRequest(network_id=OTHER_NETWORK))
    assert missing.value.code is CoordinatorErrorCode.FORBIDDEN


def test_registration_authentication_idempotent_retry_and_keyring_boundary(
    tmp_path: Path,
) -> None:
    registry = service(tmp_path)
    registry.create_network(NETWORK)
    token, _ = enrollment(registry)
    request = registration(token)
    first = registry.register(request)

    assert first.identity == request.identity
    assert first.refresh_credential not in repr(first)
    with registry.store.connect() as connection:
        sql_dump = "\n".join(connection.iterdump())
    assert token not in sql_dump
    assert first.refresh_credential not in sql_dump
    assert registry.authenticate_refresh(authentication(first)).identity == request.identity
    assert registry.list_nodes(NETWORK)[0].status is NodeStatus.OFFLINE
    assert registry.list_nodes(OTHER_NETWORK) == ()
    assert [item.action for item in registry.audit_records(NETWORK)] == [
        CoordinatorAuditAction.NODE_REGISTERED
    ]

    second = registry.register(request)
    assert second.identity.node_id == first.identity.node_id
    assert second.credential_id != first.credential_id
    with pytest.raises(RegistryError):
        registry.authenticate_refresh(authentication(first))
    assert registry.authenticate_refresh(authentication(second)).identity == request.identity
    assert [item.action for item in registry.audit_records(NETWORK)] == [
        CoordinatorAuditAction.NODE_REGISTERED,
        CoordinatorAuditAction.CREDENTIAL_ROTATED,
    ]
    with pytest.raises(RegistryError) as token_proof:
        registry.register(request.model_copy(update={"enrollment_token": "x" * 48}))
    assert token_proof.value.code is CoordinatorErrorCode.CONFLICT

    secrets = MemorySecrets()
    credentials = AgentRefreshCredentialStore(secrets)
    credentials.save(second)
    name = coordinator_refresh_name(NETWORK, request.identity.node_id)
    assert secrets.values[name] == second.refresh_credential
    assert credentials.load(NETWORK, request.identity.node_id) == second.refresh_credential
    credentials.delete(NETWORK, request.identity.node_id)
    credentials.delete(NETWORK, request.identity.node_id)
    assert credentials.load(NETWORK, request.identity.node_id) is None

    reopened = service(tmp_path)
    assert reopened.authenticate_refresh(authentication(second)).identity == request.identity


def test_enrollment_expiry_replay_cross_network_and_version_fail_closed(
    tmp_path: Path,
) -> None:
    clock = MutableClock()
    registry = service(tmp_path, clock)
    registry.create_network(NETWORK)
    registry.create_network(OTHER_NETWORK)

    expired, _ = enrollment(registry, ttl=30)
    clock.now += timedelta(seconds=31)
    with pytest.raises(RegistryError) as expired_error:
        registry.register(registration(expired))
    assert expired_error.value.code is CoordinatorErrorCode.UNAUTHENTICATED

    token, _ = enrollment(registry)
    first = registry.register(registration(token, device="b" * 64, key="c" * 64))
    with pytest.raises(RegistryError) as replay:
        registry.register(registration(token, device="c" * 64, key="d" * 64))
    assert replay.value.code is CoordinatorErrorCode.UNAUTHENTICATED

    other_token, _ = enrollment(registry, network_id=OTHER_NETWORK)
    with pytest.raises(RegistryError) as cross_network:
        registry.register(registration(other_token, identity(network_id=NETWORK), key="e" * 64))
    assert cross_network.value.code is CoordinatorErrorCode.UNAUTHENTICATED

    version_token, _ = enrollment(registry)
    incompatible = identity(protocol=ProtocolVersion(major=2, minor=0))
    with pytest.raises(RegistryError) as version:
        registry.register(registration(version_token, incompatible, key="f" * 64))
    assert version.value.code is CoordinatorErrorCode.VERSION_INCOMPATIBLE
    assert (
        registry.authenticate_refresh(authentication(first)).identity.node_id
        == first.identity.node_id
    )


def test_multi_use_identity_conflicts_idempotency_conflict_and_revoked_reenrollment(
    tmp_path: Path,
) -> None:
    registry = service(tmp_path)
    registry.create_network(NETWORK)
    token, _ = enrollment(registry, max_uses=2)
    first_identity = identity()
    first_request = registration(token, first_identity, device="1" * 64, key="1" * 64)
    first = registry.register(first_request)
    registry.register(registration(token, device="2" * 64, key="2" * 64))
    with pytest.raises(RegistryError):
        registry.register(registration(token, device="3" * 64, key="3" * 64))

    with pytest.raises(RegistryError) as key_conflict:
        registry.register(
            registration(
                token,
                identity(first_identity.node_id, display_name="Changed"),
                device="1" * 64,
                key="1" * 64,
            )
        )
    assert key_conflict.value.code is CoordinatorErrorCode.CONFLICT

    occupied_token, _ = enrollment(registry, max_uses=2)
    with pytest.raises(RegistryError) as node_occupied:
        registry.register(
            registration(
                occupied_token,
                identity(first_identity.node_id),
                device="4" * 64,
                key="4" * 64,
            )
        )
    assert node_occupied.value.code is CoordinatorErrorCode.CONFLICT
    with pytest.raises(RegistryError) as device_occupied:
        registry.register(
            registration(
                occupied_token,
                identity(),
                device="1" * 64,
                key="5" * 64,
            )
        )
    assert device_occupied.value.code is CoordinatorErrorCode.CONFLICT

    registry.revoke_node(NETWORK, first.identity.node_id, reason="设备移除")
    with pytest.raises(RegistryError):
        registry.authenticate_refresh(authentication(first))
    with pytest.raises(RegistryError) as resume:
        registry.register(first_request)
    assert resume.value.code is CoordinatorErrorCode.FORBIDDEN
    reenroll, _ = enrollment(registry)
    with pytest.raises(RegistryError) as revoked_identity:
        registry.register(registration(reenroll, first_identity, device="1" * 64, key="6" * 64))
    assert revoked_identity.value.code is CoordinatorErrorCode.CONFLICT
    revoked = next(
        item
        for item in registry.list_nodes(NETWORK)
        if item.identity.node_id == first.identity.node_id
    )
    assert revoked.status is NodeStatus.REVOKED
    with pytest.raises(RegistryError):
        registry.revoke_node(NETWORK, first.identity.node_id, reason="重复")
    with pytest.raises(RegistryError):
        registry.revoke_node(NETWORK, NodeId.new(), reason="不存在")


def test_refresh_rotation_authentication_rejections_and_rate_limit_window(
    tmp_path: Path,
) -> None:
    clock = MutableClock()
    registry = service(tmp_path, clock, limit=2)
    registry.create_network(NETWORK)
    registry.create_network(OTHER_NETWORK)
    token, _ = enrollment(registry)
    registered = registry.register(registration(token))
    auth = authentication(registered)
    rotated = registry.rotate_refresh(auth)
    with pytest.raises(RegistryError):
        registry.authenticate_refresh(auth)
    with pytest.raises(RegistryError) as limited:
        registry.authenticate_refresh(authentication(rotated))
    assert limited.value.code is CoordinatorErrorCode.RATE_LIMITED

    clock.monotonic = 61
    assert registry.authenticate_refresh(authentication(rotated)).identity == registered.identity
    wrong_network = authentication(rotated).model_copy(update={"network_id": OTHER_NETWORK})
    with pytest.raises(RegistryError):
        registry.authenticate_refresh(wrong_network)

    clock.monotonic = 122
    wrong_secret = authentication(rotated).model_copy(update={"refresh_credential": "x" * 48})
    with pytest.raises(RegistryError):
        registry.authenticate_refresh(wrong_secret)
    with pytest.raises(RegistryError):
        registry.rotate_refresh(wrong_secret)
    clock.monotonic = 183
    wrong_protocol = authentication(rotated).model_copy(
        update={"protocol": ProtocolVersion(major=2, minor=0)}
    )
    with pytest.raises(RegistryError):
        registry.authenticate_refresh(wrong_protocol)

    assert [item.action for item in registry.audit_records(NETWORK)][-1] is (
        CoordinatorAuditAction.CREDENTIAL_ROTATED
    )


def test_atomic_enrollment_consumption_allows_only_one_concurrent_node(
    tmp_path: Path,
) -> None:
    registry = service(tmp_path)
    registry.create_network(NETWORK)
    token, _ = enrollment(registry)
    requests = (
        registration(token, device="7" * 64, key="7" * 64),
        registration(token, device="8" * 64, key="8" * 64),
    )

    def attempt(request: NodeRegistrationRequest) -> str:
        try:
            return str(registry.register(request).identity.node_id)
        except RegistryError as exc:
            return exc.code.value

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = tuple(executor.map(attempt, requests))
    assert sum(item.startswith("node_") for item in results) == 1
    assert results.count(CoordinatorErrorCode.UNAUTHENTICATED.value) == 1


def test_audit_optional_fields_and_clock_storage_failures_are_bounded(tmp_path: Path) -> None:
    registry = service(tmp_path)
    registry.create_network(NETWORK)
    with registry.store.connect() as connection:
        connection.execute(
            """INSERT INTO coordinator_audit(
                audit_id, network_id, node_id, server_revision, action,
                result, error_code, item_count, occurred_at
            ) VALUES (?, ?, NULL, 0, ?, ?, ?, 1, ?)""",
            (
                "coordaudit_0123456789abcdef0123456789abcdef",
                str(NETWORK),
                CoordinatorAuditAction.DIRECTORY_READ.value,
                "rejected",
                CoordinatorErrorCode.FORBIDDEN.value,
                NOW.isoformat(),
            ),
        )
    record = registry.audit_records(NETWORK)[0]
    assert record.node_id is None
    assert record.error_code is CoordinatorErrorCode.FORBIDDEN

    invalid_clock = CoordinatorRegistryService(
        SQLiteCoordinatorStore(tmp_path / "naive.sqlite3"),
        clock=lambda: datetime(2026, 7, 26),
    )
    with pytest.raises(ValueError, match="时区"):
        invalid_clock.create_network(NETWORK)
    with pytest.raises(ValueError, match="大于零"):
        CoordinatorRegistryService(
            SQLiteCoordinatorStore(tmp_path / "invalid.sqlite3"),
            refresh_attempts_per_minute=0,
        )

    broken = service(tmp_path / "broken")
    broken.create_network(NETWORK)
    token, _ = enrollment(broken)
    with broken.store.connect() as connection:
        connection.execute("DELETE FROM revisions WHERE network_id=?", (str(NETWORK),))
    with pytest.raises(RuntimeError, match="修订"):
        broken.register(registration(token))


def test_heartbeat_uses_server_time_and_progresses_freshness(tmp_path: Path) -> None:
    clock = MutableClock()
    registry = service(tmp_path, clock)
    registry.create_network(NETWORK)
    token, _ = enrollment(registry)
    registered = registry.register(registration(token))
    auth = authentication(registered)

    response = registry.heartbeat(
        auth,
        heartbeat_for(auth, sent_at=NOW + timedelta(days=365)),
    )
    assert response.received_at == NOW
    assert response.node_status is NodeStatus.ONLINE
    online = registry.list_nodes(NETWORK)[0]
    assert online.last_received_at == NOW
    assert online.last_agent_sent_at == NOW + timedelta(days=365)

    clock.now += timedelta(seconds=30)
    assert registry.refresh_node_states(NETWORK)[0].status is NodeStatus.STALE
    clock.now += timedelta(seconds=60)
    assert registry.refresh_node_states(NETWORK)[0].status is NodeStatus.OFFLINE
    restored = registry.heartbeat(auth, heartbeat_for(auth))
    assert restored.node_status is NodeStatus.ONLINE
    assert registry.refresh_node_states(NETWORK)[0].status is NodeStatus.ONLINE


def test_heartbeat_rejects_bad_binding_version_and_revocation(tmp_path: Path) -> None:
    registry = service(tmp_path)
    registry.create_network(NETWORK)
    token, _ = enrollment(registry)
    registered = registry.register(registration(token))
    auth = authentication(registered)
    mismatched = heartbeat_for(auth).model_copy(update={"node_id": NodeId.new()})
    with pytest.raises(RegistryError) as forbidden:
        registry.heartbeat(auth, mismatched)
    assert forbidden.value.code is CoordinatorErrorCode.FORBIDDEN

    incompatible = heartbeat_for(
        auth,
        protocol=ProtocolVersion(major=2, minor=0),
    )
    with pytest.raises(RegistryError) as version:
        registry.heartbeat(auth, incompatible)
    assert version.value.code is CoordinatorErrorCode.VERSION_INCOMPATIBLE
    node = registry.list_nodes(NETWORK)[0]
    assert node.status is NodeStatus.INCOMPATIBLE
    assert node.last_received_at is None
    assert registry.refresh_node_states(NETWORK)[0].status is NodeStatus.INCOMPATIBLE

    registry.revoke_node(NETWORK, auth.node_id, reason="lost")
    with pytest.raises(RegistryError) as revoked:
        registry.heartbeat(auth, heartbeat_for(auth))
    assert revoked.value.code is CoordinatorErrorCode.UNAUTHENTICATED
    assert registry.refresh_node_states(NETWORK)[0].status is NodeStatus.REVOKED


def test_admin_rotation_revocation_and_explicit_restore(tmp_path: Path) -> None:
    registry = service(tmp_path)
    registry.create_network(NETWORK)
    token, _ = enrollment(registry)
    registered = registry.register(registration(token))
    node_id = registered.identity.node_id
    rotated = registry.admin_rotate_refresh(NETWORK, node_id)
    with pytest.raises(RegistryError):
        registry.authenticate_refresh(authentication(registered))
    assert registry.authenticate_refresh(authentication(rotated)).identity.node_id == node_id

    registry.revoke_node(NETWORK, node_id, reason="compromised")
    restored = registry.restore_node(NETWORK, node_id)
    restored_node = registry.authenticate_refresh(authentication(restored))
    assert restored_node.status is NodeStatus.OFFLINE
    actions = tuple(record.action for record in registry.audit_records(NETWORK))
    assert CoordinatorAuditAction.NODE_RESTORED in actions
    with registry.store.connect() as connection:
        count = connection.execute(
            "SELECT COUNT(*) AS count FROM revocations WHERE node_id=?",
            (str(node_id),),
        ).fetchone()
    assert count is not None and count["count"] == 1

    with pytest.raises(RegistryError):
        registry.restore_node(NETWORK, node_id)
    registry.revoke_node(NETWORK, node_id, reason="again")
    with pytest.raises(RegistryError):
        registry.admin_rotate_refresh(NETWORK, node_id)


@pytest.mark.parametrize(
    ("stale", "offline"),
    [(0, 2), (10, 10)],
)
def test_heartbeat_policy_rejects_invalid_thresholds(stale: int, offline: int) -> None:
    with pytest.raises(ValueError):
        HeartbeatPolicy(
            stale_after_seconds=stale,
            offline_after_seconds=offline,
        )


def test_schema_v1_migration_adds_heartbeat_timestamps(tmp_path: Path) -> None:
    path = tmp_path / "legacy.sqlite3"
    with sqlite3.connect(path) as connection:
        connection.executescript(
            """
            CREATE TABLE schema_metadata (version INTEGER NOT NULL);
            INSERT INTO schema_metadata(version) VALUES (1);
            CREATE TABLE nodes (
                node_id TEXT PRIMARY KEY,
                network_id TEXT NOT NULL,
                device_identity_hash TEXT NOT NULL,
                identity_json TEXT NOT NULL,
                status TEXT NOT NULL,
                server_revision INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                revoked_at TEXT
            );
            """
        )
    store = SQLiteCoordinatorStore(path)
    with store.connect() as connection:
        columns = {row["name"] for row in connection.execute("PRAGMA table_info(nodes)").fetchall()}
    assert store.schema_version() == 3
    assert {"last_received_at", "last_agent_sent_at"} <= columns


def test_unheard_node_remains_offline_and_missing_status_row_fails(tmp_path: Path) -> None:
    registry = service(tmp_path)
    registry.create_network(NETWORK)
    token, _ = enrollment(registry)
    registry.register(registration(token))
    assert registry.refresh_node_states(NETWORK)[0].status is NodeStatus.OFFLINE

    with registry.store.connect() as connection, pytest.raises(RuntimeError, match="状态记录"):
        registry._change_status(  # pyright: ignore[reportPrivateUsage]
            connection,
            NETWORK,
            NodeId.new(),
            NodeStatus.OFFLINE,
            NodeStatus.OFFLINE,
            NOW,
        )


def test_heartbeat_rejects_naive_agent_timestamp() -> None:
    with pytest.raises(ValueError, match="时区"):
        HeartbeatRequest(
            network_id=NETWORK,
            node_id=NodeId.new(),
            sent_at=datetime(2026, 7, 26),
        )
