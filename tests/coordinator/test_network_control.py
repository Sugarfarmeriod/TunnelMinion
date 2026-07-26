"""Coordinator 受管网络地址、签名配置与 saga 控制面测试。"""

from __future__ import annotations

import sqlite3
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path
from time import perf_counter
from typing import cast

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError
from tests.network.factories import (
    NETWORK_ID,
    NODE_A,
    NODE_B,
    PUBLIC_KEY_A,
    PUBLIC_KEY_B,
    candidate,
    desired,
    peer,
)

from tunnelminion.coordinator.contracts import CoordinatorErrorCode
from tunnelminion.coordinator.identity import SigningKeyService
from tunnelminion.coordinator.network_control import (
    AddressPoolRequest,
    EndpointCandidateReport,
    ManagedNetworkControlService,
    NetworkPublicKeyRequest,
    RelayRoleRequest,
    SagaStatus,
)
from tunnelminion.coordinator.registry import RegistryError, SQLiteCoordinatorStore
from tunnelminion.domain.identifiers import NetworkId, NodeId
from tunnelminion.network.contracts import (
    AcknowledgementStage,
    CandidateSource,
    DesiredNetworkConfig,
    LeaseStatus,
    NetworkAcknowledgement,
    NetworkError,
    NetworkErrorCode,
    ProviderKind,
    RelayRole,
    canonical_sha256,
)
from tunnelminion.network.signing import (
    DesiredConfigVerificationError,
    verify_signed_desired_config,
)

NOW = datetime(2026, 7, 26, 10, 0, tzinfo=UTC)
OTHER_NETWORK = NetworkId.new()
OTHER_NODE = NodeId.new()


class Clock:
    """可推进的 UTC 与单调测试时钟。"""

    def __init__(self) -> None:
        self.value = NOW
        self.monotonic_value = 100.0

    def utcnow(self) -> datetime:
        return self.value

    def monotonic(self) -> float:
        return self.monotonic_value


class MemorySecrets:
    """测试签名服务使用的进程内秘密后端。"""

    def __init__(self) -> None:
        self.values: dict[str, str] = {}

    def get(self, name: str) -> str | None:
        return self.values.get(name)

    def set(self, name: str, value: str) -> None:
        self.values[name] = value

    def delete(self, name: str) -> None:
        self.values.pop(name, None)


def stack(
    tmp_path: Path, *, candidate_limit: int = 30
) -> tuple[ManagedNetworkControlService, SQLiteCoordinatorStore, SigningKeyService, Clock]:
    """创建带两个 network 和三个已登记节点的控制面。"""
    clock = Clock()
    store = SQLiteCoordinatorStore(tmp_path / "network-control.sqlite3")
    keys = SigningKeyService(store, MemorySecrets(), clock=clock.utcnow)
    keys.rotate()
    service = ManagedNetworkControlService(
        store,
        keys,
        clock=clock.utcnow,
        monotonic_clock=clock.monotonic,
        candidate_updates_per_minute=candidate_limit,
    )
    service.create_network(NETWORK_ID)
    service.create_network(OTHER_NETWORK)
    _insert_node(store, NETWORK_ID, NODE_A)
    _insert_node(store, NETWORK_ID, NODE_B)
    _insert_node(store, OTHER_NETWORK, OTHER_NODE)
    return service, store, keys, clock


def _insert_node(store: SQLiteCoordinatorStore, network_id: NetworkId, node_id: NodeId) -> None:
    with store.connect() as connection:
        connection.execute(
            """INSERT INTO nodes(
                node_id, network_id, device_identity_hash, identity_json,
                status, server_revision, created_at
            ) VALUES (?, ?, ?, '{}', 'online', 1, ?)""",
            (str(node_id), str(network_id), f"{node_id!s:0<64}"[:64], NOW.isoformat()),
        )


def _error() -> NetworkError:
    return NetworkError(
        code=NetworkErrorCode.VERIFY_FAILED,
        message="独立验证失败",
        correlation_id="test-correlation",
    )


def _ack(
    node_id: NodeId,
    revision: int,
    stage: AcknowledgementStage,
    *,
    error: NetworkError | None = None,
) -> NetworkAcknowledgement:
    return NetworkAcknowledgement(
        network_id=NETWORK_ID,
        node_id=node_id,
        revision=revision,
        stage=stage,
        plan_hash=canonical_sha256({"node": str(node_id)}) if stage.value >= "applied" else None,
        receipt_hash=canonical_sha256({"receipt": str(node_id)})
        if stage.value >= "applied"
        else None,
        error=error,
        acknowledged_at=NOW,
    )


def _two_configs(
    service: ManagedNetworkControlService, *, parent_revision: int = 0
) -> tuple[DesiredNetworkConfig, DesiredNetworkConfig]:
    revision = service.next_revision(NETWORK_ID)
    first = desired(revision=revision, parent_revision=parent_revision)
    second = desired(
        target_node_id=NODE_B,
        provider=ProviderKind.MACOS,
        revision=revision,
        parent_revision=parent_revision,
        interface_name="tmn-test-b",
        address="10.203.0.2/32",
        peers=(
            peer(
                node_id=NODE_A,
                public_key=PUBLIC_KEY_A,
                allowed_host_routes=("10.203.0.1/32",),
            ),
        ),
    )
    return first, second


def test_address_pool_and_transactional_stable_leases(tmp_path: Path) -> None:
    service, store, keys, _ = stack(tmp_path)
    with pytest.raises(ValueError):
        ManagedNetworkControlService(store, keys, candidate_updates_per_minute=0)
    request = AddressPoolRequest(
        pool="10.203.0.0/29",
        reserved_addresses=("10.203.0.1",),
    )
    assert service.configure_address_pool(NETWORK_ID, request) == (
        service.configure_address_pool(NETWORK_ID, request)
    )
    assert len(service.list_address_pools(NETWORK_ID)) == 1

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = (
            executor.submit(service.allocate_address, NETWORK_ID, node, pool=request.pool)
            for node in (NODE_A, NODE_B)
        )
        leases = tuple(future.result() for future in futures)
    assert {item.address for item in leases} == {"10.203.0.2/32", "10.203.0.3/32"}
    assert (
        service.allocate_address(NETWORK_ID, NODE_A, pool=request.pool).address == leases[0].address
    )

    active = service.set_lease_status(NETWORK_ID, NODE_A, LeaseStatus.ACTIVE)
    released = service.set_lease_status(NETWORK_ID, NODE_A, LeaseStatus.RELEASED)
    restored = service.set_lease_status(NETWORK_ID, NODE_A, LeaseStatus.ACTIVE)
    assert active.status is LeaseStatus.ACTIVE
    assert released.status is LeaseStatus.RELEASED
    assert restored.address == active.address


def test_address_pool_conflicts_exhaustion_and_recovery_collision(tmp_path: Path) -> None:
    service, store, _, _ = stack(tmp_path)
    service.configure_address_pool(NETWORK_ID, AddressPoolRequest(pool="10.10.0.0/30"))
    with pytest.raises(RegistryError) as overlap:
        service.configure_address_pool(OTHER_NETWORK, AddressPoolRequest(pool="10.10.0.0/29"))
    assert overlap.value.code is CoordinatorErrorCode.CONFLICT
    with pytest.raises(RegistryError):
        service.configure_address_pool(
            NETWORK_ID,
            AddressPoolRequest(pool="10.10.0.0/30", reserved_addresses=("10.10.0.1",)),
        )
    service.configure_address_pool(
        OTHER_NETWORK,
        AddressPoolRequest(pool="10.11.0.0/30"),
    )

    first = service.allocate_address(NETWORK_ID, NODE_A, pool="10.10.0.0/30")
    service.set_lease_status(NETWORK_ID, NODE_A, LeaseStatus.ACTIVE)
    service.set_lease_status(NETWORK_ID, NODE_A, LeaseStatus.RELEASED)
    second = service.allocate_address(NETWORK_ID, NODE_B, pool="10.10.0.0/30")
    assert second.address == first.address
    with pytest.raises(RegistryError, match="不能静默重新编号"):
        service.set_lease_status(NETWORK_ID, NODE_A, LeaseStatus.ACTIVE)
    reassigned = service.allocate_address(NETWORK_ID, NODE_A, pool="10.10.0.0/30")
    assert reassigned.address != first.address
    third = NodeId.new()
    _insert_node(store, NETWORK_ID, third)
    with pytest.raises(RegistryError, match="没有可用地址"):
        service.allocate_address(NETWORK_ID, third, pool="10.10.0.0/30")


def test_pool_and_lease_validation_rejects_unsafe_transitions(tmp_path: Path) -> None:
    service, _, _, _ = stack(tmp_path)
    with pytest.raises(ValidationError):
        AddressPoolRequest(pool="8.8.8.0/24")
    with pytest.raises(ValidationError):
        AddressPoolRequest(pool="10.0.0.0/8")
    with pytest.raises(ValidationError):
        AddressPoolRequest(pool="10.0.0.0/30", reserved_addresses=("10.0.1.1",))
    with pytest.raises(ValidationError):
        AddressPoolRequest(
            pool="10.0.0.0/30",
            reserved_addresses=("10.0.0.1", "10.0.0.1"),
        )
    with pytest.raises(RegistryError):
        service.allocate_address(NETWORK_ID, NODE_A, pool="10.0.0.0/30")
    service.configure_address_pool(NETWORK_ID, AddressPoolRequest(pool="10.0.0.0/30"))
    reserved = service.allocate_address(NETWORK_ID, NODE_A, pool="10.0.0.0/30")
    assert service.set_lease_status(NETWORK_ID, NODE_A, LeaseStatus.RESERVED) == reserved
    service.set_lease_status(NETWORK_ID, NODE_A, LeaseStatus.RELEASED)
    with pytest.raises(RegistryError) as invalid:
        service.set_lease_status(NETWORK_ID, NODE_A, LeaseStatus.RESERVED)
    assert invalid.value.code is CoordinatorErrorCode.OUT_OF_ORDER
    with pytest.raises(RegistryError):
        service.set_lease_status(NETWORK_ID, NODE_B, LeaseStatus.ACTIVE)


def test_released_lease_recovers_same_address_when_still_free(tmp_path: Path) -> None:
    service, _, _, _ = stack(tmp_path)
    service.configure_address_pool(NETWORK_ID, AddressPoolRequest(pool="10.12.0.0/30"))
    first = service.allocate_address(NETWORK_ID, NODE_A, pool="10.12.0.0/30")
    service.set_lease_status(NETWORK_ID, NODE_A, LeaseStatus.RELEASED)
    recovered = service.allocate_address(NETWORK_ID, NODE_A, pool="10.12.0.0/30")
    assert recovered.address == first.address


def test_public_key_lifecycle_rejects_secrets_and_cross_network(tmp_path: Path) -> None:
    service, _, _, _ = stack(tmp_path)
    with pytest.raises(ValidationError):
        NetworkPublicKeyRequest.model_validate(
            {"public_key": PUBLIC_KEY_A, "private_key": "secret"}
        )
    with pytest.raises(ValidationError):
        NetworkPublicKeyRequest.model_validate(
            {
                "public_key": PUBLIC_KEY_A,
                "configuration": desired().model_dump(mode="json"),
            }
        )
    pending_a = service.register_public_key(
        NETWORK_ID, NODE_A, NetworkPublicKeyRequest(public_key=PUBLIC_KEY_A)
    )
    assert pending_a == service.register_public_key(
        NETWORK_ID, NODE_A, NetworkPublicKeyRequest(public_key=PUBLIC_KEY_A)
    )
    active_a = service.activate_public_key(NETWORK_ID, NODE_A, PUBLIC_KEY_A)
    assert active_a.status.value == "active"
    assert service.activate_public_key(NETWORK_ID, NODE_A, PUBLIC_KEY_A) == active_a
    service.register_public_key(
        NETWORK_ID, NODE_A, NetworkPublicKeyRequest(public_key=PUBLIC_KEY_B)
    )
    active_b = service.activate_public_key(NETWORK_ID, NODE_A, PUBLIC_KEY_B)
    keys = service.list_public_keys(NETWORK_ID, NODE_A)
    assert active_b.status.value == "active"
    assert [item.status.value for item in keys] == ["retired", "active"]
    with pytest.raises(RegistryError):
        service.activate_public_key(NETWORK_ID, NODE_A, PUBLIC_KEY_A)
    with pytest.raises(RegistryError):
        service.activate_public_key(NETWORK_ID, NODE_B, PUBLIC_KEY_A)
    with pytest.raises(RegistryError):
        service.register_public_key(
            OTHER_NETWORK, NODE_A, NetworkPublicKeyRequest(public_key=PUBLIC_KEY_A)
        )


def test_candidate_source_ttl_size_freshness_and_rate_budgets(tmp_path: Path) -> None:
    service, _, _, _ = stack(tmp_path, candidate_limit=20)
    accepted = candidate(
        observed_at=NOW,
        expires_at=NOW + timedelta(minutes=5),
        source=CandidateSource.NODE_OBSERVED,
    )
    assert service.replace_candidates(
        NETWORK_ID, NODE_A, EndpointCandidateReport(candidates=(accepted,))
    ) == (accepted,)
    assert service.fresh_candidates(NETWORK_ID, NODE_A) == (accepted,)
    with pytest.raises(RegistryError):
        service.replace_candidates(
            NETWORK_ID,
            NODE_A,
            EndpointCandidateReport(candidates=(candidate(expires_at=NOW + timedelta(hours=2)),)),
        )
    with pytest.raises(RegistryError):
        service.replace_candidates(
            OTHER_NETWORK,
            NODE_A,
            EndpointCandidateReport(candidates=(accepted,)),
        )
    with pytest.raises(RegistryError):
        service.replace_candidates(
            NETWORK_ID,
            NODE_A,
            EndpointCandidateReport(candidates=(accepted, accepted)),
        )
    with pytest.raises(RegistryError):
        service.replace_candidates(
            NETWORK_ID,
            NODE_A,
            EndpointCandidateReport(
                candidates=(
                    candidate(
                        observed_at=NOW - timedelta(minutes=10),
                        expires_at=NOW - timedelta(minutes=1),
                    ),
                )
            ),
        )
    oversized = tuple(
        candidate(
            host=f"2001:db8::{index + 1}",
            port=18_000 + index,
            observed_at=NOW,
            expires_at=NOW + timedelta(minutes=5),
        )
        for index in range(8)
    )
    with pytest.raises(RegistryError) as too_large:
        service.replace_candidates(
            NETWORK_ID,
            NODE_A,
            EndpointCandidateReport(candidates=oversized),
        )
    assert too_large.value.code is CoordinatorErrorCode.SNAPSHOT_TOO_LARGE
    with pytest.raises(ValidationError):
        EndpointCandidateReport.model_validate({"candidates": [], "model_endpoint": "10.0.0.1:9"})

    limited, _, _, limited_clock = stack(tmp_path / "limited", candidate_limit=2)
    limited.replace_candidates(NETWORK_ID, NODE_A, EndpointCandidateReport())
    limited.replace_candidates(NETWORK_ID, NODE_A, EndpointCandidateReport())
    with pytest.raises(RegistryError) as rate_limited:
        limited.replace_candidates(NETWORK_ID, NODE_A, EndpointCandidateReport())
    assert rate_limited.value.code is CoordinatorErrorCode.RATE_LIMITED
    limited_clock.monotonic_value += 60
    assert limited.replace_candidates(NETWORK_ID, NODE_A, EndpointCandidateReport()) == ()


def test_relay_role_requires_explicit_capability_and_is_idempotent(tmp_path: Path) -> None:
    service, _, _, _ = stack(tmp_path)
    with pytest.raises(ValidationError):
        RelayRoleRequest(role=RelayRole.ACTIVE)
    capable = service.set_relay_role(
        NETWORK_ID,
        NODE_A,
        RelayRoleRequest(role=RelayRole.CAPABLE, capability_verified=True),
    )
    active = service.set_relay_role(
        NETWORK_ID,
        NODE_A,
        RelayRoleRequest(role=RelayRole.ACTIVE, capability_verified=True),
    )
    assert active == service.set_relay_role(
        NETWORK_ID,
        NODE_A,
        RelayRoleRequest(role=RelayRole.ACTIVE, capability_verified=True),
    )
    assert capable.revision < active.revision


def test_domain_separated_config_signing_and_offline_verification(tmp_path: Path) -> None:
    service, _, keys, clock = stack(tmp_path)
    with pytest.raises(RegistryError):
        service.next_revision(NetworkId.new())
    with pytest.raises(ValueError):
        service.publish_desired_configs(())
    configs = _two_configs(service)
    with pytest.raises(ValueError):
        service.publish_desired_configs(configs, ttl_seconds=1)
    with pytest.raises(RegistryError):
        service.publish_desired_configs(
            (
                configs[0],
                configs[1].model_copy(update={"revision": configs[1].revision + 1}),
            )
        )
    with pytest.raises(RegistryError):
        service.publish_desired_configs((configs[0], configs[0]))
    envelopes = service.publish_desired_configs(configs)
    assert envelopes == service.publish_desired_configs(configs)
    verification_keys = keys.verification_keys().keys
    pins = {envelopes[0].key_fingerprint}
    verified = verify_signed_desired_config(
        envelopes[0],
        verification_keys,
        pins,
        network_id=NETWORK_ID,
        target_node_id=NODE_A,
        parent_revision=0,
        now=NOW,
    )
    assert verified == configs[0]

    with pytest.raises(DesiredConfigVerificationError):
        verify_signed_desired_config(
            envelopes[0],
            verification_keys,
            pins,
            network_id=NETWORK_ID,
            target_node_id=NODE_B,
            parent_revision=0,
            now=NOW,
        )
    with pytest.raises(DesiredConfigVerificationError):
        verify_signed_desired_config(
            envelopes[0],
            (),
            pins,
            network_id=NETWORK_ID,
            target_node_id=NODE_A,
            parent_revision=0,
            now=NOW,
        )
    future_key = verification_keys[0].model_copy(
        update={"activates_at": NOW + timedelta(minutes=1)}
    )
    with pytest.raises(DesiredConfigVerificationError):
        verify_signed_desired_config(
            envelopes[0],
            (future_key,),
            pins,
            network_id=NETWORK_ID,
            target_node_id=NODE_A,
            parent_revision=0,
            now=NOW,
        )
    retired_key = verification_keys[0].model_copy(update={"retires_at": NOW})
    with pytest.raises(DesiredConfigVerificationError):
        verify_signed_desired_config(
            envelopes[0],
            (retired_key,),
            pins,
            network_id=NETWORK_ID,
            target_node_id=NODE_A,
            parent_revision=0,
            now=NOW,
        )
    with pytest.raises(DesiredConfigVerificationError):
        verify_signed_desired_config(
            envelopes[0],
            verification_keys,
            set(),
            network_id=NETWORK_ID,
            target_node_id=NODE_A,
            parent_revision=0,
            now=NOW,
        )
    tampered = envelopes[0].model_copy(update={"signature": "A" * len(envelopes[0].signature)})
    with pytest.raises(DesiredConfigVerificationError):
        verify_signed_desired_config(
            tampered,
            verification_keys,
            pins,
            network_id=NETWORK_ID,
            target_node_id=NODE_A,
            parent_revision=0,
            now=NOW,
        )
    clock.value += timedelta(hours=1)
    with pytest.raises(DesiredConfigVerificationError):
        verify_signed_desired_config(
            envelopes[0],
            verification_keys,
            pins,
            network_id=NETWORK_ID,
            target_node_id=NODE_A,
            parent_revision=0,
            now=clock.value,
        )
    naive_now = NOW.replace(tzinfo=None)
    assert (
        verify_signed_desired_config(
            envelopes[0],
            verification_keys,
            pins,
            network_id=NETWORK_ID,
            target_node_id=NODE_A,
            parent_revision=0,
            now=naive_now,
        )
        == configs[0]
    )


def test_signature_rejects_public_key_fingerprint_mismatch(tmp_path: Path) -> None:
    service, _, keys, _ = stack(tmp_path)
    envelope = service.publish_desired_configs(_two_configs(service))[0]
    wrong = keys.verification_keys().keys[0].model_copy(update={"public_key": _public_key()})
    with pytest.raises(DesiredConfigVerificationError):
        verify_signed_desired_config(
            envelope,
            (wrong,),
            {envelope.key_fingerprint},
            network_id=NETWORK_ID,
            target_node_id=NODE_A,
            parent_revision=0,
            now=NOW,
        )


def _public_key() -> str:
    private = Ed25519PrivateKey.generate()
    import base64

    from cryptography.hazmat.primitives import serialization

    raw = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def test_revision_saga_activates_only_after_all_nodes_verify(tmp_path: Path) -> None:
    service, _, _, _ = stack(tmp_path)
    envelopes = service.publish_desired_configs(_two_configs(service))
    revision = envelopes[0].config.revision
    pending = service.acknowledge(_ack(NODE_A, revision, AcknowledgementStage.APPLIED))
    assert pending.status is SagaStatus.PENDING
    service.acknowledge(_ack(NODE_A, revision, AcknowledgementStage.VERIFIED))
    active = service.acknowledge(_ack(NODE_B, revision, AcknowledgementStage.VERIFIED))
    assert active.status is SagaStatus.ACTIVE
    assert active.rollback_node_ids == ()
    assert service.get_saga(NETWORK_ID, revision) == active


def test_revision_saga_partial_failure_requests_idempotent_rollback(tmp_path: Path) -> None:
    service, _, _, _ = stack(tmp_path)
    revision = service.publish_desired_configs(_two_configs(service))[0].config.revision
    applied = _ack(NODE_A, revision, AcknowledgementStage.APPLIED)
    assert service.acknowledge(applied) == service.acknowledge(applied)
    failed = service.acknowledge(
        _ack(
            NODE_B,
            revision,
            AcknowledgementStage.MANUAL_INTERVENTION,
            error=_error(),
        )
    )
    assert failed.status is SagaStatus.ROLLING_BACK
    assert failed.rollback_node_ids == (NODE_A,)
    rolled_back = service.acknowledge(_ack(NODE_A, revision, AcknowledgementStage.ROLLED_BACK))
    assert rolled_back.status is SagaStatus.MANUAL_INTERVENTION
    with pytest.raises(RegistryError) as out_of_order:
        service.acknowledge(_ack(NODE_A, revision, AcknowledgementStage.APPLIED))
    assert out_of_order.value.code is CoordinatorErrorCode.OUT_OF_ORDER
    with pytest.raises(RegistryError):
        service.acknowledge(_ack(OTHER_NODE, revision, AcknowledgementStage.PENDING))
    with pytest.raises(RegistryError):
        service.acknowledge(_ack(NODE_A, revision + 100, AcknowledgementStage.PENDING))
    with pytest.raises(RegistryError):
        service.get_saga(NETWORK_ID, revision + 100)


def test_revision_saga_records_complete_rollback(tmp_path: Path) -> None:
    service, _, _, _ = stack(tmp_path)
    revision = service.publish_desired_configs(_two_configs(service))[0].config.revision
    service.acknowledge(_ack(NODE_A, revision, AcknowledgementStage.ROLLED_BACK))
    rolled_back = service.acknowledge(_ack(NODE_B, revision, AcknowledgementStage.ROLLED_BACK))
    assert rolled_back.status is SagaStatus.ROLLED_BACK


def test_publish_rejects_revision_conflict_and_survives_database_restart(
    tmp_path: Path,
) -> None:
    service, store, keys, clock = stack(tmp_path)
    configs = _two_configs(service)
    envelopes = service.publish_desired_configs(configs)
    conflicting = configs[0].model_copy(update={"interface_name": "tmn-conflict"})
    with pytest.raises(RegistryError):
        service.publish_desired_configs((conflicting, configs[1]))

    reopened_store = SQLiteCoordinatorStore(store.path)
    reopened = ManagedNetworkControlService(
        reopened_store,
        keys,
        clock=clock.utcnow,
        monotonic_clock=clock.monotonic,
    )
    restored = reopened.get_saga(NETWORK_ID, envelopes[0].config.revision)
    assert {str(item) for item in restored.required_node_ids} == {
        str(NODE_A),
        str(NODE_B),
    }
    with pytest.raises(RegistryError):
        reopened.publish_desired_configs(
            (
                desired(
                    revision=envelopes[0].config.revision + 10,
                    parent_revision=envelopes[0].config.revision,
                ),
            )
        )


def test_ack_schema_does_not_store_error_message_in_columns(tmp_path: Path) -> None:
    service, store, _, _ = stack(tmp_path)
    revision = service.publish_desired_configs(_two_configs(service))[0].config.revision
    service.acknowledge(
        _ack(
            NODE_A,
            revision,
            AcknowledgementStage.MANUAL_INTERVENTION,
            error=_error(),
        )
    )
    with store.connect() as connection:
        row = cast(
            sqlite3.Row,
            connection.execute(
                "SELECT * FROM network_acknowledgements WHERE node_id=?",
                (str(NODE_A),),
            ).fetchone(),
        )
    assert row["error_code"] == NetworkErrorCode.VERIFY_FAILED.value
    assert "private_key" not in cast(str, row["error_json"])


def test_control_plane_storage_growth_is_linear_and_bounded(tmp_path: Path) -> None:
    """保留 revision 历史时按节点线性增长，易变候选则原位替换。"""
    service, store, _, _ = stack(tmp_path, candidate_limit=200)
    started = perf_counter()
    parent_revision = 0
    for index in range(20):
        endpoint = candidate(
            host=f"2001:db8::{index + 1}",
            port=18_000 + index,
            observed_at=NOW,
            expires_at=NOW + timedelta(minutes=5),
        )
        service.replace_candidates(
            NETWORK_ID,
            NODE_A,
            EndpointCandidateReport(candidates=(endpoint,)),
        )
        configs = _two_configs(service, parent_revision=parent_revision)
        revision = service.publish_desired_configs(configs)[0].config.revision
        service.acknowledge(_ack(NODE_A, revision, AcknowledgementStage.VERIFIED))
        service.acknowledge(_ack(NODE_B, revision, AcknowledgementStage.VERIFIED))
        parent_revision = revision

    with store.connect() as connection:
        counts = {
            table: cast(
                int,
                connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0],
            )
            for table in (
                "network_endpoint_candidates",
                "network_sagas",
                "network_desired_configs",
                "network_acknowledgements",
            )
        }
    assert counts == {
        "network_endpoint_candidates": 1,
        "network_sagas": 20,
        "network_desired_configs": 40,
        "network_acknowledgements": 40,
    }
    assert store.path.stat().st_size < 2_000_000
    assert perf_counter() - started < 10
