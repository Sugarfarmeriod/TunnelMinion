"""受管网络测试使用的稳定 fixture。"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from tunnelminion.domain.identifiers import NetworkId, NodeId, ResourceId
from tunnelminion.network.contracts import (
    AddressLease,
    CandidateSource,
    DesiredNetworkConfig,
    EndpointCandidate,
    KeyLifecycle,
    LeaseStatus,
    ManagedResourceOwnership,
    NetworkIdentity,
    NetworkObservation,
    OwnershipState,
    PeerConfiguration,
    ProviderKind,
    ProviderMode,
    RelayRole,
    canonical_sha256,
)

NOW = datetime(2026, 7, 26, 9, 0, tzinfo=UTC)
NETWORK_ID = NetworkId.new()
NODE_A = NodeId.new()
NODE_B = NodeId.new()
PUBLIC_KEY_A = f"{'A' * 43}="
PUBLIC_KEY_B = f"{'B' * 43}="


def candidate(**updates: object) -> EndpointCandidate:
    values: dict[str, object] = {
        "host": "203.0.113.10",
        "port": 18889,
        "source": CandidateSource.ADMIN_EXPLICIT,
        "observed_at": NOW,
        "expires_at": NOW + timedelta(minutes=5),
    }
    values.update(updates)
    return EndpointCandidate.model_validate(values)


def lease(**updates: object) -> AddressLease:
    values: dict[str, object] = {
        "network_id": NETWORK_ID,
        "node_id": NODE_A,
        "address": "10.203.0.1/32",
        "pool": "10.203.0.0/24",
        "revision": 1,
        "status": LeaseStatus.RESERVED,
    }
    values.update(updates)
    return AddressLease.model_validate(values)


def identity(**updates: object) -> NetworkIdentity:
    values: dict[str, object] = {
        "network_id": NETWORK_ID,
        "node_id": NODE_A,
        "provider": ProviderKind.WINDOWS,
        "public_key": PUBLIC_KEY_A,
        "key_lifecycle": KeyLifecycle.ACTIVE,
        "secret_reference_configured": True,
        "lease": lease(),
        "candidates": (candidate(),),
        "relay_role": RelayRole.NONE,
    }
    values.update(updates)
    return NetworkIdentity.model_validate(values)


def peer(**updates: object) -> PeerConfiguration:
    values: dict[str, object] = {
        "node_id": NODE_B,
        "public_key": PUBLIC_KEY_B,
        "allowed_host_routes": ("10.203.0.2/32",),
        "candidates": (candidate(),),
        "persistent_keepalive_seconds": 25,
        "relay_role": RelayRole.NONE,
    }
    values.update(updates)
    return PeerConfiguration.model_validate(values)


def desired(**updates: object) -> DesiredNetworkConfig:
    values: dict[str, object] = {
        "network_id": NETWORK_ID,
        "target_node_id": NODE_A,
        "provider": ProviderKind.WINDOWS,
        "revision": 1,
        "parent_revision": 0,
        "interface_name": "tmn-test-a",
        "address": "10.203.0.1/32",
        "peers": (peer(),),
        "relay_policy": RelayRole.NONE,
    }
    values.update(updates)
    return DesiredNetworkConfig.model_validate(values)


def observation(
    *,
    ownership_state: OwnershipState = OwnershipState.ABSENT,
    mode: ProviderMode = ProviderMode.MANAGED,
    **updates: object,
) -> NetworkObservation:
    managed = ownership_state is OwnershipState.MANAGED_OWNED
    values: dict[str, object] = {
        "provider": ProviderKind.WINDOWS,
        "mode": mode,
        "interface_name": "tmn-test-a",
        "stable_interface_id": "fake:tmn-test-a" if managed else None,
        "addresses": ("10.203.0.1/32",) if managed else (),
        "host_routes": ("10.203.0.2/32",) if managed else (),
        "public_key_hash": canonical_sha256({"key": "a"}) if managed else None,
        "ownership": ownership_state,
        "system_fingerprint": canonical_sha256(
            {"interface": "tmn-test-a", "ownership": ownership_state}
        ),
        "observed_at": NOW,
    }
    values.update(updates)
    return NetworkObservation.model_validate(values)


def ownership(observed: NetworkObservation) -> ManagedResourceOwnership:
    assert observed.stable_interface_id is not None
    assert observed.public_key_hash is not None
    return ManagedResourceOwnership(
        resource_id=ResourceId.new(),
        network_id=NETWORK_ID,
        node_id=NODE_A,
        provider=ProviderKind.WINDOWS,
        interface_name="tmn-test-a",
        stable_interface_id=observed.stable_interface_id,
        creation_nonce="a" * 32,
        public_key_hash=observed.public_key_hash,
        parent_revision=0,
        desired_config_hash=canonical_sha256(desired().model_dump(mode="json")),
        system_fingerprint=observed.system_fingerprint,
    )
