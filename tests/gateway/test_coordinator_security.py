"""Coordinator assertion 与 static token 共存的 Gateway 认证测试。"""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path

import pytest
from tests.coordinator.test_identity import online_identity_stack
from tests.coordinator.test_registry import NETWORK, NOW, MutableClock, identity

from tunnelminion.agent.coordinator import CoordinatorAuthorizationView, CoordinatorCache
from tunnelminion.coordinator.contracts import (
    DirectoryFreshness,
    DirectoryNodeSummary,
    NodeStatus,
    VerificationKeySet,
)
from tunnelminion.domain.identifiers import NodeId
from tunnelminion.gateway.security import (
    GatewayAuthenticationKind,
    GatewayManagedPeerPolicy,
    GatewayPeerPolicy,
    GatewaySecurityPolicy,
)

STATIC_TOKEN = "tmn_test-static-credential-with-more-than-thirty-two-characters"


def authorization_view(
    tmp_path: Path,
) -> tuple[
    MutableClock,
    VerificationKeySet,
    CoordinatorCache,
    DirectoryNodeSummary,
    str,
]:
    clock, _, keys, assertions, request = online_identity_stack(tmp_path)
    node = DirectoryNodeSummary(
        identity=identity(request.authentication.node_id),
        status=NodeStatus.ONLINE,
        freshness=DirectoryFreshness.FRESH,
        last_received_at=NOW,
        capability_count=1,
        service_count=0,
        server_revision=3,
    )
    key_set = keys.verification_keys()
    cache = CoordinatorCache()
    cache.replace(
        CoordinatorAuthorizationView(
            network_id=NETWORK,
            generated_at=NOW,
            expires_at=NOW + timedelta(seconds=60),
            nodes=(node,),
            verification_keys=key_set,
        )
    )
    assertion = assertions.issue(request).assertion
    return clock, key_set, cache, node, assertion


def test_managed_assertion_is_offline_verified_and_audience_bound(tmp_path: Path) -> None:
    clock, keys, cache, node, assertion = authorization_view(tmp_path)
    policy = GatewaySecurityPolicy(
        [],
        managed_peers=[
            GatewayManagedPeerPolicy(
                node.identity.node_id,
                frozenset({"get_node_summary"}),
            )
        ],
        coordinator_cache=cache,
        pinned_fingerprints={keys.keys[0].fingerprint},
        wall_clock=clock.utcnow,
    )

    peer = policy.authenticate(f"Bearer {assertion}", audience="tool-gateway")
    assert peer is not None
    assert peer.node_id == node.identity.node_id
    assert peer.authentication_kind is GatewayAuthenticationKind.COORDINATOR
    assert peer.allowed_operations == frozenset()
    assert policy.authenticate(f"Bearer {assertion}", audience="operation-gateway") is None
    assert policy.authenticate(f"Bearer {assertion}tampered") is None


def test_revocation_and_cache_expiry_fail_closed_without_breaking_static(
    tmp_path: Path,
) -> None:
    clock, keys, cache, node, assertion = authorization_view(tmp_path)
    static = GatewayPeerPolicy.from_token(
        node.identity.node_id,
        STATIC_TOKEN,
        {"get_node_summary"},
    )
    policy = GatewaySecurityPolicy(
        [static],
        managed_peers=[
            GatewayManagedPeerPolicy(
                node.identity.node_id,
                frozenset({"get_node_summary"}),
            )
        ],
        coordinator_cache=cache,
        pinned_fingerprints={keys.keys[0].fingerprint},
        wall_clock=clock.utcnow,
    )

    cache.replace(
        CoordinatorAuthorizationView(
            network_id=NETWORK,
            generated_at=NOW,
            expires_at=NOW + timedelta(seconds=60),
            nodes=(
                node.model_copy(
                    update={
                        "status": NodeStatus.REVOKED,
                        "freshness": DirectoryFreshness.REVOKED,
                    }
                ),
            ),
            verification_keys=keys,
        )
    )
    assert policy.authenticate(f"Bearer {assertion}") is None
    assert policy.authenticate(f"Bearer {STATIC_TOKEN}") == static
    cache.replace(
        CoordinatorAuthorizationView(
            network_id=NETWORK,
            generated_at=NOW,
            expires_at=NOW + timedelta(seconds=1),
            nodes=(node,),
            verification_keys=keys,
        )
    )
    clock.now += timedelta(seconds=2)
    assert policy.authenticate(f"Bearer {assertion}") is None
    assert policy.authenticate(f"Bearer {STATIC_TOKEN}") == static


def test_managed_policy_configuration_and_unknown_node_fail_closed(tmp_path: Path) -> None:
    clock, keys, cache, node, assertion = authorization_view(tmp_path)
    with pytest.raises(ValueError, match="至少需要"):
        GatewayManagedPeerPolicy(node.identity.node_id, frozenset())
    managed = GatewayManagedPeerPolicy(
        NodeId.new(),
        frozenset({"get_node_summary"}),
    )
    with pytest.raises(ValueError, match="不得重复"):
        GatewaySecurityPolicy(
            [],
            managed_peers=[managed, managed],
            coordinator_cache=cache,
        )
    with pytest.raises(ValueError, match="授权缓存"):
        GatewaySecurityPolicy([], managed_peers=[managed])

    policy = GatewaySecurityPolicy(
        [],
        managed_peers=[managed],
        coordinator_cache=cache,
        pinned_fingerprints={keys.keys[0].fingerprint},
        wall_clock=clock.utcnow,
    )
    assert policy.authenticate(f"Bearer {assertion}") is None
