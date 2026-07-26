"""Coordinator 签名 key、短期 assertion 与离线验签安全边界测试。"""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from tests.coordinator.test_registry import (
    NETWORK,
    NOW,
    MemorySecrets,
    MutableClock,
    authentication,
    enrollment,
    registration,
    service,
)

from tunnelminion.coordinator.contracts import (
    AccessAssertionRequest,
    NodeStatus,
)
from tunnelminion.coordinator.identity import (
    ASSERTION_ISSUER,
    AssertionService,
    AssertionVerificationError,
    OfflineAssertionVerifier,
    SigningKeyService,
)
from tunnelminion.coordinator.registry import RegistryError
from tunnelminion.domain.identifiers import NetworkId, NodeId


def online_identity_stack(
    tmp_path: Path,
) -> tuple[
    MutableClock,
    MemorySecrets,
    SigningKeyService,
    AssertionService,
    AccessAssertionRequest,
]:
    clock = MutableClock()
    registry = service(tmp_path, clock)
    registry.create_network(NETWORK)
    token, _ = enrollment(registry)
    registered = registry.register(registration(token))
    auth = authentication(registered)
    from tunnelminion.coordinator.contracts import HeartbeatRequest

    registry.heartbeat(
        auth,
        HeartbeatRequest(
            network_id=auth.network_id,
            node_id=auth.node_id,
            sent_at=NOW,
        ),
    )
    secrets = MemorySecrets()
    keys = SigningKeyService(registry.store, secrets, clock=clock.utcnow)
    keys.rotate()
    assertions = AssertionService(registry, keys, clock=clock.utcnow)
    request = AccessAssertionRequest(
        authentication=auth,
        audience="tool-gateway",
    )
    return clock, secrets, keys, assertions, request


def test_key_rotation_secret_separation_publication_and_destruction(
    tmp_path: Path,
) -> None:
    clock, secrets, keys, _, _ = online_identity_stack(tmp_path)
    first = keys.active_signer()[0]
    assert first.private_key_reference in secrets.values
    assert first.public_key not in secrets.values.values()
    assert keys.verification_keys().keys[0].fingerprint == first.fingerprint

    clock.now += timedelta(seconds=1)
    second = keys.rotate(overlap_seconds=120)
    published = keys.verification_keys()
    assert {key.key_id for key in published.keys} == {first.key_id, second.key_id}
    assert keys.active_signer()[0].key_id == second.key_id

    clock.now += timedelta(seconds=120)
    assert keys.destroy_retired() == 1
    assert keys.destroy_retired() == 0
    assert first.private_key_reference not in secrets.values
    assert tuple(key.key_id for key in keys.verification_keys().keys) == (second.key_id,)
    keys.rotate()


def test_signing_key_fail_closed_paths(tmp_path: Path) -> None:
    clock = MutableClock()
    registry = service(tmp_path, clock)
    secrets = MemorySecrets()
    keys = SigningKeyService(registry.store, secrets, clock=clock.utcnow)
    with pytest.raises(ValueError, match="TTL"):
        keys.rotate(overlap_seconds=119)
    with pytest.raises(RuntimeError, match="没有可用"):
        keys.active_signer()
    with pytest.raises(RuntimeError, match="没有可发布"):
        keys.verification_keys()
    metadata = keys.rotate()
    secrets.delete(metadata.private_key_reference)
    with pytest.raises(RuntimeError, match="不可用"):
        keys.active_signer()
    secrets.set(metadata.private_key_reference, "invalid")
    with pytest.raises(RuntimeError, match="无效"):
        keys.active_signer()
    clock.now = clock.now.replace(tzinfo=None)
    with pytest.raises(ValueError, match="时区"):
        keys.verification_keys()


def test_key_metadata_failure_removes_new_secret(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registry = service(tmp_path)
    secrets = MemorySecrets()
    keys = SigningKeyService(registry.store, secrets, clock=lambda: NOW)

    def reject_metadata(_: object) -> None:
        raise OSError("disk unavailable")

    monkeypatch.setattr(registry.store, "put_signing_key", reject_metadata)
    with pytest.raises(OSError, match="disk"):
        keys.rotate()
    assert secrets.values == {}


def test_issue_and_verify_bound_assertion_with_bounded_replay(tmp_path: Path) -> None:
    clock, _, keys, assertions, request = online_identity_stack(tmp_path)
    issued = assertions.issue(request)
    key_set = keys.verification_keys()
    verifier = OfflineAssertionVerifier(
        key_set,
        {key_set.keys[0].fingerprint},
        clock=clock.utcnow,
    )
    expected_node = request.authentication.node_id
    verified = verifier.verify(
        issued.assertion,
        audience="tool-gateway",
        network_id=NETWORK,
        node_id=expected_node,
    )
    replay = verifier.verify(
        issued.assertion,
        audience="tool-gateway",
        network_id=NETWORK,
        node_id=expected_node,
    )
    assert verified == replay
    assert verified.expires_at - verified.issued_at == timedelta(seconds=120)
    assert issued.key_id == verified.key_id

    clock.now += timedelta(seconds=120)
    with pytest.raises(AssertionVerificationError, match="时间边界"):
        verifier.verify(
            issued.assertion,
            audience="tool-gateway",
            network_id=NETWORK,
        )


def test_assertion_rejects_binding_algorithm_key_pin_and_tampering(
    tmp_path: Path,
) -> None:
    clock, _, keys, assertions, request = online_identity_stack(tmp_path)
    issued = assertions.issue(request)
    key_set = keys.verification_keys()
    fingerprint = key_set.keys[0].fingerprint
    verifier = OfflineAssertionVerifier(key_set, {fingerprint}, clock=clock.utcnow)

    with pytest.raises(AssertionVerificationError, match="未知 assertion audience"):
        verifier.verify(issued.assertion, audience="other", network_id=NETWORK)
    with pytest.raises(AssertionVerificationError, match="指纹"):
        OfflineAssertionVerifier(key_set, set(), clock=clock.utcnow).verify(
            issued.assertion,
            audience="tool-gateway",
            network_id=NETWORK,
        )
    with pytest.raises(AssertionVerificationError, match="绑定"):
        verifier.verify(
            issued.assertion,
            audience="tool-gateway",
            network_id=NetworkId("network_ffffffffffffffffffffffffffffffff"),
        )
    with pytest.raises(AssertionVerificationError, match="绑定"):
        verifier.verify(
            issued.assertion,
            audience="tool-gateway",
            network_id=NETWORK,
            node_id=NodeId.new(),
        )
    parts = issued.assertion.split(".")
    parts[2] = ("A" if parts[2][0] != "A" else "B") + parts[2][1:]
    with pytest.raises(AssertionVerificationError, match="签名"):
        verifier.verify(
            ".".join(parts),
            audience="tool-gateway",
            network_id=NETWORK,
        )
    downgraded = jwt.encode(
        {"kid": "ignored"},
        "a-secure-test-key-with-at-least-32-bytes",
        algorithm="HS256",
        headers={"kid": key_set.keys[0].key_id, "typ": "JWT"},
    )
    with pytest.raises(AssertionVerificationError, match="算法"):
        verifier.verify(downgraded, audience="tool-gateway", network_id=NETWORK)

    private = Ed25519PrivateKey.generate()
    unknown = jwt.encode(
        {"iss": ASSERTION_ISSUER},
        private,
        algorithm="EdDSA",
        headers={"kid": "key-unknown", "typ": "JWT"},
    )
    with pytest.raises(AssertionVerificationError, match="未知"):
        verifier.verify(unknown, audience="tool-gateway", network_id=NETWORK)
    with pytest.raises(AssertionVerificationError, match="格式"):
        verifier.verify("not-a-jwt", audience="tool-gateway", network_id=NETWORK)


def test_assertion_rejects_key_windows_and_malformed_claim_types(
    tmp_path: Path,
) -> None:
    clock, _, keys, _, request = online_identity_stack(tmp_path)
    key_set = keys.verification_keys()
    key = key_set.keys[0]
    private_key = keys.active_signer()[1]
    claims: dict[str, object] = {
        "iss": ASSERTION_ISSUER,
        "sub": str(request.authentication.node_id),
        "node": str(request.authentication.node_id),
        "net": str(NETWORK),
        "aud": "tool-gateway",
        "iat": int(NOW.timestamp()),
        "nbf": int(NOW.timestamp()),
        "exp": int((NOW + timedelta(seconds=120)).timestamp()),
        "jti": "a" * 32,
        "pv": 1,
    }

    future_set = key_set.model_copy(
        update={"keys": (key.model_copy(update={"activates_at": NOW + timedelta(seconds=1)}),)}
    )
    with pytest.raises(AssertionVerificationError, match="验证窗口"):
        OfflineAssertionVerifier(
            future_set,
            {key.fingerprint},
            clock=clock.utcnow,
        ).verify(
            jwt.encode(
                claims,
                private_key,
                algorithm="EdDSA",
                headers={"kid": key.key_id, "typ": "JWT"},
            ),
            audience="tool-gateway",
            network_id=NETWORK,
        )
    retired_set = key_set.model_copy(update={"keys": (key.model_copy(update={"retires_at": NOW}),)})
    with pytest.raises(AssertionVerificationError, match="验证窗口"):
        OfflineAssertionVerifier(
            retired_set,
            {key.fingerprint},
            clock=clock.utcnow,
        ).verify(
            jwt.encode(
                claims,
                private_key,
                algorithm="EdDSA",
                headers={"kid": key.key_id, "typ": "JWT"},
            ),
            audience="tool-gateway",
            network_id=NETWORK,
        )

    for field, value in (("iat", True), ("net", 123)):
        malformed = claims | {field: value}
        token = jwt.encode(
            malformed,
            private_key,
            algorithm="EdDSA",
            headers={"kid": key.key_id, "typ": "JWT"},
        )
        with pytest.raises(AssertionVerificationError, match="声明类型"):
            OfflineAssertionVerifier(
                key_set,
                {key.fingerprint},
                clock=clock.utcnow,
            ).verify(token, audience="tool-gateway", network_id=NETWORK)


def test_assertion_requires_online_node(tmp_path: Path) -> None:
    clock = MutableClock()
    registry = service(tmp_path, clock)
    registry.create_network(NETWORK)
    token, _ = enrollment(registry)
    registered = registry.register(registration(token))
    secrets = MemorySecrets()
    keys = SigningKeyService(registry.store, secrets, clock=clock.utcnow)
    keys.rotate()
    assertions = AssertionService(registry, keys, clock=clock.utcnow)
    with pytest.raises(RegistryError, match="在线"):
        assertions.issue(
            AccessAssertionRequest(
                authentication=authentication(registered),
                audience="coordinator-agent",
            )
        )
    assert registry.list_nodes(NETWORK)[0].status is NodeStatus.OFFLINE
