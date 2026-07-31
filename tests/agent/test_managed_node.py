"""常规 managed node 配置、秘密与 enrollment 边界测试。"""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

import pytest
from pydantic import ValidationError

from tunnelminion.agent.coordinator import CoordinatorClientError, CoordinatorTransport
from tunnelminion.agent.managed_node import (
    MANAGED_NODE_CONFIG_VERSION,
    FileManagedNodeConfigRepository,
    ManagedNodeConfig,
    ManagedNodeSecretStoreKind,
    ManagedNodeState,
    ServiceObservationConfig,
    enroll_managed_node,
    managed_node_secret_store,
    managed_node_status,
)
from tunnelminion.coordinator.client_credentials import AgentRefreshCredentialStore
from tunnelminion.coordinator.contracts import (
    GatewayEndpoint,
    NodeRegistrationRequest,
    NodeRegistrationResponse,
    VerificationKeySet,
    VerificationKeyView,
)
from tunnelminion.domain.identifiers import NetworkId, NodeId, RefreshCredentialId
from tunnelminion.domain.tools import Platform

NETWORK = NetworkId.new()
NODE = NodeId.new()
FINGERPRINT = "a" * 64


class MemorySecrets:
    """测试用内存秘密存储。"""

    def __init__(self) -> None:
        self.values: dict[str, str] = {}

    def get(self, name: str) -> str | None:
        return self.values.get(name)

    def set(self, name: str, value: str) -> None:
        self.values[name] = value

    def delete(self, name: str) -> None:
        self.values.pop(name, None)


class FailingSecrets(MemorySecrets):
    """模拟系统秘密存储写入失败。"""

    def set(self, name: str, value: str) -> None:
        del name, value
        raise RuntimeError("secret store unavailable")


class EnrollmentTransport:
    """只实现 enrollment 所需路径的受控传输。"""

    def __init__(self, fingerprint: str = FINGERPRINT) -> None:
        self.fingerprint = fingerprint
        self.requests: list[NodeRegistrationRequest] = []

    async def verification_keys(self) -> VerificationKeySet:
        return VerificationKeySet(
            generated_at=datetime(2026, 7, 31, tzinfo=UTC),
            keys=(
                VerificationKeyView(
                    key_id="key-test",
                    public_key="A" * 43,
                    fingerprint=self.fingerprint,
                    activates_at=datetime(2026, 7, 31, tzinfo=UTC),
                ),
            ),
        )

    async def register(self, request: NodeRegistrationRequest) -> NodeRegistrationResponse:
        self.requests.append(request)
        return NodeRegistrationResponse(
            identity=request.identity,
            credential_id=RefreshCredentialId.new(),
            refresh_credential=f"tmnr_{'r' * 43}",
            server_revision=1,
            issued_at=datetime(2026, 7, 31, tzinfo=UTC),
        )


def config(**updates: object) -> ManagedNodeConfig:
    """生成不含秘密的有效 managed node 配置。"""
    values: dict[str, object] = {
        "coordinator_endpoint": "http://10.77.0.1:8790",
        "network_id": NETWORK,
        "node_id": NODE,
        "display_name": "Windows A",
        "platform": Platform.WINDOWS,
        "gateway_endpoint": GatewayEndpoint(host="10.77.0.2", port=8787),
        "pinned_fingerprints": frozenset({FINGERPRINT}),
    }
    values.update(updates)
    return ManagedNodeConfig.model_validate(values)


def test_config_round_trip_is_atomic_and_contains_no_secret_fields(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from tunnelminion.agent import managed_node

    repository = FileManagedNodeConfigRepository(tmp_path / "nested" / "managed-node.json")
    expected = config(
        services=ServiceObservationConfig(docker_enabled=False),
        secret_store=ManagedNodeSecretStoreKind.RESTRICTED_FILE,
    )
    monkeypatch.setattr(managed_node.os, "name", "posix")
    repository.save(expected)
    monkeypatch.setattr(managed_node.os, "name", "nt")
    repository.save(expected)
    assert repository.load() == expected
    serialized = (tmp_path / "nested" / "managed-node.json").read_text(encoding="utf-8")
    assert json.loads(serialized)["schema_version"] == MANAGED_NODE_CONFIG_VERSION
    for forbidden in ("enrollment_token", "refresh_credential", "assertion", "private_key"):
        assert forbidden not in serialized
    assert not (tmp_path / "nested" / "managed-node.json.tmp").exists()
    repository.delete()
    repository.delete()
    assert repository.load() is None


@pytest.mark.parametrize(
    "secret_field",
    ("enrollment_token", "refresh_credential", "access_assertion", "private_key"),
)
def test_config_rejects_unknown_secret_fields(secret_field: str) -> None:
    value = config().model_dump(mode="json")
    value[secret_field] = "must-not-leak"
    with pytest.raises(ValidationError):
        ManagedNodeConfig.model_validate(value)


def test_config_reuses_coordinator_and_gateway_validation() -> None:
    with pytest.raises(ValidationError):
        config(coordinator_endpoint="http://8.8.8.8")
    with pytest.raises(ValidationError):
        config(pinned_fingerprints={"bad"})
    with pytest.raises(ValidationError):
        config(schema_version="managed-node/v2")
    with pytest.raises(ValidationError):
        config(base_backoff_seconds=10, max_backoff_seconds=5)
    with pytest.raises(ValidationError):
        config(gateway_endpoint={"host": "127.0.0.1", "port": 8787})


def test_status_distinguishes_unconfigured_disabled_enrollment_and_ready() -> None:
    assert managed_node_status(None).state is ManagedNodeState.UNCONFIGURED
    invalid = managed_node_status(None, error_code="managed_config_invalid")
    assert invalid.state is ManagedNodeState.UNAVAILABLE
    assert invalid.last_error_code == "managed_config_invalid"
    disabled = managed_node_status(config(enabled=False))
    assert disabled.state is ManagedNodeState.DISABLED
    assert not disabled.credential_configured

    secrets = MemorySecrets()
    credentials = AgentRefreshCredentialStore(secrets)
    pending = managed_node_status(config(), credentials)
    assert pending.state is ManagedNodeState.ENROLLMENT_REQUIRED
    secrets.set(f"coordinator-refresh:{NETWORK}:{NODE}", "refresh-test-placeholder")
    ready = managed_node_status(config(), credentials)
    assert ready.state is ManagedNodeState.READY
    assert ready.credential_configured
    unavailable = managed_node_status(config(), credentials, error_code="secret_store_unavailable")
    assert unavailable.state is ManagedNodeState.UNAVAILABLE
    assert unavailable.last_error_code == "secret_store_unavailable"
    assert "refresh-test-placeholder" not in unavailable.model_dump_json()


def test_identity_and_device_hash_are_stable_and_public() -> None:
    value = config()
    assert value.identity().node_id == NODE
    assert value.identity().gateway_endpoint.host == "10.77.0.2"
    assert value.device_identity_hash() == config().device_identity_hash()
    assert len(value.device_identity_hash()) == 64


def test_enrollment_confirms_fingerprint_is_repeatable_and_surfaces_store_failure() -> None:
    value = config()
    transport = EnrollmentTransport()
    secrets = MemorySecrets()
    credentials = AgentRefreshCredentialStore(secrets)
    token = f"tmne_{'e' * 43}"

    first = asyncio.run(
        enroll_managed_node(
            value,
            token,
            cast(CoordinatorTransport, transport),
            credentials,
        )
    )
    second = asyncio.run(
        enroll_managed_node(
            value,
            token,
            cast(CoordinatorTransport, transport),
            credentials,
        )
    )
    assert credentials.load(NETWORK, NODE) == first.refresh_credential
    assert transport.requests[0].idempotency_key == transport.requests[1].idempotency_key
    assert second.identity == first.identity

    mismatch = EnrollmentTransport("b" * 64)
    with pytest.raises(CoordinatorClientError, match="指纹"):
        asyncio.run(
            enroll_managed_node(
                value,
                token,
                cast(CoordinatorTransport, mismatch),
                credentials,
            )
        )

    with pytest.raises(RuntimeError, match="secret store unavailable"):
        asyncio.run(
            enroll_managed_node(
                value,
                token,
                cast(CoordinatorTransport, EnrollmentTransport()),
                AgentRefreshCredentialStore(FailingSecrets()),
            )
        )


def test_secret_store_selection_uses_keyring_or_restricted_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from tunnelminion.agent import managed_node

    keyring_marker = MemorySecrets()
    monkeypatch.setattr(managed_node, "KeyringSecretStore", lambda: keyring_marker)
    assert managed_node_secret_store(tmp_path, ManagedNodeSecretStoreKind.KEYRING) is keyring_marker
    restricted = managed_node_secret_store(tmp_path, ManagedNodeSecretStoreKind.RESTRICTED_FILE)
    restricted.set("test", "value")
    assert restricted.get("test") == "value"
