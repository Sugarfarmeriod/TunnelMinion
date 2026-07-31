"""常规 Windows/macOS 应用的 managed node 组装与生命周期测试。"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

import pytest
from fastapi import FastAPI

from tunnelminion.agent.coordinator import CoordinatorTransport
from tunnelminion.agent.managed_application import (
    ManagedNodeApplication,
    build_managed_node_application,
    managed_application_lifespan,
)
from tunnelminion.agent.managed_node import (
    MANAGED_NODE_CONFIG_FILE,
    FileManagedNodeConfigRepository,
    ManagedNodeConfig,
    ManagedNodeSecretStoreKind,
    ManagedNodeState,
    ManagedNodeStatus,
    managed_node_secret_store,
)
from tunnelminion.agent.managed_runtime import ManagedNodeRuntime
from tunnelminion.agent.network_sync import ManagedNetworkSyncTransport
from tunnelminion.agent.service_observation import CollectionAdapter
from tunnelminion.coordinator.client_credentials import AgentRefreshCredentialStore
from tunnelminion.coordinator.contracts import GatewayEndpoint, NodeRegistrationResponse
from tunnelminion.domain.identifiers import NetworkId, NodeId, RefreshCredentialId
from tunnelminion.domain.tools import Platform
from tunnelminion.model.secrets import SecretStore, SecretStoreError
from tunnelminion.tools.registry import ToolRegistry


def config(node_id: NodeId, **updates: object) -> ManagedNodeConfig:
    values: dict[str, object] = {
        "coordinator_endpoint": "http://10.77.0.1:8790",
        "network_id": NetworkId.new(),
        "node_id": node_id,
        "display_name": "Windows A",
        "platform": Platform.WINDOWS,
        "gateway_endpoint": GatewayEndpoint(host="10.77.0.2", port=8787),
        "pinned_fingerprints": frozenset({"a" * 64}),
        "secret_store": ManagedNodeSecretStoreKind.RESTRICTED_FILE,
    }
    values.update(updates)
    return ManagedNodeConfig.model_validate(values)


def build(
    root: Path,
    node_id: NodeId,
    platform: Platform = Platform.WINDOWS,
) -> ManagedNodeApplication:
    adapter = cast(CollectionAdapter, object())
    return build_managed_node_application(
        root,
        node_id,
        platform,
        ToolRegistry(),
        adapter,
        adapter,
        adapter,
        coordinator_transport=cast(CoordinatorTransport, object()),
        network_transport=cast(ManagedNetworkSyncTransport, object()),
    )


def test_factory_keeps_unconfigured_disabled_and_mismatched_nodes_inert(
    tmp_path: Path,
) -> None:
    node_id = NodeId.new()
    assert build(tmp_path / "missing", node_id).enrollment.state is ManagedNodeState.UNCONFIGURED

    root = tmp_path / "configured"
    repository = FileManagedNodeConfigRepository(root / MANAGED_NODE_CONFIG_FILE)
    repository.save(config(node_id, enabled=False))
    disabled = build(root, node_id)
    assert disabled.enrollment.state is ManagedNodeState.DISABLED
    assert disabled.runtime is None

    repository.save(config(NodeId.new()))
    mismatch = build(root, node_id)
    assert mismatch.enrollment.state is ManagedNodeState.UNAVAILABLE
    assert mismatch.enrollment.last_error_code == "identity_mismatch"
    assert mismatch.runtime is None


def test_factory_isolates_invalid_config_and_unavailable_secret_store(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    node_id = NodeId.new()
    invalid_root = tmp_path / "invalid"
    invalid_root.mkdir()
    (invalid_root / MANAGED_NODE_CONFIG_FILE).write_text(
        '{"refresh_credential":"forbidden"}',
        encoding="utf-8",
    )
    invalid = build(invalid_root, node_id)
    assert invalid.enrollment.state is ManagedNodeState.UNAVAILABLE
    assert invalid.enrollment.last_error_code == "managed_config_invalid"
    assert invalid.runtime is None

    class UnavailableSecrets:
        def get(self, name: str) -> str | None:
            del name
            raise SecretStoreError("secret backend unavailable")

        def set(self, name: str, value: str) -> None:
            del name, value

        def delete(self, name: str) -> None:
            del name

    root = tmp_path / "unavailable"
    FileManagedNodeConfigRepository(root / MANAGED_NODE_CONFIG_FILE).save(
        config(node_id, secret_store=ManagedNodeSecretStoreKind.KEYRING)
    )

    def unavailable_store(
        _root: Path,
        _kind: ManagedNodeSecretStoreKind,
    ) -> SecretStore:
        return UnavailableSecrets()

    monkeypatch.setattr(
        "tunnelminion.agent.managed_application.managed_node_secret_store",
        unavailable_store,
    )
    unavailable = build(root, node_id)
    assert unavailable.enrollment.state is ManagedNodeState.UNAVAILABLE
    assert unavailable.enrollment.last_error_code == "secret_store_unavailable"
    assert unavailable.runtime is None


def test_factory_requires_enrollment_then_builds_all_three_runtime_domains(
    tmp_path: Path,
) -> None:
    node_id = NodeId.new()
    root = tmp_path / "managed"
    managed_config = config(node_id)
    FileManagedNodeConfigRepository(root / MANAGED_NODE_CONFIG_FILE).save(managed_config)

    pending = build(root, node_id)
    assert pending.enrollment.state is ManagedNodeState.ENROLLMENT_REQUIRED
    assert pending.runtime is None

    credentials = AgentRefreshCredentialStore(
        managed_node_secret_store(root, managed_config.secret_store)
    )
    credentials.save(
        NodeRegistrationResponse(
            identity=managed_config.identity(),
            credential_id=RefreshCredentialId.new(),
            refresh_credential=f"tmnr_{'r' * 43}",
            server_revision=1,
            issued_at=datetime(2026, 7, 31, tzinfo=UTC),
        )
    )
    ready = build(root, node_id)
    assert ready.enrollment.state is ManagedNodeState.READY
    assert ready.runtime is not None
    assert ready.coordinator is not None
    assert ready.network is not None
    assert {item.domain.value for item in ready.runtime.status.loops} == {
        "directory",
        "services",
        "managed-config",
    }
    serialized = str(ready.resource_payload()).lower()
    for forbidden in ("10.77", "tmnr_", "private_key", "signature", "endpoint"):
        assert forbidden not in serialized


def test_lifespan_is_inert_without_runtime_and_starts_and_stops_ready_runtime() -> None:
    class FakeRuntime:
        def __init__(self) -> None:
            self.calls: list[str] = []

        async def start(self) -> None:
            self.calls.append("start")

        async def stop(self) -> None:
            self.calls.append("stop")

    async def scenario() -> None:
        inert = ManagedNodeApplication(config=None, enrollment=build_status())
        async with managed_application_lifespan(inert)(FastAPI()):
            pass

        runtime = FakeRuntime()
        ready = ManagedNodeApplication(
            config=None,
            enrollment=build_status(),
            runtime=cast(ManagedNodeRuntime, runtime),
        )
        async with managed_application_lifespan(ready)(FastAPI()):
            assert runtime.calls == ["start"]
        assert runtime.calls == ["start", "stop"]

    asyncio.run(scenario())


def build_status() -> ManagedNodeStatus:
    """避免生命周期测试依赖文件系统。"""
    from tunnelminion.agent.managed_node import managed_node_status

    return managed_node_status(None)
