"""macOS Provider 平台绑定与共享 saga 契约测试。"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
from tests.network.factories import NETWORK_ID, NODE_A, NOW, desired

from tunnelminion.domain.identifiers import NetworkId, NodeId, ResourceId
from tunnelminion.network.contracts import (
    DesiredNetworkConfig,
    LocalNetworkKeyMaterial,
    ManagedResourceOwnership,
    NetworkAction,
    NetworkPlan,
    NetworkPlanStep,
    OwnershipState,
    PlanStepKind,
    ProviderKind,
    ProviderMode,
    ReceiptStatus,
    canonical_sha256,
)
from tunnelminion.network.ledger import ManagedResourceLedgerEntry, SQLiteManagedResourceLedger
from tunnelminion.platforms.macos.managed_system import (
    MacOSPeerSnapshot,
    MacOSProviderPreflight,
    MacOSTunnelSnapshot,
)
from tunnelminion.platforms.macos.network_provider import (
    MacOSNetworkProvider,
    SQLiteMacOSOperationJournal,
    macos_operation_journal,
)
from tunnelminion.tools.contracts import ToolCancellationToken

KEY = f"netop_{'b' * 64}"


def config(**updates: object) -> DesiredNetworkConfig:
    values: dict[str, object] = {
        "provider": ProviderKind.MACOS,
        "interface_name": "tmn-test-b",
    }
    values.update(updates)
    return desired(**values)


def absent(name: str = "tmn-test-b") -> MacOSTunnelSnapshot:
    return MacOSTunnelSnapshot(
        interface_name=name,
        interface_present=False,
        interface_up=False,
        service_present=False,
        service_running=False,
    )


class FakeMacOSBackend:
    def __init__(self) -> None:
        self.snapshot = absent()
        self.execute_calls: list[PlanStepKind] = []

    def preflight(self) -> MacOSProviderPreflight:
        return MacOSProviderPreflight(
            mode=ProviderMode.MANAGED,
            platform_supported=True,
            wireguard_manager_available=True,
            wg_available=True,
            service_control_available=True,
            route_tool_available=True,
            administrator=True,
        )

    async def observe(self, interface_name: str) -> MacOSTunnelSnapshot:
        return self.snapshot.model_copy(update={"interface_name": interface_name})

    def ensure_secret(self, desired: DesiredNetworkConfig) -> LocalNetworkKeyMaterial:
        del desired
        return self.ensure_identity(NETWORK_ID, NODE_A)

    def ensure_identity(
        self,
        network_id: NetworkId,
        node_id: NodeId,
    ) -> LocalNetworkKeyMaterial:
        assert network_id == NETWORK_ID
        assert node_id == NODE_A
        return LocalNetworkKeyMaterial(
            secret_reference="keyring:macos/test",
            public_key="B" * 43 + "=",
            public_key_hash=canonical_sha256({"public": "macos"}),
        )

    def create_identity(
        self,
        network_id: NetworkId,
        node_id: NodeId,
    ) -> LocalNetworkKeyMaterial:
        return self.ensure_identity(network_id, node_id)

    async def validate_no_conflicts(self, desired: DesiredNetworkConfig) -> None:
        del desired

    async def execute_step(
        self,
        plan: NetworkPlan,
        step: NetworkPlanStep,
        *,
        secret_reference: str,
        creation_nonce: str,
        idempotency_key: str,
    ) -> str:
        assert secret_reference == "keyring:macos/test"
        assert idempotency_key == KEY
        self.execute_calls.append(step.kind)
        if step.kind is PlanStepKind.CREATE_INTERFACE:
            self.snapshot = MacOSTunnelSnapshot(
                interface_name=plan.desired.interface_name,
                interface_present=True,
                interface_up=True,
                addresses=(plan.desired.address,),
                service_present=True,
                service_running=True,
                peers=tuple(
                    MacOSPeerSnapshot(
                        public_key=peer.public_key,
                        allowed_host_routes=peer.allowed_host_routes,
                    )
                    for peer in plan.desired.peers
                ),
                host_routes=tuple(
                    route for peer in plan.desired.peers for route in peer.allowed_host_routes
                ),
                public_key_hash=canonical_sha256({"public": "macos"}),
                stable_interface_id="utun9",
                creation_nonce=creation_nonce,
            )
        return canonical_sha256({"step": step.kind.value})

    async def rollback_step(
        self,
        plan: NetworkPlan,
        step: NetworkPlanStep,
        *,
        secret_reference: str,
        creation_nonce: str,
        idempotency_key: str,
    ) -> str:
        del plan, secret_reference, creation_nonce, idempotency_key
        return canonical_sha256({"rollback": step.kind.value})


def provider(
    tmp_path: Path,
    backend: FakeMacOSBackend,
) -> tuple[MacOSNetworkProvider, SQLiteManagedResourceLedger, SQLiteMacOSOperationJournal]:
    ledger = SQLiteManagedResourceLedger(tmp_path / "ledger.sqlite3")
    journals = macos_operation_journal(tmp_path / "macos-operations.sqlite3")
    return MacOSNetworkProvider(backend, ledger, journals), ledger, journals


def test_observe_protect_plan_apply_verify_and_journal(tmp_path: Path) -> None:
    backend = FakeMacOSBackend()
    value, ledger, journals = provider(tmp_path, backend)
    identity = value.ensure_local_identity(NETWORK_ID, NODE_A)
    assert identity.public_key == "B" * 43 + "="
    assert identity.secret_reference == "keyring:macos/test"
    observed = asyncio.run(value.observe("tmn-test-b"))
    assert observed.provider is ProviderKind.MACOS
    assert observed.ownership is OwnershipState.ABSENT

    backend.snapshot = MacOSTunnelSnapshot(
        interface_name="utun4",
        interface_present=True,
        interface_up=True,
        service_present=True,
        service_running=True,
        stable_interface_id="utun4",
    )
    user = asyncio.run(value.observe("utun4"))
    assert user.ownership is OwnershipState.OBSERVED_USER

    backend.snapshot = absent()
    observed = asyncio.run(value.observe("tmn-test-b"))
    plan = asyncio.run(
        value.plan(
            action=NetworkAction.CREATE,
            desired=config(),
            observed=observed,
            ownership=None,
        )
    )
    assert all(step.expected_effect.startswith("macos:") for step in plan.steps)
    receipt = asyncio.run(
        value.apply(plan, idempotency_key=KEY, cancellation=ToolCancellationToken())
    )
    assert receipt.status is ReceiptStatus.APPLIED
    assert asyncio.run(value.verify(plan)).succeeded
    assert asyncio.run(value.observe("tmn-test-b")).ownership is OwnershipState.MANAGED_OWNED
    entry = ledger.get(NETWORK_ID, NODE_A)
    assert entry is not None and entry.ownership.provider is ProviderKind.MACOS
    journals.assert_no_secret_material()
    backend.snapshot = backend.snapshot.model_copy(update={"stable_interface_id": "utun-replaced"})
    assert asyncio.run(value.observe("tmn-test-b")).ownership is OwnershipState.OWNERSHIP_CONFLICT


def test_parent_ledger_remains_owned_after_allowed_network_observation_upgrade(
    tmp_path: Path,
) -> None:
    backend = FakeMacOSBackend()
    backend.snapshot = MacOSTunnelSnapshot(
        interface_name="tmn-test-b",
        interface_present=True,
        interface_up=True,
        addresses=("10.203.0.1/32",),
        service_present=True,
        service_running=True,
        peers=(
            MacOSPeerSnapshot(
                public_key="peer-a",
                allowed_host_routes=("10.203.0.2/32",),
                allowed_networks=("10.203.0.2/32", "10.203.0.0/24"),
            ),
        ),
        host_routes=("10.203.0.2/32",),
        public_key_hash=canonical_sha256({"public": "macos"}),
        stable_interface_id="utun9",
        creation_nonce="a" * 32,
    )
    value, ledger, _ = provider(tmp_path, backend)
    legacy_fingerprint = canonical_sha256(
        {
            "interface_name": backend.snapshot.interface_name,
            "interface_present": backend.snapshot.interface_present,
            "addresses": backend.snapshot.addresses,
            "peers": [
                {
                    "public_key": peer.public_key,
                    "endpoint_host": peer.endpoint_host,
                    "endpoint_port": peer.endpoint_port,
                    "allowed_host_routes": peer.allowed_host_routes,
                }
                for peer in backend.snapshot.peers
            ],
            "host_routes": backend.snapshot.host_routes,
            "public_key_hash": backend.snapshot.public_key_hash,
            "stable_interface_id": backend.snapshot.stable_interface_id,
            "creation_nonce": backend.snapshot.creation_nonce,
        }
    )
    ledger.put(
        ManagedResourceLedgerEntry(
            ownership=ManagedResourceOwnership(
                resource_id=ResourceId.new(),
                network_id=NETWORK_ID,
                node_id=NODE_A,
                provider=ProviderKind.MACOS,
                interface_name="tmn-test-b",
                stable_interface_id="utun9",
                creation_nonce="a" * 32,
                public_key_hash=canonical_sha256({"public": "macos"}),
                parent_revision=0,
                desired_config_hash=canonical_sha256(config().model_dump(mode="json")),
                system_fingerprint=legacy_fingerprint,
            ),
            secret_reference="keyring:macos/test",
            created_at=NOW,
            updated_at=NOW,
        )
    )

    observed = asyncio.run(value.observe("tmn-test-b"))

    assert observed.ownership is OwnershipState.MANAGED_OWNED
    assert backend.execute_calls == []


def test_rejects_wrong_provider_and_untracked_managed_name(tmp_path: Path) -> None:
    backend = FakeMacOSBackend()
    value, _, _ = provider(tmp_path, backend)
    observed = asyncio.run(value.observe("tmn-test-b"))
    with pytest.raises(ValueError, match="其他平台"):
        asyncio.run(
            value.plan(
                action=NetworkAction.CREATE,
                desired=desired(interface_name="tmn-test-b"),
                observed=observed,
                ownership=None,
            )
        )
    backend.snapshot = MacOSTunnelSnapshot(
        interface_name="tmn-test-b",
        interface_present=True,
        interface_up=True,
        service_present=True,
        service_running=True,
        stable_interface_id="utun10",
    )
    assert asyncio.run(value.observe("tmn-test-b")).ownership is OwnershipState.OWNERSHIP_UNKNOWN
