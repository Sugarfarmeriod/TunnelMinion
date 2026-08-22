"""Windows NetworkProvider 的计划、幂等、故障、回滚与恢复测试。"""

from __future__ import annotations

import asyncio
import sqlite3
from collections.abc import Callable, Coroutine
from datetime import datetime
from pathlib import Path
from typing import Any, TypeVar

import pytest
from tests.network.factories import NETWORK_ID, NODE_A, NOW, desired

from tunnelminion.domain.identifiers import NetworkId, NodeId, ResourceId
from tunnelminion.network.contracts import (
    DesiredNetworkConfig,
    LocalNetworkKeyMaterial,
    ManagedResourceOwnership,
    NetworkAction,
    NetworkError,
    NetworkErrorCode,
    NetworkPlan,
    NetworkPlanStep,
    OwnershipState,
    PlanStepKind,
    ProviderKind,
    ProviderMode,
    ProviderReceipt,
    ReceiptStatus,
    canonical_sha256,
)
from tunnelminion.network.ledger import ManagedResourceLedgerEntry, SQLiteManagedResourceLedger
from tunnelminion.platforms.windows.managed_system import (
    WindowsPeerSnapshot,
    WindowsProviderPreflight,
    WindowsTunnelSnapshot,
)
from tunnelminion.platforms.windows.network_provider import (
    SQLiteWindowsOperationJournal,
    WindowsBackendError,
    WindowsNetworkProvider,
)
from tunnelminion.tools.contracts import ToolCancellationToken

T = TypeVar("T")
KEY = f"netop_{'a' * 64}"


def run(coroutine: Coroutine[Any, Any, T]) -> T:
    return asyncio.run(coroutine)


def absent(interface_name: str = "tmn-test-a") -> WindowsTunnelSnapshot:
    return WindowsTunnelSnapshot(
        interface_name=interface_name,
        interface_present=False,
        interface_up=False,
        service_present=False,
        service_running=False,
    )


class FakeWindowsBackend:
    def __init__(self) -> None:
        self.snapshot = absent()
        self.mode = ProviderMode.MANAGED
        self.error_code: str | None = None
        self.execute_calls: list[PlanStepKind] = []
        self.rollback_calls: list[PlanStepKind] = []
        self.ensure_calls = 0
        self.fail_step: PlanStepKind | None = None
        self.crash_step: PlanStepKind | None = None
        self.fail_rollback: PlanStepKind | None = None
        self.block: asyncio.Event | None = None
        self.omit_ownership_after_create = False
        self.on_step: Callable[[PlanStepKind], None] | None = None
        self.conflict_error: WindowsBackendError | None = None

    def preflight(self) -> WindowsProviderPreflight:
        available = self.mode is ProviderMode.MANAGED
        return WindowsProviderPreflight(
            mode=self.mode,
            platform_supported=True,
            wireguard_manager_available=available,
            wg_available=True,
            service_control_available=True,
            route_tool_available=True,
            administrator=available,
            error_code=self.error_code,
        )

    async def observe(self, interface_name: str) -> WindowsTunnelSnapshot:
        assert interface_name == self.snapshot.interface_name
        return self.snapshot

    def ensure_secret(self, desired: DesiredNetworkConfig) -> LocalNetworkKeyMaterial:
        del desired
        self.ensure_calls += 1
        return self.ensure_identity(NETWORK_ID, NODE_A)

    def ensure_identity(
        self,
        network_id: NetworkId,
        node_id: NodeId,
    ) -> LocalNetworkKeyMaterial:
        assert network_id == NETWORK_ID
        assert node_id == NODE_A
        return LocalNetworkKeyMaterial(
            secret_reference="keyring:tmn/test",
            public_key="A" * 43 + "=",
            public_key_hash=canonical_sha256({"public": "own"}),
        )

    async def validate_no_conflicts(self, desired: DesiredNetworkConfig) -> None:
        del desired
        if self.conflict_error is not None:
            raise self.conflict_error

    async def execute_step(
        self,
        plan: NetworkPlan,
        step: NetworkPlanStep,
        *,
        secret_reference: str,
        creation_nonce: str,
        idempotency_key: str,
    ) -> str:
        assert secret_reference == "keyring:tmn/test"
        assert idempotency_key.startswith("netop_")
        if self.block is not None:
            await self.block.wait()
        self.execute_calls.append(step.kind)
        if self.on_step is not None:
            self.on_step(step.kind)
        if step.kind is self.crash_step:
            raise RuntimeError("injected Windows crash")
        if step.kind is self.fail_step:
            raise WindowsBackendError(
                NetworkErrorCode.APPLY_FAILED,
                "injected step failure",
                retryable=True,
            )
        if step.kind is PlanStepKind.CREATE_INTERFACE:
            routes = tuple(
                route for peer in plan.desired.peers for route in peer.allowed_host_routes
            )
            self.snapshot = WindowsTunnelSnapshot(
                interface_name=plan.desired.interface_name,
                interface_present=True,
                interface_up=True,
                addresses=(plan.desired.address,),
                service_present=True,
                service_running=True,
                peers=tuple(
                    WindowsPeerSnapshot(
                        public_key=peer.public_key,
                        allowed_host_routes=peer.allowed_host_routes,
                    )
                    for peer in plan.desired.peers
                ),
                host_routes=routes,
                public_key_hash=canonical_sha256({"public": "own"}),
                stable_interface_id="windows:tmn-test-a",
                creation_nonce=creation_nonce,
            )
            if self.omit_ownership_after_create:
                self.snapshot = self.snapshot.model_copy(
                    update={
                        "stable_interface_id": None,
                        "public_key_hash": None,
                        "creation_nonce": None,
                    }
                )
        elif step.kind in {
            PlanStepKind.STOP_INTERFACE,
            PlanStepKind.REMOVE_INTERFACE,
        }:
            self.snapshot = absent(plan.desired.interface_name)
        return canonical_sha256({"step": step.kind.value, "count": len(self.execute_calls)})

    async def rollback_step(
        self,
        plan: NetworkPlan,
        step: NetworkPlanStep,
        *,
        secret_reference: str,
        creation_nonce: str,
        idempotency_key: str,
    ) -> str:
        assert secret_reference == "keyring:tmn/test"
        assert idempotency_key.startswith("netop_")
        self.rollback_calls.append(step.kind)
        if step.kind is self.fail_rollback:
            raise WindowsBackendError(
                NetworkErrorCode.ROLLBACK_FAILED,
                "injected rollback failure",
            )
        if step.kind is PlanStepKind.CREATE_INTERFACE:
            self.snapshot = absent(plan.desired.interface_name)
        elif (
            step.kind
            in {
                PlanStepKind.STOP_INTERFACE,
                PlanStepKind.REMOVE_INTERFACE,
            }
            and plan.desired.parent_revision > 0
        ):
            self.snapshot = WindowsTunnelSnapshot(
                interface_name=plan.desired.interface_name,
                interface_present=True,
                interface_up=True,
                addresses=(plan.desired.address,),
                service_present=True,
                service_running=True,
                peers=tuple(
                    WindowsPeerSnapshot(
                        public_key=peer.public_key,
                        allowed_host_routes=peer.allowed_host_routes,
                    )
                    for peer in plan.desired.peers
                ),
                host_routes=tuple(
                    route for peer in plan.desired.peers for route in peer.allowed_host_routes
                ),
                public_key_hash=canonical_sha256({"public": "own"}),
                stable_interface_id="windows:tmn-test-a",
                creation_nonce=creation_nonce,
            )
        return canonical_sha256({"rollback": step.kind.value, "count": len(self.rollback_calls)})


def provider(
    tmp_path: Path,
    backend: FakeWindowsBackend,
    *,
    clock: Callable[[], datetime] | None = None,
) -> tuple[
    WindowsNetworkProvider,
    SQLiteManagedResourceLedger,
    SQLiteWindowsOperationJournal,
]:
    ledger = SQLiteManagedResourceLedger(tmp_path / "ledger.sqlite3")
    journals = SQLiteWindowsOperationJournal(tmp_path / "operations.sqlite3")
    return (
        WindowsNetworkProvider(backend, ledger, journals, clock=clock),
        ledger,
        journals,
    )


async def create_plan(
    value: WindowsNetworkProvider,
    *,
    desired_config: DesiredNetworkConfig | None = None,
) -> NetworkPlan:
    config = desired() if desired_config is None else desired_config
    observed = await value.observe("tmn-test-a")
    return await value.plan(
        action=NetworkAction.CREATE,
        desired=config,
        observed=observed,
        ownership=None,
    )


def test_observe_classifies_absent_user_unknown_managed_and_conflict(tmp_path: Path) -> None:
    backend = FakeWindowsBackend()
    value, ledger, _ = provider(tmp_path, backend)
    identity = value.ensure_local_identity(NETWORK_ID, NODE_A)
    assert identity.public_key == "A" * 43 + "="
    assert identity.secret_reference == "keyring:tmn/test"
    assert run(value.observe("tmn-test-a")).ownership is OwnershipState.ABSENT

    backend.snapshot = WindowsTunnelSnapshot(
        interface_name="HomeMac",
        interface_present=True,
        interface_up=True,
        service_present=True,
        service_running=True,
        public_key_hash=canonical_sha256({"public": "user"}),
        stable_interface_id="windows:homemac",
    )
    assert run(value.observe("HomeMac")).ownership is OwnershipState.OBSERVED_USER

    backend.snapshot = backend.snapshot.model_copy(
        update={
            "interface_name": "tmn-test-a",
            "stable_interface_id": "windows:tmn-test-a",
        }
    )
    assert run(value.observe("tmn-test-a")).ownership is OwnershipState.OWNERSHIP_UNKNOWN
    assert ledger.list_all() == ()


def test_parent_ledger_remains_owned_after_allowed_network_observation_upgrade(
    tmp_path: Path,
) -> None:
    backend = FakeWindowsBackend()
    backend.snapshot = WindowsTunnelSnapshot(
        interface_name="tmn-test-a",
        interface_present=True,
        interface_up=True,
        addresses=("10.203.0.1/32",),
        service_present=True,
        service_running=True,
        peers=(
            WindowsPeerSnapshot(
                public_key="peer-a",
                allowed_host_routes=("10.203.0.2/32",),
                allowed_networks=("10.203.0.2/32", "10.203.0.0/24"),
            ),
        ),
        host_routes=("10.203.0.2/32",),
        public_key_hash=canonical_sha256({"public": "own"}),
        stable_interface_id="windows:tmn-test-a",
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
                provider=ProviderKind.WINDOWS,
                interface_name="tmn-test-a",
                stable_interface_id="windows:tmn-test-a",
                creation_nonce="a" * 32,
                public_key_hash=canonical_sha256({"public": "own"}),
                parent_revision=0,
                desired_config_hash=canonical_sha256(desired().model_dump(mode="json")),
                system_fingerprint=legacy_fingerprint,
            ),
            secret_reference="keyring:tmn/test",
            created_at=NOW,
            updated_at=NOW,
        )
    )

    observed = run(value.observe("tmn-test-a"))

    assert observed.ownership is OwnershipState.MANAGED_OWNED
    assert backend.execute_calls == []


def test_plan_rejects_user_targets_wrong_provider_conflicts_and_missing_ownership(
    tmp_path: Path,
) -> None:
    backend = FakeWindowsBackend()
    value, _, _ = provider(tmp_path, backend)
    observed = run(value.observe("tmn-test-a"))
    with pytest.raises(ValueError, match="windows"):
        run(
            value.plan(
                action=NetworkAction.CREATE,
                desired=desired(provider="macos"),
                observed=observed,
                ownership=None,
            )
        )
    with pytest.raises(ValueError, match="用户接口"):
        run(
            value.plan(
                action=NetworkAction.CREATE,
                desired=desired().model_copy(update={"interface_name": "HomeMac"}),
                observed=observed,
                ownership=None,
            )
        )
    with pytest.raises(ValueError, match="名称"):
        run(
            value.plan(
                action=NetworkAction.CREATE,
                desired=desired(interface_name="tmn-other"),
                observed=observed,
                ownership=None,
            )
        )
    with pytest.raises(ValueError, match="双重所有权"):
        run(
            value.plan(
                action=NetworkAction.UPDATE,
                desired=desired(),
                observed=observed,
                ownership=None,
            )
        )
    with pytest.raises(ValueError, match="不存在"):
        run(
            value.plan(
                action=NetworkAction.CREATE,
                desired=desired(),
                observed=observed.model_copy(
                    update={"ownership": OwnershipState.OWNERSHIP_UNKNOWN}
                ),
                ownership=None,
            )
        )
    with pytest.raises(ValueError, match="地址冲突"):
        run(
            value.plan(
                action=NetworkAction.CREATE,
                desired=desired(),
                observed=observed.model_copy(update={"addresses": ("10.203.0.1/32",)}),
                ownership=None,
            )
        )
    with pytest.raises(ValueError, match="route 冲突"):
        run(
            value.plan(
                action=NetworkAction.CREATE,
                desired=desired(),
                observed=observed.model_copy(update={"host_routes": ("10.203.0.2/32",)}),
                ownership=None,
            )
        )
    backend.conflict_error = WindowsBackendError(
        NetworkErrorCode.ROUTE_NOT_ALLOWED,
        "global route conflict",
    )
    with pytest.raises(WindowsBackendError, match="global route"):
        run(create_plan(value))


def test_create_apply_verify_idempotency_and_ledger(tmp_path: Path) -> None:
    backend = FakeWindowsBackend()
    value, ledger, journals = provider(tmp_path, backend)
    plan = run(create_plan(value))

    receipt = run(value.apply(plan, idempotency_key=KEY, cancellation=ToolCancellationToken()))
    repeated = run(value.apply(plan, idempotency_key=KEY, cancellation=ToolCancellationToken()))
    verification = run(value.verify(plan))
    assert receipt.status is ReceiptStatus.APPLIED
    assert repeated.status is ReceiptStatus.APPLIED
    assert len(receipt.steps) == 5
    assert verification.succeeded
    assert backend.ensure_calls == 1
    entry = ledger.get(NETWORK_ID, NODE_A)
    assert entry is not None
    assert entry.secret_reference == "keyring:tmn/test"
    assert run(value.observe("tmn-test-a")).ownership is OwnershipState.MANAGED_OWNED
    ledger.assert_no_secret_material()
    journals.assert_no_secret_material()
    assert journals.find_by_plan_hash(f"sha256:{'0' * 64}") is None

    # 同一账本配合新的空 journal 验证时，不凭空创建操作记录。
    empty_journals = SQLiteWindowsOperationJournal(tmp_path / "empty-operations.sqlite3")
    verifier = WindowsNetworkProvider(backend, ledger, empty_journals)
    assert run(verifier.verify(plan)).succeeded
    assert empty_journals.find_by_plan_hash(plan.plan_hash) is None


def test_preflight_fingerprint_cancellation_key_conflict_and_concurrency(
    tmp_path: Path,
) -> None:
    backend = FakeWindowsBackend()
    value, _, _ = provider(tmp_path, backend)
    plan = run(create_plan(value))
    backend.mode = ProviderMode.OBSERVE_ONLY
    backend.error_code = "permission_denied"
    denied = run(value.apply(plan, idempotency_key=KEY, cancellation=ToolCancellationToken()))
    assert denied.error is not None
    assert denied.error.code is NetworkErrorCode.PERMISSION_DENIED

    backend.error_code = "dependency_unavailable"
    unavailable = run(
        value.apply(
            plan,
            idempotency_key=f"netop_{'b' * 64}",
            cancellation=ToolCancellationToken(),
        )
    )
    assert unavailable.error is not None
    assert unavailable.error.code is NetworkErrorCode.PROVIDER_UNAVAILABLE

    backend.mode = ProviderMode.MANAGED
    backend.snapshot = backend.snapshot.model_copy(update={"addresses": ("10.0.0.1/32",)})
    changed = run(
        value.apply(
            plan,
            idempotency_key=f"netop_{'c' * 64}",
            cancellation=ToolCancellationToken(),
        )
    )
    assert changed.error is not None
    assert changed.error.code is NetworkErrorCode.OWNERSHIP_CONFLICT

    backend.snapshot = absent()
    token = ToolCancellationToken()
    token.cancel()
    cancelled = run(value.apply(plan, idempotency_key=KEY, cancellation=token))
    assert cancelled.status is ReceiptStatus.CANCELLED
    another = run(create_plan(value, desired_config=desired(revision=2, parent_revision=1)))
    key_conflict = run(
        value.apply(another, idempotency_key=KEY, cancellation=ToolCancellationToken())
    )
    assert key_conflict.error is not None
    assert key_conflict.error.code is NetworkErrorCode.INVALID_CONFIG

    async def concurrent() -> None:
        other_backend = FakeWindowsBackend()
        other_backend.block = asyncio.Event()
        other, _, _ = provider(tmp_path / "concurrent", other_backend)
        other_plan = await create_plan(other)
        first = asyncio.create_task(
            other.apply(
                other_plan,
                idempotency_key=KEY,
                cancellation=ToolCancellationToken(),
            )
        )
        await asyncio.sleep(0)
        limited = await other.apply(
            other_plan,
            idempotency_key=f"netop_{'d' * 64}",
            cancellation=ToolCancellationToken(),
        )
        assert limited.error is not None and limited.error.retryable
        other_backend.block.set()
        await first

    run(concurrent())


@pytest.mark.parametrize(
    "failure",
    [PlanStepKind.WRITE_CONFIG, PlanStepKind.CONFIGURE_PEER],
)
def test_step_failure_can_rollback_confirmed_steps(
    tmp_path: Path,
    failure: PlanStepKind,
) -> None:
    backend = FakeWindowsBackend()
    backend.fail_step = failure
    value, ledger, _ = provider(tmp_path, backend)
    plan = run(create_plan(value))
    failed = run(value.apply(plan, idempotency_key=KEY, cancellation=ToolCancellationToken()))
    assert failed.status is ReceiptStatus.FAILED
    assert failed.error is not None and failed.error.retryable
    rolled = run(value.rollback(plan, failed, cancellation=ToolCancellationToken()))
    assert rolled.status is ReceiptStatus.ROLLED_BACK
    assert ledger.get(NETWORK_ID, NODE_A) is None


def test_rollback_missing_conflict_cancel_and_failure(tmp_path: Path) -> None:
    backend = FakeWindowsBackend()
    value, _, _ = provider(tmp_path, backend)
    plan = run(create_plan(value))
    missing_receipt = ProviderReceipt(
        idempotency_key=KEY,
        plan_hash=plan.plan_hash,
        revision=plan.desired.revision,
        provider=plan.desired.provider,
        observation_fingerprint=plan.observed_fingerprint,
        status=ReceiptStatus.FAILED,
        error=NetworkError(
            code=NetworkErrorCode.APPLY_FAILED,
            message="failed",
            correlation_id=plan.plan_hash,
        ),
    )
    missing = run(value.rollback(plan, missing_receipt, cancellation=ToolCancellationToken()))
    assert missing.status is ReceiptStatus.MANUAL_INTERVENTION

    created = run(value.apply(plan, idempotency_key=KEY, cancellation=ToolCancellationToken()))
    backend.snapshot = backend.snapshot.model_copy(update={"creation_nonce": "f" * 32})
    conflict = run(value.rollback(plan, created, cancellation=ToolCancellationToken()))
    assert conflict.error is not None
    assert conflict.error.code is NetworkErrorCode.OWNERSHIP_CONFLICT

    backend2 = FakeWindowsBackend()
    value2, _, _ = provider(tmp_path / "cancel", backend2)
    plan2 = run(create_plan(value2))
    created2 = run(value2.apply(plan2, idempotency_key=KEY, cancellation=ToolCancellationToken()))
    token = ToolCancellationToken()
    token.cancel()
    cancelled = run(value2.rollback(plan2, created2, cancellation=token))
    assert cancelled.status is ReceiptStatus.CANCELLED

    backend3 = FakeWindowsBackend()
    backend3.fail_rollback = PlanStepKind.ADD_HOST_ROUTE
    value3, _, _ = provider(tmp_path / "failure", backend3)
    plan3 = run(create_plan(value3))
    created3 = run(value3.apply(plan3, idempotency_key=KEY, cancellation=ToolCancellationToken()))
    failed = run(value3.rollback(plan3, created3, cancellation=ToolCancellationToken()))
    assert failed.status is ReceiptStatus.MANUAL_INTERVENTION
    assert failed.error is not None
    assert failed.error.code is NetworkErrorCode.ROLLBACK_FAILED


def test_crash_recovery_verify_failure_and_corrupt_journal(tmp_path: Path) -> None:
    backend = FakeWindowsBackend()
    backend.crash_step = PlanStepKind.CONFIGURE_PEER
    value, _, journals = provider(tmp_path, backend)
    plan = run(create_plan(value))
    with pytest.raises(RuntimeError, match="Windows crash"):
        run(value.apply(plan, idempotency_key=KEY, cancellation=ToolCancellationToken()))
    backend.crash_step = None
    recovered = run(value.recover(cancellation=ToolCancellationToken()))
    assert recovered[0].status is ReceiptStatus.ROLLED_BACK
    assert run(value.recover(cancellation=ToolCancellationToken())) == ()

    backend2 = FakeWindowsBackend()
    value2, _, _ = provider(tmp_path / "verify", backend2)
    plan2 = run(create_plan(value2))
    run(value2.apply(plan2, idempotency_key=KEY, cancellation=ToolCancellationToken()))
    backend2.snapshot = backend2.snapshot.model_copy(update={"addresses": ()})
    verification = run(value2.verify(plan2))
    assert not verification.succeeded
    assert verification.error is not None

    with sqlite3.connect(journals.path) as connection:
        connection.execute(
            "UPDATE windows_network_operations SET payload=?",
            ('{"private_key":"forbidden"}',),
        )
    with pytest.raises(ValueError, match="秘密字段"):
        journals.assert_no_secret_material()

    with sqlite3.connect(journals.path) as connection:
        connection.execute(
            "UPDATE windows_network_operations SET payload=?",
            ("[]",),
        )
    with pytest.raises(ValueError, match="结构"):
        journals.assert_no_secret_material()


def test_resume_crash_missing_ownership_successful_rollback_and_verified_not_recovered(
    tmp_path: Path,
) -> None:
    backend = FakeWindowsBackend()
    backend.crash_step = PlanStepKind.CONFIGURE_PEER
    value, ledger, _ = provider(tmp_path / "resume", backend)
    plan = run(create_plan(value))
    with pytest.raises(RuntimeError, match="crash"):
        run(value.apply(plan, idempotency_key=KEY, cancellation=ToolCancellationToken()))
    backend.crash_step = None
    resumed = run(value.apply(plan, idempotency_key=KEY, cancellation=ToolCancellationToken()))
    assert resumed.status is ReceiptStatus.APPLIED
    assert run(value.verify(plan)).succeeded
    assert run(value.recover(cancellation=ToolCancellationToken())) == ()

    rolled = run(value.rollback(plan, resumed, cancellation=ToolCancellationToken()))
    assert rolled.status is ReceiptStatus.ROLLED_BACK
    assert ledger.get(NETWORK_ID, NODE_A) is None

    incomplete = FakeWindowsBackend()
    incomplete.omit_ownership_after_create = True
    incomplete_value, _, _ = provider(tmp_path / "incomplete", incomplete)
    incomplete_plan = run(create_plan(incomplete_value))
    failed = run(
        incomplete_value.apply(
            incomplete_plan,
            idempotency_key=KEY,
            cancellation=ToolCancellationToken(),
        )
    )
    assert failed.status is ReceiptStatus.FAILED
    assert failed.error is not None
    assert failed.error.code is NetworkErrorCode.OWNERSHIP_CONFLICT


def test_update_stop_remove_and_naive_clock(tmp_path: Path) -> None:
    backend = FakeWindowsBackend()
    value, ledger, _ = provider(tmp_path, backend)
    create = run(create_plan(value))
    run(value.apply(create, idempotency_key=KEY, cancellation=ToolCancellationToken()))
    entry = ledger.get(NETWORK_ID, NODE_A)
    assert entry is not None

    update_config = desired(revision=2, parent_revision=1)
    update_observed = run(value.observe("tmn-test-a"))
    with pytest.raises(ValueError, match="指纹"):
        run(
            value.plan(
                action=NetworkAction.UPDATE,
                desired=update_config,
                observed=update_observed,
                ownership=entry.ownership.model_copy(
                    update={"system_fingerprint": f"sha256:{'f' * 64}"}
                ),
            )
        )
    update = run(
        value.plan(
            action=NetworkAction.UPDATE,
            desired=update_config,
            observed=update_observed,
            ownership=entry.ownership,
        )
    )
    updated = run(
        value.apply(
            update,
            idempotency_key=f"netop_{'b' * 64}",
            cancellation=ToolCancellationToken(),
        )
    )
    assert updated.status is ReceiptStatus.APPLIED
    updated_entry = ledger.get(NETWORK_ID, NODE_A)
    assert updated_entry is not None
    assert updated_entry.ownership.parent_revision == 2
    assert backend.ensure_calls == 1

    stop_observed = run(value.observe("tmn-test-a"))
    stop = run(
        value.plan(
            action=NetworkAction.STOP,
            desired=update_config,
            observed=stop_observed,
            ownership=updated_entry.ownership,
        )
    )
    stopped = run(
        value.apply(
            stop,
            idempotency_key=f"netop_{'c' * 64}",
            cancellation=ToolCancellationToken(),
        )
    )
    assert stopped.status is ReceiptStatus.APPLIED
    assert run(value.verify(stop)).succeeded

    backend.snapshot = backend.snapshot.model_copy(
        update={
            "interface_present": True,
            "service_present": True,
            "stable_interface_id": updated_entry.ownership.stable_interface_id,
            "public_key_hash": updated_entry.ownership.public_key_hash,
            "creation_nonce": updated_entry.ownership.creation_nonce,
        }
    )
    backend.snapshot = backend.snapshot.model_copy(
        update={
            "addresses": (update_config.address,),
            "host_routes": ("10.203.0.2/32",),
        }
    )
    # 将账本指纹同步为测试中的重新启动状态。
    ledger.put(
        entry.model_copy(
            update={
                "ownership": updated_entry.ownership.model_copy(
                    update={"system_fingerprint": backend.snapshot.system_fingerprint}
                ),
                "updated_at": updated_entry.updated_at,
            }
        )
    )
    remove_entry = ledger.get(NETWORK_ID, NODE_A)
    assert remove_entry is not None
    remove_observed = run(value.observe("tmn-test-a"))
    remove = run(
        value.plan(
            action=NetworkAction.REMOVE,
            desired=update_config,
            observed=remove_observed,
            ownership=remove_entry.ownership,
        )
    )

    removed = run(
        value.apply(
            remove,
            idempotency_key=f"netop_{'d' * 64}",
            cancellation=ToolCancellationToken(),
        )
    )
    assert removed.status is ReceiptStatus.APPLIED
    assert ledger.get(NETWORK_ID, NODE_A) is None

    naive, _, _ = provider(
        tmp_path / "naive",
        FakeWindowsBackend(),
        clock=lambda: NOW.replace(tzinfo=None),
    )
    with pytest.raises(ValueError, match="时区"):
        run(naive.observe("tmn-test-a"))


def test_remove_tolerates_idempotently_missing_ledger_at_commit(tmp_path: Path) -> None:
    backend = FakeWindowsBackend()
    value, ledger, _ = provider(tmp_path, backend)
    create = run(create_plan(value))
    run(value.apply(create, idempotency_key=KEY, cancellation=ToolCancellationToken()))
    entry = ledger.get(NETWORK_ID, NODE_A)
    assert entry is not None
    observed = run(value.observe("tmn-test-a"))
    remove = run(
        value.plan(
            action=NetworkAction.REMOVE,
            desired=desired(),
            observed=observed,
            ownership=entry.ownership,
        )
    )

    def remove_ledger_during_final_step(kind: PlanStepKind) -> None:
        if kind is PlanStepKind.DELETE_SECRET:
            ledger.delete(
                NETWORK_ID,
                NODE_A,
                expected_system_fingerprint=entry.ownership.system_fingerprint,
            )

    backend.on_step = remove_ledger_during_final_step
    result = run(
        value.apply(
            remove,
            idempotency_key=f"netop_{'e' * 64}",
            cancellation=ToolCancellationToken(),
        )
    )
    assert result.status is ReceiptStatus.APPLIED
    assert ledger.get(NETWORK_ID, NODE_A) is None
