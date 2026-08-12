"""阶段三 fake-only managed path lifecycle、恢复与故障隔离验收。"""

from __future__ import annotations

import asyncio
import sqlite3
from collections.abc import Callable
from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
from tests.agent.test_network_sync import NOW, signed
from tests.network.control_harness import (
    NetworkOperationPolicy,
    SQLiteNetworkAuthorizationRepository,
)
from tests.network.factories import NETWORK_ID, NODE_A, NODE_B, observation, ownership

from tunnelminion.domain.identifiers import AuthorizationId
from tunnelminion.network.contracts import (
    AcknowledgementStage,
    ManagedResourceOwnership,
    NetworkAcknowledgement,
    NetworkAction,
    NetworkError,
    NetworkErrorCode,
    NetworkObservation,
    NetworkPlan,
    OwnershipState,
    ProviderKind,
    ProviderReceipt,
    ReceiptStatus,
    SignedDesiredConfig,
    VerificationResult,
)
from tunnelminion.network.fakes import FakeProviderBehavior, InMemoryNetworkProvider
from tunnelminion.network.governance import (
    LifecycleCrashBoundary,
    LifecycleInjectedCrash,
    ManagedPathLifecycle,
    ManagedPathLifecycleError,
    NetworkApplyClaimConflictError,
    NetworkAuthorizationConflictError,
    NetworkAuthorizationGrant,
    NetworkAuthorizationScope,
    NetworkAuthorizationStorageError,
    NetworkGovernancePhase,
    NetworkGovernanceRecord,
    NetworkJournalEntry,
    NetworkPathStatus,
    NetworkPolicyAction,
    NetworkPolicyDecision,
    SQLiteNetworkGovernanceStore,
)
from tunnelminion.network.path_controller import (
    DirectPathErrorCode,
    DirectPathEvidence,
    NetworkPathType,
    PathSelection,
)
from tunnelminion.tools.contracts import ToolCancellationToken


class MemoryAcknowledgements:
    """只记录脱敏 acknowledgement，并可独立注入远端故障。"""

    def __init__(self, order: list[str]) -> None:
        self.order = order
        self.items: list[NetworkAcknowledgement] = []
        self.fail = False

    async def acknowledge(self, acknowledgement: NetworkAcknowledgement) -> None:
        self.order.append("ack")
        if self.fail:
            raise ConnectionError("fake acknowledgement sink offline")
        self.items.append(acknowledgement)


class MemoryPathSink:
    """只记录脱敏 path status，并可独立注入远端故障。"""

    def __init__(self, order: list[str]) -> None:
        self.order = order
        self.items: list[tuple[NetworkPathStatus, str]] = []
        self.fail = False

    async def publish(self, status: NetworkPathStatus, *, idempotency_key: str) -> None:
        self.order.append("path")
        if self.fail:
            raise ConnectionError("fake path sink offline")
        self.items.append((status, idempotency_key))


class FakePathVerifier:
    """完全隔离的 path evidence 读取器。"""

    def __init__(self, result: DirectPathEvidence | None = None) -> None:
        self.result = result
        self.calls = 0
        self.error: Exception | None = None

    async def verify(self, plan: NetworkPlan, *, now: datetime) -> DirectPathEvidence:
        self.calls += 1
        if self.error is not None:
            raise self.error
        assert self.result is not None
        return DirectPathEvidence.model_validate(
            {
                **self.result.model_dump(mode="python"),
                "network_id": plan.desired.network_id,
                "node_id": plan.desired.target_node_id,
                "plan_hash": plan.plan_hash,
                "authorization_revision": plan.desired.revision,
                "revision": plan.desired.revision,
                "observed_at": now,
                "expires_at": now + timedelta(seconds=self.result.freshness_ttl_seconds),
            }
        )


class FakePathController:
    """只消费 fake evidence 的可控 controller。"""

    def __init__(self, selection: PathSelection) -> None:
        self._selection = selection
        self.calls = 0
        self.error: BaseException | None = None

    @property
    def selection(self) -> PathSelection:
        return self._selection

    async def reconcile(
        self,
        evidence: DirectPathEvidence,
        *,
        fallback: NetworkPathType = NetworkPathType.STATIC,
    ) -> PathSelection:
        self.calls += 1
        if self.error is not None:
            raise self.error
        self._selection = PathSelection.model_validate(
            {
                **self._selection.model_dump(mode="python"),
                "network_id": evidence.network_id,
                "node_id": evidence.node_id,
                "plan_hash": evidence.plan_hash,
                "authorization_revision": evidence.authorization_revision,
                "provider": evidence.provider,
                "revision": evidence.revision,
                "path_type": NetworkPathType.DIRECT if evidence.verified else fallback,
                "target_host_hash": evidence.target_host_hash,
                "target_port": evidence.target_port,
                "route_identity_hash": evidence.route_identity_hash,
                "expires_at": evidence.expires_at,
                "last_evidence_at": evidence.observed_at,
                "stable_error_code": evidence.stable_error_code,
            }
        )
        return self._selection


class DelayedFailurePathVerifier(FakePathVerifier):
    """先让出调度，再报告 fake probe 失败，以验证异步异常边界。"""

    async def verify(self, plan: NetworkPlan, *, now: datetime) -> DirectPathEvidence:
        await asyncio.sleep(0)
        raise TimeoutError("fake delayed probe timeout")


class CancelledPathVerifier(FakePathVerifier):
    """在 fake path probe 边界传播取消，不把它伪装成降级结果。"""

    async def verify(self, plan: NetworkPlan, *, now: datetime) -> DirectPathEvidence:
        raise asyncio.CancelledError


class VerifyThenRollbackFailureProvider(InMemoryNetworkProvider):
    """先让独立 Provider verify 失败，再让 rollback 失败。"""

    async def verify(self, plan: NetworkPlan):  # type: ignore[no-untyped-def]
        self.behavior = FakeProviderBehavior.VERIFY_FAILURE
        result = await super().verify(plan)
        self.behavior = FakeProviderBehavior.ROLLBACK_FAILURE
        return result


class MismatchedReceiptProvider(InMemoryNetworkProvider):
    """返回字段自洽但不绑定当前 lifecycle 的 fake receipt。"""

    async def apply(
        self,
        plan: NetworkPlan,
        *,
        idempotency_key: str,
        cancellation: ToolCancellationToken,
    ) -> ProviderReceipt:
        receipt = await super().apply(
            plan,
            idempotency_key=idempotency_key,
            cancellation=cancellation,
        )
        return ProviderReceipt.model_validate(
            {
                **receipt.model_dump(mode="python"),
                "idempotency_key": f"netop_{'f' * 64}",
            }
        )


class MismatchedVerificationProvider(InMemoryNetworkProvider):
    """返回字段自洽但 plan hash 不同的 fake verification。"""

    async def verify(self, plan: NetworkPlan) -> VerificationResult:
        verification = await super().verify(plan)
        return VerificationResult.model_validate(
            {
                **verification.model_dump(mode="python"),
                "plan_hash": f"sha256:{'f' * 64}",
            }
        )


class MismatchedRecoveryReceiptProvider(InMemoryNetworkProvider):
    """恢复查询返回错误 idempotency 绑定的 fake receipt。"""

    async def recover(
        self,
        *,
        cancellation: ToolCancellationToken,
    ) -> tuple[ProviderReceipt, ...]:
        receipts = await super().recover(cancellation=cancellation)
        return tuple(
            ProviderReceipt.model_validate(
                {
                    **receipt.model_dump(mode="python"),
                    "idempotency_key": f"netop_{'e' * 64}",
                }
            )
            for receipt in receipts
        )


class StorageFailurePolicy(NetworkOperationPolicy):
    """授权仓储读取失败的稳定 fake。"""

    def evaluate(self, plan: NetworkPlan, *, at: datetime) -> NetworkPolicyDecision:
        raise NetworkAuthorizationStorageError("fake authorization storage failure")


class AlwaysAuthorizedPolicy(NetworkOperationPolicy):
    """仅用于覆盖已由本地 fake 授权的首次生命周期分支。"""

    def __init__(
        self,
        *,
        fail_on_call: int | None = None,
        mismatch_on_call: int | None = None,
    ) -> None:
        super().__init__()
        self.authorization_id = AuthorizationId.new()
        self.calls = 0
        self.fail_on_call = fail_on_call
        self.mismatch_on_call = mismatch_on_call

    def evaluate(self, plan: NetworkPlan, *, at: datetime) -> NetworkPolicyDecision:
        self.calls += 1
        if self.fail_on_call == self.calls:
            raise NetworkAuthorizationStorageError("fake authorization storage failure")
        if self.mismatch_on_call == self.calls:
            return NetworkPolicyDecision(
                action=NetworkPolicyAction.AWAIT_AUTHORIZATION,
                code="fake_recheck_mismatch",
            )
        return NetworkPolicyDecision(
            action=NetworkPolicyAction.EXECUTE,
            code="fake_preapproved",
            authorization_id=self.authorization_id,
        )


class FailOnEvaluationPolicy(NetworkOperationPolicy):
    """在指定一次 evaluate 上注入存储失败或 scope 变化。"""

    def __init__(self, *, fail_at: int | None = None, mismatch_at: int | None = None) -> None:
        super().__init__()
        self.calls = 0
        self.fail_at = fail_at
        self.mismatch_at = mismatch_at

    def evaluate(self, plan: NetworkPlan, *, at: datetime) -> NetworkPolicyDecision:
        self.calls += 1
        if self.fail_at == self.calls:
            raise NetworkAuthorizationStorageError("fake authorization storage failure")
        result = super().evaluate(plan, at=at)
        if self.mismatch_at == self.calls:
            return NetworkPolicyDecision(
                action=NetworkPolicyAction.AWAIT_AUTHORIZATION,
                code="local_l3_scope_mismatch",
            )
        return result


class CancelApplyProvider(InMemoryNetworkProvider):
    """apply 进入不确定取消边界的 fake。"""

    async def apply(
        self,
        plan: NetworkPlan,
        *,
        idempotency_key: str,
        cancellation: ToolCancellationToken,
    ) -> ProviderReceipt:
        self.apply_calls += 1
        raise asyncio.CancelledError


class CancelRollbackProvider(InMemoryNetworkProvider):
    """verify 失败后 rollback 被取消的 fake。"""

    async def verify(self, plan: NetworkPlan) -> VerificationResult:
        self.behavior = FakeProviderBehavior.VERIFY_FAILURE
        return await super().verify(plan)

    async def rollback(
        self,
        plan: NetworkPlan,
        receipt: ProviderReceipt,
        *,
        cancellation: ToolCancellationToken,
    ) -> ProviderReceipt:
        self.rollback_calls += 1
        raise asyncio.CancelledError


class ObserveFailureProvider(InMemoryNetworkProvider):
    """恢复前实时状态读取失败的 fake。"""

    def __init__(self, *, behavior: FakeProviderBehavior = FakeProviderBehavior.SUCCESS) -> None:
        super().__init__(observation(), behavior=behavior)
        self.fail_observe = False

    async def observe(self, interface_name: str) -> NetworkObservation:
        if self.fail_observe:
            raise ConnectionError("fake live observation unavailable")
        return await super().observe(interface_name)


class RecoverFailureProvider(InMemoryNetworkProvider):
    """Provider recover 读取失败的 fake。"""

    async def recover(
        self,
        *,
        cancellation: ToolCancellationToken,
    ) -> tuple[ProviderReceipt, ...]:
        raise ConnectionError("fake recovery unavailable")


class RecoverAppliedProvider(InMemoryNetworkProvider):
    """恢复只查询已有回执，不自动调用 rollback。"""

    async def recover(
        self,
        *,
        cancellation: ToolCancellationToken,
    ) -> tuple[ProviderReceipt, ...]:
        return tuple(self._receipts.values())  # type: ignore[attr-defined]


class RecoverCancelledProvider(InMemoryNetworkProvider):
    """返回已知的 cancelled 回执，验证终态映射。"""

    async def recover(
        self,
        *,
        cancellation: ToolCancellationToken,
    ) -> tuple[ProviderReceipt, ...]:
        receipts = tuple(self._receipts.values())  # type: ignore[attr-defined]
        if not receipts:
            return ()
        return (
            receipts[0].model_copy(
                update={
                    "status": ReceiptStatus.CANCELLED,
                    "error": NetworkError(
                        code=NetworkErrorCode.CANCELLED,
                        message="fake cancelled recovery",
                        correlation_id=receipts[0].plan_hash,
                    ),
                }
            ),
        )


class EmptyRecoverProvider(InMemoryNetworkProvider):
    """恢复查询没有找到同一 plan 的 fake Provider。"""

    async def recover(
        self,
        *,
        cancellation: ToolCancellationToken,
    ) -> tuple[ProviderReceipt, ...]:
        return ()


class RecoverManualProvider(InMemoryNetworkProvider):
    """恢复查询返回 manual intervention 回执的 fake Provider。"""

    async def recover(
        self,
        *,
        cancellation: ToolCancellationToken,
    ) -> tuple[ProviderReceipt, ...]:
        receipts = tuple(self._receipts.values())  # type: ignore[attr-defined]
        if not receipts:
            return ()
        return (
            receipts[0].model_copy(
                update={
                    "status": ReceiptStatus.MANUAL_INTERVENTION,
                    "error": NetworkError(
                        code=NetworkErrorCode.ROLLBACK_FAILED,
                        message="fake manual recovery",
                        correlation_id=receipts[0].plan_hash,
                    ),
                }
            ),
        )


class ConflictOnRecoverProvider(InMemoryNetworkProvider):
    """恢复前实时资源被其他所有者接管的 fake。"""

    def __init__(self) -> None:
        super().__init__(observation())
        self.conflict = False

    async def observe(self, interface_name: str) -> NetworkObservation:
        if self.conflict:
            return observation(ownership_state=OwnershipState.OWNERSHIP_CONFLICT)
        return await super().observe(interface_name)


class BrokenSelectionController(FakePathController):
    """读取 fallback 选择也失败的 fake controller。"""

    @property
    def selection(self) -> PathSelection:
        raise RuntimeError("selection unavailable")

    async def reconcile(
        self,
        evidence: DirectPathEvidence,
        *,
        fallback: NetworkPathType = NetworkPathType.STATIC,
    ) -> PathSelection:
        raise RuntimeError("controller unavailable")


class CountingLedger:
    """恢复时记录账本读取次数的 fake 只读端口。"""

    def __init__(self, entry: object | None = None) -> None:
        self.calls = 0
        self.entry = entry
        self.keys: list[tuple[object, object]] = []

    def get(self, network_id: object, node_id: object) -> object | None:
        self.calls += 1
        self.keys.append((network_id, node_id))
        return self.entry


def create_recovery_ledger() -> CountingLedger:
    """构造已知受管资源账本，供 CREATE 崩溃恢复 fake 使用。"""
    return CountingLedger(
        SimpleNamespace(
            ownership=ownership(observation(ownership_state=OwnershipState.MANAGED_OWNED))
        )
    )


def path_evidence(
    *,
    verified: bool = True,
    error: DirectPathErrorCode | None = None,
) -> DirectPathEvidence:
    """构造不含 endpoint 正文的四维 fake evidence。"""
    failed = error is not None or not verified
    return DirectPathEvidence(
        network_id=NETWORK_ID,
        node_id=NODE_A,
        plan_hash=f"sha256:{'a' * 64}",
        authorization_revision=1,
        provider=ProviderKind.WINDOWS,
        revision=1,
        target_host_hash=f"sha256:{'b' * 64}",
        target_port=51820,
        route_identity_hash=f"sha256:{'c' * 64}",
        candidate_count=1,
        selected_candidate_hash=f"sha256:{'a' * 64}" if not failed else None,
        endpoint_probe_at=NOW,
        endpoint_probe_succeeded=not failed or error is DirectPathErrorCode.TARGET_UNREACHABLE,
        last_handshake_at=NOW,
        handshake_probe_at=NOW,
        handshake_fresh=not failed or error is DirectPathErrorCode.TARGET_UNREACHABLE,
        host_route_probe_at=NOW,
        host_route_present=not failed or error is DirectPathErrorCode.TARGET_UNREACHABLE,
        target_probe_at=NOW,
        target_probe_succeeded=verified,
        verified=verified,
        stable_error_code=None if verified else (error or DirectPathErrorCode.TARGET_UNREACHABLE),
        source="fake",
        observed_at=NOW,
        expires_at=NOW + timedelta(seconds=180),
    )


def controller() -> FakePathController:
    return FakePathController(
        PathSelection(
            path_type=NetworkPathType.STATIC,
            provider=ProviderKind.WINDOWS,
            revision=1,
            candidate_count=0,
            consecutive_failures=0,
            consecutive_successes=0,
            selected_at=NOW,
            last_evidence_at=NOW,
        )
    )


def grant_for(record: NetworkGovernanceRecord) -> NetworkAuthorizationGrant:
    return NetworkAuthorizationGrant(
        authorization_id=AuthorizationId.new(),
        scope=NetworkAuthorizationScope.from_plan(
            record.plan,
            address_pool="10.203.0.0/24",
        ),
        approved_by="fake-local-owner",
        approved_at=NOW,
        expires_at=NOW + timedelta(minutes=5),
    )


def build(
    tmp_path: Path,
    *,
    behavior: FakeProviderBehavior = FakeProviderBehavior.SUCCESS,
    evidence: DirectPathEvidence | None = None,
    verifier: FakePathVerifier | None = None,
    path_controller: FakePathController | None = None,
    ack: MemoryAcknowledgements | None = None,
    path_sink: MemoryPathSink | None = None,
    ledger: CountingLedger | None = None,
    policy: NetworkOperationPolicy | None = None,
    provider_override: InMemoryNetworkProvider | None = None,
    without_ack_sink: bool = False,
    without_path_sink: bool = False,
    crash_after: LifecycleCrashBoundary | None = None,
    commit_last_known_good: Callable[[object], object] | None = None,
    clock: Callable[[], datetime] | None = None,
    apply_lease_seconds: int = 30,
) -> tuple[
    ManagedPathLifecycle,
    NetworkOperationPolicy,
    InMemoryNetworkProvider,
    MemoryAcknowledgements,
    MemoryPathSink,
    FakePathVerifier,
    FakePathController,
    SQLiteNetworkGovernanceStore,
]:
    order: list[str] = []
    acknowledgements = ack or MemoryAcknowledgements(order)
    sink = path_sink or MemoryPathSink(order)
    fake_verifier = verifier or FakePathVerifier(evidence or path_evidence())
    fake_controller = path_controller or controller()
    provider_type = (
        VerifyThenRollbackFailureProvider
        if behavior is FakeProviderBehavior.ROLLBACK_FAILURE
        else InMemoryNetworkProvider
    )
    provider = provider_override or provider_type(observation(), behavior=behavior)
    policy = policy or NetworkOperationPolicy()
    database = tmp_path / "governance.sqlite3"
    repository = SQLiteNetworkAuthorizationRepository(database)
    store = SQLiteNetworkGovernanceStore(
        database,
        authorization_repository=repository,
    )
    attach_writer = getattr(policy, "attach_writer", None)
    if callable(attach_writer):
        attach_writer(repository)
    lifecycle = ManagedPathLifecycle(
        provider,
        policy,
        store,
        None if without_ack_sink else acknowledgements,
        path_verifier=fake_verifier,
        path_controller=fake_controller,
        path_status_sink=None if without_path_sink else sink,
        ledger=ledger,
        clock=clock or (lambda: NOW),
        commit_last_known_good=commit_last_known_good,
        crash_after=crash_after,
        apply_lease_seconds=apply_lease_seconds,
    )
    return (
        lifecycle,
        policy,
        provider,
        acknowledgements,
        sink,
        fake_verifier,
        fake_controller,
        store,
    )


async def authorize(
    lifecycle: ManagedPathLifecycle,
    policy: NetworkOperationPolicy,
    provider: InMemoryNetworkProvider,
    *,
    action: NetworkAction = NetworkAction.CREATE,
) -> NetworkGovernanceRecord:
    """先保留 pending，再由 fake 本机控制面显式批准。"""
    envelope, _ = signed()
    pending = await lifecycle.reconcile(envelope, action=action, ownership=None)
    assert pending.phase is NetworkGovernancePhase.AWAITING_AUTHORIZATION
    assert provider.apply_calls == 0
    policy.approve(grant_for(pending), capability=policy.local_control_capability())
    return await lifecycle.reconcile(envelope, action=action, ownership=None)


@pytest.mark.anyio
async def test_lifecycle_orders_all_boundaries_and_updates_last_known_good(tmp_path: Path) -> None:
    committed: list[object] = []
    lifecycle, policy, provider, acknowledgements, sink, verifier, fake_controller, store = build(
        tmp_path,
        commit_last_known_good=committed.append,
    )
    result = await authorize(lifecycle, policy, provider)

    assert result.phase is NetworkGovernancePhase.VERIFIED
    assert result.last_known_good_revision == 1
    assert committed and committed[0] is not None
    assert provider.apply_calls == 1
    assert provider.verify_calls == 1
    assert verifier.calls == 1
    assert fake_controller.calls == 1
    assert [entry.phase for entry in result.journal] == [
        NetworkGovernancePhase.OBSERVING,
        NetworkGovernancePhase.PLANNING,
        NetworkGovernancePhase.AWAITING_AUTHORIZATION,
        NetworkGovernancePhase.AWAITING_AUTHORIZATION,
        NetworkGovernancePhase.AUTHORIZED,
        NetworkGovernancePhase.RECHECKING,
        NetworkGovernancePhase.APPLYING,
        NetworkGovernancePhase.APPLIED,
        NetworkGovernancePhase.VERIFYING,
        NetworkGovernancePhase.PROVIDER_VERIFIED,
        NetworkGovernancePhase.PATH_VERIFYING,
        NetworkGovernancePhase.PATH_RECONCILING,
        NetworkGovernancePhase.ACKNOWLEDGING,
        NetworkGovernancePhase.ACKNOWLEDGING,
        NetworkGovernancePhase.VERIFIED,
    ]
    assert acknowledgements.items[-1].stage is AcknowledgementStage.VERIFIED
    assert sink.items[0][0].path_type in {"direct", "static"}
    assert result.acknowledgement_delivered and result.path_status_delivered
    assert await lifecycle._retry_sinks(result) == result  # type: ignore[reportPrivateUsage]
    assert (
        await lifecycle._deliver_sinks(  # type: ignore[reportPrivateUsage]
            result,
            final_phase=NetworkGovernancePhase.VERIFIED,
            acknowledgement_stage=AcknowledgementStage.VERIFIED,
        )
        == result
    )
    assert store.get(NETWORK_ID, NODE_A, 1) == result


@pytest.mark.anyio
async def test_path_failure_degrades_without_provider_rollback_or_lkg(tmp_path: Path) -> None:
    lifecycle, policy, provider, _, sink, _, fake_controller, _ = build(
        tmp_path,
        evidence=path_evidence(verified=False, error=DirectPathErrorCode.HOST_ROUTE_MISSING),
    )
    result = await authorize(lifecycle, policy, provider)

    assert result.phase is NetworkGovernancePhase.PATH_DEGRADED
    assert result.last_known_good_revision is None
    assert provider.apply_calls == 1
    assert provider.rollback_calls == 0
    assert fake_controller.calls == 1
    assert sink.items[0][0].stable_error_code == DirectPathErrorCode.HOST_ROUTE_MISSING.value


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("behavior", "phase"),
    [
        (FakeProviderBehavior.VERIFY_FAILURE, NetworkGovernancePhase.ROLLED_BACK),
        (FakeProviderBehavior.STEP_FAILURE, NetworkGovernancePhase.ROLLED_BACK),
        (FakeProviderBehavior.ROLLBACK_FAILURE, NetworkGovernancePhase.MANUAL_INTERVENTION),
        (FakeProviderBehavior.OWNERSHIP_REPLACED, NetworkGovernancePhase.OWNERSHIP_CONFLICT),
    ],
)
async def test_provider_failure_matrix_is_explicit(
    tmp_path: Path,
    behavior: FakeProviderBehavior,
    phase: NetworkGovernancePhase,
) -> None:
    lifecycle, policy, provider, acknowledgements, sink, verifier, _, _ = build(
        tmp_path,
        behavior=behavior,
    )
    result = await authorize(lifecycle, policy, provider)

    assert result.phase is phase
    assert provider.rollback_calls == 1
    assert verifier.calls == 0
    assert not sink.items
    assert acknowledgements.items[-1].stage in {
        AcknowledgementStage.ROLLED_BACK,
        AcknowledgementStage.OWNERSHIP_CONFLICT,
        AcknowledgementStage.MANUAL_INTERVENTION,
    }


@pytest.mark.anyio
async def test_provider_receipt_and_verification_bindings_fail_closed_without_lkg(
    tmp_path: Path,
) -> None:
    committed: list[object] = []
    receipt_lifecycle, receipt_policy, receipt_provider, _, _, _, _, _ = build(
        tmp_path / "receipt",
        provider_override=MismatchedReceiptProvider(observation()),
        commit_last_known_good=committed.append,
    )
    receipt_result = await authorize(receipt_lifecycle, receipt_policy, receipt_provider)
    assert receipt_result.phase is NetworkGovernancePhase.RECOVERY_REQUIRED
    assert receipt_result.stable_error_code == NetworkErrorCode.JOURNAL_CONFLICT.value
    assert receipt_result.last_known_good_revision is None
    assert committed == []

    verification_lifecycle, verification_policy, verification_provider, _, _, _, _, _ = build(
        tmp_path / "verification",
        provider_override=MismatchedVerificationProvider(observation()),
        commit_last_known_good=committed.append,
    )
    verification_result = await authorize(
        verification_lifecycle,
        verification_policy,
        verification_provider,
    )
    assert verification_result.phase is NetworkGovernancePhase.RECOVERY_REQUIRED
    assert verification_result.stable_error_code == NetworkErrorCode.JOURNAL_CONFLICT.value
    assert verification_result.last_known_good_revision is None
    assert committed == []

    recovery_provider = MismatchedRecoveryReceiptProvider(observation())
    envelope, _, recovery_policy, recovery_provider, recovery_store = await crash_after_apply(
        tmp_path / "recovery",
        recovery_provider,
    )
    recovered = await recover_one(
        envelope,
        recovery_policy,
        recovery_provider,
        recovery_store,
    )
    assert recovered.phase is NetworkGovernancePhase.RECOVERY_REQUIRED
    assert recovery_provider.apply_calls == 1


@pytest.mark.anyio
async def test_apply_is_zero_without_grant_and_recheck_blocks_revocation(tmp_path: Path) -> None:
    lifecycle, policy, provider, _, _, _, _, store = build(tmp_path)
    envelope, _ = signed()
    pending = await lifecycle.reconcile(envelope, action=NetworkAction.CREATE, ownership=None)
    assert pending.phase is NetworkGovernancePhase.AWAITING_AUTHORIZATION
    assert provider.apply_calls == 0

    grant = grant_for(pending)
    policy.approve(grant, capability=policy.local_control_capability())
    policy.revoke(
        grant.authorization_id,
        revoked_at=NOW,
        capability=policy.local_control_capability(),
    )
    blocked = await lifecycle.reconcile(envelope, action=NetworkAction.CREATE, ownership=None)
    assert blocked.phase is NetworkGovernancePhase.AWAITING_AUTHORIZATION
    assert provider.apply_calls == 0
    assert store.get(NETWORK_ID, NODE_A, 1) == blocked


@pytest.mark.anyio
async def test_revoke_injected_between_claim_and_assert_blocks_provider_apply(
    tmp_path: Path,
) -> None:
    lifecycle, policy, provider, _, _, _, _, store = build(tmp_path / "claim-revoke")
    envelope, _ = signed()
    pending = await lifecycle.reconcile(envelope, action=NetworkAction.CREATE, ownership=None)
    grant = grant_for(pending)
    policy.approve(grant, capability=policy.local_control_capability())
    other = SQLiteNetworkAuthorizationRepository(tmp_path / "claim-revoke" / "governance.sqlite3")
    original_assert = store.assert_apply_claim

    def revoke_before_assert(claim: object, *, now: datetime) -> None:
        other.revoke(
            grant.authorization_id,
            revoked_at=NOW,
            capability=other.authorization_capability(),
        )
        original_assert(claim, now=now)  # type: ignore[arg-type]

    store.assert_apply_claim = revoke_before_assert  # type: ignore[method-assign]
    result = await lifecycle.reconcile(envelope, action=NetworkAction.CREATE, ownership=None)
    assert result.phase is NetworkGovernancePhase.RECOVERY_REQUIRED
    assert result.stable_error_code == NetworkErrorCode.CLAIM_CONFLICT.value
    assert provider.apply_calls == 0
    other.close()


@pytest.mark.anyio
async def test_authorization_storage_failures_remain_pending_and_never_apply(
    tmp_path: Path,
) -> None:
    failing = StorageFailurePolicy()
    lifecycle, _, provider, _, _, _, _, _ = build(tmp_path, policy=failing)
    envelope, _ = signed()
    first = await lifecycle.reconcile(envelope, action=NetworkAction.CREATE, ownership=None)
    second = await lifecycle.reconcile(envelope, action=NetworkAction.CREATE, ownership=None)
    assert first.phase is NetworkGovernancePhase.AWAITING_AUTHORIZATION
    assert second.phase is NetworkGovernancePhase.AWAITING_AUTHORIZATION
    assert second.stable_error_code == "local_l3_authorization_storage_unavailable"
    assert provider.apply_calls == 0

    recheck_failure = FailOnEvaluationPolicy(fail_at=3)
    retry_lifecycle, retry_policy, retry_provider, _, _, _, _, _ = build(
        tmp_path / "recheck-storage",
        policy=recheck_failure,
    )
    pending = await retry_lifecycle.reconcile(
        envelope,
        action=NetworkAction.CREATE,
        ownership=None,
    )
    retry_policy.approve(grant_for(pending), capability=retry_policy.local_control_capability())
    blocked = await retry_lifecycle.reconcile(
        envelope,
        action=NetworkAction.CREATE,
        ownership=None,
    )
    assert blocked.phase is NetworkGovernancePhase.AWAITING_AUTHORIZATION
    assert retry_provider.apply_calls == 0

    mismatch_policy = FailOnEvaluationPolicy(mismatch_at=3)
    mismatch_lifecycle, mismatch_policy, mismatch_provider, _, _, _, _, _ = build(
        tmp_path / "recheck-mismatch",
        policy=mismatch_policy,
    )
    mismatch_pending = await mismatch_lifecycle.reconcile(
        envelope,
        action=NetworkAction.CREATE,
        ownership=None,
    )
    mismatch_policy.approve(
        grant_for(mismatch_pending), capability=mismatch_policy.local_control_capability()
    )
    mismatched = await mismatch_lifecycle.reconcile(
        envelope,
        action=NetworkAction.CREATE,
        ownership=None,
    )
    assert mismatched.phase is NetworkGovernancePhase.AWAITING_AUTHORIZATION
    assert mismatch_provider.apply_calls == 0


@pytest.mark.anyio
async def test_concurrency_and_cancel_safe_point_do_not_duplicate_apply(tmp_path: Path) -> None:
    lifecycle, policy, provider, _, _, _, _, _ = build(tmp_path)
    envelope, _ = signed()
    pending = await lifecycle.reconcile(envelope, action=NetworkAction.CREATE, ownership=None)
    policy.approve(grant_for(pending), capability=policy.local_control_capability())
    gate = asyncio.Event()
    original = provider.apply

    async def blocked_apply(
        plan: NetworkPlan,
        *,
        idempotency_key: str,
        cancellation: ToolCancellationToken,
    ) -> ProviderReceipt:
        await gate.wait()
        return await original(plan, idempotency_key=idempotency_key, cancellation=cancellation)

    provider.apply = blocked_apply  # type: ignore[method-assign]
    first = asyncio.create_task(
        lifecycle.reconcile(envelope, action=NetworkAction.CREATE, ownership=None)
    )
    await asyncio.sleep(0)
    with pytest.raises(RuntimeError, match="已在运行"):
        await lifecycle.reconcile(envelope, action=NetworkAction.CREATE, ownership=None)
    with pytest.raises(RuntimeError, match="已在运行"):
        await lifecycle.recover()
    gate.set()
    await first

    cancelled_lifecycle, cancelled_policy, cancelled_provider, _, _, _, _, _ = build(
        tmp_path / "cancelled"
    )
    cancelled_pending = await cancelled_lifecycle.reconcile(
        envelope,
        action=NetworkAction.CREATE,
        ownership=None,
    )
    cancelled_policy.approve(
        grant_for(cancelled_pending), capability=cancelled_policy.local_control_capability()
    )
    token = ToolCancellationToken()
    token.cancel()
    cancelled = await cancelled_lifecycle.reconcile(
        envelope,
        action=NetworkAction.CREATE,
        ownership=None,
        cancellation=token,
    )
    assert cancelled.phase is NetworkGovernancePhase.CANCELLED
    assert cancelled_provider.apply_calls == 0


@pytest.mark.anyio
async def test_two_lifecycles_shared_sqlite_claim_have_one_provider_apply(
    tmp_path: Path,
) -> None:
    envelope, _ = signed()
    provider = InMemoryNetworkProvider(observation())
    database = tmp_path / "shared-lifecycle.sqlite3"
    first_policy = NetworkOperationPolicy()
    first_repository = SQLiteNetworkAuthorizationRepository(database)
    first_store = SQLiteNetworkGovernanceStore(
        database,
        authorization_repository=first_repository,
    )
    first_policy.attach_writer(first_repository)
    first = ManagedPathLifecycle(
        provider,
        first_policy,
        first_store,
        MemoryAcknowledgements([]),
        path_verifier=FakePathVerifier(path_evidence()),
        path_controller=controller(),
        clock=lambda: NOW,
    )
    pending = await first.reconcile(envelope, action=NetworkAction.CREATE, ownership=None)
    grant = grant_for(pending)
    first_policy.approve(
        grant,
        capability=first_policy.local_control_capability(),
    )

    second_policy = NetworkOperationPolicy()
    second_repository = SQLiteNetworkAuthorizationRepository(database)
    second_store = SQLiteNetworkGovernanceStore(
        database,
        authorization_repository=second_repository,
    )
    second_policy.attach_writer(second_repository)
    second = ManagedPathLifecycle(
        provider,
        second_policy,
        second_store,
        MemoryAcknowledgements([]),
        path_verifier=FakePathVerifier(path_evidence()),
        path_controller=controller(),
        clock=lambda: NOW,
    )
    gate = asyncio.Event()
    started = asyncio.Event()
    original_apply = provider.apply

    async def blocked_apply(
        plan: NetworkPlan,
        *,
        idempotency_key: str,
        cancellation: ToolCancellationToken,
    ) -> ProviderReceipt:
        started.set()
        await gate.wait()
        return await original_apply(
            plan,
            idempotency_key=idempotency_key,
            cancellation=cancellation,
        )

    provider.apply = blocked_apply  # type: ignore[method-assign]
    first_task = asyncio.create_task(
        first.reconcile(envelope, action=NetworkAction.CREATE, ownership=None)
    )
    await started.wait()
    with pytest.raises(NetworkApplyClaimConflictError, match="活动 apply claim"):
        second_repository.revoke(
            grant.authorization_id,
            revoked_at=NOW + timedelta(seconds=1),
            capability=second_repository.authorization_capability(),
        )
    second_result = await second.reconcile(
        envelope,
        action=NetworkAction.CREATE,
        ownership=None,
    )
    assert second_result.phase is NetworkGovernancePhase.APPLYING
    assert provider.apply_calls == 0
    gate.set()
    first_result = await first_task
    assert first_result.phase is NetworkGovernancePhase.VERIFIED
    assert provider.apply_calls == 1


@pytest.mark.anyio
async def test_renewal_conflict_during_long_apply_forces_recovery_without_lkg(
    tmp_path: Path,
) -> None:
    committed: list[object] = []
    lifecycle, policy, provider, _, _, _, _, store = build(
        tmp_path,
        commit_last_known_good=committed.append,
        apply_lease_seconds=1,
    )
    envelope, _ = signed()
    pending = await lifecycle.reconcile(envelope, action=NetworkAction.CREATE, ownership=None)
    policy.approve(grant_for(pending), capability=policy.local_control_capability())
    started = asyncio.Event()
    release = asyncio.Event()
    original_apply = provider.apply

    async def long_apply(
        plan: NetworkPlan,
        *,
        idempotency_key: str,
        cancellation: ToolCancellationToken,
    ) -> ProviderReceipt:
        started.set()
        await release.wait()
        return await original_apply(
            plan,
            idempotency_key=idempotency_key,
            cancellation=cancellation,
        )

    provider.apply = long_apply  # type: ignore[method-assign]

    def conflicting_renewal(*args: object, **kwargs: object) -> object:
        raise NetworkApplyClaimConflictError("fake grant version conflict")

    store.renew_apply_claim = conflicting_renewal  # type: ignore[method-assign]
    task = asyncio.create_task(
        lifecycle.reconcile(envelope, action=NetworkAction.CREATE, ownership=None)
    )
    await started.wait()
    await asyncio.sleep(0.45)
    release.set()
    result = await task
    assert result.phase is NetworkGovernancePhase.RECOVERY_REQUIRED
    assert result.last_known_good_revision is None
    assert committed == []
    assert provider.apply_calls == 1


@pytest.mark.anyio
async def test_uncertain_apply_and_rollback_cancellation_are_not_replayed(tmp_path: Path) -> None:
    cancelling_provider = CancelApplyProvider(observation())
    lifecycle, policy, provider, _, _, _, _, _ = build(
        tmp_path,
        provider_override=cancelling_provider,
    )
    envelope, _ = signed()
    pending = await lifecycle.reconcile(envelope, action=NetworkAction.CREATE, ownership=None)
    policy.approve(grant_for(pending), capability=policy.local_control_capability())
    with pytest.raises(asyncio.CancelledError):
        await lifecycle.reconcile(envelope, action=NetworkAction.CREATE, ownership=None)
    assert provider.apply_calls == 1

    rollback_provider = CancelRollbackProvider(observation())
    rollback_lifecycle, rollback_policy, rollback_provider, _, _, _, _, _ = build(
        tmp_path / "rollback-cancel",
        provider_override=rollback_provider,
    )
    rollback_pending = await rollback_lifecycle.reconcile(
        envelope,
        action=NetworkAction.CREATE,
        ownership=None,
    )
    rollback_policy.approve(
        grant_for(rollback_pending), capability=rollback_policy.local_control_capability()
    )
    with pytest.raises(asyncio.CancelledError):
        await rollback_lifecycle.reconcile(
            envelope,
            action=NetworkAction.CREATE,
            ownership=None,
        )
    assert rollback_provider.apply_calls == 1
    assert rollback_provider.rollback_calls == 1


@pytest.mark.anyio
@pytest.mark.parametrize(
    "boundary",
    [
        LifecycleCrashBoundary.PLAN,
        LifecycleCrashBoundary.APPLY,
        LifecycleCrashBoundary.VERIFY,
        LifecycleCrashBoundary.ACK,
    ],
)
async def test_crash_boundaries_recover_without_replaying_apply(
    tmp_path: Path,
    boundary: LifecycleCrashBoundary,
) -> None:
    recovery_ledger = create_recovery_ledger()
    lifecycle, policy, provider, ack, sink, _, _, store = build(
        tmp_path,
        ledger=recovery_ledger,
    )
    envelope, _ = signed()
    pending = await lifecycle.reconcile(envelope, action=NetworkAction.CREATE, ownership=None)
    policy.approve(grant_for(pending), capability=policy.local_control_capability())
    # 重建对象共享同一 SQLite、授权事实、Provider 与 fake sinks。
    crashing = ManagedPathLifecycle(
        provider,
        policy,
        store,
        ack,
        path_verifier=FakePathVerifier(path_evidence()),
        path_controller=controller(),
        path_status_sink=sink,
        clock=lambda: NOW,
        crash_after=boundary,
        ledger=recovery_ledger,
    )
    with pytest.raises(LifecycleInjectedCrash):
        await crashing.reconcile(envelope, action=NetworkAction.CREATE, ownership=None)
    calls_before = provider.apply_calls
    recovered_lifecycle = ManagedPathLifecycle(
        provider,
        policy,
        store,
        ack,
        path_verifier=FakePathVerifier(path_evidence()),
        path_controller=controller(),
        path_status_sink=sink,
        clock=lambda: NOW,
        ledger=recovery_ledger,
    )
    recovered = await recovered_lifecycle.recover()
    assert provider.apply_calls == calls_before
    assert recovered
    assert all(item.phase is not NetworkGovernancePhase.APPLYING for item in recovered)
    if boundary is LifecycleCrashBoundary.PLAN:
        held = await recovered_lifecycle.reconcile(
            envelope,
            action=NetworkAction.CREATE,
            ownership=None,
        )
        assert held.phase is NetworkGovernancePhase.MANUAL_INTERVENTION


@pytest.mark.anyio
async def test_reconcile_existing_incomplete_journal_uses_recovery_path(tmp_path: Path) -> None:
    recovery_ledger = create_recovery_ledger()
    lifecycle, policy, provider, ack, sink, _, _, store = build(
        tmp_path,
        ledger=recovery_ledger,
    )
    envelope, _ = signed()
    pending = await lifecycle.reconcile(envelope, action=NetworkAction.CREATE, ownership=None)
    policy.approve(grant_for(pending), capability=policy.local_control_capability())
    crashing = ManagedPathLifecycle(
        provider,
        policy,
        store,
        ack,
        path_verifier=FakePathVerifier(path_evidence()),
        path_controller=controller(),
        path_status_sink=sink,
        clock=lambda: NOW,
        crash_after=LifecycleCrashBoundary.APPLY,
        ledger=recovery_ledger,
    )
    with pytest.raises(LifecycleInjectedCrash):
        await crashing.reconcile(envelope, action=NetworkAction.CREATE, ownership=None)
    calls_before = provider.apply_calls
    recovered = await ManagedPathLifecycle(
        provider,
        policy,
        store,
        ack,
        path_verifier=FakePathVerifier(path_evidence()),
        path_controller=controller(),
        path_status_sink=sink,
        clock=lambda: NOW,
        ledger=recovery_ledger,
    ).reconcile(envelope, action=NetworkAction.CREATE, ownership=None)
    assert provider.apply_calls == calls_before
    assert recovered.phase in {
        NetworkGovernancePhase.ROLLED_BACK,
        NetworkGovernancePhase.VERIFIED,
        NetworkGovernancePhase.PATH_DEGRADED,
    }


@pytest.mark.anyio
async def test_independent_probe_controller_checkpoint_and_sink_failures_are_local(
    tmp_path: Path,
) -> None:
    lifecycle, policy, provider, acknowledgements, sink, _, _, _ = build(
        tmp_path,
    )
    sink.fail = True
    envelope, _ = signed()
    pending = await lifecycle.reconcile(envelope, action=NetworkAction.CREATE, ownership=None)
    policy.approve(grant_for(pending), capability=policy.local_control_capability())
    result = await lifecycle.reconcile(envelope, action=NetworkAction.CREATE, ownership=None)
    assert result.phase is NetworkGovernancePhase.VERIFIED
    assert result.path_status_delivered is False
    assert result.stable_error_code == "path_sink_failed"
    assert provider.apply_calls == 1
    assert acknowledgements.items

    sink.fail = False
    retried = await lifecycle.reconcile(envelope, action=NetworkAction.CREATE, ownership=None)
    assert retried.phase is NetworkGovernancePhase.VERIFIED
    assert retried.stable_error_code is None
    assert provider.apply_calls == 1

    controller_fake = controller()
    controller_fake.error = RuntimeError("fake controller unavailable")
    (
        controller_lifecycle,
        controller_policy,
        controller_provider,
        _,
        controller_sink,
        _,
        _,
        _,
    ) = build(
        tmp_path / "controller",
        path_controller=controller_fake,
    )
    controller_result = await authorize(
        controller_lifecycle,
        controller_policy,
        controller_provider,
    )
    assert controller_result.phase is NetworkGovernancePhase.PATH_DEGRADED
    assert controller_provider.rollback_calls == 0
    assert controller_sink.items[0][0].stable_error_code == "path_unavailable"

    def checkpoint_failure(_: object) -> None:
        raise OSError("fake checkpoint unavailable")

    checkpoint_lifecycle, checkpoint_policy, checkpoint_provider, _, _, _, _, _ = build(
        tmp_path / "checkpoint",
        commit_last_known_good=checkpoint_failure,
    )
    checkpoint_result = await authorize(
        checkpoint_lifecycle,
        checkpoint_policy,
        checkpoint_provider,
    )
    assert checkpoint_result.phase is NetworkGovernancePhase.VERIFIED
    assert checkpoint_result.last_known_good_revision is None
    assert checkpoint_result.stable_error_code == "last_known_good_checkpoint_failed"

    probe_verifier = DelayedFailurePathVerifier()
    probe_lifecycle, probe_policy, probe_provider, _, probe_sink, _, _, _ = build(
        tmp_path / "probe",
        verifier=probe_verifier,
    )
    probe_result = await authorize(probe_lifecycle, probe_policy, probe_provider)
    assert probe_result.phase is NetworkGovernancePhase.PATH_DEGRADED
    assert probe_provider.rollback_calls == 0
    assert probe_sink.items[0][0].stable_error_code == "timeout"
    retried_probe = await probe_lifecycle._verify_path(  # type: ignore[reportPrivateUsage]
        probe_result
    )
    assert retried_probe.phase is NetworkGovernancePhase.PATH_DEGRADED

    cancelled_probe_lifecycle, cancelled_probe_policy, cancelled_probe_provider, _, _, _, _, _ = (
        build(
            tmp_path / "probe-cancel",
            verifier=CancelledPathVerifier(),
        )
    )
    cancelled_probe_envelope, _ = signed()
    cancelled_probe_pending = await cancelled_probe_lifecycle.reconcile(
        cancelled_probe_envelope,
        action=NetworkAction.CREATE,
        ownership=None,
    )
    cancelled_probe_policy.approve(
        grant_for(cancelled_probe_pending),
        capability=cancelled_probe_policy.local_control_capability(),
    )
    with pytest.raises(asyncio.CancelledError):
        await cancelled_probe_lifecycle.reconcile(
            cancelled_probe_envelope,
            action=NetworkAction.CREATE,
            ownership=None,
        )
    assert cancelled_probe_provider.apply_calls == 1

    binding_verifier = FakePathVerifier(
        path_evidence().model_copy(update={"provider": ProviderKind.MACOS})
    )
    binding_lifecycle, binding_policy, binding_provider, _, binding_sink, _, _, _ = build(
        tmp_path / "binding",
        verifier=binding_verifier,
    )
    binding_result = await authorize(binding_lifecycle, binding_policy, binding_provider)
    assert binding_result.phase is NetworkGovernancePhase.PATH_DEGRADED
    assert binding_sink.items[0][0].stable_error_code == "path_evidence_binding_mismatch"

    broken_controller = BrokenSelectionController(controller().selection)
    broken_lifecycle, broken_policy, broken_provider, _, broken_sink, _, _, _ = build(
        tmp_path / "selection",
        evidence=path_evidence(verified=False, error=DirectPathErrorCode.TARGET_UNREACHABLE),
        path_controller=broken_controller,
    )
    broken_result = await authorize(broken_lifecycle, broken_policy, broken_provider)
    assert broken_result.phase is NetworkGovernancePhase.PATH_DEGRADED
    assert broken_result.path_selection is None
    assert broken_sink.items[0][0].stable_error_code == "path_unavailable"

    cancelled_controller = controller()
    cancelled_controller.error = asyncio.CancelledError()
    cancelled_lifecycle, cancelled_policy, _, _, _, _, _, _ = build(
        tmp_path / "controller-cancel",
        path_controller=cancelled_controller,
    )
    cancelled_controller_envelope, _ = signed()
    cancelled_pending = await cancelled_lifecycle.reconcile(
        cancelled_controller_envelope,
        action=NetworkAction.CREATE,
        ownership=None,
    )
    cancelled_policy.approve(
        grant_for(cancelled_pending), capability=cancelled_policy.local_control_capability()
    )
    with pytest.raises(asyncio.CancelledError):
        await cancelled_lifecycle.reconcile(
            cancelled_controller_envelope,
            action=NetworkAction.CREATE,
            ownership=None,
        )

    no_sink_lifecycle, no_sink_policy, no_sink_provider, _, _, _, _, _ = build(
        tmp_path / "no-sinks",
        without_ack_sink=True,
        without_path_sink=True,
    )
    no_sink_result = await authorize(no_sink_lifecycle, no_sink_policy, no_sink_provider)
    assert no_sink_result.acknowledgement_delivered
    assert no_sink_result.path_status_delivered


@pytest.mark.anyio
async def test_ack_failure_prevents_path_publish_but_retry_never_applies_again(
    tmp_path: Path,
) -> None:
    order: list[str] = []
    ack = MemoryAcknowledgements(order)
    sink = MemoryPathSink(order)
    lifecycle, policy, provider, _, _, _, _, _ = build(
        tmp_path,
        ack=ack,
        path_sink=sink,
    )
    ack.fail = True
    envelope, _ = signed()
    pending = await lifecycle.reconcile(envelope, action=NetworkAction.CREATE, ownership=None)
    policy.approve(grant_for(pending), capability=policy.local_control_capability())
    result = await lifecycle.reconcile(envelope, action=NetworkAction.CREATE, ownership=None)
    assert result.phase is NetworkGovernancePhase.VERIFIED
    assert result.last_known_good_revision == 1
    assert result.stable_error_code == "ack_sink_failed"
    assert order == ["ack", "ack"]
    assert not sink.items

    ack.fail = False
    retried = await lifecycle.reconcile(envelope, action=NetworkAction.CREATE, ownership=None)
    assert retried.phase is NetworkGovernancePhase.VERIFIED
    assert retried.stable_error_code is None
    assert provider.apply_calls == 1
    assert order == ["ack", "ack", "ack", "path"]
    assert ack.items[-1].idempotency_key == retried.idempotency_key
    assert sink.items[0][1] == retried.idempotency_key


@pytest.mark.anyio
async def test_ownership_ledger_is_read_during_recovery_and_no_secret_is_journaled(
    tmp_path: Path,
) -> None:
    ledger = CountingLedger()
    lifecycle, policy, provider, _, _, _, _, store = build(tmp_path, ledger=ledger)
    envelope, _ = signed()
    pending = await lifecycle.reconcile(envelope, action=NetworkAction.CREATE, ownership=None)
    policy.approve(grant_for(pending), capability=policy.local_control_capability())
    crashing = ManagedPathLifecycle(
        provider,
        policy,
        store,
        None,
        path_verifier=FakePathVerifier(path_evidence()),
        path_controller=controller(),
        clock=lambda: NOW,
        crash_after=LifecycleCrashBoundary.APPLY,
        ledger=ledger,
    )
    with pytest.raises(LifecycleInjectedCrash):
        await crashing.reconcile(envelope, action=NetworkAction.CREATE, ownership=None)
    recovered = await ManagedPathLifecycle(
        provider,
        policy,
        store,
        None,
        path_verifier=FakePathVerifier(path_evidence()),
        path_controller=controller(),
        clock=lambda: NOW,
        ledger=ledger,
    ).recover()
    assert recovered
    assert ledger.calls == 1
    payload = store.get(NETWORK_ID, NODE_A, 1)
    assert payload is not None
    encoded = payload.model_dump_json().lower()
    assert "private_key" not in encoded
    assert "preshared_key" not in encoded
    assert "endpoint" not in encoded


@pytest.mark.anyio
async def test_create_recovery_without_ledger_is_manual_before_live_provider_read(
    tmp_path: Path,
) -> None:
    _, _, policy, provider, store = await crash_after_apply(
        tmp_path,
        InMemoryNetworkProvider(observation()),
    )
    observe_calls_before_recovery = provider.observe_calls
    recovered = await ManagedPathLifecycle(
        provider,
        policy,
        store,
        None,
        path_verifier=FakePathVerifier(path_evidence()),
        path_controller=controller(),
        clock=lambda: NOW,
    ).recover()
    assert recovered[0].phase is NetworkGovernancePhase.MANUAL_INTERVENTION
    assert provider.observe_calls == observe_calls_before_recovery
    assert provider.apply_calls == 1


@pytest.mark.anyio
async def test_recovery_ledger_lookup_is_bound_to_record_network_and_node(
    tmp_path: Path,
) -> None:
    provider = InMemoryNetworkProvider(observation())
    lifecycle, policy, _, _, _, _, _, store = build(
        tmp_path,
        provider_override=provider,
    )
    envelope, _ = signed(target_node_id=NODE_B)
    pending = await lifecycle.reconcile(envelope, action=NetworkAction.CREATE, ownership=None)
    policy.approve(grant_for(pending), capability=policy.local_control_capability())
    crashing = ManagedPathLifecycle(
        provider,
        policy,
        store,
        None,
        path_verifier=FakePathVerifier(path_evidence()),
        path_controller=controller(),
        clock=lambda: NOW,
        crash_after=LifecycleCrashBoundary.APPLY,
    )
    with pytest.raises(LifecycleInjectedCrash):
        await crashing.reconcile(envelope, action=NetworkAction.CREATE, ownership=None)
    before_observe = provider.observe_calls
    wrong_node_ledger = create_recovery_ledger()
    recovered = await ManagedPathLifecycle(
        provider,
        policy,
        store,
        None,
        path_verifier=FakePathVerifier(path_evidence()),
        path_controller=controller(),
        clock=lambda: NOW,
        ledger=wrong_node_ledger,
    ).recover()
    assert recovered[0].phase is NetworkGovernancePhase.MANUAL_INTERVENTION
    assert wrong_node_ledger.keys == [(NETWORK_ID, NODE_B)]
    assert provider.observe_calls == before_observe
    assert provider.apply_calls == 1


@pytest.mark.anyio
async def test_provider_response_loss_is_recovered_by_query_not_apply_replay(
    tmp_path: Path,
) -> None:
    recovery_ledger = create_recovery_ledger()
    lifecycle, policy, provider, _, _, _, _, store = build(
        tmp_path,
        behavior=FakeProviderBehavior.RESPONSE_LOST,
        ledger=recovery_ledger,
    )
    envelope, _ = signed()
    pending = await lifecycle.reconcile(envelope, action=NetworkAction.CREATE, ownership=None)
    policy.approve(grant_for(pending), capability=policy.local_control_capability())
    with pytest.raises(TimeoutError):
        await lifecycle.reconcile(envelope, action=NetworkAction.CREATE, ownership=None)
    calls_before = provider.apply_calls
    recovered = await ManagedPathLifecycle(
        provider,
        policy,
        store,
        None,
        path_verifier=FakePathVerifier(path_evidence()),
        path_controller=controller(),
        clock=lambda: NOW,
        ledger=recovery_ledger,
    ).recover()
    assert provider.apply_calls == calls_before
    assert recovered
    assert recovered[0].phase in {
        NetworkGovernancePhase.ROLLED_BACK,
        NetworkGovernancePhase.VERIFIED,
        NetworkGovernancePhase.PATH_DEGRADED,
    }


async def crash_after_apply(
    tmp_path: Path,
    provider: InMemoryNetworkProvider,
    *,
    action: NetworkAction = NetworkAction.CREATE,
    existing_ownership: ManagedResourceOwnership | None = None,
    ledger: CountingLedger | None = None,
) -> tuple[
    SignedDesiredConfig,
    NetworkAuthorizationGrant,
    NetworkOperationPolicy,
    InMemoryNetworkProvider,
    SQLiteNetworkGovernanceStore,
]:
    lifecycle, policy, actual_provider, _, _, _, _, store = build(
        tmp_path,
        provider_override=provider,
        ledger=ledger,
    )
    envelope, _ = signed()
    pending = await lifecycle.reconcile(
        envelope,
        action=action,
        ownership=existing_ownership,
    )
    assert pending.phase is NetworkGovernancePhase.AWAITING_AUTHORIZATION
    grant = grant_for(pending)
    policy.approve(grant, capability=policy.local_control_capability())
    crashing = ManagedPathLifecycle(
        actual_provider,
        policy,
        store,
        None,
        path_verifier=FakePathVerifier(path_evidence()),
        path_controller=controller(),
        clock=lambda: NOW,
        ledger=ledger,
        crash_after=LifecycleCrashBoundary.APPLY,
    )
    with pytest.raises(LifecycleInjectedCrash):
        await crashing.reconcile(envelope, action=action, ownership=existing_ownership)
    return envelope, grant, policy, actual_provider, store


async def recover_one(
    envelope: SignedDesiredConfig,
    policy: NetworkOperationPolicy,
    provider: InMemoryNetworkProvider,
    store: SQLiteNetworkGovernanceStore,
    *,
    ledger: CountingLedger | None = None,
) -> NetworkGovernanceRecord:
    if ledger is None:
        saved = store.get(NETWORK_ID, NODE_A, 1)
        if saved is not None and saved.plan.action is NetworkAction.CREATE:
            ledger = create_recovery_ledger()
    lifecycle = ManagedPathLifecycle(
        provider,
        policy,
        store,
        None,
        path_verifier=FakePathVerifier(path_evidence()),
        path_controller=controller(),
        clock=lambda: NOW,
        ledger=ledger,
    )
    recovered = await lifecycle.recover()
    assert recovered
    return recovered[0]


@pytest.mark.anyio
async def test_fresh_preapproved_path_and_apply_cancellation_safe_point(tmp_path: Path) -> None:
    lifecycle, policy, provider, _, _, _, _, _ = build(tmp_path / "preapproved")
    envelope, _ = signed(revision=2, parent_revision=1)
    pending = await lifecycle.reconcile(envelope, action=NetworkAction.CREATE, ownership=None)
    policy.approve(grant_for(pending), capability=policy.local_control_capability())
    result = await lifecycle.reconcile(envelope, action=NetworkAction.CREATE, ownership=None)
    assert result.phase is NetworkGovernancePhase.VERIFIED
    assert provider.apply_calls == 1
    assert result.authorization_id is not None

    pending_lifecycle, pending_policy, pending_provider, _, _, _, _, _ = build(
        tmp_path / "cancel-safe",
    )
    pending = await pending_lifecycle.reconcile(
        envelope,
        action=NetworkAction.CREATE,
        ownership=None,
    )
    grant = grant_for(pending)
    pending_policy.approve(grant, capability=pending_policy.local_control_capability())
    authorized = pending_lifecycle._journal(  # type: ignore[reportPrivateUsage]
        pending,
        NetworkGovernancePhase.AUTHORIZED,
        authorization_id=grant.authorization_id,
    )
    token = ToolCancellationToken()
    token.cancel()
    cancelled = await pending_lifecycle._apply_and_verify(  # type: ignore[reportPrivateUsage]
        authorized,
        token,
    )
    assert cancelled.phase is NetworkGovernancePhase.CANCELLED
    assert pending_provider.apply_calls == 0
    with pytest.raises(asyncio.CancelledError):
        ManagedPathLifecycle._check_cancelled(token)  # type: ignore[reportPrivateUsage]

    storage_lifecycle, _, storage_provider, _, _, _, _, _ = build(
        tmp_path / "fresh-recheck-storage",
        policy=AlwaysAuthorizedPolicy(fail_on_call=2),
    )
    storage_result = await storage_lifecycle.reconcile(
        envelope,
        action=NetworkAction.CREATE,
        ownership=None,
    )
    assert storage_result.phase is NetworkGovernancePhase.AWAITING_AUTHORIZATION
    assert storage_provider.apply_calls == 0

    mismatch_lifecycle, _, mismatch_provider, _, _, _, _, _ = build(
        tmp_path / "fresh-recheck-mismatch",
        policy=AlwaysAuthorizedPolicy(mismatch_on_call=2),
    )
    mismatch_result = await mismatch_lifecycle.reconcile(
        envelope,
        action=NetworkAction.CREATE,
        ownership=None,
    )
    assert mismatch_result.phase is NetworkGovernancePhase.AWAITING_AUTHORIZATION
    assert mismatch_provider.apply_calls == 0


@pytest.mark.anyio
async def test_recovery_matrix_checks_auth_live_state_and_never_replays_apply(
    tmp_path: Path,
) -> None:
    observe_provider = ObserveFailureProvider()
    envelope, _, policy, provider, store = await crash_after_apply(
        tmp_path / "observe",
        observe_provider,
    )
    observe_provider.fail_observe = True
    recovered = await recover_one(envelope, policy, provider, store)
    assert recovered.phase is NetworkGovernancePhase.RECOVERY_REQUIRED
    assert provider.apply_calls == 1

    recover_failure = RecoverFailureProvider(observation())
    envelope, _, policy, provider, store = await crash_after_apply(
        tmp_path / "recover-failure",
        recover_failure,
    )
    recovered = await recover_one(envelope, policy, provider, store)
    assert recovered.phase is NetworkGovernancePhase.RECOVERY_REQUIRED
    assert provider.apply_calls == 1

    no_receipt = EmptyRecoverProvider(observation())
    envelope, _, policy, provider, store = await crash_after_apply(
        tmp_path / "no-receipt",
        no_receipt,
    )
    recovered = await recover_one(envelope, policy, provider, store)
    assert recovered.phase is NetworkGovernancePhase.RECOVERY_REQUIRED
    assert provider.apply_calls == 1

    cancelled_provider = RecoverCancelledProvider(observation())
    envelope, _, policy, provider, store = await crash_after_apply(
        tmp_path / "cancelled-receipt",
        cancelled_provider,
    )
    recovered = await recover_one(envelope, policy, provider, store)
    assert recovered.phase is NetworkGovernancePhase.CANCELLED
    assert provider.apply_calls == 1

    manual_provider = RecoverManualProvider(observation())
    envelope, _, policy, provider, store = await crash_after_apply(
        tmp_path / "manual-receipt",
        manual_provider,
    )
    recovered = await recover_one(envelope, policy, provider, store)
    assert recovered.phase is NetworkGovernancePhase.MANUAL_INTERVENTION
    assert provider.apply_calls == 1

    conflict_provider = ConflictOnRecoverProvider()
    envelope, _, policy, provider, store = await crash_after_apply(
        tmp_path / "live-conflict",
        conflict_provider,
    )
    conflict_provider.conflict = True
    recovered = await recover_one(envelope, policy, provider, store)
    assert recovered.phase is NetworkGovernancePhase.OWNERSHIP_CONFLICT
    assert provider.apply_calls == 1

    verify_failure = RecoverAppliedProvider(observation())
    envelope, _, policy, provider, store = await crash_after_apply(
        tmp_path / "verify-failure",
        verify_failure,
    )
    verify_failure.behavior = FakeProviderBehavior.VERIFY_FAILURE
    recovered = await recover_one(envelope, policy, provider, store)
    assert recovered.phase is NetworkGovernancePhase.ROLLED_BACK
    assert provider.apply_calls == 1
    assert provider.rollback_calls == 1

    revoked_provider = InMemoryNetworkProvider(observation())
    envelope, grant, policy, provider, store = await crash_after_apply(
        tmp_path / "revoked",
        revoked_provider,
    )
    policy.revoke(
        grant.authorization_id,
        revoked_at=NOW,
        capability=policy.local_control_capability(),
    )
    recovered = await recover_one(envelope, policy, provider, store)
    assert recovered.phase is NetworkGovernancePhase.RECOVERY_REQUIRED
    held = await ManagedPathLifecycle(
        provider,
        policy,
        store,
        None,
        path_verifier=FakePathVerifier(path_evidence()),
        path_controller=controller(),
        clock=lambda: NOW,
    ).reconcile(envelope, action=NetworkAction.CREATE, ownership=None)
    assert held.phase is NetworkGovernancePhase.RECOVERY_REQUIRED
    assert provider.apply_calls == 1


@pytest.mark.anyio
async def test_recovery_reads_non_create_ledger_and_detects_ownership_mismatch(
    tmp_path: Path,
) -> None:
    managed_observation = observation(ownership_state=OwnershipState.MANAGED_OWNED)
    managed_ownership = ownership(managed_observation)
    matching_ledger = CountingLedger(SimpleNamespace(ownership=managed_ownership))
    provider = InMemoryNetworkProvider(managed_observation)
    envelope, _, policy, provider, store = await crash_after_apply(
        tmp_path / "matching",
        provider,
        action=NetworkAction.UPDATE,
        existing_ownership=managed_ownership,
        ledger=matching_ledger,
    )
    recovered = await recover_one(
        envelope,
        policy,
        provider,
        store,
        ledger=matching_ledger,
    )
    assert recovered.phase is NetworkGovernancePhase.ROLLED_BACK
    assert matching_ledger.calls == 1

    mismatch_ledger = CountingLedger(
        SimpleNamespace(
            ownership=managed_ownership.model_copy(
                update={"system_fingerprint": f"sha256:{'f' * 64}"}
            )
        )
    )
    mismatch_provider = InMemoryNetworkProvider(managed_observation)
    envelope, _, policy, provider, store = await crash_after_apply(
        tmp_path / "mismatch",
        mismatch_provider,
        action=NetworkAction.UPDATE,
        existing_ownership=managed_ownership,
        ledger=mismatch_ledger,
    )
    recovered = await recover_one(
        envelope,
        policy,
        provider,
        store,
        ledger=mismatch_ledger,
    )
    assert recovered.phase is NetworkGovernancePhase.OWNERSHIP_CONFLICT
    assert provider.apply_calls == 1


@pytest.mark.anyio
async def test_record_validator_store_boundary_and_clock_are_fail_closed(tmp_path: Path) -> None:
    lifecycle, policy, _, _, _, _, _, store = build(tmp_path / "validator")
    envelope, _ = signed(revision=2, parent_revision=1)
    pending = await lifecycle.reconcile(envelope, action=NetworkAction.CREATE, ownership=None)
    policy.approve(grant_for(pending), capability=policy.local_control_capability())
    result = await lifecycle.reconcile(envelope, action=NetworkAction.CREATE, ownership=None)
    base = result.model_dump(mode="json")

    with sqlite3.connect(store.path) as connection:
        stored_payload = str(
            connection.execute(
                "SELECT payload FROM network_governance "
                "WHERE network_id=? AND node_id=? AND revision=?",
                (str(NETWORK_ID), str(NODE_A), 2),
            ).fetchone()[0]
        ).lower()
    assert '"signature"' not in stored_payload
    assert '"endpoint"' not in stored_payload
    assert '"allowed_host_routes"' not in stored_payload
    assert '"peers"' not in stored_payload
    assert envelope.signature.lower() not in stored_payload
    assert envelope.config.interface_name.lower() not in stored_payload

    conflicting_envelope, _ = signed(revision=2, parent_revision=1)
    conflicting_record = NetworkGovernanceRecord.model_validate(
        {
            **result.model_dump(mode="python"),
            "envelope": conflicting_envelope,
        }
    )
    with pytest.raises(NetworkAuthorizationConflictError, match="同一 revision"):
        store.put(conflicting_record)

    naive = result.model_dump(mode="json")
    naive["updated_at"] = NOW.replace(tzinfo=None).isoformat()
    with pytest.raises(ValueError):
        NetworkGovernanceRecord.model_validate(naive)

    gap = result.model_dump(mode="json")
    gap["journal"][1]["sequence"] = 7
    with pytest.raises(ValueError):
        NetworkGovernanceRecord.model_validate(gap)

    identity = result.model_dump(mode="json")
    identity["journal"][0]["idempotency_key"] = f"netop_{'f' * 64}"
    with pytest.raises(ValueError):
        NetworkGovernanceRecord.model_validate(identity)

    evidence_revision = result.model_dump(mode="json")
    evidence_revision["path_evidence"]["revision"] = 3
    with pytest.raises(ValueError):
        NetworkGovernanceRecord.model_validate(evidence_revision)

    evidence_provider = result.model_dump(mode="json")
    evidence_provider["path_evidence"]["provider"] = "macos"
    with pytest.raises(ValueError):
        NetworkGovernanceRecord.model_validate(evidence_provider)

    selection_revision = result.model_dump(mode="json")
    selection_revision["plan"]["desired"]["revision"] = 2
    selection_revision["plan"]["desired"]["parent_revision"] = 1
    selection_revision["path_evidence"]["revision"] = 2
    selection_revision["path_selection"]["revision"] = 1
    with pytest.raises(ValueError):
        NetworkGovernanceRecord.model_validate(selection_revision)

    def fail_put(_: NetworkGovernanceRecord) -> None:
        raise OSError("fake journal store unavailable")

    store.put = fail_put  # type: ignore[method-assign]
    with pytest.raises(ManagedPathLifecycleError):
        lifecycle._journal(  # type: ignore[reportPrivateUsage]
            result,
            NetworkGovernancePhase.ACKNOWLEDGING,
        )
    assert base["phase"] == NetworkGovernancePhase.VERIFIED.value

    bad_clock, _, _, _, _, _, _, _ = build(
        tmp_path / "clock",
        policy=AlwaysAuthorizedPolicy(),
        clock=lambda: NOW.replace(tzinfo=None),
    )
    with pytest.raises(ValueError):
        await bad_clock.reconcile(envelope, action=NetworkAction.CREATE, ownership=None)


@pytest.mark.anyio
async def test_journal_compacts_at_128_with_hash_chain_and_restarts_from_provider_journal(
    tmp_path: Path,
) -> None:
    lifecycle, policy, provider, _, _, _, _, _ = build(tmp_path / "journal")
    envelope, _ = signed()
    pending = await lifecycle.reconcile(envelope, action=NetworkAction.CREATE, ownership=None)
    policy.approve(grant_for(pending), capability=policy.local_control_capability())
    result = await lifecycle.reconcile(envelope, action=NetworkAction.CREATE, ownership=None)
    for _ in range(130):
        result = lifecycle._journal(  # type: ignore[reportPrivateUsage]
            result,
            NetworkGovernancePhase.ACKNOWLEDGING,
        )
    assert len(result.journal) == 128
    assert result.journal_start_sequence > 0
    assert result.journal[0].sequence == result.journal_start_sequence
    assert result.journal[0].previous_hash == result.journal_previous_hash

    journal_database = tmp_path / "journal" / "governance.sqlite3"
    reloaded_policy = NetworkOperationPolicy()
    reloaded_repository = SQLiteNetworkAuthorizationRepository(journal_database)
    reloaded_store = SQLiteNetworkGovernanceStore(
        journal_database,
        authorization_repository=reloaded_repository,
    )
    reloaded_policy.attach_writer(reloaded_repository)
    reloaded_lifecycle = ManagedPathLifecycle(
        provider,
        reloaded_policy,
        reloaded_store,
        None,
        path_verifier=FakePathVerifier(path_evidence()),
        path_controller=controller(),
        clock=lambda: NOW,
    )
    restored = reloaded_store.get(NETWORK_ID, NODE_A, 1)
    assert restored is not None
    assert len(restored.journal) == 128
    assert restored.journal[-1].entry_hash == result.journal[-1].entry_hash
    assert reloaded_lifecycle is not None

    tampered_payload = result.model_dump(mode="json")
    tampered_payload["journal"][-1]["stable_error_code"] = "tampered"
    with pytest.raises(ValueError):
        NetworkGovernanceRecord.model_validate(tampered_payload)


def test_lifecycle_contract_rejects_non_utc_journal_time() -> None:
    with pytest.raises(ValueError, match="UTC"):
        NetworkJournalEntry(
            sequence=0,
            previous_hash=f"sha256:{'0' * 64}",
            entry_hash=f"sha256:{'0' * 64}",
            phase=NetworkGovernancePhase.PLANNING,
            idempotency_key=f"netop_{'a' * 64}",
            plan_hash=f"sha256:{'b' * 64}",
            occurred_at=NOW.replace(tzinfo=None),
        )
