"""治理仓储、kill-switch 委托和错误映射的对抗性边界测试。"""

from __future__ import annotations

import asyncio
import errno
import json
import sqlite3
from collections.abc import Callable
from dataclasses import replace
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from tests.agent.test_network_sync import NOW as SIGNED_NOW
from tests.agent.test_network_sync import signed
from tests.network.control_harness import (
    NetworkOperationPolicy as HarnessPolicy,
)
from tests.network.control_harness import (
    SQLiteNetworkAuthorizationRepository as HarnessRepository,
)
from tests.network.factories import NETWORK_ID, NODE_A, NODE_B, NOW, observation, ownership
from tests.network.test_managed_path_lifecycle import (
    AlwaysAuthorizedPolicy,
    CancelApplyProvider,
    FakePathController,
    FakePathVerifier,
    MemoryAcknowledgements,
    MemoryPathSink,
    RecoverAppliedProvider,
    build,
    controller,
    crash_after_apply,
    create_recovery_ledger,
    grant_for,
    path_evidence,
    recover_one,
)

from tunnelminion.domain.identifiers import AuthorizationId
from tunnelminion.network.contracts import (
    ManagedResourceOwnership,
    NetworkAction,
    NetworkError,
    NetworkErrorCode,
    NetworkPlan,
    OwnershipState,
    ProviderReceipt,
    ReceiptStatus,
    SignedDesiredConfig,
    VerificationResult,
    canonical_sha256,
)
from tunnelminion.network.fakes import FakeProviderBehavior, InMemoryNetworkProvider
from tunnelminion.network.governance import (
    LocalControlAuthority,
    ManagedNetworkGovernanceWorkflow,
    ManagedPathLifecycle,
    ManagedPathLifecycleError,
    NetworkApplyClaim,
    NetworkApplyClaimConflictError,
    NetworkAuthorizationConflictError,
    NetworkAuthorizationGrant,
    NetworkAuthorizationStorageError,
    NetworkGovernancePhase,
    NetworkGovernanceRecord,
    SQLiteNetworkGovernanceStore,
)
from tunnelminion.network.governance import (
    NetworkOperationPolicy as ProductionPolicy,
)
from tunnelminion.network.path_controller import (
    DirectPathEvidence,
    NetworkPathType,
    PathSelection,
)
from tunnelminion.tools.contracts import ToolCancellationToken


def _sql(path: Path, statement: str, parameters: tuple[object, ...] = ()) -> None:
    with sqlite3.connect(path) as connection:
        connection.execute(statement, parameters)


class _CursorWithRowcount:
    """只在测试中把指定 UPDATE 的 rowcount 伪造成 CAS 竞争失败。"""

    def __init__(self, cursor: sqlite3.Cursor, rowcount: int | None = None) -> None:
        self._cursor = cursor
        self._rowcount = rowcount

    @property
    def rowcount(self) -> int:
        return self._cursor.rowcount if self._rowcount is None else self._rowcount

    def fetchone(self) -> tuple[Any, ...] | None:
        return self._cursor.fetchone()

    def fetchall(self) -> list[tuple[Any, ...]]:
        return self._cursor.fetchall()


class _RowcountConnection:
    """只在测试中注入一次受控的 SQLite CAS rowcount=0。"""

    def __init__(self, connection: sqlite3.Connection, statement_fragment: str) -> None:
        self._connection = connection
        self._statement_fragment = statement_fragment

    def execute(
        self,
        statement: str,
        parameters: tuple[object, ...] = (),
    ) -> _CursorWithRowcount:
        cursor = self._connection.execute(statement, parameters)
        forced = self._statement_fragment in statement
        return _CursorWithRowcount(cursor, rowcount=0 if forced else None)

    def commit(self) -> None:
        self._connection.commit()

    def rollback(self) -> None:
        self._connection.rollback()


class ApplyPermissionFailureProvider(InMemoryNetworkProvider):
    """Provider.apply 抛出权限错误的隔离 fake。"""

    async def apply(
        self,
        plan: NetworkPlan,
        *,
        idempotency_key: str,
        cancellation: ToolCancellationToken,
    ) -> ProviderReceipt:
        raise PermissionError("fake provider permission denied")


class VerifyTimeoutProvider(InMemoryNetworkProvider):
    """Provider.verify 超时的隔离 fake。"""

    async def verify(self, plan: NetworkPlan) -> VerificationResult:
        raise TimeoutError("fake provider verify timeout")


class VerifyMismatchedProvider(InMemoryNetworkProvider):
    """主 lifecycle 返回错误绑定 verification 的隔离 fake。"""

    async def verify(self, plan: NetworkPlan) -> VerificationResult:
        result = await super().verify(plan)
        return VerificationResult.model_validate(
            {
                **result.model_dump(mode="python"),
                "idempotency_key": f"netop_{'f' * 64}",
            }
        )


class CancelVerifyProvider(InMemoryNetworkProvider):
    """Provider.verify 取消的隔离 fake。"""

    async def verify(self, plan: NetworkPlan) -> VerificationResult:
        raise asyncio.CancelledError


class SlowVerifyProvider(InMemoryNetworkProvider):
    """在独立 verify 窗口让出调度的隔离 fake。"""

    async def verify(self, plan: NetworkPlan) -> VerificationResult:
        await asyncio.sleep(0.5)
        return await super().verify(plan)


class RecoverAppliedVerifyTimeoutProvider(RecoverAppliedProvider):
    """恢复得到 APPLIED 回执后 verify 超时的隔离 fake。"""

    async def verify(self, plan: NetworkPlan) -> VerificationResult:
        del plan
        raise TimeoutError("fake late recovery verify timeout")


class RecoverAppliedCancelVerifyProvider(RecoverAppliedProvider):
    """恢复得到 APPLIED 回执后 verify 取消的隔离 fake。"""

    async def verify(self, plan: NetworkPlan) -> VerificationResult:
        del plan
        raise asyncio.CancelledError


class RecoverAppliedMismatchedVerificationProvider(RecoverAppliedProvider):
    """恢复得到 APPLIED 回执后返回错绑定 verification 的隔离 fake。"""

    async def verify(self, plan: NetworkPlan) -> VerificationResult:
        result = await super().verify(plan)
        return VerificationResult.model_validate(
            {
                **result.model_dump(mode="python"),
                "idempotency_key": f"netop_{'f' * 64}",
            }
        )


class EmergencyErrorProvider(InMemoryNetworkProvider):
    """kill-switch 调用抛出稳定 Provider 错误的隔离 fake。"""

    async def emergency_stop(
        self,
        plan: NetworkPlan,
        *,
        idempotency_key: str,
        cancellation: ToolCancellationToken,
    ) -> ProviderReceipt:
        raise TimeoutError("fake emergency timeout")


class EmergencyCancelledProvider(InMemoryNetworkProvider):
    """kill-switch 调用取消的隔离 fake。"""

    async def emergency_stop(
        self,
        plan: NetworkPlan,
        *,
        idempotency_key: str,
        cancellation: ToolCancellationToken,
    ) -> ProviderReceipt:
        raise asyncio.CancelledError


class EmergencyMismatchedReceiptProvider(InMemoryNetworkProvider):
    """返回错误绑定 kill-switch 回执的隔离 fake。"""

    async def emergency_stop(
        self,
        plan: NetworkPlan,
        *,
        idempotency_key: str,
        cancellation: ToolCancellationToken,
    ) -> ProviderReceipt:
        receipt = await super().emergency_stop(
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


class EmergencyCancelledReceiptProvider(InMemoryNetworkProvider):
    """返回已取消 kill-switch 回执的隔离 fake。"""

    async def emergency_stop(
        self,
        plan: NetworkPlan,
        *,
        idempotency_key: str,
        cancellation: ToolCancellationToken,
    ) -> ProviderReceipt:
        receipt = await super().emergency_stop(
            plan,
            idempotency_key=idempotency_key,
            cancellation=cancellation,
        )
        return ProviderReceipt.model_validate(
            {
                **receipt.model_dump(mode="python"),
                "status": ReceiptStatus.CANCELLED,
                "error": NetworkError(
                    code=NetworkErrorCode.CANCELLED,
                    message="fake emergency cancelled",
                    correlation_id=plan.plan_hash,
                ),
            }
        )


class EmergencyVerifyFailureProvider(InMemoryNetworkProvider):
    """kill-switch 后独立 verify 失败的隔离 fake。"""

    async def verify(self, plan: NetworkPlan) -> VerificationResult:
        self.behavior = FakeProviderBehavior.VERIFY_FAILURE
        return await super().verify(plan)


class EmergencyVerifyCancelledProvider(InMemoryNetworkProvider):
    """kill-switch 后 verify 取消的隔离 fake。"""

    async def verify(self, plan: NetworkPlan) -> VerificationResult:
        del plan
        raise asyncio.CancelledError


class EmergencyVerifyTimeoutProvider(InMemoryNetworkProvider):
    """kill-switch 后 verify 超时的隔离 fake。"""

    async def verify(self, plan: NetworkPlan) -> VerificationResult:
        del plan
        raise TimeoutError("fake emergency verify timeout")


class EmergencyMismatchedVerificationProvider(InMemoryNetworkProvider):
    """返回错误绑定 kill-switch verification 的隔离 fake。"""

    async def verify(self, plan: NetworkPlan) -> VerificationResult:
        result = await super().verify(plan)
        return VerificationResult.model_validate(
            {
                **result.model_dump(mode="python"),
                "idempotency_key": f"netop_{'f' * 64}",
            }
        )


class RollbackRaisesProvider(InMemoryNetworkProvider):
    """回滚抛出异常的隔离 fake。"""

    async def rollback(
        self,
        plan: NetworkPlan,
        receipt: ProviderReceipt,
        *,
        cancellation: ToolCancellationToken,
    ) -> ProviderReceipt:
        del plan, receipt, cancellation
        raise ConnectionError("fake rollback unavailable")

    async def verify(self, plan: NetworkPlan) -> VerificationResult:
        self.behavior = FakeProviderBehavior.VERIFY_FAILURE
        return await super().verify(plan)


class RollbackMismatchedProvider(InMemoryNetworkProvider):
    """回滚返回错误绑定回执的隔离 fake。"""

    async def rollback(
        self,
        plan: NetworkPlan,
        receipt: ProviderReceipt,
        *,
        cancellation: ToolCancellationToken,
    ) -> ProviderReceipt:
        result = await super().rollback(plan, receipt, cancellation=cancellation)
        return ProviderReceipt.model_validate(
            {
                **result.model_dump(mode="python"),
                "idempotency_key": f"netop_{'f' * 64}",
            }
        )

    async def verify(self, plan: NetworkPlan) -> VerificationResult:
        self.behavior = FakeProviderBehavior.VERIFY_FAILURE
        return await super().verify(plan)


class PathSelectionMismatchController(FakePathController):
    """返回错误 plan binding 的隔离 path controller。"""

    async def reconcile(
        self,
        evidence: DirectPathEvidence,
        *,
        fallback: NetworkPathType = NetworkPathType.STATIC,
    ) -> PathSelection:
        selection = await super().reconcile(evidence, fallback=fallback)
        payload = selection.model_dump(mode="python")
        payload["plan_hash"] = f"sha256:{'f' * 64}"
        return PathSelection.model_validate(payload)


class EmptyProviderJournal:
    """不返回操作正文的受控 Provider journal fake。"""

    def load_operation(
        self,
        *,
        idempotency_key: str,
        plan_hash: str,
    ) -> tuple[SignedDesiredConfig, NetworkPlan] | None:
        del idempotency_key, plan_hash
        return None


async def _authorized(
    tmp_path: Path,
    *,
    provider: InMemoryNetworkProvider | None = None,
    revision: int = 1,
) -> tuple[
    ManagedPathLifecycle,
    HarnessPolicy,
    InMemoryNetworkProvider,
    MemoryAcknowledgements,
    MemoryPathSink,
    FakePathVerifier,
    FakePathController,
    SQLiteNetworkGovernanceStore,
    SignedDesiredConfig,
    NetworkAuthorizationGrant,
]:
    lifecycle, policy, actual, ack, sink, verifier, path_controller, store = build(
        tmp_path,
        provider_override=provider,
    )
    envelope, _ = signed(revision=revision, parent_revision=revision - 1)
    pending = await lifecycle.reconcile(envelope, action=NetworkAction.CREATE, ownership=None)
    grant = grant_for(pending)
    policy.approve(grant, capability=policy.local_control_capability())
    return lifecycle, policy, actual, ack, sink, verifier, path_controller, store, envelope, grant


@pytest.mark.anyio
async def test_claim_revalidation_fences_expiry_and_binding_conflicts(tmp_path: Path) -> None:
    lifecycle, policy, _, _, _, _, _, store = build(tmp_path)
    envelope, _ = signed()
    pending = await lifecycle.reconcile(envelope, action=NetworkAction.CREATE, ownership=None)
    grant = grant_for(pending)
    policy.approve(grant, capability=policy.local_control_capability())
    claim = store.claim_apply(
        pending.plan,
        authorization_id=grant.authorization_id,
        idempotency_key=pending.idempotency_key,
        now=SIGNED_NOW,
        lease_seconds=1,
    )
    with pytest.raises(ValueError, match="正数"):
        store.renew_apply_claim(claim, now=SIGNED_NOW, lease_seconds=0)
    with pytest.raises(NetworkApplyClaimConflictError, match="过期"):
        store.renew_apply_claim(
            claim,
            now=SIGNED_NOW + timedelta(seconds=1),
        )

    replacement = replace(claim, lease_token="wrong-owner")
    with pytest.raises(NetworkApplyClaimConflictError, match="owner"):
        store.assert_apply_claim(replacement, now=SIGNED_NOW)

    with pytest.raises(NetworkApplyClaimConflictError, match="唯一授权记录"):
        store.claim_apply(
            pending.plan,
            authorization_id=AuthorizationId.new(),
            idempotency_key=pending.idempotency_key,
            now=SIGNED_NOW,
        )


@pytest.mark.anyio
async def test_revoke_and_claim_scope_boundaries_fail_closed(tmp_path: Path) -> None:
    lifecycle, policy, actual, _, _, _, _, store, envelope, grant = await _authorized(
        tmp_path / "claim-boundaries"
    )
    del lifecycle
    pending = store.get(NETWORK_ID, NODE_A, 1)
    assert pending is not None
    repository = store._authorization_repository  # type: ignore[reportPrivateUsage]

    with pytest.raises(PermissionError, match="本地控制面"):
        repository.revoke(
            grant.authorization_id,
            revoked_at=SIGNED_NOW,
            capability=LocalControlAuthority().authorization_capability(),
        )
    with pytest.raises(ValueError, match="timezone-aware UTC"):
        repository.revoke(
            grant.authorization_id,
            revoked_at=datetime(2026, 7, 26),
            capability=policy.local_control_capability(),
        )
    with pytest.raises(ValueError, match="批准时间"):
        repository.revoke(
            grant.authorization_id,
            revoked_at=SIGNED_NOW - timedelta(seconds=1),
            capability=policy.local_control_capability(),
        )
    assert repository.get(grant.authorization_id) == grant

    with pytest.raises(ValueError, match="正数"):
        repository.claim_apply(
            pending.plan,
            authorization_id=grant.authorization_id,
            idempotency_key=pending.idempotency_key,
            now=SIGNED_NOW,
            lease_seconds=0,
        )
    with pytest.raises(ValueError, match="timezone-aware UTC"):
        repository.claim_apply(
            pending.plan,
            authorization_id=grant.authorization_id,
            idempotency_key=pending.idempotency_key,
            now=datetime(2026, 7, 26),
        )

    wrong_envelope, _ = signed(target_node_id=NODE_B)
    observed = await actual.observe(envelope.config.interface_name)
    wrong_plan = await actual.plan(
        action=NetworkAction.CREATE,
        desired=wrong_envelope.config,
        observed=observed,
        ownership=None,
    )
    with pytest.raises(NetworkApplyClaimConflictError, match="scope"):
        repository.claim_apply(
            wrong_plan,
            authorization_id=grant.authorization_id,
            idempotency_key=pending.idempotency_key,
            now=SIGNED_NOW,
        )

    expired_claim = repository.claim_apply(
        pending.plan,
        authorization_id=grant.authorization_id,
        idempotency_key=pending.idempotency_key,
        now=SIGNED_NOW,
        lease_seconds=1,
    )
    with pytest.raises(NetworkApplyClaimConflictError, match="过期"):
        repository.claim_apply(
            pending.plan,
            authorization_id=grant.authorization_id,
            idempotency_key=pending.idempotency_key,
            now=SIGNED_NOW + timedelta(seconds=1),
        )
    assert expired_claim.fencing_token == 1

    (
        active_lifecycle,
        active_policy,
        _,
        _,
        _,
        _,
        _,
        active_store,
        _,
        active_grant,
    ) = await _authorized(tmp_path / "revoke-active")
    del active_lifecycle
    active_pending = active_store.get(NETWORK_ID, NODE_A, 1)
    assert active_pending is not None
    active_repository = active_store._authorization_repository  # type: ignore[reportPrivateUsage]
    active_claim = active_repository.claim_apply(
        active_pending.plan,
        authorization_id=active_grant.authorization_id,
        idempotency_key=active_pending.idempotency_key,
        now=SIGNED_NOW,
    )
    with pytest.raises(NetworkApplyClaimConflictError, match="活动 apply claim"):
        active_repository.revoke(
            active_grant.authorization_id,
            revoked_at=SIGNED_NOW + timedelta(seconds=1),
            capability=active_policy.local_control_capability(),
        )
    active_repository.release_apply_claim(active_claim)
    revoked = active_repository.revoke(
        active_grant.authorization_id,
        revoked_at=SIGNED_NOW + timedelta(seconds=1),
        capability=active_policy.local_control_capability(),
    )
    assert revoked.revoked_at == SIGNED_NOW + timedelta(seconds=1)

    external = sqlite3.connect(":memory:")
    borrowed = HarnessRepository(connection=external)
    borrowed.close()
    external.close()


@pytest.mark.anyio
async def test_claim_and_governance_store_cas_fail_closed(tmp_path: Path) -> None:
    lifecycle, _policy, _, _, _, _, _, store, _, grant = await _authorized(tmp_path / "cas")
    pending = store.get(NETWORK_ID, NODE_A, 1)
    assert pending is not None
    repository = store._authorization_repository  # type: ignore[reportPrivateUsage]

    claim = repository.claim_apply(
        pending.plan,
        authorization_id=grant.authorization_id,
        idempotency_key=pending.idempotency_key,
        now=SIGNED_NOW,
    )
    renewed = repository.renew_apply_claim(
        claim,
        now=SIGNED_NOW,
        lease_seconds=60,
    )
    assert renewed.lease_expires_at > claim.lease_expires_at

    original_connection = repository._connection  # type: ignore[reportPrivateUsage]
    object.__setattr__(
        repository,
        "_connection",
        _RowcountConnection(original_connection, "SET lease_expires_at=?"),
    )
    try:
        with pytest.raises(NetworkApplyClaimConflictError, match="续租 CAS"):
            repository.renew_apply_claim(renewed, now=SIGNED_NOW)
    finally:
        object.__setattr__(repository, "_connection", original_connection)

    repository.release_apply_claim(renewed)
    object.__setattr__(
        repository,
        "_connection",
        _RowcountConnection(original_connection, "SET lease_owner_hash=?"),
    )
    try:
        with pytest.raises(NetworkApplyClaimConflictError, match="CAS 更新"):
            repository.claim_apply(
                pending.plan,
                authorization_id=grant.authorization_id,
                idempotency_key=pending.idempotency_key,
                now=SIGNED_NOW,
            )
    finally:
        object.__setattr__(repository, "_connection", original_connection)

    record = store.get(NETWORK_ID, NODE_A, 1)
    assert record is not None
    captured: list[NetworkGovernanceRecord] = []
    original_put_journal_step = store.put_journal_step

    def capture(candidate: NetworkGovernanceRecord, _status: object) -> None:
        captured.append(candidate)

    store.put_journal_step = capture  # type: ignore[method-assign]
    try:
        candidate = lifecycle._journal(  # type: ignore[reportPrivateUsage]
            record,
            NetworkGovernancePhase.RECOVERY_REQUIRED,
            stable_error_code=NetworkErrorCode.RECOVERY_REQUIRED.value,
        )
    finally:
        store.put_journal_step = original_put_journal_step  # type: ignore[method-assign]
    assert captured == [candidate]

    original_store_connection = store._connection  # type: ignore[reportPrivateUsage]
    object.__setattr__(
        store,
        "_connection",
        _RowcountConnection(original_store_connection, "UPDATE network_governance SET payload"),
    )
    try:
        with pytest.raises(NetworkAuthorizationConflictError, match="CAS 更新"):
            store.put(candidate)
    finally:
        object.__setattr__(store, "_connection", original_store_connection)


@pytest.mark.anyio
async def test_claim_assert_and_renew_fail_closed_matrix(tmp_path: Path) -> None:
    async def claim_case(
        name: str,
    ) -> tuple[
        SQLiteNetworkGovernanceStore,
        NetworkAuthorizationGrant,
        NetworkApplyClaim,
    ]:
        lifecycle, _, _, _, _, _, _, store, _, grant = await _authorized(tmp_path / name)
        del lifecycle
        pending = store.get(NETWORK_ID, NODE_A, 1)
        assert pending is not None
        claim = store.claim_apply(
            pending.plan,
            authorization_id=grant.authorization_id,
            idempotency_key=pending.idempotency_key,
            now=SIGNED_NOW,
        )
        return store, grant, claim

    store, grant, claim = await claim_case("assert-fencing")
    _sql(
        store.path,
        "UPDATE network_apply_claims SET state='released' WHERE network_id=?",
        (str(NETWORK_ID),),
    )
    with pytest.raises(NetworkApplyClaimConflictError, match="fencing"):
        store.assert_apply_claim(claim, now=SIGNED_NOW)

    store, grant, claim = await claim_case("assert-expired")
    with pytest.raises(NetworkApplyClaimConflictError, match="过期"):
        store.assert_apply_claim(claim, now=SIGNED_NOW + timedelta(seconds=31))

    store, grant, claim = await claim_case("assert-binding")
    with pytest.raises(NetworkApplyClaimConflictError, match="绑定"):
        store.assert_apply_claim(
            replace(claim, plan_hash=f"sha256:{'f' * 64}"),
            now=SIGNED_NOW,
        )

    store, grant, claim = await claim_case("assert-missing-grant")
    _sql(
        store.path,
        "DELETE FROM network_authorization_grants WHERE authorization_id=?",
        (str(grant.authorization_id),),
    )
    with pytest.raises(NetworkApplyClaimConflictError, match="记录丢失"):
        store.assert_apply_claim(claim, now=SIGNED_NOW)

    store, grant, claim = await claim_case("assert-revoked")
    revoked = NetworkAuthorizationGrant.model_validate(
        {**grant.model_dump(mode="python"), "revoked_at": SIGNED_NOW + timedelta(seconds=1)}
    )
    _sql(
        store.path,
        "UPDATE network_authorization_grants SET payload=? WHERE authorization_id=?",
        (revoked.model_dump_json(), str(grant.authorization_id)),
    )
    with pytest.raises(NetworkApplyClaimConflictError, match="撤销"):
        store.assert_apply_claim(claim, now=SIGNED_NOW + timedelta(seconds=2))

    store, grant, claim = await claim_case("assert-version")
    changed = NetworkAuthorizationGrant.model_validate(
        {**grant.model_dump(mode="python"), "approved_by": "different-owner"}
    )
    _sql(
        store.path,
        "UPDATE network_authorization_grants SET payload=? WHERE authorization_id=?",
        (changed.model_dump_json(), str(grant.authorization_id)),
    )
    with pytest.raises(NetworkApplyClaimConflictError, match="版本"):
        store.assert_apply_claim(claim, now=SIGNED_NOW)

    store, _, claim = await claim_case("renew-owner")
    with pytest.raises(NetworkApplyClaimConflictError, match="owner"):
        store.renew_apply_claim(replace(claim, lease_token="wrong-owner"), now=SIGNED_NOW)

    store, _, claim = await claim_case("renew-fencing")
    _sql(
        store.path,
        "UPDATE network_apply_claims SET state='released' WHERE network_id=?",
        (str(NETWORK_ID),),
    )
    with pytest.raises(NetworkApplyClaimConflictError, match="fencing"):
        store.renew_apply_claim(claim, now=SIGNED_NOW)

    store, _, claim = await claim_case("renew-binding")
    with pytest.raises(NetworkApplyClaimConflictError, match="绑定"):
        store.renew_apply_claim(
            replace(claim, plan_hash=f"sha256:{'e' * 64}"),
            now=SIGNED_NOW,
        )
    store, _, claim = await claim_case("renew-expired")
    with pytest.raises(NetworkApplyClaimConflictError, match="过期"):
        store.renew_apply_claim(claim, now=SIGNED_NOW + timedelta(seconds=31))

    store, grant, claim = await claim_case("renew-missing-grant")
    _sql(
        store.path,
        "DELETE FROM network_authorization_grants WHERE authorization_id=?",
        (str(grant.authorization_id),),
    )
    with pytest.raises(NetworkApplyClaimConflictError, match="记录丢失"):
        store.renew_apply_claim(claim, now=SIGNED_NOW)

    store, grant, claim = await claim_case("renew-revoked")
    revoked = NetworkAuthorizationGrant.model_validate(
        {**grant.model_dump(mode="python"), "revoked_at": SIGNED_NOW + timedelta(seconds=1)}
    )
    _sql(
        store.path,
        "UPDATE network_authorization_grants SET payload=? WHERE authorization_id=?",
        (revoked.model_dump_json(), str(grant.authorization_id)),
    )
    with pytest.raises(NetworkApplyClaimConflictError, match="撤销或过期"):
        store.renew_apply_claim(claim, now=SIGNED_NOW + timedelta(seconds=2))

    store, grant, claim = await claim_case("renew-version")
    changed = NetworkAuthorizationGrant.model_validate(
        {**grant.model_dump(mode="python"), "approved_by": "different-owner"}
    )
    _sql(
        store.path,
        "UPDATE network_authorization_grants SET payload=? WHERE authorization_id=?",
        (changed.model_dump_json(), str(grant.authorization_id)),
    )
    with pytest.raises(NetworkApplyClaimConflictError, match="版本"):
        store.renew_apply_claim(claim, now=SIGNED_NOW)


@pytest.mark.anyio
async def test_claim_terminal_methods_and_schema_migrations_fail_closed(tmp_path: Path) -> None:
    lifecycle, _, _, _, _, _, _, store, _, grant = await _authorized(tmp_path / "closed")
    del lifecycle
    pending = store.get(NETWORK_ID, NODE_A, 1)
    assert pending is not None
    claim = store.claim_apply(
        pending.plan,
        authorization_id=grant.authorization_id,
        idempotency_key=pending.idempotency_key,
        now=SIGNED_NOW,
    )
    repository = store._authorization_repository  # type: ignore[reportPrivateUsage]
    repository.close()
    for operation in (
        lambda: store.release_apply_claim(claim),
        lambda: store.fence_apply_claim(claim),
        lambda: store.reap_expired_claims(now=SIGNED_NOW),
        lambda: store.resolve_apply_claim(
            network_id=NETWORK_ID,
            node_id=NODE_A,
            revision=1,
            idempotency_key=claim.idempotency_key,
            plan_hash=claim.plan_hash,
        ),
        lambda: store.has_active_apply_claim(
            network_id=NETWORK_ID,
            node_id=NODE_A,
            revision=1,
            now=SIGNED_NOW,
        ),
    ):
        with pytest.raises(NetworkAuthorizationStorageError):
            operation()

    legacy_claim_db = tmp_path / "legacy-claim.sqlite3"
    with sqlite3.connect(legacy_claim_db) as connection:
        connection.execute(
            """CREATE TABLE network_apply_claims (
                network_id TEXT NOT NULL,
                node_id TEXT NOT NULL,
                revision INTEGER NOT NULL,
                authorization_id TEXT NOT NULL,
                authorization_version TEXT NOT NULL,
                idempotency_key TEXT NOT NULL,
                plan_hash TEXT NOT NULL,
                lease_owner_hash TEXT NOT NULL,
                lease_expires_at TEXT NOT NULL,
                PRIMARY KEY (network_id, node_id, revision),
                UNIQUE (idempotency_key)
            )"""
        )
    migrated = HarnessRepository(legacy_claim_db)
    columns = {
        str(row[1])
        for row in migrated._connection.execute(  # type: ignore[reportPrivateUsage]
            "PRAGMA table_info(network_apply_claims)"
        ).fetchall()
    }
    assert {"state", "fencing_token"} <= columns
    migrated.close()

    legacy_store_db = tmp_path / "legacy-store.sqlite3"
    with sqlite3.connect(legacy_store_db) as connection:
        connection.execute(
            """CREATE TABLE network_governance (
                network_id TEXT NOT NULL,
                node_id TEXT NOT NULL,
                revision INTEGER NOT NULL,
                payload TEXT NOT NULL,
                PRIMARY KEY (network_id, node_id, revision)
            )"""
        )
    legacy_repository = HarnessRepository(legacy_store_db)
    legacy_store = SQLiteNetworkGovernanceStore(
        legacy_store_db,
        authorization_repository=legacy_repository,
    )
    legacy_store.bind_provider_journal(object())
    store_columns = {
        str(row[1])
        for row in legacy_store._connection.execute(  # type: ignore[reportPrivateUsage]
            "PRAGMA table_info(network_governance)"
        ).fetchall()
    }
    assert {
        "identity_hash",
        "plan_hash",
        "idempotency_key",
        "journal_sequence",
        "journal_hash",
    } <= store_columns
    legacy_repository.close()


@pytest.mark.anyio
async def test_governance_store_cas_redaction_and_provider_journal_restore(
    tmp_path: Path,
) -> None:
    lifecycle, policy, provider, _, _, _, _, store = build(tmp_path / "restore")
    envelope, _ = signed()
    pending = await lifecycle.reconcile(envelope, action=NetworkAction.CREATE, ownership=None)
    policy.approve(grant_for(pending), capability=policy.local_control_capability())
    result = await lifecycle.reconcile(envelope, action=NetworkAction.CREATE, ownership=None)
    assert result.phase is NetworkGovernancePhase.VERIFIED

    store.put(result)
    store.put(result)
    stale_payload = result.model_dump(mode="python")
    stale_payload["phase"] = NetworkGovernancePhase.AWAITING_AUTHORIZATION.value
    stale = NetworkGovernanceRecord.model_validate(stale_payload)
    with pytest.raises(NetworkAuthorizationConflictError, match="journal CAS"):
        store.put(stale)
    with pytest.raises(ValueError, match="endpoint"):
        store._reject_secrets('{"endpoint":"10.0.0.2"}')  # type: ignore[reportPrivateUsage]

    incomplete = lifecycle._journal(  # type: ignore[reportPrivateUsage]
        result,
        NetworkGovernancePhase.APPLYING,
    )
    assert incomplete.phase is NetworkGovernancePhase.APPLYING
    restarted_repository = HarnessRepository(store.path)
    restarted = SQLiteNetworkGovernanceStore(
        store.path,
        authorization_repository=restarted_repository,
    )
    restarted.bind_provider_journal(provider)
    restored = restarted.get(NETWORK_ID, NODE_A, 1)
    assert restored is not None
    assert restored.phase is incomplete.phase
    assert restored.plan.plan_hash == incomplete.plan.plan_hash
    restarted._records.clear()  # type: ignore[reportPrivateUsage]
    restarted.bind_provider_journal(object())
    assert restarted.get(NETWORK_ID, NODE_A, 1) is None
    assert restarted.list_recoverable() == ()
    restarted.bind_provider_journal(EmptyProviderJournal())
    assert restarted.get(NETWORK_ID, NODE_A, 1) is None

    payload_row = sqlite3.connect(store.path)
    payload = json.loads(
        str(
            payload_row.execute(
                "SELECT payload FROM network_governance "
                "WHERE network_id=? AND node_id=? AND revision=?",
                (str(NETWORK_ID), str(NODE_A), 1),
            ).fetchone()[0]
        )
    )
    payload_row.close()

    cases: tuple[tuple[str, object, str], ...] = (
        ("non-object", [], "schema"),
        ("bad-schema", {"schema": 1}, "schema"),
    )
    for name, replacement, message in cases:
        db = tmp_path / name / "governance.sqlite3"
        db.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(store.path) as source, sqlite3.connect(db) as target:
            source.backup(target)
        _sql(db, "UPDATE network_governance SET payload=?", (json.dumps(replacement),))
        repo = HarnessRepository(db)
        broken = SQLiteNetworkGovernanceStore(db, authorization_repository=repo)
        broken.bind_provider_journal(provider)
        with pytest.raises(ManagedPathLifecycleError, match=message):
            broken.get(NETWORK_ID, NODE_A, 1)
        repo.close()

    empty_db = tmp_path / "empty-journal" / "governance.sqlite3"
    empty_db.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(store.path) as source, sqlite3.connect(empty_db) as target:
        source.backup(target)
    empty_repo = HarnessRepository(empty_db)
    empty_store = SQLiteNetworkGovernanceStore(empty_db, authorization_repository=empty_repo)
    empty_store.bind_provider_journal(EmptyProviderJournal())
    assert empty_store.get(NETWORK_ID, NODE_A, 1) is None
    empty_repo.close()

    conflict_db = tmp_path / "binding-conflict" / "governance.sqlite3"
    conflict_db.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(store.path) as source, sqlite3.connect(conflict_db) as target:
        source.backup(target)
    payload["envelope_hash"] = f"sha256:{'f' * 64}"
    _sql(conflict_db, "UPDATE network_governance SET payload=?", (json.dumps(payload),))
    conflict_repo = HarnessRepository(conflict_db)
    conflict_store = SQLiteNetworkGovernanceStore(
        conflict_db,
        authorization_repository=conflict_repo,
    )
    conflict_store.bind_provider_journal(provider)
    with pytest.raises(ManagedPathLifecycleError, match="绑定"):
        conflict_store.get(NETWORK_ID, NODE_A, 1)
    conflict_repo.close()
    restarted_repository.close()

    metadata_cases: tuple[tuple[str, str, tuple[object, ...], str], ...] = (
        (
            "identity-type",
            "UPDATE network_governance SET identity_hash=?",
            (sqlite3.Binary(b"identity"),),
            "identity 元数据",
        ),
        (
            "identity-value",
            "UPDATE network_governance SET identity_hash=?",
            (f"sha256:{'f' * 64}",),
            "identity hash",
        ),
        (
            "plan-type",
            "UPDATE network_governance SET plan_hash=?",
            (sqlite3.Binary(b"plan"),),
            "plan hash 元数据",
        ),
        (
            "plan-value",
            "UPDATE network_governance SET plan_hash=?",
            (f"sha256:{'f' * 64}",),
            "plan hash 元数据",
        ),
        (
            "idempotency-type",
            "UPDATE network_governance SET idempotency_key=?",
            (sqlite3.Binary(b"idempotency"),),
            "幂等键元数据",
        ),
        (
            "idempotency-value",
            "UPDATE network_governance SET idempotency_key=?",
            (f"netop_{'f' * 64}",),
            "幂等键元数据",
        ),
        (
            "journal-sequence-type",
            "UPDATE network_governance SET journal_sequence=?",
            (sqlite3.Binary(b"sequence"),),
            "journal 元数据格式",
        ),
        (
            "journal-hash-type",
            "UPDATE network_governance SET journal_hash=?",
            (sqlite3.Binary(b"hash"),),
            "journal 元数据格式",
        ),
        (
            "journal-sequence-value",
            "UPDATE network_governance SET journal_sequence=?",
            (999,),
            "journal 元数据冲突",
        ),
    )
    for name, statement, parameters, message in metadata_cases:
        database = tmp_path / f"metadata-{name}" / "governance.sqlite3"
        database.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(store.path) as source, sqlite3.connect(database) as target:
            source.backup(target)
        _sql(database, statement, parameters)
        repository = HarnessRepository(database)
        restarted_store = SQLiteNetworkGovernanceStore(
            database,
            authorization_repository=repository,
        )
        restarted_store.bind_provider_journal(provider)
        with pytest.raises(ManagedPathLifecycleError, match=message):
            restarted_store.get(NETWORK_ID, NODE_A, 1)
        repository.close()

    phase_database = tmp_path / "metadata-phase" / "governance.sqlite3"
    phase_database.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(store.path) as source, sqlite3.connect(phase_database) as target:
        source.backup(target)
    with sqlite3.connect(phase_database) as connection:
        payload = json.loads(
            str(
                connection.execute(
                    "SELECT payload FROM network_governance "
                    "WHERE network_id=? AND node_id=? AND revision=?",
                    (str(NETWORK_ID), str(NODE_A), 1),
                ).fetchone()[0]
            )
        )
    payload["phase"] = NetworkGovernancePhase.VERIFIED.value
    _sql(
        phase_database,
        "UPDATE network_governance SET payload=?",
        (json.dumps(payload),),
    )
    phase_repository = HarnessRepository(phase_database)
    phase_store = SQLiteNetworkGovernanceStore(
        phase_database,
        authorization_repository=phase_repository,
    )
    phase_store.bind_provider_journal(provider)
    with pytest.raises(ManagedPathLifecycleError, match="phase 与 journal"):
        phase_store.get(NETWORK_ID, NODE_A, 1)
    phase_repository.close()

    empty_journal_database = tmp_path / "metadata-empty-journal" / "governance.sqlite3"
    empty_journal_database.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(store.path) as source, sqlite3.connect(empty_journal_database) as target:
        source.backup(target)
    with sqlite3.connect(empty_journal_database) as connection:
        payload = json.loads(
            str(
                connection.execute(
                    "SELECT payload FROM network_governance "
                    "WHERE network_id=? AND node_id=? AND revision=?",
                    (str(NETWORK_ID), str(NODE_A), 1),
                ).fetchone()[0]
            )
        )
    payload["journal"] = []
    payload["journal_start_sequence"] = 0
    payload["journal_previous_hash"] = f"sha256:{'0' * 64}"
    _sql(
        empty_journal_database,
        "UPDATE network_governance SET payload=?, journal_sequence=?, journal_hash=?",
        (json.dumps(payload), -1, f"sha256:{'0' * 64}"),
    )
    empty_journal_repository = HarnessRepository(empty_journal_database)
    empty_journal_store = SQLiteNetworkGovernanceStore(
        empty_journal_database,
        authorization_repository=empty_journal_repository,
    )
    empty_journal_store.bind_provider_journal(provider)
    with pytest.raises(ManagedPathLifecycleError, match="phase 与 journal"):
        empty_journal_store.get(NETWORK_ID, NODE_A, 1)
    empty_journal_repository.close()


@pytest.mark.anyio
@pytest.mark.parametrize("mismatch", ["envelope", "action", "ownership"])
async def test_same_revision_request_identity_conflict_never_reuses_terminal_record(
    tmp_path: Path,
    mismatch: str,
) -> None:
    lifecycle, policy, provider, _, _, _, _, _ = build(tmp_path / mismatch)
    envelope, _ = signed()
    pending = await lifecycle.reconcile(envelope, action=NetworkAction.CREATE, ownership=None)
    policy.approve(grant_for(pending), capability=policy.local_control_capability())
    result = await lifecycle.reconcile(envelope, action=NetworkAction.CREATE, ownership=None)
    assert result.phase is NetworkGovernancePhase.VERIFIED

    conflicting_envelope = envelope
    conflicting_action = NetworkAction.CREATE
    conflicting_ownership: ManagedResourceOwnership | None = None
    if mismatch == "envelope":
        conflicting_envelope, _ = signed()
    elif mismatch == "action":
        conflicting_action = NetworkAction.UPDATE
    else:
        conflicting_ownership = ownership(observation(ownership_state=OwnershipState.MANAGED_OWNED))

    with pytest.raises(NetworkAuthorizationConflictError, match="同一 revision"):
        await lifecycle.reconcile(
            conflicting_envelope,
            action=conflicting_action,
            ownership=conflicting_ownership,
        )
    assert provider.apply_calls == 1


@pytest.mark.anyio
async def test_governance_record_binding_matrix_is_fail_closed(tmp_path: Path) -> None:
    lifecycle, policy, _, _, _, _, _, store, envelope, _ = await _authorized(
        tmp_path,
        revision=2,
    )
    pending = store.get(NETWORK_ID, NODE_A, 2)
    assert pending is not None
    policy.approve(grant_for(pending), capability=policy.local_control_capability())
    result = await lifecycle.reconcile(envelope, action=NetworkAction.CREATE, ownership=None)
    base = result.model_dump(mode="json")

    def reject(update: Callable[[Any], object], message: str) -> None:
        payload = json.loads(json.dumps(base))
        update(payload)
        with pytest.raises(ValueError, match=message):
            NetworkGovernanceRecord.model_validate(payload)

    def mutate_entry(payload: Any, **updates: object) -> None:
        entry = payload["journal"][0]
        entry.update(updates)
        entry["entry_hash"] = canonical_sha256(
            {
                "sequence": entry["sequence"],
                "previous_hash": entry["previous_hash"],
                "phase": entry["phase"],
                "idempotency_key": entry["idempotency_key"],
                "plan_hash": entry["plan_hash"],
                "occurred_at": datetime.fromisoformat(
                    entry["occurred_at"].replace("Z", "+00:00")
                ).isoformat(),
                "receipt_hash": entry["receipt_hash"],
                "verification_hash": entry["verification_hash"],
                "path_evidence_hash": entry["path_evidence_hash"],
                "stable_error_code": entry["stable_error_code"],
            }
        )

    reject(lambda payload: mutate_entry(payload, sequence=7), "序号")
    reject(
        lambda payload: mutate_entry(payload, previous_hash=f"sha256:{'f' * 64}"),
        "hash chain",
    )
    reject(
        lambda payload: mutate_entry(payload, idempotency_key=f"netop_{'f' * 64}"),
        "同一计划",
    )
    with pytest.raises(ValueError):
        invalid_entry = json.loads(json.dumps(base))
        invalid_entry["journal"][0]["entry_hash"] = f"sha256:{'f' * 64}"
        NetworkGovernanceRecord.model_validate(invalid_entry)
    reject(
        lambda payload: payload["receipt"].update(idempotency_key=f"netop_{'f' * 64}"),
        "receipt binding",
    )
    reject(
        lambda payload: payload["receipt"]["observation_after"].update(provider="macos"),
        "receipt observation",
    )
    reject(
        lambda payload: payload["receipt"].update(
            observation_after=None,
            observation_fingerprint=f"sha256:{'f' * 64}",
        ),
        "observation fingerprint",
    )
    reject(
        lambda payload: payload["verification"].update(idempotency_key=f"netop_{'f' * 64}"),
        "verification binding",
    )
    reject(
        lambda payload: payload["verification"]["observation"].update(interface_name="other"),
        "verification observation",
    )
    reject(
        lambda payload: payload["path_evidence"].update(network_id=f"network_{'f' * 32}"),
        "path evidence binding",
    )
    reject(
        lambda payload: payload["path_evidence"].update(
            revision=3,
            authorization_revision=3,
        ),
        "binding",
    )
    reject(lambda payload: payload["path_evidence"].update(provider="macos"), "Provider")
    reject(
        lambda payload: payload["path_evidence"].update(
            expires_at=payload["path_evidence"]["observed_at"]
        ),
        "TTL",
    )
    reject(
        lambda payload: payload["path_evidence"].update(
            observed_at=(SIGNED_NOW + timedelta(seconds=1)).isoformat(),
            expires_at=(SIGNED_NOW + timedelta(seconds=181)).isoformat(),
        ),
        "未来",
    )
    reject(
        lambda payload: payload["path_selection"].update(
            revision=1,
            authorization_revision=1,
        ),
        "早于",
    )
    reject(
        lambda payload: payload["path_selection"].update(plan_hash=f"sha256:{'f' * 64}"),
        "direct path selection",
    )


@pytest.mark.anyio
async def test_production_policy_is_read_only_and_rejects_forged_writes(tmp_path: Path) -> None:
    lifecycle, policy, _, _, _, _, _, store, envelope, grant = await _authorized(tmp_path)
    del lifecycle, policy, envelope
    production = ProductionPolicy(store.authorization_read_port)
    authority = LocalControlAuthority()
    capability = authority.authorization_capability()
    with pytest.raises(PermissionError):
        production.approve(grant, capability=capability)
    with pytest.raises(PermissionError):
        production.revoke(
            grant.authorization_id,
            revoked_at=NOW,
            capability=capability,
        )
    assert not store.authorization_read_port.accepts_kill_switch(object())


@pytest.mark.anyio
async def test_lifecycle_input_rechecks_and_kill_switch_boundaries(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="正数"):
        build(tmp_path / "invalid-lease", apply_lease_seconds=0)

    no_journal = InMemoryNetworkProvider(observation())
    object.__setattr__(no_journal, "remember_operation", None)
    lifecycle, _, _, _, _, _, _, _ = build(
        tmp_path / "no-journal",
        provider_override=no_journal,
    )
    envelope, _ = signed()
    pending = await lifecycle.reconcile(envelope, action=NetworkAction.CREATE, ownership=None)
    assert pending.phase is NetworkGovernancePhase.AWAITING_AUTHORIZATION

    recheck_policy = AlwaysAuthorizedPolicy(mismatch_on_call=2)
    recheck_lifecycle, _, _, _, _, _, _, _ = build(
        tmp_path / "recheck-mismatch",
        policy=recheck_policy,
    )
    recheck = await recheck_lifecycle.reconcile(
        envelope,
        action=NetworkAction.CREATE,
        ownership=None,
    )
    assert recheck.phase is NetworkGovernancePhase.AWAITING_AUTHORIZATION

    managed = observation(ownership_state=OwnershipState.MANAGED_OWNED)
    provider = InMemoryNetworkProvider(observation())
    lifecycle, policy, actual, _, _, _, _, _, _, _ = await _authorized(
        tmp_path / "kill-boundary",
        provider=provider,
    )
    object.__setattr__(actual, "_observation", managed)
    stop_envelope, _ = signed(revision=2, parent_revision=1)
    owned = ownership(managed)
    with pytest.raises(PermissionError):
        await lifecycle.emergency_stop(
            stop_envelope,
            owned,
            capability=LocalControlAuthority().kill_switch_capability(),
        )
    async with lifecycle._lock:  # type: ignore[reportPrivateUsage]
        with pytest.raises(RuntimeError, match="运行"):
            await lifecycle.emergency_stop(
                stop_envelope,
                owned,
                capability=policy.kill_switch_capability(),
            )

    unsupported = InMemoryNetworkProvider(observation())
    (
        unsupported_lifecycle,
        unsupported_policy,
        unsupported_actual,
        _,
        _,
        _,
        _,
        _,
        _,
        _,
    ) = await _authorized(
        tmp_path / "kill-unsupported",
        provider=unsupported,
    )
    object.__setattr__(unsupported_actual, "_observation", managed)
    object.__setattr__(unsupported, "emergency_stop", None)
    unsupported_result = await unsupported_lifecycle.emergency_stop(
        stop_envelope,
        owned,
        capability=unsupported_policy.kill_switch_capability(),
    )
    assert unsupported_result.phase is NetworkGovernancePhase.MANUAL_INTERVENTION

    no_journal_kill = InMemoryNetworkProvider(observation())
    object.__setattr__(no_journal_kill, "remember_operation", None)
    kill_lifecycle, kill_policy, kill_actual, _, _, _, _, _, _, _ = await _authorized(
        tmp_path / "kill-no-journal",
        provider=no_journal_kill,
    )
    object.__setattr__(kill_actual, "_observation", managed)
    kill_result = await kill_lifecycle.emergency_stop(
        stop_envelope,
        owned,
        capability=kill_policy.kill_switch_capability(),
    )
    assert kill_result.phase is NetworkGovernancePhase.VERIFIED


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("provider_type", "phase"),
    [
        (ApplyPermissionFailureProvider, NetworkGovernancePhase.APPLYING),
        (VerifyTimeoutProvider, NetworkGovernancePhase.RECOVERY_REQUIRED),
    ],
)
async def test_provider_exception_is_persisted_without_false_success(
    tmp_path: Path,
    provider_type: type[InMemoryNetworkProvider],
    phase: NetworkGovernancePhase,
) -> None:
    provider = provider_type(observation())
    lifecycle, _policy, actual, _, _, _, _, store, envelope, _ = await _authorized(
        tmp_path,
        provider=provider,
    )
    if isinstance(provider, ApplyPermissionFailureProvider):
        with pytest.raises(PermissionError):
            await lifecycle.reconcile(envelope, action=NetworkAction.CREATE, ownership=None)
    else:
        result = await lifecycle.reconcile(envelope, action=NetworkAction.CREATE, ownership=None)
        assert result.phase is phase
    saved = store.get(NETWORK_ID, NODE_A, 1)
    assert saved is not None
    assert saved.phase is (
        NetworkGovernancePhase.APPLYING
        if isinstance(provider, ApplyPermissionFailureProvider)
        else phase
    )
    assert actual.apply_calls == (0 if isinstance(provider, ApplyPermissionFailureProvider) else 1)


@pytest.mark.anyio
async def test_initial_authorization_recheck_execute_path_is_fail_closed_without_grant(
    tmp_path: Path,
) -> None:
    policy = AlwaysAuthorizedPolicy()
    lifecycle, _, provider, _, _, _, _, _ = build(
        tmp_path,
        policy=policy,
    )
    envelope, _ = signed()
    result = await lifecycle.reconcile(envelope, action=NetworkAction.CREATE, ownership=None)
    assert result.phase is NetworkGovernancePhase.RECOVERY_REQUIRED
    assert result.stable_error_code == NetworkErrorCode.CLAIM_CONFLICT.value
    assert provider.apply_calls == 0


@pytest.mark.anyio
async def test_provider_verify_cancellation_is_rethrown_after_apply(tmp_path: Path) -> None:
    provider = CancelVerifyProvider(observation())
    lifecycle, _, actual, _, _, _, _, _, envelope, _ = await _authorized(
        tmp_path,
        provider=provider,
    )
    with pytest.raises(asyncio.CancelledError):
        await lifecycle.reconcile(envelope, action=NetworkAction.CREATE, ownership=None)
    assert actual.apply_calls == 1


@pytest.mark.anyio
async def test_post_verify_claim_conflict_never_reaches_path_or_lkg(tmp_path: Path) -> None:
    committed: list[object] = []
    lifecycle, policy, provider, _, _, verifier, path_controller, store = build(
        tmp_path,
        commit_last_known_good=committed.append,
    )
    envelope, _ = signed()
    pending = await lifecycle.reconcile(envelope, action=NetworkAction.CREATE, ownership=None)
    policy.approve(grant_for(pending), capability=policy.local_control_capability())
    original_assert = store.assert_apply_claim
    assert_calls = 0

    def conflict_after_verify(claim: NetworkApplyClaim, *, now: datetime) -> None:
        nonlocal assert_calls
        assert_calls += 1
        if assert_calls >= 3:
            raise NetworkApplyClaimConflictError("fake post-verify claim conflict")
        original_assert(claim, now=now)

    store.assert_apply_claim = conflict_after_verify  # type: ignore[method-assign]
    result = await lifecycle.reconcile(envelope, action=NetworkAction.CREATE, ownership=None)
    assert result.phase is NetworkGovernancePhase.RECOVERY_REQUIRED
    assert provider.apply_calls == 1
    assert provider.verify_calls == 1
    assert verifier.calls == 0
    assert path_controller.calls == 0
    assert committed == []


@pytest.mark.anyio
async def test_apply_verify_claim_and_path_error_boundaries(tmp_path: Path) -> None:
    lifecycle, _, _, _, _, _, _, _ = build(tmp_path / "no-authorization")
    envelope, _ = signed()
    pending = await lifecycle.reconcile(envelope, action=NetworkAction.CREATE, ownership=None)
    no_auth = await lifecycle._apply_and_verify(  # type: ignore[reportPrivateUsage]
        pending,
        ToolCancellationToken(),
    )
    assert no_auth.phase is NetworkGovernancePhase.RECOVERY_REQUIRED

    cancel_provider = CancelApplyProvider(observation())
    cancel_lifecycle, cancel_policy, _, _, _, _, _, _ = build(
        tmp_path / "cancel-apply",
        provider_override=cancel_provider,
    )
    cancel_pending = await cancel_lifecycle.reconcile(
        envelope,
        action=NetworkAction.CREATE,
        ownership=None,
    )
    cancel_policy.approve(
        grant_for(cancel_pending),
        capability=cancel_policy.local_control_capability(),
    )
    with pytest.raises(asyncio.CancelledError):
        await cancel_lifecycle.reconcile(envelope, action=NetworkAction.CREATE, ownership=None)

    mismatch_provider = VerifyMismatchedProvider(observation())
    mismatch_lifecycle, mismatch_policy, _, _, _, _, _, _ = build(
        tmp_path / "verify-mismatch",
        provider_override=mismatch_provider,
    )
    mismatch_pending = await mismatch_lifecycle.reconcile(
        envelope,
        action=NetworkAction.CREATE,
        ownership=None,
    )
    mismatch_policy.approve(
        grant_for(mismatch_pending),
        capability=mismatch_policy.local_control_capability(),
    )
    mismatch = await mismatch_lifecycle.reconcile(
        envelope,
        action=NetworkAction.CREATE,
        ownership=None,
    )
    assert mismatch.phase is NetworkGovernancePhase.RECOVERY_REQUIRED

    conflict_lifecycle, conflict_policy, _, _, _, _, _, conflict_store = build(
        tmp_path / "post-apply-claim-conflict",
    )
    conflict_pending = await conflict_lifecycle.reconcile(
        envelope,
        action=NetworkAction.CREATE,
        ownership=None,
    )
    conflict_policy.approve(
        grant_for(conflict_pending),
        capability=conflict_policy.local_control_capability(),
    )
    original_assert = conflict_store.assert_apply_claim
    assert_calls = 0

    def conflict_after_apply(claim: NetworkApplyClaim, *, now: datetime) -> None:
        nonlocal assert_calls
        assert_calls += 1
        if assert_calls >= 2:
            raise NetworkApplyClaimConflictError("fake post-apply claim conflict")
        original_assert(claim, now=now)

    conflict_store.assert_apply_claim = conflict_after_apply  # type: ignore[method-assign]
    conflict = await conflict_lifecycle.reconcile(
        envelope,
        action=NetworkAction.CREATE,
        ownership=None,
    )
    assert conflict.phase is NetworkGovernancePhase.RECOVERY_REQUIRED

    path_controller = PathSelectionMismatchController(controller().selection)
    path_lifecycle, path_policy, _, _, _, _, _, _ = build(
        tmp_path / "path-selection-mismatch",
        path_controller=path_controller,
    )
    path_pending = await path_lifecycle.reconcile(
        envelope,
        action=NetworkAction.CREATE,
        ownership=None,
    )
    path_policy.approve(
        grant_for(path_pending),
        capability=path_policy.local_control_capability(),
    )
    path_result = await path_lifecycle.reconcile(
        envelope,
        action=NetworkAction.CREATE,
        ownership=None,
    )
    assert path_result.phase is NetworkGovernancePhase.PATH_DEGRADED

    provider_error_code = ManagedPathLifecycle._provider_error_code  # type: ignore[reportPrivateUsage]
    path_error_code = ManagedPathLifecycle._path_error_code  # type: ignore[reportPrivateUsage]
    for error in (
        NotImplementedError(),
        OSError(errno.ENOTSUP, "unsupported"),
    ):
        assert provider_error_code(error).value == "unsupported"
    assert provider_error_code(PermissionError("denied")).value == "permission_denied"
    assert path_error_code(NotImplementedError()).value == "unsupported"
    assert path_error_code(PermissionError("denied")).value == "permission_denied"
    assert path_error_code(OSError(errno.ENOTSUP, "unsupported")).value == "unsupported"


@pytest.mark.anyio
async def test_claim_renewal_conflict_blocks_lkg_during_verify(tmp_path: Path) -> None:
    committed: list[object] = []
    lifecycle, policy, provider, _, _, _, _, store = build(
        tmp_path,
        provider_override=SlowVerifyProvider(observation()),
        commit_last_known_good=committed.append,
        apply_lease_seconds=1,
    )
    envelope, _ = signed()
    pending = await lifecycle.reconcile(envelope, action=NetworkAction.CREATE, ownership=None)
    policy.approve(grant_for(pending), capability=policy.local_control_capability())

    def renew_conflict(
        claim: NetworkApplyClaim,
        *,
        now: datetime,
        lease_seconds: int = 30,
    ) -> NetworkApplyClaim:
        del claim, now, lease_seconds
        raise NetworkApplyClaimConflictError("fake renewal conflict")

    store.renew_apply_claim = renew_conflict  # type: ignore[method-assign]
    result = await lifecycle.reconcile(envelope, action=NetworkAction.CREATE, ownership=None)
    assert result.phase is NetworkGovernancePhase.RECOVERY_REQUIRED
    assert result.stable_error_code == NetworkErrorCode.CLAIM_CONFLICT.value
    assert provider.apply_calls == 1
    assert provider.verify_calls == 1
    assert committed == []


@pytest.mark.anyio
async def test_claim_renewal_task_stop_and_unexpected_failure_are_fail_closed(
    tmp_path: Path,
) -> None:
    lifecycle, policy, _, _, _, _, _, store = build(
        tmp_path / "stop",
        apply_lease_seconds=1,
    )
    envelope, _ = signed()
    pending = await lifecycle.reconcile(envelope, action=NetworkAction.CREATE, ownership=None)
    grant = grant_for(pending)
    policy.approve(grant, capability=policy.local_control_capability())
    claim = store.claim_apply(
        pending.plan,
        authorization_id=grant.authorization_id,
        idempotency_key=pending.idempotency_key,
        now=SIGNED_NOW,
    )
    stop = asyncio.Event()
    stop.set()
    invalid = asyncio.Event()
    await lifecycle._renew_claim(claim, stop, invalid)  # type: ignore[reportPrivateUsage]
    assert not invalid.is_set()
    store.release_apply_claim(claim)

    lifecycle, policy, _, _, _, _, _, store = build(
        tmp_path / "unexpected",
        apply_lease_seconds=1,
    )
    envelope, _ = signed()
    pending = await lifecycle.reconcile(envelope, action=NetworkAction.CREATE, ownership=None)
    grant = grant_for(pending)
    policy.approve(grant, capability=policy.local_control_capability())
    claim = store.claim_apply(
        pending.plan,
        authorization_id=grant.authorization_id,
        idempotency_key=pending.idempotency_key,
        now=SIGNED_NOW,
    )

    def renew_unexpected(
        claim: NetworkApplyClaim,
        *,
        now: datetime,
        lease_seconds: int = 30,
    ) -> NetworkApplyClaim:
        del claim, now, lease_seconds
        raise RuntimeError("fake SQLite renewal failure")

    store.renew_apply_claim = renew_unexpected  # type: ignore[method-assign]
    invalid = asyncio.Event()
    await lifecycle._renew_claim(  # type: ignore[reportPrivateUsage]
        claim,
        asyncio.Event(),
        invalid,
    )
    assert invalid.is_set()


@pytest.mark.anyio
async def test_path_claim_revalidation_blocks_verified_and_lkg_after_conflict(
    tmp_path: Path,
) -> None:
    async def verified(
        path: Path,
    ) -> tuple[
        ManagedPathLifecycle,
        NetworkGovernanceRecord,
        NetworkAuthorizationGrant,
        SQLiteNetworkGovernanceStore,
    ]:
        lifecycle, policy, _, _, _, _, _, store = build(path)
        envelope, _ = signed()
        pending = await lifecycle.reconcile(
            envelope,
            action=NetworkAction.CREATE,
            ownership=None,
        )
        grant = grant_for(pending)
        policy.approve(grant, capability=policy.local_control_capability())
        result = await lifecycle.reconcile(
            envelope,
            action=NetworkAction.CREATE,
            ownership=None,
        )
        return lifecycle, result, grant, store

    lifecycle, result, grant, store = await verified(tmp_path / "event")
    claim = store.claim_apply(
        result.plan,
        authorization_id=grant.authorization_id,
        idempotency_key=result.idempotency_key,
        now=SIGNED_NOW,
    )
    invalid = asyncio.Event()
    invalid.set()
    blocked = await lifecycle._verify_path(  # type: ignore[reportPrivateUsage]
        result,
        claim=claim,
        claim_invalid=invalid,
    )
    assert blocked.phase is NetworkGovernancePhase.RECOVERY_REQUIRED
    assert blocked.last_known_good_revision == result.last_known_good_revision

    lifecycle, result, grant, store = await verified(tmp_path / "assert")
    claim = store.claim_apply(
        result.plan,
        authorization_id=grant.authorization_id,
        idempotency_key=result.idempotency_key,
        now=SIGNED_NOW,
    )

    def reject_assert(claim: NetworkApplyClaim, *, now: datetime) -> None:
        del claim, now
        raise NetworkApplyClaimConflictError("fake path claim conflict")

    store.assert_apply_claim = reject_assert  # type: ignore[method-assign]
    blocked = await lifecycle._verify_path(  # type: ignore[reportPrivateUsage]
        result,
        claim=claim,
        claim_invalid=asyncio.Event(),
    )
    assert blocked.phase is NetworkGovernancePhase.RECOVERY_REQUIRED
    assert blocked.last_known_good_revision == result.last_known_good_revision


@pytest.mark.anyio
@pytest.mark.parametrize("provider_type", [RollbackRaisesProvider, RollbackMismatchedProvider])
async def test_rollback_error_matrix_is_fail_closed(
    tmp_path: Path,
    provider_type: type[InMemoryNetworkProvider],
) -> None:
    provider = provider_type(observation())
    lifecycle, policy, _, _, _, _, _, _ = build(
        tmp_path,
        provider_override=provider,
    )
    envelope, _ = signed()
    pending = await lifecycle.reconcile(envelope, action=NetworkAction.CREATE, ownership=None)
    policy.approve(grant_for(pending), capability=policy.local_control_capability())
    result = await lifecycle.reconcile(envelope, action=NetworkAction.CREATE, ownership=None)
    assert result.phase in {
        NetworkGovernancePhase.MANUAL_INTERVENTION,
        NetworkGovernancePhase.RECOVERY_REQUIRED,
    }
    assert provider.apply_calls == 1


@pytest.mark.anyio
@pytest.mark.parametrize(
    "provider_type",
    [
        EmergencyErrorProvider,
        EmergencyCancelledProvider,
        EmergencyMismatchedReceiptProvider,
        EmergencyCancelledReceiptProvider,
        EmergencyVerifyFailureProvider,
    ],
)
async def test_kill_switch_error_matrix_never_uses_normal_apply(
    tmp_path: Path,
    provider_type: type[InMemoryNetworkProvider],
) -> None:
    managed = observation(ownership_state=OwnershipState.MANAGED_OWNED)
    owned: ManagedResourceOwnership = ownership(managed)
    provider = provider_type(observation())
    lifecycle, policy, actual, _, _, _, _, _, _envelope, _ = await _authorized(
        tmp_path,
        provider=provider,
    )
    object.__setattr__(actual, "_observation", managed)
    stop_envelope, _ = signed(revision=2, parent_revision=1)
    if provider_type is EmergencyCancelledProvider:
        with pytest.raises(asyncio.CancelledError):
            await lifecycle.emergency_stop(
                stop_envelope,
                owned,
                capability=policy.kill_switch_capability(),
            )
    else:
        result = await lifecycle.emergency_stop(
            stop_envelope,
            owned,
            capability=policy.kill_switch_capability(),
        )
        assert result.phase in {
            NetworkGovernancePhase.MANUAL_INTERVENTION,
            NetworkGovernancePhase.RECOVERY_REQUIRED,
        }
    assert actual.apply_calls == 0


@pytest.mark.anyio
@pytest.mark.parametrize(
    "provider_type",
    [
        EmergencyVerifyCancelledProvider,
        EmergencyVerifyTimeoutProvider,
        EmergencyMismatchedVerificationProvider,
    ],
)
async def test_kill_switch_verify_failures_are_recoverable(
    tmp_path: Path,
    provider_type: type[InMemoryNetworkProvider],
) -> None:
    managed = observation(ownership_state=OwnershipState.MANAGED_OWNED)
    provider = provider_type(observation())
    lifecycle, policy, actual, _, _, _, _, _, _, _ = await _authorized(
        tmp_path,
        provider=provider,
    )
    object.__setattr__(actual, "_observation", managed)
    stop_envelope, _ = signed(revision=2, parent_revision=1)
    if provider_type is EmergencyVerifyCancelledProvider:
        with pytest.raises(asyncio.CancelledError):
            await lifecycle.emergency_stop(
                stop_envelope,
                ownership(managed),
                capability=policy.kill_switch_capability(),
            )
    else:
        result = await lifecycle.emergency_stop(
            stop_envelope,
            ownership(managed),
            capability=policy.kill_switch_capability(),
        )
        assert result.phase is NetworkGovernancePhase.RECOVERY_REQUIRED
    assert actual.apply_calls == 0


@pytest.mark.anyio
async def test_fake_kill_switch_cancellation_is_a_safe_point(tmp_path: Path) -> None:
    del tmp_path
    managed = observation(ownership_state=OwnershipState.MANAGED_OWNED)
    provider = InMemoryNetworkProvider(managed)
    envelope, _ = signed(revision=2, parent_revision=1)
    plan = await provider.plan(
        action=NetworkAction.STOP,
        desired=envelope.config,
        observed=managed,
        ownership=ownership(managed),
    )
    cancellation = ToolCancellationToken()
    cancellation.cancel()
    receipt = await provider.emergency_stop(
        plan,
        idempotency_key=f"netop_{'a' * 64}",
        cancellation=cancellation,
    )
    repeated = await provider.emergency_stop(
        plan,
        idempotency_key=receipt.idempotency_key,
        cancellation=ToolCancellationToken(),
    )
    assert receipt.status is ReceiptStatus.CANCELLED
    assert repeated == receipt
    assert provider.emergency_stop_calls == 2
    assert provider.apply_calls == 0


@pytest.mark.anyio
async def test_recovery_with_external_active_claim_does_not_replay_apply(tmp_path: Path) -> None:
    ledger = create_recovery_ledger()
    envelope, _, policy, provider, store = await crash_after_apply(
        tmp_path,
        InMemoryNetworkProvider(observation()),
        ledger=ledger,
    )
    _sql(
        store.path,
        "UPDATE network_apply_claims SET state='active', lease_expires_at=? "
        "WHERE network_id=? AND node_id=? AND revision=?",
        (
            (SIGNED_NOW + timedelta(minutes=1)).isoformat(),
            str(NETWORK_ID),
            str(NODE_A),
            1,
        ),
    )
    recovered = await recover_one(envelope, policy, provider, store, ledger=ledger)
    saved = store.get(NETWORK_ID, NODE_A, 1)
    assert saved is not None
    assert recovered == saved
    assert recovered.phase is NetworkGovernancePhase.APPLYING
    assert provider.apply_calls == 1


@pytest.mark.anyio
@pytest.mark.parametrize(
    "provider_type",
    [InMemoryNetworkProvider, VerifyTimeoutProvider, VerifyMismatchedProvider],
)
async def test_early_recovery_verifies_without_apply_replay(
    tmp_path: Path,
    provider_type: type[InMemoryNetworkProvider],
) -> None:
    ledger = create_recovery_ledger()
    envelope, grant, policy, provider, store = await crash_after_apply(
        tmp_path,
        provider_type(observation()),
        ledger=ledger,
    )
    del grant
    saved = store.get(NETWORK_ID, NODE_A, 1)
    assert saved is not None
    mutator = ManagedPathLifecycle(
        provider,
        policy,
        store,
        None,
        path_verifier=FakePathVerifier(path_evidence()),
        path_controller=controller(),
        clock=lambda: NOW,
        ledger=ledger,
    )
    authorized = mutator._journal(  # type: ignore[reportPrivateUsage]
        saved,
        NetworkGovernancePhase.AUTHORIZED,
    )
    assert authorized.phase is NetworkGovernancePhase.AUTHORIZED
    recovered = await recover_one(envelope, policy, provider, store, ledger=ledger)
    assert recovered.phase is NetworkGovernancePhase.RECOVERY_REQUIRED
    assert provider.apply_calls == 1


@pytest.mark.anyio
async def test_early_recovery_propagates_verify_cancellation_without_apply_replay(
    tmp_path: Path,
) -> None:
    ledger = create_recovery_ledger()
    envelope, grant, policy, provider, store = await crash_after_apply(
        tmp_path,
        CancelVerifyProvider(observation()),
        ledger=ledger,
    )
    del grant
    saved = store.get(NETWORK_ID, NODE_A, 1)
    assert saved is not None
    mutator = ManagedPathLifecycle(
        provider,
        policy,
        store,
        None,
        path_verifier=FakePathVerifier(path_evidence()),
        path_controller=controller(),
        clock=lambda: NOW,
        ledger=ledger,
    )
    mutator._journal(  # type: ignore[reportPrivateUsage]
        saved,
        NetworkGovernancePhase.AUTHORIZED,
    )
    with pytest.raises(asyncio.CancelledError):
        await recover_one(envelope, policy, provider, store, ledger=ledger)
    assert provider.apply_calls == 1


@pytest.mark.parametrize(
    "provider_type",
    [
        RecoverAppliedProvider,
        RecoverAppliedVerifyTimeoutProvider,
        RecoverAppliedMismatchedVerificationProvider,
    ],
)
@pytest.mark.anyio
async def test_late_recovery_queries_applied_receipt_without_apply_replay(
    tmp_path: Path,
    provider_type: type[InMemoryNetworkProvider],
) -> None:
    ledger = create_recovery_ledger()
    envelope, _, policy, provider, store = await crash_after_apply(
        tmp_path,
        provider_type(observation()),
        ledger=ledger,
    )
    recovered = await recover_one(envelope, policy, provider, store, ledger=ledger)
    if provider_type is RecoverAppliedProvider:
        assert recovered.phase in {
            NetworkGovernancePhase.VERIFIED,
            NetworkGovernancePhase.PATH_DEGRADED,
        }
    else:
        assert recovered.phase is NetworkGovernancePhase.RECOVERY_REQUIRED
    assert provider.apply_calls == 1


@pytest.mark.anyio
async def test_late_recovery_propagates_verify_cancellation_without_apply_replay(
    tmp_path: Path,
) -> None:
    ledger = create_recovery_ledger()
    envelope, _, policy, provider, store = await crash_after_apply(
        tmp_path,
        RecoverAppliedCancelVerifyProvider(observation()),
        ledger=ledger,
    )
    with pytest.raises(asyncio.CancelledError):
        await recover_one(envelope, policy, provider, store, ledger=ledger)
    assert provider.apply_calls == 1


@pytest.mark.anyio
async def test_legacy_workflow_delegates_all_paths_to_one_lifecycle(tmp_path: Path) -> None:
    provider = InMemoryNetworkProvider(observation())
    (
        _lifecycle,
        policy,
        actual,
        ack,
        sink,
        verifier,
        path_controller,
        store,
        envelope,
        _,
    ) = await _authorized(
        tmp_path,
        provider=provider,
    )
    adapter = ManagedNetworkGovernanceWorkflow(
        actual,
        policy,
        store,
        ack,
        path_verifier=verifier,
        path_controller=path_controller,
        path_status_sink=sink,
        clock=lambda: SIGNED_NOW,
    )
    pending = await adapter.reconcile(envelope, action=NetworkAction.CREATE, ownership=None)
    assert pending.phase is NetworkGovernancePhase.VERIFIED
    owned = ownership(await actual.observe(envelope.config.interface_name))
    assert await adapter.recover() == ()
    adapter._lifecycle.recover = lambda: _one_record(pending)  # type: ignore[method-assign, reportPrivateUsage]
    assert await adapter.recover_without_model() == (pending.receipt,)
    stop_envelope, _ = signed(revision=2, parent_revision=1)
    stopped = await adapter.emergency_stop(
        stop_envelope,
        owned,
        capability=policy.kill_switch_capability(),
    )
    assert stopped.phase is NetworkGovernancePhase.VERIFIED
    assert actual.apply_calls == 1


async def _one_record(record: NetworkGovernanceRecord) -> tuple[NetworkGovernanceRecord, ...]:
    return (record,)
