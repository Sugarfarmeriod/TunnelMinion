"""L3 网络授权、治理执行、回滚、恢复和脱敏状态测试。"""

from __future__ import annotations

import asyncio
import sqlite3
from collections.abc import Callable
from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
from pydantic import ValidationError
from tests.agent.test_network_sync import NOW, signed
from tests.network.control_harness import (
    NetworkOperationPolicy,
    SQLiteNetworkAuthorizationRepository,
)
from tests.network.factories import (
    NETWORK_ID,
    NODE_A,
    NODE_B,
    observation,
    ownership,
)
from tests.network.test_managed_path_lifecycle import (
    CountingLedger,
    FakePathVerifier,
    controller,
    create_recovery_ledger,
    path_evidence,
)

from tunnelminion.domain.identifiers import AuthorizationId
from tunnelminion.network.contracts import (
    AcknowledgementStage,
    NetworkAcknowledgement,
    NetworkAction,
    NetworkPlan,
    OwnershipState,
    ProviderKind,
    ProviderReceipt,
    ReceiptStatus,
    RelayRole,
    VerificationResult,
)
from tunnelminion.network.fakes import FakeProviderBehavior, InMemoryNetworkProvider
from tunnelminion.network.governance import (
    LocalControlAuthority,
    ManagedPathLifecycle,
    NetworkApplyClaimConflictError,
    NetworkAuthorizationConflictError,
    NetworkAuthorizationGrant,
    NetworkAuthorizationScope,
    NetworkAuthorizationStorageError,
    NetworkGovernancePhase,
    NetworkGovernanceRecord,
    NetworkOwnershipLedger,
    NetworkPathStatus,
    NetworkPolicyAction,
    SQLiteNetworkGovernanceStore,
    redacted_path_status_payload,
)
from tunnelminion.network.governance import (
    NetworkOperationPolicy as ProductionNetworkOperationPolicy,
)
from tunnelminion.network.governance import (
    SQLiteNetworkAuthorizationRepository as ProductionAuthorizationRepository,
)
from tunnelminion.tools.contracts import ToolCancellationToken


class MemoryAcknowledgements:
    def __init__(self) -> None:
        self.items: list[NetworkAcknowledgement] = []
        self.error: Exception | None = None

    async def acknowledge(self, acknowledgement: NetworkAcknowledgement) -> None:
        if self.error is not None:
            raise self.error
        self.items.append(acknowledgement)


class VerifyThenRollbackFailureProvider(InMemoryNetworkProvider):
    async def verify(self, plan: NetworkPlan) -> VerificationResult:
        self.behavior = FakeProviderBehavior.VERIFY_FAILURE
        result = await super().verify(plan)
        self.behavior = FakeProviderBehavior.ROLLBACK_FAILURE
        return result


def workflow(
    tmp_path: Path,
    provider: InMemoryNetworkProvider,
    *,
    commit_last_known_good: Callable[[object], object] | None = None,
    ledger: NetworkOwnershipLedger | None = None,
    clock: Callable[[], datetime] | None = None,
) -> tuple[
    ManagedPathLifecycle,
    NetworkOperationPolicy,
    SQLiteNetworkGovernanceStore,
    MemoryAcknowledgements,
]:
    policy = NetworkOperationPolicy()
    database = tmp_path / "governance.sqlite3"
    repository = SQLiteNetworkAuthorizationRepository(database)
    store = SQLiteNetworkGovernanceStore(
        database,
        authorization_repository=repository,
    )
    policy.attach_writer(repository)
    acknowledgements = MemoryAcknowledgements()
    return (
        ManagedPathLifecycle(
            provider,
            policy,
            store,
            acknowledgements,
            path_verifier=FakePathVerifier(path_evidence()),
            path_controller=controller(),
            path_status_sink=None,
            ledger=ledger,
            clock=clock or (lambda: NOW),
            commit_last_known_good=commit_last_known_good,
        ),
        policy,
        store,
        acknowledgements,
    )


def grant_for(
    record: NetworkGovernanceRecord,
    *,
    expires_in: timedelta = timedelta(minutes=5),
) -> NetworkAuthorizationGrant:
    return NetworkAuthorizationGrant(
        authorization_id=AuthorizationId.new(),
        scope=NetworkAuthorizationScope.from_plan(
            record.plan,
            address_pool="10.203.0.0/24",
        ),
        approved_by="local-owner",
        approved_at=NOW,
        expires_at=NOW + expires_in,
    )


@pytest.mark.anyio
async def test_unsigned_local_approval_boundary_and_verified_idempotency(
    tmp_path: Path,
) -> None:
    envelope, _ = signed()
    provider = InMemoryNetworkProvider(observation())
    committed: list[object] = []
    governance, policy, store, acknowledgements = workflow(
        tmp_path,
        provider,
        commit_last_known_good=lambda item: committed.append(item),
    )

    awaiting = await governance.reconcile(
        envelope,
        action=NetworkAction.CREATE,
        ownership=None,
    )
    assert awaiting.phase is NetworkGovernancePhase.AWAITING_AUTHORIZATION
    assert acknowledgements.items[-1].stage is AcknowledgementStage.AWAITING_AUTHORIZATION

    grant = grant_for(awaiting)
    with pytest.raises(TypeError):
        policy.approve(grant, local_control=False)  # type: ignore[call-arg]
    policy.approve(grant, capability=policy.local_control_capability())

    verified = await governance.reconcile(
        envelope,
        action=NetworkAction.CREATE,
        ownership=None,
    )
    repeated = await governance.reconcile(
        envelope,
        action=NetworkAction.CREATE,
        ownership=None,
    )
    assert verified.phase is NetworkGovernancePhase.VERIFIED
    assert verified.verification is not None and verified.verification.succeeded
    assert repeated == verified
    assert provider.apply_calls == 1
    assert committed == [envelope]
    assert [item.stage for item in acknowledgements.items] == [
        AcknowledgementStage.AWAITING_AUTHORIZATION,
        AcknowledgementStage.VERIFIED,
    ]
    assert acknowledgements.items[-1].receipt_hash is not None
    store.assert_no_secret_material()


@pytest.mark.anyio
async def test_coordinator_ack_failure_does_not_block_local_governance(
    tmp_path: Path,
) -> None:
    envelope, _ = signed()
    provider = InMemoryNetworkProvider(observation())
    governance, policy, _, acknowledgements = workflow(tmp_path, provider)
    awaiting = await governance.reconcile(
        envelope,
        action=NetworkAction.CREATE,
        ownership=None,
    )
    policy.approve(grant_for(awaiting), capability=policy.local_control_capability())
    acknowledgements.error = ConnectionError("offline")
    verified = await governance.reconcile(
        envelope,
        action=NetworkAction.CREATE,
        ownership=None,
    )
    assert verified.phase is NetworkGovernancePhase.VERIFIED


@pytest.mark.anyio
async def test_scope_expansion_revocation_and_expiry_require_new_approval(
    tmp_path: Path,
) -> None:
    envelope, _ = signed()
    governance, policy, _, _ = workflow(tmp_path, InMemoryNetworkProvider(observation()))
    awaiting = await governance.reconcile(
        envelope,
        action=NetworkAction.CREATE,
        ownership=None,
    )
    grant = grant_for(awaiting)
    policy.approve(grant, capability=policy.local_control_capability())
    assert policy.evaluate(awaiting.plan, at=NOW).action is NetworkPolicyAction.EXECUTE

    expanded = awaiting.plan.model_copy(update={"plan_hash": f"sha256:{'f' * 64}"})
    assert policy.evaluate(expanded, at=NOW).action is NetworkPolicyAction.AWAIT_AUTHORIZATION
    with pytest.raises(TypeError):
        policy.revoke(  # type: ignore[call-arg]
            grant.authorization_id,
            revoked_at=NOW,
            local_control=False,  # type: ignore[call-arg]
        )
    policy.revoke(
        grant.authorization_id,
        revoked_at=NOW,
        capability=policy.local_control_capability(),
    )
    assert policy.evaluate(awaiting.plan, at=NOW).action is NetworkPolicyAction.AWAIT_AUTHORIZATION

    expired = grant_for(awaiting, expires_in=timedelta(seconds=1))
    policy.approve(expired, capability=policy.local_control_capability())
    assert (
        policy.evaluate(awaiting.plan, at=NOW + timedelta(seconds=1)).action
        is NetworkPolicyAction.AWAIT_AUTHORIZATION
    )


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("behavior", "expected"),
    [
        (FakeProviderBehavior.STEP_FAILURE, NetworkGovernancePhase.ROLLED_BACK),
        (FakeProviderBehavior.VERIFY_FAILURE, NetworkGovernancePhase.ROLLED_BACK),
        (
            FakeProviderBehavior.OWNERSHIP_REPLACED,
            NetworkGovernancePhase.OWNERSHIP_CONFLICT,
        ),
    ],
)
async def test_failure_rolls_back_or_fuses_on_ownership_conflict(
    tmp_path: Path,
    behavior: FakeProviderBehavior,
    expected: NetworkGovernancePhase,
) -> None:
    envelope, _ = signed()
    provider = InMemoryNetworkProvider(observation(), behavior=behavior)
    governance, policy, _, acknowledgements = workflow(tmp_path, provider)
    awaiting = await governance.reconcile(
        envelope,
        action=NetworkAction.CREATE,
        ownership=None,
    )
    policy.approve(grant_for(awaiting), capability=policy.local_control_capability())
    result = await governance.reconcile(
        envelope,
        action=NetworkAction.CREATE,
        ownership=None,
    )

    assert result.phase is expected
    assert provider.rollback_calls == 1
    if expected is NetworkGovernancePhase.OWNERSHIP_CONFLICT:
        assert acknowledgements.items[-1].stage is AcknowledgementStage.OWNERSHIP_CONFLICT
    else:
        assert result.receipt is not None
        assert result.receipt.status is ReceiptStatus.ROLLED_BACK


@pytest.mark.anyio
async def test_response_loss_crash_recovery_and_cancellation_are_bounded(
    tmp_path: Path,
) -> None:
    envelope, _ = signed()
    provider = InMemoryNetworkProvider(
        observation(),
        behavior=FakeProviderBehavior.RESPONSE_LOST,
    )
    governance, policy, store, _ = workflow(
        tmp_path / "loss",
        provider,
        ledger=create_recovery_ledger(),
    )
    awaiting = await governance.reconcile(
        envelope,
        action=NetworkAction.CREATE,
        ownership=None,
    )
    policy.approve(grant_for(awaiting), capability=policy.local_control_capability())
    with pytest.raises(TimeoutError, match="response loss"):
        await governance.reconcile(
            envelope,
            action=NetworkAction.CREATE,
            ownership=None,
        )
    recovered_retry = await governance.reconcile(
        envelope,
        action=NetworkAction.CREATE,
        ownership=None,
    )
    assert recovered_retry.phase is NetworkGovernancePhase.ROLLED_BACK
    assert provider.apply_calls == 1
    assert store.list_recoverable() == ()

    crash_observed = observation(ownership_state=OwnershipState.MANAGED_OWNED)
    crash_ownership = ownership(crash_observed)
    crashing = InMemoryNetworkProvider(
        crash_observed,
        behavior=FakeProviderBehavior.CRASH_AFTER_STEP,
    )
    crash_flow, crash_policy, crash_store, _ = workflow(
        tmp_path / "crash",
        crashing,
        ledger=CountingLedger(SimpleNamespace(ownership=crash_ownership)),
    )
    crash_awaiting = await crash_flow.reconcile(
        envelope,
        action=NetworkAction.UPDATE,
        ownership=crash_ownership,
    )
    crash_policy.approve(
        grant_for(crash_awaiting), capability=crash_policy.local_control_capability()
    )
    with pytest.raises(RuntimeError, match="provider crash"):
        await crash_flow.reconcile(
            envelope,
            action=NetworkAction.UPDATE,
            ownership=crash_ownership,
        )
    recovered = await crash_flow.recover()
    assert recovered[0].receipt is not None
    assert recovered[0].receipt.status is ReceiptStatus.ROLLED_BACK
    saved = crash_store.get(NETWORK_ID, NODE_A, 1)
    assert saved is not None and saved.phase is NetworkGovernancePhase.ROLLED_BACK

    cancelled_provider = InMemoryNetworkProvider(observation())
    cancelled_flow, cancelled_policy, _, _ = workflow(
        tmp_path / "cancel",
        cancelled_provider,
    )
    cancelled_awaiting = await cancelled_flow.reconcile(
        envelope,
        action=NetworkAction.CREATE,
        ownership=None,
    )
    cancelled_policy.approve(
        grant_for(cancelled_awaiting), capability=cancelled_policy.local_control_capability()
    )
    token = ToolCancellationToken()
    token.cancel()
    cancelled = await cancelled_flow.reconcile(
        envelope,
        action=NetworkAction.CREATE,
        ownership=None,
        cancellation=token,
    )
    assert cancelled.phase is NetworkGovernancePhase.CANCELLED
    assert cancelled_provider.apply_calls == 0

    empty_provider = InMemoryNetworkProvider(observation())
    empty_flow, _, empty_store, _ = workflow(
        tmp_path / "empty-recovery",
        empty_provider,
        ledger=create_recovery_ledger(),
    )
    empty_awaiting = await empty_flow.reconcile(
        envelope,
        action=NetworkAction.CREATE,
        ownership=None,
    )
    empty_flow._journal(  # type: ignore[reportPrivateUsage]
        empty_awaiting,
        NetworkGovernancePhase.APPLYING,
    )
    empty_recovered = await empty_flow.recover()
    assert empty_recovered and empty_recovered[0].phase is NetworkGovernancePhase.RECOVERY_REQUIRED
    unchanged = empty_store.get(NETWORK_ID, NODE_A, 1)
    assert unchanged is not None and unchanged.phase is NetworkGovernancePhase.RECOVERY_REQUIRED


@pytest.mark.anyio
async def test_rollback_failure_requires_manual_intervention(tmp_path: Path) -> None:
    envelope, _ = signed()
    provider = VerifyThenRollbackFailureProvider(observation())
    governance, policy, _, acknowledgements = workflow(tmp_path, provider)
    awaiting = await governance.reconcile(
        envelope,
        action=NetworkAction.CREATE,
        ownership=None,
    )
    policy.approve(grant_for(awaiting), capability=policy.local_control_capability())
    result = await governance.reconcile(
        envelope,
        action=NetworkAction.CREATE,
        ownership=None,
    )
    assert result.phase is NetworkGovernancePhase.MANUAL_INTERVENTION
    assert acknowledgements.items[-1].stage is AcknowledgementStage.MANUAL_INTERVENTION


@pytest.mark.anyio
async def test_single_apply_lock_and_emergency_stop_require_local_matching_ownership(
    tmp_path: Path,
) -> None:
    envelope, _ = signed()
    provider = InMemoryNetworkProvider(observation())
    governance, policy, _, _ = workflow(tmp_path / "lock", provider)
    awaiting = await governance.reconcile(
        envelope,
        action=NetworkAction.CREATE,
        ownership=None,
    )
    policy.approve(grant_for(awaiting), capability=policy.local_control_capability())
    original_apply = provider.apply
    gate = asyncio.Event()

    async def blocking_apply(
        plan: NetworkPlan,
        *,
        idempotency_key: str,
        cancellation: ToolCancellationToken,
    ) -> ProviderReceipt:
        await gate.wait()
        return await original_apply(
            plan,
            idempotency_key=idempotency_key,
            cancellation=cancellation,
        )

    provider.apply = blocking_apply  # type: ignore[method-assign]
    first = asyncio.create_task(
        governance.reconcile(envelope, action=NetworkAction.CREATE, ownership=None)
    )
    await asyncio.sleep(0)
    with pytest.raises(RuntimeError, match="path lifecycle 已在运行"):
        await governance.reconcile(envelope, action=NetworkAction.CREATE, ownership=None)
    gate.set()
    await first

    managed = observation(ownership_state=OwnershipState.MANAGED_OWNED)
    owned = ownership(managed)
    emergency_provider = InMemoryNetworkProvider(managed)
    emergency, emergency_policy, _, _ = workflow(tmp_path / "emergency", emergency_provider)
    with pytest.raises(TypeError):
        await emergency.emergency_stop(  # type: ignore[call-arg]
            envelope,
            owned,
            local_control=False,  # type: ignore[call-arg]
        )
    mismatched = owned.model_copy(update={"system_fingerprint": f"sha256:{'0' * 64}"})
    with pytest.raises(RuntimeError, match="不匹配"):
        await emergency.emergency_stop(
            envelope,
            mismatched,
            capability=emergency_policy.kill_switch_capability(),
        )
    stopped = await emergency.emergency_stop(
        envelope,
        owned,
        capability=emergency_policy.kill_switch_capability(),
    )
    assert stopped.phase is NetworkGovernancePhase.VERIFIED


def test_scope_store_status_and_clock_validation(tmp_path: Path) -> None:
    envelope, _ = signed()
    provider = InMemoryNetworkProvider(observation())
    governance, _, store, _ = workflow(tmp_path, provider)
    assert governance is not None

    status = NetworkPathStatus(
        network_id=NETWORK_ID,
        node_id=NODE_A,
        revision=1,
        path_type="direct",
        candidate_count=2,
        relay_identity_hash=None,
        last_handshake_at=NOW,
        last_probe_at=NOW,
    )
    payload = redacted_path_status_payload(status)
    assert set(payload) == {
        "network_id",
        "node_id",
        "revision",
        "path_type",
        "candidate_count",
        "relay_identity_hash",
        "last_handshake_at",
        "last_probe_at",
        "stable_error_code",
    }
    with pytest.raises(ValidationError):
        NetworkPathStatus.model_validate({**payload, "endpoint": "198.51.100.1:18889"})

    connection = sqlite3.connect(tmp_path / "governance.sqlite3")
    connection.execute(
        """
        INSERT INTO network_governance(network_id, node_id, revision, payload)
        VALUES (?, ?, ?, ?)
        """,
        (str(NETWORK_ID), str(NODE_B), 99, '{"private_key":"secret"}'),
    )
    connection.commit()
    connection.close()
    with pytest.raises(ValueError, match="秘密字段"):
        store.get(NETWORK_ID, NODE_B, 99)

    naive_database = tmp_path / "naive.sqlite3"
    naive_repository = SQLiteNetworkAuthorizationRepository(naive_database)
    naive_store = SQLiteNetworkGovernanceStore(
        naive_database,
        authorization_repository=naive_repository,
    )
    naive = ManagedPathLifecycle(
        provider,
        NetworkOperationPolicy(),
        naive_store,
        MemoryAcknowledgements(),
        path_verifier=FakePathVerifier(path_evidence()),
        path_controller=controller(),
        path_status_sink=None,
        clock=lambda: NOW.replace(tzinfo=None),
    )
    with pytest.raises(ValueError, match="时区"):
        asyncio.run(naive.reconcile(envelope, action=NetworkAction.CREATE, ownership=None))


def test_scope_rejects_noncanonical_values_and_invalid_grant_times() -> None:
    with pytest.raises(ValidationError):
        NetworkAuthorizationScope(
            network_id=NETWORK_ID,
            node_id=NODE_A,
            provider=ProviderKind.WINDOWS,
            action=NetworkAction.CREATE,
            ownership_fingerprint=f"sha256:{'a' * 64}",
            interface_prefix="tmn-",
            address_pool="10.203.0.1/24",
            allowed_host_routes=frozenset({"10.203.0.2/32"}),
            allowed_route_overlaps=frozenset(),
            peer_node_ids=(NODE_B,),
            maximum_peers=1,
            allowed_relay_roles=frozenset({RelayRole.NONE}),
            revision=1,
            parent_revision=0,
            plan_hash=f"sha256:{'b' * 64}",
            observed_fingerprint=f"sha256:{'c' * 64}",
        )
    valid = NetworkAuthorizationScope(
        network_id=NETWORK_ID,
        node_id=NODE_A,
        provider=ProviderKind.WINDOWS,
        action=NetworkAction.CREATE,
        ownership_fingerprint=f"sha256:{'a' * 64}",
        interface_prefix="tmn-",
        address_pool="10.203.0.0/24",
        allowed_host_routes=frozenset({"10.203.0.2/32"}),
        allowed_route_overlaps=frozenset(),
        peer_node_ids=(NODE_B,),
        maximum_peers=1,
        allowed_relay_roles=frozenset({RelayRole.NONE}),
        revision=1,
        parent_revision=0,
        plan_hash=f"sha256:{'b' * 64}",
        observed_fingerprint=f"sha256:{'c' * 64}",
    )
    invalid_scopes = (
        {"allowed_host_routes": frozenset({"2001:0db8::2/128"})},
        {"maximum_peers": 1, "peer_node_ids": (NODE_A, NODE_B)},
        {"peer_node_ids": (NODE_B, NODE_B), "maximum_peers": 2},
    )
    for update in invalid_scopes:
        with pytest.raises(ValidationError):
            NetworkAuthorizationScope.model_validate({**valid.model_dump(), **update})
    with pytest.raises(ValidationError, match="过期"):
        NetworkAuthorizationGrant(
            authorization_id=AuthorizationId.new(),
            scope=valid,
            approved_by="owner",
            approved_at=NOW,
            expires_at=NOW,
        )
    with pytest.raises(ValidationError, match="撤销"):
        NetworkAuthorizationGrant(
            authorization_id=AuthorizationId.new(),
            scope=valid,
            approved_by="owner",
            approved_at=NOW,
            expires_at=NOW + timedelta(minutes=1),
            revoked_at=NOW - timedelta(seconds=1),
        )

    secret_status = NetworkPathStatus(
        network_id=NETWORK_ID,
        node_id=NODE_A,
        revision=1,
        path_type="offline",
        candidate_count=0,
        stable_error_code="private_key",
    )
    with pytest.raises(ValueError, match="秘密"):
        redacted_path_status_payload(secret_status)


@pytest.mark.anyio
async def test_authorization_repository_migrates_restarts_and_revokes_irreversibly(
    tmp_path: Path,
) -> None:
    envelope, _ = signed()
    provider = InMemoryNetworkProvider(observation())
    governance, policy, store, _ = workflow(tmp_path, provider)
    awaiting = await governance.reconcile(
        envelope,
        action=NetworkAction.CREATE,
        ownership=None,
    )
    grant = grant_for(awaiting)
    policy.approve(grant, capability=policy.local_control_capability())

    # 新连接只从同一治理 SQLite 的授权表恢复，不依赖进程内状态。
    restarted = SQLiteNetworkAuthorizationRepository(tmp_path / "governance.sqlite3")
    assert restarted.list_grants(NETWORK_ID, NODE_A) == (grant,)
    assert not hasattr(restarted.read_only, "approve")
    assert (
        NetworkOperationPolicy(restarted).evaluate(awaiting.plan, at=NOW).action
        is NetworkPolicyAction.EXECUTE
    )

    revoked = restarted.revoke(
        grant.authorization_id,
        revoked_at=NOW + timedelta(seconds=1),
        capability=restarted.authorization_capability(),
    )
    assert revoked.revoked_at == NOW + timedelta(seconds=1)
    assert (
        NetworkOperationPolicy(restarted).evaluate(awaiting.plan, at=NOW).action
        is NetworkPolicyAction.AWAIT_AUTHORIZATION
    )
    with pytest.raises(NetworkAuthorizationConflictError, match="不同授权范围"):
        restarted.approve(grant, capability=restarted.authorization_capability())
    with pytest.raises(NetworkAuthorizationConflictError, match="不可重新写入"):
        restarted.revoke(
            grant.authorization_id,
            revoked_at=NOW + timedelta(seconds=2),
            capability=restarted.authorization_capability(),
        )
    assert (
        SQLiteNetworkAuthorizationRepository(tmp_path / "governance.sqlite3").get(
            grant.authorization_id
        )
        == revoked
    )
    restarted.close()
    assert store.authorization_read_port.list_grants(NETWORK_ID, NODE_A) == (revoked,)


@pytest.mark.anyio
async def test_authorization_repository_rejects_scope_conflicts_and_corrupt_payload(
    tmp_path: Path,
) -> None:
    envelope, _ = signed()
    governance, policy, _, _ = workflow(tmp_path, InMemoryNetworkProvider(observation()))
    awaiting = await governance.reconcile(
        envelope,
        action=NetworkAction.CREATE,
        ownership=None,
    )
    grant = grant_for(awaiting)
    policy.approve(grant, capability=policy.local_control_capability())
    repository = SQLiteNetworkAuthorizationRepository(tmp_path / "governance.sqlite3")

    conflicting = grant.model_copy(
        update={
            "scope": grant.scope.model_copy(update={"observed_fingerprint": f"sha256:{'f' * 64}"})
        }
    )
    with pytest.raises(NetworkAuthorizationConflictError, match="不同授权范围"):
        repository.approve(conflicting, capability=repository.authorization_capability())

    connection = sqlite3.connect(tmp_path / "governance.sqlite3")
    connection.execute(
        "UPDATE network_authorization_grants SET payload = ? WHERE authorization_id = ?",
        ('{"private_key":"do-not-store"}', str(grant.authorization_id)),
    )
    connection.commit()
    connection.close()
    with pytest.raises(NetworkAuthorizationStorageError, match="秘密字段"):
        repository.list_grants(NETWORK_ID, NODE_A)


@pytest.mark.anyio
async def test_apply_claim_rechecks_revoke_in_same_sqlite_cas_domain(tmp_path: Path) -> None:
    envelope, _ = signed()
    provider = InMemoryNetworkProvider(observation())
    governance, policy, store, _ = workflow(tmp_path, provider)
    pending = await governance.reconcile(
        envelope,
        action=NetworkAction.CREATE,
        ownership=None,
    )
    grant = grant_for(pending)
    policy.approve(grant, capability=policy.local_control_capability())
    other = SQLiteNetworkAuthorizationRepository(tmp_path / "governance.sqlite3")
    claim = store.claim_apply(
        pending.plan,
        authorization_id=grant.authorization_id,
        idempotency_key=pending.idempotency_key,
        now=NOW,
    )

    with pytest.raises(NetworkApplyClaimConflictError, match="活动 apply claim"):
        other.revoke(
            grant.authorization_id,
            revoked_at=NOW + timedelta(seconds=1),
            capability=other.authorization_capability(),
        )
    store.assert_apply_claim(claim, now=NOW + timedelta(seconds=1))
    assert provider.apply_calls == 0
    other.close()


@pytest.mark.anyio
async def test_apply_claim_is_single_writer_and_expiry_is_fenced(tmp_path: Path) -> None:
    envelope, _ = signed()
    provider = InMemoryNetworkProvider(observation())
    governance, policy, store, _ = workflow(tmp_path, provider)
    pending = await governance.reconcile(
        envelope,
        action=NetworkAction.CREATE,
        ownership=None,
    )
    grant = grant_for(pending)
    policy.approve(grant, capability=policy.local_control_capability())
    other = SQLiteNetworkAuthorizationRepository(tmp_path / "governance.sqlite3")

    first = store.claim_apply(
        pending.plan,
        authorization_id=grant.authorization_id,
        idempotency_key=pending.idempotency_key,
        now=NOW,
    )
    with pytest.raises(NetworkApplyClaimConflictError, match="活跃"):
        other.claim_apply(
            pending.plan,
            authorization_id=grant.authorization_id,
            idempotency_key=pending.idempotency_key,
            now=NOW,
        )
    store.release_apply_claim(first)
    second = other.claim_apply(
        pending.plan,
        authorization_id=grant.authorization_id,
        idempotency_key=pending.idempotency_key,
        now=NOW + timedelta(seconds=1),
    )
    assert second.fencing_token > first.fencing_token
    assert other.reap_expired_claims(now=NOW + timedelta(seconds=40)) == 1
    with pytest.raises(NetworkApplyClaimConflictError, match="不可重放"):
        store.claim_apply(
            pending.plan,
            authorization_id=grant.authorization_id,
            idempotency_key=pending.idempotency_key,
            now=NOW + timedelta(seconds=41),
        )
    assert provider.apply_calls == 0
    other.close()


def test_authorization_repository_rejects_index_mismatch_and_read_failure(tmp_path: Path) -> None:
    envelope, _ = signed()
    provider = InMemoryNetworkProvider(observation())
    repository = SQLiteNetworkAuthorizationRepository(tmp_path / "governance.sqlite3")
    plan = asyncio.run(
        provider.plan(
            action=NetworkAction.CREATE,
            desired=envelope.config,
            observed=observation(),
            ownership=None,
        )
    )
    grant = NetworkAuthorizationGrant(
        authorization_id=AuthorizationId.new(),
        scope=NetworkAuthorizationScope.from_plan(plan, address_pool="10.203.0.0/24"),
        approved_by="local-owner",
        approved_at=NOW,
        expires_at=NOW + timedelta(minutes=5),
    )
    repository.approve(grant, capability=repository.authorization_capability())
    connection = sqlite3.connect(tmp_path / "governance.sqlite3")
    connection.execute(
        "UPDATE network_authorization_grants SET network_id = ? WHERE authorization_id = ?",
        (f"network_{'b' * 32}", str(grant.authorization_id)),
    )
    connection.commit()
    connection.close()
    with pytest.raises(NetworkAuthorizationConflictError, match="索引"):
        repository.list_grants(NETWORK_ID, NODE_A)

    repository.close()
    with pytest.raises(NetworkAuthorizationStorageError, match="结构读取失败"):
        repository.list_grants(NETWORK_ID, NODE_A)


def test_authorization_repository_uses_store_read_port(tmp_path: Path) -> None:
    database = tmp_path / "store-reader.sqlite3"
    repository = SQLiteNetworkAuthorizationRepository(database)
    store = SQLiteNetworkGovernanceStore(
        database,
        authorization_repository=repository,
    )
    assert store.list_grants(NETWORK_ID, NODE_A) == ()


def test_authorization_repository_validation_and_defensive_fail_closed_paths(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(ValueError, match="路径或现有连接"):
        SQLiteNetworkAuthorizationRepository()
    connection = sqlite3.connect(":memory:")
    with pytest.raises(ValueError, match="路径或现有连接"):
        SQLiteNetworkAuthorizationRepository(tmp_path / "both.sqlite3", connection=connection)
    connection.close()

    envelope, _ = signed()
    provider = InMemoryNetworkProvider(observation())
    plan = asyncio.run(
        provider.plan(
            action=NetworkAction.CREATE,
            desired=envelope.config,
            observed=observation(),
            ownership=None,
        )
    )
    grant = NetworkAuthorizationGrant(
        authorization_id=AuthorizationId.new(),
        scope=NetworkAuthorizationScope.from_plan(plan, address_pool="10.203.0.0/24"),
        approved_by="local-owner",
        approved_at=NOW,
        expires_at=NOW + timedelta(minutes=5),
    )
    production_authority = LocalControlAuthority()
    production_repository = ProductionAuthorizationRepository(
        ":memory:",
        control=production_authority,
    )
    assert not hasattr(production_repository, "authorization_capability")
    assert not hasattr(production_repository, "kill_switch_capability")
    assert not hasattr(ProductionNetworkOperationPolicy(), "local_control_capability")
    assert not hasattr(ProductionNetworkOperationPolicy(), "kill_switch_capability")
    forged_authority = LocalControlAuthority()
    with pytest.raises(PermissionError):
        production_repository.approve(
            grant,
            capability=forged_authority.authorization_capability(),
        )
    production_repository.close()
    repository = SQLiteNetworkAuthorizationRepository(":memory:")
    assert repository.approve(grant, capability=repository.authorization_capability()) == grant
    assert repository.approve(grant, capability=repository.authorization_capability()) == grant
    before_invalid_revoke = repository.list_grants(NETWORK_ID, NODE_A)
    with pytest.raises(ValueError, match="撤销时间"):
        repository.revoke(
            grant.authorization_id,
            revoked_at=NOW - timedelta(seconds=1),
            capability=repository.authorization_capability(),
        )
    assert repository.list_grants(NETWORK_ID, NODE_A) == before_invalid_revoke
    assert repository.revoke(
        grant.authorization_id,
        revoked_at=NOW + timedelta(seconds=1),
        capability=repository.authorization_capability(),
    ).revoked_at == NOW + timedelta(seconds=1)
    assert repository.revoke(
        grant.authorization_id,
        revoked_at=NOW + timedelta(seconds=1),
        capability=repository.authorization_capability(),
    ).revoked_at == NOW + timedelta(seconds=1)
    with pytest.raises(NetworkAuthorizationStorageError, match="未找到"):
        repository.revoke(
            AuthorizationId.new(),
            revoked_at=NOW,
            capability=repository.authorization_capability(),
        )
    with pytest.raises(ValueError, match="撤销时间"):
        repository.revoke(
            grant.authorization_id,
            revoked_at=NOW.replace(tzinfo=None),
            capability=repository.authorization_capability(),
        )
    repository.assert_no_secret_material()
    repository.close()
    assert repository._owns_connection is True  # pyright: ignore[reportPrivateUsage]

    shared_database = tmp_path / "shared.sqlite3"
    shared_repository = SQLiteNetworkAuthorizationRepository(shared_database)
    store = SQLiteNetworkGovernanceStore(
        shared_database,
        authorization_repository=shared_repository,
    )
    assert store.authorization_read_port.list_grants(NETWORK_ID, NODE_A) == ()

    policy = NetworkOperationPolicy()
    with pytest.raises(NetworkAuthorizationStorageError, match="尚未绑定"):
        policy.read_port()
    first = SQLiteNetworkAuthorizationRepository(":memory:")
    second = SQLiteNetworkAuthorizationRepository(":memory:")
    policy.bind(first)
    with pytest.raises(ValueError, match="多个"):
        policy.bind(second)
    first.close()
    second.close()

    # 解析层拒绝 JSON、秘密键、非对象、未知字段和非字符串行。
    cases = (
        ("{", "合法 JSON"),
        ("[]", "格式不可验证"),
        ('{"secret":"value"}', "秘密字段"),
        ("{}", "payload 不可验证"),
    )
    for index, (payload, message) in enumerate(cases):
        path = tmp_path / f"payload-{index}.sqlite3"
        case_repo = SQLiteNetworkAuthorizationRepository(path)
        case_repo.approve(
            grant.model_copy(update={"authorization_id": AuthorizationId.new()}),
            capability=case_repo.authorization_capability(),
        )
        case_connection = sqlite3.connect(path)
        case_connection.execute("UPDATE network_authorization_grants SET payload = ?", (payload,))
        case_connection.commit()
        case_connection.close()
        with pytest.raises(NetworkAuthorizationStorageError, match=message):
            case_repo.list_grants(NETWORK_ID, NODE_A)
        case_repo.close()

    malformed = SQLiteNetworkAuthorizationRepository(tmp_path / "malformed.sqlite3")
    malformed_grant = grant.model_copy(update={"authorization_id": AuthorizationId.new()})
    malformed.approve(malformed_grant, capability=malformed.authorization_capability())
    malformed_connection = sqlite3.connect(tmp_path / "malformed.sqlite3")
    malformed_connection.execute(
        "UPDATE network_authorization_grants SET payload = ?",
        ('{"scope":{"secret_value":"x"}}',),
    )
    malformed_connection.commit()
    malformed_connection.close()
    with pytest.raises(NetworkAuthorizationStorageError, match="秘密字段"):
        malformed.list_grants(NETWORK_ID, NODE_A)
    malformed.close()

    invalid_row = SQLiteNetworkAuthorizationRepository(tmp_path / "invalid-row.sqlite3")
    invalid_grant = grant.model_copy(update={"authorization_id": AuthorizationId.new()})
    invalid_row.approve(invalid_grant, capability=invalid_row.authorization_capability())
    invalid_connection = sqlite3.connect(tmp_path / "invalid-row.sqlite3")
    invalid_connection.execute(
        "UPDATE network_authorization_grants SET payload = ?",
        (sqlite3.Binary(b"not-text"),),
    )
    invalid_connection.commit()
    invalid_connection.close()
    with pytest.raises(NetworkAuthorizationStorageError, match="记录格式"):
        invalid_row.list_grants(NETWORK_ID, NODE_A)
    invalid_row.close()

    bad_schema = SQLiteNetworkAuthorizationRepository(tmp_path / "bad-schema.sqlite3")
    bad_schema._connection.execute(  # pyright: ignore[reportPrivateUsage]
        "DROP TABLE network_authorization_grants"
    )
    bad_schema._connection.execute(  # pyright: ignore[reportPrivateUsage]
        "CREATE TABLE network_authorization_grants (authorization_id TEXT PRIMARY KEY)"
    )
    with pytest.raises(NetworkAuthorizationStorageError, match="结构不可验证"):
        bad_schema.list_grants(NETWORK_ID, NODE_A)
    bad_schema.close()

    invalid_grant = grant.model_copy(update={"approved_at": NOW.replace(tzinfo=None)})
    with pytest.raises(ValueError, match="timezone-aware UTC"):
        NetworkAuthorizationGrant.model_validate(invalid_grant.model_dump())

    constructor_bad_schema = tmp_path / "constructor-bad-schema.sqlite3"
    constructor_connection = sqlite3.connect(constructor_bad_schema)
    constructor_connection.execute(
        "CREATE TABLE network_authorization_grants "
        "(authorization_id TEXT, network_id TEXT, node_id TEXT, payload TEXT)"
    )
    constructor_connection.commit()
    constructor_connection.close()
    with pytest.raises(NetworkAuthorizationStorageError, match="结构不可验证"):
        SQLiteNetworkAuthorizationRepository(constructor_bad_schema)

    closed_connection = sqlite3.connect(":memory:")
    closed_connection.close()
    with pytest.raises(NetworkAuthorizationStorageError, match="迁移失败"):
        SQLiteNetworkAuthorizationRepository(connection=closed_connection)

    read_failure = SQLiteNetworkAuthorizationRepository(":memory:")
    monkeypatch.setattr(read_failure, "_validate_schema", lambda: None)
    read_failure._connection.close()  # pyright: ignore[reportPrivateUsage]
    with pytest.raises(NetworkAuthorizationStorageError, match="记录读取失败"):
        read_failure.list_grants(NETWORK_ID, NODE_A)

    transaction_sql_failure = SQLiteNetworkAuthorizationRepository(":memory:")
    transaction_sql_failure._connection.close()  # pyright: ignore[reportPrivateUsage]
    with (
        pytest.raises(NetworkAuthorizationStorageError, match="事务失败"),
        transaction_sql_failure._transaction(),  # pyright: ignore[reportPrivateUsage]
    ):
        pass

    transaction_repo = SQLiteNetworkAuthorizationRepository(":memory:")
    with pytest.raises(RuntimeError, match="test transaction"), transaction_repo._transaction():  # pyright: ignore[reportPrivateUsage]
        raise RuntimeError("test transaction")
    transaction_repo.close()

    duplicate = SQLiteNetworkAuthorizationRepository(tmp_path / "duplicate.sqlite3")
    duplicate._connection.execute(  # pyright: ignore[reportPrivateUsage]
        "DROP TABLE network_authorization_grants"
    )
    duplicate._connection.execute(  # pyright: ignore[reportPrivateUsage]
        "CREATE TABLE network_authorization_grants "
        "(authorization_id TEXT, network_id TEXT, node_id TEXT, payload TEXT)"
    )
    payload = grant.model_dump_json()
    duplicate._connection.executemany(  # pyright: ignore[reportPrivateUsage]
        "INSERT INTO network_authorization_grants VALUES (?, ?, ?, ?)",
        [
            (str(grant.authorization_id), str(NETWORK_ID), str(NODE_A), payload),
            (str(grant.authorization_id), str(NETWORK_ID), str(NODE_A), payload),
        ],
    )
    duplicate._connection.commit()  # pyright: ignore[reportPrivateUsage]
    # 用 monkeypatch 保留冲突表的测试目的，绕过正常表结构的主键门禁。
    monkeypatch.setattr(duplicate, "_validate_schema", lambda: None)
    with pytest.raises(NetworkAuthorizationConflictError, match="重复"):
        duplicate.list_grants(NETWORK_ID, NODE_A)
    with pytest.raises(NetworkAuthorizationConflictError, match="冲突记录"):
        duplicate.approve(grant, capability=duplicate.authorization_capability())
    with pytest.raises(NetworkAuthorizationConflictError, match="冲突记录"):
        duplicate.revoke(
            grant.authorization_id,
            revoked_at=NOW,
            capability=duplicate.authorization_capability(),
        )
    duplicate.close()

    compare_and_swap = SQLiteNetworkAuthorizationRepository(":memory:")
    compare_and_swap.approve(grant, capability=compare_and_swap.authorization_capability())
    original_safe_payload = (  # pyright: ignore[reportPrivateUsage]
        SQLiteNetworkAuthorizationRepository._safe_payload  # pyright: ignore[reportPrivateUsage]
    )

    def mutate_before_update(value: NetworkAuthorizationGrant) -> str:
        compare_and_swap._connection.execute(  # pyright: ignore[reportPrivateUsage]
            "UPDATE network_authorization_grants SET payload = payload || ' ' "
            "WHERE authorization_id = ?",
            (str(value.authorization_id),),
        )
        return original_safe_payload(value)

    monkeypatch.setattr(
        SQLiteNetworkAuthorizationRepository,
        "_safe_payload",
        staticmethod(mutate_before_update),
    )
    with pytest.raises(NetworkAuthorizationConflictError, match="并发冲突"):
        compare_and_swap.revoke(
            grant.authorization_id,
            revoked_at=NOW + timedelta(seconds=1),
            capability=compare_and_swap.authorization_capability(),
        )
    compare_and_swap.close()
