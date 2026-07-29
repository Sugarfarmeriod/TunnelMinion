"""L3 网络授权、治理执行、回滚、恢复和脱敏状态测试。"""

from __future__ import annotations

import asyncio
import sqlite3
from collections.abc import Callable
from datetime import timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError
from tests.agent.test_network_sync import NOW, signed
from tests.network.factories import (
    NETWORK_ID,
    NODE_A,
    NODE_B,
    observation,
    ownership,
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
    ManagedNetworkGovernanceWorkflow,
    NetworkAuthorizationGrant,
    NetworkAuthorizationScope,
    NetworkGovernancePhase,
    NetworkGovernanceRecord,
    NetworkOperationPolicy,
    NetworkPathStatus,
    NetworkPolicyAction,
    SQLiteNetworkGovernanceStore,
    redacted_path_status_payload,
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
) -> tuple[
    ManagedNetworkGovernanceWorkflow,
    NetworkOperationPolicy,
    SQLiteNetworkGovernanceStore,
    MemoryAcknowledgements,
]:
    policy = NetworkOperationPolicy()
    store = SQLiteNetworkGovernanceStore(tmp_path / "governance.sqlite3")
    acknowledgements = MemoryAcknowledgements()
    return (
        ManagedNetworkGovernanceWorkflow(
            provider,
            policy,
            store,
            acknowledgements,
            clock=lambda: NOW,
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
    with pytest.raises(PermissionError, match="本地控制面"):
        policy.approve(grant, local_control=False)
    policy.approve(grant, local_control=True)

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
        AcknowledgementStage.APPLYING,
        AcknowledgementStage.APPLIED,
        AcknowledgementStage.VERIFIED,
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
    policy.approve(grant_for(awaiting), local_control=True)
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
    policy.approve(grant, local_control=True)
    assert policy.evaluate(awaiting.plan, at=NOW).action is NetworkPolicyAction.EXECUTE

    expanded = awaiting.plan.model_copy(update={"plan_hash": f"sha256:{'f' * 64}"})
    assert policy.evaluate(expanded, at=NOW).action is NetworkPolicyAction.AWAIT_AUTHORIZATION
    with pytest.raises(PermissionError, match="本地控制面"):
        policy.revoke(
            grant.authorization_id,
            revoked_at=NOW,
            local_control=False,
        )
    policy.revoke(grant.authorization_id, revoked_at=NOW, local_control=True)
    assert policy.evaluate(awaiting.plan, at=NOW).action is NetworkPolicyAction.AWAIT_AUTHORIZATION

    expired = grant_for(awaiting, expires_in=timedelta(seconds=1))
    policy.approve(expired, local_control=True)
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
    policy.approve(grant_for(awaiting), local_control=True)
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
    governance, policy, store, _ = workflow(tmp_path / "loss", provider)
    awaiting = await governance.reconcile(
        envelope,
        action=NetworkAction.CREATE,
        ownership=None,
    )
    policy.approve(grant_for(awaiting), local_control=True)
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
    assert recovered_retry.phase is NetworkGovernancePhase.VERIFIED
    assert provider.apply_calls == 2
    assert store.list_recoverable() == ()

    crashing = InMemoryNetworkProvider(
        observation(),
        behavior=FakeProviderBehavior.CRASH_AFTER_STEP,
    )
    crash_flow, crash_policy, crash_store, _ = workflow(tmp_path / "crash", crashing)
    crash_awaiting = await crash_flow.reconcile(
        envelope,
        action=NetworkAction.CREATE,
        ownership=None,
    )
    crash_policy.approve(grant_for(crash_awaiting), local_control=True)
    with pytest.raises(RuntimeError, match="provider crash"):
        await crash_flow.reconcile(
            envelope,
            action=NetworkAction.CREATE,
            ownership=None,
        )
    recovered = await crash_flow.recover_without_model()
    assert recovered[0].status is ReceiptStatus.ROLLED_BACK
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
    cancelled_policy.approve(grant_for(cancelled_awaiting), local_control=True)
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
    empty_flow, _, empty_store, _ = workflow(tmp_path / "empty-recovery", empty_provider)
    empty_awaiting = await empty_flow.reconcile(
        envelope,
        action=NetworkAction.CREATE,
        ownership=None,
    )
    empty_store.put(empty_awaiting.model_copy(update={"phase": NetworkGovernancePhase.APPLYING}))
    assert await empty_flow.recover_without_model() == ()
    unchanged = empty_store.get(NETWORK_ID, NODE_A, 1)
    assert unchanged is not None and unchanged.phase is NetworkGovernancePhase.APPLYING


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
    policy.approve(grant_for(awaiting), local_control=True)
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
    policy.approve(grant_for(awaiting), local_control=True)
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
    with pytest.raises(RuntimeError, match="apply 已在运行"):
        await governance.reconcile(envelope, action=NetworkAction.CREATE, ownership=None)
    gate.set()
    await first

    managed = observation(ownership_state=OwnershipState.MANAGED_OWNED)
    owned = ownership(managed)
    emergency_provider = InMemoryNetworkProvider(managed)
    emergency, _, _, _ = workflow(tmp_path / "emergency", emergency_provider)
    with pytest.raises(PermissionError, match="本地控制面"):
        await emergency.emergency_stop(envelope, owned, local_control=False)
    mismatched = owned.model_copy(update={"system_fingerprint": f"sha256:{'0' * 64}"})
    with pytest.raises(RuntimeError, match="不匹配"):
        await emergency.emergency_stop(envelope, mismatched, local_control=True)
    stopped = await emergency.emergency_stop(envelope, owned, local_control=True)
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

    naive = ManagedNetworkGovernanceWorkflow(
        provider,
        NetworkOperationPolicy(),
        SQLiteNetworkGovernanceStore(tmp_path / "naive.sqlite3"),
        MemoryAcknowledgements(),
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
