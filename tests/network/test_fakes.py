"""内存 NetworkProvider 的成功、故障、取消与恢复测试。"""

from __future__ import annotations

import pytest
from tests.network.factories import NETWORK_ID, NODE_A, desired, observation, ownership

from tunnelminion.network.contracts import (
    NetworkAction,
    NetworkErrorCode,
    OwnershipState,
    ProviderMode,
    ReceiptStatus,
    canonical_sha256,
)
from tunnelminion.network.fakes import FakeProviderBehavior, InMemoryNetworkProvider
from tunnelminion.tools.contracts import ToolCancellationToken

KEY = f"netop_{'a' * 64}"


async def _create_plan(provider: InMemoryNetworkProvider):
    observed = await provider.observe("tmn-test-a")
    return await provider.plan(
        action=NetworkAction.CREATE,
        desired=desired(),
        observed=observed,
        ownership=None,
    )


@pytest.mark.anyio
async def test_fake_provider_plans_and_applies_idempotent_create() -> None:
    provider = InMemoryNetworkProvider(observation())
    identity = provider.ensure_local_identity(NETWORK_ID, NODE_A)
    assert identity.public_key == "A" * 43 + "="
    assert identity.secret_reference.startswith("fake:")
    plan = await _create_plan(provider)
    token = ToolCancellationToken()

    receipt = await provider.apply(plan, idempotency_key=KEY, cancellation=token)
    repeated = await provider.apply(plan, idempotency_key=KEY, cancellation=token)
    verified = await provider.verify(plan)

    assert receipt.status is ReceiptStatus.APPLIED
    assert repeated == receipt
    assert provider.apply_calls == 2
    assert len(receipt.steps) == 5
    assert verified.succeeded
    assert verified.error is None
    assert provider.verify_calls == 1


@pytest.mark.anyio
async def test_fake_provider_rejects_wrong_interface_and_provider() -> None:
    provider = InMemoryNetworkProvider(observation())
    with pytest.raises(ValueError, match="fixture 接口"):
        await provider.observe("other")
    observed = await provider.observe("tmn-test-a")
    with pytest.raises(ValueError, match="观察 Provider"):
        await provider.plan(
            action=NetworkAction.CREATE,
            desired=desired(provider="macos"),
            observed=observed,
            ownership=None,
        )
    with pytest.raises(ValueError, match="观察接口"):
        await provider.plan(
            action=NetworkAction.CREATE,
            desired=desired(interface_name="tmn-other"),
            observed=observed,
            ownership=None,
        )


@pytest.mark.anyio
async def test_fake_provider_enforces_create_and_managed_ownership() -> None:
    managed = observation(ownership_state=OwnershipState.MANAGED_OWNED)
    provider = InMemoryNetworkProvider(managed)
    owned = ownership(managed)

    with pytest.raises(ValueError, match="接口不存在"):
        await provider.plan(
            action=NetworkAction.CREATE,
            desired=desired(),
            observed=managed,
            ownership=None,
        )
    with pytest.raises(ValueError, match="受管所有权"):
        await provider.plan(
            action=NetworkAction.UPDATE,
            desired=desired(revision=2, parent_revision=1),
            observed=managed.model_copy(update={"ownership": OwnershipState.OBSERVED_USER}),
            ownership=owned,
        )
    with pytest.raises(ValueError, match="实时系统指纹"):
        await provider.plan(
            action=NetworkAction.UPDATE,
            desired=desired(revision=2, parent_revision=1),
            observed=managed,
            ownership=owned.model_copy(
                update={"system_fingerprint": canonical_sha256({"other": True})}
            ),
        )

    for action, count in (
        (NetworkAction.UPDATE, 4),
        (NetworkAction.STOP, 1),
        (NetworkAction.REMOVE, 4),
    ):
        plan = await provider.plan(
            action=action,
            desired=desired(revision=2, parent_revision=1),
            observed=managed,
            ownership=owned,
        )
        assert len(plan.steps) == count


@pytest.mark.anyio
@pytest.mark.parametrize("action", [NetworkAction.STOP, NetworkAction.REMOVE])
async def test_fake_provider_normal_stop_and_remove_reach_absent_state(
    action: NetworkAction,
) -> None:
    managed = observation(ownership_state=OwnershipState.MANAGED_OWNED)
    provider = InMemoryNetworkProvider(managed)
    plan = await provider.plan(
        action=action,
        desired=desired(revision=2, parent_revision=1),
        observed=managed,
        ownership=ownership(managed),
    )

    receipt = await provider.apply(
        plan,
        idempotency_key=KEY,
        cancellation=ToolCancellationToken(),
    )
    verification = await provider.verify(plan)

    assert receipt.status is ReceiptStatus.APPLIED
    assert receipt.observation_after is not None
    assert receipt.observation_after.ownership is OwnershipState.ABSENT
    assert verification.succeeded
    assert verification.observation.ownership is OwnershipState.ABSENT


@pytest.mark.anyio
async def test_create_plan_rejects_address_route_and_name_conflicts() -> None:
    provider = InMemoryNetworkProvider(observation())
    with pytest.raises(ValueError, match="现有地址冲突"):
        await provider.plan(
            action=NetworkAction.CREATE,
            desired=desired(),
            observed=observation(addresses=("10.203.0.1/32",)),
            ownership=None,
        )
    with pytest.raises(ValueError, match="route 重叠"):
        await provider.plan(
            action=NetworkAction.CREATE,
            desired=desired(),
            observed=observation(host_routes=("10.128.0.0/9",)),
            ownership=None,
        )
    with pytest.raises(ValueError, match="接口不存在"):
        await provider.plan(
            action=NetworkAction.CREATE,
            desired=desired(),
            observed=observation(ownership_state=OwnershipState.OWNERSHIP_UNKNOWN),
            ownership=None,
        )


@pytest.mark.anyio
async def test_apply_cancellation_observe_only_and_runtime_ownership_fail_closed() -> None:
    provider = InMemoryNetworkProvider(observation())
    plan = await _create_plan(provider)
    cancelled = ToolCancellationToken()
    cancelled.cancel()
    receipt = await provider.apply(plan, idempotency_key=KEY, cancellation=cancelled)
    assert receipt.status is ReceiptStatus.CANCELLED
    assert receipt.error is not None
    assert receipt.error.code is NetworkErrorCode.CANCELLED

    readonly = InMemoryNetworkProvider(observation(mode=ProviderMode.OBSERVE_ONLY))
    readonly_plan = await _create_plan(readonly)
    failed = await readonly.apply(
        readonly_plan,
        idempotency_key=f"netop_{'b' * 64}",
        cancellation=ToolCancellationToken(),
    )
    assert failed.error is not None
    assert failed.error.code is NetworkErrorCode.PROVIDER_UNAVAILABLE

    conflicted = InMemoryNetworkProvider(
        observation(ownership_state=OwnershipState.OWNERSHIP_CONFLICT)
    )
    conflicted_plan = await conflicted.plan(
        action=NetworkAction.CREATE,
        desired=desired(),
        observed=observation(),
        ownership=None,
    )
    blocked = await conflicted.apply(
        conflicted_plan,
        idempotency_key=f"netop_{'c' * 64}",
        cancellation=ToolCancellationToken(),
    )
    assert blocked.error is not None
    assert blocked.error.code is NetworkErrorCode.OWNERSHIP_CONFLICT


@pytest.mark.anyio
async def test_response_loss_retries_to_original_receipt() -> None:
    provider = InMemoryNetworkProvider(observation(), behavior=FakeProviderBehavior.RESPONSE_LOST)
    plan = await _create_plan(provider)
    with pytest.raises(TimeoutError, match="response loss"):
        await provider.apply(plan, idempotency_key=KEY, cancellation=ToolCancellationToken())

    receipt = await provider.apply(plan, idempotency_key=KEY, cancellation=ToolCancellationToken())
    assert receipt.status is ReceiptStatus.APPLIED
    assert len(receipt.steps) == len(plan.steps)


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("behavior", "raises"),
    [
        (FakeProviderBehavior.STEP_FAILURE, False),
        (FakeProviderBehavior.CRASH_AFTER_STEP, True),
    ],
)
async def test_step_failure_and_crash_preserve_partial_receipt(
    behavior: FakeProviderBehavior, raises: bool
) -> None:
    provider = InMemoryNetworkProvider(observation(), behavior=behavior)
    plan = await _create_plan(provider)
    if raises:
        with pytest.raises(RuntimeError, match="provider crash"):
            await provider.apply(plan, idempotency_key=KEY, cancellation=ToolCancellationToken())
    else:
        failed = await provider.apply(
            plan, idempotency_key=KEY, cancellation=ToolCancellationToken()
        )
        assert failed.status is ReceiptStatus.FAILED
        assert len(failed.steps) == 1

    provider.behavior = FakeProviderBehavior.SUCCESS
    recovered = await provider.recover(cancellation=ToolCancellationToken())
    assert len(recovered) == 1
    assert recovered[0].status is ReceiptStatus.ROLLED_BACK


@pytest.mark.anyio
async def test_verify_failure_and_unapplied_state_are_explicit() -> None:
    provider = InMemoryNetworkProvider(observation(), behavior=FakeProviderBehavior.VERIFY_FAILURE)
    plan = await _create_plan(provider)
    await provider.apply(plan, idempotency_key=KEY, cancellation=ToolCancellationToken())
    failed = await provider.verify(plan)
    assert not failed.succeeded
    assert failed.error is not None
    assert failed.error.code is NetworkErrorCode.VERIFY_FAILED

    fresh = InMemoryNetworkProvider(observation())
    fresh_plan = await _create_plan(fresh)
    mismatch = await fresh.verify(fresh_plan)
    assert not mismatch.succeeded
    assert mismatch.error is not None


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("behavior", "status", "code"),
    [
        (
            FakeProviderBehavior.ROLLBACK_FAILURE,
            ReceiptStatus.FAILED,
            NetworkErrorCode.ROLLBACK_FAILED,
        ),
        (
            FakeProviderBehavior.OWNERSHIP_REPLACED,
            ReceiptStatus.MANUAL_INTERVENTION,
            NetworkErrorCode.OWNERSHIP_CONFLICT,
        ),
    ],
)
async def test_rollback_failure_and_ownership_replacement_stop_safely(
    behavior: FakeProviderBehavior,
    status: ReceiptStatus,
    code: NetworkErrorCode,
) -> None:
    provider = InMemoryNetworkProvider(observation())
    plan = await _create_plan(provider)
    receipt = await provider.apply(plan, idempotency_key=KEY, cancellation=ToolCancellationToken())
    provider.behavior = behavior
    result = await provider.rollback(plan, receipt, cancellation=ToolCancellationToken())
    assert result.status is status
    assert result.error is not None
    assert result.error.code is code


@pytest.mark.anyio
async def test_rollback_cancel_success_and_empty_recovery() -> None:
    provider = InMemoryNetworkProvider(observation())
    plan = await _create_plan(provider)
    receipt = await provider.apply(plan, idempotency_key=KEY, cancellation=ToolCancellationToken())
    token = ToolCancellationToken()
    token.cancel()
    cancelled = await provider.rollback(plan, receipt, cancellation=token)
    assert cancelled.status is ReceiptStatus.CANCELLED

    rolled_back = await provider.rollback(plan, receipt, cancellation=ToolCancellationToken())
    assert rolled_back.status is ReceiptStatus.ROLLED_BACK
    assert rolled_back.observation_after is not None
    assert rolled_back.observation_after.ownership is OwnershipState.ABSENT
    assert provider.rollback_calls == 2
    assert await provider.recover(cancellation=ToolCancellationToken()) == ()
