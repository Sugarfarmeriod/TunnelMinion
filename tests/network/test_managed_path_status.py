"""阶段四路径状态、TTL、刷新合并与脱敏 sink 验收。"""

from __future__ import annotations

import asyncio
import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest
from pydantic import ValidationError
from tests.agent.test_network_sync import NOW, signed
from tests.network.control_harness import (
    NetworkOperationPolicy,
    SQLiteNetworkAuthorizationRepository,
)
from tests.network.factories import NETWORK_ID, NODE_A
from tests.network.test_managed_path_lifecycle import (
    FakePathController,
    FakePathVerifier,
    build,
    create_recovery_ledger,
    grant_for,
    path_evidence,
)

from tunnelminion.domain.identifiers import AuthorizationId, NetworkId, NodeId
from tunnelminion.network.contracts import (
    NetworkAction,
    NetworkPlan,
    ProviderKind,
    SignedDesiredConfig,
    canonical_sha256,
)
from tunnelminion.network.governance import (
    ManagedNetworkGovernanceWorkflow,
    ManagedPathLifecycle,
    ManagedPathLifecycleError,
    ManagedPathStatus,
    NetworkAuthorizationConflictError,
    NetworkGovernancePhase,
    NetworkGovernanceRecord,
    SQLiteNetworkGovernanceStore,
    redacted_managed_path_status_payload,
)
from tunnelminion.network.path_controller import (
    DirectPathController,
    DirectPathErrorCode,
    DirectPathEvidence,
    NetworkPathType,
    PathControllerPolicy,
    PathSelection,
)
from tunnelminion.network.path_status import (
    MANAGED_PATH_REFRESH_MIN_INTERVAL,
    ManagedPathAuthorizationState,
    ManagedPathFreshness,
    restore_managed_path_status_payload,
    source_category,
)
from tunnelminion.tools.contracts import ToolCancellationToken


class MutableClock:
    """只推进 fake 时间，不读取系统网络或系统时钟。"""

    def __init__(self, value: datetime = NOW) -> None:
        self.value = value

    def __call__(self) -> datetime:
        return self.value


class RecordingManagedPathSink:
    """记录严格脱敏 status，并可独立注入 sink 失败。"""

    def __init__(self) -> None:
        self.items: list[tuple[ManagedPathStatus, str]] = []
        self.fail = False

    async def publish(self, status: ManagedPathStatus, *, idempotency_key: str) -> None:
        if self.fail:
            raise ConnectionError("fake managed path sink offline")
        self.items.append((status, idempotency_key))


class GatedPathVerifier(FakePathVerifier):
    """让只读 probe 跨 await，以验证取消不会取消共享刷新。"""

    def __init__(self, result: DirectPathEvidence) -> None:
        super().__init__(result)
        self.block = False
        self.started = asyncio.Event()
        self.release = asyncio.Event()

    async def verify(self, plan: NetworkPlan, *, now: datetime) -> DirectPathEvidence:
        if self.block:
            self.started.set()
            await self.release.wait()
        return await super().verify(plan, now=now)


class CancelOncePathVerifier(FakePathVerifier):
    """仅取消下一次 probe，便于验证恢复预算而不改变 apply 结果。"""

    def __init__(self, result: DirectPathEvidence) -> None:
        super().__init__(result)
        self.cancel_next = False

    async def verify(self, plan: NetworkPlan, *, now: datetime) -> DirectPathEvidence:
        if self.cancel_next:
            self.cancel_next = False
            self.calls += 1
            raise asyncio.CancelledError
        return await super().verify(plan, now=now)


class RestoreFailingController(FakePathController):
    """在 fake 重启时拒绝恢复 checkpoint 的 controller。"""

    def restore(self, selection: PathSelection) -> None:
        raise RuntimeError("fake controller restore failure")


def _status_without_evidence(**updates: object) -> ManagedPathStatus:
    values: dict[str, object] = {
        "network_id": NETWORK_ID,
        "node_id": NODE_A,
        "revision": 1,
        "plan_hash": f"sha256:{'a' * 64}",
        "authorization_revision": 1,
        "provider": ProviderKind.WINDOWS,
        "authorization_state": ManagedPathAuthorizationState.UNKNOWN,
        "authorization_id": None,
        "path_type": NetworkPathType.STATIC,
        "selection": None,
        "evidence": None,
        "source": "none",
        "freshness": ManagedPathFreshness.UNVERIFIED,
        "candidate_count": 0,
        "last_known_good_revision": None,
        "observed_at": None,
        "refreshed_at": None,
        "expires_at": None,
        "stable_error_code": None,
        "journal_sequence": 0,
        "updated_at": NOW,
    }
    values.update(updates)
    return ManagedPathStatus.model_validate(values)


def _status_from_evidence(
    base_evidence: DirectPathEvidence,
    **updates: object,
) -> ManagedPathStatus:
    values: dict[str, object] = {
        "network_id": base_evidence.network_id,
        "node_id": base_evidence.node_id,
        "revision": base_evidence.revision,
        "plan_hash": base_evidence.plan_hash,
        "authorization_revision": base_evidence.authorization_revision,
        "provider": base_evidence.provider,
        "authorization_state": ManagedPathAuthorizationState.AUTHORIZED,
        "authorization_id": AuthorizationId.new(),
        "path_type": NetworkPathType.STATIC,
        "selection": None,
        "evidence": base_evidence,
        "source": source_category(base_evidence.source),
        "freshness": (
            ManagedPathFreshness.FRESH
            if base_evidence.verified
            else ManagedPathFreshness.UNVERIFIED
        ),
        "candidate_count": base_evidence.candidate_count,
        "last_known_good_revision": 1 if base_evidence.verified else None,
        "observed_at": base_evidence.observed_at,
        "refreshed_at": base_evidence.observed_at,
        "expires_at": base_evidence.expires_at,
        "stable_error_code": None,
        "journal_sequence": 0,
        "updated_at": base_evidence.observed_at,
    }
    values.update(updates)
    return ManagedPathStatus.model_validate(values)


def _direct_selection(
    evidence: DirectPathEvidence,
    **updates: object,
) -> PathSelection:
    values: dict[str, object] = {
        "network_id": evidence.network_id,
        "node_id": evidence.node_id,
        "plan_hash": evidence.plan_hash,
        "authorization_revision": evidence.authorization_revision,
        "path_type": NetworkPathType.DIRECT,
        "provider": evidence.provider,
        "revision": evidence.revision,
        "last_known_good_revision": evidence.revision,
        "candidate_count": evidence.candidate_count,
        "consecutive_failures": 0,
        "consecutive_successes": 2,
        "selected_at": evidence.observed_at,
        "last_evidence_at": evidence.observed_at,
        "stable_error_code": None,
        "target_host_hash": evidence.target_host_hash,
        "target_port": evidence.target_port,
        "route_identity_hash": evidence.route_identity_hash,
        "expires_at": evidence.expires_at,
    }
    values.update(updates)
    return PathSelection.model_validate(values)


def _static_selection(**updates: object) -> PathSelection:
    values: dict[str, object] = {
        "network_id": None,
        "node_id": None,
        "plan_hash": None,
        "authorization_revision": None,
        "path_type": NetworkPathType.STATIC,
        "provider": ProviderKind.WINDOWS,
        "revision": 1,
        "last_known_good_revision": None,
        "candidate_count": 0,
        "consecutive_failures": 0,
        "consecutive_successes": 0,
        "selected_at": NOW,
        "last_evidence_at": NOW,
        "stable_error_code": None,
        "target_host_hash": None,
        "target_port": None,
        "route_identity_hash": None,
        "expires_at": None,
    }
    values.update(updates)
    return PathSelection.model_validate(values)


def _rewrite_status_row(database: Path, status: ManagedPathStatus) -> None:
    payload = status.model_dump_json()
    connection = sqlite3.connect(database)
    connection.execute(
        "UPDATE network_path_status SET payload=?, status_hash=?, journal_sequence=? "
        "WHERE network_id=? AND node_id=? AND revision=?",
        (
            payload,
            canonical_sha256(status.model_dump(mode="json")),
            status.journal_sequence,
            str(status.network_id),
            str(status.node_id),
            status.revision,
        ),
    )
    connection.commit()
    connection.close()


def _v1_status_payload(status: ManagedPathStatus) -> tuple[str, str]:
    values = status.model_dump(mode="json")
    values["schema_version"] = 1
    values.pop("last_refresh_attempt_at")
    payload = json.dumps(values, separators=(",", ":"), sort_keys=True)
    return payload, canonical_sha256(values)


def _insert_raw_status(store: SQLiteNetworkGovernanceStore, payload: str, status_hash: str) -> None:
    store._connection.execute(  # type: ignore[reportPrivateUsage]
        "INSERT INTO network_path_status(network_id, node_id, revision, payload, "
        "status_hash, journal_sequence) VALUES (?, ?, ?, ?, ?, ?)",
        (str(NETWORK_ID), str(NODE_A), 1, payload, status_hash, 0),
    )


def real_controller() -> DirectPathController:
    """构造生产 controller，保留两次成功和 minimum dwell 语义。"""
    initial = PathSelection(
        path_type=NetworkPathType.STATIC,
        provider=ProviderKind.WINDOWS,
        revision=1,
        candidate_count=0,
        consecutive_failures=0,
        consecutive_successes=0,
        selected_at=NOW,
        last_evidence_at=NOW,
    )
    return DirectPathController(
        PathControllerPolicy(
            consecutive_success_threshold=2,
            consecutive_failure_threshold=3,
            minimum_dwell_seconds=0,
        ),
        initial=initial,
    )


async def authorized_lifecycle(
    lifecycle: ManagedPathLifecycle,
    policy: NetworkOperationPolicy,
    *,
    action: NetworkAction = NetworkAction.CREATE,
) -> tuple[SignedDesiredConfig, NetworkGovernanceRecord, NetworkGovernanceRecord]:
    """只通过 fake 本机控制面授权，返回 envelope、首轮和第二轮结果。"""
    envelope, _ = signed()
    pending = await lifecycle.reconcile(envelope, action=action, ownership=None)
    policy.approve(grant_for(pending), capability=policy.local_control_capability())
    first = await lifecycle.reconcile(envelope, action=action, ownership=None)
    second = await lifecycle.reconcile(envelope, action=action, ownership=None)
    return envelope, first, second


@pytest.mark.anyio
async def test_persisted_real_controller_state_projects_stale_and_restores(
    tmp_path: Path,
) -> None:
    clock = MutableClock()
    probe = FakePathVerifier(path_evidence())
    sink = RecordingManagedPathSink()
    lifecycle, policy, provider, _, _, _, _, store = build(
        tmp_path,
        verifier=probe,
        path_controller=real_controller(),
        managed_status_sink=sink,
        clock=clock,
    )
    envelope, first, direct = await authorized_lifecycle(lifecycle, policy)

    assert first.path_selection is not None
    assert first.path_selection.path_type is NetworkPathType.STATIC
    assert direct.path_selection is not None
    assert direct.path_selection.path_type is NetworkPathType.DIRECT
    assert provider.apply_calls == 1
    current = lifecycle.get_path_status(
        direct.plan.desired.network_id, direct.plan.desired.target_node_id, 1
    )
    assert current is not None
    assert current.freshness.value == "fresh"
    assert current.currently_usable
    assert current.last_known_good_revision == 1
    assert sink.items
    assert sink.items[-1][0].freshness.value == "fresh"
    assert sink.items[-1][0].plan_hash == current.plan_hash
    store.assert_no_secret_material()

    clock.value = NOW + timedelta(seconds=181)
    stale = lifecycle.get_path_status(
        direct.plan.desired.network_id, direct.plan.desired.target_node_id, 1
    )
    assert stale is not None
    assert stale.freshness.value == "stale"
    assert not stale.currently_usable
    assert stale.last_known_good_revision == 1
    assert stale.expires_at == current.expires_at

    restarted_controller = real_controller()
    restarted, restarted_policy, restarted_provider, _, _, _, _, _ = build(
        tmp_path,
        verifier=probe,
        path_controller=restarted_controller,
        provider_override=provider,
        clock=clock,
    )
    restored = await restarted.reconcile(envelope, action=NetworkAction.CREATE, ownership=None)
    assert restored.phase is NetworkGovernancePhase.VERIFIED
    assert restarted_controller.selection.path_type is NetworkPathType.DIRECT
    assert restarted_provider.apply_calls == 1
    assert restarted_policy is not policy


@pytest.mark.anyio
async def test_stale_readonly_refresh_recovers_fresh_without_provider_apply_and_rate_replays(
    tmp_path: Path,
) -> None:
    clock = MutableClock()
    probe = FakePathVerifier(path_evidence())
    lifecycle, policy, provider, _, _, _, _, _ = build(
        tmp_path,
        verifier=probe,
        path_controller=real_controller(),
        clock=clock,
    )
    _, _, direct = await authorized_lifecycle(lifecycle, policy)
    before_apply = provider.apply_calls
    clock.value = NOW + timedelta(seconds=181)
    stale = lifecycle.get_path_status(
        direct.plan.desired.network_id, direct.plan.desired.target_node_id, 1
    )
    assert stale is not None and stale.freshness.value == "stale"

    refreshed = await lifecycle.refresh_path(
        direct.plan.desired.network_id,
        direct.plan.desired.target_node_id,
        1,
    )
    assert refreshed is not None
    assert refreshed.freshness.value == "fresh"
    assert refreshed.path_type is NetworkPathType.DIRECT
    assert refreshed.currently_usable
    assert refreshed.expires_at == clock.value + timedelta(seconds=180)
    assert provider.apply_calls == before_apply == 1
    calls = probe.calls

    clock.value += timedelta(seconds=10)
    limited = await lifecycle.refresh_path(
        direct.plan.desired.network_id,
        direct.plan.desired.target_node_id,
        1,
    )
    assert limited is not None
    assert limited.stable_error_code == "path_refresh_rate_limited"
    assert limited.expires_at == refreshed.expires_at
    assert probe.calls == calls
    assert provider.apply_calls == before_apply


@pytest.mark.anyio
async def test_failed_refresh_consumes_persisted_attempt_budget_without_provider_apply(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = MutableClock()
    probe = FakePathVerifier(path_evidence())
    lifecycle, policy, provider, _, _, _, _, store = build(
        tmp_path,
        verifier=probe,
        path_controller=real_controller(),
        clock=clock,
    )
    _, _, direct = await authorized_lifecycle(lifecycle, policy)
    assert not lifecycle._managed_path_status_pending(direct)  # type: ignore[reportPrivateUsage]
    stored_record = store.get(NETWORK_ID, NODE_A, 1)
    assert stored_record is not None and stored_record.verification is not None
    failed_verification = stored_record.verification.model_copy(update={"succeeded": False})
    blocked_record = stored_record.model_copy(update={"verification": failed_verification})

    def get_blocked_record(*_args: object) -> NetworkGovernanceRecord:
        return blocked_record

    monkeypatch.setattr(store, "get", get_blocked_record)
    blocked = await lifecycle._refresh_path_once(  # type: ignore[reportPrivateUsage]
        NETWORK_ID,
        NODE_A,
        1,
        ToolCancellationToken(),
    )
    assert blocked is not None
    monkeypatch.undo()
    before_probe = probe.calls
    clock.value = NOW + timedelta(seconds=181)
    probe.error = TimeoutError("fake target timeout")

    failed = await lifecycle.refresh_path(NETWORK_ID, NODE_A, 1)
    assert failed is not None
    assert failed.stable_error_code == "timeout"
    assert failed.last_refresh_attempt_at == clock.value
    assert probe.calls == before_probe + 1
    assert provider.apply_calls == 1
    persisted = lifecycle.get_path_status(NETWORK_ID, NODE_A, 1)
    assert persisted is not None
    assert persisted.last_refresh_attempt_at == clock.value

    limited = await lifecycle.refresh_path(NETWORK_ID, NODE_A, 1)
    assert limited is not None
    assert limited.stable_error_code == "path_refresh_rate_limited"
    assert limited.last_refresh_attempt_at == clock.value
    assert probe.calls == before_probe + 1
    assert provider.apply_calls == 1
    direct_limited = await lifecycle._refresh_path_once(  # type: ignore[reportPrivateUsage]
        NETWORK_ID,
        NODE_A,
        1,
        ToolCancellationToken(),
    )
    assert direct_limited is not None
    assert direct_limited.stable_error_code == "path_refresh_rate_limited"

    restarted, _, _, _, _, _, _, _ = build(
        tmp_path,
        verifier=probe,
        path_controller=real_controller(),
        provider_override=provider,
        clock=clock,
    )
    restarted_status = restarted.get_path_status(NETWORK_ID, NODE_A, 1)
    assert restarted_status is not None
    assert restarted_status.last_refresh_attempt_at == clock.value
    restarted_limited = await restarted.refresh_path(NETWORK_ID, NODE_A, 1)
    assert restarted_limited is not None
    assert restarted_limited.stable_error_code == "path_refresh_rate_limited"
    assert probe.calls == before_probe + 1
    assert provider.apply_calls == 1

    clock.value += MANAGED_PATH_REFRESH_MIN_INTERVAL
    retried = await restarted.refresh_path(NETWORK_ID, NODE_A, 1)
    assert retried is not None
    assert retried.stable_error_code == "timeout"
    assert retried.last_refresh_attempt_at == clock.value
    assert probe.calls == before_probe + 2
    assert provider.apply_calls == 1
    assert direct.plan.plan_hash == retried.plan_hash


@pytest.mark.anyio
async def test_refresh_single_flight_survives_caller_cancellation(tmp_path: Path) -> None:
    clock = MutableClock()
    base = path_evidence()
    assert base is not None
    probe = GatedPathVerifier(base)
    lifecycle, policy, provider, _, _, _, _, _ = build(
        tmp_path,
        verifier=probe,
        clock=clock,
    )
    _, _, direct = await authorized_lifecycle(lifecycle, policy)
    clock.value = NOW + timedelta(seconds=181)
    probe.block = True
    first = asyncio.create_task(
        lifecycle.refresh_path(
            direct.plan.desired.network_id, direct.plan.desired.target_node_id, 1
        )
    )
    await probe.started.wait()
    first.cancel()
    with pytest.raises(asyncio.CancelledError):
        await first
    second = asyncio.create_task(
        lifecycle.refresh_path(
            direct.plan.desired.network_id, direct.plan.desired.target_node_id, 1
        )
    )
    probe.release.set()
    result = await second
    assert result is not None and result.freshness.value == "fresh"
    assert probe.calls == 2
    assert provider.apply_calls == 1


@pytest.mark.anyio
async def test_cancelled_refresh_recovery_obeys_persisted_budget_across_restart(
    tmp_path: Path,
) -> None:
    clock = MutableClock()
    probe = CancelOncePathVerifier(path_evidence())
    ledger = create_recovery_ledger()
    lifecycle, policy, provider, _, _, _, _, store = build(
        tmp_path,
        verifier=probe,
        path_controller=real_controller(),
        ledger=ledger,
        clock=clock,
    )
    envelope, _, direct = await authorized_lifecycle(lifecycle, policy)
    assert direct.phase is NetworkGovernancePhase.VERIFIED
    assert provider.apply_calls == 1

    clock.value = NOW + timedelta(seconds=181)
    probe.cancel_next = True
    with pytest.raises(asyncio.CancelledError):
        await lifecycle.refresh_path(
            direct.plan.desired.network_id,
            direct.plan.desired.target_node_id,
            direct.plan.desired.revision,
        )
    calls_after_cancel = probe.calls
    persisted = store.get_path_status(NETWORK_ID, NODE_A, 1)
    assert persisted is not None
    assert persisted.last_refresh_attempt_at == clock.value

    same_process = await lifecycle.reconcile(
        envelope,
        action=NetworkAction.CREATE,
        ownership=None,
    )
    assert same_process.phase is NetworkGovernancePhase.PATH_VERIFYING
    assert probe.calls == calls_after_cancel
    assert provider.apply_calls == 1

    restarted, _, restarted_provider, _, _, _, _, _ = build(
        tmp_path,
        verifier=probe,
        path_controller=real_controller(),
        ledger=ledger,
        provider_override=provider,
        clock=clock,
    )
    within_interval = await restarted.reconcile(
        envelope,
        action=NetworkAction.CREATE,
        ownership=None,
    )
    assert within_interval.phase is NetworkGovernancePhase.PATH_VERIFYING
    assert probe.calls == calls_after_cancel
    assert restarted_provider.apply_calls == 1

    clock.value += MANAGED_PATH_REFRESH_MIN_INTERVAL
    recovered = await restarted.reconcile(
        envelope,
        action=NetworkAction.CREATE,
        ownership=None,
    )
    assert recovered.phase is NetworkGovernancePhase.VERIFIED
    assert probe.calls == calls_after_cancel + 1
    assert restarted_provider.apply_calls == 1


@pytest.mark.anyio
async def test_failed_refresh_keeps_last_known_good_and_rich_sink_retry_clears_own_error(
    tmp_path: Path,
) -> None:
    clock = MutableClock()
    probe = FakePathVerifier(path_evidence())
    sink = RecordingManagedPathSink()
    sink.fail = True
    lifecycle, policy, provider, _, _, _, _, store = build(
        tmp_path,
        verifier=probe,
        managed_status_sink=sink,
        clock=clock,
    )
    envelope, _, direct = await authorized_lifecycle(lifecycle, policy)
    assert direct.phase is NetworkGovernancePhase.VERIFIED
    assert direct.stable_error_code == "managed_path_status_sink_failed"
    assert not direct.managed_path_status_delivered
    assert provider.apply_calls == 1
    assert store.get_path_status(
        direct.plan.desired.network_id, direct.plan.desired.target_node_id, 1
    )
    sink.fail = False
    retried = await lifecycle.reconcile(envelope, action=NetworkAction.CREATE, ownership=None)
    assert retried.managed_path_status_delivered
    assert retried.stable_error_code is None
    assert provider.apply_calls == 1
    assert len(sink.items) == 1
    assert sink.items[-1][0].stable_error_code is None
    assert sink.items[-1][0].freshness is ManagedPathFreshness.FRESH

    clock.value = NOW + timedelta(seconds=181)
    probe.error = TimeoutError("fake target timeout")
    failed = await lifecycle.refresh_path(
        direct.plan.desired.network_id,
        direct.plan.desired.target_node_id,
        1,
    )
    assert failed is not None
    assert failed.freshness.value == "stale"
    assert failed.last_known_good_revision == 1
    assert provider.apply_calls == 1
    payload = redacted_managed_path_status_payload(failed)
    encoded = json.dumps(payload, sort_keys=True).lower()
    assert '"endpoint"' not in encoded
    assert "private_key" not in encoded


@pytest.mark.anyio
async def test_reconcile_retries_non_direct_path_without_refresh_attempt(
    tmp_path: Path,
) -> None:
    initial = PathSelection(
        path_type=NetworkPathType.STATIC,
        provider=ProviderKind.WINDOWS,
        revision=1,
        candidate_count=0,
        consecutive_failures=0,
        consecutive_successes=0,
        selected_at=NOW,
        last_evidence_at=NOW,
    )
    path_controller = DirectPathController(
        PathControllerPolicy(
            consecutive_success_threshold=3,
            consecutive_failure_threshold=3,
            minimum_dwell_seconds=0,
        ),
        initial=initial,
    )
    lifecycle, policy, provider, _, _, probe, _, _ = build(
        tmp_path,
        path_controller=path_controller,
    )
    _, _, result = await authorized_lifecycle(lifecycle, policy)
    assert result.phase is NetworkGovernancePhase.VERIFIED
    assert result.path_selection is not None
    assert result.path_selection.path_type is NetworkPathType.STATIC
    assert result.last_refresh_attempt_at is None
    assert probe.calls == 2
    assert provider.apply_calls == 1


@pytest.mark.anyio
async def test_reconcile_enters_unbudgeted_path_retry_branch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lifecycle, policy, _, _, _, _, _, _ = build(tmp_path)
    envelope, _, result = await authorized_lifecycle(lifecycle, policy)
    stored = lifecycle._store.get(NETWORK_ID, NODE_A, 1)  # type: ignore[reportPrivateUsage]
    assert (
        stored is not None
        and stored.phase is NetworkGovernancePhase.VERIFIED
        and stored.last_refresh_attempt_at is None
    )
    calls: list[NetworkGovernanceRecord] = []

    async def fake_verify(record: NetworkGovernanceRecord) -> NetworkGovernanceRecord:
        await asyncio.sleep(0)
        calls.append(record)
        return record

    def always_retry(_: NetworkGovernanceRecord) -> bool:
        return True

    monkeypatch.setattr(lifecycle, "_needs_path_retry", always_retry)
    monkeypatch.setattr(lifecycle, "_verify_path", fake_verify)
    retried = await lifecycle.reconcile(
        envelope,
        action=NetworkAction.CREATE,
        ownership=None,
    )
    assert result.phase is NetworkGovernancePhase.VERIFIED
    assert calls == [result]
    assert retried == result


@pytest.mark.anyio
async def test_refresh_redelivers_new_managed_status_and_retries_independent_sink_failure(
    tmp_path: Path,
) -> None:
    clock = MutableClock()
    probe = FakePathVerifier(path_evidence())
    sink = RecordingManagedPathSink()
    lifecycle, policy, provider, _, _, _, _, _ = build(
        tmp_path,
        verifier=probe,
        path_controller=real_controller(),
        managed_status_sink=sink,
        clock=clock,
    )
    _, _, direct = await authorized_lifecycle(lifecycle, policy)
    assert sink.items
    assert not lifecycle._managed_path_status_pending(direct)  # type: ignore[reportPrivateUsage]
    pending_hash = direct.model_copy(
        update={"managed_path_status_delivery_hash": f"sha256:{'0' * 64}"}
    )
    assert lifecycle._managed_path_status_pending(pending_hash)  # type: ignore[reportPrivateUsage]
    initial_sink_count = len(sink.items)
    initial = sink.items[-1][0]
    assert initial.evidence is not None

    clock.value = NOW + timedelta(seconds=181)
    refreshed = await lifecycle.refresh_path(NETWORK_ID, NODE_A, 1)
    assert refreshed is not None
    assert len(sink.items) == initial_sink_count + 1
    published = sink.items[-1][0]
    assert published.evidence is not None
    assert published.observed_at == refreshed.observed_at
    assert published.evidence == refreshed.evidence
    assert published.observed_at != initial.observed_at
    assert provider.apply_calls == 1

    clock.value += timedelta(seconds=31)
    sink.fail = True
    failed = await lifecycle.refresh_path(NETWORK_ID, NODE_A, 1)
    assert failed is not None
    assert failed.stable_error_code == "managed_path_status_sink_failed"
    assert len(sink.items) == initial_sink_count + 1
    assert provider.apply_calls == 1

    sink.fail = False
    retried = await lifecycle.reconcile(
        direct.envelope,
        action=NetworkAction.CREATE,
        ownership=None,
    )
    assert retried.managed_path_status_delivered
    assert retried.managed_path_status_delivery_hash is not None
    assert retried.stable_error_code is None
    assert len(sink.items) == initial_sink_count + 2
    retry_payload = sink.items[-1][0]
    assert retry_payload.stable_error_code is None
    assert retry_payload.observed_at == failed.observed_at
    assert retry_payload.evidence == failed.evidence
    assert provider.apply_calls == 1


@pytest.mark.anyio
async def test_journal_and_path_status_are_atomic_across_retry_and_recovery(
    tmp_path: Path,
) -> None:
    lifecycle, policy, provider, _, _, _, _, store = build(tmp_path)
    envelope, _ = signed()
    store._connection.execute(  # type: ignore[reportPrivateUsage]
        "CREATE TRIGGER fail_path_status_insert BEFORE INSERT ON network_path_status "
        "BEGIN SELECT RAISE(ABORT, 'injected path status insert failure'); END;"
    )
    with pytest.raises(ManagedPathLifecycleError, match="journal 持久化失败"):
        await lifecycle.reconcile(envelope, action=NetworkAction.CREATE, ownership=None)
    assert store._connection.execute(  # type: ignore[reportPrivateUsage]
        "SELECT COUNT(*) FROM network_governance"
    ).fetchone() == (0,)
    assert store._connection.execute(  # type: ignore[reportPrivateUsage]
        "SELECT COUNT(*) FROM network_path_status"
    ).fetchone() == (0,)
    store._connection.execute("DROP TRIGGER fail_path_status_insert")  # type: ignore[reportPrivateUsage]

    pending = await lifecycle.reconcile(
        envelope,
        action=NetworkAction.CREATE,
        ownership=None,
    )
    assert pending.phase is NetworkGovernancePhase.AWAITING_AUTHORIZATION
    policy.approve(grant_for(pending), capability=policy.local_control_capability())
    store._connection.execute(  # type: ignore[reportPrivateUsage]
        "CREATE TRIGGER fail_path_status_update BEFORE UPDATE OF payload "
        "ON network_path_status BEGIN SELECT RAISE(ABORT, "
        "'injected path status update failure'); END;"
    )
    with pytest.raises(ManagedPathLifecycleError, match="journal 持久化失败"):
        await lifecycle.reconcile(envelope, action=NetworkAction.CREATE, ownership=None)
    unchanged = store.get(NETWORK_ID, NODE_A, 1)
    assert unchanged is not None
    assert unchanged.phase is NetworkGovernancePhase.AWAITING_AUTHORIZATION
    assert provider.apply_calls == 0
    store._connection.execute("DROP TRIGGER fail_path_status_update")  # type: ignore[reportPrivateUsage]

    recovered = await lifecycle.reconcile(
        envelope,
        action=NetworkAction.CREATE,
        ownership=None,
    )
    assert recovered.phase is NetworkGovernancePhase.VERIFIED
    assert provider.apply_calls == 1


@pytest.mark.anyio
async def test_atomic_journal_failure_after_apply_recovers_without_provider_replay(
    tmp_path: Path,
) -> None:
    lifecycle, policy, provider, _, _, _, _, store = build(
        tmp_path,
        path_controller=real_controller(),
    )
    envelope, _ = signed()
    pending = await lifecycle.reconcile(
        envelope,
        action=NetworkAction.CREATE,
        ownership=None,
    )
    policy.approve(grant_for(pending), capability=policy.local_control_capability())
    first = await lifecycle.reconcile(
        envelope,
        action=NetworkAction.CREATE,
        ownership=None,
    )
    assert first.phase is NetworkGovernancePhase.VERIFIED
    assert first.path_selection is not None
    assert first.path_selection.path_type is NetworkPathType.STATIC
    assert provider.apply_calls == 1

    store._connection.execute(  # type: ignore[reportPrivateUsage]
        "CREATE TRIGGER fail_path_status_retry BEFORE UPDATE OF payload "
        "ON network_path_status BEGIN SELECT RAISE(ABORT, 'injected recovery failure'); END;"
    )
    with pytest.raises(ManagedPathLifecycleError, match="journal 持久化失败"):
        await lifecycle.reconcile(envelope, action=NetworkAction.CREATE, ownership=None)
    unchanged = store.get(NETWORK_ID, NODE_A, 1)
    assert unchanged is not None
    assert unchanged.phase is NetworkGovernancePhase.VERIFIED
    assert provider.apply_calls == 1
    store._connection.execute("DROP TRIGGER fail_path_status_retry")  # type: ignore[reportPrivateUsage]

    recovered = await lifecycle.reconcile(
        envelope,
        action=NetworkAction.CREATE,
        ownership=None,
    )
    assert recovered.phase is NetworkGovernancePhase.VERIFIED
    assert provider.apply_calls == 1


def test_path_status_v1_migration_verifies_raw_hash_and_is_atomic(tmp_path: Path) -> None:
    source = _status_without_evidence()
    v1_payload, v1_hash = _v1_status_payload(source)

    with pytest.raises(ValueError, match="object"):
        restore_managed_path_status_payload("[]")
    with pytest.raises(ValueError, match="版本"):
        restore_managed_path_status_payload('{"schema_version":99}')
    v1_with_v2_field = json.loads(v1_payload)
    v1_with_v2_field["last_refresh_attempt_at"] = None
    with pytest.raises(ValueError, match="v2"):
        restore_managed_path_status_payload(
            json.dumps(v1_with_v2_field, separators=(",", ":"), sort_keys=True)
        )

    valid_database = tmp_path / "valid.sqlite3"
    valid_store = SQLiteNetworkGovernanceStore(
        valid_database,
        authorization_repository=SQLiteNetworkAuthorizationRepository(valid_database),
    )
    _insert_raw_status(valid_store, v1_payload, v1_hash)
    restored = valid_store.get_path_status(NETWORK_ID, NODE_A, 1)
    assert restored is not None
    assert restored.schema_version == 2
    assert restored.last_refresh_attempt_at is None
    migrated = valid_store._connection.execute(  # type: ignore[reportPrivateUsage]
        "SELECT payload, status_hash FROM network_path_status"
    ).fetchone()
    assert migrated is not None
    assert json.loads(migrated[0])["schema_version"] == 2
    assert migrated[1] == canonical_sha256(restored.model_dump(mode="json"))

    invalid_database = tmp_path / "invalid.sqlite3"
    invalid_store = SQLiteNetworkGovernanceStore(
        invalid_database,
        authorization_repository=SQLiteNetworkAuthorizationRepository(invalid_database),
    )
    _insert_raw_status(invalid_store, "[]", "sha256:" + "0" * 64)
    with pytest.raises(ManagedPathLifecycleError, match="schema"):
        invalid_store.get_path_status(NETWORK_ID, NODE_A, 1)

    tampered_database = tmp_path / "tampered.sqlite3"
    tampered_store = SQLiteNetworkGovernanceStore(
        tampered_database,
        authorization_repository=SQLiteNetworkAuthorizationRepository(tampered_database),
    )
    tampered_values = json.loads(v1_payload)
    tampered_values["candidate_count"] = 1
    _insert_raw_status(
        tampered_store,
        json.dumps(tampered_values, separators=(",", ":"), sort_keys=True),
        v1_hash,
    )
    with pytest.raises(ManagedPathLifecycleError, match=r"schema|hash|identity"):
        tampered_store.get_path_status(NETWORK_ID, NODE_A, 1)
    untouched = tampered_store._connection.execute(  # type: ignore[reportPrivateUsage]
        "SELECT payload, status_hash FROM network_path_status"
    ).fetchone()
    assert untouched == (
        json.dumps(tampered_values, separators=(",", ":"), sort_keys=True),
        v1_hash,
    )

    crash_database = tmp_path / "crash.sqlite3"
    crash_store = SQLiteNetworkGovernanceStore(
        crash_database,
        authorization_repository=SQLiteNetworkAuthorizationRepository(crash_database),
    )
    _insert_raw_status(crash_store, v1_payload, v1_hash)
    crash_store._connection.execute(  # type: ignore[reportPrivateUsage]
        "CREATE TRIGGER fail_v1_migration BEFORE UPDATE OF payload ON network_path_status "
        "BEGIN SELECT RAISE(ABORT, 'injected v1 migration failure'); END;"
    )
    with pytest.raises(ManagedPathLifecycleError, match="迁移失败"):
        crash_store.get_path_status(NETWORK_ID, NODE_A, 1)
    unchanged = crash_store._connection.execute(  # type: ignore[reportPrivateUsage]
        "SELECT payload, status_hash FROM network_path_status"
    ).fetchone()
    assert unchanged == (v1_payload, v1_hash)
    crash_store._connection.execute("DROP TRIGGER fail_v1_migration")  # type: ignore[reportPrivateUsage]
    assert crash_store.get_path_status(NETWORK_ID, NODE_A, 1) is not None

    cas_database = tmp_path / "cas.sqlite3"
    cas_store = SQLiteNetworkGovernanceStore(
        cas_database,
        authorization_repository=SQLiteNetworkAuthorizationRepository(cas_database),
    )
    _insert_raw_status(cas_store, v1_payload, v1_hash)
    cas_store._connection.execute(  # type: ignore[reportPrivateUsage]
        "CREATE TRIGGER ignore_v1_migration BEFORE UPDATE OF payload ON network_path_status "
        "BEGIN SELECT RAISE(IGNORE); END;"
    )
    with pytest.raises(ManagedPathLifecycleError, match="CAS 冲突"):
        cas_store.get_path_status(NETWORK_ID, NODE_A, 1)
    assert cas_store._connection.execute(  # type: ignore[reportPrivateUsage]
        "SELECT payload, status_hash FROM network_path_status"
    ).fetchone() == (v1_payload, v1_hash)


@pytest.mark.anyio
async def test_v1_path_status_restores_after_restart_without_apply_replay(tmp_path: Path) -> None:
    clock = MutableClock()
    probe = FakePathVerifier(path_evidence())
    lifecycle, policy, provider, _, _, _, _, store = build(
        tmp_path,
        verifier=probe,
        path_controller=real_controller(),
        clock=clock,
    )
    envelope, _, result = await authorized_lifecycle(lifecycle, policy)
    status = store.get_path_status(NETWORK_ID, NODE_A, 1)
    assert status is not None
    v1_payload, v1_hash = _v1_status_payload(status)
    store._connection.execute(  # type: ignore[reportPrivateUsage]
        "UPDATE network_path_status SET payload=?, status_hash=? "
        "WHERE network_id=? AND node_id=? AND revision=?",
        (v1_payload, v1_hash, str(NETWORK_ID), str(NODE_A), 1),
    )

    restarted, _, restarted_provider, _, _, _, _, _ = build(
        tmp_path,
        verifier=probe,
        path_controller=real_controller(),
        provider_override=provider,
        clock=clock,
    )
    restored = restarted.get_path_status(NETWORK_ID, NODE_A, 1)
    assert restored is not None and restored.schema_version == 2
    recovered = await restarted.reconcile(
        envelope,
        action=NetworkAction.CREATE,
        ownership=None,
    )
    assert recovered.phase is NetworkGovernancePhase.VERIFIED
    assert restarted_provider.apply_calls == 1
    assert result.phase is NetworkGovernancePhase.VERIFIED


def test_managed_path_status_binding_and_freshness_matrix() -> None:
    assert source_category("fixture") == "fake"
    assert source_category("platform-windows") == "platform_read_only"
    assert source_category("structured-candidate") == "structured-candidate"
    with pytest.raises(ValueError, match="source"):
        source_category("untrusted-source")

    unknown = _status_without_evidence()
    assert unknown.at(NOW).freshness is ManagedPathFreshness.UNVERIFIED
    assert not unknown.currently_usable
    evidence = path_evidence()
    fresh = _status_from_evidence(evidence)
    assert fresh.currently_usable
    direct = _status_from_evidence(
        evidence,
        path_type=NetworkPathType.DIRECT,
        selection=_direct_selection(evidence),
    )
    assert direct.currently_usable
    with pytest.raises(ValueError, match="updated_at"):
        direct.model_copy(
            update={"last_refresh_attempt_at": NOW + timedelta(seconds=1)}
        ).validate_binding()  # type: ignore[reportCallIssue]
    with pytest.raises(ValueError, match="status evidence"):
        direct.model_copy(
            update={"updated_at": evidence.observed_at - timedelta(seconds=1)}
        ).validate_binding()  # type: ignore[reportCallIssue]
    with pytest.raises(ValueError):
        failed_for_stale = _status_from_evidence(
            path_evidence(
                verified=False,
                error=DirectPathErrorCode.TARGET_UNREACHABLE,
            )
        ).model_copy(update={"freshness": ManagedPathFreshness.STALE})
        failed_for_stale.validate_binding()  # type: ignore[reportCallIssue]
    with pytest.raises(ValueError):
        successful_as_unverified = direct.model_copy(
            update={"freshness": ManagedPathFreshness.UNVERIFIED}
        )
        successful_as_unverified.validate_binding()  # type: ignore[reportCallIssue]
    with pytest.raises(ValueError):
        _status_from_evidence(
            evidence,
            path_type=NetworkPathType.DIRECT,
            selection=_direct_selection(
                evidence,
                last_evidence_at=evidence.observed_at - timedelta(seconds=1),
            ),
        )
    assert not direct.model_copy(update={"selection": None})._direct_binding_is_valid()  # type: ignore[reportPrivateUsage]
    stale = direct.at(evidence.expires_at)
    assert stale.freshness is ManagedPathFreshness.STALE
    assert stale.stable_error_code == "path_evidence_stale"
    preserved = direct.model_validate(
        {**direct.model_dump(mode="python"), "stable_error_code": "keep-me"}
    ).at(evidence.expires_at)
    assert preserved.stable_error_code == "keep-me"
    offline = _status_from_evidence(
        evidence,
        path_type=NetworkPathType.OFFLINE,
    )
    assert not offline.currently_usable
    failed_evidence = path_evidence(
        verified=False,
        error=DirectPathErrorCode.TARGET_UNREACHABLE,
    )
    failed = _status_from_evidence(failed_evidence)
    assert failed.at(NOW).stable_error_code == "target_unreachable"
    custom_failed = failed.model_validate(
        {**failed.model_dump(mode="python"), "stable_error_code": "custom-failure"}
    )
    assert custom_failed.at(NOW).stable_error_code == "custom-failure"
    with pytest.raises(ValueError, match="timezone-aware UTC"):
        unknown.at(datetime(2026, 8, 13))

    invalid_payloads: list[dict[str, object]] = [
        {
            "authorization_state": ManagedPathAuthorizationState.AUTHORIZED,
            "authorization_id": None,
        },
        {
            "authorization_state": ManagedPathAuthorizationState.UNKNOWN,
            "authorization_id": AuthorizationId.new(),
        },
        {"authorization_revision": 2},
        {"source": "fake"},
        {"source": "untrusted-source"},
        {"observed_at": NOW},
        {"updated_at": datetime(2026, 8, 13)},
        {"updated_at": datetime(2026, 8, 13, tzinfo=timezone(timedelta(hours=8)))},
        {"freshness": ManagedPathFreshness.FRESH},
    ]
    for updates in invalid_payloads:
        with pytest.raises((ValidationError, ValueError)):
            _status_without_evidence(**updates)

    mismatched_evidence = DirectPathEvidence.model_validate(
        {**evidence.model_dump(mode="python"), "network_id": NetworkId.new()}
    )
    invalid_evidence_payloads = [
        {"network_id": NetworkId.new()},
        {"evidence": mismatched_evidence},
        {"source": "structured-candidate"},
        {"observed_at": NOW + timedelta(seconds=1)},
        {"candidate_count": 2},
    ]
    for updates in invalid_evidence_payloads:
        with pytest.raises((ValidationError, ValueError)):
            _status_from_evidence(evidence, **updates)

    invalid_selection_payloads = [
        _direct_selection(evidence, revision=2, authorization_revision=2),
        _direct_selection(evidence, network_id=NetworkId.new()),
        _direct_selection(evidence, node_id=NodeId.new()),
        _direct_selection(evidence, plan_hash=f"sha256:{'f' * 64}"),
        _direct_selection(evidence, authorization_revision=2, revision=2),
        _direct_selection(evidence, provider=ProviderKind.MACOS),
        _direct_selection(evidence, target_host_hash=f"sha256:{'d' * 64}"),
        _static_selection(authorization_revision=2),
    ]
    for selection in invalid_selection_payloads:
        with pytest.raises((ValidationError, ValueError)):
            _status_from_evidence(
                evidence,
                path_type=NetworkPathType.DIRECT,
                selection=selection,
            )
    invalid_authorization_selection = _direct_selection(evidence).model_copy(
        update={"authorization_revision": 2}
    )
    with pytest.raises(ValueError):
        _status_from_evidence(
            evidence,
            path_type=NetworkPathType.DIRECT,
            selection=invalid_authorization_selection,
        )
    with pytest.raises(ValueError):
        direct.model_copy(update={"selection": invalid_authorization_selection}).validate_binding()  # type: ignore[reportCallIssue]
    with pytest.raises(ValueError):
        _status_from_evidence(
            evidence,
            path_type=NetworkPathType.DIRECT,
            selection=_direct_selection(evidence, authorization_revision=2),
        )
    with pytest.raises((ValidationError, ValueError), match=r"path type|direct"):
        _status_from_evidence(
            evidence,
            path_type=NetworkPathType.DIRECT,
            selection=_static_selection(),
        )
    with pytest.raises((ValidationError, ValueError), match=r"path type|direct"):
        _status_from_evidence(
            evidence,
            path_type=NetworkPathType.STATIC,
            selection=_direct_selection(evidence),
        )
    with pytest.raises((ValidationError, ValueError), match=r"selection|evidence"):
        _status_from_evidence(evidence, path_type=NetworkPathType.DIRECT, selection=None)
    with pytest.raises((ValidationError, ValueError)):
        _status_from_evidence(
            failed_evidence,
            path_type=NetworkPathType.DIRECT,
            selection=_direct_selection(failed_evidence),
        )
    with pytest.raises((ValidationError, ValueError)):
        _status_from_evidence(failed_evidence, freshness=ManagedPathFreshness.FRESH)
    with pytest.raises((ValidationError, ValueError), match=r"过期|fresh"):
        _status_from_evidence(
            evidence,
            freshness=ManagedPathFreshness.FRESH,
            updated_at=evidence.expires_at,
        )
    with pytest.raises((ValidationError, ValueError), match=r"时间摘要|时间线"):
        _status_from_evidence(
            evidence,
            refreshed_at=evidence.observed_at - timedelta(seconds=1),
        )

    expired_constructed = direct.model_copy(
        update={
            "freshness": ManagedPathFreshness.FRESH,
            "updated_at": evidence.expires_at,
        }
    )
    assert not expired_constructed.currently_usable
    contradictory_constructed = direct.model_copy(
        update={
            "path_type": NetworkPathType.STATIC,
            "selection": _direct_selection(evidence),
        }
    )
    assert not contradictory_constructed.currently_usable

    def forbidden_model_dump(**_: object) -> dict[str, str]:
        return {"endpoint": "forbidden"}

    secret_status = cast(
        ManagedPathStatus,
        SimpleNamespace(model_dump=forbidden_model_dump),
    )
    with pytest.raises(ValueError, match="禁止"):
        redacted_managed_path_status_payload(secret_status)


def test_direct_controller_restore_rejects_older_revision() -> None:
    controller = DirectPathController(
        PathControllerPolicy(minimum_dwell_seconds=0),
        initial=_static_selection(revision=2),
    )
    with pytest.raises(ValueError, match="倒退"):
        controller.restore(_static_selection(revision=1))
    controller.restore(_static_selection(revision=3))
    assert controller.selection.revision == 3


@pytest.mark.anyio
async def test_path_status_store_cas_and_sqlite_fail_closed(tmp_path: Path) -> None:
    clock = MutableClock()
    lifecycle, policy, _, _, _, _, _, store = build(tmp_path, clock=clock)
    _, _, record = await authorized_lifecycle(lifecycle, policy)
    status = store.get_path_status(NETWORK_ID, NODE_A, 1)
    assert status is not None
    store.put_path_status(status)
    with pytest.raises(NetworkAuthorizationConflictError, match="冲突"):
        store.put_path_status(
            status.model_validate(
                {**status.model_dump(mode="python"), "stable_error_code": "same-sequence"}
            )
        )
    newer = status.model_validate(
        {
            **status.model_dump(mode="python"),
            "journal_sequence": status.journal_sequence + 1,
            "stable_error_code": "cas-update",
        }
    )
    store._connection.execute(  # type: ignore[reportPrivateUsage]
        "CREATE TRIGGER ignore_path_status_update BEFORE UPDATE OF payload "
        "ON network_path_status BEGIN SELECT RAISE(IGNORE); END;"
    )
    with pytest.raises(NetworkAuthorizationConflictError, match="CAS"):
        store.put_path_status(newer)
    store._connection.execute("DROP TRIGGER ignore_path_status_update")  # type: ignore[reportPrivateUsage]
    store._connection.execute(  # type: ignore[reportPrivateUsage]
        "UPDATE network_path_status SET status_hash=? WHERE network_id=? "
        "AND node_id=? AND revision=?",
        (f"sha256:{'0' * 64}", str(NETWORK_ID), str(NODE_A), 1),
    )
    with pytest.raises(ManagedPathLifecycleError, match="hash"):
        store.get_path_status(NETWORK_ID, NODE_A, 1)
    assert store.get_path_status(NetworkId.new(), NodeId.new(), 1) is None
    store._connection.execute("DROP TABLE network_path_status")  # type: ignore[reportPrivateUsage]
    with pytest.raises(ManagedPathLifecycleError, match="schema"):
        store.get_path_status(NETWORK_ID, NODE_A, 1)
    assert record.phase is NetworkGovernancePhase.VERIFIED


@pytest.mark.anyio
async def test_legacy_status_adapter_delegates_without_provider_apply(tmp_path: Path) -> None:
    lifecycle, policy, provider, _, _, verifier, fake_controller, store = build(tmp_path)
    envelope, _, direct = await authorized_lifecycle(lifecycle, policy)
    adapter = ManagedNetworkGovernanceWorkflow(
        provider,
        policy,
        store,
        None,
        path_verifier=verifier,
        path_controller=fake_controller,
    )
    status = adapter.get_path_status(NETWORK_ID, NODE_A, 1)
    assert status is not None and status.plan_hash == direct.plan.plan_hash
    refreshed = await adapter.refresh_path(NETWORK_ID, NODE_A, 1)
    assert refreshed is not None
    assert refreshed.freshness is ManagedPathFreshness.FRESH
    assert provider.apply_calls == 1
    delegated = await adapter.reconcile(envelope, action=NetworkAction.CREATE, ownership=None)
    assert delegated.phase is NetworkGovernancePhase.VERIFIED
    assert delegated.plan.plan_hash == direct.plan.plan_hash
    assert provider.apply_calls == 1


@pytest.mark.anyio
async def test_refresh_missing_records_and_pending_status_are_read_only(tmp_path: Path) -> None:
    lifecycle, policy, provider, _, _, _, _, store = build(tmp_path)
    envelope, _, _ = await authorized_lifecycle(lifecycle, policy)
    current = lifecycle.get_path_status(NETWORK_ID, NODE_A, 1)
    assert current is not None
    store._connection.execute(  # type: ignore[reportPrivateUsage]
        "DELETE FROM network_path_status WHERE network_id=? AND node_id=? AND revision=?",
        (str(NETWORK_ID), str(NODE_A), 1),
    )
    derived = lifecycle.get_path_status(NETWORK_ID, NODE_A, 1)
    assert derived is not None and derived.plan_hash == current.plan_hash
    store.put_path_status(current)
    store._records.pop((str(NETWORK_ID), str(NODE_A), 1), None)  # type: ignore[reportPrivateUsage]
    store._connection.execute(  # type: ignore[reportPrivateUsage]
        "DELETE FROM network_governance WHERE network_id=? AND node_id=? AND revision=?",
        (str(NETWORK_ID), str(NODE_A), 1),
    )
    persisted_only = await lifecycle.refresh_path(NETWORK_ID, NODE_A, 1)
    assert persisted_only is not None and persisted_only.plan_hash == current.plan_hash
    assert lifecycle.get_path_status(NetworkId.new(), NodeId.new(), 1) is None
    pending_path = tmp_path / "pending"
    pending_lifecycle, _, pending_provider, _, _, _, _, _ = build(pending_path)
    pending_envelope, _ = signed()
    pending = await pending_lifecycle.reconcile(
        pending_envelope,
        action=NetworkAction.CREATE,
        ownership=None,
    )
    pending_status = await pending_lifecycle.refresh_path(
        pending.plan.desired.network_id,
        pending.plan.desired.target_node_id,
        pending.plan.desired.revision,
    )
    assert pending_status is not None
    assert pending_provider.apply_calls == 0
    assert provider.apply_calls == 1
    assert envelope.config.network_id == pending.plan.desired.network_id


@pytest.mark.anyio
async def test_restart_path_checkpoint_mismatches_fail_closed(tmp_path: Path) -> None:
    clock = MutableClock()
    lifecycle, policy, provider, _, _, verifier, _, store = build(tmp_path, clock=clock)
    envelope, _, direct = await authorized_lifecycle(lifecycle, policy)
    status = store.get_path_status(NETWORK_ID, NODE_A, 1)
    assert status is not None and status.selection is not None

    store._connection.execute(  # type: ignore[reportPrivateUsage]
        "DELETE FROM network_path_status WHERE network_id=? AND node_id=? AND revision=?",
        (str(NETWORK_ID), str(NODE_A), 1),
    )
    restored_without_checkpoint = await lifecycle.reconcile(
        envelope,
        action=NetworkAction.CREATE,
        ownership=None,
    )
    assert restored_without_checkpoint.phase is NetworkGovernancePhase.VERIFIED
    status = lifecycle.get_path_status(NETWORK_ID, NODE_A, 1)
    assert status is not None
    store.put_path_status(status)

    sequence_conflict = status.model_validate(
        {
            **status.model_dump(mode="python"),
            "journal_sequence": status.journal_sequence + 1,
        }
    )
    _rewrite_status_row(tmp_path / "governance.sqlite3", sequence_conflict)
    with pytest.raises(ManagedPathLifecycleError, match="journal"):
        await lifecycle.reconcile(envelope, action=NetworkAction.CREATE, ownership=None)
    _rewrite_status_row(tmp_path / "governance.sqlite3", status)

    plan_conflict = _status_without_evidence(
        plan_hash=f"sha256:{'f' * 64}",
        authorization_state=ManagedPathAuthorizationState.AUTHORIZED,
        authorization_id=status.authorization_id,
        journal_sequence=status.journal_sequence,
        updated_at=status.updated_at,
    )
    _rewrite_status_row(tmp_path / "governance.sqlite3", plan_conflict)
    with pytest.raises(ManagedPathLifecycleError, match="path status"):
        lifecycle.get_path_status(NETWORK_ID, NODE_A, 1)
    with pytest.raises(ManagedPathLifecycleError, match="path status"):
        await lifecycle.reconcile(envelope, action=NetworkAction.CREATE, ownership=None)
    _rewrite_status_row(tmp_path / "governance.sqlite3", status)

    selection = status.selection
    assert selection is not None
    failing_controller = RestoreFailingController(selection)
    failing_lifecycle = ManagedPathLifecycle(
        provider,
        policy,
        store,
        None,
        path_verifier=verifier,
        path_controller=failing_controller,
        clock=clock,
    )
    with pytest.raises(ManagedPathLifecycleError, match="checkpoint"):
        await failing_lifecycle.reconcile(envelope, action=NetworkAction.CREATE, ownership=None)
    assert direct.phase is NetworkGovernancePhase.VERIFIED


@pytest.mark.anyio
async def test_refresh_completion_does_not_remove_replacement_task(tmp_path: Path) -> None:
    clock = MutableClock()
    probe = GatedPathVerifier(path_evidence())
    lifecycle, policy, provider, _, _, _, _, _ = build(
        tmp_path,
        verifier=probe,
        clock=clock,
    )
    _, _, _ = await authorized_lifecycle(lifecycle, policy)
    clock.value = NOW + timedelta(seconds=181)
    probe.block = True
    key = (str(NETWORK_ID), str(NODE_A), 1)
    first = asyncio.create_task(lifecycle.refresh_path(NETWORK_ID, NODE_A, 1))
    await probe.started.wait()
    replacement = asyncio.create_task(asyncio.sleep(0, result=None))
    lifecycle._path_refresh_tasks[key] = cast(  # type: ignore[reportPrivateUsage]
        "asyncio.Task[ManagedPathStatus | None]", replacement
    )
    probe.release.set()
    result = await first
    await replacement
    assert result is not None and result.freshness is ManagedPathFreshness.FRESH
    assert key in lifecycle._path_refresh_tasks  # type: ignore[reportPrivateUsage]
    lifecycle._path_refresh_tasks.pop(key, None)  # type: ignore[reportPrivateUsage]
    assert provider.apply_calls == 1
