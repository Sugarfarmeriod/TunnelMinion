"""假适配器下批准操作纵向工作流测试。"""

from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path
from typing import cast

import pytest
from tests.operation.factories import NOW, plan

from tunnelminion.domain.identifiers import AuthorizationId, LeaseId, OperationId
from tunnelminion.memory.sqlite import SQLiteStores
from tunnelminion.operation.contracts import (
    AuthorizationDecision,
    AuthorizationKind,
    AuthorizationRecord,
    LeaseRecord,
    OperationErrorCode,
    OperationLevel,
    OperationRecord,
    OperationStatus,
    ServiceEvidence,
    VerificationResult,
    transition_operation,
)
from tunnelminion.operation.fakes import (
    FakeAdapterBehavior,
    FakeRequesterVerifier,
    FakeServiceEvidenceProvider,
    FakeSharingAdapter,
)
from tunnelminion.operation.workflow import (
    OperationWorkflow,
    WorkflowUsage,
    build_operation_plan,
    operation_token_name,
)


class MemorySecretStore:
    """测试用内存秘密存储。"""

    def __init__(self) -> None:
        self.values: dict[str, str] = {}

    def get(self, name: str) -> str | None:
        return self.values.get(name)

    def set(self, name: str, value: str) -> None:
        self.values[name] = value

    def delete(self, name: str) -> None:
        self.values.pop(name, None)


def _authorized_record(*, authorization_expires_at: datetime | None = None) -> OperationRecord:
    operation_plan = plan()
    authorization = AuthorizationRecord(
        authorization_id=AuthorizationId.new(),
        operation_id=operation_plan.operation_id,
        kind=AuthorizationKind.ONE_TIME,
        decision=AuthorizationDecision.APPROVED,
        operator="target-local-user",
        basis="目标节点本地批准",
        decided_at=NOW,
        expires_at=authorization_expires_at,
    )
    record = OperationRecord.planned(operation_plan).model_copy(
        update={"authorization": authorization}
    )
    return transition_operation(
        record,
        OperationStatus.AUTHORIZED,
        reason="目标节点本地批准",
        occurred_at=NOW,
    )


_CURRENT_PLAN_SERVICE = object()


def _workflow(
    path: Path,
    record: OperationRecord,
    *,
    adapter_behavior: FakeAdapterBehavior = FakeAdapterBehavior.SUCCESS,
    verification_result: VerificationResult = VerificationResult.PASSED,
    verifier_raises: bool = False,
    current_service: ServiceEvidence | None | object = _CURRENT_PLAN_SERVICE,
) -> tuple[OperationWorkflow, FakeSharingAdapter, FakeRequesterVerifier, MemorySecretStore]:
    stores = SQLiteStores.open(path)
    stores.operations.put(record)
    evidence_value = (
        record.plan.service
        if current_service is _CURRENT_PLAN_SERVICE
        else cast(ServiceEvidence | None, current_service)
    )
    evidence = FakeServiceEvidenceProvider(evidence_value)
    adapter = FakeSharingAdapter(adapter_behavior)
    verifier = FakeRequesterVerifier(
        record.plan.request_node_id,
        verification_result,
        raise_error=verifier_raises,
    )
    secrets_store = MemorySecretStore()
    workflow = OperationWorkflow(
        stores.operations,
        secrets_store,
        evidence,
        adapter,
        verifier,
    )
    return workflow, adapter, verifier, secrets_store


@pytest.mark.anyio
async def test_success_is_independently_verified_and_expires_without_model(
    tmp_path: Path,
) -> None:
    record = _authorized_record()
    workflow, adapter, verifier, secrets_store = _workflow(tmp_path / "success.sqlite3", record)
    usage = WorkflowUsage(
        model_input_tokens=100,
        model_output_tokens=20,
        model_cost_usd=0.01,
        tool_call_count=3,
    )

    succeeded = await workflow.execute_authorized(
        record.plan.operation_id,
        at=NOW + timedelta(seconds=1),
        usage=usage,
    )

    assert succeeded.status is OperationStatus.SUCCEEDED
    assert succeeded.lease is not None
    assert succeeded.resources
    assert succeeded.verifications[0].result is VerificationResult.PASSED
    assert adapter.create_calls == 1
    assert verifier.calls == 1
    assert operation_token_name(record.plan.operation_id) in secrets_store.values
    assert succeeded.metrics.model_input_tokens == 100
    assert succeeded.metrics.authorization_kind is AuthorizationKind.ONE_TIME
    assert succeeded.metrics.final_result == "succeeded"
    assert succeeded.metrics.phase_latency_ms["workflow_total"] >= 0

    assert await workflow.expire_due(at=NOW + timedelta(seconds=2)) == ()
    expired = await workflow.expire_due(at=succeeded.lease.expires_at)
    assert expired[0].status is OperationStatus.EXPIRED
    assert adapter.active_resources == {}
    assert operation_token_name(record.plan.operation_id) not in secrets_store.values
    with pytest.raises(ValueError, match="authorized"):
        await workflow.execute_authorized(record.plan.operation_id, at=NOW + timedelta(seconds=2))


@pytest.mark.anyio
async def test_expired_or_missing_authorization_never_reaches_adapter(tmp_path: Path) -> None:
    expired_record = _authorized_record(authorization_expires_at=NOW + timedelta(seconds=1))
    workflow, adapter, _, _ = _workflow(tmp_path / "expired.sqlite3", expired_record)
    expired = await workflow.execute_authorized(
        expired_record.plan.operation_id,
        at=NOW + timedelta(seconds=1),
    )
    assert expired.status is OperationStatus.AUTHORIZATION_EXPIRED
    assert adapter.create_calls == 0

    missing_plan = plan()
    missing = transition_operation(
        OperationRecord.planned(missing_plan),
        OperationStatus.AUTHORIZED,
        reason="无效测试记录",
        occurred_at=NOW,
    )
    workflow, _, _, _ = _workflow(tmp_path / "missing-auth.sqlite3", missing)
    with pytest.raises(ValueError, match="有效批准"):
        await workflow.execute_authorized(missing_plan.operation_id, at=NOW)


@pytest.mark.anyio
async def test_service_change_execution_failure_and_verification_failure_roll_back(
    tmp_path: Path,
) -> None:
    changed_record = _authorized_record()
    changed_service = changed_record.plan.service.model_copy(
        update={"fingerprint": f"sha256:{'8' * 64}"}
    )
    workflow, adapter, _, _ = _workflow(
        tmp_path / "changed.sqlite3",
        changed_record,
        current_service=changed_service,
    )
    changed = await workflow.execute_authorized(changed_record.plan.operation_id, at=NOW)
    assert changed.status is OperationStatus.ROLLED_BACK
    assert changed.error is not None
    assert changed.error.code is OperationErrorCode.SERVICE_CHANGED
    assert adapter.create_calls == 0

    missing_service = _authorized_record()
    workflow, _, _, _ = _workflow(
        tmp_path / "missing-service.sqlite3",
        missing_service,
        current_service=None,
    )
    assert (
        await workflow.execute_authorized(missing_service.plan.operation_id, at=NOW)
    ).status is OperationStatus.ROLLED_BACK

    for behavior in (
        FakeAdapterBehavior.EXECUTION_FAILURE,
        FakeAdapterBehavior.EXECUTION_EXCEPTION,
    ):
        record = _authorized_record()
        workflow, adapter, _, _ = _workflow(
            tmp_path / f"{behavior.value}.sqlite3",
            record,
            adapter_behavior=behavior,
        )
        failed = await workflow.execute_authorized(record.plan.operation_id, at=NOW)
        assert failed.status is OperationStatus.ROLLED_BACK
        assert failed.error is not None
        assert failed.error.code is OperationErrorCode.EXECUTION_FAILED
        assert adapter.active_resources == {}

    for result, raises in (
        (VerificationResult.FAILED, False),
        (VerificationResult.PASSED, True),
    ):
        record = _authorized_record()
        workflow, adapter, _, _ = _workflow(
            tmp_path / f"verify-{result.value}-{raises}.sqlite3",
            record,
            verification_result=result,
            verifier_raises=raises,
        )
        failed = await workflow.execute_authorized(record.plan.operation_id, at=NOW)
        assert failed.status is OperationStatus.ROLLED_BACK
        assert failed.error is not None
        assert failed.error.code is OperationErrorCode.VERIFICATION_FAILED
        assert adapter.active_resources == {}


@pytest.mark.anyio
async def test_cleanup_failure_is_visible_and_blocks_false_success(tmp_path: Path) -> None:
    for behavior in (
        FakeAdapterBehavior.CLEANUP_FAILURE,
        FakeAdapterBehavior.CLEANUP_EXCEPTION,
        FakeAdapterBehavior.OWNERSHIP_MISMATCH,
    ):
        record = _authorized_record()
        workflow, _, _, secrets_store = _workflow(
            tmp_path / f"cleanup-{behavior.value}.sqlite3",
            record,
            adapter_behavior=behavior,
            verification_result=VerificationResult.FAILED,
        )
        failed = await workflow.execute_authorized(record.plan.operation_id, at=NOW)
        assert failed.status is OperationStatus.CLEANUP_FAILED
        assert failed.cleanup is not None
        assert failed.cleanup.manual_action is not None
        assert operation_token_name(record.plan.operation_id) not in secrets_store.values


@pytest.mark.anyio
async def test_revoke_and_recovery_clean_without_replaying_write(tmp_path: Path) -> None:
    record = _authorized_record()
    workflow, adapter, _, _ = _workflow(tmp_path / "revoke.sqlite3", record)
    succeeded = await workflow.execute_authorized(record.plan.operation_id, at=NOW)
    revoked = await workflow.revoke(record.plan.operation_id, at=NOW + timedelta(seconds=1))
    assert succeeded.status is OperationStatus.SUCCEEDED
    assert revoked.status is OperationStatus.ROLLED_BACK
    assert adapter.create_calls == 1
    with pytest.raises(ValueError, match="succeeded"):
        await workflow.revoke(record.plan.operation_id, at=NOW + timedelta(seconds=2))

    recovering = _authorized_record()
    lease = LeaseRecord(
        lease_id=LeaseId.new(),
        operation_id=recovering.plan.operation_id,
        starts_at=NOW,
        expires_at=NOW + timedelta(minutes=5),
    )
    executing = transition_operation(
        recovering.model_copy(update={"lease": lease}),
        OperationStatus.EXECUTING,
        reason="进程在适配器返回前退出",
        occurred_at=NOW,
    )
    workflow, adapter, _, _ = _workflow(tmp_path / "recover.sqlite3", executing)
    recovered = await workflow.recover_unfinished(at=NOW + timedelta(seconds=1))
    assert recovered[0].status is OperationStatus.ROLLED_BACK
    assert adapter.create_calls == 0
    assert adapter.cleanup_calls == 1

    active_record = _authorized_record()
    active_workflow, _, _, _ = _workflow(
        tmp_path / "recover-active-source.sqlite3",
        active_record,
    )
    active = await active_workflow.execute_authorized(active_record.plan.operation_id, at=NOW)
    workflow, adapter, _, _ = _workflow(
        tmp_path / "recover-active.sqlite3",
        active,
    )
    recovered = await workflow.recover_unfinished(at=NOW + timedelta(seconds=1))
    assert recovered[0].status is OperationStatus.ROLLED_BACK
    assert recovered[0].metrics.final_result == "recovered_without_replay"
    assert adapter.create_calls == 0
    assert adapter.cleanup_calls == 1

    rolling_record = _authorized_record()
    rolling = transition_operation(
        rolling_record,
        OperationStatus.ROLLING_BACK,
        reason="上次清理中断",
        occurred_at=NOW,
    )
    workflow, adapter, _, _ = _workflow(tmp_path / "recover-rollback.sqlite3", rolling)
    recovered = await workflow.recover_unfinished(at=NOW + timedelta(seconds=1))
    assert recovered[0].status is OperationStatus.ROLLED_BACK
    assert adapter.cleanup_calls == 1

    waiting_record = _authorized_record()
    waiting = OperationRecord.model_validate(
        {
            **waiting_record.model_dump(),
            "authorization": None,
            "status": OperationStatus.AWAITING_AUTHORIZATION,
            "transitions": (
                waiting_record.transitions[0],
                {
                    "from_status": OperationStatus.PLANNED,
                    "to_status": OperationStatus.AWAITING_AUTHORIZATION,
                    "reason": "仍在等待用户决定",
                    "occurred_at": NOW,
                },
            ),
        }
    )
    workflow, adapter, _, _ = _workflow(tmp_path / "recover-waiting.sqlite3", waiting)
    assert await workflow.recover_unfinished(at=NOW + timedelta(seconds=1)) == ()
    assert adapter.cleanup_calls == 0


@pytest.mark.anyio
async def test_workflow_rejects_unknown_operation_and_fake_boundaries(tmp_path: Path) -> None:
    record = _authorized_record()
    workflow, adapter, verifier, _ = _workflow(tmp_path / "boundaries.sqlite3", record)
    with pytest.raises(KeyError, match="不存在"):
        await workflow.execute_authorized(OperationId.new(), at=NOW)

    lease = LeaseRecord(
        lease_id=LeaseId.new(),
        operation_id=record.plan.operation_id,
        starts_at=NOW,
        expires_at=NOW + timedelta(minutes=1),
    )
    with pytest.raises(ValueError, match="高熵"):
        await adapter.create(record.plan, lease, "short")
    with pytest.raises(ValueError, match="预算"):
        await verifier.verify(record.plan, lease, "short")

    mismatched_evidence = FakeServiceEvidenceProvider(record.plan.service)
    assert await mismatched_evidence.read("other-service") is None


def test_plan_builder_requires_complete_fields_and_stabilizes_idempotency() -> None:
    source = plan()
    built = build_operation_plan(
        request_node_id=source.request_node_id,
        target_node_id=source.target_node_id,
        thread_id=source.thread_id,
        run_id=source.run_id,
        tool_run_ids=source.tool_run_ids,
        tool_name=source.tool_name,
        level=OperationLevel.L2,
        service=source.service,
        expected_change=source.expected_change,
        access_scope=source.access_scope,
        risk_summary=source.risk_summary,
        verification_method=source.verification_method,
        rollback_method=source.rollback_method,
        created_at=source.created_at,
        operation_id=source.operation_id,
    )
    rebuilt = build_operation_plan(
        request_node_id=source.request_node_id,
        target_node_id=source.target_node_id,
        thread_id=source.thread_id,
        run_id=source.run_id,
        tool_run_ids=source.tool_run_ids,
        tool_name=source.tool_name,
        level=OperationLevel.L2,
        service=source.service,
        expected_change=source.expected_change,
        access_scope=source.access_scope,
        risk_summary=source.risk_summary,
        verification_method=source.verification_method,
        rollback_method=source.rollback_method,
        created_at=source.created_at,
    )
    assert built.idempotency_key == rebuilt.idempotency_key
    assert built.operation_id == source.operation_id
    assert rebuilt.operation_id != source.operation_id
