"""批准操作契约与状态机测试。"""

from __future__ import annotations

from datetime import timedelta

import pytest
from pydantic import ValidationError
from tests.operation.factories import NOW, full_record, plan

from tunnelminion.domain.identifiers import (
    AuthorizationId,
    LeaseId,
    NodeId,
    OperationId,
)
from tunnelminion.domain.versioning import ProtocolVersion
from tunnelminion.operation.contracts import (
    AccessScope,
    AuthorizationDecision,
    AuthorizationKind,
    AuthorizationRecord,
    CleanupRecord,
    CleanupResult,
    LeaseRecord,
    OperationError,
    OperationErrorCode,
    OperationPlan,
    OperationRecord,
    OperationStatus,
    OperationSummary,
    OperationTransition,
    VerificationResult,
    compute_idempotency_key,
    transition_operation,
)


def test_plan_validates_protocol_idempotency_key_and_request_scope() -> None:
    valid = plan()
    same_key = compute_idempotency_key(
        request_node_id=valid.request_node_id,
        target_node_id=valid.target_node_id,
        tool_name=valid.tool_name,
        plan_version=valid.plan_version,
        service_fingerprint=valid.service.fingerprint,
        access_scope=valid.access_scope,
    )
    assert same_key == valid.idempotency_key

    with pytest.raises(ValidationError, match="主版本不兼容"):
        plan(protocol_version=ProtocolVersion(major=2, minor=0))
    with pytest.raises(ValidationError, match="幂等键"):
        plan(idempotency_key=f"opkey_{'0' * 64}")

    other_peer = NodeId.new()
    invalid_scope = valid.access_scope.model_copy(update={"allowed_peer_id": other_peer})
    with pytest.raises(ValidationError, match="请求节点"):
        OperationPlan.model_validate(
            {
                **valid.model_dump(),
                "access_scope": invalid_scope,
                "idempotency_key": compute_idempotency_key(
                    request_node_id=valid.request_node_id,
                    target_node_id=valid.target_node_id,
                    tool_name=valid.tool_name,
                    plan_version=valid.plan_version,
                    service_fingerprint=valid.service.fingerprint,
                    access_scope=invalid_scope,
                ),
            }
        )


def test_authorization_lease_and_cleanup_validate_absolute_times() -> None:
    operation_id = OperationId.new()
    valid_authorization = AuthorizationRecord(
        authorization_id=AuthorizationId.new(),
        operation_id=operation_id,
        kind=AuthorizationKind.ONE_TIME,
        decision=AuthorizationDecision.APPROVED,
        operator="local-user",
        basis="逐次批准",
        decided_at=NOW,
        expires_at=NOW + timedelta(minutes=1),
    )
    assert valid_authorization.decision is AuthorizationDecision.APPROVED
    with pytest.raises(ValidationError, match="授权过期"):
        valid_authorization.model_copy(
            update={"expires_at": NOW - timedelta(seconds=1)}
        ).__class__.model_validate(
            {
                **valid_authorization.model_dump(),
                "expires_at": NOW - timedelta(seconds=1),
            }
        )

    valid_lease = LeaseRecord(
        lease_id=LeaseId.new(),
        operation_id=operation_id,
        starts_at=NOW,
        expires_at=NOW + timedelta(minutes=5),
    )
    assert valid_lease.revoked_at is None
    with pytest.raises(ValidationError, match="结束时间"):
        LeaseRecord.model_validate({**valid_lease.model_dump(), "expires_at": NOW})
    with pytest.raises(ValidationError, match="撤销时间"):
        LeaseRecord.model_validate(
            {**valid_lease.model_dump(), "revoked_at": NOW - timedelta(seconds=1)}
        )

    success = CleanupRecord(
        operation_id=operation_id,
        result=CleanupResult.SUCCEEDED,
        reason="资源已删除",
        completed_at=NOW,
    )
    assert success.manual_action is None
    with pytest.raises(ValidationError, match="人工处理"):
        CleanupRecord(
            operation_id=operation_id,
            result=CleanupResult.OWNERSHIP_MISMATCH,
            reason="资源指纹不同",
            completed_at=NOW,
        )


def test_state_machine_accepts_success_rollback_and_terminal_paths() -> None:
    success = OperationRecord.planned(plan())
    for index, status in enumerate(
        (
            OperationStatus.AWAITING_AUTHORIZATION,
            OperationStatus.AUTHORIZED,
            OperationStatus.EXECUTING,
            OperationStatus.VERIFYING,
            OperationStatus.SUCCEEDED,
            OperationStatus.EXPIRING,
            OperationStatus.EXPIRED,
        ),
        start=1,
    ):
        success = transition_operation(
            success,
            status,
            reason=f"step-{index}",
            occurred_at=NOW + timedelta(seconds=index),
        )
    assert success.status is OperationStatus.EXPIRED

    rollback = OperationRecord.planned(plan())
    for index, status in enumerate(
        (
            OperationStatus.AUTHORIZED,
            OperationStatus.EXECUTING,
            OperationStatus.ROLLING_BACK,
            OperationStatus.ROLLED_BACK,
        ),
        start=1,
    ):
        rollback = transition_operation(
            rollback,
            status,
            reason=status.value,
            occurred_at=NOW + timedelta(seconds=index),
        )
    assert rollback.status is OperationStatus.ROLLED_BACK

    cleanup_failed = OperationRecord.planned(plan())
    cleanup_failed = transition_operation(
        cleanup_failed,
        OperationStatus.AUTHORIZED,
        reason="预授权",
        occurred_at=NOW + timedelta(seconds=1),
    )
    cleanup_failed = transition_operation(
        cleanup_failed,
        OperationStatus.EXECUTING,
        reason="执行",
        occurred_at=NOW + timedelta(seconds=2),
    )
    cleanup_failed = transition_operation(
        cleanup_failed,
        OperationStatus.ROLLING_BACK,
        reason="执行失败",
        occurred_at=NOW + timedelta(seconds=3),
    )
    cleanup_failed = transition_operation(
        cleanup_failed,
        OperationStatus.CLEANUP_FAILED,
        reason="所有权不匹配",
        occurred_at=NOW + timedelta(seconds=4),
    )
    assert cleanup_failed.status is OperationStatus.CLEANUP_FAILED

    for final_status in (
        OperationStatus.REJECTED,
        OperationStatus.CANCELLED,
        OperationStatus.AUTHORIZATION_EXPIRED,
    ):
        record = OperationRecord.planned(plan())
        if final_status is not OperationStatus.CANCELLED:
            record = transition_operation(
                record,
                OperationStatus.AWAITING_AUTHORIZATION,
                reason="需要授权",
                occurred_at=NOW + timedelta(seconds=1),
            )
        record = transition_operation(
            record,
            final_status,
            reason=final_status.value,
            occurred_at=NOW + timedelta(seconds=2),
        )
        assert record.status is final_status


def test_state_machine_rejects_illegal_or_time_reversed_history() -> None:
    record = OperationRecord.planned(plan())
    with pytest.raises(ValueError, match="不允许"):
        transition_operation(
            record,
            OperationStatus.SUCCEEDED,
            reason="跳过执行",
            occurred_at=NOW + timedelta(seconds=1),
        )
    with pytest.raises(ValidationError, match="时间不得倒退"):
        transition_operation(
            record,
            OperationStatus.AUTHORIZED,
            reason="时间倒退",
            occurred_at=NOW - timedelta(seconds=1),
        )

    initial = record.transitions[0]
    invalid_cases = (
        {"transitions": (), "match": "至少需要"},
        {
            "transitions": (
                initial,
                OperationTransition(
                    from_status=OperationStatus.AUTHORIZED,
                    to_status=OperationStatus.EXECUTING,
                    reason="断裂",
                    occurred_at=NOW + timedelta(seconds=1),
                ),
            ),
            "match": "不连续",
        },
        {
            "transitions": (
                initial,
                OperationTransition(
                    from_status=OperationStatus.PLANNED,
                    to_status=OperationStatus.SUCCEEDED,
                    reason="非法",
                    occurred_at=NOW + timedelta(seconds=1),
                ),
            ),
            "match": "非法转换",
        },
        {"status": OperationStatus.AUTHORIZED, "match": "当前状态"},
        {"updated_at": NOW - timedelta(seconds=1), "match": "更新时间"},
    )
    for case in invalid_cases:
        match = str(case["match"])
        values = record.model_dump()
        values.update({key: value for key, value in case.items() if key != "match"})
        with pytest.raises(ValidationError, match=match):
            OperationRecord.model_validate(values)


def test_aggregate_rejects_child_from_another_operation() -> None:
    record = full_record()
    assert record.authorization is not None
    foreign = record.authorization.model_copy(update={"operation_id": OperationId.new()})
    with pytest.raises(ValidationError, match="同一个"):
        OperationRecord.model_validate({**record.model_dump(), "authorization": foreign})


def test_summary_exposes_lifecycle_but_redacts_authentication_material() -> None:
    record = full_record()
    assert record.authorization is not None
    record = record.model_copy(
        update={
            "authorization": record.authorization.model_copy(
                update={"basis": "Authorization: secret-value，由本地用户批准"}
            ),
            "error": OperationError(
                code=OperationErrorCode.EXECUTION_FAILED,
                message="Bearer hidden-token 不能访问",
                correlation_id="corr-redact",
            ),
        }
    )
    summary = OperationSummary.from_record(record)
    serialized = summary.model_dump_json()
    assert summary.absolute_expires_at is not None
    assert summary.resource_ids
    assert summary.verification_results == (VerificationResult.PASSED,)
    assert summary.cleanup_result is CleanupResult.SUCCEEDED
    assert "secret-value" not in serialized
    assert "hidden-token" not in serialized

    empty = OperationSummary.from_record(OperationRecord.planned(plan()))
    assert empty.authorization_kind is None
    assert empty.authorization_basis is None
    assert empty.absolute_expires_at is None
    assert empty.cleanup_result is None
    assert empty.error is None


def test_access_scope_rejects_out_of_range_values() -> None:
    with pytest.raises(ValidationError):
        AccessScope(
            allowed_peer_id=NodeId.new(),
            bind_host="10.77.0.1",
            bind_port=80,
            duration_seconds=0,
        )
