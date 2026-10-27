"""跨电脑修复只公开批准和进度所需的摘要。"""

from datetime import timedelta

from tunnelminion.gateway.contracts import PeerRepairView
from tunnelminion.operation.contracts import AuthorizationDecision, OperationStatus
from tunnelminion.repair.contracts import REPAIR_AUTHORIZATION_SECONDS, RepairRecord


def peer_repair_view(record: RepairRecord) -> PeerRepairView:
    """明确列出可公开字段，完整目标、执行记录和本机审计留在服务所在节点。"""
    plan = record.plan
    authorization = record.authorization
    return PeerRepairView(
        repair_id=plan.operation_id,
        node_id=plan.node_id,
        service_name=plan.service_name,
        kind=plan.kind,
        status=record.status,
        action_summary=plan.action_summary,
        reason=plan.reason,
        impact_summary=plan.impact_summary,
        verification_summary=plan.verification_summary,
        failure_summary=plan.failure_summary,
        created_at=plan.created_at,
        updated_at=record.updated_at,
        approval_expires_at=(
            plan.created_at + timedelta(seconds=REPAIR_AUTHORIZATION_SECONDS)
            if record.status is OperationStatus.AWAITING_AUTHORIZATION
            else None
        ),
        approved_by_peer=(
            authorization.operator.startswith("peer:")
            if authorization is not None
            and authorization.decision is AuthorizationDecision.APPROVED
            else None
        ),
        verification_passed=record.verification.passed if record.verification is not None else None,
        error_code=record.error.code if record.error is not None else None,
        error_message=record.error.message if record.error is not None else None,
    )
