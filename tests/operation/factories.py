"""批准操作测试数据工厂。"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from tunnelminion.domain.identifiers import (
    AuthorizationId,
    LeaseId,
    NodeId,
    OperationId,
    ResourceId,
    RunId,
    ThreadId,
    ToolRunId,
)
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
    OperationLevel,
    OperationPlan,
    OperationRecord,
    ResourceOwnership,
    ServiceEvidence,
    VerificationRecord,
    VerificationResult,
    compute_idempotency_key,
)

NOW = datetime(2026, 7, 24, 8, 0, tzinfo=UTC)
FINGERPRINT = f"sha256:{'1' * 64}"
RESOURCE_FINGERPRINT = f"sha256:{'2' * 64}"


def plan(**updates: object) -> OperationPlan:
    request_node = NodeId.new()
    target_node = NodeId.new()
    scope = AccessScope(
        allowed_peer_id=request_node,
        bind_host="10.77.0.1",
        bind_port=18881,
        duration_seconds=300,
    )
    values: dict[str, object] = {
        "operation_id": OperationId.new(),
        "plan_version": 1,
        "idempotency_key": compute_idempotency_key(
            request_node_id=request_node,
            target_node_id=target_node,
            tool_name="share_local_http_service",
            plan_version=1,
            service_fingerprint=FINGERPRINT,
            access_scope=scope,
        ),
        "request_node_id": request_node,
        "target_node_id": target_node,
        "thread_id": ThreadId.new(),
        "run_id": RunId.new(),
        "tool_run_ids": (ToolRunId.new(),),
        "tool_name": "share_local_http_service",
        "level": OperationLevel.L2,
        "service": ServiceEvidence(
            service_id="home-dashboard",
            scheme="http",
            host="127.0.0.1",
            port=8080,
            process_or_container="fixture",
            fingerprint=FINGERPRINT,
            observed_at=NOW,
        ),
        "expected_change": "创建一个临时私网 HTTP 入口。",
        "access_scope": scope,
        "risk_summary": "指定 peer 可在五分钟内访问服务。",
        "verification_method": "请求节点沿 WireGuard 发起 GET 探测。",
        "rollback_method": "停止本次代理并确认端口释放。",
        "created_at": NOW,
    }
    values.update(updates)
    return OperationPlan.model_validate(values)


def full_record() -> OperationRecord:
    operation_plan = plan()
    operation_id = operation_plan.operation_id
    return OperationRecord.planned(operation_plan).model_copy(
        update={
            "authorization": AuthorizationRecord(
                authorization_id=AuthorizationId.new(),
                operation_id=operation_id,
                kind=AuthorizationKind.ONE_TIME,
                decision=AuthorizationDecision.APPROVED,
                operator="target-local-user",
                basis="本地页面逐次批准",
                decided_at=NOW + timedelta(seconds=1),
                expires_at=NOW + timedelta(minutes=1),
            ),
            "lease": LeaseRecord(
                lease_id=LeaseId.new(),
                operation_id=operation_id,
                starts_at=NOW + timedelta(seconds=2),
                expires_at=NOW + timedelta(minutes=5),
            ),
            "resources": (
                ResourceOwnership(
                    resource_id=ResourceId.new(),
                    operation_id=operation_id,
                    kind="embedded_http_proxy",
                    bind_host="10.77.0.1",
                    bind_port=18881,
                    owner_fingerprint=RESOURCE_FINGERPRINT,
                    process_id=1234,
                    created_at=NOW + timedelta(seconds=2),
                ),
            ),
            "verifications": (
                VerificationRecord(
                    operation_id=operation_id,
                    verifier_node_id=operation_plan.request_node_id,
                    result=VerificationResult.PASSED,
                    status_code=200,
                    evidence_summary="健康判据满足",
                    verified_at=NOW + timedelta(seconds=3),
                ),
            ),
            "cleanup": CleanupRecord(
                operation_id=operation_id,
                result=CleanupResult.SUCCEEDED,
                reason="租约到期后端口已经释放",
                completed_at=NOW + timedelta(minutes=5),
            ),
            "error": OperationError(
                code=OperationErrorCode.VERIFICATION_FAILED,
                message="历史失败已恢复",
                correlation_id="corr-test",
            ),
        }
    )
