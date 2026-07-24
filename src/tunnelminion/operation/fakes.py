"""批准操作工作流使用的确定性假适配器。"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from tunnelminion.domain.identifiers import NodeId, OperationId, ResourceId
from tunnelminion.operation.contracts import (
    CleanupRecord,
    CleanupResult,
    LeaseRecord,
    OperationError,
    OperationErrorCode,
    OperationPlan,
    ResourceOwnership,
    ServiceEvidence,
    VerificationRecord,
    VerificationResult,
)
from tunnelminion.operation.workflow import AdapterExecutionResult


class FakeAdapterBehavior(StrEnum):
    """假共享适配器的可注入结果。"""

    SUCCESS = "success"
    EXECUTION_FAILURE = "execution_failure"
    EXECUTION_EXCEPTION = "execution_exception"
    CLEANUP_FAILURE = "cleanup_failure"
    CLEANUP_EXCEPTION = "cleanup_exception"
    OWNERSHIP_MISMATCH = "ownership_mismatch"


class FakeServiceEvidenceProvider:
    """返回可在测试中替换的实时服务证据。"""

    def __init__(self, current: ServiceEvidence | None) -> None:
        self.current = current
        self.reads = 0

    async def read(self, service_id: str) -> ServiceEvidence | None:
        self.reads += 1
        if self.current is not None and self.current.service_id != service_id:
            return None
        return self.current


class FakeSharingAdapter:
    """不创建监听资源但保留调用与所有权语义。"""

    def __init__(self, behavior: FakeAdapterBehavior = FakeAdapterBehavior.SUCCESS) -> None:
        self.behavior = behavior
        self.create_calls = 0
        self.cleanup_calls = 0
        self.active_resources: dict[str, ResourceOwnership] = {}

    async def create(
        self,
        plan: OperationPlan,
        lease: LeaseRecord,
        access_token: str,
    ) -> AdapterExecutionResult:
        del lease
        self.create_calls += 1
        if len(access_token) < 32:
            raise ValueError("假适配器也要求高熵访问令牌")
        if self.behavior is FakeAdapterBehavior.EXECUTION_EXCEPTION:
            raise RuntimeError("injected execution exception")
        resource = ResourceOwnership(
            resource_id=ResourceId.new(),
            operation_id=plan.operation_id,
            kind="fake_http_proxy",
            bind_host=plan.access_scope.bind_host,
            bind_port=plan.access_scope.bind_port,
            owner_fingerprint=f"sha256:{'3' * 64}",
            process_id=1234,
            created_at=plan.created_at,
        )
        self.active_resources[str(resource.resource_id)] = resource
        if self.behavior is FakeAdapterBehavior.EXECUTION_FAILURE:
            return AdapterExecutionResult(
                resources=(resource,),
                error=OperationError(
                    code=OperationErrorCode.EXECUTION_FAILED,
                    message="注入的执行失败",
                    correlation_id=str(plan.operation_id),
                ),
            )
        return AdapterExecutionResult(resources=(resource,))

    async def cleanup(
        self,
        operation_id: OperationId,
        resources: tuple[ResourceOwnership, ...],
        *,
        at: datetime,
    ) -> CleanupRecord:
        self.cleanup_calls += 1
        if self.behavior is FakeAdapterBehavior.CLEANUP_EXCEPTION:
            raise RuntimeError("injected cleanup exception")
        if self.behavior is FakeAdapterBehavior.OWNERSHIP_MISMATCH:
            return CleanupRecord(
                operation_id=operation_id,
                result=CleanupResult.OWNERSHIP_MISMATCH,
                reason="资源指纹不匹配，未删除未知资源",
                manual_action="在目标节点核对端口占用者",
                completed_at=at,
            )
        if self.behavior is FakeAdapterBehavior.CLEANUP_FAILURE:
            return CleanupRecord(
                operation_id=operation_id,
                result=CleanupResult.FAILED,
                reason="注入的清理失败",
                manual_action="停止测试自有资源",
                completed_at=at,
            )
        for resource in resources:
            self.active_resources.pop(str(resource.resource_id), None)
        return CleanupRecord(
            operation_id=operation_id,
            result=CleanupResult.SUCCEEDED,
            reason="假适配器已清理全部自有资源",
            completed_at=at,
        )


class FakeRequesterVerifier:
    """返回指定请求节点验证结果或注入异常。"""

    def __init__(
        self,
        requester_node_id: NodeId,
        result: VerificationResult = VerificationResult.PASSED,
        *,
        raise_error: bool = False,
    ) -> None:
        self.requester_node_id = requester_node_id
        self.result = result
        self.raise_error = raise_error
        self.calls = 0

    async def verify(
        self,
        plan: OperationPlan,
        lease: LeaseRecord,
        access_token: str,
    ) -> VerificationRecord:
        self.calls += 1
        if self.raise_error:
            raise TimeoutError("injected verifier timeout")
        if len(access_token) < 32:
            raise ValueError("请求节点收到的令牌不满足测试预算")
        return VerificationRecord(
            operation_id=plan.operation_id,
            verifier_node_id=self.requester_node_id,
            result=self.result,
            status_code=200 if self.result is VerificationResult.PASSED else None,
            evidence_summary="假请求节点验证结果",
            verified_at=lease.starts_at,
        )
