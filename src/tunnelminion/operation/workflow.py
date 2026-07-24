"""批准操作的持久化执行、验证、回滚和恢复工作流。"""

from __future__ import annotations

import secrets
import time
from datetime import datetime, timedelta
from typing import Protocol

from pydantic import BaseModel, ConfigDict

from tunnelminion.domain.identifiers import (
    LeaseId,
    NodeId,
    OperationId,
    RunId,
    ThreadId,
    ToolRunId,
)
from tunnelminion.model.secrets import SecretStore
from tunnelminion.operation.contracts import (
    AccessScope,
    AuthorizationDecision,
    CleanupRecord,
    CleanupResult,
    LeaseRecord,
    OperationError,
    OperationErrorCode,
    OperationLevel,
    OperationMetrics,
    OperationPlan,
    OperationRecord,
    OperationStatus,
    OperationStore,
    ResourceOwnership,
    ServiceEvidence,
    VerificationRecord,
    VerificationResult,
    compute_idempotency_key,
    transition_operation,
)


def operation_token_name(operation_id: OperationId) -> str:
    """生成只在秘密存储中出现的访问令牌名称。"""
    return f"operation-access-token:{operation_id}"


def build_operation_plan(
    *,
    request_node_id: NodeId,
    target_node_id: NodeId,
    thread_id: ThreadId,
    run_id: RunId,
    tool_run_ids: tuple[ToolRunId, ...],
    tool_name: str,
    level: OperationLevel,
    service: ServiceEvidence,
    expected_change: str,
    access_scope: AccessScope,
    risk_summary: str,
    verification_method: str,
    rollback_method: str,
    created_at: datetime,
    plan_version: int = 1,
    operation_id: OperationId | None = None,
) -> OperationPlan:
    """从全部必填字段构造带稳定幂等键的计划。"""
    identifier = operation_id or OperationId.new()
    return OperationPlan(
        operation_id=identifier,
        plan_version=plan_version,
        idempotency_key=compute_idempotency_key(
            request_node_id=request_node_id,
            target_node_id=target_node_id,
            tool_name=tool_name,
            plan_version=plan_version,
            service_fingerprint=service.fingerprint,
            access_scope=access_scope,
        ),
        request_node_id=request_node_id,
        target_node_id=target_node_id,
        thread_id=thread_id,
        run_id=run_id,
        tool_run_ids=tool_run_ids,
        tool_name=tool_name,
        level=level,
        service=service,
        expected_change=expected_change,
        access_scope=access_scope,
        risk_summary=risk_summary,
        verification_method=verification_method,
        rollback_method=rollback_method,
        created_at=created_at,
    )


class AdapterExecutionResult(BaseModel):
    """固定共享适配器返回的资源或脱敏失败。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    resources: tuple[ResourceOwnership, ...] = ()
    error: OperationError | None = None


class ServiceEvidenceProvider(Protocol):
    """执行前重新读取实时服务状态。"""

    async def read(self, service_id: str) -> ServiceEvidence | None: ...


class SharingAdapter(Protocol):
    """只管理 TunnelMinion 自有共享资源的适配器。"""

    async def create(
        self,
        plan: OperationPlan,
        lease: LeaseRecord,
        access_token: str,
    ) -> AdapterExecutionResult: ...

    async def cleanup(
        self,
        operation_id: OperationId,
        resources: tuple[ResourceOwnership, ...],
        *,
        at: datetime,
    ) -> CleanupRecord: ...


class RequesterVerifier(Protocol):
    """请求节点沿真实私网路径执行的独立验证。"""

    async def verify(
        self,
        plan: OperationPlan,
        lease: LeaseRecord,
        access_token: str,
    ) -> VerificationRecord: ...


class WorkflowUsage(BaseModel):
    """执行前已经产生的模型和工具用量。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    model_input_tokens: int = 0
    model_output_tokens: int = 0
    model_cost_usd: float = 0
    tool_call_count: int = 0


class OperationWorkflow:
    """不让模型接触写适配器的确定性工作流。"""

    def __init__(
        self,
        operations: OperationStore,
        secrets_store: SecretStore,
        evidence: ServiceEvidenceProvider,
        adapter: SharingAdapter,
        verifier: RequesterVerifier,
    ) -> None:
        self._operations = operations
        self._secrets = secrets_store
        self._evidence = evidence
        self._adapter = adapter
        self._verifier = verifier

    async def execute_authorized(
        self,
        operation_id: OperationId,
        *,
        at: datetime,
        usage: WorkflowUsage | None = None,
    ) -> OperationRecord:
        """重读实时状态后执行一次已授权操作，绝不重放已有执行。"""
        usage = usage or WorkflowUsage()
        started = time.perf_counter()
        record = self._required(operation_id)
        if record.status is not OperationStatus.AUTHORIZED:
            raise ValueError("只有 authorized 操作可以执行")
        authorization = record.authorization
        if authorization is None or authorization.decision is not AuthorizationDecision.APPROVED:
            raise ValueError("操作缺少有效批准记录")
        if authorization.expires_at is not None and authorization.expires_at <= at:
            expired = transition_operation(
                record,
                OperationStatus.AUTHORIZATION_EXPIRED,
                reason="授权在执行前已经过期",
                occurred_at=at,
            )
            return self._finish(expired, usage, started, "authorization_expired")

        current = await self._evidence.read(record.plan.service.service_id)
        if current is None or current.fingerprint != record.plan.service.fingerprint:
            error = OperationError(
                code=OperationErrorCode.SERVICE_CHANGED,
                message="目标服务实时状态与已批准计划不一致",
                correlation_id=str(operation_id),
            )
            return await self._rollback(
                record.model_copy(update={"error": error}),
                at=at,
                usage=usage,
                started=started,
                final_result="service_changed",
            )

        lease = LeaseRecord(
            lease_id=LeaseId.new(),
            operation_id=operation_id,
            starts_at=at,
            expires_at=at + timedelta(seconds=record.plan.access_scope.duration_seconds),
        )
        executing = record.model_copy(update={"lease": lease})
        executing = transition_operation(
            executing,
            OperationStatus.EXECUTING,
            reason="实时服务指纹与授权计划一致",
            occurred_at=at,
        )
        self._operations.put(executing)
        token_name = operation_token_name(operation_id)
        access_token = secrets.token_urlsafe(32)
        self._secrets.set(token_name, access_token)

        try:
            execution = await self._adapter.create(executing.plan, lease, access_token)
        except Exception:
            execution = AdapterExecutionResult(
                error=OperationError(
                    code=OperationErrorCode.EXECUTION_FAILED,
                    message="共享适配器执行失败",
                    retryable=True,
                    correlation_id=str(operation_id),
                )
            )
        if execution.error is not None:
            failed = executing.model_copy(
                update={"resources": execution.resources, "error": execution.error}
            )
            return await self._rollback(
                failed,
                at=at,
                usage=usage,
                started=started,
                final_result="execution_failed",
            )

        verifying = executing.model_copy(update={"resources": execution.resources})
        verifying = transition_operation(
            verifying,
            OperationStatus.VERIFYING,
            reason="目标节点已创建自有入口，等待请求节点独立验证",
            occurred_at=at,
        )
        self._operations.put(verifying)
        try:
            verification = await self._verifier.verify(verifying.plan, lease, access_token)
        except Exception:
            verification = VerificationRecord(
                operation_id=operation_id,
                verifier_node_id=record.plan.request_node_id,
                result=VerificationResult.TIMEOUT,
                evidence_summary="请求节点验证未返回有效结果",
                verified_at=at,
            )
        verified = verifying.model_copy(
            update={"verifications": (*verifying.verifications, verification)}
        )
        if verification.result is not VerificationResult.PASSED:
            error = OperationError(
                code=OperationErrorCode.VERIFICATION_FAILED,
                message="请求节点未能独立验证临时入口",
                correlation_id=str(operation_id),
            )
            return await self._rollback(
                verified.model_copy(update={"error": error}),
                at=at,
                usage=usage,
                started=started,
                final_result="verification_failed",
            )

        succeeded = transition_operation(
            verified,
            OperationStatus.SUCCEEDED,
            reason="请求节点独立验证通过",
            occurred_at=verification.verified_at,
        )
        return self._finish(succeeded, usage, started, "succeeded")

    async def revoke(
        self,
        operation_id: OperationId,
        *,
        at: datetime,
    ) -> OperationRecord:
        """不依赖模型撤销已经创建的入口。"""
        record = self._required(operation_id)
        if record.status is not OperationStatus.SUCCEEDED:
            raise ValueError("只有 succeeded 操作可以按资源回滚方式撤销")
        return await self._rollback(
            record,
            at=at,
            usage=WorkflowUsage(),
            started=time.perf_counter(),
            final_result="revoked",
        )

    async def expire_due(self, *, at: datetime) -> tuple[OperationRecord, ...]:
        """清理达到绝对过期时间的成功入口。"""
        results: list[OperationRecord] = []
        for record in self._operations.list_unfinished():
            if (
                record.status is OperationStatus.SUCCEEDED
                and record.lease is not None
                and record.lease.expires_at <= at
            ):
                expiring = transition_operation(
                    record,
                    OperationStatus.EXPIRING,
                    reason="共享租约达到绝对过期时间",
                    occurred_at=at,
                )
                self._operations.put(expiring)
                results.append(await self._finish_expiry(expiring, at=at))
        return tuple(results)

    async def recover_unfinished(self, *, at: datetime) -> tuple[OperationRecord, ...]:
        """重启后只检查并清理副作用，不重放写步骤。"""
        recovered: list[OperationRecord] = list(await self.expire_due(at=at))
        for record in self._operations.list_unfinished():
            if record.status in {OperationStatus.EXECUTING, OperationStatus.VERIFYING}:
                recovered.append(
                    await self._rollback(
                        record,
                        at=at,
                        usage=WorkflowUsage(),
                        started=time.perf_counter(),
                        final_result="recovered_without_replay",
                    )
                )
            elif record.status is OperationStatus.ROLLING_BACK:
                recovered.append(await self._complete_rollback(record, at=at))
        return tuple(recovered)

    async def _rollback(
        self,
        record: OperationRecord,
        *,
        at: datetime,
        usage: WorkflowUsage,
        started: float,
        final_result: str,
    ) -> OperationRecord:
        rolling_back = transition_operation(
            record,
            OperationStatus.ROLLING_BACK,
            reason=final_result,
            occurred_at=at,
        )
        self._operations.put(rolling_back)
        completed = await self._complete_rollback(rolling_back, at=at)
        return self._finish(completed, usage, started, final_result)

    async def _complete_rollback(
        self,
        record: OperationRecord,
        *,
        at: datetime,
    ) -> OperationRecord:
        cleanup = await self._safe_cleanup(record, at=at)
        target = (
            OperationStatus.ROLLED_BACK
            if cleanup.result is CleanupResult.SUCCEEDED
            else OperationStatus.CLEANUP_FAILED
        )
        completed = record.model_copy(update={"cleanup": cleanup})
        completed = transition_operation(
            completed,
            target,
            reason=cleanup.reason,
            occurred_at=cleanup.completed_at,
        )
        self._secrets.delete(operation_token_name(record.plan.operation_id))
        self._operations.put(completed)
        return completed

    async def _finish_expiry(self, record: OperationRecord, *, at: datetime) -> OperationRecord:
        cleanup = await self._safe_cleanup(record, at=at)
        target = (
            OperationStatus.EXPIRED
            if cleanup.result is CleanupResult.SUCCEEDED
            else OperationStatus.CLEANUP_FAILED
        )
        completed = record.model_copy(update={"cleanup": cleanup})
        completed = transition_operation(
            completed,
            target,
            reason=cleanup.reason,
            occurred_at=cleanup.completed_at,
        )
        self._secrets.delete(operation_token_name(record.plan.operation_id))
        self._operations.put(completed)
        return completed

    async def _safe_cleanup(
        self,
        record: OperationRecord,
        *,
        at: datetime,
    ) -> CleanupRecord:
        try:
            return await self._adapter.cleanup(
                record.plan.operation_id,
                record.resources,
                at=at,
            )
        except Exception:
            return CleanupRecord(
                operation_id=record.plan.operation_id,
                result=CleanupResult.FAILED,
                reason="共享适配器清理失败",
                manual_action="在目标节点检查该操作记录的自有代理进程",
                completed_at=at,
            )

    def _finish(
        self,
        record: OperationRecord,
        usage: WorkflowUsage,
        started: float,
        final_result: str,
    ) -> OperationRecord:
        elapsed_ms = max(0, round((time.perf_counter() - started) * 1000))
        metrics = OperationMetrics(
            phase_latency_ms={"workflow_total": elapsed_ms},
            model_input_tokens=usage.model_input_tokens,
            model_output_tokens=usage.model_output_tokens,
            model_cost_usd=usage.model_cost_usd,
            tool_call_count=usage.tool_call_count,
            authorization_kind=(
                record.authorization.kind if record.authorization is not None else None
            ),
            final_result=final_result,
        )
        completed = OperationRecord.model_validate({**record.model_dump(), "metrics": metrics})
        self._operations.put(completed)
        return completed

    def _required(self, operation_id: OperationId) -> OperationRecord:
        record = self._operations.get(operation_id)
        if record is None:
            raise KeyError("操作不存在")
        return record
