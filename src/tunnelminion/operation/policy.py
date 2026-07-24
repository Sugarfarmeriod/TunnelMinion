"""目标节点拥有最终决定权的确定性操作策略。"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict

from tunnelminion.domain.identifiers import AuthorizationId, OperationId
from tunnelminion.operation.contracts import (
    AuthorizationDecision,
    AuthorizationKind,
    AuthorizationRecord,
    OperationLevel,
    OperationPlan,
    OperationRecord,
    OperationStatus,
    OperationStore,
    Preauthorization,
    PreauthorizationStore,
    transition_operation,
)
from tunnelminion.tools.registry import ToolRegistry


class PolicyAction(StrEnum):
    """策略对候选计划作出的确定性动作。"""

    EXECUTE = "execute"
    AWAIT_AUTHORIZATION = "await_authorization"
    PLAN_ONLY = "plan_only"
    REFUSE = "refuse"


class OperationPolicyDecision(BaseModel):
    """不依赖模型描述的风险等级与授权结果。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    action: PolicyAction
    actual_level: OperationLevel
    code: str
    basis: str
    matched_authorization_id: AuthorizationId | None = None


class OperationPolicy:
    """根据固定工具注册和本地预授权判断候选计划。"""

    def __init__(
        self,
        registry: ToolRegistry,
        preauthorizations: PreauthorizationStore,
    ) -> None:
        self._registry = registry
        self._preauthorizations = preauthorizations

    def evaluate(self, plan: OperationPlan, *, at: datetime) -> OperationPolicyDecision:
        """模型声明不影响注册表中的实际等级。"""
        entry = self._registry.lookup(plan.tool_name)
        if entry is None:
            return OperationPolicyDecision(
                action=PolicyAction.REFUSE,
                actual_level=OperationLevel.L4,
                code="tool_not_registered",
                basis="目标节点没有注册该执行工具",
            )
        level = entry.operation_level
        if plan.level is not level:
            return OperationPolicyDecision(
                action=PolicyAction.REFUSE,
                actual_level=level,
                code="model_level_mismatch",
                basis="计划等级与目标节点确定性注册表不一致",
            )
        if level is OperationLevel.L0:
            return OperationPolicyDecision(
                action=PolicyAction.EXECUTE,
                actual_level=level,
                code="read_only",
                basis="L0 只读工具可以自动执行",
            )
        if level is OperationLevel.L1:
            return OperationPolicyDecision(
                action=PolicyAction.PLAN_ONLY,
                actual_level=level,
                code="advice_only",
                basis="L1 只生成建议，不执行写操作",
            )
        if level is OperationLevel.L2:
            matched = next(
                (
                    item
                    for item in self._preauthorizations.list_active(at=at)
                    if item.matches(plan, at=at)
                ),
                None,
            )
            if matched is not None:
                return OperationPolicyDecision(
                    action=PolicyAction.EXECUTE,
                    actual_level=level,
                    code="preauthorization_matched",
                    basis="计划完整命中目标节点本地预授权",
                    matched_authorization_id=matched.authorization_id,
                )
            return OperationPolicyDecision(
                action=PolicyAction.AWAIT_AUTHORIZATION,
                actual_level=level,
                code="local_approval_required",
                basis="L2 默认需要目标节点本地用户逐次批准",
            )
        if level is OperationLevel.L3:
            return OperationPolicyDecision(
                action=PolicyAction.REFUSE,
                actual_level=level,
                code="sensitive_operation_not_supported",
                basis="本 change 不注册 L3 执行路径",
            )
        return OperationPolicyDecision(
            action=PolicyAction.REFUSE,
            actual_level=OperationLevel.L4,
            code="forbidden_operation",
            basis="L4 操作始终禁止",
        )


class AuthorizationService:
    """只接受目标节点本地控制面决定的授权服务。"""

    def __init__(
        self,
        operations: OperationStore,
        preauthorizations: PreauthorizationStore,
        policy: OperationPolicy,
    ) -> None:
        self._operations = operations
        self._preauthorizations = preauthorizations
        self._policy = policy

    @staticmethod
    def _require_local(local_control: bool) -> None:
        if not local_control:
            raise PermissionError("授权只能由目标节点本地控制面修改")

    def create_preauthorization(
        self,
        authorization: Preauthorization,
        *,
        local_control: bool,
    ) -> Preauthorization:
        """聊天或远端请求不能创建预授权。"""
        self._require_local(local_control)
        self._preauthorizations.put(authorization)
        return authorization

    def revoke_preauthorization(
        self,
        authorization_id: AuthorizationId,
        *,
        revoked_at: datetime,
        local_control: bool,
    ) -> Preauthorization:
        """撤销只影响尚未开始的新操作，不改写已执行租约。"""
        self._require_local(local_control)
        current = self._preauthorizations.get(authorization_id)
        if current is None:
            raise KeyError("预授权不存在")
        revoked = Preauthorization.model_validate(
            {**current.model_dump(), "revoked_at": revoked_at}
        )
        self._preauthorizations.put(revoked)
        return revoked

    def submit(self, record: OperationRecord, *, at: datetime) -> OperationRecord:
        """应用幂等和目标节点策略，绝不直接调用写适配器。"""
        existing = self._operations.get_by_idempotency_key(record.plan.idempotency_key)
        if existing is not None:
            return existing
        if record.status is not OperationStatus.PLANNED:
            raise ValueError("只有 planned 操作可以进入授权策略")
        decision = self._policy.evaluate(record.plan, at=at)
        if decision.action is PolicyAction.EXECUTE:
            kind = (
                AuthorizationKind.PREAUTHORIZATION
                if decision.matched_authorization_id is not None
                else AuthorizationKind.ONE_TIME
            )
            authorization = AuthorizationRecord(
                authorization_id=decision.matched_authorization_id or AuthorizationId.new(),
                operation_id=record.plan.operation_id,
                kind=kind,
                decision=AuthorizationDecision.APPROVED,
                operator="target-node-policy",
                basis=decision.basis,
                decided_at=at,
            )
            updated = record.model_copy(update={"authorization": authorization})
            updated = transition_operation(
                updated,
                OperationStatus.AUTHORIZED,
                reason=decision.basis,
                occurred_at=at,
            )
        elif decision.action is PolicyAction.AWAIT_AUTHORIZATION:
            updated = transition_operation(
                record,
                OperationStatus.AWAITING_AUTHORIZATION,
                reason=decision.basis,
                occurred_at=at,
            )
        else:
            updated = transition_operation(
                record,
                OperationStatus.CANCELLED,
                reason=decision.basis,
                occurred_at=at,
            )
        self._operations.put(updated)
        return updated

    def approve_once(
        self,
        operation_id: OperationId,
        *,
        operator: str,
        decided_at: datetime,
        expires_at: datetime,
        local_control: bool,
    ) -> OperationRecord:
        """记录目标节点本地逐次批准。"""
        self._require_local(local_control)
        record = self._required_operation(operation_id)
        if record.status is not OperationStatus.AWAITING_AUTHORIZATION:
            raise ValueError("操作当前不等待授权")
        authorization = AuthorizationRecord(
            authorization_id=AuthorizationId.new(),
            operation_id=operation_id,
            kind=AuthorizationKind.ONE_TIME,
            decision=AuthorizationDecision.APPROVED,
            operator=operator,
            basis="目标节点本地用户逐次批准",
            decided_at=decided_at,
            expires_at=expires_at,
        )
        updated = record.model_copy(update={"authorization": authorization})
        updated = transition_operation(
            updated,
            OperationStatus.AUTHORIZED,
            reason=authorization.basis,
            occurred_at=decided_at,
        )
        self._operations.put(updated)
        return updated

    def reject_once(
        self,
        operation_id: OperationId,
        *,
        operator: str,
        reason: str,
        decided_at: datetime,
        local_control: bool,
    ) -> OperationRecord:
        """记录目标节点本地拒绝且不创建任何资源。"""
        self._require_local(local_control)
        record = self._required_operation(operation_id)
        if record.status is not OperationStatus.AWAITING_AUTHORIZATION:
            raise ValueError("操作当前不等待授权")
        authorization = AuthorizationRecord(
            authorization_id=AuthorizationId.new(),
            operation_id=operation_id,
            kind=AuthorizationKind.ONE_TIME,
            decision=AuthorizationDecision.REJECTED,
            operator=operator,
            basis=reason,
            decided_at=decided_at,
        )
        updated = record.model_copy(update={"authorization": authorization})
        updated = transition_operation(
            updated,
            OperationStatus.REJECTED,
            reason=reason,
            occurred_at=decided_at,
        )
        self._operations.put(updated)
        return updated

    def expire_once(
        self,
        operation_id: OperationId,
        *,
        expired_at: datetime,
    ) -> OperationRecord:
        """在没有模型参与时终结已过期的逐次授权。"""
        record = self._required_operation(operation_id)
        if record.status not in {
            OperationStatus.AWAITING_AUTHORIZATION,
            OperationStatus.AUTHORIZED,
        }:
            raise ValueError("操作当前没有可过期的授权")
        updated = transition_operation(
            record,
            OperationStatus.AUTHORIZATION_EXPIRED,
            reason="授权有效期已经结束",
            occurred_at=expired_at,
        )
        self._operations.put(updated)
        return updated

    def cancel(
        self,
        operation_id: OperationId,
        *,
        reason: str,
        cancelled_at: datetime,
        local_control: bool,
    ) -> OperationRecord:
        """在执行开始前由目标节点本地用户取消操作。"""
        self._require_local(local_control)
        record = self._required_operation(operation_id)
        if record.status not in {
            OperationStatus.PLANNED,
            OperationStatus.AWAITING_AUTHORIZATION,
            OperationStatus.AUTHORIZED,
        }:
            raise ValueError("操作当前不能直接取消")
        updated = transition_operation(
            record,
            OperationStatus.CANCELLED,
            reason=reason,
            occurred_at=cancelled_at,
        )
        self._operations.put(updated)
        return updated

    def _required_operation(self, operation_id: OperationId) -> OperationRecord:
        record = self._operations.get(operation_id)
        if record is None:
            raise KeyError("操作不存在")
        return record
