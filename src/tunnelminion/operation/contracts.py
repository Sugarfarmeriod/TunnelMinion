"""跨节点批准操作使用的稳定、无秘密领域契约。"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime
from enum import IntEnum, StrEnum
from typing import Protocol, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

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
from tunnelminion.domain.versioning import ProtocolVersion

OPERATION_PROTOCOL_VERSION = ProtocolVersion(major=1, minor=0)
_SENSITIVE_TEXT = re.compile(
    r"(?i)(authorization|x-tunnelminion-share-token)\s*[:=]\s*\S+"
    r"|bearer\s+\S+"
    r"|tmn_share_[A-Za-z0-9_-]+"
)


def _redact_public_text(value: str) -> str:
    """移除摘要中意外出现的常见认证材料。"""
    return _SENSITIVE_TEXT.sub("[REDACTED]", value)


class OperationLevel(IntEnum):
    """确定性策略使用的 L0-L4 操作等级。"""

    L0 = 0
    L1 = 1
    L2 = 2
    L3 = 3
    L4 = 4


class OperationStatus(StrEnum):
    """批准操作的全部持久化生命周期状态。"""

    PLANNED = "planned"
    AWAITING_AUTHORIZATION = "awaiting_authorization"
    AUTHORIZED = "authorized"
    EXECUTING = "executing"
    VERIFYING = "verifying"
    SUCCEEDED = "succeeded"
    EXPIRING = "expiring"
    EXPIRED = "expired"
    ROLLING_BACK = "rolling_back"
    ROLLED_BACK = "rolled_back"
    CLEANUP_FAILED = "cleanup_failed"
    REJECTED = "rejected"
    CANCELLED = "cancelled"
    AUTHORIZATION_EXPIRED = "authorization_expired"


TERMINAL_OPERATION_STATUSES = frozenset(
    {
        OperationStatus.EXPIRED,
        OperationStatus.ROLLED_BACK,
        OperationStatus.CLEANUP_FAILED,
        OperationStatus.REJECTED,
        OperationStatus.CANCELLED,
        OperationStatus.AUTHORIZATION_EXPIRED,
    }
)

_ALLOWED_TRANSITIONS: dict[OperationStatus, frozenset[OperationStatus]] = {
    OperationStatus.PLANNED: frozenset(
        {
            OperationStatus.AWAITING_AUTHORIZATION,
            OperationStatus.AUTHORIZED,
            OperationStatus.CANCELLED,
        }
    ),
    OperationStatus.AWAITING_AUTHORIZATION: frozenset(
        {
            OperationStatus.AUTHORIZED,
            OperationStatus.REJECTED,
            OperationStatus.CANCELLED,
            OperationStatus.AUTHORIZATION_EXPIRED,
        }
    ),
    OperationStatus.AUTHORIZED: frozenset(
        {
            OperationStatus.EXECUTING,
            OperationStatus.ROLLING_BACK,
            OperationStatus.CANCELLED,
            OperationStatus.AUTHORIZATION_EXPIRED,
        }
    ),
    OperationStatus.EXECUTING: frozenset({OperationStatus.VERIFYING, OperationStatus.ROLLING_BACK}),
    OperationStatus.VERIFYING: frozenset({OperationStatus.SUCCEEDED, OperationStatus.ROLLING_BACK}),
    OperationStatus.SUCCEEDED: frozenset({OperationStatus.EXPIRING, OperationStatus.ROLLING_BACK}),
    OperationStatus.EXPIRING: frozenset({OperationStatus.EXPIRED, OperationStatus.CLEANUP_FAILED}),
    OperationStatus.ROLLING_BACK: frozenset(
        {OperationStatus.ROLLED_BACK, OperationStatus.CLEANUP_FAILED}
    ),
}


class ServiceEvidence(BaseModel):
    """执行前必须重新确认的本机服务指纹。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    service_id: str = Field(min_length=1, max_length=128)
    scheme: str = Field(pattern=r"^https?$")
    host: str = Field(min_length=1, max_length=255)
    port: int = Field(ge=1, le=65535)
    process_or_container: str = Field(min_length=1, max_length=256)
    fingerprint: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    observed_at: datetime


class AccessScope(BaseModel):
    """计划允许的唯一请求节点、私网入口和持续时间。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    allowed_peer_id: NodeId
    bind_host: str = Field(min_length=1, max_length=255)
    bind_port: int = Field(ge=1024, le=65535)
    duration_seconds: int = Field(ge=1, le=86_400)


def compute_idempotency_key(
    *,
    request_node_id: NodeId,
    target_node_id: NodeId,
    tool_name: str,
    plan_version: int,
    service_fingerprint: str,
    access_scope: AccessScope,
) -> str:
    """由稳定计划字段生成不包含秘密的幂等键。"""
    value = {
        "request_node_id": str(request_node_id),
        "target_node_id": str(target_node_id),
        "tool_name": tool_name,
        "plan_version": plan_version,
        "service_fingerprint": service_fingerprint,
        "access_scope": access_scope.model_dump(mode="json"),
    }
    canonical = json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    return f"opkey_{hashlib.sha256(canonical.encode()).hexdigest()}"


class OperationPlan(BaseModel):
    """经服务端复核后才能进入授权流程的结构化计划。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    protocol_version: ProtocolVersion = OPERATION_PROTOCOL_VERSION
    operation_id: OperationId
    plan_version: int = Field(ge=1)
    idempotency_key: str = Field(pattern=r"^opkey_[0-9a-f]{64}$")
    request_node_id: NodeId
    target_node_id: NodeId
    thread_id: ThreadId
    run_id: RunId
    tool_run_ids: tuple[ToolRunId, ...] = ()
    tool_name: str = Field(min_length=1, max_length=128)
    level: OperationLevel
    service: ServiceEvidence
    expected_change: str = Field(min_length=1, max_length=2_000)
    access_scope: AccessScope
    risk_summary: str = Field(min_length=1, max_length=2_000)
    verification_method: str = Field(min_length=1, max_length=2_000)
    rollback_method: str = Field(min_length=1, max_length=2_000)
    created_at: datetime

    @model_validator(mode="after")
    def validate_protocol_and_key(self) -> Self:
        if not OPERATION_PROTOCOL_VERSION.is_compatible_with(self.protocol_version):
            raise ValueError("操作协议主版本不兼容")
        expected = compute_idempotency_key(
            request_node_id=self.request_node_id,
            target_node_id=self.target_node_id,
            tool_name=self.tool_name,
            plan_version=self.plan_version,
            service_fingerprint=self.service.fingerprint,
            access_scope=self.access_scope,
        )
        if self.idempotency_key != expected:
            raise ValueError("幂等键与计划稳定字段不一致")
        if self.request_node_id != self.access_scope.allowed_peer_id:
            raise ValueError("访问范围必须限制为计划请求节点")
        return self


class AuthorizationKind(StrEnum):
    """授权依据种类。"""

    ONE_TIME = "one_time"
    PREAUTHORIZATION = "preauthorization"


class AuthorizationDecision(StrEnum):
    """目标节点本地策略产生的授权决定。"""

    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"
    REVOKED = "revoked"


class AuthorizationRecord(BaseModel):
    """不包含凭据的授权决策记录。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    authorization_id: AuthorizationId
    operation_id: OperationId
    kind: AuthorizationKind
    decision: AuthorizationDecision
    operator: str = Field(min_length=1, max_length=256)
    basis: str = Field(min_length=1, max_length=2_000)
    decided_at: datetime
    expires_at: datetime | None = None

    @model_validator(mode="after")
    def validate_expiry(self) -> Self:
        if self.expires_at is not None and self.expires_at <= self.decided_at:
            raise ValueError("授权过期时间必须晚于决策时间")
        return self


class Preauthorization(BaseModel):
    """目标节点所有者创建的细粒度、可撤销 L2 授权。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    authorization_id: AuthorizationId
    target_node_id: NodeId
    request_peer_id: NodeId
    tool_name: str = Field(min_length=1, max_length=128)
    service_ids: frozenset[str] = Field(min_length=1)
    service_fingerprints: frozenset[str] = Field(min_length=1)
    minimum_port: int = Field(ge=1024, le=65535)
    maximum_port: int = Field(ge=1024, le=65535)
    maximum_duration_seconds: int = Field(ge=1, le=86_400)
    created_by: str = Field(min_length=1, max_length=256)
    valid_from: datetime
    valid_until: datetime
    revoked_at: datetime | None = None

    @model_validator(mode="after")
    def validate_scope(self) -> Self:
        if self.maximum_port < self.minimum_port:
            raise ValueError("预授权最大端口不得小于最小端口")
        if self.valid_until <= self.valid_from:
            raise ValueError("预授权有效期结束时间必须晚于开始时间")
        if self.revoked_at is not None and self.revoked_at < self.valid_from:
            raise ValueError("预授权撤销时间不得早于生效时间")
        return self

    def matches(self, plan: OperationPlan, *, at: datetime) -> bool:
        """完整匹配 peer、工具、服务、端口、时长和有效期。"""
        scope = plan.access_scope
        return (
            self.revoked_at is None
            and self.valid_from <= at < self.valid_until
            and plan.level is OperationLevel.L2
            and plan.target_node_id == self.target_node_id
            and plan.request_node_id == self.request_peer_id
            and plan.tool_name == self.tool_name
            and plan.service.service_id in self.service_ids
            and plan.service.fingerprint in self.service_fingerprints
            and self.minimum_port <= scope.bind_port <= self.maximum_port
            and scope.duration_seconds <= self.maximum_duration_seconds
        )


class LeaseRecord(BaseModel):
    """绝对时间约束的临时资源租约；不保存访问令牌。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    lease_id: LeaseId
    operation_id: OperationId
    starts_at: datetime
    expires_at: datetime
    revoked_at: datetime | None = None

    @model_validator(mode="after")
    def validate_times(self) -> Self:
        if self.expires_at <= self.starts_at:
            raise ValueError("租约结束时间必须晚于开始时间")
        if self.revoked_at is not None and self.revoked_at < self.starts_at:
            raise ValueError("撤销时间不得早于租约开始时间")
        return self


class ResourceOwnership(BaseModel):
    """只描述 TunnelMinion 自有资源的不可变指纹。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    resource_id: ResourceId
    operation_id: OperationId
    kind: str = Field(min_length=1, max_length=128)
    bind_host: str = Field(min_length=1, max_length=255)
    bind_port: int = Field(ge=1024, le=65535)
    owner_fingerprint: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    process_id: int | None = Field(default=None, gt=0)
    created_at: datetime


class VerificationResult(StrEnum):
    """请求节点独立验证的结果。"""

    PASSED = "passed"
    FAILED = "failed"
    TIMEOUT = "timeout"
    REQUESTER_OFFLINE = "requester_offline"


class VerificationRecord(BaseModel):
    """请求节点沿真实访问路径产生的有界证据。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    operation_id: OperationId
    verifier_node_id: NodeId
    result: VerificationResult
    status_code: int | None = Field(default=None, ge=100, le=599)
    evidence_summary: str = Field(min_length=1, max_length=2_000)
    verified_at: datetime


class CleanupResult(StrEnum):
    """回滚或过期清理结果。"""

    SUCCEEDED = "succeeded"
    FAILED = "failed"
    OWNERSHIP_MISMATCH = "ownership_mismatch"


class CleanupRecord(BaseModel):
    """清理动作及人工介入建议。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    operation_id: OperationId
    result: CleanupResult
    reason: str = Field(min_length=1, max_length=2_000)
    manual_action: str | None = Field(default=None, min_length=1, max_length=2_000)
    completed_at: datetime

    @model_validator(mode="after")
    def require_manual_action_on_failure(self) -> Self:
        if self.result is not CleanupResult.SUCCEEDED and self.manual_action is None:
            raise ValueError("清理失败必须提供人工处理建议")
        return self


class OperationErrorCode(StrEnum):
    """批准操作边界稳定且脱敏的错误码。"""

    INVALID_PLAN = "invalid_plan"
    VERSION_INCOMPATIBLE = "version_incompatible"
    AUTHORIZATION_REQUIRED = "authorization_required"
    AUTHORIZATION_REJECTED = "authorization_rejected"
    AUTHORIZATION_EXPIRED = "authorization_expired"
    STATE_CONFLICT = "state_conflict"
    SERVICE_CHANGED = "service_changed"
    EXECUTION_FAILED = "execution_failed"
    VERIFICATION_FAILED = "verification_failed"
    CLEANUP_FAILED = "cleanup_failed"
    PROTOCOL_NOT_SUPPORTED = "protocol_not_supported"


class OperationError(BaseModel):
    """可进入列表和诊断导出的脱敏操作错误。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    code: OperationErrorCode
    message: str = Field(min_length=1, max_length=500)
    retryable: bool = False
    correlation_id: str = Field(min_length=1, max_length=128)


class OperationTransition(BaseModel):
    """一次已校验的状态变化。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    from_status: OperationStatus | None
    to_status: OperationStatus
    reason: str = Field(min_length=1, max_length=2_000)
    occurred_at: datetime


class OperationMetrics(BaseModel):
    """供评估报告读取的稳定成本与阶段延迟字段。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    phase_latency_ms: dict[str, int] = Field(default_factory=dict)
    model_input_tokens: int = Field(default=0, ge=0)
    model_output_tokens: int = Field(default=0, ge=0)
    model_cost_usd: float = Field(default=0, ge=0)
    tool_call_count: int = Field(default=0, ge=0)
    authorization_kind: AuthorizationKind | None = None
    final_result: str | None = Field(default=None, min_length=1, max_length=128)


class OperationRecord(BaseModel):
    """可在重启后恢复的完整操作聚合。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    plan: OperationPlan
    status: OperationStatus
    authorization: AuthorizationRecord | None = None
    lease: LeaseRecord | None = None
    resources: tuple[ResourceOwnership, ...] = ()
    verifications: tuple[VerificationRecord, ...] = ()
    cleanup: CleanupRecord | None = None
    error: OperationError | None = None
    metrics: OperationMetrics = Field(default_factory=OperationMetrics)
    transitions: tuple[OperationTransition, ...]
    updated_at: datetime

    @model_validator(mode="after")
    def validate_aggregate(self) -> Self:
        operation_id = self.plan.operation_id
        children = (
            self.authorization,
            self.lease,
            self.cleanup,
            *self.resources,
            *self.verifications,
        )
        if any(item is not None and item.operation_id != operation_id for item in children):
            raise ValueError("操作子记录必须属于同一个 operation_id")
        if not self.transitions:
            raise ValueError("操作至少需要一条初始状态记录")
        previous: OperationStatus | None = None
        previous_time: datetime | None = None
        for transition in self.transitions:
            if transition.from_status != previous:
                raise ValueError("状态历史不连续")
            if previous is not None and transition.to_status not in _ALLOWED_TRANSITIONS.get(
                previous, frozenset()
            ):
                raise ValueError("状态历史包含非法转换")
            if previous_time is not None and transition.occurred_at < previous_time:
                raise ValueError("状态历史时间不得倒退")
            previous = transition.to_status
            previous_time = transition.occurred_at
        if self.status != previous:
            raise ValueError("当前状态必须与最后一条状态历史一致")
        if self.updated_at < self.transitions[-1].occurred_at:
            raise ValueError("操作更新时间不得早于最后状态变化")
        return self

    @classmethod
    def planned(cls, plan: OperationPlan) -> Self:
        """为服务端已校验计划创建初始持久化记录。"""
        transition = OperationTransition(
            from_status=None,
            to_status=OperationStatus.PLANNED,
            reason="服务端已校验结构化计划",
            occurred_at=plan.created_at,
        )
        return cls(
            plan=plan,
            status=OperationStatus.PLANNED,
            transitions=(transition,),
            updated_at=plan.created_at,
        )


def transition_operation(
    record: OperationRecord,
    to_status: OperationStatus,
    *,
    reason: str,
    occurred_at: datetime,
) -> OperationRecord:
    """执行确定性状态转换，拒绝终态重开和时间倒退。"""
    allowed = _ALLOWED_TRANSITIONS.get(record.status, frozenset())
    if to_status not in allowed:
        raise ValueError(f"不允许从 {record.status.value} 转换到 {to_status.value}")
    transition = OperationTransition(
        from_status=record.status,
        to_status=to_status,
        reason=reason,
        occurred_at=occurred_at,
    )
    return OperationRecord.model_validate(
        {
            **record.model_dump(),
            "status": to_status,
            "transitions": (*record.transitions, transition),
            "updated_at": occurred_at,
        }
    )


class OperationSummary(BaseModel):
    """本地列表和诊断导出使用的允许字段摘要。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    operation_id: OperationId
    request_node_id: NodeId
    target_node_id: NodeId
    tool_name: str
    level: OperationLevel
    status: OperationStatus
    authorization_kind: AuthorizationKind | None
    authorization_basis: str | None
    bind_host: str
    bind_port: int
    absolute_expires_at: datetime | None
    resource_ids: tuple[ResourceId, ...]
    verification_results: tuple[VerificationResult, ...]
    cleanup_result: CleanupResult | None
    error: OperationError | None
    updated_at: datetime

    @classmethod
    def from_record(cls, record: OperationRecord) -> Self:
        """从完整记录构造不含凭据和远端正文的摘要。"""
        return cls(
            operation_id=record.plan.operation_id,
            request_node_id=record.plan.request_node_id,
            target_node_id=record.plan.target_node_id,
            tool_name=record.plan.tool_name,
            level=record.plan.level,
            status=record.status,
            authorization_kind=(
                record.authorization.kind if record.authorization is not None else None
            ),
            authorization_basis=(
                _redact_public_text(record.authorization.basis)
                if record.authorization is not None
                else None
            ),
            bind_host=record.plan.access_scope.bind_host,
            bind_port=record.plan.access_scope.bind_port,
            absolute_expires_at=record.lease.expires_at if record.lease is not None else None,
            resource_ids=tuple(item.resource_id for item in record.resources),
            verification_results=tuple(item.result for item in record.verifications),
            cleanup_result=record.cleanup.result if record.cleanup is not None else None,
            error=(
                record.error.model_copy(
                    update={"message": _redact_public_text(record.error.message)}
                )
                if record.error is not None
                else None
            ),
            updated_at=record.updated_at,
        )


class OperationStore(Protocol):
    """操作聚合的持久化访问边界。"""

    def put(self, record: OperationRecord) -> None: ...

    def get(self, operation_id: OperationId) -> OperationRecord | None: ...

    def get_by_idempotency_key(self, key: str) -> OperationRecord | None: ...

    def list_all(self) -> tuple[OperationRecord, ...]: ...

    def list_unfinished(self) -> tuple[OperationRecord, ...]: ...

    def list_summaries(self) -> tuple[OperationSummary, ...]: ...


class PreauthorizationStore(Protocol):
    """预授权的持久化访问边界。"""

    def put(self, authorization: Preauthorization) -> None: ...

    def get(self, authorization_id: AuthorizationId) -> Preauthorization | None: ...

    def list_all(self) -> tuple[Preauthorization, ...]: ...

    def list_active(self, *, at: datetime) -> tuple[Preauthorization, ...]: ...
