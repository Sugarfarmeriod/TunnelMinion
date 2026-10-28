"""与平台工具实现解耦的版本化远端网关信封。"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, JsonValue

from tunnelminion.domain.errors import ToolError
from tunnelminion.domain.identifiers import NodeId, OperationId, RunId, ThreadId, ToolRunId
from tunnelminion.domain.invites import DisplayName
from tunnelminion.domain.service_marks import ServiceMark
from tunnelminion.domain.tools import Platform, ToolDefinition
from tunnelminion.domain.versioning import ProtocolVersion
from tunnelminion.operation.contracts import (
    OPERATION_PROTOCOL_VERSION,
    LeaseRecord,
    OperationPlan,
    OperationSummary,
    VerificationRecord,
)
from tunnelminion.tools.contracts import ToolExecutionStatus

GATEWAY_PROTOCOL = ProtocolVersion(major=1, minor=0)


class ServicePort(BaseModel):
    """对外只提供端口，不提供监听地址。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    port: int = Field(ge=1, le=65535)
    protocol: Literal["tcp", "udp"]
    has_web_page: bool | None = None


class PeerServiceEntry(BaseModel):
    """对端允许展示的一项服务。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    key: str = Field(min_length=1, max_length=160)
    name: str = Field(min_length=1, max_length=80)
    kind: Literal["docker", "python", "program"]
    state: Literal["running", "stopped"] = "running"
    mark: ServiceMark | None = None
    web_title: str | None = None
    ports: tuple[ServicePort, ...]


class GatewayServices(BaseModel):
    """经本机筛选后的服务快照。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    node_id: NodeId
    display_name: DisplayName
    observed_at: datetime
    services: tuple[PeerServiceEntry, ...] = ()
    pending_repair_ids: tuple[OperationId, ...] = ()


class PeerRepairView(BaseModel):
    """给获准代批准的对端看的修复摘要，只出现在 /v1/repairs 接口里。

    不含命令、路径和启动参数；修法种类、状态和错误码用字符串，读取方忽略未知字段，
    这样提供方新增修法或字段时，旧版本的读取方仍能显示。
    """

    model_config = ConfigDict(extra="ignore", frozen=True)

    repair_id: OperationId
    node_id: NodeId
    service_name: str = Field(min_length=1, max_length=120)
    kind: str = Field(min_length=1, max_length=40)
    status: str = Field(min_length=1, max_length=40)
    action_summary: str = Field(min_length=1, max_length=300)
    reason: str = Field(min_length=1, max_length=500)
    impact_summary: str = Field(min_length=1, max_length=500)
    verification_summary: str = Field(min_length=1, max_length=300)
    failure_summary: str = Field(min_length=1, max_length=300)
    created_at: datetime
    updated_at: datetime
    # 仍在等批准时是批准截止时间，其余状态为空。
    approval_expires_at: datetime | None = None
    # 这次修复是否由对端代为批准；等批准或被拒绝时为空。
    approved_by_peer: bool | None = None
    verification_passed: bool | None = None
    error_code: str | None = Field(default=None, max_length=40)
    error_message: str | None = Field(default=None, max_length=500)


class GatewayErrorCode(StrEnum):
    """传输和版本协商层的稳定错误码。"""

    PROTOCOL_VERSION_UNSUPPORTED = "protocol_version_unsupported"
    TOOL_NOT_FOUND = "tool_not_found"
    TOOL_VERSION_UNSUPPORTED = "tool_version_unsupported"
    UNAUTHENTICATED = "unauthenticated"
    TRUST_SYNC_REQUIRED = "trust_sync_required"
    FORBIDDEN = "forbidden"
    RATE_LIMITED = "rate_limited"
    OPERATION_NOT_ALLOWED = "operation_not_allowed"
    OPERATION_NOT_FOUND = "operation_not_found"
    OPERATION_STATE_CONFLICT = "operation_state_conflict"
    PLAN_TAMPERED = "plan_tampered"
    RESPONSE_TOO_LARGE = "response_too_large"
    DELEGATION_NOT_ALLOWED = "delegation_not_allowed"
    DELEGATION_BUSY = "delegation_busy"
    DELEGATION_NOT_FOUND = "delegation_not_found"
    DELEGATION_UNAVAILABLE = "delegation_unavailable"
    MODEL_BORROWING_NOT_ALLOWED = "model_borrowing_not_allowed"
    MODEL_BORROWING_UNAVAILABLE = "model_borrowing_unavailable"
    MODEL_QUOTA_EXCEEDED = "model_quota_exceeded"
    MODEL_BUSY = "model_busy"
    MODEL_CALL_FAILED = "model_call_failed"
    INVITE_INVALID = "invite_invalid"
    REPAIR_APPROVAL_NOT_ALLOWED = "repair_approval_not_allowed"
    REPAIR_NOT_FOUND = "repair_not_found"
    REPAIR_STATE_CONFLICT = "repair_state_conflict"
    REPAIR_UNAVAILABLE = "repair_unavailable"


class GatewayError(BaseModel):
    """不包含内部异常和秘密的远端结构化错误。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    code: GatewayErrorCode
    message: str
    retryable: bool = False


class GatewayErrorResponse(BaseModel):
    """协议层失败响应。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    protocol: ProtocolVersion = GATEWAY_PROTOCOL
    error: GatewayError


class GatewayCapabilities(BaseModel):
    """远端节点明确允许发现的只读能力。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    protocol: ProtocolVersion
    node_id: NodeId
    platform: Platform
    tools: tuple[ToolDefinition, ...]
    operation_protocol: ProtocolVersion = OPERATION_PROTOCOL_VERSION
    operations: tuple[str, ...] = ()


class RemoteToolCall(BaseModel):
    """一次精确工具和版本的跨节点调用信封。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    protocol: ProtocolVersion
    tool_version: ProtocolVersion
    thread_id: ThreadId
    run_id: RunId
    tool_run_id: ToolRunId
    caller_node_id: NodeId
    arguments: dict[str, JsonValue] = Field(default_factory=dict)
    timeout_seconds: float = Field(gt=0, le=300)


class RemoteToolResult(BaseModel):
    """保留来源和关联 ID 的远端工具执行结果。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    protocol: ProtocolVersion
    execution_node_id: NodeId
    run_id: RunId
    tool_run_id: ToolRunId
    status: ToolExecutionStatus
    output: JsonValue | None = None
    truncated: bool = False
    error: ToolError | None = None


class RemoteOperationSubmission(BaseModel):
    """请求节点提交到目标节点重新校验的完整计划。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    protocol: ProtocolVersion
    plan: OperationPlan


class RequesterVerificationCallback(BaseModel):
    """请求节点临时开放、且只用于本次执行的验证回调。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    endpoint: str = Field(pattern=r"^http://[^/]+(?::[0-9]+)?$")
    token: str = Field(min_length=43, max_length=512, repr=False)
    timeout_seconds: float = Field(default=10, gt=0, le=30)


class RemoteOperationExecution(BaseModel):
    """只引用目标节点已经持久化且授权的计划。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    protocol: ProtocolVersion
    operation_id: OperationId
    plan_version: int = Field(ge=1)
    idempotency_key: str = Field(pattern=r"^opkey_[0-9a-f]{64}$")
    request_node_id: NodeId
    target_node_id: NodeId
    thread_id: ThreadId
    run_id: RunId
    tool_run_ids: tuple[ToolRunId, ...] = ()
    verification_callback: RequesterVerificationCallback | None = None


class RemoteVerificationRequest(BaseModel):
    """目标节点向请求节点传递的一次性验证材料。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    protocol: ProtocolVersion = GATEWAY_PROTOCOL
    plan: OperationPlan
    lease: LeaseRecord
    access_token: str = Field(min_length=43, max_length=512, repr=False)


class RemoteVerificationResult(BaseModel):
    """请求节点沿自己的真实网络路径生成的验证证据。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    protocol: ProtocolVersion = GATEWAY_PROTOCOL
    verification: VerificationRecord


class RemoteOperationResult(BaseModel):
    """不含临时凭据的跨节点操作状态信封。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    protocol: ProtocolVersion
    execution_node_id: NodeId
    summary: OperationSummary
