"""与平台工具实现解耦的版本化远端网关信封。"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, JsonValue

from tunnelminion.domain.errors import ToolError
from tunnelminion.domain.identifiers import NodeId, OperationId, RunId, ThreadId, ToolRunId
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


class GatewayErrorCode(StrEnum):
    """传输和版本协商层的稳定错误码。"""

    PROTOCOL_VERSION_UNSUPPORTED = "protocol_version_unsupported"
    TOOL_NOT_FOUND = "tool_not_found"
    TOOL_VERSION_UNSUPPORTED = "tool_version_unsupported"
    UNAUTHENTICATED = "unauthenticated"
    FORBIDDEN = "forbidden"
    RATE_LIMITED = "rate_limited"
    OPERATION_NOT_ALLOWED = "operation_not_allowed"
    OPERATION_NOT_FOUND = "operation_not_found"
    OPERATION_STATE_CONFLICT = "operation_state_conflict"
    PLAN_TAMPERED = "plan_tampered"
    RESPONSE_TOO_LARGE = "response_too_large"


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
