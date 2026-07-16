"""供工具与跨节点请求使用的稳定机器可读错误。"""

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, JsonValue


class ErrorCode(StrEnum):
    """可在运行时与网关边界之间安全交换的错误码。"""

    INVALID_ARGUMENT = "invalid_argument"
    TOOL_NOT_FOUND = "tool_not_found"
    DEPENDENCY_UNAVAILABLE = "dependency_unavailable"
    PERMISSION_DENIED = "permission_denied"
    UNAUTHENTICATED = "unauthenticated"
    FORBIDDEN = "forbidden"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"
    RESULT_TOO_LARGE = "result_too_large"
    OPERATION_NOT_SUPPORTED = "operation_not_supported"
    NODE_UNREACHABLE = "node_unreachable"
    REMOTE_TIMEOUT = "remote_timeout"
    VERSION_INCOMPATIBLE = "version_incompatible"
    INTERNAL = "internal"


class ToolError(BaseModel):
    """经过脱敏的失败信息，用于替代平台相关异常。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    code: ErrorCode
    message: str = Field(min_length=1, max_length=500)
    retryable: bool = False
    details: dict[str, JsonValue] = Field(default_factory=dict)
