"""失败分类与脱敏运行记录的通用边界。"""

from __future__ import annotations

from datetime import UTC, datetime

from tunnelminion.agent.context_contracts import (
    FailureCategory,
    FailurePhase,
    FailureReason,
    FailureRecord,
)
from tunnelminion.model.contracts import ProviderError, ProviderErrorCode
from tunnelminion.tools.contracts import ToolAdapterError

_PROVIDER_REASONS = {
    ProviderErrorCode.AUTHENTICATION_FAILED: FailureReason.MODEL_AUTHENTICATION_FAILED,
    ProviderErrorCode.MODEL_NOT_FOUND: FailureReason.MODEL_NOT_FOUND,
    ProviderErrorCode.TIMEOUT: FailureReason.MODEL_TIMEOUT,
    ProviderErrorCode.NETWORK_UNREACHABLE: FailureReason.MODEL_NETWORK_UNREACHABLE,
    ProviderErrorCode.INVALID_RESPONSE: FailureReason.MODEL_INVALID_RESPONSE,
    ProviderErrorCode.CAPABILITY_INCOMPATIBLE: FailureReason.MODEL_CAPABILITY_INCOMPATIBLE,
    ProviderErrorCode.CANCELLED: FailureReason.MODEL_CANCELLED,
    ProviderErrorCode.INVALID_CONTEXT: FailureReason.CONTEXT_INVALID,
}


def classify_failure(
    error: BaseException,
    *,
    phase: FailurePhase,
    source_refs: tuple[str, ...] = (),
) -> FailureRecord:
    """只根据异常类型和枚举代码分类，永不复制异常消息。"""
    category = FailureCategory.HARNESS_OR_TOOL
    reason = FailureReason.AGENT_RUNTIME_FAILED
    retryable = False
    if isinstance(error, ProviderError):
        reason = _PROVIDER_REASONS[error.code]
        category = (
            FailureCategory.CONTEXT
            if error.code is ProviderErrorCode.INVALID_CONTEXT
            else FailureCategory.PROMPT_OR_MODEL
        )
        retryable = error.retryable
    elif isinstance(error, ToolAdapterError):
        category = FailureCategory.HARNESS_OR_TOOL
        reason = FailureReason.TOOL_FAILED
        retryable = error.error.retryable
    elif isinstance(error, PermissionError):
        category = FailureCategory.GOVERNANCE
        reason = FailureReason.GOVERNANCE_DENIED
    elif phase is FailurePhase.CONTEXT_BUILD:
        category = FailureCategory.CONTEXT
        reason = FailureReason.CONTEXT_INVALID
    elif phase is FailurePhase.HISTORY_SUMMARY:
        category = FailureCategory.CONTEXT
        reason = FailureReason.SUMMARY_FAILED
    return FailureRecord(
        category=category,
        phase=phase,
        reason=reason,
        retryable=retryable,
        occurred_at=datetime.now(UTC),
        source_refs=source_refs,
    )
