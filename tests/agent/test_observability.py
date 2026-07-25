import pytest

from tunnelminion.agent.context_contracts import (
    FailureCategory,
    FailurePhase,
    FailureReason,
)
from tunnelminion.agent.observability import classify_failure
from tunnelminion.domain.errors import ErrorCode, ToolError
from tunnelminion.model.contracts import ProviderError, ProviderErrorCode
from tunnelminion.tools.contracts import ToolAdapterError


@pytest.mark.parametrize(
    ("code", "reason", "category"),
    [
        (
            ProviderErrorCode.AUTHENTICATION_FAILED,
            FailureReason.MODEL_AUTHENTICATION_FAILED,
            FailureCategory.PROMPT_OR_MODEL,
        ),
        (
            ProviderErrorCode.MODEL_NOT_FOUND,
            FailureReason.MODEL_NOT_FOUND,
            FailureCategory.PROMPT_OR_MODEL,
        ),
        (
            ProviderErrorCode.TIMEOUT,
            FailureReason.MODEL_TIMEOUT,
            FailureCategory.PROMPT_OR_MODEL,
        ),
        (
            ProviderErrorCode.NETWORK_UNREACHABLE,
            FailureReason.MODEL_NETWORK_UNREACHABLE,
            FailureCategory.PROMPT_OR_MODEL,
        ),
        (
            ProviderErrorCode.INVALID_RESPONSE,
            FailureReason.MODEL_INVALID_RESPONSE,
            FailureCategory.PROMPT_OR_MODEL,
        ),
        (
            ProviderErrorCode.CAPABILITY_INCOMPATIBLE,
            FailureReason.MODEL_CAPABILITY_INCOMPATIBLE,
            FailureCategory.PROMPT_OR_MODEL,
        ),
        (
            ProviderErrorCode.CANCELLED,
            FailureReason.MODEL_CANCELLED,
            FailureCategory.PROMPT_OR_MODEL,
        ),
        (
            ProviderErrorCode.INVALID_CONTEXT,
            FailureReason.CONTEXT_INVALID,
            FailureCategory.CONTEXT,
        ),
    ],
)
def test_provider_failures_use_stable_redacted_classification(
    code: ProviderErrorCode,
    reason: FailureReason,
    category: FailureCategory,
) -> None:
    failure = classify_failure(
        ProviderError(code, "private-provider-body", retryable=True),
        phase=FailurePhase.MODEL_INVOKE,
        source_refs=("snapshot:sha256-only",),
    )

    assert failure.reason is reason
    assert failure.category is category
    assert failure.retryable
    assert "private-provider-body" not in failure.model_dump_json()


def test_context_tool_governance_and_unknown_failures_are_distinct() -> None:
    context = classify_failure(ValueError("secret"), phase=FailurePhase.CONTEXT_BUILD)
    summary = classify_failure(RuntimeError("secret"), phase=FailurePhase.HISTORY_SUMMARY)
    tool = classify_failure(
        ToolAdapterError(
            ToolError(
                code=ErrorCode.TIMEOUT,
                message="secret",
                retryable=True,
            )
        ),
        phase=FailurePhase.TOOL_EXECUTE,
    )
    governance = classify_failure(
        PermissionError("secret"),
        phase=FailurePhase.GOVERNANCE_CHECK,
    )
    unknown = classify_failure(RuntimeError("secret"), phase=FailurePhase.AGENT_RUNTIME)

    assert (context.category, context.reason) == (
        FailureCategory.CONTEXT,
        FailureReason.CONTEXT_INVALID,
    )
    assert summary.reason is FailureReason.SUMMARY_FAILED
    assert tool.category is FailureCategory.HARNESS_OR_TOOL
    assert tool.reason is FailureReason.TOOL_FAILED
    assert tool.retryable
    assert governance.category is FailureCategory.GOVERNANCE
    assert governance.reason is FailureReason.GOVERNANCE_DENIED
    assert unknown.reason is FailureReason.AGENT_RUNTIME_FAILED
    assert all(
        "secret" not in item.model_dump_json()
        for item in (context, summary, tool, governance, unknown)
    )
