import asyncio

import pytest

from tunnelminion.agent.context_contracts import ContextRequest, ContextTaskType
from tunnelminion.agent.context_runtime import (
    ContextModelRuntime,
    ContextSnapshotBuilder,
    SnapshotModelProvider,
)
from tunnelminion.domain.identifiers import RunId, ThreadId, ToolRunId
from tunnelminion.memory.context import ContextBudgets, ToolResultContext
from tunnelminion.model.contracts import (
    CancellationToken,
    ModelCapabilities,
    ModelMessage,
    ModelRequest,
    ModelResponse,
    ProviderError,
    ProviderErrorCode,
    ToolCall,
    ToolDefinition,
)


class RecordingProvider:
    """记录原始请求，证明每个有效快照只触发一次 Provider。"""

    def __init__(self) -> None:
        self.requests: list[ModelRequest] = []

    @property
    def capabilities(self) -> ModelCapabilities:
        return ModelCapabilities(tool_calls=True, structured_output=True)

    async def complete(
        self,
        request: ModelRequest,
        cancellation: CancellationToken | None = None,
    ) -> ModelResponse:
        del cancellation
        self.requests.append(request)
        return ModelResponse(content="ok")


def _request(**updates: object) -> ContextRequest:
    request = ContextRequest(
        task_type=ContextTaskType.LOCAL_CONVERSATION,
        current_intent="检查状态",
        thread_id=ThreadId.new(),
        run_id=RunId.new(),
        prompt_id="readonly-agent",
        prompt_version="v1",
        messages=(
            ModelMessage(role="system", content="只读"),
            ModelMessage(role="user", content="状态？"),
        ),
        tools=(
            ToolDefinition(
                name="get_status",
                description="读取状态",
                input_schema={"type": "object", "additionalProperties": False},
            ),
        ),
    )
    return request.model_copy(update=updates)


def test_runtime_builds_versioned_snapshot_and_calls_provider_once() -> None:
    provider = RecordingProvider()
    runtime = ContextModelRuntime(
        provider,
        provider_name="openai-compatible",
        model_name="qwen",
        tool_schema_version="readonly-tools/v1",
    )

    first = asyncio.run(runtime.invoke(_request()))
    second = asyncio.run(runtime.invoke(_request()))

    assert first.response.content == "ok"
    assert first.snapshot.snapshot_id != second.snapshot.snapshot_id
    assert first.snapshot.trace.builder_version == ContextSnapshotBuilder.VERSION
    assert first.snapshot.trace.provider_name == "openai-compatible"
    assert [item.kind.value for item in first.snapshot.content_references] == [
        "message",
        "message",
        "tool-schema",
    ]
    assert len(provider.requests) == 2
    assert provider.requests[0] == first.snapshot.model_request


def test_builder_records_budget_drop_and_injects_bounded_tool_result() -> None:
    builder = ContextSnapshotBuilder()
    request = _request(
        messages=(
            ModelMessage(role="system", content="x" * 300),
            ModelMessage(role="user", content="状态？"),
        ),
        budgets=ContextBudgets(message_chars=256),
    )

    snapshot = builder.build(
        request,
        provider_name="provider",
        model_name="model",
        tool_schema_version="tools/v1",
    )

    assert snapshot.budget_decisions[0].dropped_count == 1
    assert snapshot.truncations[0].reason.value == "budget-exceeded"
    tool_snapshot = builder.build(
        _request(
            messages=(
                ModelMessage(
                    role="assistant",
                    content="",
                    tool_calls=(ToolCall(call_id="call-1", name="probe", arguments={}),),
                ),
            ),
            tool_results=(
                ToolResultContext(
                    tool_run_id=ToolRunId.new(),
                    content='{"status":"ok"}',
                    tool_call_id="call-1",
                    tool_name="probe",
                ),
            ),
        ),
        provider_name="provider",
        model_name="model",
        tool_schema_version="tools/v1",
    )
    assert tool_snapshot.model_request.messages[-1].role == "tool"
    assert tool_snapshot.budget_decisions[3].included_count == 1
    appended = builder.build(
        _request(
            tool_results=(
                ToolResultContext(
                    tool_run_id=ToolRunId.new(),
                    content='{"status":"ok"}',
                    tool_call_id="orphan-call",
                    tool_name="probe",
                ),
            ),
        ),
        provider_name="provider",
        model_name="model",
        tool_schema_version="tools/v1",
    )
    assert appended.model_request.messages[-1].tool_call_id == "orphan-call"
    with pytest.raises(ValueError, match="必须关联"):
        builder.build(
            _request(
                tool_results=(
                    ToolResultContext(
                        tool_run_id=ToolRunId.new(),
                        content='{"status":"ok"}',
                    ),
                ),
            ),
            provider_name="provider",
            model_name="model",
            tool_schema_version="tools/v1",
        )


def test_snapshot_provider_rejects_missing_or_incompatible_builder_version() -> None:
    provider = RecordingProvider()
    builder = ContextSnapshotBuilder()
    snapshot = builder.build(
        _request(),
        provider_name="provider",
        model_name="model",
        tool_schema_version="tools/v1",
    )

    with pytest.raises(ProviderError) as unsupported:
        asyncio.run(
            SnapshotModelProvider(
                provider,
                supported_builder_version="context-builder/v2",
            ).invoke(snapshot)
        )
    assert unsupported.value.code is ProviderErrorCode.INVALID_CONTEXT

    mismatched = snapshot.model_copy(
        update={
            "trace": snapshot.trace.model_copy(
                update={"builder_version": "context-builder/tampered"}
            )
        }
    )
    with pytest.raises(ProviderError) as tampered:
        asyncio.run(SnapshotModelProvider(provider).invoke(mismatched))
    assert tampered.value.code is ProviderErrorCode.INVALID_CONTEXT
    assert provider.requests == []
