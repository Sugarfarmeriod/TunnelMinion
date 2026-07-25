"""Tool Runtime 参数、资源限制、错误和审计测试。"""

from __future__ import annotations

import asyncio
from collections.abc import Coroutine
from pathlib import Path
from typing import Any, TypeVar, cast

import pytest
from pydantic import JsonValue, ValidationError
from tests.tools.test_registry import definition

from tunnelminion.domain.errors import ErrorCode, ToolError
from tunnelminion.domain.identifiers import ArtifactId, NodeId, RunId, ThreadId, ToolRunId
from tunnelminion.domain.tools import Platform, RiskLevel
from tunnelminion.memory.context import ArtifactContextManager
from tunnelminion.memory.sqlite import SQLiteStores
from tunnelminion.tools.audit import InMemoryAuditSink
from tunnelminion.tools.contracts import (
    ToolAdapterError,
    ToolCallContext,
    ToolCancellationToken,
    ToolExecutionRequest,
    ToolExecutionResult,
    ToolExecutionStatus,
)
from tunnelminion.tools.fakes import FakeToolAdapter, FakeToolBehavior
from tunnelminion.tools.registry import ToolRegistry
from tunnelminion.tools.runtime import ToolRuntime

T = TypeVar("T")


def run(coroutine: Coroutine[Any, Any, T]) -> T:
    """运行一个异步测试动作。"""
    return asyncio.run(coroutine)


def context() -> ToolCallContext:
    """返回具有完整关联 ID 的调用上下文。"""
    return ToolCallContext(
        thread_id=ThreadId.new(),
        run_id=RunId.new(),
        caller_node_id=NodeId.new(),
        execution_node_id=NodeId.new(),
    )


def request(name: str = "probe_service", **arguments: JsonValue) -> ToolExecutionRequest:
    """返回标准工具调用请求。"""
    return ToolExecutionRequest(context=context(), tool_name=name, arguments=arguments)


def build_runtime(
    adapter: FakeToolAdapter,
    *,
    risk: RiskLevel = RiskLevel.READ_ONLY,
    platforms: frozenset[Platform] = frozenset({Platform.WINDOWS}),
    timeout: float = 1,
    max_bytes: int = 1024,
    output_schema: dict[str, JsonValue] | None = None,
    max_concurrency: int = 4,
    artifact_manager: ArtifactContextManager | None = None,
) -> tuple[ToolRuntime, InMemoryAuditSink]:
    """组装一个只有 `probe_service` 的 Runtime。"""
    registry = ToolRegistry()
    tool = definition(
        "probe_service",
        risk,
        platforms=platforms,
        input_schema={
            "type": "object",
            "properties": {
                "port": {"type": "integer", "minimum": 1, "maximum": 65535},
                "api_token": {"type": "string"},
                "note": {"type": "string"},
                "items": {"type": "array"},
            },
            "required": ["port"],
            "additionalProperties": False,
        },
        output_schema=output_schema or {"type": "object"},
    ).model_copy(update={"timeout_seconds": timeout, "max_result_bytes": max_bytes})
    registry.register(tool, adapter)
    audit = InMemoryAuditSink()
    return (
        ToolRuntime(
            registry,
            Platform.WINDOWS,
            audit,
            max_concurrency=max_concurrency,
            artifact_manager=artifact_manager,
        ),
        audit,
    )


def test_rejects_invalid_concurrency_unknown_and_non_read_only_tools() -> None:
    registry = ToolRegistry()
    with pytest.raises(ValueError, match="至少"):
        ToolRuntime(registry, Platform.WINDOWS, InMemoryAuditSink(), max_concurrency=0)

    runtime = ToolRuntime(registry, Platform.WINDOWS, InMemoryAuditSink())
    unknown = run(runtime.execute(request("invented_tool")))
    assert unknown.error is not None
    assert unknown.error.code is ErrorCode.TOOL_NOT_FOUND

    forbidden_runtime, audit = build_runtime(FakeToolAdapter(), risk=RiskLevel.REQUIRES_APPROVAL)
    forbidden = run(forbidden_runtime.execute(request(port=80)))
    assert forbidden.error is not None
    assert forbidden.error.code is ErrorCode.FORBIDDEN
    assert audit.records[0].tool_version is not None


def test_rejects_unsupported_platform_and_arguments_before_adapter_call() -> None:
    adapter = FakeToolAdapter()
    runtime, audit = build_runtime(adapter, platforms=frozenset({Platform.MACOS}))
    unsupported = run(runtime.execute(request(port=80)))
    assert unsupported.error is not None
    assert unsupported.error.code is ErrorCode.OPERATION_NOT_SUPPORTED

    runtime, audit = build_runtime(adapter)
    invalid = run(runtime.execute(request(port=70000, extra="value")))
    assert invalid.error is not None
    assert invalid.error.code is ErrorCode.INVALID_ARGUMENT
    assert invalid.error.details["path"] in {"$", "port"}
    assert adapter.calls == []
    assert audit.records[-1].status is ToolExecutionStatus.FAILED


def test_success_is_correlated_and_arguments_are_redacted() -> None:
    adapter = FakeToolAdapter()
    runtime, audit = build_runtime(adapter)
    long_note = "n" * 200
    result = run(
        runtime.execute(
            request(
                port=8080,
                api_token="top-secret",
                note=long_note,
                items=cast(JsonValue, list(range(25))),
            )
        )
    )

    assert result.status is ToolExecutionStatus.SUCCESS
    assert result.output is not None
    record = audit.records[0]
    assert record.thread_id.root
    assert record.run_id.root
    assert record.tool_run_id == result.tool_run_id
    assert record.arguments_summary["api_token"] == "[REDACTED]"
    assert str(record.arguments_summary["note"]).endswith("…")
    assert len(cast(list[JsonValue], record.arguments_summary["items"])) == 20
    assert record.started_at <= record.finished_at
    assert "top-secret" not in record.model_dump_json()


def test_pre_cancel_active_cancel_and_timeout_are_structured_and_audited() -> None:
    adapter = FakeToolAdapter(delay_seconds=1)
    runtime, audit = build_runtime(adapter, timeout=0.05)
    token = ToolCancellationToken()
    token.cancel()
    pre_cancelled = run(runtime.execute(request(port=80), token))
    assert pre_cancelled.status is ToolExecutionStatus.CANCELLED

    async def cancel_active() -> ToolExecutionResult:
        active_token = ToolCancellationToken()
        task = asyncio.create_task(runtime.execute(request(port=81), active_token))
        await asyncio.sleep(0)
        active_token.cancel()
        return await task

    active = run(cancel_active())
    assert active.error is not None
    assert active.error.code is ErrorCode.CANCELLED

    slow_runtime, slow_audit = build_runtime(FakeToolAdapter(FakeToolBehavior.SLOW), timeout=0.01)
    timed_out = run(slow_runtime.execute(request(port=82)))
    assert timed_out.error is not None
    assert timed_out.error.code is ErrorCode.TIMEOUT
    assert timed_out.error.retryable
    assert len(audit.records) == 2
    assert slow_audit.records[0].error_code is ErrorCode.TIMEOUT


def test_adapter_errors_invalid_outputs_and_unexpected_failures_are_safe() -> None:
    adapter_runtime, _ = build_runtime(FakeToolAdapter(FakeToolBehavior.ADAPTER_ERROR))
    adapter_error = run(adapter_runtime.execute(request(port=80)))
    assert adapter_error.error is not None
    assert adapter_error.error.code is ErrorCode.INVALID_ARGUMENT

    unsupported_runtime, _ = build_runtime(FakeToolAdapter(FakeToolBehavior.PLATFORM_UNSUPPORTED))
    unsupported = run(unsupported_runtime.execute(request(port=80)))
    assert unsupported.error is not None
    assert unsupported.error.code is ErrorCode.OPERATION_NOT_SUPPORTED

    invalid_output_runtime, _ = build_runtime(FakeToolAdapter(), output_schema={"type": "array"})
    invalid_output = run(invalid_output_runtime.execute(request(port=80)))
    assert invalid_output.error is not None
    assert invalid_output.error.code is ErrorCode.INTERNAL

    class ExplodingAdapter:
        async def execute(
            self,
            arguments: dict[str, JsonValue],
            cancellation: ToolCancellationToken,
        ) -> JsonValue:
            del arguments, cancellation
            raise RuntimeError("sensitive platform detail")

    registry = ToolRegistry()
    registry.register(definition("explode"), ExplodingAdapter())
    audit = InMemoryAuditSink()
    runtime = ToolRuntime(registry, Platform.WINDOWS, audit)
    exploded = run(runtime.execute(request("explode")))
    assert exploded.error is not None
    assert exploded.error.code is ErrorCode.INTERNAL
    assert "sensitive" not in exploded.error.message


def test_large_and_untrusted_results_are_bounded_without_changing_policy() -> None:
    large_runtime, _ = build_runtime(
        FakeToolAdapter(FakeToolBehavior.LARGE_RESULT, large_result_size=1000),
        max_bytes=32,
    )
    partial = run(large_runtime.execute(request(port=80)))
    assert partial.status is ToolExecutionStatus.PARTIAL
    assert partial.truncated
    assert partial.error is not None
    assert partial.error.code is ErrorCode.RESULT_TOO_LARGE
    assert cast(int, partial.error.details["original_bytes"]) > 32

    injection_runtime, _ = build_runtime(FakeToolAdapter(FakeToolBehavior.PROMPT_INJECTION))
    injection = run(injection_runtime.execute(request(port=80)))
    assert "危险工具" in str(injection.output)
    unknown = run(injection_runtime.execute(request("run_dangerous_command")))
    assert unknown.error is not None
    assert unknown.error.code is ErrorCode.TOOL_NOT_FOUND


def test_large_result_is_persisted_as_controlled_artifact(tmp_path: Path) -> None:
    stores = SQLiteStores.open(tmp_path / "tool-artifact.sqlite3")
    runtime, _ = build_runtime(
        FakeToolAdapter(FakeToolBehavior.LARGE_RESULT, large_result_size=1000),
        max_bytes=32,
        artifact_manager=ArtifactContextManager(
            stores.artifacts,
            inline_bytes=256,
            preview_chars=80,
        ),
    )

    partial = run(runtime.execute(request(port=80)))

    assert partial.status is ToolExecutionStatus.PARTIAL
    assert partial.artifact_id is not None
    assert partial.content_bytes is not None and partial.content_bytes > 256
    assert partial.content_type == "application/json"
    assert len(str(partial.output)) < partial.content_bytes
    artifact = stores.artifacts.get(partial.artifact_id)
    assert artifact is not None
    assert artifact.tool_run_id == partial.tool_run_id
    assert artifact.content_bytes == partial.content_bytes
    assert artifact.content_hash.startswith("sha256:")


def test_concurrency_limit_is_enforced() -> None:
    adapter = FakeToolAdapter(delay_seconds=0.02)
    runtime, _ = build_runtime(adapter, max_concurrency=1)

    async def execute_pair() -> None:
        await asyncio.gather(
            runtime.execute(request(port=80)),
            runtime.execute(request(port=81)),
        )

    run(execute_pair())
    assert adapter.max_active == 1


def test_result_model_rejects_inconsistent_states() -> None:
    tool_run_id = ToolRunId.new()
    error = ToolError(code=ErrorCode.INTERNAL, message="失败")
    with pytest.raises(ValidationError):
        ToolExecutionResult(
            tool_run_id=tool_run_id,
            status=ToolExecutionStatus.SUCCESS,
            error=error,
        )
    with pytest.raises(ValidationError):
        ToolExecutionResult(
            tool_run_id=tool_run_id,
            status=ToolExecutionStatus.PARTIAL,
            error=error,
        )
    with pytest.raises(ValidationError, match="大小和类型"):
        ToolExecutionResult(
            tool_run_id=tool_run_id,
            status=ToolExecutionStatus.PARTIAL,
            output="preview",
            truncated=True,
            artifact_id=ArtifactId.new(),
            error=error,
        )
    with pytest.raises(ValidationError):
        ToolExecutionResult(
            tool_run_id=tool_run_id,
            status=ToolExecutionStatus.FAILED,
            output={"unexpected": True},
            error=error,
        )
    with pytest.raises(ValidationError):
        ToolExecutionResult(
            tool_run_id=tool_run_id,
            status=ToolExecutionStatus.FAILED,
        )


def test_adapter_cancel_error_maps_to_cancelled_status() -> None:
    class CancelAdapter:
        async def execute(
            self,
            arguments: dict[str, JsonValue],
            cancellation: ToolCancellationToken,
        ) -> JsonValue:
            del arguments, cancellation
            raise ToolAdapterError(ToolError(code=ErrorCode.CANCELLED, message="适配器取消"))

    registry = ToolRegistry()
    registry.register(definition("cancel_adapter"), CancelAdapter())
    runtime = ToolRuntime(registry, Platform.WINDOWS, InMemoryAuditSink())
    result = run(runtime.execute(request("cancel_adapter")))
    assert result.status is ToolExecutionStatus.CANCELLED
