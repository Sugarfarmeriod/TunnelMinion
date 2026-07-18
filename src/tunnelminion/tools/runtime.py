"""具有策略、资源限制和审计的结构化 Tool Runtime。"""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from typing import cast

from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError
from pydantic import JsonValue

from tunnelminion.domain.errors import ErrorCode, ToolError
from tunnelminion.domain.identifiers import ToolRunId
from tunnelminion.domain.tools import Platform, RiskLevel
from tunnelminion.tools.audit import AuditRecord, AuditSink
from tunnelminion.tools.contracts import (
    ToolAdapterError,
    ToolCancellationToken,
    ToolExecutionRequest,
    ToolExecutionResult,
    ToolExecutionStatus,
)
from tunnelminion.tools.registry import RegisteredTool, ToolRegistry

_SECRET_ARGUMENT_MARKERS = ("api_key", "authorization", "password", "secret", "token")


class ToolRuntime:
    """执行明确注册的只读工具并为每次尝试生成审计证据。"""

    def __init__(
        self,
        registry: ToolRegistry,
        platform: Platform,
        audit_sink: AuditSink,
        *,
        max_concurrency: int = 4,
    ) -> None:
        if max_concurrency < 1:
            raise ValueError("max_concurrency 必须至少为 1")
        self._registry = registry
        self._platform = platform
        self._audit_sink = audit_sink
        self._semaphore = asyncio.Semaphore(max_concurrency)

    async def execute(
        self,
        request: ToolExecutionRequest,
        cancellation: ToolCancellationToken | None = None,
    ) -> ToolExecutionResult:
        """校验、执行和审计一次工具调用。"""
        token = cancellation or ToolCancellationToken()
        tool_run_id = request.tool_run_id or self._new_tool_run_id()
        started_at = datetime.now(UTC)
        entry = self._registry.lookup(request.tool_name)

        if entry is None:
            return self._finish(
                request,
                tool_run_id,
                started_at,
                None,
                ToolExecutionStatus.FAILED,
                ToolError(code=ErrorCode.TOOL_NOT_FOUND, message="工具未注册"),
            )
        if entry.definition.risk_level is not RiskLevel.READ_ONLY:
            return self._finish(
                request,
                tool_run_id,
                started_at,
                entry,
                ToolExecutionStatus.FAILED,
                ToolError(code=ErrorCode.FORBIDDEN, message="MVP 只允许执行只读工具"),
            )
        if self._platform not in entry.definition.platforms:
            return self._finish(
                request,
                tool_run_id,
                started_at,
                entry,
                ToolExecutionStatus.FAILED,
                ToolError(
                    code=ErrorCode.OPERATION_NOT_SUPPORTED,
                    message="当前平台不支持该工具",
                ),
            )

        validation_error = self._validate_arguments(entry, request.arguments)
        if validation_error is not None:
            return self._finish(
                request,
                tool_run_id,
                started_at,
                entry,
                ToolExecutionStatus.FAILED,
                validation_error,
            )
        if token.cancelled:
            return self._finish(
                request,
                tool_run_id,
                started_at,
                entry,
                ToolExecutionStatus.CANCELLED,
                ToolError(code=ErrorCode.CANCELLED, message="工具调用已取消"),
            )

        try:
            async with self._semaphore:
                output = await self._execute_adapter(entry, request.arguments, token)
            Draft202012Validator(entry.definition.output_schema).validate(  # pyright: ignore[reportUnknownMemberType]
                output
            )
        except ToolAdapterError as exc:
            status = (
                ToolExecutionStatus.CANCELLED
                if exc.error.code is ErrorCode.CANCELLED
                else ToolExecutionStatus.FAILED
            )
            return self._finish(request, tool_run_id, started_at, entry, status, exc.error)
        except ValidationError:
            return self._finish(
                request,
                tool_run_id,
                started_at,
                entry,
                ToolExecutionStatus.FAILED,
                ToolError(code=ErrorCode.INTERNAL, message="工具输出不符合已注册 schema"),
            )
        except Exception:
            return self._finish(
                request,
                tool_run_id,
                started_at,
                entry,
                ToolExecutionStatus.FAILED,
                ToolError(code=ErrorCode.INTERNAL, message="工具执行失败"),
            )

        serialized = json.dumps(output, ensure_ascii=False, separators=(",", ":")).encode()
        if len(serialized) > entry.definition.max_result_bytes:
            preview = serialized[: entry.definition.max_result_bytes].decode(
                "utf-8", errors="ignore"
            )
            return self._finish(
                request,
                tool_run_id,
                started_at,
                entry,
                ToolExecutionStatus.PARTIAL,
                ToolError(
                    code=ErrorCode.RESULT_TOO_LARGE,
                    message="工具结果超过预算，已返回截断预览",
                    details={"original_bytes": len(serialized)},
                ),
                output=preview,
                truncated=True,
            )
        return self._finish(
            request,
            tool_run_id,
            started_at,
            entry,
            ToolExecutionStatus.SUCCESS,
            None,
            output=output,
        )

    async def _execute_adapter(
        self,
        entry: RegisteredTool,
        arguments: dict[str, JsonValue],
        cancellation: ToolCancellationToken,
    ) -> JsonValue:
        task = asyncio.create_task(entry.adapter.execute(arguments, cancellation))
        cancel_task = asyncio.create_task(cancellation.wait())
        done, _ = await asyncio.wait(
            {task, cancel_task},
            timeout=entry.definition.timeout_seconds,
            return_when=asyncio.FIRST_COMPLETED,
        )
        if cancel_task in done:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
            raise ToolAdapterError(ToolError(code=ErrorCode.CANCELLED, message="工具调用已取消"))
        if task not in done:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
            raise ToolAdapterError(
                ToolError(code=ErrorCode.TIMEOUT, message="工具执行超时", retryable=True)
            )
        cancel_task.cancel()
        await asyncio.gather(cancel_task, return_exceptions=True)
        return await task

    @staticmethod
    def _validate_arguments(
        entry: RegisteredTool, arguments: dict[str, JsonValue]
    ) -> ToolError | None:
        errors = sorted(
            Draft202012Validator(entry.definition.input_schema).iter_errors(  # pyright: ignore[reportUnknownMemberType]
                arguments
            ),
            key=lambda error: tuple(str(part) for part in error.absolute_path),
        )
        if not errors:
            return None
        first = errors[0]
        path = ".".join(str(part) for part in first.absolute_path) or "$"
        return ToolError(
            code=ErrorCode.INVALID_ARGUMENT,
            message="工具参数不符合 schema",
            details={"path": path, "validator": str(first.validator)},
        )

    @staticmethod
    def _new_tool_run_id() -> ToolRunId:
        return ToolRunId.new()

    def _finish(
        self,
        request: ToolExecutionRequest,
        tool_run_id: ToolRunId,
        started_at: datetime,
        entry: RegisteredTool | None,
        status: ToolExecutionStatus,
        error: ToolError | None,
        *,
        output: JsonValue | None = None,
        truncated: bool = False,
    ) -> ToolExecutionResult:
        result = ToolExecutionResult(
            tool_run_id=tool_run_id,
            status=status,
            output=output,
            truncated=truncated,
            error=error,
        )
        context = request.context
        self._audit_sink.append(
            AuditRecord(
                thread_id=context.thread_id,
                run_id=context.run_id,
                tool_run_id=tool_run_id,
                caller_node_id=context.caller_node_id,
                execution_node_id=context.execution_node_id,
                tool_name=request.tool_name,
                tool_version=entry.definition.version if entry is not None else None,
                arguments_summary=cast(dict[str, JsonValue], self._sanitize(request.arguments)),
                started_at=started_at,
                finished_at=datetime.now(UTC),
                status=status,
                error_code=error.code if error is not None else None,
            )
        )
        return result

    @classmethod
    def _sanitize(cls, value: JsonValue, key: str = "") -> JsonValue:
        if any(marker in key.lower() for marker in _SECRET_ARGUMENT_MARKERS):
            return "[REDACTED]"
        if isinstance(value, dict):
            return {item_key: cls._sanitize(item, item_key) for item_key, item in value.items()}
        if isinstance(value, list):
            return [cls._sanitize(item) for item in value[:20]]
        if isinstance(value, str) and len(value) > 128:
            return f"{value[:128]}…"
        return value
