"""Tool Runtime 的执行边界与结构化结果。"""

from __future__ import annotations

import asyncio
from enum import StrEnum
from typing import Protocol

from pydantic import BaseModel, ConfigDict, Field, JsonValue, model_validator

from tunnelminion.domain.errors import ToolError
from tunnelminion.domain.identifiers import NodeId, RunId, ThreadId, ToolRunId


class ToolCancellationToken:
    """可从 Agent 或远端网关传播到工具适配器的取消信号。"""

    def __init__(self) -> None:
        self._event = asyncio.Event()

    def cancel(self) -> None:
        """请求停止当前工具调用。"""
        self._event.set()

    @property
    def cancelled(self) -> bool:
        """返回是否已经请求取消。"""
        return self._event.is_set()

    async def wait(self) -> None:
        """等待取消请求。"""
        await self._event.wait()


class ToolAdapterError(Exception):
    """平台适配器主动返回的安全结构化错误。"""

    def __init__(self, error: ToolError) -> None:
        super().__init__(error.message)
        self.error = error


class ToolAdapter(Protocol):
    """预定义工具适配器的最小异步接口。"""

    async def execute(
        self,
        arguments: dict[str, JsonValue],
        cancellation: ToolCancellationToken,
    ) -> JsonValue:
        """执行固定能力，不得解释或执行动态代码。"""
        ...


class ToolCallContext(BaseModel):
    """一次工具调用的本地与跨节点关联上下文。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    thread_id: ThreadId
    run_id: RunId
    caller_node_id: NodeId
    execution_node_id: NodeId


class ToolExecutionRequest(BaseModel):
    """进入 Tool Runtime 的结构化调用请求。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    context: ToolCallContext
    tool_run_id: ToolRunId | None = None
    tool_name: str = Field(min_length=1, max_length=128)
    arguments: dict[str, JsonValue] = Field(default_factory=dict)


class ToolExecutionStatus(StrEnum):
    """可审计且可供 Agent 判断的工具终态。"""

    SUCCESS = "success"
    PARTIAL = "partial"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ToolExecutionResult(BaseModel):
    """工具输出或错误；截断结果保留部分证据。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    tool_run_id: ToolRunId
    status: ToolExecutionStatus
    output: JsonValue | None = None
    truncated: bool = False
    error: ToolError | None = None

    @model_validator(mode="after")
    def validate_result(self) -> ToolExecutionResult:
        """保证成功、部分结果和失败的字段组合一致。"""
        if self.status is ToolExecutionStatus.SUCCESS:
            if self.error is not None or self.truncated:
                raise ValueError("成功结果不得包含错误或截断标记")
        elif self.status is ToolExecutionStatus.PARTIAL:
            if self.error is None or not self.truncated or self.output is None:
                raise ValueError("部分结果必须包含输出、截断标记和错误")
        else:
            if self.output is not None:
                raise ValueError("失败或取消结果不得包含输出")
            if self.error is None:
                raise ValueError("失败或取消结果必须包含错误")
        return self
