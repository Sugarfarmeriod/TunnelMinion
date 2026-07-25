"""与具体模型服务无关的 Provider 契约。"""

from __future__ import annotations

import asyncio
from enum import StrEnum
from typing import Protocol

from pydantic import BaseModel, ConfigDict, Field, JsonValue, model_validator


class ProviderErrorCode(StrEnum):
    """模型边界使用的可诊断错误码。"""

    AUTHENTICATION_FAILED = "authentication_failed"
    NETWORK_UNREACHABLE = "network_unreachable"
    TIMEOUT = "timeout"
    MODEL_NOT_FOUND = "model_not_found"
    CAPABILITY_INCOMPATIBLE = "capability_incompatible"
    CANCELLED = "cancelled"
    INVALID_RESPONSE = "invalid_response"
    INVALID_CONTEXT = "invalid_context"


class ProviderError(Exception):
    """不包含凭据或原始响应正文的模型错误。"""

    def __init__(self, code: ProviderErrorCode, message: str, *, retryable: bool = False) -> None:
        super().__init__(message)
        self.code = code
        self.retryable = retryable


class CancellationToken:
    """可跨 Provider 调用传播的协作式取消信号。"""

    def __init__(self) -> None:
        self._event = asyncio.Event()

    def cancel(self) -> None:
        """请求取消当前调用。"""
        self._event.set()

    @property
    def cancelled(self) -> bool:
        """返回调用是否已请求取消。"""
        return self._event.is_set()

    async def wait(self) -> None:
        """等待取消请求。"""
        await self._event.wait()


class ModelCapabilities(BaseModel):
    """Provider 对 Agent 声明的最低能力。"""

    model_config = ConfigDict(frozen=True)

    tool_calls: bool
    structured_output: bool


class ToolDefinition(BaseModel):
    """可供模型选择的结构化工具定义。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(min_length=1, max_length=128)
    description: str = Field(min_length=1, max_length=1000)
    input_schema: dict[str, JsonValue]


class ModelRequest(BaseModel):
    """单次模型调用及其能力要求。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    messages: tuple[ModelMessage, ...] = Field(min_length=1)
    tools: tuple[ToolDefinition, ...] = ()
    require_tool_call: bool = False
    response_schema: dict[str, JsonValue] | None = None


class ToolCall(BaseModel):
    """模型返回的结构化工具调用。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    call_id: str = Field(min_length=1)
    name: str = Field(min_length=1)
    arguments: dict[str, JsonValue]


class ModelMessage(BaseModel):
    """发给模型的公开消息，包含继续工具循环所需的协议字段。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    role: str = Field(pattern="^(system|user|assistant|tool)$")
    content: str
    tool_calls: tuple[ToolCall, ...] = ()
    tool_call_id: str | None = None
    name: str | None = None

    @model_validator(mode="after")
    def validate_tool_fields(self) -> ModelMessage:
        """限制工具协议字段只能出现在对应角色上。"""
        if self.tool_calls and self.role != "assistant":
            raise ValueError("tool_calls 只允许出现在 assistant 消息")
        if self.role == "tool" and self.tool_call_id is None:
            raise ValueError("tool 消息必须包含 tool_call_id")
        if self.role != "tool" and (self.tool_call_id is not None or self.name is not None):
            raise ValueError("tool_call_id 和 name 只允许出现在 tool 消息")
        return self


class ModelUsage(BaseModel):
    """Provider 可获得的 token 使用量。"""

    model_config = ConfigDict(frozen=True)

    input_tokens: int | None = Field(default=None, ge=0)
    output_tokens: int | None = Field(default=None, ge=0)
    total_tokens: int | None = Field(default=None, ge=0)


class ModelResponse(BaseModel):
    """统一后的模型文本、工具调用和结构化结果。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    content: str | None = None
    tool_calls: tuple[ToolCall, ...] = ()
    structured_output: JsonValue | None = None
    usage: ModelUsage = Field(default_factory=ModelUsage)


class ModelProvider(Protocol):
    """所有模型 Provider 必须实现的异步边界。"""

    @property
    def capabilities(self) -> ModelCapabilities:
        """返回当前适配器声明的能力。"""
        ...

    async def complete(
        self,
        request: ModelRequest,
        cancellation: CancellationToken | None = None,
    ) -> ModelResponse:
        """执行一次有超时且可取消的模型调用。"""
        ...
