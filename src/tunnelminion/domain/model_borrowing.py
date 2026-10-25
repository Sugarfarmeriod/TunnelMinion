"""模型借用：借用方把一轮模型调用交给提供方的模型去算。

借用的只是一次模型调用。Agent 的循环、工具执行和判断都留在借用方本机；
提供方只记录每个对端每天用了多少 token、调用了几次，不保存消息内容。
"""

from __future__ import annotations

from datetime import date

from pydantic import BaseModel, ConfigDict, Field, JsonValue

from tunnelminion.domain.identifiers import NodeId
from tunnelminion.model.contracts import (
    ModelMessage,
    ModelRequest,
    ModelResponse,
    ModelUsage,
    ToolCall,
    ToolDefinition,
)

# 一次借用调用的总时长上限，与工具调用的 30 秒上限分开算。
MAX_MODEL_CALL_SECONDS = 180.0
# 提供方给每个对端的默认每日 token 额度。
DEFAULT_DAILY_TOKEN_QUOTA = 200_000
# 同一个对端同时进行的借用调用上限。
MAX_CONCURRENT_CALLS_PER_PEER = 2


class BorrowedMessage(BaseModel):
    """线上传输的一条消息。

    与 `ModelMessage` 字段相同，但 `reasoning_content` 会被传输：
    部分推理模型要求同一轮工具循环里把它原样带回。
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    role: str = Field(pattern="^(system|user|assistant|tool)$")
    content: str
    reasoning_content: str | None = None
    tool_calls: tuple[ToolCall, ...] = ()
    tool_call_id: str | None = None
    name: str | None = None

    @classmethod
    def from_message(cls, message: ModelMessage) -> BorrowedMessage:
        """把本机消息转成线上格式。"""
        return cls(
            role=message.role,
            content=message.content,
            reasoning_content=message.reasoning_content,
            tool_calls=message.tool_calls,
            tool_call_id=message.tool_call_id,
            name=message.name,
        )

    def to_message(self) -> ModelMessage:
        """还原成本机消息，并重新执行角色与字段的校验。"""
        return ModelMessage(
            role=self.role,
            content=self.content,
            reasoning_content=self.reasoning_content,
            tool_calls=self.tool_calls,
            tool_call_id=self.tool_call_id,
            name=self.name,
        )


class BorrowedModelCall(BaseModel):
    """`POST /v1/model:complete` 的请求体。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    caller_node_id: NodeId
    messages: tuple[BorrowedMessage, ...] = Field(min_length=1, max_length=200)
    tools: tuple[ToolDefinition, ...] = Field(default=(), max_length=64)
    require_tool_call: bool = False
    response_schema: dict[str, JsonValue] | None = None

    @classmethod
    def from_request(cls, caller: NodeId, request: ModelRequest) -> BorrowedModelCall:
        """把本机的一次模型请求转成线上格式。"""
        return cls(
            caller_node_id=caller,
            messages=tuple(BorrowedMessage.from_message(item) for item in request.messages),
            tools=request.tools,
            require_tool_call=request.require_tool_call,
            response_schema=request.response_schema,
        )

    def to_request(self) -> ModelRequest:
        """还原成提供方本机模型能直接处理的请求。"""
        return ModelRequest(
            messages=tuple(item.to_message() for item in self.messages),
            tools=self.tools,
            require_tool_call=self.require_tool_call,
            response_schema=self.response_schema,
        )


class BorrowedModelResult(BaseModel):
    """`POST /v1/model:complete` 成功时的响应体。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    provider_node_id: NodeId
    content: str | None = None
    reasoning_content: str | None = None
    tool_calls: tuple[ToolCall, ...] = ()
    structured_output: JsonValue | None = None
    usage: ModelUsage = Field(default_factory=ModelUsage)

    @classmethod
    def from_response(cls, provider: NodeId, response: ModelResponse) -> BorrowedModelResult:
        """把提供方模型的回复转成线上格式。"""
        return cls(
            provider_node_id=provider,
            content=response.content,
            reasoning_content=response.reasoning_content,
            tool_calls=response.tool_calls,
            structured_output=response.structured_output,
            usage=response.usage,
        )

    def to_response(self) -> ModelResponse:
        """还原成借用方 Agent 能直接使用的回复。"""
        return ModelResponse(
            content=self.content,
            reasoning_content=self.reasoning_content,
            tool_calls=self.tool_calls,
            structured_output=self.structured_output,
            usage=self.usage,
        )


class ModelUsageRecord(BaseModel):
    """提供方给某个对端某一天记的账：只有次数和 token，没有内容。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    peer_node_id: NodeId
    day: date
    calls: int = Field(ge=0)
    tokens: int = Field(ge=0)
