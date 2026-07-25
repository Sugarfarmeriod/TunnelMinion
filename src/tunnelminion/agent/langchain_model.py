"""把 TunnelMinion 模型 Provider 适配为 LangChain 聊天模型。"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Any, cast

from langchain_core.language_models import BaseChatModel
from langchain_core.messages import AIMessage, BaseMessage, HumanMessage, SystemMessage, ToolMessage
from langchain_core.outputs import ChatGeneration, ChatResult
from langchain_core.runnables import Runnable
from langchain_core.tools import BaseTool
from langchain_core.utils.function_calling import convert_to_openai_tool
from pydantic import ConfigDict, Field, JsonValue

from tunnelminion.agent.context_contracts import ContextRequest, ContextTaskType
from tunnelminion.agent.context_runtime import ContextModelRuntime
from tunnelminion.domain.identifiers import RunId, ThreadId
from tunnelminion.model.contracts import (
    CancellationToken,
    ModelMessage,
    ModelProvider,
    ModelResponse,
    ToolCall,
    ToolDefinition,
)


@dataclass
class ModelRunMetrics:
    """一次 Agent run 的模型轮次与可获得 token 累计。"""

    model_rounds: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    total_tokens: int = 0

    def record(self, response: ModelResponse) -> None:
        """只累计 Provider 实际返回的使用量。"""
        self.model_rounds += 1
        self.input_tokens += response.usage.input_tokens or 0
        self.output_tokens += response.usage.output_tokens or 0
        self.total_tokens += response.usage.total_tokens or 0


class TunnelMinionChatModel(BaseChatModel):
    """保留既有 Provider 边界的 LangChain `BaseChatModel`。"""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    provider: object
    run_metrics: ModelRunMetrics = Field(default_factory=ModelRunMetrics)
    cancellation_token: CancellationToken | None = None
    thread_id: ThreadId | None = None
    run_id: RunId | None = None

    @property
    def _llm_type(self) -> str:
        return "tunnelminion-provider"

    @property
    def _identifying_params(self) -> dict[str, Any]:
        return {"provider": type(self.provider).__name__}

    def bind_tools(
        self,
        tools: Sequence[dict[str, Any] | type | Callable[..., Any] | BaseTool],
        *,
        tool_choice: str | None = None,
        **kwargs: Any,
    ) -> Runnable[Any, AIMessage]:
        """把 LangChain 工具规范绑定到单次模型调用。"""
        formatted = [convert_to_openai_tool(tool) for tool in tools]
        return self.bind(tools=formatted, tool_choice=tool_choice, **kwargs)

    def _generate(
        self,
        messages: list[BaseMessage],
        stop: list[str] | None = None,
        run_manager: Any | None = None,
        **kwargs: Any,
    ) -> ChatResult:
        """支持 LangChain 同步入口；产品路径优先使用异步调用。"""
        del stop, run_manager
        return asyncio.run(self._complete(messages, kwargs))

    async def _agenerate(
        self,
        messages: list[BaseMessage],
        stop: list[str] | None = None,
        run_manager: Any | None = None,
        **kwargs: Any,
    ) -> ChatResult:
        """通过现有异步 Provider 完成一次模型轮次。"""
        del stop, run_manager
        return await self._complete(messages, kwargs)

    async def _complete(self, messages: list[BaseMessage], kwargs: dict[str, Any]) -> ChatResult:
        if self.thread_id is None or self.run_id is None:
            raise ValueError("生产模型调用必须关联 thread_id 和 run_id")
        request = ContextRequest(
            task_type=ContextTaskType.LOCAL_CONVERSATION,
            current_intent=self._text_content(messages[-1].content),
            thread_id=self.thread_id,
            run_id=self.run_id,
            prompt_id="readonly-agent",
            prompt_version="v1",
            messages=tuple(self._convert_message(message) for message in messages),
            tools=self._convert_tools(cast(list[dict[str, Any]], kwargs.get("tools", []))),
            require_tool_call=kwargs.get("tool_choice") in {"required", "any"},
        )
        invocation = await ContextModelRuntime(
            cast(ModelProvider, self.provider),
            tool_schema_version="readonly-tools/v1",
        ).invoke(
            request,
            self.cancellation_token,
        )
        response = invocation.response
        self.run_metrics.record(response)
        return self._convert_response(response)

    @classmethod
    def _convert_message(cls, message: BaseMessage) -> ModelMessage:
        content = cls._text_content(message.content)
        if isinstance(message, SystemMessage):
            return ModelMessage(role="system", content=content)
        if isinstance(message, HumanMessage):
            return ModelMessage(role="user", content=content)
        if isinstance(message, ToolMessage):
            return ModelMessage(
                role="tool",
                content=content,
                tool_call_id=message.tool_call_id,
                name=message.name,
            )
        if isinstance(message, AIMessage):
            calls = tuple(
                ToolCall(
                    call_id=str(call["id"]),
                    name=str(call["name"]),
                    arguments=cast(dict[str, JsonValue], call["args"]),
                )
                for call in message.tool_calls
            )
            return ModelMessage(role="assistant", content=content, tool_calls=calls)
        raise TypeError(f"不支持的 LangChain 消息类型：{type(message).__name__}")

    @staticmethod
    def _text_content(content: str | list[str | dict[str, Any]] | None) -> str:
        if content is None:
            return ""
        if isinstance(content, str):
            return content
        return json.dumps(content, ensure_ascii=False, separators=(",", ":"))

    @staticmethod
    def _convert_tools(tools: list[dict[str, Any]]) -> tuple[ToolDefinition, ...]:
        definitions: list[ToolDefinition] = []
        for tool in tools:
            function = cast(dict[str, Any], tool["function"])
            definitions.append(
                ToolDefinition(
                    name=str(function["name"]),
                    description=str(function.get("description") or "只读工具"),
                    input_schema=cast(dict[str, JsonValue], function["parameters"]),
                )
            )
        return tuple(definitions)

    @staticmethod
    def _convert_response(response: ModelResponse) -> ChatResult:
        tool_calls = [
            {
                "id": call.call_id,
                "name": call.name,
                "args": call.arguments,
                "type": "tool_call",
            }
            for call in response.tool_calls
        ]
        usage = response.usage.model_dump(mode="json")
        message = AIMessage(
            content=response.content or "",
            tool_calls=cast(Any, tool_calls),
            response_metadata={"usage": usage},
        )
        return ChatResult(
            generations=[ChatGeneration(message=message)],
            llm_output={"usage": usage},
        )
