"""把 TunnelMinion 模型 Provider 适配为 LangChain 聊天模型。"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from typing import Any, cast

from langchain_core.language_models import BaseChatModel
from langchain_core.messages import AIMessage, BaseMessage, HumanMessage, SystemMessage, ToolMessage
from langchain_core.outputs import ChatGeneration, ChatResult
from langchain_core.runnables import Runnable
from langchain_core.tools import BaseTool
from langchain_core.utils.function_calling import convert_to_openai_tool
from pydantic import ConfigDict, Field, JsonValue

from tunnelminion.agent.context_contracts import (
    ContextContentKind,
    ContextContentReference,
    ContextRequest,
    ContextTaskType,
    ContextTrust,
    FailurePhase,
    FailureRecord,
    HistoryContext,
    RedactedContextRecord,
)
from tunnelminion.agent.context_runtime import (
    ContextBuildError,
    ContextModelRuntime,
    make_context_reference,
)
from tunnelminion.agent.observability import classify_failure
from tunnelminion.agent.prompts import READONLY_AGENT_PROMPT
from tunnelminion.domain.identifiers import ArtifactId, RunId, ThreadId, ToolRunId
from tunnelminion.memory.context import ToolResultContext
from tunnelminion.memory.contracts import LongTermMemory
from tunnelminion.model.contracts import (
    CancellationToken,
    ModelMessage,
    ModelProvider,
    ModelResponse,
    ToolCall,
    ToolDefinition,
)


def _context_records() -> list[RedactedContextRecord]:
    return []


def _failure_records() -> list[FailureRecord]:
    return []


@dataclass
class ModelRunMetrics:
    """一次 Agent run 的模型轮次与可获得 token 累计。"""

    model_rounds: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    total_tokens: int = 0
    context_records: list[RedactedContextRecord] = dataclass_field(default_factory=_context_records)
    failures: list[FailureRecord] = dataclass_field(default_factory=_failure_records)

    def record(
        self,
        response: ModelResponse,
        record: RedactedContextRecord,
    ) -> None:
        """只累计 Provider 实际返回的使用量。"""
        self.model_rounds += 1
        self.input_tokens += response.usage.input_tokens or 0
        self.output_tokens += response.usage.output_tokens or 0
        self.total_tokens += response.usage.total_tokens or 0
        self.context_records.append(record)

    def record_failure(self, failure: FailureRecord) -> None:
        """保存稳定分类，不记录异常消息或输入正文。"""
        self.failures.append(failure)


class TunnelMinionChatModel(BaseChatModel):
    """保留既有 Provider 边界的 LangChain `BaseChatModel`。"""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    provider: object
    run_metrics: ModelRunMetrics = Field(default_factory=ModelRunMetrics)
    cancellation_token: CancellationToken | None = None
    thread_id: ThreadId | None = None
    run_id: RunId | None = None
    history_context: HistoryContext | None = None
    memories: tuple[LongTermMemory, ...] = ()

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
        converted = tuple(self._convert_message(message) for message in messages)
        normal_messages: list[ModelMessage] = []
        tool_results: list[ToolResultContext] = []
        artifact_references: list[ContextContentReference] = []
        for message in converted:
            result = self._tool_result_context(message)
            if result is None:
                normal_messages.append(message)
                continue
            tool_results.append(result)
            if result.artifact_id is not None:
                artifact_references.append(
                    make_context_reference(
                        ContextContentKind.ARTIFACT,
                        f"tool-run:{result.tool_run_id}",
                        result.content,
                        ContextTrust.UNTRUSTED_DATA,
                        artifact_id=result.artifact_id,
                        content_chars=result.content_bytes,
                    )
                )
        request = ContextRequest(
            task_type=ContextTaskType.LOCAL_CONVERSATION,
            current_intent=self._text_content(messages[-1].content),
            thread_id=self.thread_id,
            run_id=self.run_id,
            prompt_id=READONLY_AGENT_PROMPT.prompt_id,
            prompt_version=READONLY_AGENT_PROMPT.version,
            messages=tuple(normal_messages),
            tools=self._convert_tools(cast(list[dict[str, Any]], kwargs.get("tools", []))),
            tool_results=tuple(tool_results),
            artifact_references=tuple(artifact_references),
            require_tool_call=kwargs.get("tool_choice") in {"required", "any"},
            history=self.history_context,
            memories=self.memories,
        )
        try:
            invocation = await ContextModelRuntime(
                cast(ModelProvider, self.provider),
                tool_schema_version="readonly-tools/v1",
            ).invoke(
                request,
                self.cancellation_token,
            )
        except Exception as exc:
            phase = (
                FailurePhase.CONTEXT_BUILD
                if isinstance(exc, ContextBuildError)
                else FailurePhase.MODEL_INVOKE
            )
            self.run_metrics.record_failure(
                classify_failure(
                    exc,
                    phase=phase,
                    source_refs=(f"run:{self.run_id}",),
                )
            )
            raise
        response = invocation.response
        self.run_metrics.record(
            response,
            invocation.record,
        )
        return self._convert_response(response)

    @staticmethod
    def _tool_result_context(message: ModelMessage) -> ToolResultContext | None:
        """从本项目生成的 ToolMessage 信封提取独立预算和制品元数据。"""
        if message.role != "tool":
            return None
        try:
            payload = cast(dict[str, Any], json.loads(message.content))
            result = cast(dict[str, Any], payload["result"])
            tool_run_id = ToolRunId(str(result["tool_run_id"]))
            raw_artifact_id = result.get("artifact_id")
            return ToolResultContext(
                tool_run_id=tool_run_id,
                content=message.content,
                artifact_id=(
                    ArtifactId(str(raw_artifact_id)) if raw_artifact_id is not None else None
                ),
                tool_call_id=message.tool_call_id,
                tool_name=message.name,
                content_bytes=int(result.get("content_bytes") or len(message.content)),
                content_type=str(result.get("content_type") or "application/json"),
                truncated=bool(result.get("truncated")),
            )
        except (KeyError, TypeError, ValueError, json.JSONDecodeError):
            return None

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
