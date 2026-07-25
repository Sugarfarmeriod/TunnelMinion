"""对消息、工具、结果和记忆分别应用硬预算的 Context Builder。"""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from typing import TypeVar

from pydantic import BaseModel, ConfigDict, Field, JsonValue

from tunnelminion.domain.identifiers import ArtifactId, ToolRunId
from tunnelminion.memory.contracts import LongTermMemory, ToolArtifact, ToolArtifactStore
from tunnelminion.model.contracts import ModelMessage, ToolDefinition

T = TypeVar("T")


class ContextBudgets(BaseModel):
    """历史、消息、工具、结果和记忆互不借用的字符预算。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    message_chars: int = Field(default=16_000, ge=256, le=2_000_000)
    history_chars: int = Field(default=12_000, ge=256, le=2_000_000)
    tool_schema_chars: int = Field(default=16_000, ge=256, le=2_000_000)
    tool_result_chars: int = Field(default=24_000, ge=256, le=2_000_000)
    memory_chars: int = Field(default=8_000, ge=256, le=2_000_000)


class ToolResultContext(BaseModel):
    """进入模型上下文前的工具结果摘要或引用。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    tool_run_id: ToolRunId
    content: str
    artifact_id: ArtifactId | None = None


class ContextDropCounts(BaseModel):
    """因预算或确认策略未进入上下文的项目数量。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    messages: int = Field(ge=0)
    tools: int = Field(ge=0)
    tool_results: int = Field(ge=0)
    memories: int = Field(ge=0)


class ContextSize(BaseModel):
    """实际进入上下文的分类字符规模。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    message_chars: int = Field(ge=0)
    tool_schema_chars: int = Field(ge=0)
    tool_result_chars: int = Field(ge=0)
    memory_chars: int = Field(ge=0)
    total_chars: int = Field(ge=0)


class BuiltContext(BaseModel):
    """经过分类预算后可交给 Agent 的上下文。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    messages: tuple[ModelMessage, ...]
    tools: tuple[ToolDefinition, ...]
    tool_results: tuple[ToolResultContext, ...]
    memories: tuple[LongTermMemory, ...]
    dropped: ContextDropCounts
    rolling_summary: str | None = None
    size: ContextSize


class ArtifactContextManager:
    """把大型工具正文保存为 artifact，仅返回相关预览与引用。"""

    def __init__(
        self,
        store: ToolArtifactStore,
        *,
        inline_bytes: int = 8_000,
        preview_chars: int = 1_000,
    ) -> None:
        if inline_bytes < 256 or preview_chars < 64:
            raise ValueError("artifact 内联和预览预算过小")
        self._store = store
        self._inline_bytes = inline_bytes
        self._preview_chars = preview_chars

    def prepare(
        self,
        tool_run_id: ToolRunId,
        content: JsonValue,
        question: str,
    ) -> ToolResultContext:
        """小结果直接内联，大结果持久化后选择相关文本片段。"""
        serialized = json.dumps(content, ensure_ascii=False, separators=(",", ":"))
        size = len(serialized.encode("utf-8"))
        if size <= self._inline_bytes:
            return ToolResultContext(tool_run_id=tool_run_id, content=serialized)
        artifact = ToolArtifact(
            artifact_id=ArtifactId.new(),
            tool_run_id=tool_run_id,
            content=content,
            content_bytes=size,
            created_at=datetime.now(UTC),
        )
        self._store.put(artifact)
        preview = self._relevant_preview(serialized, question)
        return ToolResultContext(
            tool_run_id=tool_run_id,
            artifact_id=artifact.artifact_id,
            content=f"artifact={artifact.artifact_id}; preview={preview}",
        )

    def _relevant_preview(self, content: str, question: str) -> str:
        terms = {
            term.lower() for term in re.findall(r"[\w\u4e00-\u9fff]+", question) if len(term) >= 2
        }
        ranked: list[tuple[int, int, str]] = []
        for index, fragment in enumerate(re.split(r"(?<=[},\]])", content)):
            lowered = fragment.lower()
            score = sum(term in lowered for term in terms)
            if score:
                ranked.append((-score, index, fragment))
        ranked.sort()
        selected = "".join(fragment for _, _, fragment in ranked) if ranked else content
        return selected[: self._preview_chars]


class ContextBuilder:
    """优先保留最近消息/结果，并拒绝未经用户确认的长期记忆。"""

    def __init__(self, budgets: ContextBudgets | None = None) -> None:
        self._budgets = budgets or ContextBudgets()

    def build(
        self,
        messages: Sequence[ModelMessage],
        tools: Sequence[ToolDefinition],
        tool_results: Sequence[ToolResultContext],
        memories: Sequence[LongTermMemory],
        previous_summary: str | None = None,
    ) -> BuiltContext:
        """分别裁剪四类输入，任何一类都不能挤占其他类别预算。"""
        initial_messages = self._recent(
            messages,
            self._budgets.message_chars,
            lambda item: len(item.content),
        )
        initially_dropped = len(messages) - len(initial_messages)
        rolling_summary = self._rolling_summary(messages[:initially_dropped], previous_summary)
        if rolling_summary is not None:
            rolling_summary = rolling_summary[: self._budgets.message_chars // 4]
        selected_messages = self._recent(
            messages,
            self._budgets.message_chars - len(rolling_summary or ""),
            lambda item: len(item.content),
        )
        selected_tools = self._forward(
            tools,
            self._budgets.tool_schema_chars,
            self._tool_size,
        )
        selected_results = self._recent(
            tool_results,
            self._budgets.tool_result_chars,
            lambda item: len(item.content),
        )
        confirmed = tuple(item for item in memories if item.user_confirmed)
        selected_memories = self._forward(
            confirmed,
            self._budgets.memory_chars,
            lambda item: len(item.content) + len(item.source),
        )
        tool_schema_chars = sum(self._tool_size(item) for item in selected_tools)
        message_chars = sum(len(item.content) for item in selected_messages) + len(
            rolling_summary or ""
        )
        tool_result_chars = sum(len(item.content) for item in selected_results)
        memory_chars = sum(len(item.content) + len(item.source) for item in selected_memories)
        return BuiltContext(
            messages=selected_messages,
            tools=selected_tools,
            tool_results=selected_results,
            memories=selected_memories,
            dropped=ContextDropCounts(
                messages=len(messages) - len(selected_messages),
                tools=len(tools) - len(selected_tools),
                tool_results=len(tool_results) - len(selected_results),
                memories=len(memories) - len(selected_memories),
            ),
            rolling_summary=rolling_summary,
            size=ContextSize(
                message_chars=message_chars,
                tool_schema_chars=tool_schema_chars,
                tool_result_chars=tool_result_chars,
                memory_chars=memory_chars,
                total_chars=(message_chars + tool_schema_chars + tool_result_chars + memory_chars),
            ),
        )

    @staticmethod
    def _forward(items: Sequence[T], budget: int, size: Callable[[T], int]) -> tuple[T, ...]:
        selected: list[T] = []
        used = 0
        for item in items:
            item_size = size(item)
            if used + item_size > budget:
                continue
            selected.append(item)
            used += item_size
        return tuple(selected)

    @staticmethod
    def _recent(items: Sequence[T], budget: int, size: Callable[[T], int]) -> tuple[T, ...]:
        selected: list[T] = []
        used = 0
        for item in reversed(items):
            item_size = size(item)
            if used + item_size > budget:
                break
            selected.append(item)
            used += item_size
        return tuple(reversed(selected))

    @staticmethod
    def _tool_size(tool: ToolDefinition) -> int:
        return (
            len(tool.name)
            + len(tool.description)
            + len(json.dumps(tool.input_schema, ensure_ascii=False, separators=(",", ":")))
        )

    @staticmethod
    def _rolling_summary(
        messages: Sequence[ModelMessage], previous_summary: str | None
    ) -> str | None:
        if not messages:
            return previous_summary
        parts = [previous_summary] if previous_summary else []
        parts.extend(f"{item.role}: {item.content[:120]}" for item in messages)
        return "历史对话摘要（不得作为实时事实）: " + " | ".join(parts)
