"""Context Builder 分类预算、近期优先与记忆确认测试。"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import cast

import pytest
from pydantic import JsonValue, ValidationError

from tunnelminion.domain.identifiers import ArtifactId, MemoryId, NodeId, ToolRunId
from tunnelminion.memory.context import (
    ArtifactContextManager,
    ContextBudgets,
    ContextBuilder,
    ToolResultContext,
)
from tunnelminion.memory.contracts import (
    LongTermMemory,
    MemoryKind,
    MemoryNamespace,
)
from tunnelminion.memory.sqlite import SQLiteStores
from tunnelminion.model.contracts import ModelMessage, ToolDefinition


def tool(name: str, description_size: int) -> ToolDefinition:
    """创建具有可控 schema 大小的模型工具。"""
    return ToolDefinition(
        name=name,
        description="d" * description_size,
        input_schema={"type": "object", "properties": {}},
    )


def memory(content: str, *, confirmed: bool = True) -> LongTermMemory:
    """创建具有固定 namespace 的长期记忆。"""
    return LongTermMemory(
        memory_id=MemoryId.new(),
        namespace=MemoryNamespace(user="u", network="n", node_id=NodeId.new()),
        kind=MemoryKind.PREFERENCE,
        content=content,
        source="user",
        user_confirmed=confirmed,
        updated_at=datetime.now(UTC),
    )


def test_context_builder_applies_independent_budgets() -> None:
    """一类输入超额不会借用另一类剩余空间。"""
    builder = ContextBuilder(
        ContextBudgets(
            message_chars=256,
            tool_schema_chars=256,
            tool_result_chars=256,
            memory_chars=256,
        )
    )
    messages = (
        ModelMessage(role="user", content="旧" * 200),
        ModelMessage(role="assistant", content="近" * 100),
        ModelMessage(role="user", content="新" * 100),
    )
    tools = (tool("small_tool", 50), tool("large_tool", 300))
    results = (
        ToolResultContext(tool_run_id=ToolRunId.new(), content="旧" * 200),
        ToolResultContext(tool_run_id=ToolRunId.new(), content="新" * 100),
    )
    memories = (
        memory("保留" * 40),
        memory("模型猜测" * 20, confirmed=False),
        memory("过大" * 200),
    )

    built = builder.build(messages, tools, results, memories)

    assert built.messages == messages[2:]
    assert built.tools == tools[:1]
    assert built.tool_results == results[1:]
    assert built.memories == memories[:1]
    assert built.dropped.model_dump() == {
        "messages": 2,
        "tools": 1,
        "tool_results": 1,
        "memories": 2,
    }
    assert sum(len(item.content) for item in built.messages) <= 256
    assert sum(len(item.content) for item in built.tool_results) <= 256
    assert built.rolling_summary is not None
    assert built.rolling_summary.startswith("历史对话摘要（不得作为实时事实）")
    assert "user:" in built.rolling_summary
    assert built.size.message_chars <= 256
    assert built.size.total_chars == (
        built.size.message_chars
        + built.size.tool_schema_chars
        + built.size.tool_result_chars
        + built.size.memory_chars
    )


def test_default_context_builder_keeps_small_confirmed_inputs() -> None:
    """默认预算下的小型已确认输入完整保留。"""
    messages = (ModelMessage(role="user", content="你好"),)
    tools = (tool("node_summary", 10),)
    results = (ToolResultContext(tool_run_id=ToolRunId.new(), content="ready"),)
    memories = (memory("偏好中文"),)

    built = ContextBuilder().build(messages, tools, results, memories)

    assert built.messages == messages
    assert built.tools == tools
    assert built.tool_results == results
    assert built.memories == memories
    assert built.dropped.messages == 0
    assert built.rolling_summary is None
    assert built.size.total_chars > 0

    continued = ContextBuilder().build(messages, tools, results, memories, "既有摘要")
    assert continued.rolling_summary == "既有摘要"
    assert continued.size.message_chars == len("你好既有摘要")


def test_current_tool_result_survives_old_status_conflict() -> None:
    """旧对话状态即使进入摘要，也明确降级，最新工具结果仍完整进入上下文。"""
    builder = ContextBuilder(ContextBudgets(message_chars=256, tool_result_chars=256))
    messages = (
        ModelMessage(role="assistant", content="旧检测说服务离线" * 40),
        ModelMessage(role="user", content="现在服务恢复了吗？"),
    )
    current = ToolResultContext(
        tool_run_id=ToolRunId.new(), content='{"reachable":true,"checked_at":"now"}'
    )

    built = builder.build(messages, (), (current,), ())

    assert built.tool_results == (current,)
    assert built.rolling_summary is not None
    assert "不得作为实时事实" in built.rolling_summary
    assert "reachable" in built.tool_results[0].content


def test_context_budget_rejects_too_small_or_unknown_values() -> None:
    """预算不能小到失去实际约束意义，也不接受未知字段。"""
    try:
        ContextBudgets(message_chars=1)
    except ValidationError as exc:
        assert "message_chars" in str(exc)
    else:
        raise AssertionError("应拒绝过小预算")

    try:
        ContextBudgets.model_validate({"unknown": 1})
    except ValidationError as exc:
        assert "unknown" in str(exc)
    else:
        raise AssertionError("应拒绝未知预算字段")


def test_artifact_manager_inlines_small_and_persists_large_results(tmp_path: Path) -> None:
    """大结果保存完整 artifact，模型只收到问题相关片段和稳定引用。"""
    store = SQLiteStores.open(tmp_path / "context.sqlite3").artifacts
    manager = ArtifactContextManager(store, inline_bytes=256, preview_chars=80)
    small_id = ToolRunId.new()
    small = manager.prepare(small_id, {"status": "ok"}, "状态")
    assert small.artifact_id is None
    assert small.content == '{"status":"ok"}'

    large_id = ToolRunId.new()
    large_content = cast(
        JsonValue,
        {
            "services": [{"name": "unrelated-service", "port": index} for index in range(40)]
            + [{"name": "pdf-service", "port": 8080}]
        },
    )
    prepared = manager.prepare(large_id, large_content, "pdf service 在哪里")

    assert isinstance(prepared.artifact_id, ArtifactId)
    artifact = store.get(prepared.artifact_id)
    assert artifact is not None
    assert artifact.content == large_content
    assert artifact.content_bytes > 256
    assert "artifact=" in prepared.content
    assert "pdf-service" in prepared.content
    assert len(prepared.content) < 200

    fallback = manager.prepare(ToolRunId.new(), large_content, "完全不匹配词语")
    assert fallback.artifact_id is not None
    assert "services" in fallback.content


@pytest.mark.parametrize(
    "values",
    [
        {"inline_bytes": 1, "preview_chars": 100},
        {"inline_bytes": 256, "preview_chars": 1},
    ],
)
def test_artifact_manager_rejects_useless_budgets(tmp_path: Path, values: dict[str, int]) -> None:
    """artifact 预算不能小到无法提供安全引用。"""
    store = SQLiteStores.open(tmp_path / "invalid.sqlite3").artifacts
    with pytest.raises(ValueError, match="预算过小"):
        ArtifactContextManager(store, **values)
