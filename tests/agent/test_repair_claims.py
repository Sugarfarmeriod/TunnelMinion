"""修复声明必须与本次工具结果一致，并保存纠正后的回答。"""

import asyncio
from pathlib import Path
from unittest.mock import AsyncMock

import pytest
from pydantic import JsonValue
from tests.agent.test_langchain_agent import ScriptedProvider, definition

from tunnelminion.agent.conversation import InMemoryConversationService, StartRunInput
from tunnelminion.agent.langchain_model import TunnelMinionChatModel
from tunnelminion.agent.runtime import LangChainReadOnlyAgent
from tunnelminion.domain.delegation import DELEGATE_TOOL_NAME
from tunnelminion.domain.identifiers import NodeId
from tunnelminion.domain.tools import Platform
from tunnelminion.memory.sqlite import SQLiteStores
from tunnelminion.model.contracts import ModelResponse, ToolCall
from tunnelminion.tools.audit import InMemoryAuditSink
from tunnelminion.tools.fakes import FakeToolAdapter, FakeToolBehavior
from tunnelminion.tools.registry import ToolRegistry
from tunnelminion.tools.runtime import ToolRuntime

CORRECTION = "这次没有生成修复，需要的话请让我提出修法"
CLAIM = "我已经提出了一条待批准的修复。"


CASES: list[tuple[str | None, JsonValue, bool, bool]] = [
    (None, {}, False, False),
    ("probe_service", {}, False, False),
    ("probe_service", {"proposed": True}, False, False),
    ("propose_repair", [], False, False),
    ("propose_repair", {"proposed": False}, False, False),
    ("propose_repair", {"proposed": True}, True, False),
    ("propose_repair", {"proposed": True}, False, True),
    (DELEGATE_TOOL_NAME, {"status": "completed", "result": None}, False, False),
    (
        DELEGATE_TOOL_NAME,
        {"status": "completed", "result": {"proposed_repairs": []}},
        False,
        False,
    ),
    (
        DELEGATE_TOOL_NAME,
        {"status": "completed", "result": {"proposed_repairs": [{}]}},
        False,
        True,
    ),
    (
        DELEGATE_TOOL_NAME,
        {"status": "failed", "result": {"proposed_repairs": [{}]}},
        False,
        False,
    ),
]


@pytest.mark.parametrize(("tool_name", "output", "failed", "has_repair"), CASES)
def test_repair_claim_is_checked_and_persisted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    tool_name: str | None,
    output: JsonValue,
    failed: bool,
    has_repair: bool,
) -> None:
    registry = ToolRegistry()
    adapter = FakeToolAdapter(FakeToolBehavior.ADAPTER_ERROR)
    if not failed:
        monkeypatch.setattr(adapter, "execute", AsyncMock(return_value=output))
    name = tool_name or "probe_service"
    registry.register(definition(name), adapter)
    responses = [ModelResponse(content=CLAIM)]
    if tool_name:
        responses.insert(
            0,
            ModelResponse(
                tool_calls=(ToolCall(call_id="repair-check", name=name, arguments={"port": 8082}),)
            ),
        )
    provider = ScriptedProvider()
    monkeypatch.setattr(provider, "complete", AsyncMock(side_effect=responses))
    agent = LangChainReadOnlyAgent(
        TunnelMinionChatModel(provider=provider),
        registry,
        ToolRuntime(registry, Platform.WINDOWS, InMemoryAuditSink()),
        Platform.WINDOWS,
    )
    stores = SQLiteStores.open(tmp_path / "claims.sqlite3")
    node = NodeId.new()
    conversations = InMemoryConversationService(node, lambda: agent, stores.checkpoints)
    thread = conversations.create_thread()

    async def scenario() -> None:
        started = await conversations.start_run(
            thread.thread_id,
            StartRunInput(question="相册怎么修？", tool_names=(name,)),
        )
        events = [event async for event in conversations.stream_events(started.run_id)]
        result = conversations.get_run(started.run_id).result
        assert result is not None
        basis = "inferred" if tool_name and not failed and isinstance(output, dict) else "none"
        assert result.answer_basis == basis
        assert (CORRECTION in result.answer) is not has_repair
        assert (CORRECTION in result.evidence_answer.inferences[0]) is not has_repair
        if has_repair:
            assert result.answer.startswith(CLAIM)
        assert events[-1].message == result.answer
        restored = InMemoryConversationService(node, lambda: agent, stores.checkpoints)
        saved = restored.get_thread(thread.thread_id).messages[-1]
        assert saved.content == result.answer and saved.answer_basis == basis
        assert restored.get_run(started.run_id).result == result

    asyncio.run(scenario())


@pytest.mark.parametrize(
    ("answer", "claim"),
    [
        ("提出了重启容器的修复。", True),
        ("已提交修复，等你批准。", True),
        ("修法已经生成了，正在等待批准。", True),
        ("有一个待批准的修复。", True),
        ("已提交一条修法，等您批准。", True),
        ("服务没有运行。", False),
        ("需要的话，我可以提出修复。", False),
        ("这次没有提出修复。", False),
        ("没有待批准的修复。", False),
    ],
)
def test_small_repair_claim_matcher(
    monkeypatch: pytest.MonkeyPatch, answer: str, claim: bool
) -> None:
    from tests.agent.test_langchain_agent import build_agent, context

    agent, provider, _ = build_agent()
    monkeypatch.setattr(provider, "complete", AsyncMock(return_value=ModelResponse(content=answer)))
    result = asyncio.run(agent.run("相册的检查结果是什么？", context(), ("probe_service",)))
    assert result.answer == (f"{answer}\n\n{CORRECTION}" if claim else answer)
