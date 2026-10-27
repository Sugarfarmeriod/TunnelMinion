"""本地 thread/run 生命周期、事件和取消测试。"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Coroutine
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, TypeVar
from unittest.mock import AsyncMock

import pytest
from pydantic import TypeAdapter
from tests.agent.test_connection_fact_check import connection_agent, connection_case
from tests.agent.test_langchain_agent import ScriptedProvider, SlowProvider, build_agent

from tunnelminion.agent.conversation import (
    InMemoryConversationService,
    RunEvent,
    RunEventType,
    RunStatus,
    RunView,
    StartRunInput,
)
from tunnelminion.agent.runtime import AgentStopReason, CheckedAgentTurnResult
from tunnelminion.domain.identifiers import MemoryId, NodeId, RunId, ServiceId, ThreadId
from tunnelminion.memory.contracts import (
    CheckpointStatus,
    LongTermMemory,
    MemoryKind,
    MemoryNamespace,
)
from tunnelminion.memory.service import MemoryContextRetriever
from tunnelminion.memory.sqlite import SQLiteStores
from tunnelminion.model.contracts import ModelResponse
from tunnelminion.tools.fakes import FakeToolBehavior

T = TypeVar("T")


def run(coroutine: Coroutine[Any, Any, T]) -> T:
    """执行异步测试动作。"""
    return asyncio.run(coroutine)


def service(*, slow: bool = False) -> InMemoryConversationService:
    """创建使用确定性 Agent 的进程内会话服务。"""
    provider = SlowProvider() if slow else None
    return InMemoryConversationService(
        NodeId.new(),
        lambda: build_agent(provider)[0],
    )


async def collect(events: AsyncIterator[RunEvent]) -> list[RunEvent]:
    """收集直到 run 终态的全部公开事件。"""
    return [event async for event in events]


def test_thread_run_and_public_tool_event_lifecycle() -> None:
    """一次成功 run 依次公开目标、工具状态和最终结果。"""
    conversations = service()
    first = conversations.create_thread()
    second = conversations.create_thread()
    assert conversations.list_threads() == (first, second)

    async def scenario() -> tuple[RunView, list[RunEvent]]:
        started = await conversations.start_run(
            first.thread_id,
            StartRunInput(question="检查 8082", tool_names=("probe_service",)),
        )
        events = await collect(conversations.stream_events(started.run_id))
        return conversations.get_run(started.run_id), events

    final, events = run(scenario())

    assert final.status is RunStatus.COMPLETED
    assert final.finished_at is not None
    assert final.result is not None
    assert isinstance(final.result, CheckedAgentTurnResult)
    assert final.result.answer_checked
    assert final.result.answer_basis == "inferred"
    assert final.result.checked_service_id is None
    assert final.result.answer.startswith("已确认服务状态")
    assert final.result.answer == final.result.evidence_answer.inferences[0]
    assert final.result.evidence_answer.summary == final.result.evidence_answer.inferences[0]
    assert final.result.evidence_answer.confirmed_facts == ()
    assert final.result.evidence_answer.unknowns == (
        "这是模型根据本次检查记录得出的推断，程序还没有逐条核对。",
    )
    assert final.model_dump()["result"]["answer_basis"] == "inferred"
    public_result = TypeAdapter(RunView).dump_python(final)["result"]
    assert "answer_basis" not in public_result
    assert "answer_checked" not in public_result
    assert "checked_service_id" not in public_result
    assert [event.event_type for event in events] == [
        RunEventType.GOAL,
        RunEventType.TOOL,
        RunEventType.TOOL,
        RunEventType.FINISHED,
    ]
    assert events[1].tool_status == "started"
    assert events[2].tool_status == "success"
    assert events[2].tool_run_id == final.result.tool_run_ids[0]
    assert events[-1].stop_reason is AgentStopReason.COMPLETED
    assert not hasattr(events[-1], "hidden_reasoning")
    assert run(collect(conversations.stream_events(final.run_id, after=1))) == events[1:]
    assert conversations.cancel_run(final.run_id).status is RunStatus.COMPLETED
    detail = conversations.get_thread(first.thread_id)
    assert [message.role for message in detail.messages] == ["user", "assistant"]
    assert detail.thread.message_count == 2
    assert detail.thread.updated_at >= detail.thread.created_at
    assert detail.messages[1].answer_checked
    assert detail.messages[1].answer_basis == "inferred"

    async def continue_scenario() -> None:
        continued = await conversations.start_run(
            first.thread_id,
            StartRunInput(question="继续检查", tool_names=("probe_service",)),
        )
        _ = await collect(conversations.stream_events(continued.run_id))

    run(continue_scenario())
    assert conversations.get_thread(first.thread_id).thread.message_count == 4

    async def second_thread_scenario() -> None:
        other = await conversations.start_run(
            second.thread_id,
            StartRunInput(question="另一个线程", tool_names=("probe_service",)),
        )
        _ = await collect(conversations.stream_events(other.run_id))

    run(second_thread_scenario())
    conversations.delete_thread(first.thread_id)
    assert conversations.list_threads()[0].thread_id == second.thread_id


@pytest.mark.parametrize("tool_failure", [False, True])
def test_free_answer_without_successful_checks_has_no_conclusion(
    monkeypatch: pytest.MonkeyPatch, tool_failure: bool
) -> None:
    """没有成功检查记录时保留模型原文，只显示缺少依据的原因。"""
    agent, provider, adapter = build_agent()
    draft = "已确认服务状态，并引用工具证据。"
    if tool_failure:
        adapter.behavior = FakeToolBehavior.ADAPTER_ERROR
    else:
        monkeypatch.setattr(
            provider, "complete", AsyncMock(return_value=ModelResponse(content=draft))
        )
    conversations = InMemoryConversationService(NodeId.new(), lambda: agent)
    thread = conversations.create_thread()

    async def scenario() -> CheckedAgentTurnResult:
        started = await conversations.start_run(
            thread.thread_id,
            StartRunInput(question="检查当前状态", tool_names=("probe_service",)),
        )
        _ = await collect(conversations.stream_events(started.run_id))
        result = conversations.get_run(started.run_id).result
        assert result is not None
        return result

    result = run(scenario())
    summary = (
        "模型这次没有成功取得任何检查记录，它的回答缺少依据，所以没有当作结论显示。"
        "可以展开“模型原始说明”查看，或换个说法再问一次。"
    )
    assert result.answer_checked and result.answer_basis == "none"
    assert result.answer == result.evidence_answer.summary == summary
    assert result.evidence_answer.confirmed_facts == ()
    assert result.evidence_answer.inferences[0].startswith(draft)
    assert result.evidence_answer.unknowns == ("本次没有成功的检查记录，无法确认所问的实际情况。",)
    assert len(result.evidence_answer.evidence) == int(tool_failure)
    assert all(item.status == "failed" for item in result.evidence_answer.evidence)
    assert conversations.get_thread(thread.thread_id).messages[-1].answer_basis == "none"


@pytest.mark.parametrize("draft", ["", " \n\t "])
def test_empty_free_answer_has_no_conclusion(monkeypatch: pytest.MonkeyPatch, draft: str) -> None:
    """空回答和仅有空白的回答都不能成为可显示结论。"""
    agent, provider, _ = build_agent()
    monkeypatch.setattr(provider, "complete", AsyncMock(return_value=ModelResponse(content=draft)))
    conversations = InMemoryConversationService(NodeId.new(), lambda: agent)
    thread = conversations.create_thread()

    async def scenario() -> CheckedAgentTurnResult:
        started = await conversations.start_run(
            thread.thread_id,
            StartRunInput(question="检查当前状态", tool_names=("probe_service",)),
        )
        _ = await collect(conversations.stream_events(started.run_id))
        result = conversations.get_run(started.run_id).result
        assert result is not None
        return result

    result = run(scenario())
    summary = "模型这次没有给出回答，所以没有可显示的结论。可以换个说法再问一次。"
    assert result.answer_checked and result.answer_basis == "none"
    assert result.answer == result.evidence_answer.summary == summary
    assert result.evidence_answer.confirmed_facts == ()
    assert result.evidence_answer.inferences == ((draft,) if draft else ())
    assert result.evidence_answer.unknowns == ("模型没有返回回答，无法确认所问的实际情况。",)
    assert conversations.get_thread(thread.thread_id).messages[-1].answer_basis == "none"


def test_continued_run_includes_prior_thread_messages() -> None:
    """第二次 run 通过独立历史上下文看到同一 thread 的近期原文。"""
    provider = ScriptedProvider()
    conversations = InMemoryConversationService(
        NodeId.new(),
        lambda: build_agent(provider)[0],
    )
    thread = conversations.create_thread()

    async def scenario() -> None:
        first = await conversations.start_run(
            thread.thread_id,
            StartRunInput(question="第一次检查 8082", tool_names=("probe_service",)),
        )
        _ = await collect(conversations.stream_events(first.run_id))
        second = await conversations.start_run(
            thread.thread_id,
            StartRunInput(question="继续刚才的检查", tool_names=("probe_service",)),
        )
        _ = await collect(conversations.stream_events(second.run_id))

    run(scenario())

    second_run_request = provider.requests[2]
    contents = [item.content for item in second_run_request.messages]
    assert "第一次检查 8082" in contents
    previous_answer = conversations.get_thread(thread.thread_id).messages[1]
    assert previous_answer.answer_checked
    assert previous_answer.answer_basis == "inferred"
    assert previous_answer.content in contents
    assert "已确认服务状态" in previous_answer.content
    assert contents[-1] == "继续刚才的检查"


def test_incident_run_injects_context_but_stores_only_public_question() -> None:
    provider = ScriptedProvider()
    conversations = InMemoryConversationService(
        NodeId.new(),
        lambda: build_agent(provider)[0],
    )
    thread = conversations.create_thread()

    async def scenario() -> None:
        started = await conversations.start_incident_run(
            thread.thread_id,
            StartRunInput(question="还缺什么证据？", tool_names=("probe_service",)),
            '{"event_type":"local_only"}',
        )
        _ = await collect(conversations.stream_events(started.run_id))

    run(scenario())

    assert "local_only" in provider.requests[0].messages[-1].content
    detail = conversations.get_thread(thread.thread_id)
    assert detail.messages[0].content == "还缺什么证据？"
    assert "local_only" not in detail.messages[0].content


def test_incident_run_rejects_unbounded_context() -> None:
    conversations = service()
    thread = conversations.create_thread()

    with pytest.raises(ValueError, match="必须有界"):
        run(
            conversations.start_incident_run(
                thread.thread_id,
                StartRunInput(question="检查", tool_names=("get_node_summary",)),
                "x" * 12_001,
            )
        )


def test_run_retrieves_only_relevant_memory_for_current_node(tmp_path: Path) -> None:
    """生产会话入口只注入当前五层作用域内的相关确认记忆。"""
    stores = SQLiteStores.open(tmp_path / "memory-context.sqlite3")
    node = NodeId.new()
    stores.memories.put(
        LongTermMemory(
            memory_id=MemoryId.new(),
            namespace=MemoryNamespace(user="local-user", network="home", node_id=node),
            kind=MemoryKind.PREFERENCE,
            content="偏好使用中文回答",
            source="用户设置",
            user_confirmed=True,
            updated_at=datetime.now(UTC),
        )
    )
    stores.memories.put(
        LongTermMemory(
            memory_id=MemoryId.new(),
            namespace=MemoryNamespace(
                user="local-user",
                network="home",
                node_id=NodeId.new(),
            ),
            kind=MemoryKind.PREFERENCE,
            content="其他节点的秘密偏好",
            source="其他节点",
            user_confirmed=True,
            updated_at=datetime.now(UTC),
        )
    )
    provider = ScriptedProvider()
    conversations = InMemoryConversationService(
        node,
        lambda: build_agent(provider)[0],
        memory_retriever=MemoryContextRetriever(stores.memories),
    )
    thread = conversations.create_thread()

    async def scenario() -> None:
        started = await conversations.start_run(
            thread.thread_id,
            StartRunInput(question="请用中文检查 8082", tool_names=("probe_service",)),
        )
        _ = await collect(conversations.stream_events(started.run_id))

    run(scenario())

    contents = [item.content for item in provider.requests[0].messages]
    assert any("偏好使用中文回答" in item for item in contents)
    assert all("其他节点的秘密偏好" not in item for item in contents)


def test_user_cancel_and_failed_run_reach_terminal_events() -> None:
    """取消和内部失败都产生稳定终态，且异常正文不外泄。"""
    conversations = service(slow=True)
    thread = conversations.create_thread()

    async def cancel_scenario() -> tuple[RunView, list[RunEvent]]:
        started = await conversations.start_run(
            thread.thread_id,
            StartRunInput(question="等待", tool_names=("probe_service",)),
        )
        conversations.cancel_run(started.run_id)
        events = await collect(conversations.stream_events(started.run_id))
        return conversations.get_run(started.run_id), events

    cancelled, cancel_events = run(cancel_scenario())
    assert cancelled.status is RunStatus.CANCELLED
    assert cancel_events[-1].stop_reason is AgentStopReason.CANCELLED

    failing = service()
    bad_thread = failing.create_thread()

    async def fail_scenario() -> tuple[RunView, list[RunEvent]]:
        started = await failing.start_run(
            bad_thread.thread_id,
            StartRunInput(question="失败", tool_names=("missing_tool",)),
        )
        events = await collect(failing.stream_events(started.run_id))
        return failing.get_run(started.run_id), events

    failed, failed_events = run(fail_scenario())
    assert failed.status is RunStatus.FAILED
    assert failed.error_code == "agent_runtime_failed"
    assert failed.error_message == "Agent run 执行失败"
    assert failed.failure is not None
    assert failed.failure.category.value == "harness_or_tool"
    assert failed.failure.reason.value == "agent_runtime_failed"
    assert failed_events[-1].event_type is RunEventType.FAILED


def test_concurrent_run_creates_structured_unfinished_workflow_state() -> None:
    """同一 thread 的在途 run 进入结构化状态，而不是写进自由文本摘要。"""
    conversations = service(slow=True)
    thread = conversations.create_thread()

    async def scenario() -> None:
        first = await conversations.start_run(
            thread.thread_id,
            StartRunInput(question="第一项仍在执行", tool_names=("probe_service",)),
        )
        second = await conversations.start_run(
            thread.thread_id,
            StartRunInput(question="第二项", tool_names=("probe_service",)),
        )
        workflow = conversations._workflow_state(  # pyright: ignore[reportPrivateUsage]
            thread.thread_id
        )
        assert workflow is not None
        assert workflow.status == "unfinished"
        assert str(first.run_id) in workflow.pending_steps[0]
        conversations.cancel_run(first.run_id)
        conversations.cancel_run(second.run_id)
        _ = await collect(conversations.stream_events(first.run_id))
        _ = await collect(conversations.stream_events(second.run_id))

    run(scenario())


def test_unknown_thread_and_run_are_rejected() -> None:
    """未知稳定 ID 不会隐式创建资源。"""
    conversations = service()

    with pytest.raises(KeyError, match="thread_not_found"):
        run(
            conversations.start_run(
                ThreadId.new(),
                StartRunInput(question="x", tool_names=("probe_service",)),
            )
        )
    with pytest.raises(KeyError, match="run_not_found"):
        conversations.get_run(RunId.new())
    with pytest.raises(KeyError, match="run_not_found"):
        conversations.cancel_run(RunId.new())
    with pytest.raises(KeyError, match="run_not_found"):
        run(collect(conversations.stream_events(RunId.new())))
    with pytest.raises(KeyError, match="thread_not_found"):
        conversations.get_thread(ThreadId.new())
    with pytest.raises(KeyError, match="thread_not_found"):
        conversations.get_thread_service_id(ThreadId.new())
    with pytest.raises(KeyError, match="thread_not_found"):
        conversations.delete_thread(ThreadId.new())


def test_delete_running_thread_cancels_and_removes_owned_runs(tmp_path: Path) -> None:
    """删除线程会取消在途 run，且后台收尾不会重新创建消息。"""
    stores = SQLiteStores.open(tmp_path / "delete-running.sqlite3")
    conversations = InMemoryConversationService(
        NodeId.new(), lambda: build_agent(SlowProvider())[0], stores.checkpoints
    )
    thread = conversations.create_thread()

    async def scenario() -> tuple[RunId, Any]:
        started = await conversations.start_run(
            thread.thread_id,
            StartRunInput(question="等待后删除", tool_names=("probe_service",)),
        )
        removed_state = conversations._runs[  # pyright: ignore[reportPrivateUsage]
            str(started.run_id)
        ]
        conversations.delete_thread(thread.thread_id)
        await asyncio.sleep(0.2)
        return started.run_id, removed_state

    run_id, removed_state = run(scenario())
    conversations._persist(removed_state)  # pyright: ignore[reportPrivateUsage]
    conversations._add_message(  # pyright: ignore[reportPrivateUsage]
        thread.thread_id,
        "assistant",
        "迟到的后台结果",
        run_id,
    )
    assert conversations.list_threads() == ()
    assert stores.checkpoints.list_all() == ()
    with pytest.raises(KeyError, match="run_not_found"):
        conversations.get_run(run_id)


@pytest.mark.parametrize("legacy", [False, True])
def test_restart_restores_completed_thread_and_run(tmp_path: Path, legacy: bool) -> None:
    """完成态可在新 Runtime 中读回，删除线程也同步清理 checkpoint。"""
    stores = SQLiteStores.open(tmp_path / "completed.sqlite3")
    original = InMemoryConversationService(
        NodeId.new(), lambda: build_agent()[0], stores.checkpoints
    )
    thread = original.create_thread()

    async def scenario() -> RunId:
        started = await original.start_run(
            thread.thread_id,
            StartRunInput(question="持久化检查", tool_names=("probe_service",)),
        )
        _ = await collect(original.stream_events(started.run_id))
        return started.run_id

    run_id = run(scenario())
    checkpoint = stores.checkpoints.get(run_id)
    assert checkpoint is not None
    public = dict(checkpoint.public_state)
    public.pop("service_id")
    if legacy:
        saved_thread = public["thread"]
        assert isinstance(saved_thread, dict)
        saved_thread.pop("title")
        saved_thread.pop("context")
        messages = public["messages"]
        assert isinstance(messages, list)
        for message in messages:
            assert isinstance(message, dict)
            message.pop("answer_basis")
        saved_run = public["run"]
        assert isinstance(saved_run, dict)
        saved_result = saved_run["result"]
        assert isinstance(saved_result, dict)
        saved_result.pop("answer_basis")
    stores.checkpoints.put(checkpoint.model_copy(update={"public_state": public}))
    restored = InMemoryConversationService(
        NodeId.new(), lambda: build_agent()[0], stores.checkpoints
    )

    assert restored.get_run(run_id).status is RunStatus.COMPLETED
    assert restored.get_thread(thread.thread_id).thread.message_count == 2
    assert len(restored.get_thread(thread.thread_id).messages) == 2
    assert restored.get_thread(thread.thread_id).messages[-1].answer_basis == (
        "checked" if legacy else "inferred"
    )
    result = restored.get_run(run_id).result
    assert result is not None and result.checked_service_id is None
    assert result.answer_basis == ("checked" if legacy else "inferred")
    assert restored.get_thread_service_id(thread.thread_id) is None
    assert restored.get_thread(thread.thread_id).context is None
    assert restored.list_threads()[0].title == "持久化检查"
    restored.delete_thread(thread.thread_id)
    assert stores.checkpoints.list_all() == ()


@pytest.mark.parametrize("read_only_preview", [False, True])
def test_restart_marks_running_run_interrupted_without_replay(
    tmp_path: Path, read_only_preview: bool
) -> None:
    """崩溃时的运行只标记中断，不调用 Agent factory，也不重放工具。"""
    stores = SQLiteStores.open(tmp_path / "interrupted.sqlite3")
    original = InMemoryConversationService(
        NodeId.new(), lambda: build_agent(SlowProvider())[0], stores.checkpoints
    )
    thread = original.create_thread()

    async def start_only() -> RunId:
        started = await original.start_run(
            thread.thread_id,
            StartRunInput(question="不要重放", tool_names=("probe_service",)),
        )
        return started.run_id

    run_id = run(start_only())
    factory_calls = 0

    def forbidden_factory() -> Any:
        nonlocal factory_calls
        factory_calls += 1
        raise AssertionError("恢复过程不应创建或执行 Agent")

    original_checkpoint = stores.checkpoints.get(run_id)
    restored = InMemoryConversationService(
        NodeId.new(), forbidden_factory, stores.checkpoints, read_only_preview=read_only_preview
    )
    view = restored.get_run(run_id)
    events = run(collect(restored.stream_events(run_id)))

    assert factory_calls == 0
    assert view.status is RunStatus.INTERRUPTED
    assert view.error_code == "run_interrupted"
    assert events[-1].event_type is RunEventType.INTERRUPTED
    assert "未自动重放工具" in (events[-1].message or "")
    checkpoint = stores.checkpoints.get(run_id)
    assert checkpoint is not None
    if read_only_preview:
        assert checkpoint == original_checkpoint
    else:
        assert checkpoint.status is CheckpointStatus.INTERRUPTED


@pytest.mark.parametrize("outcome", ["completed", "failed", "cancelled", "interrupted"])
def test_program_context_survives_terminal_states_and_restart(tmp_path: Path, outcome: str) -> None:
    """检查对象从接受请求时保存，不依赖模型成功，重启只读恢复。"""
    target, _, _ = connection_case()
    stores = SQLiteStores.open(tmp_path / f"program-{outcome}.sqlite3")
    if outcome == "completed":
        agent, _ = connection_agent()
        tools = ("list_network_listeners",)
    else:
        agent = build_agent(SlowProvider())[0]
        tools = ("missing_tool",) if outcome == "failed" else ("probe_service",)
    original = InMemoryConversationService(target.node_id, lambda: agent, stores.checkpoints)
    thread = original.create_thread()

    async def scenario() -> RunId:
        started = await original.start_run(
            thread.thread_id, StartRunInput(question="继续检查", tool_names=tools), target
        )
        checkpoint = stores.checkpoints.get(started.run_id)
        assert checkpoint is not None
        assert checkpoint.public_state["service_id"] == str(target.service_id)
        if outcome == "cancelled":
            original.cancel_run(started.run_id)
        if outcome != "interrupted":
            _ = await collect(original.stream_events(started.run_id))
        return started.run_id

    identifier = run(scenario())
    factory_calls = 0

    def forbidden_factory() -> Any:
        nonlocal factory_calls
        factory_calls += 1
        raise AssertionError("恢复关联不能启动 Agent")

    restored = InMemoryConversationService(target.node_id, forbidden_factory, stores.checkpoints)
    assert restored.get_thread_service_id(thread.thread_id) == target.service_id
    assert restored.get_run(identifier).status.value == outcome
    assert factory_calls == 0


def test_program_context_changes_only_with_accepted_request(tmp_path: Path) -> None:
    """主动换对象和普通请求更新关联，另一线程及被拒绝请求不串用。"""
    target, _, _ = connection_case()
    stores = SQLiteStores.open(tmp_path / "program-switch.sqlite3")
    original = InMemoryConversationService(
        target.node_id, lambda: build_agent()[0], stores.checkpoints
    )
    first = original.create_thread()
    second = original.create_thread()

    async def scenario() -> None:
        started = await original.start_run(
            first.thread_id,
            StartRunInput(question="第一次", tool_names=("missing_tool",)),
            target,
        )
        _ = await collect(original.stream_events(started.run_id))
        assert original.get_thread_service_id(first.thread_id) == target.service_id
        assert original.get_thread_service_id(second.thread_id) is None
        with pytest.raises(ValueError, match="另一台电脑"):
            await original.start_run(
                first.thread_id,
                StartRunInput(question="不允许的对象", tool_names=("missing_tool",)),
                target.model_copy(update={"node_id": NodeId.new()}),
            )
        assert original.get_thread_service_id(first.thread_id) == target.service_id
        changed = target.model_copy(update={"service_id": ServiceId.new()})
        next_run = await original.start_run(
            first.thread_id,
            StartRunInput(question="换一个程序", tool_names=("missing_tool",)),
            changed,
        )
        _ = await collect(original.stream_events(next_run.run_id))
        assert original.get_thread_service_id(first.thread_id) == changed.service_id
        ordinary = await original.start_run(
            first.thread_id,
            StartRunInput(question="不针对程序的问题", tool_names=("missing_tool",)),
        )
        _ = await collect(original.stream_events(ordinary.run_id))
        assert original.get_thread_service_id(first.thread_id) is None
        assert original.get_thread_service_id(second.thread_id) is None

    run(scenario())
    restored = InMemoryConversationService(
        target.node_id, lambda: build_agent()[0], stores.checkpoints
    )
    assert restored.get_thread_service_id(first.thread_id) is None


@pytest.mark.parametrize("record_kind", ["checked", "unchecked", "explicit-empty", "no-result"])
def test_legacy_program_context_uses_only_checked_identity(
    tmp_path: Path, record_kind: str
) -> None:
    """旧记录只从可信核对标记恢复，空关联与缺证据不猜测，也不改写原记录。"""
    target, _, _ = connection_case()
    stores = SQLiteStores.open(tmp_path / f"legacy-program-{record_kind}.sqlite3")
    agent = build_agent()[0] if record_kind == "no-result" else connection_agent()[0]
    original = InMemoryConversationService(target.node_id, lambda: agent, stores.checkpoints)
    thread = original.create_thread()

    async def scenario() -> RunId:
        started = await original.start_run(
            thread.thread_id,
            StartRunInput(
                question="原来的程序",
                tool_names=("missing_tool",)
                if record_kind == "no-result"
                else ("list_network_listeners",),
            ),
            target,
        )
        _ = await collect(original.stream_events(started.run_id))
        return started.run_id

    identifier = run(scenario())
    checkpoint = stores.checkpoints.get(identifier)
    assert checkpoint is not None
    public = dict(checkpoint.public_state)
    public.pop("service_id")
    if record_kind == "unchecked":
        view = original.get_run(identifier)
        assert view.result is not None
        public["run"] = view.model_copy(
            update={"result": view.result.model_copy(update={"answer_checked": False})}
        ).model_dump(mode="json")
    elif record_kind == "explicit-empty":
        public["service_id"] = None
    stores.checkpoints.put(checkpoint.model_copy(update={"public_state": public}))

    def forbidden_factory() -> Any:
        raise AssertionError("读取旧关联不能执行模型")

    restored = InMemoryConversationService(target.node_id, forbidden_factory, stores.checkpoints)
    assert restored.get_thread_service_id(thread.thread_id) == (
        target.service_id if record_kind == "checked" else None
    )
    assert (
        restored.get_thread(thread.thread_id).messages
        == original.get_thread(thread.thread_id).messages
    )
    retained = stores.checkpoints.get(identifier)
    assert retained is not None and retained.public_state == public
