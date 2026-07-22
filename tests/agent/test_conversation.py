"""本地 thread/run 生命周期、事件和取消测试。"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Coroutine
from pathlib import Path
from typing import Any, TypeVar

import pytest
from tests.agent.test_langchain_agent import SlowProvider, build_agent

from tunnelminion.agent.conversation import (
    InMemoryConversationService,
    RunEvent,
    RunEventType,
    RunStatus,
    RunView,
    StartRunInput,
)
from tunnelminion.agent.runtime import AgentStopReason
from tunnelminion.domain.identifiers import NodeId, RunId, ThreadId
from tunnelminion.memory.contracts import CheckpointStatus
from tunnelminion.memory.sqlite import SQLiteStores

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
    assert failed.error_code == "agent_run_failed"
    assert failed.error_message == "Agent run 执行失败"
    assert failed_events[-1].event_type is RunEventType.FAILED


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
        conversations.delete_thread(ThreadId.new())


def test_delete_running_thread_cancels_and_removes_owned_runs(tmp_path: Path) -> None:
    """删除线程会取消在途 run，且后台收尾不会重新创建消息。"""
    stores = SQLiteStores.open(tmp_path / "delete-running.sqlite3")
    conversations = InMemoryConversationService(
        NodeId.new(), lambda: build_agent(SlowProvider())[0], stores.checkpoints
    )
    thread = conversations.create_thread()

    async def scenario() -> RunId:
        started = await conversations.start_run(
            thread.thread_id,
            StartRunInput(question="等待后删除", tool_names=("probe_service",)),
        )
        conversations.delete_thread(thread.thread_id)
        await asyncio.sleep(0.2)
        return started.run_id

    run_id = run(scenario())
    assert conversations.list_threads() == ()
    assert stores.checkpoints.list_all() == ()
    with pytest.raises(KeyError, match="run_not_found"):
        conversations.get_run(run_id)


def test_restart_restores_completed_thread_and_run(tmp_path: Path) -> None:
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
    restored = InMemoryConversationService(
        NodeId.new(), lambda: build_agent()[0], stores.checkpoints
    )

    assert restored.get_run(run_id).status is RunStatus.COMPLETED
    assert restored.get_thread(thread.thread_id).thread.message_count == 2
    assert len(restored.get_thread(thread.thread_id).messages) == 2
    restored.delete_thread(thread.thread_id)
    assert stores.checkpoints.list_all() == ()


def test_restart_marks_running_run_interrupted_without_replay(tmp_path: Path) -> None:
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

    restored = InMemoryConversationService(NodeId.new(), forbidden_factory, stores.checkpoints)
    view = restored.get_run(run_id)
    events = run(collect(restored.stream_events(run_id)))

    assert factory_calls == 0
    assert view.status is RunStatus.INTERRUPTED
    assert view.error_code == "run_interrupted"
    assert events[-1].event_type is RunEventType.INTERRUPTED
    assert "未自动重放工具" in (events[-1].message or "")
    checkpoint = stores.checkpoints.get(run_id)
    assert checkpoint is not None
    assert checkpoint.status is CheckpointStatus.INTERRUPTED
