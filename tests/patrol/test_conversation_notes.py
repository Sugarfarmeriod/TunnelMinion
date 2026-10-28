"""巡检对话：带服务上下文创建、写入说明、标题取第一句、不打断正在进行的回答。"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
from tests.agent.test_conversation import build_agent
from tests.agent.test_langchain_agent import SlowProvider
from tests.repair.factories import NODE
from tests.repair.test_result_messages import conversations

from tunnelminion.agent.conversation import (
    InMemoryConversationService,
    StartRunInput,
    ThreadContext,
)
from tunnelminion.domain.identifiers import ThreadId
from tunnelminion.memory.sqlite import SQLiteStores


def test_patrol_thread_keeps_context_title_and_survives_restart(tmp_path: Path) -> None:
    chat = conversations(tmp_path)
    context = ThreadContext(
        node_id=str(NODE), service_key="docker:compose:photos", service_name="相册"
    )
    thread = chat.create_thread(context=context)
    assert thread.context == context
    assert chat.append_notice(thread.thread_id, "巡检发现 相册 挂了：容器已退出。")
    [view] = chat.list_threads()
    assert view.title == "巡检发现 相册 挂了：容器已退出。" and view.context == context
    message = chat.get_thread(thread.thread_id).messages[0]
    assert message.role == "assistant" and message.answer_checked
    restored = conversations(tmp_path)
    assert restored.get_thread(thread.thread_id).context == context
    assert len(restored.get_thread(thread.thread_id).messages) == 1


def test_notice_is_skipped_for_missing_thread_preview_and_running_answer(tmp_path: Path) -> None:
    assert not conversations(tmp_path).append_notice(ThreadId.new(), "说明")
    preview = conversations(tmp_path, preview=True)
    assert not preview.append_notice(preview.create_thread().thread_id, "说明")

    provider = SlowProvider()
    stores = SQLiteStores.open(tmp_path / "slow.sqlite3")
    chat = InMemoryConversationService(NODE, lambda: build_agent(provider)[0], stores.checkpoints)
    thread_id = chat.create_thread().thread_id

    async def scenario() -> None:
        run = await chat.start_run(
            thread_id, StartRunInput(question="看看服务", tool_names=("probe_service",))
        )
        assert not chat.append_notice(thread_id, "说明")
        chat.cancel_run(run.run_id)
        _ = [event async for event in chat.stream_events(run.run_id)]
        assert chat.append_notice(thread_id, "说明")

    asyncio.run(scenario())
    assert chat.get_thread(thread_id).messages[-1].content == "说明"


def test_failed_notice_persistence_rolls_back(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    chat = conversations(tmp_path)
    thread_id = chat.create_thread().thread_id
    before = chat.get_thread(thread_id)

    def fail(*_: object) -> None:
        raise OSError("fake storage failure")

    monkeypatch.setattr(chat, "_persist", fail)
    with pytest.raises(OSError):
        chat.append_notice(thread_id, "说明")
    assert chat.get_thread(thread_id) == before
