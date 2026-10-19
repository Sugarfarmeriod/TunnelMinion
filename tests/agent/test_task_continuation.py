"""任务重建后显式续办，保留检查进度而不恢复隐藏推理或权限。"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from pathlib import Path

import pytest
from tests.agent.test_connection_fact_check import connection_agent, connection_case
from tests.agent.test_conversation import collect, run
from tests.agent.test_langchain_agent import ScriptedProvider, build_agent

from tunnelminion.agent.conversation import InMemoryConversationService, RunStatus, StartRunInput
from tunnelminion.agent.langchain_model import TunnelMinionChatModel
from tunnelminion.agent.runtime import ServiceCheckTarget
from tunnelminion.agent.task_progress import TaskProgress
from tunnelminion.domain.identifiers import NodeId, RunId
from tunnelminion.memory.sqlite import SQLiteStores
from tunnelminion.model.contracts import CancellationToken, ModelRequest, ModelResponse
from tunnelminion.tools.registry import ToolRegistry


class InterruptedProvider(ScriptedProvider):
    """完成一次工具后等待进程退出，模拟报告尚未生成时中断。"""

    def __init__(self) -> None:
        super().__init__()
        self.report_started = asyncio.Event()

    async def complete(
        self, request: ModelRequest, cancellation: CancellationToken | None = None
    ) -> ModelResponse:
        if not self.requests:
            response = await super().complete(request, cancellation)
            return response.model_copy(update={"reasoning_content": "不能保存的隐藏推理"})
        self.requests.append(request)
        self.report_started.set()
        await asyncio.Event().wait()
        raise AssertionError("等待应随进程退出取消")


class ContinueProvider(ScriptedProvider):
    """使用上次的历史检查生成说明，不重复调用已执行的工具。"""

    async def complete(
        self, request: ModelRequest, cancellation: CancellationToken | None = None
    ) -> ModelResponse:
        del cancellation
        self.requests.append(request)
        return ModelResponse(content="已根据上次检查继续整理；历史结果不能证明当前状态。")


def interrupted_task(
    tmp_path: Path, target: ServiceCheckTarget | None = None
) -> tuple[SQLiteStores, NodeId, RunId]:
    """保存真实 LangChain 工具循环在报告前中断的任务。"""
    stores = SQLiteStores.open(tmp_path / "tasks.sqlite3")
    node = target.node_id if target is not None else NodeId.new()
    provider = InterruptedProvider()
    agent, _, adapter = build_agent(provider)
    original = InMemoryConversationService(node, lambda: agent, stores.checkpoints)
    thread = original.create_thread()

    async def interrupt() -> RunId:
        started = await original.start_run(
            thread.thread_id,
            StartRunInput(question="查清 8082 的连接情况", tool_names=("probe_service",)),
            target,
        )
        await asyncio.wait_for(provider.report_started.wait(), timeout=3)
        return started.run_id

    identifier = run(interrupt())
    assert adapter.calls == [{"port": 8082}]
    return stores, node, identifier


def test_resume_restores_goal_and_completed_tool_without_replaying_it(tmp_path: Path) -> None:
    stores, node, identifier = interrupted_task(tmp_path)
    checkpoint = stores.checkpoints.get(identifier)
    assert checkpoint is not None
    assert "不能保存的隐藏推理" not in checkpoint.model_dump_json()
    assert checkpoint.tool_run_ids
    provider = ContinueProvider()
    agent, _, adapter = build_agent(provider)
    restored = InMemoryConversationService(node, lambda: agent, stores.checkpoints)
    assert restored.get_run(identifier).status is RunStatus.INTERRUPTED
    assert provider.requests == []

    async def continue_task() -> RunId:
        started = await restored.resume_run(identifier, question="接着整理刚才的结果")
        await collect(restored.stream_events(started.run_id))
        repeated = await restored.resume_run(identifier)
        assert repeated.run_id == started.run_id
        return started.run_id

    resumed_id = run(continue_task())
    assert resumed_id != identifier
    assert restored.get_run(resumed_id).status is RunStatus.COMPLETED
    assert adapter.calls == []
    content = "\n".join(message.content for message in provider.requests[0].messages)
    assert "查清 8082 的连接情况" in content
    assert "接着整理刚才的结果" in content
    assert "历史" in content
    assert str(checkpoint.tool_run_ids[0]) in content
    assert '"ok":true' in content


def test_new_question_on_interrupted_thread_continues_saved_task(tmp_path: Path) -> None:
    stores, node, identifier = interrupted_task(tmp_path)
    provider = ContinueProvider()
    restored = InMemoryConversationService(
        node, lambda: build_agent(provider)[0], stores.checkpoints
    )
    thread = restored.get_run(identifier).thread_id

    async def follow_up() -> None:
        started = await restored.start_run(
            thread,
            StartRunInput(question="刚才检查到哪了？", tool_names=("probe_service",)),
        )
        await collect(restored.stream_events(started.run_id))

    run(follow_up())
    content = "\n".join(message.content for message in provider.requests[0].messages)
    assert "查清 8082 的连接情况" in content
    assert "刚才检查到哪了？" in content
    assert any(
        call.name == "probe_service"
        for message in provider.requests[0].messages
        for call in message.tool_calls
    )


def test_resume_rejects_changed_node_and_preview_without_starting_model(tmp_path: Path) -> None:
    stores, node, identifier = interrupted_task(tmp_path)
    provider = ContinueProvider()
    for current, preview in ((NodeId.new(), False), (node, True)):
        restored = InMemoryConversationService(
            current,
            lambda: build_agent(provider)[0],
            stores.checkpoints,
            read_only_preview=preview,
        )
        with pytest.raises(ValueError):
            run(restored.resume_run(identifier))
    assert provider.requests == []


def test_resume_revalidates_current_tool_catalog(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    stores, node, identifier = interrupted_task(tmp_path)
    provider = ContinueProvider()
    agent = build_agent(provider)[0]
    monkeypatch.setattr(agent, "_registry", ToolRegistry())
    restored = InMemoryConversationService(node, lambda: agent, stores.checkpoints)

    async def rejected() -> None:
        started = await restored.resume_run(identifier)
        await collect(restored.stream_events(started.run_id))
        assert restored.get_run(started.run_id).status is RunStatus.FAILED

    run(rejected())
    assert provider.requests == []


@pytest.mark.parametrize("mismatch", ["thread", "caller", "execution", "tool"])
def test_saved_progress_cannot_cross_task_or_tool_scope(mismatch: str) -> None:
    _, request, result = connection_case()
    progress = TaskProgress().record(request, result, datetime.now(UTC))
    context = request.context
    tools = (request.tool_name,)
    if mismatch == "thread":
        context = context.model_copy(update={"thread_id": type(context.thread_id).new()})
    elif mismatch == "caller":
        context = context.model_copy(update={"caller_node_id": NodeId.new()})
    elif mismatch == "execution":
        context = context.model_copy(update={"execution_node_id": NodeId.new()})
    else:
        tools = ()
    assert progress.messages(context, tools) == []


def test_history_is_not_promoted_to_current_connection_fact(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target, request, result = connection_case()
    agent, _ = connection_agent()
    provider = ContinueProvider()
    monkeypatch.setattr(agent, "_model", TunnelMinionChatModel(provider=provider))
    progress = TaskProgress().record(request, result, datetime.now(UTC))
    answer = run(
        agent.run(
            "继续刚才的任务",
            request.context,
            ("list_network_listeners",),
            target=target,
            progress=progress,
        )
    )
    assert answer.evidence_answer.confirmed_facts == ()
    assert "还没有取得能核对" in answer.answer
    assert answer.tool_calls == 0
    assert any(message.role == "tool" for message in provider.requests[0].messages)


def test_preview_rejects_new_task_without_creating_model() -> None:
    provider = ContinueProvider()
    conversations = InMemoryConversationService(
        NodeId.new(), lambda: build_agent(provider)[0], read_only_preview=True
    )
    thread = conversations.create_thread()
    with pytest.raises(ValueError, match="只读预览"):
        run(
            conversations.start_run(
                thread.thread_id, StartRunInput(question="检查", tool_names=("probe_service",))
            )
        )
    assert provider.requests == []
    assert conversations.get_thread(thread.thread_id).messages == ()
