"""任务重建后显式续办，保留检查进度而不恢复隐藏推理或权限。"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import JsonValue
from tests.agent.test_connection_fact_check import (
    ListenerAdapter,
    connection_agent,
    connection_case,
)
from tests.agent.test_conversation import collect, run
from tests.agent.test_langchain_agent import ScriptedProvider, build_agent

from tunnelminion.agent.conversation import InMemoryConversationService, RunStatus, StartRunInput
from tunnelminion.agent.langchain_model import TunnelMinionChatModel
from tunnelminion.agent.runtime import AgentRunLimits, AgentStopReason, ServiceCheckTarget
from tunnelminion.agent.task_progress import TaskProgress
from tunnelminion.domain.errors import ErrorCode, ToolError
from tunnelminion.domain.identifiers import NodeId, RunId
from tunnelminion.memory.sqlite import SQLiteStores
from tunnelminion.model.contracts import CancellationToken, ModelRequest, ModelResponse, ToolCall
from tunnelminion.tools.contracts import ToolAdapterError, ToolCancellationToken
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


# 只作挂起保护：顺序由 report_started 事件保证，上限留足慢速 CI 跑完完整工具循环的时间。
REPORT_STARTED_TIMEOUT_SECONDS = 30


async def wait_report_started(provider: InterruptedProvider) -> None:
    """等待真实工具循环进入报告阶段，超时给出明确原因。"""
    try:
        await asyncio.wait_for(
            provider.report_started.wait(), timeout=REPORT_STARTED_TIMEOUT_SECONDS
        )
    except TimeoutError:
        pytest.fail(
            f"工具循环在 {REPORT_STARTED_TIMEOUT_SECONDS} 秒内没有进入报告阶段，"
            f"已收到 {len(provider.requests)} 次模型请求"
        )


class ContinueProvider(ScriptedProvider):
    """使用上次的历史检查生成说明，不重复调用已执行的工具。"""

    async def complete(
        self, request: ModelRequest, cancellation: CancellationToken | None = None
    ) -> ModelResponse:
        del cancellation
        self.requests.append(request)
        return ModelResponse(content="已根据上次检查继续整理；历史结果不能证明当前状态。")


class SkillOnlyThenRecheckProvider(ScriptedProvider):
    """先把查阅方法说成已复查，收到程序缺项反馈后才执行新检查。"""

    async def complete(
        self, request: ModelRequest, cancellation: CancellationToken | None = None
    ) -> ModelResponse:
        del cancellation
        self.requests.append(request)
        if len(self.requests) == 1:
            return ModelResponse(
                tool_calls=(
                    ToolCall(
                        call_id="read-method",
                        name="read_investigation_skill",
                        arguments={"skill_id": "service.local-only", "version": "1"},
                    ),
                )
            )
        if len(self.requests) == 2:
            return ModelResponse(content="已经重新检查当前服务，它只允许本机连接。")
        if len(self.requests) == 3:
            return ModelResponse(
                tool_calls=(
                    ToolCall(
                        call_id="fresh-listener",
                        name="list_network_listeners",
                        arguments={"port": 8787},
                    ),
                )
            )
        return ModelResponse(content="已依据本轮实际监听记录完成核对。")


@pytest.mark.parametrize("denied", [False, True])
def test_resumed_skill_lookup_cannot_replace_current_service_check(
    monkeypatch: pytest.MonkeyPatch,
    denied: bool,
) -> None:
    """方法和历史都不算新检查，程序反馈后实际取证才形成当前事实。"""
    if denied:

        async def reject(
            self: ListenerAdapter,
            arguments: dict[str, JsonValue],
            cancellation: ToolCancellationToken,
        ) -> JsonValue:
            del self, arguments, cancellation
            raise ToolAdapterError(
                ToolError(code=ErrorCode.PERMISSION_DENIED, message="检查被拒绝")
            )

        monkeypatch.setattr(ListenerAdapter, "execute", reject)
    target, request, previous = connection_case()
    provider = SkillOnlyThenRecheckProvider()
    agent, _ = connection_agent()
    monkeypatch.setattr(agent, "_model", TunnelMinionChatModel(provider=provider))
    progress = TaskProgress(current_listener_check_required=True).record(
        request, previous, datetime.now(UTC)
    )
    result = run(
        agent.run(
            "继续原任务，重新核对当前监听。",
            request.context.model_copy(update={"run_id": RunId.new()}),
            ("list_network_listeners",),
            limits=AgentRunLimits(max_model_rounds=4, max_tool_calls=3),
            target=target,
            progress=progress,
        )
    )
    assert result.stop_reason is AgentStopReason.COMPLETED
    assert result.model_rounds == len(provider.requests) == 4
    assert result.tool_calls == 1
    feedback = provider.requests[2].messages[-1]
    assert feedback.role == "user" and "尚缺少所选入口的本轮监听检查" in feedback.content
    if denied:
        assert result.evidence_answer.confirmed_facts == ()
        assert result.evidence_answer.evidence[0].status == "failed"
    else:
        assert result.evidence_answer.confirmed_facts
        assert result.evidence_answer.confirmed_facts[0].evidence_refs == result.tool_run_ids
    assert str(previous.tool_run_id) not in result.tool_run_ids


def test_resumed_check_without_current_tool_stops_at_original_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """模型始终不执行新检查时，不能绕过原轮数预算或宣称任务完成。"""
    target, request, previous = connection_case()
    provider = ContinueProvider()
    agent, _ = connection_agent()
    monkeypatch.setattr(agent, "_model", TunnelMinionChatModel(provider=provider))
    result = run(
        agent.run(
            "重新核对当前监听。",
            request.context,
            ("list_network_listeners",),
            limits=AgentRunLimits(max_model_rounds=2),
            target=target,
            progress=TaskProgress(current_listener_check_required=True).record(
                request, previous, datetime.now(UTC)
            ),
        )
    )
    assert result.stop_reason is AgentStopReason.MODEL_LIMIT
    assert len(provider.requests) == 2 and result.tool_calls == 0
    assert result.evidence_answer.confirmed_facts == ()


def test_resumed_skill_and_recheck_share_original_tool_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """技能查阅也消耗原工具预算，反馈不能额外获得检查次数。"""
    target, request, previous = connection_case()
    provider = SkillOnlyThenRecheckProvider()
    agent, _ = connection_agent()
    monkeypatch.setattr(agent, "_model", TunnelMinionChatModel(provider=provider))
    result = run(
        agent.run(
            "重新核对当前监听。",
            request.context,
            ("list_network_listeners",),
            limits=AgentRunLimits(max_model_rounds=4, max_tool_calls=1),
            target=target,
            progress=TaskProgress(current_listener_check_required=True).record(
                request, previous, datetime.now(UTC)
            ),
        )
    )
    assert result.stop_reason is AgentStopReason.TOOL_LIMIT
    assert len(provider.requests) == 3 and result.tool_calls == 0
    assert result.evidence_answer.confirmed_facts == ()


def test_resumed_check_does_not_request_unavailable_listener_tool() -> None:
    """本次工具目录没有监听检查时，保留未知而不追加模型循环。"""
    target, request, previous = connection_case()
    request = request.model_copy(update={"tool_name": "probe_service"})
    provider = ContinueProvider()
    agent, _, _ = build_agent(provider)
    result = run(
        agent.run(
            "继续原任务。",
            request.context,
            ("probe_service",),
            target=target,
            progress=TaskProgress(current_listener_check_required=True).record(
                request, previous, datetime.now(UTC)
            ),
        )
    )
    assert len(provider.requests) == 1 and result.tool_calls == 0
    assert result.evidence_answer.confirmed_facts == ()


def test_explicit_resume_rechecks_after_rebuilding_task_service(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """公开续办入口设置回检要求，服务重建后只用本轮检查确认当前事实。"""
    target, _, _ = connection_case()
    initial_provider = InterruptedProvider()
    initial_agent, _ = connection_agent()
    monkeypatch.setattr(initial_agent, "_model", TunnelMinionChatModel(provider=initial_provider))
    stores = SQLiteStores.open(tmp_path / "service-check.sqlite3")
    original = InMemoryConversationService(
        target.node_id, lambda: initial_agent, stores.checkpoints
    )
    thread = original.create_thread()

    async def cancel_after_check() -> RunId:
        started = await original.start_run(
            thread.thread_id,
            StartRunInput(question="检查当前入口", tool_names=("list_network_listeners",)),
            target,
        )
        await wait_report_started(initial_provider)
        original.cancel_run(started.run_id)
        await collect(original.stream_events(started.run_id))
        return started.run_id

    previous_id = run(cancel_after_check())
    previous = stores.checkpoints.get(previous_id)
    assert previous is not None and len(previous.tool_run_ids) == 1
    provider = SkillOnlyThenRecheckProvider()
    agent, _ = connection_agent()
    monkeypatch.setattr(agent, "_model", TunnelMinionChatModel(provider=provider))
    restored = InMemoryConversationService(target.node_id, lambda: agent, stores.checkpoints)
    assert provider.requests == []

    async def resume() -> RunId:
        started = await restored.resume_run(previous_id, question="重新核对当前入口", target=target)
        await collect(restored.stream_events(started.run_id))
        return started.run_id

    current = restored.get_run(run(resume()))
    assert current.result is not None and current.result.stop_reason is AgentStopReason.COMPLETED
    assert current.result.model_rounds == 4 and current.result.tool_calls == 1
    assert current.result.evidence_answer.confirmed_facts[0].evidence_refs == (
        current.result.tool_run_ids
    )
    assert {str(item) for item in previous.tool_run_ids}.isdisjoint(current.result.tool_run_ids)
    checkpoint = stores.checkpoints.get(current.run_id)
    assert checkpoint is not None
    continuation = checkpoint.public_state["continuation"]
    assert isinstance(continuation, dict)
    progress = TaskProgress.model_validate(continuation["progress"])
    assert progress.current_listener_check_required and len(progress.observations) == 2


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
        await wait_report_started(provider)
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
    assert answer.stop_reason is AgentStopReason.COMPLETED
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
