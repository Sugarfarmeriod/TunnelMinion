"""普通任务和续办必须在原远端执行，每次重新经过当前授权。"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
from tests.agent.test_conversation import collect, run
from tests.agent.test_remote import RemoteQuestionProvider, build_loader
from tests.agent.test_task_continuation import InterruptedProvider

from tunnelminion.agent.conversation import InMemoryConversationService, RunStatus, StartRunInput
from tunnelminion.agent.langchain_model import TunnelMinionChatModel
from tunnelminion.agent.remote import (
    PreparedRemoteAgentTools,
    RemoteCapabilityLoader,
    RemotePreparationError,
)
from tunnelminion.agent.runtime import (
    AgentCancellationToken,
    AgentRunLimits,
    AgentStopReason,
    LangChainReadOnlyAgent,
    ServiceCheckTarget,
)
from tunnelminion.coordinator.contracts import ServiceProtocol
from tunnelminion.domain.errors import ErrorCode
from tunnelminion.domain.identifiers import NodeId, RunId, ServiceId
from tunnelminion.domain.tools import Platform
from tunnelminion.memory.sqlite import SQLiteStores
from tunnelminion.tools.audit import InMemoryAuditSink
from tunnelminion.tools.contracts import ToolCallContext, ToolCancellationToken
from tunnelminion.tools.registry import ToolRegistry
from tunnelminion.tools.runtime import ToolRuntime


class CurrentRemotePreparer:
    """复用 ASGI Gateway 的真实授权边界，只替换实际网络传输。"""

    def __init__(self, loader: RemoteCapabilityLoader) -> None:
        self.loader = loader
        self.allowed = True
        self.calls = 0

    async def prepare(
        self,
        target_node_id: NodeId,
        context: ToolCallContext,
        requested_tools: tuple[str, ...],
        cancellation: ToolCancellationToken | None = None,
    ) -> PreparedRemoteAgentTools:
        assert target_node_id == context.execution_node_id
        self.calls += 1
        if not self.allowed:
            raise RemotePreparationError(ErrorCode.FORBIDDEN, "当前授权已撤销")
        return await self.loader.prepare(context, requested_tools, cancellation)


def remote_target(context: ToolCallContext) -> ServiceCheckTarget:
    return ServiceCheckTarget(
        service_id=ServiceId.new(),
        node_id=context.execution_node_id,
        display_name="远端程序",
        protocol=ServiceProtocol.TCP,
        port=8082,
    )


def remote_agent(
    provider: RemoteQuestionProvider | InterruptedProvider, preparer: CurrentRemotePreparer
) -> LangChainReadOnlyAgent:
    registry = ToolRegistry()
    return LangChainReadOnlyAgent(
        TunnelMinionChatModel(provider=provider),
        registry,
        ToolRuntime(registry, Platform.WINDOWS, InMemoryAuditSink()),
        Platform.WINDOWS,
        remote_tools=preparer,
    )


def test_remote_task_routes_goal_and_tools_to_original_node() -> None:
    loader, context, local_audit, _ = build_loader()
    preparer = CurrentRemotePreparer(loader)
    provider = RemoteQuestionProvider()
    agent = remote_agent(provider, preparer)
    service = InMemoryConversationService(context.caller_node_id, lambda: agent)
    thread = service.create_thread()

    async def investigate() -> None:
        started = await service.start_run(
            thread.thread_id,
            StartRunInput(question="检查这个程序", tool_names=("list_network_listeners",)),
            remote_target(context),
        )
        events = await collect(service.stream_events(started.run_id))
        result = service.get_run(started.run_id).result
        assert result is not None and result.tool_calls == 2
        assert len(result.tool_run_ids) == 2
        assert events[0].target_node_id == str(context.execution_node_id)
        assert all(event.target_node_id == str(context.execution_node_id) for event in events[:-1])

    run(investigate())
    assert preparer.calls == 1
    assert len(local_audit.records) == 2
    assert any("另一台电脑" in message.content for message in provider.requests[0].messages)


def test_remote_preflight_counts_toward_tool_limit() -> None:
    loader, context, audit, _ = build_loader()
    provider = RemoteQuestionProvider()
    result = run(
        remote_agent(provider, CurrentRemotePreparer(loader)).run(
            "检查远端",
            context,
            ("list_network_listeners",),
            AgentRunLimits(max_tool_calls=1),
            target=remote_target(context),
        )
    )
    assert result.stop_reason is AgentStopReason.TOOL_LIMIT
    assert result.tool_calls == 1
    assert len(audit.records) == 1


def test_remote_resume_rechecks_authorization_before_model(tmp_path: Path) -> None:
    loader, context, audit, _ = build_loader()
    preparer = CurrentRemotePreparer(loader)
    provider = InterruptedProvider()
    stores = SQLiteStores.open(tmp_path / "remote-task.sqlite3")
    original = InMemoryConversationService(
        context.caller_node_id, lambda: remote_agent(provider, preparer), stores.checkpoints
    )
    thread = original.create_thread()
    target = remote_target(context)

    async def interrupt() -> RunId:
        started = await original.start_run(
            thread.thread_id,
            StartRunInput(question="查远端", tool_names=("list_network_listeners",)),
            target,
        )
        await asyncio.wait_for(provider.report_started.wait(), timeout=3)
        return started.run_id

    identifier = run(interrupt())
    initial_count = len(audit.records)
    preparer.allowed = False
    next_provider = RemoteQuestionProvider()
    restored = InMemoryConversationService(
        context.caller_node_id, lambda: remote_agent(next_provider, preparer), stores.checkpoints
    )

    async def rejected() -> None:
        started = await restored.resume_run(identifier, target=target)
        await collect(restored.stream_events(started.run_id))
        failed = restored.get_run(started.run_id)
        assert failed.status is RunStatus.FAILED
        assert failed.error_code == ErrorCode.FORBIDDEN.value
        assert "授权" in (failed.error_message or "")

    run(rejected())
    assert next_provider.requests == []
    assert len(audit.records) == initial_count
    assert preparer.calls == 2


def test_remote_context_without_preparer_cannot_fall_back_to_local() -> None:
    _, context, _, _ = build_loader()
    registry = ToolRegistry()
    provider = RemoteQuestionProvider()
    agent = LangChainReadOnlyAgent(
        TunnelMinionChatModel(provider=provider),
        registry,
        ToolRuntime(registry, Platform.WINDOWS, InMemoryAuditSink()),
        Platform.WINDOWS,
    )
    with pytest.raises(ValueError, match="远端只读"):
        run(agent.run("检查", context, ("list_network_listeners",)))
    assert provider.requests == []


@pytest.mark.parametrize("stop", ["cancel", "timeout"])
def test_preflight_obeys_whole_task_timeout_and_cancel(stop: str) -> None:
    loader, context, _, _ = build_loader()
    entered = asyncio.Event()
    tokens: list[ToolCancellationToken] = []

    class WaitingPreparer(CurrentRemotePreparer):
        async def prepare(
            self,
            target_node_id: NodeId,
            context: ToolCallContext,
            requested_tools: tuple[str, ...],
            cancellation: ToolCancellationToken | None = None,
        ) -> PreparedRemoteAgentTools:
            del target_node_id, context, requested_tools
            assert cancellation is not None
            tokens.append(cancellation)
            entered.set()
            await asyncio.Event().wait()
            raise AssertionError("预检等待应随取消或超时结束")

    provider = RemoteQuestionProvider()
    agent = remote_agent(provider, WaitingPreparer(loader))
    token = AgentCancellationToken()

    async def scenario() -> AgentStopReason:
        task = asyncio.create_task(
            agent.run(
                "检查远端",
                context,
                ("list_network_listeners",),
                AgentRunLimits(timeout_seconds=0.05 if stop == "timeout" else 5),
                cancellation=token,
            )
        )
        await entered.wait()
        if stop == "cancel":
            token.cancel()
        return (await task).stop_reason

    assert run(scenario()) is (
        AgentStopReason.CANCELLED if stop == "cancel" else AgentStopReason.TIMEOUT
    )
    assert tokens[0].cancelled
    assert provider.requests == []
