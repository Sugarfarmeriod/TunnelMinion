"""后台事件、聊天追问和中断续办共用任务记录与实际执行身份。"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from pathlib import Path

import pytest
from tests.agent.test_conversation import collect, run
from tests.agent.test_task_continuation import ContinueProvider
from tests.incident.test_investigation import (
    NODE,
    NOW,
    SERVICE,
    ScriptedProvider,
    _incident,  # pyright: ignore[reportPrivateUsage]
    _local_node_incident,  # pyright: ignore[reportPrivateUsage]
    _runtime,  # pyright: ignore[reportPrivateUsage]
)
from tests.web.test_conversation import program_overview, selected_program

from tunnelminion.agent.conversation import (
    InMemoryConversationService,
    RunEvent,
    RunStatus,
    StartRunInput,
)
from tunnelminion.agent.langchain_model import TunnelMinionChatModel
from tunnelminion.agent.runtime import AgentRunLimits, AgentStopReason, LangChainReadOnlyAgent
from tunnelminion.coordinator.contracts import ServiceProtocol
from tunnelminion.domain.identifiers import IncidentId, RunId
from tunnelminion.domain.tools import Platform
from tunnelminion.incident.contracts import IncidentEventType, IncidentStatus, SnapshotSource
from tunnelminion.incident.investigation import (
    READ_ONLY_INVESTIGATION_TOOLS,
    ConfiguredIncidentRunner,
)
from tunnelminion.incident.tasks import IncidentTaskHarness
from tunnelminion.memory.sqlite import SQLiteStores
from tunnelminion.model.contracts import (
    CancellationToken,
    ModelRequest,
    ModelResponse,
    ProviderError,
    ProviderErrorCode,
)


def task_harness(
    tmp_path: Path,
    *,
    provider: ScriptedProvider | None = None,
    conversations: InMemoryConversationService | None = None,
) -> tuple[IncidentTaskHarness, ScriptedProvider, ContinueProvider, SQLiteStores]:
    """保留真实调查与工具循环，只替换平台数据、模型和临时存储。"""
    base, store, _, initial_provider = _runtime(tmp_path, "valid")
    registry = base._registry  # pyright: ignore[reportPrivateUsage]
    tools = base._tools  # pyright: ignore[reportPrivateUsage]
    investigation_provider = provider or initial_provider
    follow_up_provider = ContinueProvider()

    def create_agent() -> LangChainReadOnlyAgent:
        return LangChainReadOnlyAgent(
            TunnelMinionChatModel(provider=follow_up_provider), registry, tools, Platform.WINDOWS
        )

    stores = SQLiteStores.open(tmp_path / "runtime.sqlite3")
    service = conversations or InMemoryConversationService(NODE, create_agent, stores.checkpoints)
    selected = selected_program().model_copy(
        update={
            "service_id": SERVICE,
            "node_id": NODE,
            "protocol": ServiceProtocol.HTTP,
            "port": 43123,
        }
    )
    harness = IncidentTaskHarness(
        service,
        store,
        ConfiguredIncidentRunner(
            lambda: investigation_provider,
            registry,
            tools,
            store,
            Platform.WINDOWS,
            local_node_id=NODE,
            clock=lambda: NOW,
        ),
        create_agent,
        program_overview(selected).view,
    )
    return harness, investigation_provider, follow_up_provider, stores


def test_background_event_uses_shared_run_id_thread_progress_and_metrics(tmp_path: Path) -> None:
    harness, provider, _, stores = task_harness(tmp_path)
    incident = _incident(harness.store, event_type=IncidentEventType.SERVICE_ADDED)
    final = run(harness.run(incident))
    assert final.status is IncidentStatus.CONFIRMED and final.run_id is not None
    thread = harness.store.thread_for(incident.incident_id)
    assert thread is not None
    view = harness.conversations.get_run(final.run_id)
    assert view.thread_id == thread and view.status is RunStatus.COMPLETED
    assert view.result is not None and view.result.model_rounds == len(provider.requests) == 3
    assert view.result.tool_calls == 2
    checkpoint = stores.checkpoints.get(final.run_id)
    assert checkpoint is not None and len(checkpoint.tool_run_ids) == 2
    progress = checkpoint.public_state["continuation"]
    assert isinstance(progress, dict) and progress["incident_id"] == str(incident.incident_id)
    detail = harness.conversations.get_thread(thread)
    assert len(detail.messages) == 2 and detail.messages[-1].answer_checked
    assert detail.messages[-1].answer_basis == "checked"
    assert "该次变化" in detail.messages[-1].content
    before = len(provider.requests)
    assert run(harness.run(final)) == final
    assert len(provider.requests) == before


def test_follow_up_and_plain_chat_keep_same_incident_and_thread(tmp_path: Path) -> None:
    harness, _, provider, _ = task_harness(tmp_path)
    incident = _incident(harness.store, event_type=IncidentEventType.SERVICE_ADDED)
    original = run(harness.run(incident))
    assert original.run_id is not None
    thread = harness.conversations.get_run(original.run_id).thread_id

    async def follow_up() -> None:
        started = await harness.follow_up(incident.incident_id, "继续解释刚才的检查")
        await collect(harness.conversations.stream_events(started.run_id))
        assert started.thread_id == thread
        next_run = await harness.conversations.start_run(
            thread,
            StartRunInput(question="目前还有哪些未知？", tool_names=READ_ONLY_INVESTIGATION_TOOLS),
        )
        await collect(harness.conversations.stream_events(next_run.run_id))
        assert harness.conversations.get_run(next_run.run_id).status is RunStatus.COMPLETED

    run(follow_up())
    assert len(provider.requests) == 2
    assert harness.store.get(incident.incident_id) == original
    assert len(harness.conversations.get_thread(thread).messages) == 6
    assert "历史数据" in "\n".join(message.content for message in provider.requests[0].messages)


def test_historical_action_words_do_not_become_current_user_instruction(tmp_path: Path) -> None:
    harness, _, provider, _ = task_harness(tmp_path)
    incident = _incident(harness.store, event_type=IncidentEventType.SERVICE_ADDED)
    completed = run(harness.run(incident))
    assert completed.report is not None
    historical = completed.model_copy(
        update={
            "report": completed.report.model_copy(
                update={
                    "candidate_explanations": ("服务停止或重启可能导致变化",),
                }
            )
        }
    )
    harness.store.put_incident(historical)

    async def explain() -> None:
        started = await harness.follow_up(incident.incident_id, "解释上次检查")
        await collect(harness.conversations.stream_events(started.run_id))
        result = harness.conversations.get_run(started.run_id).result
        assert result is not None and result.model_rounds == 1

    run(explain())
    assert provider.requests[0].messages[-1].content == "解释上次检查"
    assert any("服务停止或重启" in message.content for message in provider.requests[0].messages)


def test_explicit_follow_up_after_budget_uses_saved_checks_and_new_attempt_budget(
    tmp_path: Path,
) -> None:
    harness, provider, _, stores = task_harness(tmp_path)
    incident = _incident(harness.store, event_type=IncidentEventType.SERVICE_ADDED)
    thread = harness.conversations.create_thread().thread_id
    harness.store.bind_thread(incident.incident_id, thread)

    async def complete_remaining() -> None:
        started = await harness.conversations.start_incident_run(
            thread,
            StartRunInput(
                question="调查新增程序",
                tool_names=READ_ONLY_INVESTIGATION_TOOLS,
                limits=AgentRunLimits(max_model_rounds=1),
            ),
            "{}",
            incident_id=incident.incident_id,
            execution_node_id=NODE,
        )
        await collect(harness.conversations.stream_events(started.run_id))
        assert harness.conversations.get_run(started.run_id).result is not None
        updated = harness.store.get(incident.incident_id)
        assert updated is not None and updated.status is IncidentStatus.BUDGET_EXHAUSTED
        assert len(provider.requests) == 1
        assert await harness.run(updated) == updated
        assert len(provider.requests) == 1
        resumed = await harness.follow_up(incident.incident_id, "继续查完")
        await collect(harness.conversations.stream_events(resumed.run_id))
        current = harness.store.get(incident.incident_id)
        assert current is not None and current.status is IncidentStatus.CONFIRMED
        assert current.run_id == resumed.run_id
        checkpoint = stores.checkpoints.get(resumed.run_id)
        assert checkpoint is not None and len(checkpoint.tool_run_ids) == 2
        result = harness.conversations.get_run(resumed.run_id).result
        assert result is not None and result.tool_calls == 1

    run(complete_remaining())
    assert provider.requests[1].tools[0].name == "get_process_summary"


def test_process_rebuild_continues_unfinished_event_without_repeating_completed_tool(
    tmp_path: Path,
) -> None:
    entered = asyncio.Event()

    class PausedProvider(ScriptedProvider):
        async def complete(
            self, request: ModelRequest, cancellation: CancellationToken | None = None
        ) -> ModelResponse:
            if self.requests:
                entered.set()
                await asyncio.Event().wait()
                raise AssertionError("等待应随进程退出取消")
            return await super().complete(request, cancellation)

    harness, _, _, stores = task_harness(tmp_path, provider=PausedProvider("valid"))
    incident = _incident(harness.store, event_type=IncidentEventType.SERVICE_ADDED)

    async def interrupt() -> RunId:
        started = await harness.follow_up(incident.incident_id, "调查新增程序")
        await asyncio.wait_for(entered.wait(), timeout=3)
        return started.run_id

    identifier = run(interrupt())
    harness.store.recover_interrupted(at=NOW)
    restored_service = InMemoryConversationService(
        NODE, lambda: pytest.fail("事件续办不得使用默认本机 Agent"), stores.checkpoints
    )
    restored, provider, follow_up_provider, _ = task_harness(
        tmp_path, conversations=restored_service
    )
    assert provider.requests == []
    assert restored_service.get_run(identifier).status is RunStatus.INTERRUPTED
    pending = restored.store.get(incident.incident_id)
    assert pending is not None
    assert run(restored.run(pending)) == pending
    assert provider.requests == []

    async def finish() -> None:
        started = await restored.follow_up(incident.incident_id, "接着刚才查")
        await collect(restored_service.stream_events(started.run_id))
        assert restored_service.get_run(started.run_id).status is RunStatus.COMPLETED
        result = restored_service.get_run(started.run_id).result
        assert result is not None and result.tool_calls == 1
        explanation = await restored.follow_up(incident.incident_id, "解释上次检查")
        await collect(restored_service.stream_events(explanation.run_id))
        explained = restored_service.get_run(explanation.run_id).result
        assert explained is not None and explained.model_rounds == 1

    run(finish())
    assert len(follow_up_provider.requests) == 1
    assert provider.requests[0].tools[0].name == "get_process_summary"


def test_missing_incident_driver_is_not_silently_replaced_with_local_chat(tmp_path: Path) -> None:
    harness, _, _, _ = task_harness(tmp_path)
    incident = _incident(harness.store)
    source = InMemoryConversationService(NODE, lambda: pytest.fail("不得偷偷调用本机 Agent"))
    thread = source.create_thread()
    with pytest.raises(ValueError, match="执行器当前不可用"):
        run(
            source.start_incident_run(
                thread.thread_id,
                StartRunInput(question="继续", tool_names=READ_ONLY_INVESTIGATION_TOOLS),
                "{}",
                incident_id=incident.incident_id,
                execution_node_id=NODE,
            )
        )
    assert source.get_thread(thread.thread_id).messages == ()
    with pytest.raises(KeyError):
        run(harness.follow_up(IncidentId.new(), "检查"))


def test_preview_rejects_incident_task_before_creating_persisted_binding(tmp_path: Path) -> None:
    conversations = InMemoryConversationService(
        NODE, lambda: pytest.fail("只读预览不得创建模型"), read_only_preview=True
    )
    harness, provider, _, stores = task_harness(tmp_path, conversations=conversations)
    incident = _incident(harness.store)
    with pytest.raises(ValueError, match="只读预览"):
        run(harness.follow_up(incident.incident_id, "开始调查"))
    assert harness.store.thread_for(incident.incident_id) is None
    assert conversations.list_threads() == ()
    assert stores.checkpoints.list_all() == ()
    assert provider.requests == []


def test_incident_task_respects_selected_tool_scope(tmp_path: Path) -> None:
    harness, provider, _, stores = task_harness(tmp_path)
    incident = _incident(harness.store, event_type=IncidentEventType.SERVICE_ADDED)
    thread = harness.conversations.create_thread().thread_id

    async def restricted() -> None:
        started = await harness.conversations.start_incident_run(
            thread,
            StartRunInput(question="只查监听", tool_names=("list_network_listeners",)),
            "{}",
            incident_id=incident.incident_id,
            execution_node_id=NODE,
        )
        await collect(harness.conversations.stream_events(started.run_id))
        final = harness.store.get(incident.incident_id)
        assert final is not None and final.status is IncidentStatus.INSUFFICIENT_EVIDENCE
        checkpoint = stores.checkpoints.get(started.run_id)
        assert checkpoint is not None and len(checkpoint.tool_run_ids) == 1
        result = harness.conversations.get_run(started.run_id).result
        assert result is not None and result.selected_tools == ("list_network_listeners",)
        assert result.evidence_answer.confirmed_facts == ()

    run(restricted())
    assert len(provider.requests) == 1
    assert [tool.name for tool in provider.requests[0].tools] == ["list_network_listeners"]


def test_failed_tool_is_kept_as_failed_evidence_without_confirmed_fact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    harness, _, _, _ = task_harness(tmp_path)
    registry = harness.runner._registry  # pyright: ignore[reportPrivateUsage]
    entry = registry.lookup("list_network_listeners")
    assert entry is not None
    monkeypatch.setattr(entry.adapter, "fail", True)
    incident = _incident(harness.store, event_type=IncidentEventType.SERVICE_ADDED)
    final = run(harness.run(incident))
    assert final.run_id is not None and final.status is IncidentStatus.INSUFFICIENT_EVIDENCE
    result = harness.conversations.get_run(final.run_id).result
    assert result is not None and result.tool_calls == len(result.tool_run_ids) == 1
    assert result.evidence_answer.confirmed_facts == ()
    assert result.evidence_answer.evidence[0].status == "failed"
    assert "不可用" in result.answer


@pytest.mark.parametrize("keep_report", [True, False])
def test_expired_program_returns_unknown_without_reusing_old_success(
    tmp_path: Path, keep_report: bool
) -> None:
    harness, _, provider, _ = task_harness(tmp_path)
    incident = _incident(harness.store, event_type=IncidentEventType.SERVICE_ADDED)
    completed = run(harness.run(incident))
    if not keep_report:
        completed = completed.model_copy(update={"status": IncidentStatus.CLOSED, "report": None})
        harness.store.put_incident(completed)
    previous = harness.overview()
    harness.overview = lambda: previous.model_copy(
        update={"services": previous.services.model_copy(update={"items": ()})}
    )

    async def check_expired() -> None:
        started = await harness.follow_up(incident.incident_id, "继续核对")
        await collect(harness.conversations.stream_events(started.run_id))
        result = harness.conversations.get_run(started.run_id).result
        assert result is not None and "已失效" in result.answer
        assert result.tool_calls == 0 and result.tool_run_ids == ()
        assert result.evidence_answer.confirmed_facts == ()
        assert result.evidence_answer.unknowns

    run(check_expired())
    assert harness.store.get(incident.incident_id) == completed
    assert provider.requests == []


@pytest.mark.parametrize("stop", ["cancel", "timeout"])
def test_shared_cancel_and_timeout_reach_original_investigator(tmp_path: Path, stop: str) -> None:
    entered = asyncio.Event()

    class WaitingProvider(ScriptedProvider):
        async def complete(
            self, request: ModelRequest, cancellation: CancellationToken | None = None
        ) -> ModelResponse:
            assert cancellation is not None
            self.requests.append(request)
            entered.set()
            await cancellation.wait()
            raise ProviderError(ProviderErrorCode.CANCELLED, "已取消")

    harness, _, _, _ = task_harness(tmp_path, provider=WaitingProvider("valid"))
    incident = _incident(harness.store, event_type=IncidentEventType.SERVICE_ADDED)
    thread = harness.conversations.create_thread().thread_id

    async def stop_task() -> None:
        started = await harness.conversations.start_incident_run(
            thread,
            StartRunInput(
                question="检查",
                tool_names=READ_ONLY_INVESTIGATION_TOOLS,
                limits=AgentRunLimits(timeout_seconds=0.02 if stop == "timeout" else 5),
            ),
            "{}",
            incident_id=incident.incident_id,
            execution_node_id=NODE,
        )
        await entered.wait()
        if stop == "cancel":
            with pytest.raises(ValueError, match="仍在进行"):
                await harness.follow_up(incident.incident_id, "重复开始")
            harness.conversations.cancel_run(started.run_id)
        await collect(harness.conversations.stream_events(started.run_id))
        final = harness.store.get(incident.incident_id)
        view = harness.conversations.get_run(started.run_id)
        assert final is not None
        assert final.status is (
            IncidentStatus.CANCELLED if stop == "cancel" else IncidentStatus.BUDGET_EXHAUSTED
        )
        assert view.result is not None
        assert view.result.stop_reason is (
            AgentStopReason.CANCELLED if stop == "cancel" else AgentStopReason.TIMEOUT
        )

    run(stop_task())


def test_unavailable_model_is_saved_without_local_fallback(tmp_path: Path) -> None:
    harness, provider, follow_up_provider, _ = task_harness(
        tmp_path, provider=ScriptedProvider("unavailable")
    )
    incident = _incident(harness.store, event_type=IncidentEventType.SERVICE_ADDED)
    final = run(harness.run(incident))
    assert final.status is IncidentStatus.INVESTIGATION_UNAVAILABLE
    thread = harness.store.thread_for(incident.incident_id)
    assert thread is not None
    last = harness.conversations.get_thread(thread).messages[-1]
    assert harness.conversations.get_run(last.run_id).status is RunStatus.FAILED
    assert len(provider.requests) == 1 and follow_up_provider.requests == []


@pytest.mark.parametrize("stuck_stream", [False, True])
def test_cancelling_background_harness_cancels_shared_run_with_bounded_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, stuck_stream: bool
) -> None:
    entered = asyncio.Event()

    class WaitingProvider(ScriptedProvider):
        async def complete(
            self, request: ModelRequest, cancellation: CancellationToken | None = None
        ) -> ModelResponse:
            assert cancellation is not None
            entered.set()
            await cancellation.wait()
            raise ProviderError(ProviderErrorCode.CANCELLED, "已取消")

    harness, _, _, _ = task_harness(tmp_path, provider=WaitingProvider("valid"))
    incident = _incident(harness.store, event_type=IncidentEventType.SERVICE_ADDED)
    original_stream = harness.conversations.stream_events

    async def stream(run_id: RunId, after: int = 0) -> AsyncIterator[RunEvent]:
        async for event in original_stream(run_id, after):
            yield event
        if stuck_stream:
            await asyncio.Event().wait()

    monkeypatch.setattr(harness.conversations, "stream_events", stream)

    async def scenario() -> None:
        task = asyncio.create_task(harness.run(incident))
        await asyncio.wait_for(entered.wait(), timeout=1)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, timeout=2)
        final = harness.store.get(incident.incident_id)
        assert final is not None and final.run_id is not None
        assert final.status is IncidentStatus.CANCELLED
        assert harness.conversations.get_run(final.run_id).status is RunStatus.CANCELLED

    run(scenario())


def test_background_does_not_duplicate_accepted_manual_task_and_pre_cancel_is_kept(
    tmp_path: Path,
) -> None:
    harness, provider, _, _ = task_harness(tmp_path)
    incident = _incident(harness.store, event_type=IncidentEventType.SERVICE_ADDED)

    async def scenario() -> None:
        started = await harness.follow_up(incident.incident_id, "手动开始调查")
        assert await harness.run(incident) == incident
        harness.conversations.cancel_run(started.run_id)
        await collect(harness.conversations.stream_events(started.run_id))
        assert harness.conversations.get_run(started.run_id).status is RunStatus.CANCELLED
        assert provider.requests == []

    run(scenario())


def test_missing_model_configuration_preserves_shared_attempt_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    harness, provider, follow_up_provider, _ = task_harness(tmp_path)

    def unavailable() -> ScriptedProvider:
        raise ProviderError(ProviderErrorCode.MODEL_NOT_FOUND, "未配置")

    monkeypatch.setattr(harness.runner, "_provider_factory", unavailable)
    incident = _incident(harness.store, event_type=IncidentEventType.SERVICE_ADDED)
    final = run(harness.run(incident))
    assert final.status is IncidentStatus.INVESTIGATION_UNAVAILABLE and final.run_id is not None
    assert harness.conversations.get_run(final.run_id).status is RunStatus.FAILED
    assert provider.requests == [] and follow_up_provider.requests == []


def test_offline_node_follow_up_uses_fresh_original_remote_summary(tmp_path: Path) -> None:
    from tests.agent.test_remote import build_loader
    from tests.agent.test_remote_task import CurrentRemotePreparer

    from tunnelminion.incident.storage import SQLiteIncidentStore
    from tunnelminion.tools.audit import InMemoryAuditSink
    from tunnelminion.tools.registry import ToolRegistry
    from tunnelminion.tools.runtime import ToolRuntime

    loader, context, _, _ = build_loader()
    preparer = CurrentRemotePreparer(loader)
    provider = ContinueProvider()
    registry = ToolRegistry()
    runtime = ToolRuntime(registry, Platform.WINDOWS, InMemoryAuditSink())
    stores = SQLiteStores.open(tmp_path / "node-runtime.sqlite3")
    store = SQLiteIncidentStore(tmp_path / "node-incidents.sqlite3")

    def create_agent() -> LangChainReadOnlyAgent:
        return LangChainReadOnlyAgent(
            TunnelMinionChatModel(provider=provider),
            registry,
            runtime,
            Platform.WINDOWS,
            remote_tools=preparer,
        )

    conversations = InMemoryConversationService(
        context.caller_node_id, create_agent, stores.checkpoints
    )
    original = _local_node_incident(store, source=SnapshotSource.STATIC_PEER_OBSERVATION)
    incident = original.model_copy(
        update={
            "event": original.event.model_copy(
                update={
                    "target_node_id": context.execution_node_id,
                    "object_id": str(context.execution_node_id),
                }
            )
        }
    )
    store.put_incident(incident)
    harness = IncidentTaskHarness(
        conversations,
        store,
        ConfiguredIncidentRunner(
            lambda: provider,
            registry,
            runtime,
            store,
            Platform.WINDOWS,
            local_node_id=context.caller_node_id,
            remote_tools=preparer,
            clock=lambda: NOW,
        ),
        create_agent,
        program_overview(selected_program()).view,
    )
    previous = run(harness.run(incident))
    assert previous.status is IncidentStatus.INSUFFICIENT_EVIDENCE
    assert provider.requests == [] and preparer.calls == 0

    async def check_again() -> None:
        started = await harness.follow_up(incident.incident_id, "现在原电脑能联系上吗？")
        await collect(conversations.stream_events(started.run_id))
        result = conversations.get_run(started.run_id).result
        assert result is not None and result.answer_checked
        assert "原来的电脑已响应" in result.answer
        assert "私网连接接口已启用" in result.answer
        assert len(result.evidence_answer.confirmed_facts) == 2
        assert result.tool_calls == 1

    run(check_again())
    assert preparer.calls == 1 and len(provider.requests) == 1
