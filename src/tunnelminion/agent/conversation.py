"""本地 thread/run 生命周期与公开事件流。"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from tunnelminion.agent.context_contracts import (
    HistoryContext,
    RollingSummary,
    WorkflowContextState,
)
from tunnelminion.agent.history import ThreadHistoryAssembler
from tunnelminion.agent.runtime import (
    AgentCancellationToken,
    AgentRunLimits,
    AgentStopReason,
    AgentToolEvent,
    AgentTurnResult,
    LangChainReadOnlyAgent,
)
from tunnelminion.domain.identifiers import NodeId, RunId, ThreadId, ToolRunId
from tunnelminion.memory.context import ContextBudgets
from tunnelminion.memory.contracts import (
    CheckpointRecord,
    CheckpointStatus,
    CheckpointStore,
)
from tunnelminion.model.contracts import ModelMessage
from tunnelminion.tools.contracts import ToolCallContext


class RunStatus(StrEnum):
    """本地 run 的公开生命周期。"""

    RUNNING = "running"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    FAILED = "failed"
    INTERRUPTED = "interrupted"


class RunEventType(StrEnum):
    """不包含隐藏推理的公开事件类型。"""

    GOAL = "goal"
    TOOL = "tool"
    FINISHED = "finished"
    FAILED = "failed"
    INTERRUPTED = "interrupted"


class ThreadView(BaseModel):
    """聊天线程的稳定身份与创建时间。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    thread_id: ThreadId
    created_at: datetime
    updated_at: datetime
    message_count: int = Field(ge=0)


class ThreadMessage(BaseModel):
    """线程中可恢复的用户问题或公开 Agent 回答。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    role: str = Field(pattern="^(user|assistant)$")
    content: str
    created_at: datetime
    run_id: RunId


class ThreadDetail(BaseModel):
    """继续线程和页面渲染所需的公开消息。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    thread: ThreadView
    messages: tuple[ThreadMessage, ...]


class StartRunInput(BaseModel):
    """创建一次有界 Agent run 的输入。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    question: str = Field(min_length=1, max_length=20_000)
    tool_names: tuple[str, ...] = Field(min_length=1, max_length=64)
    limits: AgentRunLimits = Field(default_factory=AgentRunLimits)


class RunView(BaseModel):
    """可轮询的 run 状态与最终公开结果。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    run_id: RunId
    thread_id: ThreadId
    status: RunStatus
    created_at: datetime
    finished_at: datetime | None = None
    result: AgentTurnResult | None = None
    error_code: str | None = None
    error_message: str | None = None


class RunEvent(BaseModel):
    """SSE 使用的顺序化公开事件。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    sequence: int = Field(ge=1)
    event_type: RunEventType
    created_at: datetime
    run_id: RunId
    target_node_id: str | None = None
    tool_name: str | None = None
    tool_status: str | None = None
    elapsed_ms: float | None = Field(default=None, ge=0)
    tool_run_id: str | None = None
    stop_reason: AgentStopReason | None = None
    message: str | None = None


class _ConversationCheckpointState(BaseModel):
    """checkpoint 中可验证、可恢复的公开会话快照。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    thread: ThreadView
    messages: tuple[ThreadMessage, ...]
    run: RunView
    events: tuple[RunEvent, ...]
    rolling_summary: RollingSummary | None = None


@dataclass
class _RunState:
    """仅存在于当前进程的可变运行状态；第 6 阶段再持久化。"""

    run_id: RunId
    thread_id: ThreadId
    created_at: datetime
    cancellation: AgentCancellationToken
    status: RunStatus = RunStatus.RUNNING
    finished_at: datetime | None = None
    result: AgentTurnResult | None = None
    error_code: str | None = None
    error_message: str | None = None
    events: list[RunEvent] = field(default_factory=lambda: [])
    changed: asyncio.Event = field(default_factory=asyncio.Event)
    task: asyncio.Task[None] | None = None


@dataclass
class _ThreadState:
    """当前进程中的线程消息集合。"""

    thread_id: ThreadId
    created_at: datetime
    updated_at: datetime
    messages: list[ThreadMessage] = field(default_factory=lambda: [])
    rolling_summary: RollingSummary | None = None


class InMemoryConversationService:
    """在持久化阶段到来前管理本机线程、run、取消和事件。"""

    def __init__(
        self,
        node_id: NodeId,
        agent_factory: Callable[[], LangChainReadOnlyAgent],
        checkpoints: CheckpointStore | None = None,
        history_assembler: ThreadHistoryAssembler | None = None,
    ) -> None:
        self._node_id = node_id
        self._agent_factory = agent_factory
        self._threads: dict[str, _ThreadState] = {}
        self._runs: dict[str, _RunState] = {}
        self._checkpoints = checkpoints
        self._history_assembler = history_assembler or ThreadHistoryAssembler()
        self._restore()

    def create_thread(self) -> ThreadView:
        """创建稳定线程身份。"""
        now = datetime.now(UTC)
        thread = _ThreadState(
            thread_id=ThreadId.new(),
            created_at=now,
            updated_at=now,
        )
        self._threads[str(thread.thread_id)] = thread
        return self._thread_view(thread)

    def list_threads(self) -> tuple[ThreadView, ...]:
        """按创建时间返回当前进程中的线程。"""
        return tuple(
            self._thread_view(item)
            for item in sorted(self._threads.values(), key=lambda item: item.created_at)
        )

    def get_thread(self, thread_id: ThreadId) -> ThreadDetail:
        """读取一个线程及其公开消息。"""
        state = self._threads.get(str(thread_id))
        if state is None:
            raise KeyError("thread_not_found")
        return ThreadDetail(thread=self._thread_view(state), messages=tuple(state.messages))

    def delete_thread(self, thread_id: ThreadId) -> None:
        """删除线程、短期消息和所属 run，并取消仍在执行的 run。"""
        key = str(thread_id)
        if key not in self._threads:
            raise KeyError("thread_not_found")
        for run_key, state in tuple(self._runs.items()):
            if state.thread_id == thread_id:
                if state.status is RunStatus.RUNNING:
                    state.cancellation.cancel()
                self._runs.pop(run_key)
        self._threads.pop(key)
        if self._checkpoints is not None:
            self._checkpoints.delete_thread(thread_id)

    async def start_run(self, thread_id: ThreadId, value: StartRunInput) -> RunView:
        """验证线程与模型后，在后台启动一次 Agent run。"""
        thread = self._threads.get(str(thread_id))
        if thread is None:
            raise KeyError("thread_not_found")
        history_context = self._history_assembler.assemble(
            tuple(ModelMessage(role=item.role, content=item.content) for item in thread.messages),
            history_budget=ContextBudgets().history_chars,
            previous_summary=thread.rolling_summary,
            workflow_state=self._workflow_state(thread_id),
        )
        thread.rolling_summary = history_context.rolling_summary
        agent = self._agent_factory()
        state = _RunState(
            run_id=RunId.new(),
            thread_id=thread_id,
            created_at=datetime.now(UTC),
            cancellation=AgentCancellationToken(),
        )
        self._runs[str(state.run_id)] = state
        self._add_message(thread_id, "user", value.question, state.run_id)
        self._append(
            state,
            RunEventType.GOAL,
            target_node_id=str(self._node_id),
            message=value.question,
        )
        state.task = asyncio.create_task(self._execute(state, agent, value, history_context))
        return self._view(state)

    def get_run(self, run_id: RunId) -> RunView:
        """读取 run 当前状态。"""
        return self._view(self._get(run_id))

    def cancel_run(self, run_id: RunId) -> RunView:
        """请求取消仍在运行的 run；终态调用保持幂等。"""
        state = self._get(run_id)
        if state.status is RunStatus.RUNNING:
            state.cancellation.cancel()
        return self._view(state)

    async def stream_events(self, run_id: RunId, after: int = 0) -> AsyncIterator[RunEvent]:
        """从指定序号后流出事件，直到 run 进入终态。"""
        state = self._get(run_id)
        cursor = max(after, 0)
        while True:
            state.changed.clear()
            pending = [event for event in state.events if event.sequence > cursor]
            for event in pending:
                cursor = event.sequence
                yield event
            if state.status is not RunStatus.RUNNING and cursor >= len(state.events):
                return
            await state.changed.wait()

    async def _execute(
        self,
        state: _RunState,
        agent: LangChainReadOnlyAgent,
        value: StartRunInput,
        history_context: HistoryContext,
    ) -> None:
        def tool_event(event: AgentToolEvent) -> None:
            self._append(
                state,
                RunEventType.TOOL,
                target_node_id=event.target_node_id,
                tool_name=event.tool_name,
                tool_status=event.status,
                elapsed_ms=event.elapsed_ms,
                tool_run_id=event.tool_run_id,
            )

        try:
            result = await agent.run(
                value.question,
                ToolCallContext(
                    thread_id=state.thread_id,
                    run_id=state.run_id,
                    caller_node_id=self._node_id,
                    execution_node_id=self._node_id,
                ),
                value.tool_names,
                value.limits,
                state.cancellation,
                tool_event,
                history_context,
            )
            state.result = result
            state.status = (
                RunStatus.CANCELLED
                if result.stop_reason is AgentStopReason.CANCELLED
                else RunStatus.COMPLETED
            )
            state.finished_at = datetime.now(UTC)
            self._add_message(state.thread_id, "assistant", result.answer, state.run_id)
            self._append(
                state,
                RunEventType.FINISHED,
                elapsed_ms=result.elapsed_ms,
                stop_reason=result.stop_reason,
                message=result.answer,
            )
        except Exception:
            state.status = RunStatus.FAILED
            state.finished_at = datetime.now(UTC)
            state.error_code = "agent_run_failed"
            state.error_message = "Agent run 执行失败"
            self._append(
                state,
                RunEventType.FAILED,
                message=state.error_message,
            )

    def _append(self, state: _RunState, event_type: RunEventType, **values: object) -> None:
        state.events.append(
            RunEvent.model_validate(
                {
                    "sequence": len(state.events) + 1,
                    "event_type": event_type,
                    "created_at": datetime.now(UTC),
                    "run_id": state.run_id,
                    **values,
                }
            )
        )
        state.changed.set()
        self._persist(state)

    def _persist(self, state: _RunState) -> None:
        """保存公开状态；不保存取消令牌、后台任务或隐藏推理。"""
        if self._checkpoints is None:
            return
        thread = self._threads.get(str(state.thread_id))
        if thread is None:
            return
        status = CheckpointStatus(state.status.value)
        self._checkpoints.put(
            CheckpointRecord(
                thread_id=state.thread_id,
                run_id=state.run_id,
                status=status,
                public_state=_ConversationCheckpointState(
                    thread=self._thread_view(thread),
                    messages=tuple(thread.messages),
                    run=self._view(state),
                    events=tuple(state.events),
                    rolling_summary=thread.rolling_summary,
                ).model_dump(mode="json"),
                tool_run_ids=(
                    tuple(ToolRunId(item) for item in state.result.tool_run_ids)
                    if state.result is not None
                    else ()
                ),
                updated_at=datetime.now(UTC),
            )
        )

    def _restore(self) -> None:
        """读取公开 checkpoint，并把崩溃时仍在运行的 run 标记为中断。"""
        if self._checkpoints is None:
            return
        for record in self._checkpoints.list_all():
            public = _ConversationCheckpointState.model_validate(record.public_state)
            thread_view = public.thread
            messages = list(public.messages)
            self._threads[str(record.thread_id)] = _ThreadState(
                thread_id=record.thread_id,
                created_at=thread_view.created_at,
                updated_at=thread_view.updated_at,
                messages=messages,
                rolling_summary=public.rolling_summary,
            )
            run_view = public.run
            state = _RunState(
                run_id=record.run_id,
                thread_id=record.thread_id,
                created_at=run_view.created_at,
                cancellation=AgentCancellationToken(),
                status=run_view.status,
                finished_at=run_view.finished_at,
                result=run_view.result,
                error_code=run_view.error_code,
                error_message=run_view.error_message,
                events=list(public.events),
            )
            self._runs[str(record.run_id)] = state
            if state.status is RunStatus.RUNNING:
                state.status = RunStatus.INTERRUPTED
                state.finished_at = datetime.now(UTC)
                state.error_code = "run_interrupted"
                state.error_message = "服务重启时 run 尚未完成；未自动重放工具"
                self._append(
                    state,
                    RunEventType.INTERRUPTED,
                    message=state.error_message,
                )

    def _workflow_state(self, thread_id: ThreadId) -> WorkflowContextState | None:
        pending = tuple(
            item
            for item in self._runs.values()
            if item.thread_id == thread_id
            and item.status in {RunStatus.RUNNING, RunStatus.INTERRUPTED}
        )
        if not pending:
            return None
        return WorkflowContextState(
            status="unfinished",
            pending_steps=tuple(f"{item.run_id}:{item.status.value}" for item in pending),
            source_run_ids=tuple(item.run_id for item in pending),
            safety_constraints=(
                "不得自动重放工具调用",
                "不得从摘要恢复授权或写操作",
            ),
        )

    def _get(self, run_id: RunId) -> _RunState:
        state = self._runs.get(str(run_id))
        if state is None:
            raise KeyError("run_not_found")
        return state

    def _add_message(
        self,
        thread_id: ThreadId,
        role: str,
        content: str,
        run_id: RunId,
    ) -> None:
        thread = self._threads.get(str(thread_id))
        if thread is None:
            return
        now = datetime.now(UTC)
        thread.messages.append(
            ThreadMessage(role=role, content=content, created_at=now, run_id=run_id)
        )
        thread.updated_at = now

    @staticmethod
    def _thread_view(state: _ThreadState) -> ThreadView:
        return ThreadView(
            thread_id=state.thread_id,
            created_at=state.created_at,
            updated_at=state.updated_at,
            message_count=len(state.messages),
        )

    @staticmethod
    def _view(state: _RunState) -> RunView:
        return RunView(
            run_id=state.run_id,
            thread_id=state.thread_id,
            status=state.status,
            created_at=state.created_at,
            finished_at=state.finished_at,
            result=state.result,
            error_code=state.error_code,
            error_message=state.error_message,
        )
