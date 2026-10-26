"""被委派方：接下另一台电脑交来的问题，用本机的 Agent 和本机工具查清楚。

每次委派都有上限（模型轮数、工具次数、总时长），由本机决定，请求方改不了。
本机处理委派时只用本机工具，不能再把问题交给别的电脑。
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from contextvars import ContextVar, copy_context
from datetime import UTC, datetime
from typing import Protocol

from tunnelminion.agent.runtime import (
    AgentCancellationToken,
    AgentRunLimits,
    CheckedAgentTurnResult,
    TaskAgent,
)
from tunnelminion.domain.delegation import (
    DELEGATE_TOOL_NAME,
    MAX_MODEL_ROUNDS,
    MAX_SECONDS,
    MAX_TOOL_CALLS,
    DelegationBusyError,
    DelegationErrorCode,
    DelegationEvidence,
    DelegationProposedRepair,
    DelegationRecord,
    DelegationRequest,
    DelegationResult,
    DelegationStatus,
)
from tunnelminion.domain.identifiers import DelegationId, NodeId, RunId, ThreadId
from tunnelminion.model.contracts import ProviderError
from tunnelminion.tools.contracts import ToolCallContext

_LIMITS = AgentRunLimits(
    max_model_rounds=MAX_MODEL_ROUNDS,
    max_tool_calls=MAX_TOOL_CALLS,
    timeout_seconds=MAX_SECONDS,
)
current_delegation: ContextVar[DelegationRecord | None] = ContextVar(
    "current_delegation", default=None
)


class DelegationStore(Protocol):
    """委派记录的读写。"""

    def put(self, record: DelegationRecord) -> None: ...

    def get(self, delegation_id: DelegationId) -> DelegationRecord | None: ...

    def running_for(self, caller_node_id: NodeId) -> tuple[DelegationRecord, ...]: ...

    def recent(self, limit: int = 50) -> tuple[DelegationRecord, ...]: ...


def summarize(result: CheckedAgentTurnResult) -> DelegationResult:
    """只保留结论和证据摘要，不带工具原始输出。"""
    answer = result.evidence_answer
    return DelegationResult(
        summary=answer.summary[:4000],
        confirmed_facts=tuple(fact.statement for fact in answer.confirmed_facts[:20]),
        inferences=answer.inferences[:20],
        unknowns=answer.unknowns[:20],
        evidence=tuple(
            DelegationEvidence(tool_name=item.tool_name, status=item.status)
            for item in answer.evidence[:MAX_TOOL_CALLS]
        ),
        stop_reason=result.stop_reason.value,
        model_rounds=result.model_rounds,
        tool_calls=result.tool_calls,
        elapsed_ms=result.elapsed_ms,
    )


class DelegationService:
    """接收委派、在后台运行一次有边界的本机调查，并保存记录。"""

    def __init__(
        self,
        node_id: NodeId,
        store: DelegationStore,
        agent_factory: Callable[[], TaskAgent],
        tool_names: Callable[[], tuple[str, ...]],
        *,
        clock: Callable[[], datetime] | None = None,
        repair_query: Callable[[DelegationId], tuple[DelegationProposedRepair, ...]] | None = None,
    ) -> None:
        self._node_id = node_id
        self._store = store
        self._agent_factory = agent_factory
        self._tool_names = tool_names
        self._clock = clock or (lambda: datetime.now(UTC))
        self._repair_query = repair_query
        self._tasks: dict[str, tuple[asyncio.Task[None], AgentCancellationToken]] = {}
        self._fail_interrupted()

    def _fail_interrupted(self) -> None:
        # 进程重启前还在跑的委派已经没有执行者了，如实记为失败。
        for record in self._store.recent(200):
            if record.status is DelegationStatus.RUNNING:
                self._finish(record, DelegationStatus.FAILED, error=DelegationErrorCode.FAILED)

    def submit(self, request: DelegationRequest) -> DelegationRecord:
        if self._store.running_for(request.caller_node_id):
            raise DelegationBusyError("这台电脑已有一个委派在处理中")
        record = DelegationRecord(
            delegation_id=DelegationId.new(),
            caller_node_id=request.caller_node_id,
            executing_node_id=self._node_id,
            question=request.question,
            service_key=request.service_key,
            status=DelegationStatus.RUNNING,
            created_at=self._clock(),
        )
        self._store.put(record)
        cancellation = AgentCancellationToken()
        # 后台任务保留提交请求的追踪上下文，不受后续轮询影响。
        task = asyncio.create_task(self._run(record, cancellation), context=copy_context())
        self._tasks[str(record.delegation_id)] = (task, cancellation)
        task.add_done_callback(lambda _: self._tasks.pop(str(record.delegation_id), None))
        return record

    def get(self, delegation_id: DelegationId, caller_node_id: NodeId) -> DelegationRecord | None:
        """只有发起委派的那台电脑能看到它的记录。"""
        record = self._store.get(delegation_id)
        return record if record is not None and record.caller_node_id == caller_node_id else None

    async def cancel(
        self, delegation_id: DelegationId, caller_node_id: NodeId
    ) -> DelegationRecord | None:
        record = self.get(delegation_id, caller_node_id)
        if record is None or record.status is not DelegationStatus.RUNNING:
            return record
        running = self._tasks.get(str(delegation_id))
        if running is not None:
            task, cancellation = running
            cancellation.cancel()
            await asyncio.gather(task, return_exceptions=True)
        current = self._store.get(delegation_id) or record
        if current.status is DelegationStatus.RUNNING:
            current = self._finish(current, DelegationStatus.CANCELLED)
        return current

    async def wait(self, delegation_id: DelegationId) -> None:
        """等后台调查结束；供测试和关闭时使用。"""
        running = self._tasks.get(str(delegation_id))
        if running is not None:
            await asyncio.gather(running[0], return_exceptions=True)

    async def _run(self, record: DelegationRecord, cancellation: AgentCancellationToken) -> None:
        question = record.question
        if record.service_key:
            question += f"\n（对方指明的相关服务：{record.service_key}）"
        # 在本机执行：调用方和执行方都是本机，Agent 不会去找远端工具。
        context = ToolCallContext(
            thread_id=ThreadId.new(),
            run_id=RunId.new(),
            caller_node_id=self._node_id,
            execution_node_id=self._node_id,
        )
        tools = tuple(name for name in self._tool_names() if name != DELEGATE_TOOL_NAME)
        delegation_token = current_delegation.set(record)
        try:
            agent = self._agent_factory()
            result = await asyncio.wait_for(
                agent.run(question, context, tools, _LIMITS, cancellation),
                timeout=MAX_SECONDS + 5,
            )
            summary = summarize(result)
            if self._repair_query is not None:
                summary = summary.model_copy(
                    update={"proposed_repairs": self._repair_query(record.delegation_id)[:3]}
                )
        except ProviderError:
            self._finish(
                record, DelegationStatus.FAILED, error=DelegationErrorCode.MODEL_UNAVAILABLE
            )
            return
        except TimeoutError:
            self._finish(record, DelegationStatus.FAILED, error=DelegationErrorCode.TIMEOUT)
            return
        except Exception:
            self._finish(record, DelegationStatus.FAILED, error=DelegationErrorCode.FAILED)
            return
        finally:
            current_delegation.reset(delegation_token)
        status = (
            DelegationStatus.CANCELLED if cancellation.cancelled else DelegationStatus.COMPLETED
        )
        self._finish(record, status, result=summary)

    def _finish(
        self,
        record: DelegationRecord,
        status: DelegationStatus,
        *,
        result: DelegationResult | None = None,
        error: DelegationErrorCode | None = None,
    ) -> DelegationRecord:
        finished = record.model_copy(
            update={
                "status": status,
                "finished_at": self._clock(),
                "result": result,
                "error_code": error,
            }
        )
        self._store.put(finished)
        return finished
