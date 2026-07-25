from datetime import UTC, datetime, timedelta

from tunnelminion.agent.context_contracts import (
    ContextFact,
    ContextRequest,
    ContextTaskType,
    FactSource,
    HistoryContext,
    RollingSummary,
    WorkflowContextState,
)
from tunnelminion.agent.context_runtime import ContextSnapshotBuilder
from tunnelminion.agent.history import FactResolver, ThreadHistoryAssembler
from tunnelminion.domain.identifiers import RunId, ThreadId
from tunnelminion.memory.context import ContextBudgets
from tunnelminion.model.contracts import ModelMessage


class FailingSummarizer:
    """模拟摘要服务失败，证明近期原文仍能降级保留。"""

    def summarize(
        self,
        messages: tuple[ModelMessage, ...],
        previous: RollingSummary | None,
    ) -> str:
        del messages, previous
        raise RuntimeError("摘要不可用")


def _messages(count: int, size: int = 80) -> tuple[ModelMessage, ...]:
    return tuple(
        ModelMessage(
            role="user" if index % 2 == 0 else "assistant",
            content=f"message-{index}-" + ("x" * size),
        )
        for index in range(count)
    )


def test_history_keeps_recent_original_and_versions_rolling_summary() -> None:
    assembler = ThreadHistoryAssembler()

    short = assembler.assemble(_messages(2, 20), history_budget=256)
    assert len(short.recent_messages) == 2
    assert short.rolling_summary is None
    assert short.dropped_message_count == 0

    long = assembler.assemble(_messages(5), history_budget=256)
    assert long.recent_messages == _messages(5)[-1:]
    assert long.rolling_summary is not None
    assert long.rolling_summary.version == "rolling-summary/v1"
    assert long.rolling_summary.covered_message_count == 4
    assert len(long.rolling_summary.source_message_refs) == 4
    assert "newer-realtime-evidence-conflicts" in (long.rolling_summary.invalidation_conditions)

    continued = assembler.assemble(
        _messages(3),
        history_budget=256,
        previous_summary=long.rolling_summary,
    )
    assert continued.rolling_summary is not None
    assert (
        continued.rolling_summary.covered_message_count > long.rolling_summary.covered_message_count
    )


def test_summary_failure_retains_recent_history_and_reports_degradation() -> None:
    history = ThreadHistoryAssembler(FailingSummarizer()).assemble(
        _messages(4),
        history_budget=256,
    )

    assert history.recent_messages == _messages(4)[-1:]
    assert history.rolling_summary is None
    assert history.summary_error_code == "summary_failed"
    assert history.dropped_message_count == 3
    snapshot = ContextSnapshotBuilder().build(
        ContextRequest(
            task_type=ContextTaskType.LOCAL_CONVERSATION,
            current_intent="继续",
            thread_id=ThreadId.new(),
            run_id=RunId.new(),
            prompt_id="readonly-agent",
            prompt_version="v1",
            messages=(ModelMessage(role="user", content="继续"),),
            history=history,
        ),
        provider_name="provider",
        model_name="model",
        tool_schema_version="tools/v1",
    )
    assert any(item.reason.value == "summary-failed" for item in snapshot.truncations)


def test_fact_resolver_prefers_realtime_then_newest_source() -> None:
    now = datetime.now(UTC)
    resolved, conflicts = FactResolver().resolve(
        (
            ContextFact(
                key="pdf.port",
                value="8080",
                source=FactSource.HISTORY,
                source_id="history:old",
                observed_at=now - timedelta(days=1),
            ),
            ContextFact(
                key="pdf.port",
                value="9090",
                source=FactSource.REALTIME_EVIDENCE,
                source_id="toolrun:new",
                observed_at=now,
            ),
            ContextFact(
                key="pdf.port",
                value="7070",
                source=FactSource.MODEL_INFERENCE,
                source_id="model:guess",
            ),
            ContextFact(
                key="node.status",
                value="offline",
                source=FactSource.REALTIME_EVIDENCE,
                source_id="toolrun:older",
                observed_at=now - timedelta(seconds=1),
            ),
            ContextFact(
                key="node.status",
                value="online",
                source=FactSource.REALTIME_EVIDENCE,
                source_id="toolrun:newer",
                observed_at=now,
            ),
        )
    )

    assert [(item.key, item.value) for item in resolved] == [
        ("node.status", "online"),
        ("pdf.port", "9090"),
    ]
    assert {item.stale_value for item in conflicts} == {
        "offline",
        "8080",
        "7070",
    }
    assert all(item.reason == "lower-priority-or-older" for item in conflicts)


def test_snapshot_orders_workflow_history_facts_and_current_message() -> None:
    now = datetime.now(UTC)
    summary = RollingSummary(
        version="rolling-summary/v1",
        content="PDF 过去使用 8080。",
        covered_message_count=2,
        source_message_refs=("history:1", "history:2"),
        generated_at=now,
        invalidation_conditions=("newer-realtime-evidence-conflicts",),
    )
    history = HistoryContext(
        recent_messages=(ModelMessage(role="assistant", content="上次端口是 8080。"),),
        rolling_summary=summary,
        workflow_state=WorkflowContextState(
            status="unfinished",
            pending_steps=("重新探测",),
            source_run_ids=(RunId.new(),),
            safety_constraints=("不得自动重放工具",),
        ),
        dropped_message_count=2,
        history_chars=80,
    )
    snapshot = ContextSnapshotBuilder().build(
        ContextRequest(
            task_type=ContextTaskType.LOCAL_CONVERSATION,
            current_intent="现在端口是多少？",
            thread_id=ThreadId.new(),
            run_id=RunId.new(),
            prompt_id="readonly-agent",
            prompt_version="v1",
            messages=(
                ModelMessage(role="system", content="只使用只读工具。"),
                ModelMessage(role="user", content="现在端口是多少？"),
            ),
            history=history,
            facts=(
                ContextFact(
                    key="pdf.port",
                    value="8080",
                    source=FactSource.HISTORY,
                    source_id="history:summary",
                ),
                ContextFact(
                    key="pdf.port",
                    value="9090",
                    source=FactSource.REALTIME_EVIDENCE,
                    source_id="toolrun:latest",
                    observed_at=now,
                ),
            ),
            budgets=ContextBudgets(history_chars=256),
        ),
        provider_name="provider",
        model_name="model",
        tool_schema_version="tools/v1",
    )

    contents = [item.content for item in snapshot.model_request.messages]
    assert "程序维护的未完成工作流状态" in contents[1]
    assert "历史导航摘要" in contents[2]
    assert contents[3] == "上次端口是 8080。"
    assert '"value":"9090"' in contents[4]
    assert '"stale_value":"8080"' in contents[4]
    assert contents[-1] == "现在端口是多少？"
    assert snapshot.resolved_facts[0].value == "9090"
    assert snapshot.fact_conflicts[0].stale_value == "8080"
    assert snapshot.budget_decisions[1].kind.value == "history-summary"
    assert snapshot.truncations[-1].source_id == "thread-history:budget"
