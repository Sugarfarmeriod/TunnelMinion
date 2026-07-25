"""thread 历史预算、滚动摘要和确定性事实优先级。"""

from __future__ import annotations

import hashlib
from collections import defaultdict
from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Protocol

from tunnelminion.agent.context_contracts import (
    ContextFact,
    FactConflict,
    FactSource,
    HistoryContext,
    ResolvedFact,
    RollingSummary,
    WorkflowContextState,
)
from tunnelminion.domain.identifiers import MemoryId
from tunnelminion.model.contracts import ModelMessage

_FACT_PRIORITY = {
    FactSource.REALTIME_EVIDENCE: 4,
    FactSource.CONFIRMED_MEMORY: 3,
    FactSource.HISTORY: 2,
    FactSource.MODEL_INFERENCE: 1,
}
_SUMMARY_INVALIDATION_CONDITIONS = (
    "source-message-changed-or-deleted",
    "referenced-memory-revised-or-deleted",
    "workflow-state-changed",
    "newer-realtime-evidence-conflicts",
)


class HistorySummarizer(Protocol):
    """可替换但必须失败可见的历史摘要边界。"""

    def summarize(
        self,
        messages: tuple[ModelMessage, ...],
        previous: RollingSummary | None,
    ) -> str: ...


class DeterministicHistorySummarizer:
    """不调用模型的首版摘要器，只保留角色和有界原文。"""

    def summarize(
        self,
        messages: tuple[ModelMessage, ...],
        previous: RollingSummary | None,
    ) -> str:
        parts = [previous.content] if previous is not None else []
        parts.extend(f"{message.role}: {message.content[:160]}" for message in messages)
        return "历史导航摘要（不是实时事实）：" + " | ".join(parts)


class ThreadHistoryAssembler:
    """保留近期原文，并把更早内容滚动进带来源的摘要。"""

    SUMMARY_VERSION = "rolling-summary/v1"

    def __init__(self, summarizer: HistorySummarizer | None = None) -> None:
        self._summarizer = summarizer or DeterministicHistorySummarizer()

    def assemble(
        self,
        messages: Sequence[ModelMessage],
        *,
        history_budget: int,
        previous_summary: RollingSummary | None = None,
        workflow_state: WorkflowContextState | None = None,
        memory_ids: Sequence[MemoryId] = (),
    ) -> HistoryContext:
        """当前消息由调用方单独保留；这里只对既有 thread 历史使用独立预算。"""
        if not messages and previous_summary is None:
            return HistoryContext(
                workflow_state=workflow_state,
                dropped_message_count=0,
                history_chars=0,
            )
        summary_budget = max(64, history_budget // 3)
        recent_budget = history_budget - summary_budget
        if (
            previous_summary is None
            and sum(len(item.content) for item in messages) <= history_budget
        ):
            recent_budget = history_budget
        recent = self._recent(messages, recent_budget)
        older = tuple(messages[: len(messages) - len(recent)])
        summary: RollingSummary | None = previous_summary
        summary_error: str | None = None
        if older:
            try:
                content = self._summarizer.summarize(older, previous_summary)[:summary_budget]
                refs = (
                    previous_summary.source_message_refs if previous_summary is not None else ()
                ) + tuple(self._message_ref(item, index) for index, item in enumerate(older))
                refs += tuple(f"memory:{memory_id}" for memory_id in memory_ids)
                summary = RollingSummary(
                    version=self.SUMMARY_VERSION,
                    content=content,
                    covered_message_count=(
                        (previous_summary.covered_message_count if previous_summary else 0)
                        + len(older)
                    ),
                    source_message_refs=refs,
                    generated_at=datetime.now(UTC),
                    invalidation_conditions=_SUMMARY_INVALIDATION_CONDITIONS,
                )
            except Exception:
                summary_error = "summary_failed"
        summary_chars = len(summary.content) if summary is not None else 0
        return HistoryContext(
            recent_messages=recent,
            rolling_summary=summary,
            workflow_state=workflow_state,
            dropped_message_count=len(older),
            history_chars=sum(len(item.content) for item in recent) + summary_chars,
            summary_error_code=summary_error,
        )

    @staticmethod
    def _recent(
        messages: Sequence[ModelMessage],
        budget: int,
    ) -> tuple[ModelMessage, ...]:
        selected: list[ModelMessage] = []
        used = 0
        for message in reversed(messages):
            size = len(message.content)
            if used + size > budget:
                break
            selected.append(message)
            used += size
        return tuple(reversed(selected))

    @staticmethod
    def _message_ref(message: ModelMessage, index: int) -> str:
        digest = hashlib.sha256(f"{message.role}\0{message.content}".encode()).hexdigest()
        return f"history:{index}:sha256:{digest}"


class FactResolver:
    """按来源优先级、采集时间和来源 ID 稳定解析事实冲突。"""

    def resolve(
        self,
        candidates: Sequence[ContextFact],
    ) -> tuple[tuple[ResolvedFact, ...], tuple[FactConflict, ...]]:
        grouped: dict[str, list[ContextFact]] = defaultdict(list)
        for candidate in candidates:
            grouped[candidate.key].append(candidate)
        resolved: list[ResolvedFact] = []
        conflicts: list[FactConflict] = []
        for key in sorted(grouped):
            ranked = sorted(
                grouped[key],
                key=lambda item: (
                    _FACT_PRIORITY[item.source],
                    item.observed_at or datetime.min.replace(tzinfo=UTC),
                    item.source_id,
                ),
                reverse=True,
            )
            selected = ranked[0]
            resolved.append(
                ResolvedFact(
                    key=selected.key,
                    value=selected.value,
                    source=selected.source,
                    source_id=selected.source_id,
                    observed_at=selected.observed_at,
                )
            )
            conflicts.extend(
                FactConflict(
                    key=key,
                    selected_source_id=selected.source_id,
                    stale_value=item.value,
                    stale_source=item.source,
                    stale_source_id=item.source_id,
                )
                for item in ranked[1:]
                if item.value != selected.value
            )
        return tuple(resolved), tuple(conflicts)
