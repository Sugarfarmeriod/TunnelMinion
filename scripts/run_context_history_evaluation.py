"""运行历史上下文、摘要降级与事实新鲜度的确定性阶段门禁。"""

from __future__ import annotations

import argparse
import json
from collections.abc import Sequence
from pathlib import Path
from time import perf_counter

from pydantic import BaseModel, ConfigDict, Field

from tunnelminion.agent.context_contracts import (
    ContextFact,
    ContextRequest,
    ContextTaskType,
    FactSource,
)
from tunnelminion.agent.context_runtime import ContextSnapshotBuilder
from tunnelminion.agent.history import FactResolver, ThreadHistoryAssembler
from tunnelminion.domain.identifiers import RunId, ThreadId
from tunnelminion.memory.context import ContextBudgets
from tunnelminion.model.contracts import ModelMessage


class ContextHistoryMetrics(BaseModel):
    """3.x 阶段可重复计算的正确性和开销指标。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    scenario_count: int = Field(ge=1)
    task_completion_rate: float = Field(ge=0, le=1)
    evidence_consistency_rate: float = Field(ge=0, le=1)
    trimming_correctness_rate: float = Field(ge=0, le=1)
    average_builder_latency_ms: float = Field(ge=0)
    provider_tokens: int = Field(ge=0)
    estimated_cost: float = Field(ge=0)


class ContextHistoryReport(BaseModel):
    """带 Builder 与摘要版本的阶段评估报告。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: int = 1
    change: str
    stage: str
    builder_version: str
    summary_version: str
    metrics: ContextHistoryMetrics
    notes: tuple[str, ...]


def _messages(count: int) -> tuple[ModelMessage, ...]:
    return tuple(
        ModelMessage(
            role="user" if index % 2 == 0 else "assistant",
            content=f"history-{index}-" + ("x" * 120),
        )
        for index in range(count)
    )


def evaluate(iterations: int = 100) -> ContextHistoryReport:
    """重复组装固定长 thread，并验证裁剪和实时证据优先级。"""
    assembler = ThreadHistoryAssembler()
    history = assembler.assemble(_messages(40), history_budget=1_024)
    facts = (
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
        ),
    )
    builder = ContextSnapshotBuilder()
    request = ContextRequest(
        task_type=ContextTaskType.LOCAL_CONVERSATION,
        current_intent="确认 PDF 当前端口",
        thread_id=ThreadId.new(),
        run_id=RunId.new(),
        prompt_id="readonly-agent",
        prompt_version="v1",
        messages=(
            ModelMessage(role="system", content="只使用实时只读证据。"),
            ModelMessage(role="user", content="PDF 当前端口是什么？"),
        ),
        history=history,
        facts=facts,
        budgets=ContextBudgets(history_chars=1_024),
    )
    started = perf_counter()
    snapshots = tuple(
        builder.build(
            request,
            provider_name="offline",
            model_name="none",
            tool_schema_version="readonly-tools/v1",
        )
        for _ in range(iterations)
    )
    average_latency = (perf_counter() - started) * 1_000 / iterations
    latest = snapshots[-1]
    resolved, conflicts = FactResolver().resolve(facts)
    scenarios = (
        bool(history.recent_messages and history.rolling_summary),
        history.dropped_message_count > 0,
        resolved[0].value == "9090",
        conflicts[0].stale_value == "8080",
    )
    rate = sum(scenarios) / len(scenarios)
    trimming_passed = (
        history.history_chars <= 1_024
        and latest.budget_decisions[1].used_chars <= 1_024
        and any(item.source_id == "thread-history:budget" for item in latest.truncations)
    )
    return ContextHistoryReport(
        change="integrate-agent-context-and-prompt-runtime",
        stage="history-context",
        builder_version=ContextSnapshotBuilder.VERSION,
        summary_version=ThreadHistoryAssembler.SUMMARY_VERSION,
        metrics=ContextHistoryMetrics(
            scenario_count=len(scenarios),
            task_completion_rate=rate,
            evidence_consistency_rate=rate,
            trimming_correctness_rate=1.0 if trimming_passed else 0.0,
            average_builder_latency_ms=average_latency,
            provider_tokens=0,
            estimated_cost=0.0,
        ),
        notes=(
            "本门禁只测确定性上下文组装，不调用模型 Provider。",
            "真实模型的 token、成本与端到端延迟留到综合真机验收。",
        ),
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    report = evaluate()
    serialized = report.model_dump_json(indent=2) + "\n"
    if args.output is None:
        print(json.dumps(report.model_dump(mode="json"), ensure_ascii=False, indent=2))
    else:
        args.output.write_text(serialized, encoding="utf-8")
    metrics = report.metrics
    if args.check and (
        metrics.task_completion_rate != 1.0
        or metrics.evidence_consistency_rate != 1.0
        or metrics.trimming_correctness_rate != 1.0
        or metrics.average_builder_latency_ms > 50
    ):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
