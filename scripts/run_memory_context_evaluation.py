"""运行长期记忆隔离、生命周期与错误注入的确定性阶段门禁。"""

from __future__ import annotations

import argparse
import json
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from time import perf_counter

from pydantic import BaseModel, ConfigDict, Field

from tunnelminion.domain.identifiers import MemoryId, NodeId
from tunnelminion.memory.contracts import LongTermMemory, MemoryKind, MemoryNamespace
from tunnelminion.memory.service import MemoryContextQuery, MemoryContextRetriever


class InMemoryMemoryStore:
    """只用于确定性评测的最小长期记忆存储。"""

    def __init__(self) -> None:
        self._items: dict[str, LongTermMemory] = {}

    def put(self, memory: LongTermMemory) -> None:
        self._items[str(memory.memory_id)] = memory

    def get(self, memory_id: MemoryId) -> LongTermMemory | None:
        return self._items.get(str(memory_id))

    def list_all(self) -> tuple[LongTermMemory, ...]:
        return tuple(self._items.values())

    def list_namespace(
        self,
        namespace: MemoryNamespace,
    ) -> tuple[LongTermMemory, ...]:
        return tuple(
            memory
            for memory in self._items.values()
            if memory.namespace.user == namespace.user
            and memory.namespace.network == namespace.network
            and memory.namespace.node_id == namespace.node_id
        )

    def delete(self, memory_id: MemoryId) -> None:
        self._items.pop(str(memory_id), None)

    def clear_namespace(self, namespace: MemoryNamespace) -> None:
        for memory in self.list_namespace(namespace):
            self.delete(memory.memory_id)


class MemoryContextMetrics(BaseModel):
    """4.x 阶段可重复计算的正确性、隔离性和性能指标。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    scenario_count: int = Field(ge=1)
    memory_hit_correctness: float = Field(ge=0, le=1)
    incorrect_injection_rate: float = Field(ge=0, le=1)
    namespace_leakage_rate: float = Field(ge=0, le=1)
    lifecycle_residual_rate: float = Field(ge=0, le=1)
    average_retrieval_latency_ms: float = Field(ge=0)
    provider_tokens: int = Field(ge=0)
    estimated_cost: float = Field(ge=0)


class MemoryContextReport(BaseModel):
    """带检索规则版本的长期记忆阶段评测报告。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: int = 1
    change: str
    stage: str
    retrieval_policy: str
    metrics: MemoryContextMetrics
    notes: tuple[str, ...]


def _memory(
    namespace: MemoryNamespace,
    content: str,
    *,
    confirmed: bool = True,
    valid_until: datetime | None = None,
    deleted_at: datetime | None = None,
) -> LongTermMemory:
    return LongTermMemory(
        memory_id=MemoryId.new(),
        namespace=namespace,
        kind=MemoryKind.STABLE_SERVICE_FACT,
        content=content,
        source="固定评测数据",
        user_confirmed=confirmed,
        updated_at=datetime.now(UTC),
        valid_until=valid_until,
        deleted_at=deleted_at,
    )


def evaluate(iterations: int = 100) -> MemoryContextReport:
    """检验硬作用域过滤先于相关性排序，且失效正文不会残留。"""
    now = datetime.now(UTC)
    scope = MemoryNamespace(
        user="local-user",
        network="home",
        node_id=NodeId.new(),
    )
    store = InMemoryMemoryStore()
    expected = _memory(scope, "PDF 服务当前端口是 9090")
    records = (
        expected,
        _memory(scope, "PDF 未确认端口是 7070", confirmed=False),
        _memory(
            scope,
            "PDF 过期端口是 8080",
            valid_until=now - timedelta(seconds=1),
        ),
        _memory(
            scope.model_copy(update={"task_type": "operation-plan"}),
            "PDF 越权任务端口是 6000",
        ),
        _memory(
            scope.model_copy(update={"user": "other-user"}),
            "PDF 越权用户端口是 5000",
        ),
        _memory(scope, "[DELETED]", deleted_at=now),
    )
    for memory in records:
        store.put(memory)

    retriever = MemoryContextRetriever(store)
    query = MemoryContextQuery(namespace=scope, question="PDF 当前端口", at=now)
    started = perf_counter()
    results = tuple(retriever.retrieve(query) for _ in range(iterations))
    average_latency = (perf_counter() - started) * 1_000 / iterations
    latest = results[-1]
    selected_ids = {str(memory.memory_id) for memory in latest}
    forbidden_ids = {str(memory.memory_id) for memory in records[1:]}
    leaked = tuple(memory for memory in latest if memory.namespace != scope)
    residual = tuple(
        memory
        for memory in latest
        if memory.deleted_at is not None
        or memory.superseded_by is not None
        or (memory.valid_until is not None and memory.valid_until <= now)
    )
    return MemoryContextReport(
        change="integrate-agent-context-and-prompt-runtime",
        stage="memory-context",
        retrieval_policy="namespace-first/v1",
        metrics=MemoryContextMetrics(
            scenario_count=len(records),
            memory_hit_correctness=1.0 if latest == (expected,) else 0.0,
            incorrect_injection_rate=(len(selected_ids & forbidden_ids) / len(forbidden_ids)),
            namespace_leakage_rate=len(leaked) / len(latest) if latest else 0.0,
            lifecycle_residual_rate=len(residual) / len(latest) if latest else 0.0,
            average_retrieval_latency_ms=average_latency,
            provider_tokens=0,
            estimated_cost=0.0,
        ),
        notes=(
            "本门禁只验证确定性记忆检索与生命周期规则，不调用模型 Provider。",
            "跨用户、跨节点、跨任务和跨安全域候选必须在相关性排序前移除。",
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
        metrics.memory_hit_correctness != 1.0
        or metrics.incorrect_injection_rate != 0.0
        or metrics.namespace_leakage_rate != 0.0
        or metrics.lifecycle_residual_rate != 0.0
        or metrics.average_retrieval_latency_ms > 50
    ):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
