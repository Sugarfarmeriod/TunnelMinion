"""长期记忆的确认、敏感信息拒绝和作用域内管理流程。"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from enum import StrEnum
from typing import Protocol

from pydantic import BaseModel, ConfigDict, Field

from tunnelminion.domain.identifiers import MemoryId
from tunnelminion.memory.contracts import (
    LongTermMemory,
    LongTermMemoryStore,
    MemoryKind,
    MemoryNamespace,
)


class MemoryCandidateOrigin(StrEnum):
    """候选内容的来源类型，用来阻止实时状态和原始日志长期化。"""

    USER_STATEMENT = "user-statement"
    MODEL_INFERENCE = "model-inference"
    REALTIME_SNAPSHOT = "realtime-snapshot"
    SYSTEM_LOG = "system-log"


class MemoryCandidate(BaseModel):
    """等待用户显式确认后写入的稳定信息候选。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    namespace: MemoryNamespace
    kind: MemoryKind
    content: str = Field(min_length=1, max_length=20_000)
    source: str = Field(min_length=1, max_length=2_000)
    origin: MemoryCandidateOrigin
    user_confirmed: bool
    valid_until: datetime | None = None


class MemoryWriteRejected(ValueError):
    """候选记忆不满足长期保存边界。"""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class MemoryInvalidationSink(Protocol):
    """让摘要或候选缓存按 Memory ID 失效的最小边界。"""

    def invalidate_memory(self, memory_id: MemoryId) -> None: ...


class MemoryContextQuery(BaseModel):
    """先执行硬作用域过滤，再做相关性排序的检索请求。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    namespace: MemoryNamespace
    question: str = Field(min_length=1, max_length=20_000)
    at: datetime
    limit: int = Field(default=8, ge=1, le=64)


class MemoryContextRetriever:
    """只返回当前作用域内仍有效、已确认且相关的记忆。"""

    def __init__(self, store: LongTermMemoryStore) -> None:
        self._store = store

    def retrieve(self, query: MemoryContextQuery) -> tuple[LongTermMemory, ...]:
        """硬过滤发生在相关性计算之前，越权候选不会进入排序集合。"""
        scoped = tuple(
            memory
            for memory in self._store.list_namespace(query.namespace)
            if memory.namespace == query.namespace
            and memory.user_confirmed
            and memory.deleted_at is None
            and memory.superseded_by is None
            and (memory.valid_until is None or memory.valid_until > query.at)
        )
        terms = {
            term.lower()
            for term in re.findall(r"[\w\u4e00-\u9fff]+", query.question)
            if len(term) >= 2
        }

        def relevance(memory: LongTermMemory) -> tuple[int, float, str]:
            searchable = f"{memory.kind.value} {memory.content} {memory.source}".lower()
            score = sum(term in searchable for term in terms)
            if memory.kind in {MemoryKind.PREFERENCE, MemoryKind.SECURITY_CONSTRAINT}:
                score += 1
            return score, memory.updated_at.timestamp(), str(memory.memory_id)

        ranked = sorted(scoped, key=relevance, reverse=True)
        return tuple(memory for memory in ranked if relevance(memory)[0] > 0)[: query.limit]


class LongTermMemoryService:
    """只允许经过确认且不含秘密的稳定事实进入 Memory Store。"""

    _SENSITIVE_PATTERNS = (
        re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----", re.IGNORECASE),
        re.compile(r"\b(?:api[_-]?key|access[_-]?token|client[_-]?secret)\s*[:=]", re.I),
        re.compile(r"\bauthorization\s*:\s*", re.IGNORECASE),
        re.compile(r"\bbearer\s+[A-Za-z0-9._~+/=-]{8,}", re.IGNORECASE),
    )

    def __init__(
        self,
        store: LongTermMemoryStore,
        invalidation_sinks: tuple[MemoryInvalidationSink, ...] = (),
    ) -> None:
        self._store = store
        self._invalidation_sinks = invalidation_sinks

    def save_confirmed(self, candidate: MemoryCandidate) -> LongTermMemory:
        """验证确认状态、来源类别和敏感模式后保存候选。"""
        self._validate_candidate(candidate)
        memory = LongTermMemory(
            memory_id=MemoryId.new(),
            namespace=candidate.namespace,
            kind=candidate.kind,
            content=candidate.content,
            source=candidate.source,
            user_confirmed=True,
            updated_at=datetime.now(UTC),
            valid_until=candidate.valid_until,
        )
        self._store.put(memory)
        return memory

    def _validate_candidate(self, candidate: MemoryCandidate) -> None:
        """集中执行长期记忆写入边界。"""
        if not candidate.user_confirmed:
            raise MemoryWriteRejected("confirmation_required")
        if candidate.origin is MemoryCandidateOrigin.REALTIME_SNAPSHOT:
            raise MemoryWriteRejected("realtime_snapshot_forbidden")
        if candidate.origin is MemoryCandidateOrigin.SYSTEM_LOG:
            raise MemoryWriteRejected("system_log_forbidden")
        if candidate.valid_until is not None and candidate.valid_until <= datetime.now(UTC):
            raise MemoryWriteRejected("valid_until_must_be_future")
        combined = f"{candidate.content}\n{candidate.source}"
        if any(pattern.search(combined) for pattern in self._SENSITIVE_PATTERNS):
            raise MemoryWriteRejected("sensitive_content_forbidden")

    def list(self, namespace: MemoryNamespace) -> tuple[LongTermMemory, ...]:
        """只列出指定用户、网络和节点作用域内的记忆。"""
        now = datetime.now(UTC)
        return tuple(
            memory
            for memory in self._store.list_namespace(namespace)
            if memory.namespace == namespace
            and memory.user_confirmed
            and memory.deleted_at is None
            and memory.superseded_by is None
            and (memory.valid_until is None or memory.valid_until > now)
        )

    def revise(
        self,
        memory_id: MemoryId,
        content: str,
        source: str,
    ) -> LongTermMemory:
        """修正一条已有记忆，同时再次执行敏感内容检查。"""
        existing = self._store.get(memory_id)
        if existing is None:
            raise KeyError("memory_not_found")
        candidate = MemoryCandidate(
            namespace=existing.namespace,
            kind=existing.kind,
            content=content,
            source=source,
            origin=MemoryCandidateOrigin.USER_STATEMENT,
            user_confirmed=True,
        )
        self._validate_candidate(candidate)
        if (
            existing.deleted_at is not None
            or existing.superseded_by is not None
            or (existing.valid_until is not None and existing.valid_until <= datetime.now(UTC))
        ):
            raise KeyError("memory_not_active")
        revised = LongTermMemory(
            memory_id=MemoryId.new(),
            namespace=existing.namespace,
            kind=existing.kind,
            content=candidate.content,
            source=candidate.source,
            user_confirmed=True,
            updated_at=datetime.now(UTC),
            valid_until=existing.valid_until,
            revision_of=existing.memory_id,
        )
        superseded = existing.model_copy(
            update={
                "content": "[SUPERSEDED]",
                "source": "revision-chain",
                "superseded_by": revised.memory_id,
                "updated_at": revised.updated_at,
            }
        )
        self._store.put(superseded)
        self._store.put(revised)
        self._invalidate(existing.memory_id)
        return revised

    def delete(self, memory_id: MemoryId) -> None:
        """删除单条记忆；未知 ID 不隐式成功。"""
        existing = self._store.get(memory_id)
        if existing is None or existing.deleted_at is not None:
            raise KeyError("memory_not_found")
        active = self._active_revision(existing)
        self._store.put(
            active.model_copy(
                update={
                    "content": "[DELETED]",
                    "source": "tombstone",
                    "deleted_at": datetime.now(UTC),
                }
            )
        )
        self._invalidate(memory_id)
        if active.memory_id != memory_id:
            self._invalidate(active.memory_id)

    def clear(self, namespace: MemoryNamespace) -> None:
        """只清空显式指定的 namespace。"""
        for memory in self.list(namespace):
            self.delete(memory.memory_id)

    def _invalidate(self, memory_id: MemoryId) -> None:
        for sink in self._invalidation_sinks:
            sink.invalidate_memory(memory_id)

    def _active_revision(self, memory: LongTermMemory) -> LongTermMemory:
        seen = {str(memory.memory_id)}
        current = memory
        while current.superseded_by is not None:
            replacement_id = str(current.superseded_by)
            if replacement_id in seen:
                raise RuntimeError("memory_revision_cycle")
            seen.add(replacement_id)
            replacement = self._store.get(current.superseded_by)
            if replacement is None:
                raise RuntimeError("memory_revision_missing")
            current = replacement
        return current
