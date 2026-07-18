"""长期记忆的确认、敏感信息拒绝和作用域内管理流程。"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from enum import StrEnum

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


class MemoryWriteRejected(ValueError):
    """候选记忆不满足长期保存边界。"""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class LongTermMemoryService:
    """只允许经过确认且不含秘密的稳定事实进入 Memory Store。"""

    _SENSITIVE_PATTERNS = (
        re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----", re.IGNORECASE),
        re.compile(r"\b(?:api[_-]?key|access[_-]?token|client[_-]?secret)\s*[:=]", re.I),
        re.compile(r"\bauthorization\s*:\s*", re.IGNORECASE),
        re.compile(r"\bbearer\s+[A-Za-z0-9._~+/=-]{8,}", re.IGNORECASE),
    )

    def __init__(self, store: LongTermMemoryStore) -> None:
        self._store = store

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
        combined = f"{candidate.content}\n{candidate.source}"
        if any(pattern.search(combined) for pattern in self._SENSITIVE_PATTERNS):
            raise MemoryWriteRejected("sensitive_content_forbidden")

    def list(self, namespace: MemoryNamespace) -> tuple[LongTermMemory, ...]:
        """只列出指定用户、网络和节点作用域内的记忆。"""
        return self._store.list_namespace(namespace)

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
        revised = LongTermMemory(
            memory_id=memory_id,
            namespace=existing.namespace,
            kind=existing.kind,
            content=candidate.content,
            source=candidate.source,
            user_confirmed=True,
            updated_at=datetime.now(UTC),
        )
        self._store.put(revised)
        return revised

    def delete(self, memory_id: MemoryId) -> None:
        """删除单条记忆；未知 ID 不隐式成功。"""
        if self._store.get(memory_id) is None:
            raise KeyError("memory_not_found")
        self._store.delete(memory_id)

    def clear(self, namespace: MemoryNamespace) -> None:
        """只清空显式指定的 namespace。"""
        self._store.clear_namespace(namespace)
