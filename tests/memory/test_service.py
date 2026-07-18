"""长期记忆确认、安全拒绝和作用域管理测试。"""

from __future__ import annotations

from pathlib import Path

import pytest

from tunnelminion.domain.identifiers import MemoryId, NodeId
from tunnelminion.memory.contracts import MemoryKind, MemoryNamespace
from tunnelminion.memory.service import (
    LongTermMemoryService,
    MemoryCandidate,
    MemoryCandidateOrigin,
    MemoryWriteRejected,
)
from tunnelminion.memory.sqlite import SQLiteStores


def namespace(node_id: NodeId | None = None) -> MemoryNamespace:
    """创建隔离测试使用的记忆作用域。"""
    return MemoryNamespace(user="local-user", network="home", node_id=node_id or NodeId.new())


def candidate(
    scope: MemoryNamespace,
    *,
    content: str = "B 是家里的 Mac",
    source: str = "用户在设置页确认",
    origin: MemoryCandidateOrigin = MemoryCandidateOrigin.USER_STATEMENT,
    confirmed: bool = True,
) -> MemoryCandidate:
    """创建节点别名候选。"""
    return MemoryCandidate(
        namespace=scope,
        kind=MemoryKind.NODE_ALIAS,
        content=content,
        source=source,
        origin=origin,
        user_confirmed=confirmed,
    )


def service(tmp_path: Path) -> LongTermMemoryService:
    """创建使用真实 SQLite 适配器的服务。"""
    return LongTermMemoryService(SQLiteStores.open(tmp_path / "memory.sqlite3").memories)


def test_confirmed_memory_can_be_saved_revised_deleted_and_cleared(tmp_path: Path) -> None:
    """用户确认的稳定事实可在所属 namespace 内完整管理。"""
    memories = service(tmp_path)
    first_scope = namespace()
    second_scope = namespace()
    saved = memories.save_confirmed(candidate(first_scope))
    other = memories.save_confirmed(candidate(second_scope, content="C 是服务器"))

    assert memories.list(first_scope) == (saved,)
    assert memories.list(second_scope) == (other,)
    revised = memories.revise(saved.memory_id, "B 是书房里的 Mac", "用户修正")
    assert revised.memory_id == saved.memory_id
    assert revised.updated_at >= saved.updated_at
    assert memories.list(first_scope) == (revised,)

    memories.delete(revised.memory_id)
    assert memories.list(first_scope) == ()
    memories.clear(second_scope)
    assert memories.list(second_scope) == ()


@pytest.mark.parametrize(
    ("value", "code"),
    [
        (candidate(namespace(), confirmed=False), "confirmation_required"),
        (
            candidate(namespace(), origin=MemoryCandidateOrigin.REALTIME_SNAPSHOT),
            "realtime_snapshot_forbidden",
        ),
        (
            candidate(namespace(), origin=MemoryCandidateOrigin.SYSTEM_LOG),
            "system_log_forbidden",
        ),
        (
            candidate(namespace(), content="api_key=should-not-be-here"),
            "sensitive_content_forbidden",
        ),
        (
            candidate(namespace(), source="Authorization: Bearer secret-value"),
            "sensitive_content_forbidden",
        ),
        (
            candidate(namespace(), content="-----BEGIN TEST PRIVATE KEY-----"),
            "sensitive_content_forbidden",
        ),
    ],
)
def test_forbidden_memory_candidates_are_rejected(
    tmp_path: Path, value: MemoryCandidate, code: str
) -> None:
    """未确认推测、实时快照、日志和秘密都不能进入长期记忆。"""
    memories = service(tmp_path)
    with pytest.raises(MemoryWriteRejected) as caught:
        memories.save_confirmed(value)
    assert caught.value.code == code
    assert memories.list(value.namespace) == ()


def test_confirmed_model_suggestion_is_allowed_but_sensitive_revision_is_not(
    tmp_path: Path,
) -> None:
    """模型建议必须先确认；确认后仍受敏感信息检查。"""
    memories = service(tmp_path)
    scope = namespace()
    saved = memories.save_confirmed(candidate(scope, origin=MemoryCandidateOrigin.MODEL_INFERENCE))
    assert saved.user_confirmed is True

    with pytest.raises(MemoryWriteRejected, match="sensitive_content_forbidden"):
        memories.revise(saved.memory_id, "Bearer abcdefghijklmnop", "用户修正")
    with pytest.raises(KeyError, match="memory_not_found"):
        memories.revise(MemoryId.new(), "x", "用户")
    with pytest.raises(KeyError, match="memory_not_found"):
        memories.delete(MemoryId.new())
