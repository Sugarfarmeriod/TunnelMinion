"""三个独立 SQLite 存储适配器的持久化与隔离测试。"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

from tunnelminion.domain.identifiers import (
    ArtifactId,
    MemoryId,
    NodeId,
    RunId,
    ThreadId,
    ToolRunId,
)
from tunnelminion.memory.contracts import (
    CheckpointRecord,
    CheckpointStatus,
    CheckpointStore,
    LongTermMemory,
    LongTermMemoryStore,
    MemoryKind,
    MemoryNamespace,
    ToolArtifact,
    ToolArtifactStore,
)
from tunnelminion.memory.sqlite import SQLiteStores


def checkpoint(
    thread_id: ThreadId,
    run_id: RunId,
    status: CheckpointStatus = CheckpointStatus.RUNNING,
) -> CheckpointRecord:
    """创建不含隐藏推理的公开 checkpoint。"""
    return CheckpointRecord(
        thread_id=thread_id,
        run_id=run_id,
        status=status,
        public_state={"remaining_model_rounds": 3},
        tool_run_ids=(ToolRunId.new(),),
        updated_at=datetime.now(UTC),
    )


def memory(namespace: MemoryNamespace, content: str = "B 是家里的 Mac") -> LongTermMemory:
    """创建用户确认的节点别名记忆。"""
    return LongTermMemory(
        memory_id=MemoryId.new(),
        namespace=namespace,
        kind=MemoryKind.NODE_ALIAS,
        content=content,
        source="用户在本地聊天中确认",
        user_confirmed=True,
        updated_at=datetime.now(UTC),
    )


def test_checkpoint_store_upserts_lists_persists_and_deletes(tmp_path: Path) -> None:
    """checkpoint 可更新、重开读取并按线程整体删除。"""
    path = tmp_path / "nested" / "runtime.sqlite3"
    stores = SQLiteStores.open(path)
    store: CheckpointStore = stores.checkpoints
    thread = ThreadId.new()
    first = checkpoint(thread, RunId.new())
    second = checkpoint(thread, RunId.new())

    assert store.get(first.run_id) is None
    store.put(first)
    store.put(second)
    completed = first.model_copy(
        update={
            "status": CheckpointStatus.COMPLETED,
            "updated_at": first.updated_at + timedelta(seconds=1),
        }
    )
    store.put(completed)

    assert store.get(first.run_id) == completed
    assert store.list_thread(thread) == (completed, second)
    reopened = SQLiteStores.open(path)
    assert reopened.checkpoints.get(second.run_id) == second
    reopened.checkpoints.delete_thread(thread)
    reopened.checkpoints.delete_thread(thread)
    assert reopened.checkpoints.list_thread(thread) == ()


def test_artifact_store_round_trip_update_and_delete(tmp_path: Path) -> None:
    """大型工具正文只通过 artifact 接口读写。"""
    store: ToolArtifactStore = SQLiteStores.open(tmp_path / "data.sqlite3").artifacts
    artifact = ToolArtifact(
        artifact_id=ArtifactId.new(),
        tool_run_id=ToolRunId.new(),
        content={"listeners": [8080, 8082]},
        content_bytes=32,
        created_at=datetime.now(UTC),
    )

    assert store.get(artifact.artifact_id) is None
    store.put(artifact)
    assert store.get(artifact.artifact_id) == artifact
    updated = artifact.model_copy(update={"content": {"listeners": [8082]}, "content_bytes": 20})
    store.put(updated)
    assert store.get(artifact.artifact_id) == updated
    store.delete(artifact.artifact_id)
    store.delete(artifact.artifact_id)
    assert store.get(artifact.artifact_id) is None


def test_memory_store_enforces_namespace_queries_and_scope_clear(tmp_path: Path) -> None:
    """长期记忆查询与清空严格限定用户、网络和节点三元组。"""
    store: LongTermMemoryStore = SQLiteStores.open(tmp_path / "data.sqlite3").memories
    node = NodeId.new()
    home = MemoryNamespace(user="local-user", network="home", node_id=node)
    work = MemoryNamespace(user="local-user", network="work", node_id=node)
    first = memory(home)
    second = memory(work, "B 是工作 Mac")

    assert store.get(first.memory_id) is None
    store.put(first)
    store.put(second)
    assert store.list_all() == (first, second)
    assert store.list_namespace(home) == (first,)
    assert store.list_namespace(work) == (second,)

    moved = first.model_copy(
        update={
            "namespace": work,
            "content": "B 已移动到工作网络",
            "updated_at": datetime.now(UTC),
        }
    )
    store.put(moved)
    assert store.list_namespace(home) == ()
    assert store.list_namespace(work) == (moved, second)
    store.delete(second.memory_id)
    store.delete(second.memory_id)
    assert store.get(second.memory_id) is None
    store.clear_namespace(work)
    store.clear_namespace(work)
    assert store.list_namespace(work) == ()
