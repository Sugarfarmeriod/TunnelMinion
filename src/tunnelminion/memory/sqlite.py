"""checkpoint、artifact 与长期记忆的 SQLite 适配器。"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from pathlib import Path

from tunnelminion.domain.identifiers import ArtifactId, MemoryId, RunId, ThreadId
from tunnelminion.memory.contracts import (
    CheckpointRecord,
    LongTermMemory,
    MemoryNamespace,
    ToolArtifact,
)


class _SQLiteDatabase:
    """每次操作使用短连接，避免跨线程共享 sqlite3 连接。"""

    def __init__(self, path: Path) -> None:
        self._path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS checkpoints (
                    run_id TEXT PRIMARY KEY,
                    thread_id TEXT NOT NULL,
                    payload TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS checkpoints_thread
                    ON checkpoints(thread_id);
                CREATE TABLE IF NOT EXISTS tool_artifacts (
                    artifact_id TEXT PRIMARY KEY,
                    payload TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS long_term_memories (
                    memory_id TEXT PRIMARY KEY,
                    user_namespace TEXT NOT NULL,
                    network_namespace TEXT NOT NULL,
                    node_id TEXT NOT NULL,
                    payload TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS memories_namespace
                    ON long_term_memories(user_namespace, network_namespace, node_id);
                """
            )

    def connect(self) -> sqlite3.Connection:
        """创建启用 WAL 和忙等待的本地连接。"""
        connection = sqlite3.connect(self._path, timeout=5)
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA foreign_keys=ON")
        return connection


class SQLiteCheckpointStore:
    """SQLite checkpoint 表适配。"""

    def __init__(self, database: _SQLiteDatabase) -> None:
        self._database = database

    def put(self, record: CheckpointRecord) -> None:
        with self._database.connect() as connection:
            connection.execute(
                """INSERT INTO checkpoints(run_id, thread_id, payload) VALUES (?, ?, ?)
                ON CONFLICT(run_id) DO UPDATE SET
                    thread_id=excluded.thread_id, payload=excluded.payload""",
                (str(record.run_id), str(record.thread_id), record.model_dump_json()),
            )

    def get(self, run_id: RunId) -> CheckpointRecord | None:
        with self._database.connect() as connection:
            row = connection.execute(
                "SELECT payload FROM checkpoints WHERE run_id=?", (str(run_id),)
            ).fetchone()
        return CheckpointRecord.model_validate_json(row[0]) if row is not None else None

    def list_all(self) -> tuple[CheckpointRecord, ...]:
        with self._database.connect() as connection:
            rows = connection.execute("SELECT payload FROM checkpoints ORDER BY rowid").fetchall()
        return tuple(CheckpointRecord.model_validate_json(row[0]) for row in rows)

    def list_thread(self, thread_id: ThreadId) -> tuple[CheckpointRecord, ...]:
        with self._database.connect() as connection:
            rows = connection.execute(
                "SELECT payload FROM checkpoints WHERE thread_id=? ORDER BY rowid",
                (str(thread_id),),
            ).fetchall()
        return tuple(CheckpointRecord.model_validate_json(row[0]) for row in rows)

    def delete_thread(self, thread_id: ThreadId) -> None:
        with self._database.connect() as connection:
            connection.execute("DELETE FROM checkpoints WHERE thread_id=?", (str(thread_id),))


class SQLiteToolArtifactStore:
    """SQLite tool artifact 表适配。"""

    def __init__(self, database: _SQLiteDatabase) -> None:
        self._database = database

    def put(self, artifact: ToolArtifact) -> None:
        with self._database.connect() as connection:
            connection.execute(
                """INSERT INTO tool_artifacts(artifact_id, payload) VALUES (?, ?)
                ON CONFLICT(artifact_id) DO UPDATE SET payload=excluded.payload""",
                (str(artifact.artifact_id), artifact.model_dump_json()),
            )

    def get(self, artifact_id: ArtifactId) -> ToolArtifact | None:
        with self._database.connect() as connection:
            row = connection.execute(
                "SELECT payload FROM tool_artifacts WHERE artifact_id=?", (str(artifact_id),)
            ).fetchone()
        return ToolArtifact.model_validate_json(row[0]) if row is not None else None

    def delete(self, artifact_id: ArtifactId) -> None:
        with self._database.connect() as connection:
            connection.execute(
                "DELETE FROM tool_artifacts WHERE artifact_id=?", (str(artifact_id),)
            )


class SQLiteLongTermMemoryStore:
    """SQLite 长期记忆表适配。"""

    def __init__(self, database: _SQLiteDatabase) -> None:
        self._database = database

    def put(self, memory: LongTermMemory) -> None:
        namespace = memory.namespace
        with self._database.connect() as connection:
            connection.execute(
                """INSERT INTO long_term_memories(
                    memory_id, user_namespace, network_namespace, node_id, payload
                ) VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(memory_id) DO UPDATE SET
                    user_namespace=excluded.user_namespace,
                    network_namespace=excluded.network_namespace,
                    node_id=excluded.node_id,
                    payload=excluded.payload""",
                (
                    str(memory.memory_id),
                    namespace.user,
                    namespace.network,
                    str(namespace.node_id),
                    memory.model_dump_json(),
                ),
            )

    def get(self, memory_id: MemoryId) -> LongTermMemory | None:
        with self._database.connect() as connection:
            row = connection.execute(
                "SELECT payload FROM long_term_memories WHERE memory_id=?", (str(memory_id),)
            ).fetchone()
        return LongTermMemory.model_validate_json(row[0]) if row is not None else None

    def list_all(self) -> tuple[LongTermMemory, ...]:
        """按写入顺序返回全部 namespace 的长期记忆，供受控导出使用。"""
        with self._database.connect() as connection:
            rows = connection.execute(
                "SELECT payload FROM long_term_memories ORDER BY rowid"
            ).fetchall()
        return tuple(LongTermMemory.model_validate_json(row[0]) for row in rows)

    def list_namespace(self, namespace: MemoryNamespace) -> tuple[LongTermMemory, ...]:
        with self._database.connect() as connection:
            rows = connection.execute(
                """SELECT payload FROM long_term_memories
                WHERE user_namespace=? AND network_namespace=? AND node_id=?
                ORDER BY rowid""",
                (namespace.user, namespace.network, str(namespace.node_id)),
            ).fetchall()
        return tuple(LongTermMemory.model_validate_json(row[0]) for row in rows)

    def delete(self, memory_id: MemoryId) -> None:
        with self._database.connect() as connection:
            connection.execute(
                "DELETE FROM long_term_memories WHERE memory_id=?", (str(memory_id),)
            )

    def clear_namespace(self, namespace: MemoryNamespace) -> None:
        with self._database.connect() as connection:
            connection.execute(
                """DELETE FROM long_term_memories
                WHERE user_namespace=? AND network_namespace=? AND node_id=?""",
                (namespace.user, namespace.network, str(namespace.node_id)),
            )


@dataclass(frozen=True)
class SQLiteStores:
    """共享一个数据库文件但保持三个独立访问对象。"""

    checkpoints: SQLiteCheckpointStore
    artifacts: SQLiteToolArtifactStore
    memories: SQLiteLongTermMemoryStore

    @classmethod
    def open(cls, path: Path) -> SQLiteStores:
        """初始化 schema 并返回独立存储适配器。"""
        database = _SQLiteDatabase(path)
        return cls(
            checkpoints=SQLiteCheckpointStore(database),
            artifacts=SQLiteToolArtifactStore(database),
            memories=SQLiteLongTermMemoryStore(database),
        )
