"""checkpoint、artifact 与长期记忆的 SQLite 适配器。"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from tunnelminion.domain.identifiers import (
    ArtifactId,
    AuthorizationId,
    MemoryId,
    OperationId,
    RunId,
    ThreadId,
)
from tunnelminion.memory.contracts import (
    CheckpointRecord,
    LongTermMemory,
    MemoryNamespace,
    ToolArtifact,
)
from tunnelminion.operation.contracts import (
    TERMINAL_OPERATION_STATUSES,
    OperationRecord,
    OperationStore,
    OperationSummary,
    Preauthorization,
    PreauthorizationStore,
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
                CREATE TABLE IF NOT EXISTS operations (
                    operation_id TEXT PRIMARY KEY,
                    idempotency_key TEXT NOT NULL UNIQUE,
                    status TEXT NOT NULL,
                    target_node_id TEXT NOT NULL,
                    payload TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS operations_status
                    ON operations(status);
                CREATE INDEX IF NOT EXISTS operations_target
                    ON operations(target_node_id);
                CREATE TABLE IF NOT EXISTS operation_authorizations (
                    authorization_id TEXT PRIMARY KEY,
                    operation_id TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    FOREIGN KEY(operation_id) REFERENCES operations(operation_id)
                        ON DELETE CASCADE
                );
                CREATE TABLE IF NOT EXISTS operation_leases (
                    lease_id TEXT PRIMARY KEY,
                    operation_id TEXT NOT NULL UNIQUE,
                    expires_at TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    FOREIGN KEY(operation_id) REFERENCES operations(operation_id)
                        ON DELETE CASCADE
                );
                CREATE INDEX IF NOT EXISTS operation_leases_expiry
                    ON operation_leases(expires_at);
                CREATE TABLE IF NOT EXISTS operation_resources (
                    resource_id TEXT PRIMARY KEY,
                    operation_id TEXT NOT NULL,
                    owner_fingerprint TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    FOREIGN KEY(operation_id) REFERENCES operations(operation_id)
                        ON DELETE CASCADE
                );
                CREATE TABLE IF NOT EXISTS operation_verifications (
                    operation_id TEXT NOT NULL,
                    sequence INTEGER NOT NULL,
                    payload TEXT NOT NULL,
                    PRIMARY KEY(operation_id, sequence),
                    FOREIGN KEY(operation_id) REFERENCES operations(operation_id)
                        ON DELETE CASCADE
                );
                CREATE TABLE IF NOT EXISTS operation_cleanups (
                    operation_id TEXT PRIMARY KEY,
                    payload TEXT NOT NULL,
                    FOREIGN KEY(operation_id) REFERENCES operations(operation_id)
                        ON DELETE CASCADE
                );
                CREATE TABLE IF NOT EXISTS operation_transitions (
                    operation_id TEXT NOT NULL,
                    sequence INTEGER NOT NULL,
                    from_status TEXT,
                    to_status TEXT NOT NULL,
                    occurred_at TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    PRIMARY KEY(operation_id, sequence),
                    FOREIGN KEY(operation_id) REFERENCES operations(operation_id)
                        ON DELETE CASCADE
                );
                CREATE TABLE IF NOT EXISTS operation_preauthorizations (
                    authorization_id TEXT PRIMARY KEY,
                    target_node_id TEXT NOT NULL,
                    request_peer_id TEXT NOT NULL,
                    tool_name TEXT NOT NULL,
                    valid_until TEXT NOT NULL,
                    revoked_at TEXT,
                    payload TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS operation_preauthorizations_match
                    ON operation_preauthorizations(
                        target_node_id, request_peer_id, tool_name, valid_until
                    );
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
        return tuple(
            memory
            for row in rows
            if (memory := LongTermMemory.model_validate_json(row[0])).namespace == namespace
        )

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


class SQLiteOperationStore:
    """操作聚合及其恢复索引的 SQLite 适配器。"""

    def __init__(self, database: _SQLiteDatabase) -> None:
        self._database = database

    def put(self, record: OperationRecord) -> None:
        """在一个事务中更新聚合和所有可独立检查的子记录。"""
        operation_id = str(record.plan.operation_id)
        with self._database.connect() as connection:
            connection.execute(
                """INSERT INTO operations(
                    operation_id, idempotency_key, status, target_node_id, payload
                ) VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(operation_id) DO UPDATE SET
                    idempotency_key=excluded.idempotency_key,
                    status=excluded.status,
                    target_node_id=excluded.target_node_id,
                    payload=excluded.payload""",
                (
                    operation_id,
                    record.plan.idempotency_key,
                    record.status.value,
                    str(record.plan.target_node_id),
                    record.model_dump_json(),
                ),
            )
            for table in (
                "operation_authorizations",
                "operation_leases",
                "operation_resources",
                "operation_verifications",
                "operation_cleanups",
                "operation_transitions",
            ):
                connection.execute(f"DELETE FROM {table} WHERE operation_id=?", (operation_id,))
            if record.authorization is not None:
                connection.execute(
                    """INSERT INTO operation_authorizations(
                        authorization_id, operation_id, payload
                    ) VALUES (?, ?, ?)""",
                    (
                        str(record.authorization.authorization_id),
                        operation_id,
                        record.authorization.model_dump_json(),
                    ),
                )
            if record.lease is not None:
                connection.execute(
                    """INSERT INTO operation_leases(
                        lease_id, operation_id, expires_at, payload
                    ) VALUES (?, ?, ?, ?)""",
                    (
                        str(record.lease.lease_id),
                        operation_id,
                        record.lease.expires_at.isoformat(),
                        record.lease.model_dump_json(),
                    ),
                )
            connection.executemany(
                """INSERT INTO operation_resources(
                    resource_id, operation_id, owner_fingerprint, payload
                ) VALUES (?, ?, ?, ?)""",
                (
                    (
                        str(item.resource_id),
                        operation_id,
                        item.owner_fingerprint,
                        item.model_dump_json(),
                    )
                    for item in record.resources
                ),
            )
            connection.executemany(
                """INSERT INTO operation_verifications(
                    operation_id, sequence, payload
                ) VALUES (?, ?, ?)""",
                (
                    (operation_id, sequence, item.model_dump_json())
                    for sequence, item in enumerate(record.verifications)
                ),
            )
            if record.cleanup is not None:
                connection.execute(
                    """INSERT INTO operation_cleanups(operation_id, payload)
                    VALUES (?, ?)""",
                    (operation_id, record.cleanup.model_dump_json()),
                )
            connection.executemany(
                """INSERT INTO operation_transitions(
                    operation_id, sequence, from_status, to_status, occurred_at, payload
                ) VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    (
                        operation_id,
                        sequence,
                        item.from_status.value if item.from_status is not None else None,
                        item.to_status.value,
                        item.occurred_at.isoformat(),
                        item.model_dump_json(),
                    )
                    for sequence, item in enumerate(record.transitions)
                ),
            )

    def get(self, operation_id: OperationId) -> OperationRecord | None:
        """按稳定 operation_id 读取完整聚合。"""
        with self._database.connect() as connection:
            row = connection.execute(
                "SELECT payload FROM operations WHERE operation_id=?",
                (str(operation_id),),
            ).fetchone()
        return OperationRecord.model_validate_json(row[0]) if row is not None else None

    def get_by_idempotency_key(self, key: str) -> OperationRecord | None:
        with self._database.connect() as connection:
            row = connection.execute(
                "SELECT payload FROM operations WHERE idempotency_key=?",
                (key,),
            ).fetchone()
        return OperationRecord.model_validate_json(row[0]) if row is not None else None

    def list_all(self) -> tuple[OperationRecord, ...]:
        with self._database.connect() as connection:
            rows = connection.execute("SELECT payload FROM operations ORDER BY rowid").fetchall()
        return tuple(OperationRecord.model_validate_json(row[0]) for row in rows)

    def list_unfinished(self) -> tuple[OperationRecord, ...]:
        terminal = tuple(item.value for item in TERMINAL_OPERATION_STATUSES)
        placeholders = ", ".join("?" for _ in terminal)
        with self._database.connect() as connection:
            rows = connection.execute(
                f"""SELECT payload FROM operations
                WHERE status NOT IN ({placeholders}) ORDER BY rowid""",
                terminal,
            ).fetchall()
        return tuple(OperationRecord.model_validate_json(row[0]) for row in rows)

    def list_summaries(self) -> tuple[OperationSummary, ...]:
        return tuple(OperationSummary.from_record(item) for item in self.list_all())


class SQLitePreauthorizationStore:
    """细粒度 L2 预授权的 SQLite 适配器。"""

    def __init__(self, database: _SQLiteDatabase) -> None:
        self._database = database

    def put(self, authorization: Preauthorization) -> None:
        with self._database.connect() as connection:
            connection.execute(
                """INSERT INTO operation_preauthorizations(
                    authorization_id, target_node_id, request_peer_id, tool_name,
                    valid_until, revoked_at, payload
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(authorization_id) DO UPDATE SET
                    target_node_id=excluded.target_node_id,
                    request_peer_id=excluded.request_peer_id,
                    tool_name=excluded.tool_name,
                    valid_until=excluded.valid_until,
                    revoked_at=excluded.revoked_at,
                    payload=excluded.payload""",
                (
                    str(authorization.authorization_id),
                    str(authorization.target_node_id),
                    str(authorization.request_peer_id),
                    authorization.tool_name,
                    authorization.valid_until.isoformat(),
                    (
                        authorization.revoked_at.isoformat()
                        if authorization.revoked_at is not None
                        else None
                    ),
                    authorization.model_dump_json(),
                ),
            )

    def get(self, authorization_id: AuthorizationId) -> Preauthorization | None:
        with self._database.connect() as connection:
            row = connection.execute(
                """SELECT payload FROM operation_preauthorizations
                WHERE authorization_id=?""",
                (str(authorization_id),),
            ).fetchone()
        return Preauthorization.model_validate_json(row[0]) if row is not None else None

    def list_all(self) -> tuple[Preauthorization, ...]:
        with self._database.connect() as connection:
            rows = connection.execute(
                "SELECT payload FROM operation_preauthorizations ORDER BY rowid"
            ).fetchall()
        return tuple(Preauthorization.model_validate_json(row[0]) for row in rows)

    def list_active(self, *, at: datetime) -> tuple[Preauthorization, ...]:
        with self._database.connect() as connection:
            rows = connection.execute(
                """SELECT payload FROM operation_preauthorizations
                WHERE valid_until>? AND revoked_at IS NULL ORDER BY rowid""",
                (at.isoformat(),),
            ).fetchall()
        return tuple(
            item
            for row in rows
            if (item := Preauthorization.model_validate_json(row[0])).valid_from <= at
        )


@dataclass(frozen=True)
class SQLiteStores:
    """共享一个数据库文件但保持各领域独立访问对象。"""

    checkpoints: SQLiteCheckpointStore
    artifacts: SQLiteToolArtifactStore
    memories: SQLiteLongTermMemoryStore
    operations: OperationStore
    preauthorizations: PreauthorizationStore

    @classmethod
    def open(cls, path: Path) -> SQLiteStores:
        """初始化 schema 并返回独立存储适配器。"""
        database = _SQLiteDatabase(path)
        return cls(
            checkpoints=SQLiteCheckpointStore(database),
            artifacts=SQLiteToolArtifactStore(database),
            memories=SQLiteLongTermMemoryStore(database),
            operations=SQLiteOperationStore(database),
            preauthorizations=SQLitePreauthorizationStore(database),
        )
