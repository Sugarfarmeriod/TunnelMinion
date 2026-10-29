"""checkpoint、artifact 与长期记忆的 SQLite 适配器。"""

from __future__ import annotations

import sqlite3
from collections.abc import Callable, Generator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, date, datetime
from pathlib import Path

from pydantic import TypeAdapter

from tunnelminion.domain.delegation import DelegationRecord, DelegationStatus
from tunnelminion.domain.identifiers import (
    ArtifactId,
    AuthorizationId,
    DelegationId,
    MemoryId,
    NodeId,
    OperationId,
    RunId,
    ThreadId,
)
from tunnelminion.domain.invites import InvitePermissions
from tunnelminion.domain.model_borrowing import ModelUsageRecord
from tunnelminion.domain.service_marks import ServiceMark
from tunnelminion.domain.trust import (
    FriendPermissions,
    OwnerRoster,
    SignaturePurpose,
    SignedEnvelope,
    TrustedPerson,
    key_fingerprint,
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
    OperationStatus,
    OperationStore,
    OperationSummary,
    Preauthorization,
    PreauthorizationStore,
)
from tunnelminion.operation.requester import (
    RequesterOperationRecord,
    RequesterOperationStore,
)
from tunnelminion.repair.contracts import (
    REPAIR_ACTIVE_STATUSES,
    REPAIR_TERMINAL_STATUSES,
    AnyLaunchRecord,
    LaunchRecordStore,
    RepairClaimResult,
    RepairRecord,
    RepairStore,
)
from tunnelminion.trust.contracts import (
    AlreadyInitializedError,
    DevicePermissions,
    IdentityError,
    OwnerRotationStep,
    TrustAudit,
    VersionRejectedError,
)
from tunnelminion.trust.signatures import (
    VerificationError,
    roster_conflicts,
    verify_device_certificate,
    verify_owner_roster,
    verify_owner_rotation,
    verify_trust_list,
)


def _migrate_friend_device_history(connection: sqlite3.Connection) -> None:
    """早期开发版的朋友电脑历史只按节点记录；遇到旧表结构时按"节点 + 地址"重建。

    旧记录没有地址，用已保存的朋友名单补回"节点 + 地址"；已经移除的朋友不在名单里，补不回来。
    """
    columns = {row[1] for row in connection.execute("PRAGMA table_info(friend_device_history)")}
    if "host" in columns:
        return
    connection.executescript(
        """
        DROP TABLE friend_device_history;
        CREATE TABLE friend_device_history (
            node_id TEXT NOT NULL,
            host TEXT NOT NULL,
            PRIMARY KEY (node_id, host)
        );
        """
    )
    for (raw,) in connection.execute("SELECT envelope_json FROM friend_rosters").fetchall():
        devices = SignedEnvelope.model_validate_json(raw).payload.get("devices")
        connection.executemany(
            "INSERT OR IGNORE INTO friend_device_history VALUES (?, ?)",
            (
                (str(item["node_id"]), str(item["host"]))
                for item in (devices if isinstance(devices, list) else [])
                if isinstance(item, dict)
            ),
        )
    connection.commit()


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
                CREATE TABLE IF NOT EXISTS delegations (
                    delegation_id TEXT PRIMARY KEY,
                    caller_node_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    payload TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS delegations_caller_status
                    ON delegations(caller_node_id, status);
                CREATE TABLE IF NOT EXISTS service_marks (
                    mark_key TEXT PRIMARY KEY,
                    mark TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS model_usage (
                    peer_node_id TEXT NOT NULL,
                    day TEXT NOT NULL,
                    calls INTEGER NOT NULL,
                    tokens INTEGER NOT NULL,
                    PRIMARY KEY(peer_node_id, day)
                );
                CREATE TABLE IF NOT EXISTS gateway_invites (
                    token_digest BLOB PRIMARY KEY,
                    permissions_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    accepted_at TEXT,
                    accepted_node_id TEXT
                );
                CREATE TABLE IF NOT EXISTS trust_identity (
                    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                    owner_fingerprint TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS trust_documents (
                    kind TEXT PRIMARY KEY,
                    version INTEGER NOT NULL,
                    envelope_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS trust_audit (
                    sequence INTEGER PRIMARY KEY,
                    payload TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS trust_rotations (
                    previous_owner_fingerprint TEXT PRIMARY KEY,
                    owner_fingerprint TEXT NOT NULL UNIQUE,
                    step_json TEXT NOT NULL,
                    previous_roster_json TEXT
                );
                CREATE TABLE IF NOT EXISTS owner_invites (
                    token_digest BLOB PRIMARY KEY,
                    expires_at TEXT NOT NULL,
                    accepted_at TEXT,
                    accepted_node_id TEXT
                );
                CREATE TABLE IF NOT EXISTS device_permissions (
                    node_id TEXT PRIMARY KEY,
                    payload TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS friend_rosters (
                    owner_fingerprint TEXT PRIMARY KEY,
                    version INTEGER NOT NULL,
                    envelope_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS friend_permissions (
                    owner_fingerprint TEXT PRIMARY KEY,
                    payload TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS friend_invites (
                    token_digest BLOB PRIMARY KEY,
                    display_name TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    accepted_at TEXT,
                    accepted_node_id TEXT
                );
                CREATE TABLE IF NOT EXISTS friend_node_owners (
                    node_id TEXT PRIMARY KEY,
                    owner_fingerprint TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS friend_device_history (
                    node_id TEXT NOT NULL,
                    host TEXT NOT NULL,
                    PRIMARY KEY (node_id, host)
                );
                CREATE TABLE IF NOT EXISTS own_device_history (
                    node_id TEXT PRIMARY KEY
                );
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
                CREATE TABLE IF NOT EXISTS requester_operations (
                    operation_id TEXT PRIMARY KEY,
                    idempotency_key TEXT NOT NULL UNIQUE,
                    target_node_id TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    payload TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS requester_operations_target
                    ON requester_operations(target_node_id);
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
                CREATE TABLE IF NOT EXISTS repairs (
                    operation_id TEXT PRIMARY KEY,
                    idempotency_key TEXT NOT NULL,
                    service_key TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    started_at TEXT,
                    payload TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS repairs_idempotency ON repairs(idempotency_key);
                CREATE INDEX IF NOT EXISTS repairs_status ON repairs(status);
                CREATE INDEX IF NOT EXISTS repairs_created ON repairs(created_at DESC);
                CREATE INDEX IF NOT EXISTS repairs_rate ON repairs(service_key, started_at);
                CREATE TABLE IF NOT EXISTS launch_records (
                    service_key TEXT PRIMARY KEY,
                    recorded_at TEXT NOT NULL,
                    payload TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS launch_records_recorded
                    ON launch_records(recorded_at DESC);
                """
            )
            _migrate_friend_device_history(connection)

    @contextmanager
    def connect(self) -> Generator[sqlite3.Connection, None, None]:
        """创建短连接，结束时提交或回滚并立即释放文件句柄。"""
        connection = sqlite3.connect(self._path, timeout=5)
        try:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA foreign_keys=ON")
            with connection:
                yield connection
        finally:
            connection.close()


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


class SQLiteRepairStore:
    """修复记录与跨进程执行占用。"""

    def __init__(self, database: _SQLiteDatabase) -> None:
        self._database = database

    @staticmethod
    def _write(connection: sqlite3.Connection, record: RepairRecord) -> None:
        connection.execute(
            """INSERT INTO repairs(
                operation_id, idempotency_key, service_key, status, created_at, started_at, payload
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(operation_id) DO UPDATE SET
                idempotency_key=excluded.idempotency_key,
                service_key=excluded.service_key,
                status=excluded.status,
                created_at=excluded.created_at,
                started_at=excluded.started_at,
                payload=excluded.payload""",
            (
                str(record.plan.operation_id),
                record.plan.idempotency_key,
                record.plan.service_key,
                record.status.value,
                record.plan.created_at.astimezone(UTC).isoformat(),
                record.execution.started_at.astimezone(UTC).isoformat()
                if record.execution is not None
                else None,
                record.model_dump_json(),
            ),
        )

    def put(self, record: RepairRecord) -> None:
        with self._database.connect() as connection:
            self._write(connection, record)

    def get(self, operation_id: OperationId) -> RepairRecord | None:
        with self._database.connect() as connection:
            row = connection.execute(
                "SELECT payload FROM repairs WHERE operation_id=?", (str(operation_id),)
            ).fetchone()
        return RepairRecord.model_validate_json(row[0]) if row is not None else None

    def get_by_idempotency_key(self, key: str) -> RepairRecord | None:
        terminal = tuple(item.value for item in REPAIR_TERMINAL_STATUSES)
        placeholders = ", ".join("?" for _ in terminal)
        with self._database.connect() as connection:
            row = connection.execute(
                f"""SELECT payload FROM repairs
                WHERE idempotency_key=? AND status NOT IN ({placeholders})
                ORDER BY created_at DESC, rowid DESC LIMIT 1""",
                (key, *terminal),
            ).fetchone()
        return RepairRecord.model_validate_json(row[0]) if row is not None else None

    def list_all(self) -> tuple[RepairRecord, ...]:
        with self._database.connect() as connection:
            rows = connection.execute(
                "SELECT payload FROM repairs ORDER BY created_at DESC, rowid DESC"
            ).fetchall()
        return tuple(RepairRecord.model_validate_json(row[0]) for row in rows)

    def claim_execution(
        self, executing: RepairRecord, *, rate_window_start: datetime, rate_limit: int
    ) -> RepairClaimResult:
        with self._database.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            if executing.status is not OperationStatus.EXECUTING or executing.execution is None:
                return RepairClaimResult.STATE_CONFLICT
            row = connection.execute(
                "SELECT status FROM repairs WHERE operation_id=?",
                (str(executing.plan.operation_id),),
            ).fetchone()
            if row is None or row[0] != OperationStatus.AUTHORIZED.value:
                return RepairClaimResult.STATE_CONFLICT
            active = tuple(item.value for item in REPAIR_ACTIVE_STATUSES)
            placeholders = ", ".join("?" for _ in active)
            if connection.execute(
                f"SELECT 1 FROM repairs WHERE status IN ({placeholders}) LIMIT 1", active
            ).fetchone():
                return RepairClaimResult.BUSY
            count = connection.execute(
                "SELECT COUNT(*) FROM repairs WHERE service_key=? AND started_at>=?",
                (executing.plan.service_key, rate_window_start.astimezone(UTC).isoformat()),
            ).fetchone()[0]
            if count >= rate_limit:
                return RepairClaimResult.RATE_LIMITED
            self._write(connection, executing)
            return RepairClaimResult.CLAIMED


# Python 脚本的启动记录和 macOS 后台服务记录放在同一张表里，按字段区分。
_ANY_LAUNCH_RECORD: TypeAdapter[AnyLaunchRecord] = TypeAdapter(AnyLaunchRecord)


class SQLiteLaunchRecordStore:
    """按服务身份保存最新的本机启动方式。"""

    def __init__(self, database: _SQLiteDatabase) -> None:
        self._database = database

    def put(self, record: AnyLaunchRecord) -> None:
        with self._database.connect() as connection:
            connection.execute(
                """INSERT INTO launch_records(service_key, recorded_at, payload) VALUES (?, ?, ?)
                ON CONFLICT(service_key) DO UPDATE SET
                    recorded_at=excluded.recorded_at, payload=excluded.payload""",
                (
                    record.service_key,
                    record.recorded_at.astimezone(UTC).isoformat(),
                    record.model_dump_json(),
                ),
            )

    def get(self, service_key: str) -> AnyLaunchRecord | None:
        with self._database.connect() as connection:
            row = connection.execute(
                "SELECT payload FROM launch_records WHERE service_key=?", (service_key,)
            ).fetchone()
        return _ANY_LAUNCH_RECORD.validate_json(row[0]) if row is not None else None

    def list_all(self) -> tuple[AnyLaunchRecord, ...]:
        with self._database.connect() as connection:
            rows = connection.execute(
                "SELECT payload FROM launch_records ORDER BY recorded_at DESC, rowid DESC"
            ).fetchall()
        return tuple(_ANY_LAUNCH_RECORD.validate_json(row[0]) for row in rows)


class SQLiteRequesterOperationStore:
    """请求端计划和脱敏远端摘要的 SQLite 适配器。"""

    def __init__(self, database: _SQLiteDatabase) -> None:
        self._database = database

    def put(self, record: RequesterOperationRecord) -> None:
        with self._database.connect() as connection:
            connection.execute(
                """INSERT INTO requester_operations(
                    operation_id, idempotency_key, target_node_id, updated_at, payload
                ) VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(operation_id) DO UPDATE SET
                    idempotency_key=excluded.idempotency_key,
                    target_node_id=excluded.target_node_id,
                    updated_at=excluded.updated_at,
                    payload=excluded.payload""",
                (
                    str(record.plan.operation_id),
                    record.plan.idempotency_key,
                    str(record.plan.target_node_id),
                    record.updated_at.isoformat(),
                    record.model_dump_json(),
                ),
            )

    def get(self, operation_id: OperationId) -> RequesterOperationRecord | None:
        with self._database.connect() as connection:
            row = connection.execute(
                "SELECT payload FROM requester_operations WHERE operation_id=?",
                (str(operation_id),),
            ).fetchone()
        return RequesterOperationRecord.model_validate_json(row[0]) if row is not None else None

    def list_all(self) -> tuple[RequesterOperationRecord, ...]:
        with self._database.connect() as connection:
            rows = connection.execute(
                "SELECT payload FROM requester_operations ORDER BY rowid"
            ).fetchall()
        return tuple(RequesterOperationRecord.model_validate_json(row[0]) for row in rows)


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


class SQLiteServiceMarkStore:
    """用户对本机服务的"是我的服务 / 隐藏"标记。"""

    def __init__(self, database: _SQLiteDatabase) -> None:
        self._database = database

    def all(self) -> dict[str, ServiceMark]:
        with self._database.connect() as connection:
            rows = connection.execute("SELECT mark_key, mark FROM service_marks").fetchall()
        return {str(key): ServiceMark(mark) for key, mark in rows}

    def set(self, key: str, mark: ServiceMark) -> None:
        with self._database.connect() as connection:
            connection.execute(
                """INSERT INTO service_marks(mark_key, mark, updated_at) VALUES (?, ?, ?)
                ON CONFLICT(mark_key) DO UPDATE SET
                    mark=excluded.mark, updated_at=excluded.updated_at""",
                (key, mark.value, datetime.now(UTC).isoformat()),
            )

    def clear(self, key: str) -> None:
        with self._database.connect() as connection:
            connection.execute("DELETE FROM service_marks WHERE mark_key=?", (key,))


class SQLiteDelegationStore:
    """被委派方保存的委派记录：谁问的、问了什么、查到了什么。"""

    def __init__(self, database: _SQLiteDatabase) -> None:
        self._database = database

    def put(self, record: DelegationRecord) -> None:
        with self._database.connect() as connection:
            connection.execute(
                """INSERT INTO delegations(
                    delegation_id, caller_node_id, status, created_at, payload
                ) VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(delegation_id) DO UPDATE SET
                    status=excluded.status, payload=excluded.payload""",
                (
                    str(record.delegation_id),
                    str(record.caller_node_id),
                    record.status.value,
                    record.created_at.isoformat(),
                    record.model_dump_json(),
                ),
            )

    def get(self, delegation_id: DelegationId) -> DelegationRecord | None:
        with self._database.connect() as connection:
            row = connection.execute(
                "SELECT payload FROM delegations WHERE delegation_id=?", (str(delegation_id),)
            ).fetchone()
        return DelegationRecord.model_validate_json(row[0]) if row is not None else None

    def running_for(self, caller_node_id: NodeId) -> tuple[DelegationRecord, ...]:
        with self._database.connect() as connection:
            rows = connection.execute(
                "SELECT payload FROM delegations WHERE caller_node_id=? AND status=?",
                (str(caller_node_id), DelegationStatus.RUNNING.value),
            ).fetchall()
        return tuple(DelegationRecord.model_validate_json(row[0]) for row in rows)

    def recent(self, limit: int = 50) -> tuple[DelegationRecord, ...]:
        """最近的委派，最新的在前。"""
        with self._database.connect() as connection:
            rows = connection.execute(
                "SELECT payload FROM delegations ORDER BY created_at DESC, rowid DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return tuple(DelegationRecord.model_validate_json(row[0]) for row in rows)


class SQLiteModelUsageStore:
    """按对端和本地日期累加用量，不保存内容。"""

    def __init__(self, database: _SQLiteDatabase) -> None:
        self._database = database

    def add(self, peer: NodeId, day: date, calls: int, tokens: int) -> None:
        with self._database.connect() as connection:
            connection.execute(
                """INSERT INTO model_usage(peer_node_id, day, calls, tokens) VALUES (?, ?, ?, ?)
                ON CONFLICT(peer_node_id, day) DO UPDATE SET
                    calls=model_usage.calls + excluded.calls,
                    tokens=model_usage.tokens + excluded.tokens""",
                (str(peer), day.isoformat(), calls, tokens),
            )

    def get(self, peer: NodeId, day: date) -> ModelUsageRecord:
        with self._database.connect() as connection:
            row = connection.execute(
                "SELECT calls, tokens FROM model_usage WHERE peer_node_id=? AND day=?",
                (str(peer), day.isoformat()),
            ).fetchone()
        return ModelUsageRecord(
            peer_node_id=peer, day=day, calls=row[0] if row else 0, tokens=row[1] if row else 0
        )

    def list(self, day: date | None = None) -> tuple[ModelUsageRecord, ...]:
        with self._database.connect() as connection:
            rows = connection.execute(
                """SELECT peer_node_id, day, calls, tokens FROM model_usage
                WHERE (? IS NULL OR day=?) ORDER BY peer_node_id, day""",
                (day.isoformat() if day is not None else None,) * 2,
            ).fetchall()
        return tuple(
            ModelUsageRecord(peer_node_id=NodeId(peer), day=day, calls=calls, tokens=tokens)
            for peer, day, calls, tokens in rows
        )


class SQLiteInviteStore:
    """只存令牌摘要，以单条更新消费邀请码。"""

    def __init__(self, database: _SQLiteDatabase) -> None:
        self._database = database

    def create(
        self,
        digest: bytes,
        permissions: InvitePermissions,
        created_at: datetime,
        expires_at: datetime,
    ) -> None:
        with self._database.connect() as connection:
            connection.execute(
                """INSERT INTO gateway_invites
                (token_digest, permissions_json, created_at, expires_at) VALUES (?, ?, ?, ?)""",
                (
                    digest,
                    permissions.model_dump_json(),
                    created_at.astimezone(UTC).isoformat(),
                    expires_at.astimezone(UTC).isoformat(),
                ),
            )

    def accept(self, digest: bytes, node_id: NodeId, now: datetime) -> InvitePermissions | None:
        timestamp = now.astimezone(UTC).isoformat()
        with self._database.connect() as connection:
            row = connection.execute(
                """UPDATE gateway_invites SET accepted_at=?, accepted_node_id=?
                WHERE token_digest=? AND accepted_at IS NULL AND expires_at > ?
                RETURNING permissions_json""",
                (timestamp, str(node_id), digest, timestamp),
            ).fetchone()
        return InvitePermissions.model_validate_json(row[0]) if row is not None else None


# 本机没有单独收紧某个朋友时的上限：不在本地额外限制，以"我信任的人"名单里的权限为准。
_FRIEND_CONFLICT_NOTE = "；名单里有电脑和其他朋友的电脑编号冲突，这些电脑暂不认"
_UNRESTRICTED_FRIEND = FriendPermissions(allow_model_borrowing=True, daily_quota=100_000_000)


class SQLiteTrustStore:
    """本机信任锚、签名原文和审计；名单比较与写入共用短事务。"""

    def __init__(self, database: _SQLiteDatabase) -> None:
        self._database = database

    @staticmethod
    def _read_connection(path: Path) -> sqlite3.Connection:
        """有 WAL 时读取已提交事务；没有 WAL 时避免只读预检创建辅助文件。"""
        immutable = "" if path.with_name(path.name + "-wal").exists() else "&immutable=1"
        return sqlite3.connect(path.resolve().as_uri() + "?mode=ro" + immutable, uri=True)

    @staticmethod
    def is_initialized(path: Path) -> bool:
        """确认恢复码前只读检查，旧数据库也不创建新表。"""
        if not path.exists():
            return False
        connection = SQLiteTrustStore._read_connection(path)
        try:
            return (
                connection.execute(
                    "SELECT 1 FROM sqlite_master WHERE type='table' AND name='trust_identity'"
                ).fetchone()
                is not None
                and connection.execute("SELECT 1 FROM trust_identity").fetchone() is not None
            )
        finally:
            connection.close()

    def owner_fingerprint(self) -> str | None:
        """本机记住的机主指纹；未初始化时为空。"""
        with self._database.connect() as connection:
            row = connection.execute(
                "SELECT owner_fingerprint FROM trust_identity WHERE singleton=1"
            ).fetchone()
        return row[0] if row is not None else None

    @staticmethod
    def read_roster(path: Path) -> OwnerRoster:
        """恢复确认前只读名单；保存时仍须在写锁内重查当前名单。"""
        connection = SQLiteTrustStore._read_connection(path)
        try:
            owner = connection.execute("SELECT owner_fingerprint FROM trust_identity").fetchone()
            row = connection.execute(
                "SELECT envelope_json FROM trust_documents WHERE kind=?",
                (SignaturePurpose.OWNER_ROSTER.value,),
            ).fetchone()
            if owner is None or row is None:
                raise IdentityError("本机身份记录不完整")
            return verify_owner_roster(SignedEnvelope.model_validate_json(row[0]), owner[0])
        finally:
            connection.close()

    def load(self, kind: SignaturePurpose) -> SignedEnvelope | None:
        """读取已接受的某类签名原文。"""
        with self._database.connect() as connection:
            row = connection.execute(
                "SELECT envelope_json FROM trust_documents WHERE kind=?", (kind.value,)
            ).fetchone()
        return SignedEnvelope.model_validate_json(row[0]) if row is not None else None

    def initialize(
        self,
        owner_fingerprint: str,
        roster: SignedEnvelope,
        trust_list: SignedEnvelope,
        certificate: SignedEnvelope,
        persist_keys: Callable[[], None],
        rotations: tuple[OwnerRotationStep, ...] = (),
        *,
        replace: bool = False,
    ) -> None:
        """验签后一次写入信任锚、两份名单、证书和审计；`persist_keys` 在同一事务内执行。

        `replace` 为真时，在同一个事务里先清掉本机旧身份再写入新身份，任何一步失败都整体回滚。
        """
        owner_roster = verify_owner_roster(roster, owner_fingerprint)
        people = verify_trust_list(trust_list, owner_roster.owner_public_key, owner_fingerprint)
        device = verify_device_certificate(
            certificate, owner_roster.owner_public_key, owner_fingerprint
        )
        entry = owner_roster.device(device.node_id)
        if entry is None or entry.device_public_key != device.device_public_key:
            raise VerificationError("身份签名验证失败")
        if rotations:
            self._verify_history(rotations, roster)
        with self._database.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            if replace:
                self._clear_identity(connection)
            if connection.execute("SELECT 1 FROM trust_identity").fetchone() is not None:
                raise AlreadyInitializedError("本机身份已经初始化，不能重复初始化")
            connection.execute("INSERT INTO trust_identity VALUES (1, ?)", (owner_fingerprint,))
            self._write(connection, roster, owner_roster.version)
            self._write(connection, trust_list, people.version)
            self._write(connection, certificate, owner_roster.version)
            self._record_rotations(connection, rotations, None)
            self._audit(
                connection,
                roster,
                owner_roster.version,
                tuple(str(item.node_id) for item in owner_roster.devices),
                "本机初始化",
            )
            self._audit(
                connection,
                trust_list,
                people.version,
                tuple(item.owner_fingerprint for item in people.people),
                "本机初始化",
            )
            # 先取得初始化写锁；秘密写入失败时，身份记录和审计一起回滚。
            persist_keys()

    def accept(self, envelope: SignedEnvelope, reason: str) -> None:
        """验签通过且版本严格更大时才写入，并记一条审计。"""
        with self._database.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            owner = self.owner_fingerprint()
            if owner is None:
                raise IdentityError("本机身份尚未初始化")
            if (
                envelope.purpose is SignaturePurpose.OWNER_ROSTER
                and envelope.signer_fingerprint != owner
            ):
                self._accept_friend_roster(connection, envelope, reason)
                return
            if envelope.purpose is SignaturePurpose.OWNER_ROSTER:
                roster = verify_owner_roster(envelope, owner)
                version = roster.version
                subjects = tuple(str(item.node_id) for item in roster.devices)
            elif envelope.purpose is SignaturePurpose.TRUST_LIST:
                current = self.load(SignaturePurpose.OWNER_ROSTER)
                if current is None:
                    raise IdentityError("本机身份记录不完整")
                roster = verify_owner_roster(current, owner)
                people = verify_trust_list(envelope, roster.owner_public_key, owner)
                version = people.version
                subjects = tuple(item.owner_fingerprint for item in people.people)
            else:
                raise VerificationError("身份签名验证失败")
            row = connection.execute(
                "SELECT version, envelope_json FROM trust_documents WHERE kind=?",
                (envelope.purpose.value,),
            ).fetchone()
            if row is not None and version <= row[0]:
                raise VersionRejectedError("名单版本必须大于已接受的版本")
            if row is not None:
                previous = SignedEnvelope.model_validate_json(row[1])
                if envelope.purpose is SignaturePurpose.OWNER_ROSTER:
                    old_subjects = tuple(
                        str(item.node_id) for item in verify_owner_roster(previous, owner).devices
                    )
                else:
                    old_subjects = tuple(
                        item.owner_fingerprint
                        for item in verify_trust_list(
                            previous, roster.owner_public_key, owner
                        ).people
                    )
                added = sorted(set(subjects) - set(old_subjects))
                removed = sorted(set(old_subjects) - set(subjects))
                if added:
                    reason += f"；新增 {'、'.join(added)}"
                if removed:
                    reason += f"；移除 {'、'.join(removed)}"
                subjects = tuple(sorted(set(subjects) | set(old_subjects)))
            self._write(connection, envelope, version)
            self._audit(connection, envelope, version, subjects, reason)
            if envelope.purpose is SignaturePurpose.TRUST_LIST:
                people = verify_trust_list(envelope, roster.owner_public_key, owner)
                trusted = {
                    self._resolve_friend(connection, item).owner_fingerprint
                    for item in people.people
                }
                for fingerprint, previous_version, raw in connection.execute(
                    "SELECT owner_fingerprint, version, envelope_json FROM friend_rosters"
                ).fetchall():
                    if fingerprint not in trusted:
                        previous = SignedEnvelope.model_validate_json(raw)
                        self._audit(
                            connection,
                            previous,
                            previous_version,
                            (fingerprint,),
                            "移除朋友的电脑名单",
                            action="remove",
                        )
                        connection.execute(
                            "DELETE FROM friend_rosters WHERE owner_fingerprint=?", (fingerprint,)
                        )
                        for table in ("friend_permissions", "friend_node_owners"):
                            connection.execute(
                                f"DELETE FROM {table} WHERE owner_fingerprint=?", (fingerprint,)
                            )
            if envelope.purpose is SignaturePurpose.OWNER_ROSTER:
                self._check_local_certificate(connection, roster)

    @staticmethod
    def _verify_steps(
        steps: tuple[OwnerRotationStep, ...], owner: str, recovery: str, version: int
    ) -> OwnerRoster:
        seen = {owner}
        roster: OwnerRoster | None = None
        for step in steps:
            roster = verify_owner_rotation(step.rotation, step.roster, owner, recovery, version)
            if roster.owner_fingerprint in seen:
                raise VerificationError("身份签名验证失败")
            seen.add(roster.owner_fingerprint)
            owner, recovery, version = (
                roster.owner_fingerprint,
                roster.recovery_fingerprint,
                roster.version,
            )
        assert roster is not None
        return roster

    @classmethod
    def _verify_history(
        cls, steps: tuple[OwnerRotationStep, ...], envelope: SignedEnvelope
    ) -> None:
        first = steps[0].rotation.payload
        public_key = first.get("recovery_public_key")
        previous = first.get("previous_owner_fingerprint")
        if not isinstance(public_key, str) or not isinstance(previous, str):
            raise VerificationError("身份签名验证失败")
        last = cls._verify_steps(steps, previous, key_fingerprint(public_key), 0)
        roster = verify_owner_roster(envelope, last.owner_fingerprint)
        if (
            roster.recovery_fingerprint != last.recovery_fingerprint
            or roster.version < last.version
            or (roster.version == last.version and envelope != steps[-1].roster)
        ):
            raise VerificationError("身份签名验证失败")

    @staticmethod
    def _record_rotations(
        connection: sqlite3.Connection,
        steps: tuple[OwnerRotationStep, ...],
        previous: SignedEnvelope | None,
    ) -> None:
        for step in steps:
            connection.execute(
                "INSERT INTO trust_rotations VALUES (?, ?, ?, ?)",
                (
                    step.rotation.payload["previous_owner_fingerprint"],
                    step.roster.signer_fingerprint,
                    step.model_dump_json(),
                    previous.model_dump_json() if previous is not None else None,
                ),
            )
            previous = step.roster

    def rotations(self, owner_fingerprint: str) -> tuple[OwnerRotationStep, ...]:
        """保留完整声明链，供离线电脑逐步跟上当前身份。"""
        steps: list[OwnerRotationStep] = []
        with self._database.connect() as connection:
            while row := connection.execute(
                "SELECT previous_owner_fingerprint, step_json FROM trust_rotations "
                "WHERE owner_fingerprint=?",
                (owner_fingerprint,),
            ).fetchone():
                steps.append(OwnerRotationStep.model_validate_json(row[1]))
                owner_fingerprint = row[0]
        return tuple(reversed(steps))

    @staticmethod
    def _resolve_friend(connection: sqlite3.Connection, person: TrustedPerson) -> TrustedPerson:
        while row := connection.execute(
            "SELECT step_json FROM trust_rotations WHERE previous_owner_fingerprint=?",
            (person.owner_fingerprint,),
        ).fetchone():
            step = OwnerRotationStep.model_validate_json(row[0])
            roster = verify_owner_rotation(
                step.rotation, step.roster, person.owner_fingerprint, person.recovery_fingerprint, 0
            )
            person = person.model_copy(
                update={
                    "owner_public_key": roster.owner_public_key,
                    "recovery_fingerprint": roster.recovery_fingerprint,
                }
            )
        return person

    def resolve_friend(self, person: TrustedPerson) -> TrustedPerson:
        """朋友原名单保持签名原文，本机只应用经恢复密钥验证的公钥替换。"""
        with self._database.connect() as connection:
            return self._resolve_friend(connection, person)

    def _check_local_certificate(self, connection: sqlite3.Connection, roster: OwnerRoster) -> None:
        row = connection.execute(
            "SELECT envelope_json FROM trust_documents WHERE kind=?",
            (SignaturePurpose.DEVICE_CERTIFICATE.value,),
        ).fetchone()
        if row is None:
            return
        certificate = SignedEnvelope.model_validate_json(row[0])
        issuer = roster
        if certificate.signer_fingerprint != roster.owner_fingerprint:
            previous = connection.execute(
                "SELECT previous_roster_json FROM trust_rotations "
                "WHERE previous_owner_fingerprint=?",
                (certificate.signer_fingerprint,),
            ).fetchone()
            if previous is None or previous[0] is None:
                raise VerificationError("身份签名验证失败")
            issuer = verify_owner_roster(
                SignedEnvelope.model_validate_json(previous[0]), certificate.signer_fingerprint
            )
        local = verify_device_certificate(
            certificate, issuer.owner_public_key, issuer.owner_fingerprint
        )
        device = roster.device(local.node_id)
        if device is None or device.device_public_key != local.device_public_key:
            connection.execute(
                "DELETE FROM trust_documents WHERE kind=?",
                (SignaturePurpose.DEVICE_CERTIFICATE.value,),
            )

    def rotate(
        self,
        rotations: tuple[OwnerRotationStep, ...],
        roster: SignedEnvelope,
        trust_list: SignedEnvelope | None,
        reason: str,
        persist_keys: Callable[[], None] | None = None,
    ) -> None:
        """接受换密钥声明链；同一条声明被并发重复写入时，按验证失败处理。"""
        try:
            self._rotate(rotations, roster, trust_list, reason, persist_keys)
        except sqlite3.IntegrityError:
            raise VerificationError("身份签名验证失败") from None

    def _rotate(
        self,
        rotations: tuple[OwnerRotationStep, ...],
        roster: SignedEnvelope,
        trust_list: SignedEnvelope | None,
        reason: str,
        persist_keys: Callable[[], None] | None = None,
    ) -> None:
        """写锁内验证完整声明链和新名单，再一起替换信任锚、名单与审计。"""
        if not rotations:
            raise VerificationError("身份签名验证失败")
        self._verify_history(rotations, roster)
        with self._database.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            owner = self.owner_fingerprint()
            current = self.load(SignaturePurpose.OWNER_ROSTER)
            trusted = self.load(SignaturePurpose.TRUST_LIST)
            if owner is None or current is None or trusted is None:
                raise IdentityError("本机身份记录不完整")
            own = verify_owner_roster(current, owner)
            people = verify_trust_list(trusted, own.owner_public_key, owner)
            friends = tuple(self._resolve_friend(connection, item) for item in people.people)
            if roster.signer_fingerprint in (owner, *(item.owner_fingerprint for item in friends)):
                return
            candidates: list[tuple[str, str, int, SignedEnvelope | None]] = [
                (owner, own.recovery_fingerprint, own.version, current)
            ]
            for friend in friends:
                row = connection.execute(
                    "SELECT version, envelope_json FROM friend_rosters WHERE owner_fingerprint=?",
                    (friend.owner_fingerprint,),
                ).fetchone()
                candidates.append(
                    (
                        friend.owner_fingerprint,
                        friend.recovery_fingerprint,
                        row[0] if row is not None else 0,
                        SignedEnvelope.model_validate_json(row[1]) if row is not None else None,
                    )
                )
            match = next(
                (
                    (index, candidate)
                    for index, step in enumerate(rotations)
                    for candidate in candidates
                    if step.rotation.payload.get("previous_owner_fingerprint") == candidate[0]
                ),
                None,
            )
            if match is None:
                raise VerificationError("身份签名验证失败")
            index, (previous_owner, recovery, version, previous) = match
            steps = rotations[index:]
            self._verify_steps(steps, previous_owner, recovery, version)
            for step in steps:
                if connection.execute(
                    "SELECT 1 FROM trust_rotations WHERE previous_owner_fingerprint=?",
                    (step.roster.signer_fingerprint,),
                ).fetchone():
                    raise VerificationError("身份签名验证失败")
            updated = verify_owner_roster(roster, roster.signer_fingerprint)
            is_own = previous_owner == owner
            new_people = None
            if is_own:
                if trust_list is None:
                    raise VerificationError("身份签名验证失败")
                new_people = verify_trust_list(
                    trust_list, updated.owner_public_key, updated.owner_fingerprint
                )
                if new_people.version <= people.version:
                    raise VersionRejectedError("名单版本必须大于已接受的版本")
            self._record_rotations(connection, steps, previous)
            for step in steps:
                self._audit(
                    connection,
                    step.rotation,
                    step.roster.parse(OwnerRoster, SignaturePurpose.OWNER_ROSTER).version,
                    (
                        str(step.rotation.payload["previous_owner_fingerprint"]),
                        step.roster.signer_fingerprint,
                    ),
                    reason,
                )
            if is_own:
                assert trust_list is not None and new_people is not None
                self._write(connection, roster, updated.version)
                self._write(connection, trust_list, new_people.version)
                connection.execute(
                    "UPDATE trust_identity SET owner_fingerprint=? WHERE singleton=1",
                    (updated.owner_fingerprint,),
                )
                self._check_local_certificate(connection, updated)
                self._audit(
                    connection,
                    roster,
                    updated.version,
                    tuple(sorted({str(item.node_id) for item in (*own.devices, *updated.devices)})),
                    reason,
                )
                self._audit(
                    connection,
                    trust_list,
                    new_people.version,
                    tuple(item.owner_fingerprint for item in new_people.people),
                    reason,
                )
                connection.execute("DELETE FROM owner_invites")
                connection.execute("DELETE FROM friend_invites")
            else:
                others = tuple(
                    verify_owner_roster(SignedEnvelope.model_validate_json(raw), fingerprint)
                    for fingerprint, raw in connection.execute(
                        "SELECT owner_fingerprint, envelope_json FROM friend_rosters"
                        " WHERE owner_fingerprint<>?",
                        (previous_owner,),
                    )
                )
                if roster_conflicts(updated, (own,)):
                    raise VerificationError("朋友名单里的电脑与已有电脑冲突")
                if roster_conflicts(updated, others):
                    reason += _FRIEND_CONFLICT_NOTE
                connection.execute(
                    "DELETE FROM friend_rosters WHERE owner_fingerprint=?", (previous_owner,)
                )
                for table in ("friend_permissions", "friend_node_owners"):
                    connection.execute(
                        f"UPDATE {table} SET owner_fingerprint=? WHERE owner_fingerprint=?",
                        (updated.owner_fingerprint, previous_owner),
                    )
                self._write_friend_roster(connection, roster, updated, reason)
            if persist_keys is not None:
                persist_keys()

    def exclusive(self, action: Callable[[], None]) -> None:
        """持有身份写锁执行 `action`，期间其他连接不能提交身份变更。"""
        with self._database.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            action()

    def reset(self, clear_keys: Callable[[], None]) -> None:
        """仅清理身份资料及其限制和邀请码，保留审计、旧式配对和其他运行数据。"""
        with self._database.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._clear_identity(connection)
            clear_keys()

    def _clear_identity(self, connection: sqlite3.Connection) -> None:
        """在调用方的事务里清掉身份资料，并记一条重置审计。"""
        row = connection.execute(
            "SELECT envelope_json, version FROM trust_documents WHERE kind=?",
            (SignaturePurpose.OWNER_ROSTER.value,),
        ).fetchone()
        if row is not None:
            self._audit(
                connection,
                SignedEnvelope.model_validate_json(row[0]),
                row[1],
                (),
                "本机确认重置身份",
                action="reset",
            )
        for table in (
            "trust_identity",
            "trust_documents",
            "trust_rotations",
            "owner_invites",
            "device_permissions",
            "friend_rosters",
            "friend_permissions",
            "friend_node_owners",
            "friend_invites",
            "friend_device_history",
            "own_device_history",
        ):
            connection.execute(f"DELETE FROM {table}")

    def create_invite(self, digest: bytes, expires_at: datetime) -> None:
        """加入码只存摘要，与旧式配对邀请码分表。"""
        with self._database.connect() as connection:
            connection.execute(
                "INSERT INTO owner_invites (token_digest, expires_at) VALUES (?, ?)",
                (digest, expires_at.astimezone(UTC).isoformat()),
            )

    def consume_invite(self, digest: bytes, node_id: NodeId, now: datetime) -> bool:
        """单条更新原子消费，过期或重复请求都不返回记录。"""
        timestamp = now.astimezone(UTC).isoformat()
        with self._database.connect() as connection:
            row = connection.execute(
                """UPDATE owner_invites SET accepted_at=?, accepted_node_id=?
                WHERE token_digest=? AND accepted_at IS NULL AND expires_at > ?
                RETURNING token_digest""",
                (timestamp, str(node_id), digest, timestamp),
            ).fetchone()
        return row is not None

    def create_friend_invite(self, digest: bytes, expires_at: datetime, display_name: str) -> None:
        with self._database.connect() as connection:
            connection.execute(
                "INSERT INTO friend_invites (token_digest, display_name, expires_at) "
                "VALUES (?, ?, ?)",
                (digest, display_name, expires_at.astimezone(UTC).isoformat()),
            )

    def consume_friend_invite(self, digest: bytes, node_id: NodeId, now: datetime) -> str | None:
        timestamp = now.astimezone(UTC).isoformat()
        with self._database.connect() as connection:
            row = connection.execute(
                """UPDATE friend_invites SET accepted_at=?, accepted_node_id=?
                WHERE token_digest=? AND accepted_at IS NULL AND expires_at > ?
                RETURNING display_name""",
                (timestamp, str(node_id), digest, timestamp),
            ).fetchone()
        return row[0] if row is not None else None

    def friend_rosters(self) -> tuple[SignedEnvelope, ...]:
        with self._database.connect() as connection:
            rows = connection.execute(
                "SELECT envelope_json FROM friend_rosters ORDER BY owner_fingerprint"
            ).fetchall()
        return tuple(SignedEnvelope.model_validate_json(row[0]) for row in rows)

    def _accept_friend_roster(
        self, connection: sqlite3.Connection, envelope: SignedEnvelope, reason: str
    ) -> None:
        """在同一写锁里核对配对关系、签名和版本，移除后不能重新写入。"""
        documents = {
            kind: SignedEnvelope.model_validate_json(raw)
            for kind, raw in connection.execute("SELECT kind, envelope_json FROM trust_documents")
        }
        owner = self.owner_fingerprint()
        assert owner is not None
        own = verify_owner_roster(documents[SignaturePurpose.OWNER_ROSTER.value], owner)
        trust = verify_trust_list(
            documents[SignaturePurpose.TRUST_LIST.value], own.owner_public_key, owner
        )
        friend = next(
            (
                resolved
                for item in trust.people
                if (resolved := self._resolve_friend(connection, item)).owner_fingerprint
                == envelope.signer_fingerprint
            ),
            None,
        )
        if friend is None:
            raise VerificationError("身份签名验证失败")
        roster = verify_owner_roster(envelope, friend.owner_fingerprint)
        if (
            roster.owner_public_key != friend.owner_public_key
            or roster.recovery_fingerprint != friend.recovery_fingerprint
        ):
            raise VerificationError("身份签名验证失败")
        row = connection.execute(
            "SELECT version FROM friend_rosters WHERE owner_fingerprint=?",
            (friend.owner_fingerprint,),
        ).fetchone()
        if row is not None and roster.version <= row[0]:
            raise VersionRejectedError("名单版本必须大于已接受的版本")
        others = tuple(
            verify_owner_roster(SignedEnvelope.model_validate_json(raw), fingerprint)
            for fingerprint, raw in connection.execute(
                "SELECT owner_fingerprint, envelope_json FROM friend_rosters"
                " WHERE owner_fingerprint<>?",
                (friend.owner_fingerprint,),
            )
        )
        # 和我的电脑撞号整份拒收；和其他朋友撞号照常保存（不然别人能抢先占号，冻结这个朋友的
        # 名单更新），撞号的电脑由 friend_peer 两边都不认，并在审计里记一笔。
        if roster_conflicts(roster, (own,)):
            raise VerificationError("朋友名单里的电脑与已有电脑冲突")
        if roster_conflicts(roster, others):
            reason += _FRIEND_CONFLICT_NOTE
        self._write_friend_roster(connection, envelope, roster, reason)

    def _write_friend_roster(
        self,
        connection: sqlite3.Connection,
        envelope: SignedEnvelope,
        roster: OwnerRoster,
        reason: str,
    ) -> None:
        connection.execute(
            """INSERT INTO friend_rosters VALUES (?, ?, ?)
            ON CONFLICT(owner_fingerprint) DO UPDATE SET
                version=excluded.version, envelope_json=excluded.envelope_json""",
            (roster.owner_fingerprint, roster.version, envelope.model_dump_json()),
        )
        connection.executemany(
            "INSERT OR IGNORE INTO friend_device_history VALUES (?, ?)",
            ((str(device.node_id), device.host) for device in roster.devices),
        )
        self._audit(
            connection,
            envelope,
            roster.version,
            tuple(str(device.node_id) for device in roster.devices),
            reason,
        )

    def was_own_device(self, node_id: NodeId) -> bool:
        """曾经在本机机主签发的"我的电脑"名单上的节点；移出后不能再用残留旧令牌进来。"""
        with self._database.connect() as connection:
            return (
                connection.execute(
                    "SELECT 1 FROM own_device_history WHERE node_id=?", (str(node_id),)
                ).fetchone()
                is not None
            )

    def was_friend_device(self, node_id: NodeId, host: str | None) -> bool:
        """同一地址上曾经是朋友电脑的节点；移除后不能借残留旧令牌绕过撤销。"""
        with self._database.connect() as connection:
            return (
                connection.execute(
                    "SELECT 1 FROM friend_device_history WHERE node_id=? AND host=?",
                    (str(node_id), host or ""),
                ).fetchone()
                is not None
            )

    def friend_node_owners(self) -> dict[str, str]:
        """本机手动判定的撞号节点归属：节点编号 → 朋友机主指纹。"""
        with self._database.connect() as connection:
            return dict(
                connection.execute("SELECT node_id, owner_fingerprint FROM friend_node_owners")
            )

    def assign_friend_node(
        self, node_id: NodeId, owner_fingerprint: str, others: tuple[str, ...], reason: str
    ) -> None:
        """把撞号的节点编号判给一个朋友，并在审计里记下和谁冲突、怎么处理的。"""
        with self._database.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT version, envelope_json FROM friend_rosters WHERE owner_fingerprint=?",
                (owner_fingerprint,),
            ).fetchone()
            if row is None:
                raise IdentityError("这个朋友的名单里没有这台电脑")
            version: int = row[0]
            envelope = SignedEnvelope.model_validate_json(row[1])
            if verify_owner_roster(envelope, owner_fingerprint).device(node_id) is None:
                raise IdentityError("这个朋友的名单里没有这台电脑")
            connection.execute(
                """INSERT INTO friend_node_owners VALUES (?, ?)
                ON CONFLICT(node_id) DO UPDATE SET owner_fingerprint=excluded.owner_fingerprint""",
                (str(node_id), owner_fingerprint),
            )
            self._audit(
                connection,
                envelope,
                version,
                (str(node_id), owner_fingerprint, *others),
                reason,
                action="resolve-conflict",
            )

    def friend_permissions(self, owner_fingerprint: str) -> FriendPermissions:
        with self._database.connect() as connection:
            row = connection.execute(
                "SELECT payload FROM friend_permissions WHERE owner_fingerprint=?",
                (owner_fingerprint,),
            ).fetchone()
        return FriendPermissions.model_validate_json(row[0]) if row else _UNRESTRICTED_FRIEND

    def restrict_friend(self, owner_fingerprint: str, permissions: FriendPermissions) -> None:
        with self._database.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT payload FROM friend_permissions WHERE owner_fingerprint=?",
                (owner_fingerprint,),
            ).fetchone()
            current = FriendPermissions.model_validate_json(row[0]) if row else _UNRESTRICTED_FRIEND
            if permissions.daily_quota > current.daily_quota or any(
                permissions.model_dump()[name] and not current.model_dump()[name]
                for name in ("allow_delegation", "allow_model_borrowing")
            ):
                raise IdentityError("朋友权限只能关闭或调小")
            connection.execute(
                """INSERT INTO friend_permissions VALUES (?, ?)
                ON CONFLICT(owner_fingerprint) DO UPDATE SET payload=excluded.payload""",
                (owner_fingerprint, permissions.model_dump_json()),
            )

    def device_permissions(self, node_id: NodeId) -> DevicePermissions:
        with self._database.connect() as connection:
            row = connection.execute(
                "SELECT payload FROM device_permissions WHERE node_id=?", (str(node_id),)
            ).fetchone()
        return DevicePermissions.model_validate_json(row[0]) if row else DevicePermissions()

    def restrict_device(self, node_id: NodeId, permissions: DevicePermissions) -> None:
        """在写锁里比较当前限制，不能重新打开开关或增加额度。"""
        with self._database.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT payload FROM device_permissions WHERE node_id=?", (str(node_id),)
            ).fetchone()
            current = DevicePermissions.model_validate_json(row[0]) if row else DevicePermissions()
            if permissions.daily_quota > current.daily_quota or any(
                permissions.model_dump()[name] and not current.model_dump()[name]
                for name in (
                    "allow_delegation",
                    "allow_model_borrowing",
                    "allow_proxy_repair_approval",
                )
            ):
                raise IdentityError("我的电脑权限只能关闭或调小")
            connection.execute(
                """INSERT INTO device_permissions VALUES (?, ?)
                ON CONFLICT(node_id) DO UPDATE SET payload=excluded.payload""",
                (str(node_id), permissions.model_dump_json()),
            )

    def _write(
        self, connection: sqlite3.Connection, envelope: SignedEnvelope, version: int
    ) -> None:
        connection.execute(
            """INSERT INTO trust_documents (kind, version, envelope_json) VALUES (?, ?, ?)
            ON CONFLICT(kind) DO UPDATE SET
                version=excluded.version, envelope_json=excluded.envelope_json""",
            (envelope.purpose.value, version, envelope.model_dump_json()),
        )
        if envelope.purpose is SignaturePurpose.OWNER_ROSTER:
            devices = envelope.payload.get("devices")
            connection.executemany(
                "INSERT OR IGNORE INTO own_device_history VALUES (?)",
                (
                    (str(item["node_id"]),)
                    for item in (devices if isinstance(devices, list) else [])
                    if isinstance(item, dict)
                ),
            )

    def _audit(
        self,
        connection: sqlite3.Connection,
        envelope: SignedEnvelope,
        version: int,
        subjects: tuple[str, ...],
        reason: str,
        *,
        action: str = "accept",
    ) -> None:
        record = TrustAudit(
            action=action,
            kind=envelope.purpose,
            version=version,
            signer_fingerprint=envelope.signer_fingerprint,
            subjects=subjects,
            reason=reason,
            occurred_at=datetime.now(UTC),
        )
        connection.execute(
            "INSERT INTO trust_audit (payload) VALUES (?)", (record.model_dump_json(),)
        )

    def audits(self) -> tuple[TrustAudit, ...]:
        """按发生顺序列出审计记录。"""
        with self._database.connect() as connection:
            rows = connection.execute(
                "SELECT payload FROM trust_audit ORDER BY sequence"
            ).fetchall()
        return tuple(TrustAudit.model_validate_json(row[0]) for row in rows)


@dataclass(frozen=True)
class SQLiteStores:
    """共享一个数据库文件但保持各领域独立访问对象。"""

    checkpoints: SQLiteCheckpointStore
    artifacts: SQLiteToolArtifactStore
    memories: SQLiteLongTermMemoryStore
    operations: OperationStore
    requester_operations: RequesterOperationStore
    preauthorizations: PreauthorizationStore
    repairs: RepairStore
    launch_records: LaunchRecordStore
    service_marks: SQLiteServiceMarkStore
    delegations: SQLiteDelegationStore
    model_usage: SQLiteModelUsageStore
    invites: SQLiteInviteStore
    trust: SQLiteTrustStore

    @classmethod
    def open(cls, path: Path) -> SQLiteStores:
        """初始化 schema 并返回独立存储适配器。"""
        database = _SQLiteDatabase(path)
        return cls(
            checkpoints=SQLiteCheckpointStore(database),
            artifacts=SQLiteToolArtifactStore(database),
            memories=SQLiteLongTermMemoryStore(database),
            operations=SQLiteOperationStore(database),
            requester_operations=SQLiteRequesterOperationStore(database),
            preauthorizations=SQLitePreauthorizationStore(database),
            repairs=SQLiteRepairStore(database),
            launch_records=SQLiteLaunchRecordStore(database),
            service_marks=SQLiteServiceMarkStore(database),
            delegations=SQLiteDelegationStore(database),
            model_usage=SQLiteModelUsageStore(database),
            invites=SQLiteInviteStore(database),
            trust=SQLiteTrustStore(database),
        )
