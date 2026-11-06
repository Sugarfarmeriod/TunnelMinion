"""incident 快照与公开调查状态的 SQLite 持久化。"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Generator
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import cast

from pydantic import JsonValue

from tunnelminion.domain.identifiers import IncidentId, SnapshotId, ThreadId
from tunnelminion.incident.contracts import (
    Incident,
    IncidentEventType,
    IncidentReport,
    IncidentStatus,
    InvestigationStopReason,
    NormalizedSnapshot,
    SnapshotDiffEvent,
)

_FORBIDDEN_FIELDS = frozenset(
    {
        "authorization",
        "api_key",
        "password",
        "private_key",
        "preshared_key",
        "response_body",
    }
)


# 保留规则：事件按最后一次观察到的时间只留最新的 500 条，调查进行中的不删；不按天数删，
# 事件少的时候，很久以前调查过的结论仍留在“最近事件”页上。
# 快照只留最新一份，以及“最近事件”页能看到的最近 50 条事件和正在调查的事件引用的快照
# （调查时读取事件发生时的服务状态）。
INCIDENT_RETENTION_MAX = 500
SNAPSHOT_REFERENCED_RECENT = 50
# 每批最多删这么多行，一批一个短事务：清理和观察、网页轮流用库，中途被关掉也只丢没提交的那一批。
PRUNE_BATCH_ROWS = 500
# 空闲页至少这么大、且占文件一半以上时才整理文件，把空间还给磁盘。
RECLAIM_MIN_FREE_BYTES = 32 * 1024 * 1024
# 旧版本按全部监听端口记事件，留下大量从没调查过的服务增减事件。升级后第一次打开时记下当时最后一条
# 事件的时间，后台清理删掉这之前仍是“等着调查”的服务增减事件，删完即撤掉这个标记。
_LEGACY_CUTOFF_KEY = "legacy_service_events_before"
_SCHEMA_VERSION = 1


class SQLiteIncidentStore:
    """使用短事务保存快照与 incident，不执行模型或远端工具。"""

    def __init__(self, path: Path) -> None:
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        with self._connection_scope() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS incident_snapshots (
                    snapshot_id TEXT PRIMARY KEY,
                    revision INTEGER NOT NULL UNIQUE,
                    observed_at TEXT NOT NULL,
                    payload TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS incidents (
                    incident_id TEXT PRIMARY KEY,
                    dedup_key TEXT NOT NULL UNIQUE,
                    status TEXT NOT NULL,
                    last_observed_at TEXT NOT NULL,
                    payload TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS incidents_recent
                    ON incidents(last_observed_at DESC);
                CREATE TABLE IF NOT EXISTS incident_threads (
                    incident_id TEXT PRIMARY KEY,
                    thread_id TEXT NOT NULL UNIQUE,
                    FOREIGN KEY(incident_id) REFERENCES incidents(incident_id)
                        ON DELETE CASCADE
                );
                CREATE TABLE IF NOT EXISTS incident_store_meta (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                """
            )
            if connection.execute("PRAGMA user_version").fetchone()[0] < _SCHEMA_VERSION:
                row = connection.execute("SELECT MAX(last_observed_at) FROM incidents").fetchone()
                if row[0] is not None:
                    connection.execute(
                        "INSERT OR IGNORE INTO incident_store_meta(key, value) VALUES (?, ?)",
                        (_LEGACY_CUTOFF_KEY, row[0]),
                    )
                connection.execute(f"PRAGMA user_version={_SCHEMA_VERSION}")

    def next_revision(self) -> int:
        """返回单机数据库中的下一个快照修订。"""
        with self._connection_scope() as connection:
            row = connection.execute(
                "SELECT COALESCE(MAX(revision), 0) + 1 FROM incident_snapshots"
            ).fetchone()
        return cast(int, row[0])

    def put_snapshot(self, snapshot: NormalizedSnapshot) -> None:
        """按 snapshot ID 幂等保存完整规范化快照。"""
        with self._connection_scope() as connection:
            connection.execute(
                """INSERT INTO incident_snapshots(
                    snapshot_id, revision, observed_at, payload
                ) VALUES (?, ?, ?, ?)
                ON CONFLICT(snapshot_id) DO UPDATE SET payload=excluded.payload""",
                (
                    str(snapshot.snapshot_id),
                    snapshot.revision,
                    snapshot.observed_at.isoformat(),
                    snapshot.model_dump_json(),
                ),
            )

    def latest_snapshot(self) -> NormalizedSnapshot | None:
        """返回最高修订快照。"""
        with self._connection_scope() as connection:
            row = connection.execute(
                "SELECT payload FROM incident_snapshots ORDER BY revision DESC LIMIT 1"
            ).fetchone()
        return NormalizedSnapshot.model_validate_json(row[0]) if row is not None else None

    def get_snapshot(self, snapshot_id: SnapshotId) -> NormalizedSnapshot | None:
        """按稳定身份读取规范化快照。"""
        with self._connection_scope() as connection:
            row = connection.execute(
                "SELECT payload FROM incident_snapshots WHERE snapshot_id=?",
                (str(snapshot_id),),
            ).fetchone()
        return NormalizedSnapshot.model_validate_json(row[0]) if row is not None else None

    def record_event(self, event: SnapshotDiffEvent) -> Incident:
        """相同去重键只更新最后观测时间，不创建第二个 incident。"""
        current = self.get_by_dedup_key(event.dedup_key)
        if current is not None:
            updated = current.model_copy(
                update={"event": event, "last_observed_at": event.observed_at}
            )
            self.put_incident(updated)
            return updated
        incident = Incident(
            incident_id=IncidentId(f"incident_{event.dedup_key.removeprefix('sha256:')[:32]}"),
            dedup_key=event.dedup_key,
            event=event,
            created_at=event.observed_at,
            last_observed_at=event.observed_at,
        )
        self.put_incident(incident)
        return incident

    def put_incident(self, incident: Incident) -> None:
        """保存完整公开状态，并在写入前检查秘密边界。"""
        incident.assert_no_secret_material()
        with self._connection_scope() as connection:
            connection.execute(
                """INSERT INTO incidents(
                    incident_id, dedup_key, status, last_observed_at, payload
                ) VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(incident_id) DO UPDATE SET
                    status=excluded.status,
                    last_observed_at=excluded.last_observed_at,
                    payload=excluded.payload""",
                (
                    str(incident.incident_id),
                    incident.dedup_key,
                    incident.status.value,
                    incident.last_observed_at.isoformat(),
                    incident.model_dump_json(),
                ),
            )

    def get(self, incident_id: IncidentId) -> Incident | None:
        """按稳定身份读取 incident。"""
        with self._connection_scope() as connection:
            row = connection.execute(
                "SELECT payload FROM incidents WHERE incident_id=?",
                (str(incident_id),),
            ).fetchone()
        return Incident.model_validate_json(row[0]) if row is not None else None

    def get_by_dedup_key(self, dedup_key: str) -> Incident | None:
        """读取相同对象、事件类型和基线修订的 incident。"""
        with self._connection_scope() as connection:
            row = connection.execute(
                "SELECT payload FROM incidents WHERE dedup_key=?",
                (dedup_key,),
            ).fetchone()
        return Incident.model_validate_json(row[0]) if row is not None else None

    def list_recent(self, *, limit: int = 50) -> tuple[Incident, ...]:
        """按最后观测时间返回有界 incident 列表。"""
        if not 1 <= limit <= 100:
            raise ValueError("incident 列表上限必须位于 1 到 100")
        with self._connection_scope() as connection:
            rows = connection.execute(
                "SELECT payload FROM incidents ORDER BY last_observed_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return tuple(Incident.model_validate_json(row[0]) for row in rows)

    def thread_for(self, incident_id: IncidentId) -> ThreadId | None:
        """读取 incident 已绑定的上下文追问线程。"""
        with self._connection_scope() as connection:
            row = connection.execute(
                "SELECT thread_id FROM incident_threads WHERE incident_id=?",
                (str(incident_id),),
            ).fetchone()
        return ThreadId(row[0]) if row is not None else None

    def bind_thread(self, incident_id: IncidentId, thread_id: ThreadId) -> None:
        """每个 incident 只绑定一个现有 conversation thread。"""
        if self.get(incident_id) is None:
            raise KeyError("incident_not_found")
        current = self.thread_for(incident_id)
        if current is not None and current != thread_id:
            raise ValueError("incident 已绑定另一追问线程")
        with self._connection_scope() as connection:
            connection.execute(
                """INSERT INTO incident_threads(incident_id, thread_id) VALUES (?, ?)
                ON CONFLICT(incident_id) DO NOTHING""",
                (str(incident_id), str(thread_id)),
            )

    def recover_interrupted(self, *, at: datetime) -> tuple[Incident, ...]:
        """把重启前运行中的调查标记为中断；不自动重放任何调用。"""
        if at.tzinfo is None:
            raise ValueError("恢复时间必须包含时区")
        values: list[Incident] = []
        for incident in self._list_by_status(IncidentStatus.INVESTIGATING):
            report = incident.report or IncidentReport(
                unknowns=("调查在 Runtime 重启时中断",),
                stop_reason=InvestigationStopReason.INTERRUPTED,
            )
            updated = incident.transition(
                IncidentStatus.INTERRUPTED,
                at=at,
                report=report,
            )
            self.put_incident(updated)
            values.append(updated)
        return tuple(values)

    def assert_no_secret_material(self) -> None:
        """复核数据库 payload 不包含禁止字段。"""
        with self._connection_scope() as connection:
            # 逐行读取，不把整库 payload 一次读进内存。
            rows = connection.execute(
                "SELECT payload FROM incident_snapshots UNION ALL SELECT payload FROM incidents"
            )
            for row in rows:
                value = cast(JsonValue, json.loads(cast(str, row[0])))
                if _contains_forbidden_key(value):
                    raise ValueError("incident 数据库包含禁止字段")

    def prune_batch(self, *, batch: int = PRUNE_BATCH_ROWS) -> int:
        """按保留规则删除一批事件或快照，返回删除行数；返回 0 表示已经清理干净。

        依次处理旧版本留下的服务增减事件、排在条数上限之外的事件、无人引用的快照；
        每次调用只处理排在最前、仍有可删行的一类，最多 `batch` 行，在一个短事务里提交。
        """
        if not 1 <= batch <= 10_000:
            raise ValueError("每批清理行数必须位于 1 到 10000")
        with self._connection_scope() as connection:
            deleted = _prune_legacy_events(connection, batch)
            if deleted == 0:
                deleted = _prune_overflow_events(connection, batch)
            if deleted == 0:
                return _prune_snapshots(connection, batch)
            # 连接未开启外键约束，追问线程绑定随事件一起删除。
            connection.execute(
                "DELETE FROM incident_threads "
                "WHERE incident_id NOT IN (SELECT incident_id FROM incidents)"
            )
        return deleted

    def reclaim_space(self) -> bool:
        """空闲页足够多时整理数据库文件，把空间还给磁盘；返回是否整理过。

        `VACUUM` 本身是一个事务，中途进程退出时数据库保持整理前的样子。
        """
        connection = self._connect()
        try:
            page_size = cast(int, connection.execute("PRAGMA page_size").fetchone()[0])
            pages = cast(int, connection.execute("PRAGMA page_count").fetchone()[0])
            free = cast(int, connection.execute("PRAGMA freelist_count").fetchone()[0])
            vacuum = free * page_size >= RECLAIM_MIN_FREE_BYTES and free * 2 >= pages
            if vacuum:
                connection.execute("VACUUM")
            # 大批删除会把预写日志撑大；无论是否整理都把它收回。
            connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            return vacuum
        finally:
            connection.close()

    def _list_by_status(self, status: IncidentStatus) -> tuple[Incident, ...]:
        with self._connection_scope() as connection:
            rows = connection.execute(
                "SELECT payload FROM incidents WHERE status=? ORDER BY rowid",
                (status.value,),
            ).fetchall()
        return tuple(Incident.model_validate_json(row[0]) for row in rows)

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=5)
        connection.execute("PRAGMA journal_mode=WAL")
        return connection

    @contextmanager
    def _connection_scope(self) -> Generator[sqlite3.Connection, None, None]:
        connection = self._connect()
        try:
            with connection:
                yield connection
        finally:
            connection.close()


def _prune_legacy_events(connection: sqlite3.Connection, batch: int) -> int:
    row = connection.execute(
        "SELECT value FROM incident_store_meta WHERE key=?", (_LEGACY_CUTOFF_KEY,)
    ).fetchone()
    if row is None:
        return 0
    deleted = connection.execute(
        """DELETE FROM incidents WHERE incident_id IN (
            SELECT incident_id FROM incidents
            WHERE status=? AND last_observed_at <= ?
              AND json_extract(payload, '$.event.event_type') IN (?, ?)
            LIMIT ?
        )""",
        (
            IncidentStatus.PENDING.value,
            row[0],
            IncidentEventType.SERVICE_ADDED.value,
            IncidentEventType.SERVICE_REMOVED.value,
            batch,
        ),
    ).rowcount
    if deleted == 0:
        connection.execute("DELETE FROM incident_store_meta WHERE key=?", (_LEGACY_CUTOFF_KEY,))
    return deleted


def _prune_overflow_events(connection: sqlite3.Connection, batch: int) -> int:
    """删除排在条数上限之外的事件，先删最旧的；调查进行中的不删。"""
    return connection.execute(
        """DELETE FROM incidents WHERE incident_id IN (
            SELECT incident_id FROM incidents
            WHERE status != ? AND incident_id NOT IN (
                SELECT incident_id FROM incidents ORDER BY last_observed_at DESC LIMIT ?
            )
            ORDER BY last_observed_at LIMIT ?
        )""",
        (IncidentStatus.INVESTIGATING.value, INCIDENT_RETENTION_MAX, batch),
    ).rowcount


def _prune_snapshots(connection: sqlite3.Connection, batch: int) -> int:
    """删除最旧的无人引用快照；最新一份总是保留，作为重启后的比较基线。

    语句以 DELETE 开头，`rowcount` 才是实际删除行数。
    """
    return connection.execute(
        """DELETE FROM incident_snapshots WHERE snapshot_id IN (
            WITH kept(payload) AS (
                SELECT payload FROM (
                    SELECT payload FROM incidents ORDER BY last_observed_at DESC LIMIT ?
                )
                UNION ALL
                SELECT payload FROM incidents WHERE status=?
            ),
            refs(snapshot_id) AS (
                SELECT json_extract(payload, '$.event.baseline_snapshot_id') FROM kept
                UNION
                SELECT json_extract(payload, '$.event.current_snapshot_id') FROM kept
            )
            SELECT snapshot_id FROM incident_snapshots
            WHERE revision < (SELECT MAX(revision) FROM incident_snapshots)
              AND snapshot_id NOT IN (SELECT snapshot_id FROM refs WHERE snapshot_id IS NOT NULL)
            ORDER BY revision LIMIT ?
        )""",
        (SNAPSHOT_REFERENCED_RECENT, IncidentStatus.INVESTIGATING.value, batch),
    ).rowcount


def _contains_forbidden_key(value: JsonValue) -> bool:
    if isinstance(value, dict):
        return any(
            str(key).lower() in _FORBIDDEN_FIELDS or _contains_forbidden_key(item)
            for key, item in value.items()
        )
    if isinstance(value, list):
        return any(_contains_forbidden_key(item) for item in value)
    return False
