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

from tunnelminion.domain.identifiers import IncidentId
from tunnelminion.incident.contracts import (
    Incident,
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
                """
            )

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
            rows = connection.execute(
                "SELECT payload FROM incident_snapshots UNION ALL SELECT payload FROM incidents"
            ).fetchall()
        for row in rows:
            value = cast(JsonValue, json.loads(cast(str, row[0])))
            if _contains_forbidden_key(value):
                raise ValueError("incident 数据库包含禁止字段")

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


def _contains_forbidden_key(value: JsonValue) -> bool:
    if isinstance(value, dict):
        return any(
            str(key).lower() in _FORBIDDEN_FIELDS or _contains_forbidden_key(item)
            for key, item in value.items()
        )
    if isinstance(value, list):
        return any(_contains_forbidden_key(item) for item in value)
    return False
