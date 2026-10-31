"""巡检记录和每天调查次数的本机 SQLite 持久化。"""

from __future__ import annotations

import sqlite3
from collections.abc import Generator
from contextlib import contextmanager
from datetime import date
from pathlib import Path

from tunnelminion.patrol.contracts import PatrolRecord


class SQLitePatrolStore:
    """每次操作使用短连接；只存在本机数据目录。"""

    def __init__(self, path: Path) -> None:
        # 第一次写入时才建库：没有巡检记录的电脑不多出一个数据文件。
        self._path = path
        self._ready = False

    def _create(self) -> None:
        if self._ready:
            return
        self._path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS patrol_services (
                    service_key TEXT PRIMARY KEY,
                    payload TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS patrol_investigations (
                    day TEXT PRIMARY KEY,
                    count INTEGER NOT NULL
                );
                """
            )
        self._ready = True

    def _exists(self) -> bool:
        if not self._ready and self._path.exists():
            self._create()
        return self._ready

    @contextmanager
    def _connect(self) -> Generator[sqlite3.Connection, None, None]:
        connection = sqlite3.connect(self._path, timeout=5)
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def put(self, record: PatrolRecord) -> None:
        self._create()
        with self._connect() as connection:
            connection.execute(
                """INSERT INTO patrol_services(service_key, payload) VALUES (?, ?)
                ON CONFLICT(service_key) DO UPDATE SET payload=excluded.payload""",
                (record.key, record.model_dump_json()),
            )

    def get(self, key: str) -> PatrolRecord | None:
        if not self._exists():
            return None
        with self._connect() as connection:
            row = connection.execute(
                "SELECT payload FROM patrol_services WHERE service_key=?", (key,)
            ).fetchone()
        return PatrolRecord.model_validate_json(row[0]) if row is not None else None

    def list_all(self) -> tuple[PatrolRecord, ...]:
        if not self._exists():
            return ()
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT payload FROM patrol_services ORDER BY service_key"
            ).fetchall()
        return tuple(PatrolRecord.model_validate_json(row[0]) for row in rows)

    def delete(self, key: str) -> None:
        if not self._exists():
            return
        with self._connect() as connection:
            connection.execute("DELETE FROM patrol_services WHERE service_key=?", (key,))

    def investigations_on(self, day: date) -> int:
        if not self._exists():
            return 0
        with self._connect() as connection:
            row = connection.execute(
                "SELECT count FROM patrol_investigations WHERE day=?", (day.isoformat(),)
            ).fetchone()
        return int(row[0]) if row is not None else 0

    def take_investigation(self, day: date, *, limit: int) -> bool:
        """在一个事务里占用当天的一次调查；用完返回 False。"""
        self._create()
        with self._connect() as connection:
            row = connection.execute(
                "SELECT count FROM patrol_investigations WHERE day=?", (day.isoformat(),)
            ).fetchone()
            count = int(row[0]) if row is not None else 0
            if count >= limit:
                return False
            connection.execute(
                """INSERT INTO patrol_investigations(day, count) VALUES (?, 1)
                ON CONFLICT(day) DO UPDATE SET count=count+1""",
                (day.isoformat(),),
            )
            # 只留最近一周，数据库不会越来越大。
            connection.execute(
                "DELETE FROM patrol_investigations WHERE day < date(?, '-7 days')",
                (day.isoformat(),),
            )
        return True
