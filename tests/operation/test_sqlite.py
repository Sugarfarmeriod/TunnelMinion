"""操作聚合的 SQLite 持久化与兼容初始化测试。"""

from __future__ import annotations

import sqlite3
from datetime import timedelta
from pathlib import Path

import pytest
from tests.operation.factories import NOW, full_record, plan

from tunnelminion.memory.sqlite import SQLiteStores
from tunnelminion.operation.contracts import (
    OperationRecord,
    OperationStatus,
    OperationStore,
    transition_operation,
)


def test_operation_store_persists_indexes_children_and_summaries(tmp_path: Path) -> None:
    path = tmp_path / "runtime.sqlite3"
    store: OperationStore = SQLiteStores.open(path).operations
    missing = plan()
    assert store.get(missing.operation_id) is None
    assert store.get_by_idempotency_key(missing.idempotency_key) is None

    record = full_record()
    store.put(record)
    assert store.get(record.plan.operation_id) == record
    assert store.get_by_idempotency_key(record.plan.idempotency_key) == record
    assert store.list_all() == (record,)
    assert store.list_unfinished() == (record,)
    assert store.list_summaries()[0].operation_id == record.plan.operation_id

    with sqlite3.connect(path) as connection:
        counts = {
            table: connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            for table in (
                "operations",
                "operation_authorizations",
                "operation_leases",
                "operation_resources",
                "operation_verifications",
                "operation_cleanups",
                "operation_transitions",
            )
        }
    assert counts == {
        "operations": 1,
        "operation_authorizations": 1,
        "operation_leases": 1,
        "operation_resources": 1,
        "operation_verifications": 1,
        "operation_cleanups": 1,
        "operation_transitions": 1,
    }

    reopened = SQLiteStores.open(path).operations
    terminal = transition_operation(
        record,
        OperationStatus.CANCELLED,
        reason="用户取消",
        occurred_at=NOW + timedelta(minutes=6),
    )
    reopened.put(terminal)
    assert reopened.list_unfinished() == ()


def test_operation_store_update_removes_stale_child_rows(tmp_path: Path) -> None:
    path = tmp_path / "runtime.sqlite3"
    store = SQLiteStores.open(path).operations
    record = full_record()
    store.put(record)
    minimal = record.model_copy(
        update={
            "authorization": None,
            "lease": None,
            "resources": (),
            "verifications": (),
            "cleanup": None,
        }
    )
    store.put(minimal)

    with sqlite3.connect(path) as connection:
        for table in (
            "operation_authorizations",
            "operation_leases",
            "operation_resources",
            "operation_verifications",
            "operation_cleanups",
        ):
            assert connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] == 0


def test_idempotency_index_rejects_second_operation_for_same_plan(tmp_path: Path) -> None:
    store = SQLiteStores.open(tmp_path / "runtime.sqlite3").operations
    first_plan = plan()
    first = OperationRecord.planned(first_plan)
    store.put(first)
    duplicate_plan = first_plan.model_copy(update={"operation_id": plan().operation_id})
    duplicate = OperationRecord.planned(duplicate_plan)

    with pytest.raises(sqlite3.IntegrityError):
        store.put(duplicate)
    assert store.get_by_idempotency_key(first_plan.idempotency_key) == first


def test_schema_initialization_is_repeatable_and_legacy_data_survives_downgrade(
    tmp_path: Path,
) -> None:
    path = tmp_path / "legacy.sqlite3"
    with sqlite3.connect(path) as connection:
        connection.execute(
            "CREATE TABLE checkpoints(run_id TEXT PRIMARY KEY, thread_id TEXT, payload TEXT)"
        )
        connection.execute(
            "INSERT INTO checkpoints(run_id, thread_id, payload) VALUES ('old', 'thread', '{}')"
        )

    SQLiteStores.open(path)
    SQLiteStores.open(path)
    with sqlite3.connect(path) as connection:
        assert connection.execute("SELECT payload FROM checkpoints").fetchone()[0] == "{}"
        for table in (
            "operation_transitions",
            "operation_cleanups",
            "operation_verifications",
            "operation_resources",
            "operation_leases",
            "operation_authorizations",
            "operations",
        ):
            connection.execute(f"DROP TABLE {table}")
        assert connection.execute("SELECT payload FROM checkpoints").fetchone()[0] == "{}"
