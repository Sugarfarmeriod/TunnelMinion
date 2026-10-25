"""修复记录持久化与多个数据库连接之间的原子占用。"""

from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta, timezone
from pathlib import Path
from threading import Barrier

import pytest
from tests.repair.factories import NOW, launch_record, plan
from tests.repair.fakes import at_status

from tunnelminion.domain.identifiers import OperationId
from tunnelminion.memory.sqlite import SQLiteStores
from tunnelminion.operation.contracts import OperationStatus, transition_operation
from tunnelminion.operations import build_safe_export
from tunnelminion.repair.contracts import RepairClaimResult, RepairExecution, RepairRecord


def executing_record(*, key: str | None = None) -> RepairRecord:
    record = at_status(
        RepairRecord.planned(plan(service_key=key), actor="local-cli"), OperationStatus.AUTHORIZED
    )
    return transition_operation(
        record.model_copy(update={"execution": RepairExecution(started_at=NOW)}),
        OperationStatus.EXECUTING,
        reason="测试",
        occurred_at=NOW,
    )


def save_authorized(stores: SQLiteStores, executing: RepairRecord) -> None:
    stores.repairs.put(
        RepairRecord.model_validate(
            {
                **executing.model_dump(),
                "status": OperationStatus.AUTHORIZED,
                "transitions": executing.transitions[:-1],
                "execution": None,
            }
        )
    )


def test_roundtrip_upsert_order_and_idempotency_only_unfinished(tmp_path: Path) -> None:
    path = tmp_path / "runtime.sqlite3"
    stores = SQLiteStores.open(path)
    assert stores.repairs.get(OperationId.new()) is None
    assert stores.repairs.get_by_idempotency_key("absent") is None
    assert stores.repairs.list_all() == ()
    first = RepairRecord.planned(plan(), actor="local-cli")
    second_plan = plan().model_copy(update={"created_at": NOW + timedelta(minutes=1)})
    second = RepairRecord.planned(second_plan, actor="local-cli")
    stores.repairs.put(first)
    stores.repairs.put(second)
    reopened = SQLiteStores.open(path)
    assert reopened.repairs.list_all() == (second, first)
    assert reopened.repairs.get_by_idempotency_key(first.plan.idempotency_key) == second
    terminal = transition_operation(
        second, OperationStatus.CANCELLED, reason="测试", occurred_at=second.updated_at
    )
    stores.repairs.put(terminal)
    assert reopened.repairs.get_by_idempotency_key(first.plan.idempotency_key) == first
    succeeded = at_status(first, OperationStatus.VERIFYING)
    succeeded = transition_operation(
        succeeded, OperationStatus.SUCCEEDED, reason="测试", occurred_at=NOW
    )
    stores.repairs.put(succeeded)
    assert reopened.repairs.get_by_idempotency_key(first.plan.idempotency_key) is None
    assert reopened.repairs.get(first.plan.operation_id) == succeeded


def test_launch_records_upsert_persist_and_stay_out_of_export(tmp_path: Path) -> None:
    path = tmp_path / "runtime.sqlite3"
    stores = SQLiteStores.open(path)
    assert stores.launch_records.get("python:missing@9000") is None
    first = launch_record()
    second = launch_record(service_key="python:other.py@9000").model_copy(
        update={"recorded_at": NOW + timedelta(seconds=1)}
    )
    stores.launch_records.put(first)
    stores.launch_records.put(second)
    updated = first.model_copy(
        update={"arguments": ("changed.py",), "recorded_at": NOW + timedelta(seconds=2)}
    )
    stores.launch_records.put(updated)
    reopened = SQLiteStores.open(path)
    assert reopened.launch_records.get(first.service_key) == updated
    assert reopened.launch_records.list_all() == (updated, second)
    stores.repairs.put(RepairRecord.planned(plan(), actor="local-cli"))
    exported = build_safe_export(tmp_path)
    assert "repairs" not in exported and "launch_records" not in exported
    encoded = json.dumps(exported)
    assert "repkey_" not in encoded and first.interpreter not in encoded


def test_claim_busy_state_conflict_and_input_validation(tmp_path: Path) -> None:
    stores = SQLiteStores.open(tmp_path / "runtime.sqlite3")
    first = executing_record()
    window = NOW - timedelta(hours=1)
    assert (
        stores.repairs.claim_execution(first, rate_window_start=window, rate_limit=3)
        is RepairClaimResult.STATE_CONFLICT
    )
    save_authorized(stores, first)
    invalid_status = RepairRecord.planned(plan(), actor="local-cli")
    assert (
        stores.repairs.claim_execution(invalid_status, rate_window_start=window, rate_limit=3)
        is RepairClaimResult.STATE_CONFLICT
    )
    assert (
        stores.repairs.claim_execution(
            first.model_copy(update={"execution": None}), rate_window_start=window, rate_limit=3
        )
        is RepairClaimResult.STATE_CONFLICT
    )
    assert (
        stores.repairs.claim_execution(first, rate_window_start=window, rate_limit=3)
        is RepairClaimResult.CLAIMED
    )
    assert stores.repairs.get(first.plan.operation_id) == first
    assert (
        stores.repairs.claim_execution(first, rate_window_start=window, rate_limit=3)
        is RepairClaimResult.STATE_CONFLICT
    )
    second = executing_record(key="docker:compose:other")
    save_authorized(stores, second)
    assert (
        stores.repairs.claim_execution(second, rate_window_start=window, rate_limit=3)
        is RepairClaimResult.BUSY
    )
    current = stores.repairs.get(second.plan.operation_id)
    assert current is not None and current.status is OperationStatus.AUTHORIZED


def test_hourly_limit_counts_started_failures_and_normalizes_timezones(tmp_path: Path) -> None:
    stores = SQLiteStores.open(tmp_path / "runtime.sqlite3")
    window = NOW - timedelta(hours=1)
    for _ in range(3):
        record = executing_record()
        save_authorized(stores, record)
        assert (
            stores.repairs.claim_execution(record, rate_window_start=window, rate_limit=3)
            is RepairClaimResult.CLAIMED
        )
        record = transition_operation(
            record, OperationStatus.ROLLING_BACK, reason="测试", occurred_at=NOW
        )
        record = transition_operation(
            record, OperationStatus.CLEANUP_FAILED, reason="测试", occurred_at=NOW
        )
        stores.repairs.put(record)
    fourth = executing_record()
    save_authorized(stores, fourth)
    assert (
        stores.repairs.claim_execution(
            fourth, rate_window_start=window.astimezone(timezone(timedelta(hours=8))), rate_limit=3
        )
        is RepairClaimResult.RATE_LIMITED
    )
    assert (
        stores.repairs.claim_execution(
            fourth, rate_window_start=NOW + timedelta(microseconds=1), rate_limit=3
        )
        is RepairClaimResult.CLAIMED
    )


@pytest.mark.parametrize("same_record", [False, True])
def test_two_threads_and_connections_can_only_claim_once(tmp_path: Path, same_record: bool) -> None:
    path = tmp_path / "runtime.sqlite3"
    stores = (SQLiteStores.open(path), SQLiteStores.open(path))
    first = executing_record()
    second = first if same_record else executing_record(key="docker:compose:other")
    save_authorized(stores[0], first)
    save_authorized(stores[0], second)
    barrier = Barrier(2)

    def claim(index: int) -> RepairClaimResult:
        barrier.wait(timeout=5)
        return stores[index].repairs.claim_execution(
            (first, second)[index], rate_window_start=NOW - timedelta(hours=1), rate_limit=3
        )

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = tuple(executor.map(claim, (0, 1)))
    assert results.count(RepairClaimResult.CLAIMED) == 1
    assert (RepairClaimResult.STATE_CONFLICT if same_record else RepairClaimResult.BUSY) in results
