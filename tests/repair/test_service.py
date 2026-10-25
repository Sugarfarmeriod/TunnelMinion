"""网页和命令行共用的批准、过期及幂等行为。"""

from __future__ import annotations

import asyncio
from datetime import timedelta
from pathlib import Path

import pytest
from tests.repair.factories import NODE, NOW, plan
from tests.repair.fakes import RepairHarness, at_status

from tunnelminion.domain.identifiers import AuthorizationId, OperationId
from tunnelminion.operation.contracts import OperationStatus, Preauthorization
from tunnelminion.repair.contracts import (
    RepairAuditAction,
    RepairErrorCode,
    RepairKind,
    RepairOrigin,
    RepairOriginKind,
    RepairRecord,
)
from tunnelminion.repair.eligibility import RepairRefusal
from tunnelminion.repair.service import NoPreauthorizations, build_repair_service
from tunnelminion.tools.registry import ToolRegistry

ORIGIN = RepairOrigin(kind=RepairOriginKind.LOCAL_CLI)


def test_propose_deduplicates_pending_target_and_requires_local_approval(tmp_path: Path) -> None:
    h = RepairHarness(tmp_path)
    record = asyncio.run(
        h.service.propose(
            "docker:compose:photos",
            RepairKind.RESTART_CONTAINERS,
            "退出了",
            ORIGIN,
            actor="local-cli",
        )
    )
    assert record.status is OperationStatus.AWAITING_AUTHORIZATION
    same = asyncio.run(
        h.service.propose(
            "docker:compose:photos",
            RepairKind.RESTART_CONTAINERS,
            "别的理由",
            ORIGIN,
            actor="another",
        )
    )
    assert same == record
    assert h.service.list() == (record,)
    assert h.service.get(record.plan.operation_id) == record
    with pytest.raises(PermissionError):
        h.authorization.approve_once(
            record.plan.operation_id,
            operator="remote",
            decided_at=NOW,
            expires_at=NOW + timedelta(minutes=10),
            local_control=False,
        )
    approved = h.service.approve(record.plan.operation_id, operator="local-cli")
    assert approved.status is OperationStatus.AUTHORIZED
    assert (
        approved.authorization is not None
        and approved.authorization.expires_at == NOW + timedelta(minutes=10)
    )
    assert approved.audit[-1].detail == "local-cli 批准了修复。"
    with pytest.raises(ValueError, match="这个修复现在不等批准"):
        h.service.approve(record.plan.operation_id, operator="local-cli")
    assert not h.containers.calls
    result = asyncio.run(h.service.execute(record.plan.operation_id))
    assert result.status is OperationStatus.SUCCEEDED
    assert asyncio.run(h.service.execute(record.plan.operation_id)) == result
    assert len(h.containers.calls) == 1
    fresh = asyncio.run(
        h.service.propose(
            "docker:compose:photos",
            RepairKind.RESTART_CONTAINERS,
            "又退出了",
            ORIGIN,
            actor="local-cli",
        )
    )
    assert fresh.plan.operation_id != record.plan.operation_id


def test_propose_refusal_passes_through(tmp_path: Path) -> None:
    h = RepairHarness(tmp_path)
    with pytest.raises(RepairRefusal) as caught:
        asyncio.run(
            h.service.propose(
                "program:svc", RepairKind.RESTART_CONTAINERS, "退出了", ORIGIN, actor="local-cli"
            )
        )
    assert caught.value.error.code is RepairErrorCode.NOT_ELIGIBLE
    assert not h.store.list_all()


@pytest.mark.parametrize("access", ["get", "list", "approve", "reject"])
def test_waiting_expires_at_ten_minutes(tmp_path: Path, access: str) -> None:
    h = RepairHarness(tmp_path)
    record = h.authorization.submit(RepairRecord.planned(plan(), actor="local-cli"), at=NOW)
    h.clock.now += timedelta(minutes=10) - timedelta(microseconds=1)
    h.service.expire_due(h.clock())
    assert h.store.get(record.plan.operation_id) == record
    h.clock.now += timedelta(microseconds=1)
    if access == "get":
        h.service.get(record.plan.operation_id)
    elif access == "list":
        h.service.list()
    elif access == "approve":
        with pytest.raises(ValueError):
            h.service.approve(record.plan.operation_id, operator="local-cli")
    else:
        with pytest.raises(ValueError):
            h.service.reject(record.plan.operation_id, operator="local-cli", reason=None)
    expired = h.store.get(record.plan.operation_id)
    assert expired is not None and expired.status is OperationStatus.AUTHORIZATION_EXPIRED
    assert expired.error is not None and expired.error.code is RepairErrorCode.AUTHORIZATION_EXPIRED
    assert expired.audit[-1].action is RepairAuditAction.EXPIRED
    assert asyncio.run(h.service.execute(record.plan.operation_id)) == expired
    assert not h.containers.calls


@pytest.mark.parametrize("reason", [None, "  ", "主人选择先不修。", "等会儿再说"])
def test_reject_never_executes(tmp_path: Path, reason: str | None) -> None:
    h = RepairHarness(tmp_path)
    waiting = h.authorization.submit(RepairRecord.planned(plan(), actor="local-cli"), at=NOW)
    record = h.service.reject(waiting.plan.operation_id, operator="local-cli", reason=reason)
    assert record.status is OperationStatus.REJECTED
    assert record.authorization is not None
    assert record.authorization.basis == ((reason or "").strip() or "主人选择先不修。")
    assert record.audit[-1].action is RepairAuditAction.REJECTED
    assert asyncio.run(h.service.execute(record.plan.operation_id)) == record
    assert not h.containers.queries and not h.host.calls and not h.launcher.calls
    with pytest.raises(ValueError):
        h.service.reject(waiting.plan.operation_id, operator="local-cli", reason=None)


def test_missing_and_interrupted_are_handled_by_reads(tmp_path: Path) -> None:
    h = RepairHarness(tmp_path)
    assert h.service.get(OperationId.new()) is None
    with pytest.raises(KeyError):
        h.service.approve(OperationId.new(), operator="local-cli")
    with pytest.raises(KeyError):
        h.service.reject(OperationId.new(), operator="local-cli", reason=None)
    stale = at_status(RepairRecord.planned(plan(), actor="local-cli"), OperationStatus.EXECUTING)
    h.store.put(stale)
    h.clock.now += timedelta(minutes=16)
    result = h.service.get(stale.plan.operation_id)
    assert result is not None and result.error is not None
    assert result.error.code is RepairErrorCode.INTERRUPTED


@pytest.mark.parametrize("registered", [False, True])
def test_builder_requires_registered_tools(tmp_path: Path, registered: bool) -> None:
    h = RepairHarness(tmp_path)
    service = build_repair_service(
        node_id=NODE,
        data_dir=tmp_path,
        store=h.store,
        launch_records=h.launch_records,
        registry=h.registry if registered else ToolRegistry(),
        marks=lambda: h.marks,
        containers=h.containers,
        launcher=h.launcher,
        host=h.host,
        verifier=h.verifier,
        clock=h.clock if registered else None,
    )
    record = asyncio.run(
        service.propose(
            "docker:compose:photos",
            RepairKind.RESTART_CONTAINERS,
            "退出了",
            ORIGIN,
            actor="local-cli",
        )
    )
    assert record.status is (
        OperationStatus.AWAITING_AUTHORIZATION if registered else OperationStatus.CANCELLED
    )
    if registered:
        service.approve(record.plan.operation_id, operator="local-cli")
        result = asyncio.run(service.execute(record.plan.operation_id))
        assert result.status is OperationStatus.SUCCEEDED
    assert not h.launcher.calls


def test_empty_preauthorizations_cannot_grant_persistent_approval() -> None:
    empty = NoPreauthorizations()
    assert empty.get(AuthorizationId.new()) is None
    assert empty.list_all() == ()
    assert empty.list_active(at=NOW) == ()
    authorization = Preauthorization.model_construct()
    with pytest.raises(ValueError, match="preauthorization"):
        empty.put(authorization)
