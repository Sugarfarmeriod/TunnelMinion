"""网页和命令行共用的本机修复门面。"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path

from tunnelminion.domain.identifiers import AuthorizationId, NodeId, OperationId
from tunnelminion.domain.service_marks import ServiceMark
from tunnelminion.operation.contracts import OperationStatus, Preauthorization
from tunnelminion.operation.policy import AuthorizationService, OperationPolicy
from tunnelminion.repair.contracts import (
    REPAIR_AUTHORIZATION_SECONDS,
    REPAIR_TERMINAL_STATUSES,
    ContainerRuntime,
    HostInspector,
    LaunchRecordStore,
    LocalVerifier,
    ProcessLauncher,
    RepairAuditAction,
    RepairKind,
    RepairOrigin,
    RepairRecord,
    RepairStore,
)
from tunnelminion.repair.eligibility import AUTHORIZATION_EXPIRED_ERROR
from tunnelminion.repair.planning import RepairPlanner
from tunnelminion.repair.workflow import RepairWorkflow
from tunnelminion.tools.registry import ToolRegistry


class NoPreauthorizations:
    def put(self, authorization: Preauthorization) -> None:
        raise ValueError("preauthorization")

    def get(self, authorization_id: AuthorizationId) -> None:
        return None

    def list_all(self) -> tuple[Preauthorization, ...]:
        return ()

    def list_active(self, *, at: datetime) -> tuple[Preauthorization, ...]:
        return ()


class RepairService:
    def __init__(
        self,
        planner: RepairPlanner,
        workflow: RepairWorkflow,
        store: RepairStore,
        authorization: AuthorizationService[RepairRecord],
        clock: Callable[[], datetime],
        containers: ContainerRuntime,
        host: HostInspector,
    ) -> None:
        self._planner = planner
        self._workflow = workflow
        self._store = store
        self._authorization = authorization
        self._clock = clock
        self.containers = containers
        self.host = host
        self._result_handler: Callable[[RepairRecord], None] | None = None

    def set_result_handler(self, handler: Callable[[RepairRecord], None]) -> None:
        self._result_handler = handler
        self.list()

    def _publish_results(self) -> None:
        if self._result_handler is not None:
            for record in self._store.list_all():
                if record.status in REPAIR_TERMINAL_STATUSES and record.plan.origin.thread_id:
                    self._result_handler(record)

    async def propose(
        self,
        service_key: str,
        kind: RepairKind,
        reason: str,
        origin: RepairOrigin,
        *,
        actor: str,
    ) -> RepairRecord:
        plan = await self._planner.propose(service_key, kind, reason, origin)
        return self._authorization.submit(RepairRecord.planned(plan, actor=actor), at=self._clock())

    def list(self) -> tuple[RepairRecord, ...]:
        now = self._clock()
        self.expire_due(now)
        self._workflow.recover_interrupted(now)
        self._publish_results()
        return self._store.list_all()

    def pending_repair_ids(self) -> tuple[OperationId, ...]:
        """只读待批准且未过期的修复标识。"""
        now = self._clock()
        return tuple(
            record.plan.operation_id
            for record in self._store.list_all()
            if record.status is OperationStatus.AWAITING_AUTHORIZATION
            and record.plan.created_at + timedelta(seconds=REPAIR_AUTHORIZATION_SECONDS) > now
        )

    def get(self, operation_id: OperationId) -> RepairRecord | None:
        now = self._clock()
        self.expire_due(now)
        self._workflow.recover_interrupted(now)
        self._publish_results()
        return self._store.get(operation_id)

    def expire_due(self, now: datetime) -> None:
        for record in self._store.list_all():
            if (
                record.status is OperationStatus.AWAITING_AUTHORIZATION
                and record.plan.created_at + timedelta(seconds=REPAIR_AUTHORIZATION_SECONDS) <= now
            ):
                record = self._authorization.expire_once(record.plan.operation_id, expired_at=now)
                record = record.model_copy(update={"error": AUTHORIZATION_EXPIRED_ERROR})
                record = record.with_event(
                    RepairAuditAction.EXPIRED,
                    AUTHORIZATION_EXPIRED_ERROR.message,
                    actor="repair-workflow",
                    at=now,
                )
                self._store.put(record)
        self._publish_results()

    def _waiting(self, operation_id: OperationId) -> RepairRecord:
        record = self._store.get(operation_id)
        if record is None:
            raise KeyError(operation_id)
        if record.status is not OperationStatus.AWAITING_AUTHORIZATION:
            raise ValueError("这个修复现在不等批准")
        return record

    def approve(self, operation_id: OperationId, *, operator: str) -> RepairRecord:
        now = self._clock()
        self.expire_due(now)
        self._waiting(operation_id)
        record = self._authorization.approve_once(
            operation_id,
            operator=operator,
            decided_at=now,
            expires_at=now + timedelta(seconds=REPAIR_AUTHORIZATION_SECONDS),
            local_control=True,
        )
        record = record.with_event(
            RepairAuditAction.APPROVED, f"{operator} 批准了修复。", actor=operator, at=now
        )
        self._store.put(record)
        return record

    def reject(
        self, operation_id: OperationId, *, operator: str, reason: str | None
    ) -> RepairRecord:
        now = self._clock()
        self.expire_due(now)
        self._waiting(operation_id)
        reason = (reason or "").strip() or "主人选择先不修。"
        record = self._authorization.reject_once(
            operation_id, operator=operator, reason=reason, decided_at=now, local_control=True
        )
        record = record.with_event(RepairAuditAction.REJECTED, reason, actor=operator, at=now)
        self._store.put(record)
        self._publish_results()
        return record

    async def execute(self, operation_id: OperationId) -> RepairRecord:
        record = await self._workflow.execute(operation_id)
        self._publish_results()
        return record


def build_repair_service(
    *,
    node_id: NodeId,
    data_dir: Path,
    store: RepairStore,
    launch_records: LaunchRecordStore,
    registry: ToolRegistry,
    marks: Callable[[], Mapping[str, ServiceMark]],
    containers: ContainerRuntime,
    launcher: ProcessLauncher,
    host: HostInspector,
    verifier: LocalVerifier,
    clock: Callable[[], datetime] | None = None,
) -> RepairService:
    clock = clock or (lambda: datetime.now(UTC))
    preauthorizations = NoPreauthorizations()
    return RepairService(
        RepairPlanner(node_id, marks, launch_records, containers, host, clock),
        RepairWorkflow(
            store, containers, launcher, host, verifier, marks, data_dir / "repair-logs", clock
        ),
        store,
        AuthorizationService(
            store, preauthorizations, OperationPolicy(registry, preauthorizations)
        ),
        clock,
        containers,
        host,
    )
