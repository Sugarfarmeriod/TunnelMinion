"""网页和命令行共用的本机修复门面。"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
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
    LaunchAgentRuntime,
    LaunchRecordStore,
    LocalVerifier,
    ProcessLauncher,
    RepairAuditAction,
    RepairKind,
    RepairOrigin,
    RepairRecord,
    RepairStore,
    WindowsServiceRuntime,
)
from tunnelminion.repair.eligibility import AUTHORIZATION_EXPIRED_ERROR
from tunnelminion.repair.launch_agents import UnsupportedLaunchAgents
from tunnelminion.repair.planning import RepairPlanner
from tunnelminion.repair.windows_services import UnsupportedWindowsServices
from tunnelminion.repair.workflow import RepairWorkflow
from tunnelminion.tools.registry import ToolRegistry


@dataclass(frozen=True)
class ProxyRepairApprover:
    """由本机 Gateway 认证并从本机配置解析的代批准方。"""

    node_id: NodeId
    display_name: str


@dataclass(frozen=True)
class OwnerPreapproval:
    """主人在本机为某个服务打开的"挂了可以自动修"，由巡检代主人批准一次。"""

    enabled_on: date
    # 巡检确认的原因，例如"容器已退出"。
    reason: str


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
        launch_agents: LaunchAgentRuntime | None = None,
        windows_services: WindowsServiceRuntime | None = None,
    ) -> None:
        self._planner = planner
        self._workflow = workflow
        self._store = store
        self._authorization = authorization
        self._clock = clock
        self.containers = containers
        self.host = host
        self.launch_agents = launch_agents or UnsupportedLaunchAgents()
        self.windows_services = windows_services or UnsupportedWindowsServices()
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

    def approve(
        self,
        operation_id: OperationId,
        *,
        operator: str,
        proxy_approver: ProxyRepairApprover | None = None,
    ) -> RepairRecord:
        now = self._clock()
        self.expire_due(now)
        self._waiting(operation_id)
        if proxy_approver is not None:
            operator = f"peer:{proxy_approver.node_id}"
        record = self._authorization.approve_once(
            operation_id,
            operator=operator,
            decided_at=now,
            expires_at=now + timedelta(seconds=REPAIR_AUTHORIZATION_SECONDS),
            local_control=True,
            basis=(
                "目标节点已授权的对端代为批准"
                if proxy_approver is not None
                else "目标节点本地用户逐次批准"
            ),
        )
        record = record.with_event(
            RepairAuditAction.APPROVED,
            (
                f"由 {proxy_approver.display_name}（{proxy_approver.node_id}）代为批准了修复。"
                if proxy_approver is not None
                else f"{operator} 批准了修复。"
            ),
            actor=operator,
            at=now,
        )
        self._store.put(record)
        return record

    def approve_preauthorized(
        self, operation_id: OperationId, *, preapproval: OwnerPreapproval
    ) -> RepairRecord:
        """按主人预先允许代为批准；执行前核对、执行和验证与人工批准完全一样。"""
        now = self._clock()
        self.expire_due(now)
        self._waiting(operation_id)
        day = preapproval.enabled_on
        record = self._authorization.approve_once(
            operation_id,
            operator="patrol",
            decided_at=now,
            expires_at=now + timedelta(seconds=REPAIR_AUTHORIZATION_SECONDS),
            local_control=True,
            basis=f"按主人 {day.isoformat()} 的预先允许自动执行",
        )
        record = record.with_event(
            RepairAuditAction.APPROVED,
            f"按主人 {day.year}年{day.month}月{day.day}日 打开的“挂了可以自动修”自动执行"
            f"（巡检确认：{preapproval.reason}）。",
            actor="patrol",
            at=now,
        )
        self._store.put(record)
        return record

    def reject(
        self,
        operation_id: OperationId,
        *,
        operator: str,
        reason: str | None,
        proxy_approver: ProxyRepairApprover | None = None,
    ) -> RepairRecord:
        now = self._clock()
        self.expire_due(now)
        self._waiting(operation_id)
        reason = (reason or "").strip() or "主人选择先不修。"
        if proxy_approver is not None:
            operator = f"peer:{proxy_approver.node_id}"
            reason = f"{proxy_approver.display_name} 代为选择先不修。"
        record = self._authorization.reject_once(
            operation_id,
            operator=operator,
            reason=reason,
            decided_at=now,
            local_control=True,
            basis="目标节点已授权的对端代为批准" if proxy_approver is not None else None,
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
    launch_agents: LaunchAgentRuntime | None = None,
    windows_services: WindowsServiceRuntime | None = None,
    is_stuck: Callable[[str], bool] = lambda _key: False,
) -> RepairService:
    """`is_stuck` 回答巡检是否确认某个服务卡住了；卡住的修法只在确认以后才能提出和执行。"""
    clock = clock or (lambda: datetime.now(UTC))
    launch_agents = launch_agents or UnsupportedLaunchAgents()
    windows_services = windows_services or UnsupportedWindowsServices()
    preauthorizations = NoPreauthorizations()
    return RepairService(
        RepairPlanner(
            node_id,
            marks,
            launch_records,
            containers,
            host,
            clock,
            launch_agents=launch_agents,
            windows_services=windows_services,
            is_stuck=is_stuck,
        ),
        RepairWorkflow(
            store,
            containers,
            launcher,
            host,
            verifier,
            marks,
            data_dir / "repair-logs",
            clock,
            launch_agents=launch_agents,
            windows_services=windows_services,
            is_stuck=is_stuck,
            launch_records=launch_records,
        ),
        store,
        AuthorizationService(
            store, preauthorizations, OperationPolicy(registry, preauthorizations)
        ),
        clock,
        containers,
        host,
        launch_agents,
        windows_services,
    )
