"""本机修复列表、详情与批准入口。"""

from __future__ import annotations

from datetime import datetime, timedelta

from fastapi import APIRouter, BackgroundTasks, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from tunnelminion.domain.identifiers import NodeId, OperationId
from tunnelminion.operation.contracts import (
    AuthorizationDecision,
    OperationStatus,
    OperationTransition,
)
from tunnelminion.repair.contracts import (
    REPAIR_AUTHORIZATION_SECONDS,
    ContainerRepairTarget,
    ContainerSnapshot,
    LaunchAgentRepairTarget,
    ProgramRepairTarget,
    RepairAuditEvent,
    RepairCleanup,
    RepairError,
    RepairExecution,
    RepairKind,
    RepairOrigin,
    RepairRecord,
    RepairVerification,
    StuckProgramRepairTarget,
    WindowsServiceRepairTarget,
)
from tunnelminion.repair.manual_steps import launch_command, redact_arguments
from tunnelminion.repair.service import RepairService


class RepairListItem(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    repair_id: str
    node_id: NodeId
    origin: RepairOrigin
    service_key: str
    service_name: str
    kind: RepairKind
    status: OperationStatus
    action_summary: str
    reason: str
    created_at: datetime
    approval_expires_at: datetime | None
    verification_passed: bool | None
    error: RepairError | None

    @classmethod
    def from_record(cls, record: RepairRecord) -> RepairListItem:
        expiry = None
        if record.status is OperationStatus.AWAITING_AUTHORIZATION:
            expiry = record.plan.created_at + timedelta(seconds=REPAIR_AUTHORIZATION_SECONDS)
        elif record.status is OperationStatus.AUTHORIZED and record.authorization is not None:
            expiry = record.authorization.expires_at
        return cls(
            repair_id=str(record.plan.operation_id),
            node_id=record.plan.node_id,
            origin=record.plan.origin,
            service_key=record.plan.service_key,
            service_name=record.plan.service_name,
            kind=record.plan.kind,
            status=record.status,
            action_summary=record.plan.action_summary,
            reason=record.plan.reason,
            created_at=record.plan.created_at,
            approval_expires_at=expiry,
            verification_passed=record.verification.passed
            if record.verification is not None
            else None,
            error=record.error,
        )


class RepairList(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    repairs: tuple[RepairListItem, ...]


class RepairAuthorizationView(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    operator: str
    decision: AuthorizationDecision
    decided_at: datetime
    expires_at: datetime | None


class ContainerAdvancedView(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    commands: tuple[str, ...]
    containers: tuple[ContainerSnapshot, ...]


class PythonAdvancedView(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    interpreter: str
    arguments: tuple[str, ...]
    working_directory: str
    ports: tuple[int, ...]


class LaunchAgentAdvancedView(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    command: str
    plist_path: str
    ports: tuple[int, ...]


class ProgramAdvancedView(BaseModel):
    """普通程序和卡住的程序：重新运行的命令（像密钥的参数已换成占位）。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    command: str
    ports: tuple[int, ...]
    # 卡住的程序：要先结束的那个进程。
    end_process_id: int | None = None


class WindowsServiceAdvancedView(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    commands: tuple[str, ...]
    binary_path: str
    ports: tuple[int, ...]


AdvancedView = (
    ContainerAdvancedView
    | PythonAdvancedView
    | LaunchAgentAdvancedView
    | ProgramAdvancedView
    | WindowsServiceAdvancedView
)


class RepairDetail(RepairListItem):
    impact_summary: str
    verification_summary: str
    failure_summary: str
    authorization: RepairAuthorizationView | None
    advanced: AdvancedView
    execution: RepairExecution | None
    verification: RepairVerification | None
    cleanup: RepairCleanup | None
    audit: tuple[RepairAuditEvent, ...]
    transitions: tuple[OperationTransition, ...]


def _detail(record: RepairRecord) -> RepairDetail:
    target = record.plan.target
    advanced: AdvancedView
    if isinstance(target, ContainerRepairTarget):
        commands: list[str] = []
        for running in (False, True):
            ids = [item.container_id for item in target.containers if item.running is running]
            if ids:
                action = "restart" if running else "start"
                commands.append(" ".join(("docker", action, *ids)))
        advanced = ContainerAdvancedView(commands=tuple(commands), containers=target.containers)
    elif isinstance(target, LaunchAgentRepairTarget):
        kill = "-k " if target.stuck else ""
        advanced = LaunchAgentAdvancedView(
            command=f"launchctl kickstart {kill}gui/{target.uid}/{target.label}",
            plist_path=target.plist_path,
            ports=target.ports,
        )
    elif isinstance(target, WindowsServiceRepairTarget):
        actions = ("stop", "start") if target.restart else ("start",)
        advanced = WindowsServiceAdvancedView(
            commands=tuple(f"sc.exe {action} {target.service_name}" for action in actions),
            binary_path=target.binary_path,
            ports=target.ports,
        )
    elif isinstance(target, ProgramRepairTarget | StuckProgramRepairTarget):
        advanced = ProgramAdvancedView(
            command=launch_command(target.launch) or "（启动信息读不全）",
            ports=target.ports,
            end_process_id=(
                target.process_id if isinstance(target, StuckProgramRepairTarget) else None
            ),
        )
    else:
        advanced = PythonAdvancedView(
            interpreter=target.launch.interpreter,
            # 和普通程序的命令一样，把看起来像密钥的参数换成占位再给网页。
            arguments=redact_arguments(target.launch.arguments),
            working_directory=target.launch.working_directory,
            ports=target.ports,
        )
    authorization = record.authorization
    return RepairDetail(
        **RepairListItem.from_record(record).model_dump(),
        impact_summary=record.plan.impact_summary,
        verification_summary=record.plan.verification_summary,
        failure_summary=record.plan.failure_summary,
        authorization=(
            RepairAuthorizationView(
                operator=authorization.operator,
                decision=authorization.decision,
                decided_at=authorization.decided_at,
                expires_at=authorization.expires_at,
            )
            if authorization is not None
            else None
        ),
        advanced=advanced,
        execution=record.execution,
        verification=record.verification,
        cleanup=record.cleanup,
        audit=record.audit,
        transitions=record.transitions,
    )


class RepairRejectInput(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    reason: str | None = Field(default=None, max_length=200)


def create_repair_router(service: RepairService) -> APIRouter:
    router = APIRouter()

    def required(repair_id: str) -> RepairRecord:
        try:
            operation_id = OperationId(repair_id)
        except ValueError as exc:
            raise HTTPException(status_code=404, detail="修复不存在") from exc
        record = service.get(operation_id)
        if record is None:
            raise HTTPException(status_code=404, detail="修复不存在")
        return record

    def list_repairs() -> RepairList:
        return RepairList(
            repairs=tuple(RepairListItem.from_record(item) for item in service.list())
        )

    def get_repair(repair_id: str) -> RepairDetail:
        return _detail(required(repair_id))

    async def approve_repair(repair_id: str, background: BackgroundTasks) -> RepairDetail:
        record = required(repair_id)
        try:
            approved = service.approve(record.plan.operation_id, operator="local-web")
        except ValueError as exc:
            raise HTTPException(status_code=409, detail="这个修复现在不等批准") from exc
        background.add_task(service.execute, record.plan.operation_id)
        return _detail(approved)

    def reject_repair(repair_id: str, body: RepairRejectInput) -> RepairDetail:
        record = required(repair_id)
        try:
            rejected = service.reject(
                record.plan.operation_id, operator="local-web", reason=body.reason
            )
        except ValueError as exc:
            raise HTTPException(status_code=409, detail="这个修复现在不等批准") from exc
        return _detail(rejected)

    router.add_api_route("/api/repairs", list_repairs, methods=["GET"])
    router.add_api_route("/api/repairs/{repair_id}", get_repair, methods=["GET"])
    router.add_api_route(
        "/api/repairs/{repair_id}/approve", approve_repair, methods=["POST"], status_code=202
    )
    router.add_api_route("/api/repairs/{repair_id}/reject", reject_repair, methods=["POST"])
    return router
