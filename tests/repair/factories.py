"""修复测试共用的计划、启动记录和容器样例。"""

from __future__ import annotations

from datetime import UTC, datetime

from tunnelminion.domain.identifiers import NodeId, OperationId
from tunnelminion.operation.contracts import OperationLevel
from tunnelminion.repair.contracts import (
    REPAIR_TOOL_NAMES,
    ContainerRepairTarget,
    ContainerSnapshot,
    LaunchRecord,
    PythonRepairTarget,
    RepairKind,
    RepairOrigin,
    RepairOriginKind,
    RepairPlan,
    compute_repair_idempotency_key,
)

NOW = datetime(2026, 10, 25, 8, 0, tzinfo=UTC)
NODE = NodeId("node_" + "1" * 32)


def container(
    suffix: str = "a",
    *,
    name: str = "photos-web-1",
    running: bool = False,
    ports: tuple[int, ...] = (8080,),
    compose_project: str | None = "photos",
) -> ContainerSnapshot:
    return ContainerSnapshot(
        container_id=suffix * 64,
        name=name,
        image="photos:latest",
        running=running,
        status="Up 2 minutes" if running else "Exited (1) 13 minutes ago",
        published_ports=ports,
        compose_project=compose_project,
    )


def launch_record(
    *,
    service_key: str = "python:http.server@8765",
    arguments: tuple[str, ...] = ("-m", "http.server", "8765"),
    ports: tuple[int, ...] = (8765,),
    rule_shown: bool = True,
) -> LaunchRecord:
    return LaunchRecord(
        service_key=service_key,
        interpreter="C:/Python311/python.exe",
        arguments=arguments,
        working_directory="C:/work/site",
        ports=ports,
        username="me",
        rule_shown=rule_shown,
        process_id=4242,
        process_started_at=NOW,
        recorded_at=NOW,
    )


def plan(
    target: ContainerRepairTarget | PythonRepairTarget | None = None,
    *,
    service_key: str | None = None,
    operation_id: OperationId | None = None,
) -> RepairPlan:
    target = target or ContainerRepairTarget(compose_project="photos", containers=(container(),))
    kind = target.kind
    key = service_key or (
        target.launch.service_key
        if isinstance(target, PythonRepairTarget)
        else "docker:compose:photos"
    )
    return RepairPlan(
        operation_id=operation_id or OperationId.new(),
        idempotency_key=compute_repair_idempotency_key(
            node_id=NODE, service_key=key, kind=kind, target_fingerprint=target.fingerprint
        ),
        node_id=NODE,
        service_key=key,
        service_name="Docker 容器组 photos",
        kind=kind,
        tool_name=REPAIR_TOOL_NAMES[RepairKind(kind)],
        level=OperationLevel.L2,
        target=target,
        reason="两个容器 13 分钟前都退出了",
        origin=RepairOrigin(kind=RepairOriginKind.LOCAL_CLI, evidence=("容器已退出",)),
        action_summary="重启 Docker 容器组 photos（1 个容器）",
        impact_summary="重启大约需要半分钟，这期间相册打不开",
        verification_summary="重启后我会再打开一次相册首页",
        failure_summary="我会停下来，告诉你卡在哪，不会反复重启",
        created_at=NOW,
    )
