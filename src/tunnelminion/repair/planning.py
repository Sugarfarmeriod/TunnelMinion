"""仅用本机事实生成不可执行任意命令的修复计划。"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from datetime import datetime

from tunnelminion.domain.identifiers import NodeId, OperationId
from tunnelminion.domain.service_marks import ServiceMark
from tunnelminion.operation.contracts import OperationLevel
from tunnelminion.repair.contracts import (
    REPAIR_TOOL_NAMES,
    ContainerRepairTarget,
    ContainerRuntime,
    HostInspector,
    LaunchRecordStore,
    PythonRepairTarget,
    RepairError,
    RepairErrorCode,
    RepairKind,
    RepairOrigin,
    RepairPlan,
    compute_repair_idempotency_key,
)
from tunnelminion.repair.eligibility import (
    NOT_MINE_ERROR,
    RepairRefusal,
    check_containers,
    check_hidden,
    check_identity,
    check_python,
    read_containers,
)


class RepairPlanner:
    def __init__(
        self,
        node_id: NodeId,
        marks: Callable[[], Mapping[str, ServiceMark]],
        launch_records: LaunchRecordStore,
        containers: ContainerRuntime,
        host: HostInspector,
        clock: Callable[[], datetime],
    ) -> None:
        self._node_id = node_id
        self._marks = marks
        self._launch_records = launch_records
        self._containers = containers
        self._host = host
        self._clock = clock

    async def propose(
        self, service_key: str, kind: RepairKind, reason: str, origin: RepairOrigin
    ) -> RepairPlan:
        reason = reason.strip()
        if not reason or len(reason) > 500:
            raise ValueError("reason")
        check_identity(service_key, kind)
        mark = self._marks().get(service_key)
        check_hidden(mark)
        target: ContainerRepairTarget | PythonRepairTarget
        if kind is RepairKind.RESTART_CONTAINERS:
            compose = service_key.startswith("docker:compose:")
            name = service_key.removeprefix("docker:compose:" if compose else "docker:")
            items = await read_containers(
                self._containers,
                compose_project=name if compose else None,
                container_name=None if compose else name,
            )
            check_containers(items, mark)
            target = ContainerRepairTarget(
                compose_project=name if compose else None,
                container_name=None if compose else name,
                containers=items,
            )
            service_name = f"Docker 容器组 {name}" if compose else f"Docker 容器 {name}"
            action = (
                f"重启 Docker 容器组 {name}（{len(items)} 个容器）"
                if compose
                else f"重启 Docker 容器 {name}"
            )
            impact = "重启大约需要半分钟，这期间这个服务打不开；正在进行的操作可能要重做。"
            verification = (
                "重启后我会确认容器在运行、端口在听，并再打开一次首页。"
                if target.ports
                else "重启后我会确认容器在运行。"
            )
            failure = "没修好我会停下来，告诉你卡在哪，不会反复重启。"
        else:
            launch = self._launch_records.get(service_key)
            if launch is None:
                raise RepairRefusal(
                    RepairError(
                        code=RepairErrorCode.NO_LAUNCH_RECORD,
                        message="我不知道它原来是怎么启动的。",
                        next_step="请在终端里自己重新运行一次，之后我就记住了。",
                    )
                )
            if mark is not ServiceMark.MINE and not launch.rule_shown:
                raise RepairRefusal(NOT_MINE_ERROR)
            check_python(launch, self._host)
            target = PythonRepairTarget(launch=launch)
            entry = service_key.removeprefix("python:").rsplit("@", 1)[0]
            ports = "、".join(str(port) for port in target.ports)
            service_name = f"Python 脚本 {entry}"
            action = f"按上次的启动方式在后台重新运行 {entry}（端口 {ports}）"
            impact = (
                "脚本会在后台运行，不会回到原来的终端窗口；输出写到 TunnelMinion 的日志文件里。"
            )
            verification = f"启动后我会确认端口 {ports} 在听，并再打开一次首页。"
            failure = "没修好我会停掉这次拉起的进程，告诉你卡在哪，不会反复尝试。"
        return RepairPlan(
            operation_id=OperationId.new(),
            idempotency_key=compute_repair_idempotency_key(
                node_id=self._node_id,
                service_key=service_key,
                kind=kind,
                target_fingerprint=target.fingerprint,
            ),
            node_id=self._node_id,
            service_key=service_key,
            service_name=service_name[:120],
            kind=kind,
            tool_name=REPAIR_TOOL_NAMES[kind],
            level=OperationLevel.L2,
            target=target,
            reason=reason,
            origin=origin,
            action_summary=action[:300],
            impact_summary=impact[:500],
            verification_summary=verification[:300],
            failure_summary=failure[:300],
            created_at=self._clock(),
        )
