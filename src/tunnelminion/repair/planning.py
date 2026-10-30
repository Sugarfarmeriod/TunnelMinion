"""仅用本机事实生成不可执行任意命令的修复计划。"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from datetime import datetime

from tunnelminion.domain.identifiers import NodeId, OperationId
from tunnelminion.domain.service_marks import ServiceMark
from tunnelminion.operation.contracts import OperationLevel
from tunnelminion.repair.compose_order import (
    COMPOSE_READY_SECONDS,
    container_steps,
    describe_order,
)
from tunnelminion.repair.contracts import (
    REPAIR_TOOL_NAMES,
    ContainerRepairTarget,
    ContainerRuntime,
    HostInspector,
    LaunchAgentRecord,
    LaunchAgentRepairTarget,
    LaunchAgentRuntime,
    LaunchRecord,
    LaunchRecordStore,
    ProgramLaunchRecord,
    ProgramRepairTarget,
    PythonRepairTarget,
    RepairError,
    RepairErrorCode,
    RepairKind,
    RepairOrigin,
    RepairPlan,
    RepairTarget,
    StuckProgramRepairTarget,
    WindowsServiceRecord,
    WindowsServiceRepairTarget,
    WindowsServiceRuntime,
    compute_repair_idempotency_key,
)
from tunnelminion.repair.eligibility import (
    NOT_MINE_ERROR,
    RepairRefusal,
    check_containers,
    check_hidden,
    check_identity,
    check_launch_agent,
    check_launch_agent_label,
    check_program,
    check_program_name,
    check_python,
    check_windows_service,
    check_windows_service_runtime,
    find_stuck_process,
    read_containers,
)
from tunnelminion.repair.launch_agents import UnsupportedLaunchAgents
from tunnelminion.repair.windows_services import UnsupportedWindowsServices

NO_PROGRAM_RECORD_ERROR = RepairError(
    code=RepairErrorCode.NO_LAUNCH_RECORD,
    message="我不知道它原来是怎么启动的。",
    next_step=(
        "我只记得从终端或用户目录启动、在地图上显示的程序；"
        "请在终端里自己重新运行一次，之后我就记住了。"
    ),
)
NOT_STUCK_ERROR = RepairError(
    code=RepairErrorCode.NOT_STUCK,
    message="巡检还没确认它卡住了（要连续 3 次检查都不响应），它可能只是慢。",
    next_step="等巡检确认以后再结束它，Agent 不会去结束一个可能还在正常工作的程序。",
)


def _service_label(service_key: str) -> str:
    return service_key.split(":", 1)[1].rsplit("@", 1)[0]


def _ports_text(ports: tuple[int, ...]) -> str:
    return "、".join(str(port) for port in ports)


class RepairPlanner:
    def __init__(
        self,
        node_id: NodeId,
        marks: Callable[[], Mapping[str, ServiceMark]],
        launch_records: LaunchRecordStore,
        containers: ContainerRuntime,
        host: HostInspector,
        clock: Callable[[], datetime],
        *,
        launch_agents: LaunchAgentRuntime | None = None,
        windows_services: WindowsServiceRuntime | None = None,
        is_stuck: Callable[[str], bool] = lambda _key: False,
    ) -> None:
        self._windows_services = windows_services or UnsupportedWindowsServices()
        self._is_stuck = is_stuck
        self._node_id = node_id
        self._marks = marks
        self._launch_records = launch_records
        self._containers = containers
        self._host = host
        self._clock = clock
        self._launch_agents = launch_agents or UnsupportedLaunchAgents()

    async def propose(
        self, service_key: str, kind: RepairKind, reason: str, origin: RepairOrigin
    ) -> RepairPlan:
        reason = reason.strip()
        if not reason or len(reason) > 500:
            raise ValueError("reason")
        check_identity(service_key, kind)
        mark = self._marks().get(service_key)
        check_hidden(mark)
        target: RepairTarget
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
            steps, ordered = container_steps(items, compose=compose)
            if ordered:
                action = f"按依赖顺序处理 Docker 容器组 {name}：{describe_order(steps)}"
                impact = (
                    "被依赖的容器先起来；有下一步时，每一步都等容器在运行（有健康检查的等到健康，"
                    f"最多 {COMPOSE_READY_SECONDS:.0f} 秒）再接着做。这期间这个服务打不开；"
                    "正在进行的操作可能要重做。"
                )
            verification = (
                "重启后我会确认容器在运行、端口在听，并再打开一次首页。"
                if target.ports
                else "重启后我会确认容器在运行。"
            )
            failure = "没修好我会停下来，告诉你卡在哪，不会反复重启。"
        elif kind is RepairKind.RESTART_LAUNCH_AGENT:
            label = service_key.removeprefix("launchd:")
            check_launch_agent_label(label, self._launch_agents)
            record = self._launch_records.get(service_key)
            if not isinstance(record, LaunchAgentRecord):
                raise RepairRefusal(
                    RepairError(
                        code=RepairErrorCode.NO_LAUNCH_RECORD,
                        message="我还没见过这个后台服务正常运行，不知道修好以后该检查哪些端口。",
                        next_step="等它下次正常运行时我会记住。",
                    )
                )
            if mark is not ServiceMark.MINE and not record.rule_shown:
                raise RepairRefusal(NOT_MINE_ERROR)
            stuck = self._is_stuck(service_key)
            job = await check_launch_agent(
                label, record.ports, self._launch_agents, self._host, stuck=stuck
            )
            target = LaunchAgentRepairTarget(
                label=label,
                uid=job.uid,
                plist_path=job.plist_path,
                plist_sha256=job.plist_sha256,
                listen_ports=record.ports,
                stuck=stuck and job.pid is not None,
            )
            ports = "、".join(str(port) for port in target.ports)
            service_name = f"后台服务 {label}"
            if target.stuck:
                action = f"结束卡住的后台服务 {label} 再重新启动（端口 {ports}）"
                impact = (
                    "由 macOS 结束它再按它自己的配置启动，和在终端里运行 "
                    "launchctl kickstart -k 一样；正在进行的操作会中断，不改配置文件。"
                )
            else:
                action = f"重新启动后台服务 {label}（端口 {ports}）"
                impact = (
                    "由 macOS 按它自己的配置重新启动，和在终端里运行 launchctl kickstart 一样；"
                    "不改配置文件。"
                )
            verification = f"启动后我会确认它在运行、端口 {ports} 在听，有网页的再打开一次首页。"
            failure = (
                "没修好我会停下来，告诉你卡在哪；后台服务归 macOS 管，"
                "我不会再动它，也不会反复重启。"
            )
        elif kind is RepairKind.RELAUNCH_PROGRAM:
            check_program_name(service_key)
            program = self._launch_records.get(service_key)
            if isinstance(program, WindowsServiceRecord):
                raise RepairRefusal(
                    RepairError(
                        code=RepairErrorCode.NOT_ELIGIBLE,
                        message="它是 Windows 服务，要用“重启 Windows 服务”这种修法。",
                    )
                )
            if not isinstance(program, ProgramLaunchRecord):
                raise RepairRefusal(NO_PROGRAM_RECORD_ERROR)
            if mark is not ServiceMark.MINE and not program.rule_shown:
                raise RepairRefusal(NOT_MINE_ERROR)
            check_program(program, self._host)
            target = ProgramRepairTarget(launch=program)
            name = _service_label(service_key)
            ports = _ports_text(target.ports)
            service_name = f"程序 {name}"
            action = f"按上次的启动方式在后台重新运行 {name}（端口 {ports}）"
            impact = (
                "用你原来的账户、原来的参数和工作目录在后台运行，不会回到原来的终端窗口；"
                "输出写到 TunnelMinion 的日志文件里。TunnelMinion 关掉也不影响它。"
            )
            verification = f"启动后我会确认端口 {ports} 在听，有网页的再打开一次首页。"
            failure = "没修好我会停掉这次拉起的进程，告诉你卡在哪，不会反复尝试。"
        elif kind is RepairKind.RESTART_STUCK_PROGRAM:
            if service_key.startswith("program:"):
                check_program_name(service_key)
            stuck_launch = self._launch_records.get(service_key)
            if not isinstance(stuck_launch, LaunchRecord | ProgramLaunchRecord):
                raise RepairRefusal(NO_PROGRAM_RECORD_ERROR)
            if mark is not ServiceMark.MINE and not stuck_launch.rule_shown:
                raise RepairRefusal(NOT_MINE_ERROR)
            if not self._is_stuck(service_key):
                raise RepairRefusal(NOT_STUCK_ERROR)
            if isinstance(stuck_launch, LaunchRecord):
                check_python(stuck_launch, self._host, ports_free=False)
            else:
                check_program(stuck_launch, self._host, ports_free=False)
            pid, started_at = find_stuck_process(stuck_launch, self._host)
            target = StuckProgramRepairTarget(
                launch=stuck_launch, process_id=pid, process_started_at=started_at
            )
            name = _service_label(service_key)
            ports = _ports_text(target.ports)
            service_name = (
                f"Python 脚本 {name}" if service_key.startswith("python:") else f"程序 {name}"
            )
            action = f"结束卡住的 {name}（进程 {pid}），再按上次的启动方式重新运行（端口 {ports}）"
            impact = (
                "先礼貌地请它退出，10 秒后还在就强制结束；正在进行的操作会中断。"
                "然后用原来的账户、参数和工作目录在后台运行。"
            )
            verification = f"重新运行后我会确认端口 {ports} 在听，有网页的再打开一次首页。"
            failure = "没修好我会停掉这次拉起的进程，告诉你卡在哪，不会反复尝试。"
        elif kind is RepairKind.RESTART_WINDOWS_SERVICE:
            check_windows_service_runtime(self._windows_services)
            check_program_name(service_key)
            service_record = self._launch_records.get(service_key)
            if not isinstance(service_record, WindowsServiceRecord):
                raise RepairRefusal(
                    RepairError(
                        code=RepairErrorCode.NO_LAUNCH_RECORD,
                        message="我没认出它是 Windows 服务，或者还没见过它正常运行。",
                        next_step="等它下次正常运行时我会记住。",
                    )
                )
            if mark is not ServiceMark.MINE:
                raise RepairRefusal(NOT_MINE_ERROR)
            info = self._windows_services.inspect(service_record.service_name)
            if info is None:
                raise RepairRefusal(
                    RepairError(
                        code=RepairErrorCode.NOT_ELIGIBLE,
                        message="这台电脑上找不到这个 Windows 服务了，可能已经被卸载。",
                    )
                )
            check_windows_service(
                info,
                stuck=self._is_stuck(service_key),
                ports=service_record.ports,
                host=self._host,
            )
            target = WindowsServiceRepairTarget(
                service_name=info.name,
                binary_path=info.binary_path,
                listen_ports=service_record.ports,
                restart=info.running,
            )
            ports = _ports_text(target.ports)
            service_name = f"Windows 服务 {info.display_name}"
            action = (
                f"重启卡住的 Windows 服务 {info.display_name}（端口 {ports}）"
                if target.restart
                else f"启动已停止的 Windows 服务 {info.display_name}（端口 {ports}）"
            )
            impact = (
                "用 Windows 自带的服务管理操作这一个服务，和在服务管理器里点“重新启动”一样；"
                "不改服务配置。"
            )
            verification = f"之后我会确认服务在运行、端口 {ports} 在听，有网页的再打开一次首页。"
            failure = "没修好我会停下来，告诉你卡在哪；不会反复重启。"
        else:
            launch = self._launch_records.get(service_key)
            if not isinstance(launch, LaunchRecord):
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
