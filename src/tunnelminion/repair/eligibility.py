"""生成计划和执行前共用的资格核对。"""

from __future__ import annotations

import os
from datetime import datetime
from pathlib import Path

from tunnelminion.domain.service_marks import ServiceMark, is_mark_key
from tunnelminion.platforms.python_entrypoint import parse_python_entrypoint
from tunnelminion.repair.contracts import (
    REPAIR_KEY_PREFIXES,
    ContainerRuntime,
    ContainerSnapshot,
    HostInspector,
    LaunchAgentJob,
    LaunchAgentProblem,
    LaunchAgentRuntime,
    LaunchRecord,
    PortOwner,
    ProcessLaunchRecord,
    ProgramLaunchRecord,
    RepairError,
    RepairErrorCode,
    RepairKind,
    WindowsServiceInfo,
    WindowsServiceRuntime,
)
from tunnelminion.repair.manual_steps import (
    port_owner_steps,
    relaunch_steps,
    system_launch_daemon_steps,
    windows_service_steps,
)

AUTHORIZATION_EXPIRED_ERROR = RepairError(
    code=RepairErrorCode.AUTHORIZATION_EXPIRED,
    message="批准已经过期（10 分钟内有效），这次修复作废了。",
    next_step="需要的话请让 Agent 重新提出。",
)
NOT_MINE_ERROR = RepairError(
    code=RepairErrorCode.NOT_ELIGIBLE,
    message='这个服务还不是"是我的服务"，Agent 不能动它。',
    next_step='先在首页把它标成"是我的服务"。',
)


class RepairRefusal(Exception):
    def __init__(self, error: RepairError) -> None:
        super().__init__(error.message)
        self.error = error


# 苹果和常见系统组件、Docker 运行环境、组网工具的后台服务标签前缀；即使标成"是我的服务"也不修。
PROTECTED_LAUNCH_AGENT_PREFIXES = (
    "com.apple.",
    "com.openssh.",
    "org.cups.",
    "org.openbsd.",
    "org.ntp.",
    "org.postfix.",
    "com.docker.",
    "com.orbstack.",
    "dev.orbstack.",
    "com.wireguard.",
    "com.tailscale.",
    "io.tailscale.",
    "com.zerotier.",
)


# 组网工具和 TunnelMinion 自己：普通程序即使标成"是我的服务"也不修。
_PROTECTED_PROGRAM_PREFIXES = (
    "wireguard",
    "tailscale",
    "zerotier",
    "n2n",
    "n3n",
    "easyn2n",
    "openvpn",
    "tunnelminion",
)
_PROTECTED_PROGRAM_NAMES = frozenset({"wg", "wg-quick", "edge", "supernode"})

# Windows 服务的名字、显示名或路径里有这些词的不修：组网、杀毒和安全软件、TunnelMinion 自己。
_PROTECTED_WINDOWS_SERVICE_WORDS = (
    *_PROTECTED_PROGRAM_PREFIXES,
    "defender",
    "windefend",
    "antivirus",
    "firewall",
    "huorong",
    "hipsdaemon",
    "kaspersky",
    "avast",
    "avg",
    "eset",
    "norton",
    "mcafee",
    "sophos",
    "bitdefender",
    "malwarebytes",
    "360",
    "qqpcmgr",
)


def check_identity(service_key: str, kind: RepairKind) -> None:
    prefixes = tuple(prefix for values in REPAIR_KEY_PREFIXES.values() for prefix in values)
    if not is_mark_key(service_key) or not service_key.startswith(prefixes):
        raise RepairRefusal(
            RepairError(
                code=RepairErrorCode.NOT_ELIGIBLE,
                message=(
                    "只能修 Docker 容器、Python 脚本、普通程序、macOS 后台服务和 Windows 服务。"
                ),
            )
        )
    if not service_key.startswith(REPAIR_KEY_PREFIXES[kind]):
        raise RepairRefusal(
            RepairError(code=RepairErrorCode.NOT_ELIGIBLE, message="这种修法不适用于这个服务。")
        )


def check_hidden(mark: ServiceMark | None) -> None:
    if mark is ServiceMark.HIDDEN:
        raise RepairRefusal(
            RepairError(
                code=RepairErrorCode.NOT_ELIGIBLE,
                message="这个服务被标成了隐藏，Agent 不能动它。",
                next_step='想修的话，先在首页把它标成"是我的服务"。',
            )
        )


async def read_containers(
    runtime: ContainerRuntime, *, compose_project: str | None, container_name: str | None
) -> tuple[ContainerSnapshot, ...]:
    items = await runtime.list_containers(
        compose_project=compose_project, container_name=container_name
    )
    if items is None:
        raise RepairRefusal(
            RepairError(
                code=RepairErrorCode.DOCKER_UNAVAILABLE,
                message="Docker 没开。",
                next_step="请先打开 Docker Desktop 或 OrbStack，Agent 不会替你打开。",
            )
        )
    if not items:
        raise RepairRefusal(
            RepairError(
                code=RepairErrorCode.CONTAINER_MISSING,
                message="这个容器已经不存在了。",
                next_step="需要重新部署它，Agent 不会替你重建容器。",
            )
        )
    return items


def check_containers(items: tuple[ContainerSnapshot, ...], mark: ServiceMark | None) -> None:
    if any(
        item.image.startswith("docker/desktop") or item.name.startswith("k8s_") for item in items
    ):
        raise RepairRefusal(
            RepairError(
                code=RepairErrorCode.PROTECTED_TARGET,
                message="这是 Docker 运行环境自带的容器，Agent 不会动它。",
            )
        )
    if mark is not ServiceMark.MINE and not any(item.published_ports for item in items):
        raise RepairRefusal(NOT_MINE_ERROR)


def check_python(launch: LaunchRecord, host: HostInspector, *, ports_free: bool = True) -> None:
    """只修当前账户运行、入口还在的脚本；`ports_free` 为假时不查端口。"""
    arguments = launch.arguments
    index = 0
    module = False
    while index < len(arguments):
        argument = arguments[index]
        if argument == "-m":
            module = True
            index += 1
            break
        if argument == "--":
            index += 1
            break
        if not argument.startswith("-"):
            break
        index += 2 if argument in {"-W", "-X"} else 1
    entry = arguments[index] if index < len(arguments) else ""
    if (module and (entry == "tunnelminion" or entry.startswith("tunnelminion."))) or (
        not module and "tunnelminion" in entry.casefold()
    ):
        raise RepairRefusal(
            RepairError(
                code=RepairErrorCode.PROTECTED_TARGET,
                message="这是 TunnelMinion 自己，Agent 不会动它。",
            )
        )
    if (
        parse_python_entrypoint([launch.interpreter, *arguments]) is None
        or any(arg in {"-c", "-i"} for arg in arguments)
        or any(
            arg.startswith("-") and not arg.startswith(("-W", "-X", "--")) and "i" in arg
            for arg in arguments[:index]
        )
    ):
        raise RepairRefusal(
            RepairError(
                code=RepairErrorCode.UNSUPPORTED_LAUNCH,
                message="它是交互式 Python 或用 python -c 启动的，不能自动重新拉起。",
            )
        )
    if launch.username != host.current_username():
        raise RepairRefusal(
            RepairError(
                code=RepairErrorCode.OTHER_ACCOUNT,
                message="它原来是别的账户运行的，Agent 不会替别的账户启动程序。",
            )
        )
    if not Path(launch.interpreter).is_file():
        raise RepairRefusal(
            RepairError(
                code=RepairErrorCode.INTERPRETER_MISSING,
                message="原来用的 Python 解释器已经不在了。",
            )
        )
    if not Path(launch.working_directory).is_dir():
        raise RepairRefusal(
            RepairError(
                code=RepairErrorCode.WORKING_DIRECTORY_MISSING,
                message="脚本原来的工作目录已经不在了。",
            )
        )
    if not module and not (Path(launch.working_directory) / entry).is_file():
        raise RepairRefusal(
            RepairError(code=RepairErrorCode.ENTRY_MISSING, message="脚本的入口文件已经不在了。")
        )
    if ports_free:
        _check_ports_free(launch, host)


def _check_ports_free(launch: ProcessLaunchRecord, host: HostInspector) -> None:
    for port in launch.ports:
        owner = host.port_owner(port, launch)
        if owner is None:
            continue
        if owner.matches_launch:
            raise RepairRefusal(
                RepairError(
                    code=RepairErrorCode.ALREADY_RUNNING,
                    message="它已经自己起来了，不需要重新运行。",
                    next_step='如果它在但不响应，等巡检确认"卡住了"以后可以结束它再重新运行。',
                )
            )
        raise _port_in_use(port, owner, launch)


def _port_in_use(
    port: int, owner: PortOwner, launch: ProcessLaunchRecord | None = None
) -> RepairRefusal:
    name = owner.process_name or "别的程序"
    if (
        any(char in name for char in "/\\")
        or not name.isprintable()
        or any(char.isspace() for char in name)
    ):
        name = "别的程序"
    steps = port_owner_steps(port)
    if launch is not None:
        steps = (*steps, *relaunch_steps(launch))
    return RepairRefusal(
        RepairError(
            code=RepairErrorCode.PORT_IN_USE,
            message=f"原来的端口 {port} 现在被 {name[:200]} 占了。",
            next_step="先关掉占用这个端口的程序，Agent 不会去停它。",
            manual_steps=steps,
        )
    )


def check_program_name(service_key: str) -> None:
    """组网工具和 TunnelMinion 自己即使标成"是我的服务"也不修。"""
    name = service_key.removeprefix("program:").rsplit("@", 1)[0].casefold()
    if name.startswith(_PROTECTED_PROGRAM_PREFIXES) or name in _PROTECTED_PROGRAM_NAMES:
        raise RepairRefusal(
            RepairError(
                code=RepairErrorCode.PROTECTED_TARGET,
                message="这是组网工具或 TunnelMinion 自己，Agent 不会动它。",
            )
        )


def check_program(
    launch: ProgramLaunchRecord, host: HostInspector, *, ports_free: bool = True
) -> None:
    """只修当前账户普通权限运行、可执行文件没变的程序；`ports_free` 为假时不查端口。"""
    check_program_name(launch.service_key)
    if launch.elevated:
        raise RepairRefusal(
            RepairError(
                code=RepairErrorCode.NEEDS_ADMIN,
                message=(
                    "它原来以管理员身份运行，Agent 读不全它的启动方式，也不会用管理员身份启动程序。"
                ),
                next_step="请你自己重新运行它。",
                manual_steps=relaunch_steps(launch),
            )
        )
    if launch.username != host.current_username():
        raise RepairRefusal(
            RepairError(
                code=RepairErrorCode.OTHER_ACCOUNT,
                message="它原来是别的账户运行的，Agent 不会替别的账户启动程序。",
                next_step="请用原来的账户自己重新运行它。",
            )
        )
    assert launch.executable is not None and launch.working_directory is not None
    try:
        stat = Path(launch.executable).stat()
        same = (stat.st_size, stat.st_mtime_ns) == (
            launch.executable_size,
            launch.executable_mtime_ns,
        )
    except OSError:
        same = False
    if not same:
        raise RepairRefusal(
            RepairError(
                code=RepairErrorCode.EXECUTABLE_CHANGED,
                message="原来的程序文件已经不在了，或者已经换成了别的版本。",
                next_step="请你自己重新运行它，之后我会记住新的启动方式。",
            )
        )
    if not Path(launch.working_directory).is_dir():
        raise RepairRefusal(
            RepairError(
                code=RepairErrorCode.WORKING_DIRECTORY_MISSING,
                message="程序原来的工作目录已经不在了。",
            )
        )
    if ports_free:
        _check_ports_free(launch, host)


def find_stuck_process(launch: ProcessLaunchRecord, host: HostInspector) -> tuple[int, datetime]:
    """找出占着端口、和启动记录对得上的那个进程；对不上就拒绝，不动它。"""
    owners = [(port, host.port_owner(port, launch)) for port in launch.ports]
    listening = [(port, owner) for port, owner in owners if owner is not None]
    if not listening:
        raise RepairRefusal(
            RepairError(
                code=RepairErrorCode.NOT_STUCK,
                message="它已经退出了，不是卡住。",
                next_step="可以改用按原来的方式重新运行。",
            )
        )
    for port, owner in listening:
        if (
            not owner.matches_launch
            or owner.pid is None
            or owner.started_at is None
            or abs((owner.started_at - launch.process_started_at).total_seconds()) > 1
        ):
            refusal = _port_in_use(port, owner, launch)
            raise RepairRefusal(
                refusal.error.model_copy(
                    update={
                        "message": f"占着端口 {port} 的不是记录里的那个程序，Agent 不会结束它。"
                    }
                )
            )
    _, owner = listening[0]
    assert owner.pid is not None and owner.started_at is not None
    return owner.pid, owner.started_at


def check_windows_service_runtime(runtime: WindowsServiceRuntime) -> None:
    reason = runtime.unsupported_reason()
    if reason is not None:
        raise RepairRefusal(RepairError(code=RepairErrorCode.NOT_ELIGIBLE, message=reason))


def check_windows_service(
    info: WindowsServiceInfo, *, stuck: bool, ports: tuple[int, ...], host: HostInspector
) -> None:
    """只修主人自己装、单独授权过、没被禁用的第三方服务；在跑的只在卡住时重启。"""
    path = info.binary_path.replace("\\", "/").casefold()
    words = f"{info.name} {info.display_name} {path}".casefold()
    if (
        path[1:].startswith(":/windows/")
        or path.rsplit("/", 1)[-1] == "svchost.exe"
        or any(word in words for word in _PROTECTED_WINDOWS_SERVICE_WORDS)
    ):
        raise RepairRefusal(
            RepairError(
                code=RepairErrorCode.PROTECTED_TARGET,
                message=(
                    "这是 Windows 自带、组网、杀毒安全软件或 TunnelMinion 自己的服务，"
                    "Agent 不会动它。"
                ),
            )
        )
    if info.start_type == "disabled":
        raise RepairRefusal(
            RepairError(
                code=RepairErrorCode.SERVICE_DISABLED,
                message="这个服务被设成了“已禁用”，Agent 不会替你打开。",
                manual_steps=windows_service_steps(info.name, disabled=True, running=False),
            )
        )
    if info.running and not stuck:
        raise RepairRefusal(
            RepairError(
                code=RepairErrorCode.ALREADY_RUNNING,
                message="这个服务在运行。只有巡检确认它卡住了才会重启它。",
            )
        )
    if not info.granted:
        raise RepairRefusal(
            RepairError(
                code=RepairErrorCode.NOT_AUTHORIZED,
                message="你还没允许 Agent 重启这个 Windows 服务。",
                next_step=(
                    "在地图上点开这个服务，打开“允许重启这个 Windows 服务”（会弹一次管理员确认）。"
                ),
                manual_steps=windows_service_steps(info.name, disabled=False, running=info.running),
            )
        )
    if not info.running:
        for port in ports:
            owner = host.port_owner(port)
            if owner is not None:
                raise _port_in_use(port, owner)


def check_launch_agent_label(label: str, runtime: LaunchAgentRuntime) -> None:
    """只看平台和标签就能拒绝的情况，先于启动记录检查，让拒绝理由说到点子上。"""
    reason = runtime.unsupported_reason()
    if reason is not None:
        raise RepairRefusal(RepairError(code=RepairErrorCode.NOT_ELIGIBLE, message=reason))
    if label.casefold().startswith(PROTECTED_LAUNCH_AGENT_PREFIXES):
        raise RepairRefusal(
            RepairError(
                code=RepairErrorCode.PROTECTED_TARGET,
                message="这是系统、组网或 Docker 自带的后台服务，Agent 不会动它。",
            )
        )
    if "tunnelminion" in label.casefold():
        raise RepairRefusal(
            RepairError(
                code=RepairErrorCode.PROTECTED_TARGET,
                message="这是 TunnelMinion 自己，Agent 不会动它。",
            )
        )


async def check_launch_agent(
    label: str,
    ports: tuple[int, ...],
    runtime: LaunchAgentRuntime,
    host: HostInspector,
    *,
    stuck: bool = False,
) -> LaunchAgentJob:
    """只修当前用户自己装的、已加载的后台服务：已经退出的，或巡检确认卡住的。"""
    check_launch_agent_label(label, runtime)
    job = await runtime.inspect(label)
    if job is LaunchAgentProblem.MISSING:
        raise RepairRefusal(
            RepairError(
                code=RepairErrorCode.NOT_ELIGIBLE,
                message="在你用户目录的 ~/Library/LaunchAgents 里找不到这个后台服务的配置。",
                next_step="Agent 只修你自己装在这个目录里的后台服务。",
                manual_steps=system_launch_daemon_steps(label),
            )
        )
    if job is LaunchAgentProblem.UNSAFE:
        raise RepairRefusal(
            RepairError(
                code=RepairErrorCode.PROTECTED_TARGET,
                message=(
                    "这个后台服务的配置文件不是你自己的普通文件，或者别人也能改，Agent 不会动它。"
                ),
            )
        )
    if job is LaunchAgentProblem.INVALID:
        raise RepairRefusal(
            RepairError(
                code=RepairErrorCode.NOT_ELIGIBLE,
                message="读不懂这个后台服务的配置文件（找不到要运行的程序）。",
            )
        )
    if job.program is not None and ".app/contents/" in job.program.casefold():
        raise RepairRefusal(
            RepairError(
                code=RepairErrorCode.PROTECTED_TARGET,
                message="这是某个应用自带的后台服务，Agent 不会动它。",
            )
        )
    if not job.loaded:
        raise RepairRefusal(
            RepairError(
                code=RepairErrorCode.NOT_LOADED,
                message="这个后台服务已经被卸载了（例如用 brew services stop 停掉的）。",
                next_step="Agent 不会替你重新加载；需要的话请自己重新启用它。",
            )
        )
    if job.loaded_path is None or os.path.normpath(job.loaded_path) != os.path.normpath(
        job.plist_path
    ):
        raise RepairRefusal(
            RepairError(
                code=RepairErrorCode.NOT_ELIGIBLE,
                message="macOS 加载的不是你用户目录里的这份配置，Agent 不会动它。",
            )
        )
    if stuck:
        return job
    if job.pid is not None:
        raise RepairRefusal(
            RepairError(
                code=RepairErrorCode.ALREADY_RUNNING,
                message="它还在运行。只有巡检确认它卡住了才会结束再重新启动。",
            )
        )
    for port in ports:
        owner = host.port_owner(port)
        if owner is not None:
            raise _port_in_use(port, owner)
    return job
