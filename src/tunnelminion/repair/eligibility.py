"""生成计划和执行前共用的资格核对。"""

from __future__ import annotations

import os
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
    RepairError,
    RepairErrorCode,
    RepairKind,
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


def check_identity(service_key: str, kind: RepairKind) -> None:
    if not is_mark_key(service_key) or not service_key.startswith(
        tuple(REPAIR_KEY_PREFIXES.values())
    ):
        raise RepairRefusal(
            RepairError(
                code=RepairErrorCode.NOT_ELIGIBLE,
                message="只能修 Docker 容器、Python 脚本和 macOS 后台服务。",
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


def check_python(launch: LaunchRecord, host: HostInspector) -> None:
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
    for port in launch.ports:
        owner = host.port_owner(port, launch)
        if owner is None:
            continue
        if owner.matches_launch:
            raise RepairRefusal(
                RepairError(
                    code=RepairErrorCode.ALREADY_RUNNING,
                    message="脚本已经自己起来了，不需要修。",
                )
            )
        raise _port_in_use(port, owner)


def _port_in_use(port: int, owner: PortOwner) -> RepairRefusal:
    name = owner.process_name or "别的程序"
    if (
        any(char in name for char in "/\\")
        or not name.isprintable()
        or any(char.isspace() for char in name)
    ):
        name = "别的程序"
    return RepairRefusal(
        RepairError(
            code=RepairErrorCode.PORT_IN_USE,
            message=f"原来的端口 {port} 现在被 {name[:200]} 占了。",
            next_step="先关掉占用这个端口的程序，Agent 不会去停它。",
        )
    )


async def check_launch_agent(
    label: str, ports: tuple[int, ...], runtime: LaunchAgentRuntime, host: HostInspector
) -> LaunchAgentJob:
    """只修当前用户自己装的、已加载但已经退出的后台服务。"""
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
    job = await runtime.inspect(label)
    if job is LaunchAgentProblem.MISSING:
        raise RepairRefusal(
            RepairError(
                code=RepairErrorCode.NOT_ELIGIBLE,
                message="在你用户目录的 ~/Library/LaunchAgents 里找不到这个后台服务的配置。",
                next_step="Agent 只修你自己装在这个目录里的后台服务。",
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
    if job.pid is not None:
        raise RepairRefusal(
            RepairError(
                code=RepairErrorCode.ALREADY_RUNNING,
                message="它还在运行。现在只重新启动已经退出的后台服务。",
            )
        )
    for port in ports:
        owner = host.port_owner(port)
        if owner is not None:
            raise _port_in_use(port, owner)
    return job
