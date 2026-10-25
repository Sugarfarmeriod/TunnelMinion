"""生成计划和执行前共用的资格核对。"""

from __future__ import annotations

from pathlib import Path

from tunnelminion.domain.service_marks import ServiceMark, is_mark_key
from tunnelminion.platforms.python_entrypoint import parse_python_entrypoint
from tunnelminion.repair.contracts import (
    ContainerRuntime,
    ContainerSnapshot,
    HostInspector,
    LaunchRecord,
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


def check_identity(service_key: str, kind: RepairKind) -> None:
    if not is_mark_key(service_key) or not service_key.startswith(("docker:", "python:")):
        raise RepairRefusal(
            RepairError(
                code=RepairErrorCode.NOT_ELIGIBLE,
                message="第一版只能修 Docker 容器和 Python 脚本。",
            )
        )
    if service_key.startswith("docker:") != (kind is RepairKind.RESTART_CONTAINERS):
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
        name = owner.process_name or "别的程序"
        if (
            any(char in name for char in "/\\")
            or not name.isprintable()
            or any(char.isspace() for char in name)
        ):
            name = "别的程序"
        raise RepairRefusal(
            RepairError(
                code=RepairErrorCode.PORT_IN_USE,
                message=f"原来的端口 {port} 现在被 {name[:200]} 占了。",
                next_step="先关掉占用这个端口的程序，Agent 不会去停它。",
            )
        )
