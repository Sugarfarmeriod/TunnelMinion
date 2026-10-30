"""用本机真实的 Docker、进程和存储组装修复服务；网页和命令行共用。"""

from __future__ import annotations

import sys
from collections.abc import Callable
from pathlib import Path

from tunnelminion.domain.identifiers import NodeId
from tunnelminion.domain.tools import Platform
from tunnelminion.memory.sqlite import SQLiteStores
from tunnelminion.platforms.windows.system import SubprocessCommandRunner, SystemReader
from tunnelminion.repair.agent_tools import register_repair_agent_tools
from tunnelminion.repair.contracts import LaunchAgentRuntime, WindowsServiceRuntime
from tunnelminion.repair.definitions import register_repair_operations
from tunnelminion.repair.docker import DockerContainerRuntime
from tunnelminion.repair.launch_agents import MacLaunchAgentRuntime
from tunnelminion.repair.processes import (
    BackgroundProcessLauncher,
    PsutilHostInspector,
    SocketLocalVerifier,
)
from tunnelminion.repair.service import RepairService, build_repair_service
from tunnelminion.repair.windows_services import WindowsServiceManager
from tunnelminion.tools.registry import ToolRegistry


def build_node_repair_service(
    *,
    root: Path,
    node_id: NodeId,
    stores: SQLiteStores,
    registry: ToolRegistry,
    docker_path: str,
    system_reader: SystemReader,
    platform: Platform = Platform.WINDOWS,
) -> RepairService:
    """`registry` 里必须已经登记修法，否则策略会拒绝所有修复。"""
    containers = DockerContainerRuntime(SubprocessCommandRunner(), docker_path)
    launch_agents: LaunchAgentRuntime | None = (
        MacLaunchAgentRuntime(SubprocessCommandRunner()) if platform is Platform.MACOS else None
    )
    windows_services: WindowsServiceRuntime | None = (
        WindowsServiceManager(SubprocessCommandRunner())
        if platform is Platform.WINDOWS and sys.platform == "win32"
        else None
    )
    host = PsutilHostInspector(system_reader)
    service = build_repair_service(
        node_id=node_id,
        data_dir=root,
        store=stores.repairs,
        launch_records=stores.launch_records,
        registry=registry,
        marks=stores.service_marks.all,
        containers=containers,
        launcher=BackgroundProcessLauncher(),
        host=host,
        verifier=SocketLocalVerifier(),
        launch_agents=launch_agents,
        windows_services=windows_services,
        is_stuck=stuck_checker(root),
    )
    register_repair_agent_tools(
        registry,
        containers=containers,
        launch_records=stores.launch_records,
        host=host,
        marks=stores.service_marks.all,
        repair_service=service,
        data_dir=root,
    )
    return service


def stuck_checker(root: Path) -> Callable[[str], bool]:
    """巡检记录里确认"卡住了"的服务；网页、Gateway 和命令行读同一份巡检记录。"""
    from tunnelminion.patrol.contracts import PatrolReason, PatrolStatus
    from tunnelminion.patrol.local import patrol_store

    store = patrol_store(root)

    def is_stuck(key: str) -> bool:
        record = store.get(key)
        return (
            record is not None
            and record.status is PatrolStatus.DOWN
            and record.reason is PatrolReason.STUCK
        )

    return is_stuck


def build_local_repair_service(
    data_dir: Path | None = None, *, platform: Platform | None = None
) -> RepairService:
    """给命令行用：只打开本机存储和修复部件，不读模型密钥、不起网关。"""
    from tunnelminion.app import load_or_create_node_id
    from tunnelminion.runtime.profile import default_runtime_data_dir

    root = data_dir or default_runtime_data_dir()
    platform = platform or (Platform.MACOS if sys.platform == "darwin" else Platform.WINDOWS)
    system_reader: SystemReader
    if platform is Platform.MACOS:
        from tunnelminion.platforms.macos.system import MacOSSystemReader
        from tunnelminion.platforms.macos.system import default_docker_path as docker_path

        system_reader = MacOSSystemReader()
    else:
        from tunnelminion.platforms.windows.system import PsutilSystemReader
        from tunnelminion.platforms.windows.system import default_docker_path as docker_path

        system_reader = PsutilSystemReader()
    registry = ToolRegistry()
    register_repair_operations(registry)
    return build_node_repair_service(
        root=root,
        node_id=load_or_create_node_id(root / "node-id"),
        stores=SQLiteStores.open(root / "runtime.sqlite3"),
        registry=registry,
        docker_path=docker_path(),
        system_reader=system_reader,
        platform=platform,
    )
