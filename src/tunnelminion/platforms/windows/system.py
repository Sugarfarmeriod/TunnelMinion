"""Windows 固定命令与 psutil 只读查询边界。"""

from __future__ import annotations

import asyncio
import socket
import subprocess
from pathlib import Path
from typing import Protocol

import psutil
from pydantic import BaseModel, ConfigDict

from tunnelminion.platforms.windows.models import (
    InterfaceSnapshot,
    NetworkListener,
    ProcessInfo,
)


class CommandResult(BaseModel):
    """固定只读命令的精简结果。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    returncode: int
    stdout: str
    stderr: str


class CommandRunner(Protocol):
    """仅由适配器构造参数的命令执行边界。"""

    async def run(self, command: tuple[str, ...], timeout_seconds: float) -> CommandResult:
        """执行固定参数列表，不经过 Shell。"""
        ...


class SubprocessCommandRunner:
    """不启用 Shell 的固定只读子进程运行器。"""

    async def run(self, command: tuple[str, ...], timeout_seconds: float) -> CommandResult:
        """在线程中执行命令，避免阻塞事件循环。"""
        return await asyncio.to_thread(self._run_sync, command, timeout_seconds)

    @staticmethod
    def _run_sync(command: tuple[str, ...], timeout_seconds: float) -> CommandResult:
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_seconds,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        return CommandResult(
            returncode=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
        )


class SystemReader(Protocol):
    """Windows 系统 API 的只读查询边界。"""

    def interface(self, name: str) -> InterfaceSnapshot | None:
        """读取指定接口状态和地址。"""
        ...

    def listeners(self) -> tuple[NetworkListener, ...]:
        """读取 TCP/UDP 监听端点。"""
        ...

    def processes(self, limit: int) -> tuple[ProcessInfo, ...]:
        """读取有限数量的进程元数据。"""
        ...


class PsutilSystemReader:
    """使用 psutil 实现跨权限降级的 Windows 查询。"""

    def interface(self, name: str) -> InterfaceSnapshot | None:
        """读取接口在线状态和 IP，不读取 WireGuard 配置文件。"""
        stats = psutil.net_if_stats().get(name)
        if stats is None:
            return None
        addresses = psutil.net_if_addrs().get(name, [])
        allowed_families = {socket.AF_INET, socket.AF_INET6}
        values = tuple(
            item.address.split("%")[0] for item in addresses if item.family in allowed_families
        )
        return InterfaceSnapshot(name=name, is_up=stats.isup, addresses=values)

    def listeners(self) -> tuple[NetworkListener, ...]:
        """只返回监听地址，不读取套接字正文。"""
        results: list[NetworkListener] = []
        try:
            connections = psutil.net_connections(kind="inet")
        except psutil.AccessDenied as exc:
            raise PermissionError("当前账户无法枚举系统监听端点") from exc
        for connection in connections:
            is_tcp = connection.type == socket.SOCK_STREAM
            if is_tcp and connection.status != psutil.CONN_LISTEN:
                continue
            if not is_tcp and connection.raddr:
                continue
            if not connection.laddr:
                continue
            protocol = "tcp" if is_tcp else "udp"
            process_name: str | None = None
            if connection.pid is not None:
                try:
                    process_name = psutil.Process(connection.pid).name()
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    process_name = None
            results.append(
                NetworkListener(
                    protocol=protocol,
                    address=connection.laddr.ip,
                    port=connection.laddr.port,
                    pid=connection.pid,
                    process_name=process_name,
                )
            )
        return tuple(sorted(results, key=lambda item: (item.port, item.protocol, item.address)))

    def processes(self, limit: int) -> tuple[ProcessInfo, ...]:
        """按内存占用返回进程摘要，不请求命令行或环境变量。"""
        values: list[ProcessInfo] = []
        for process in psutil.process_iter(("pid", "name", "status", "memory_info", "num_threads")):
            try:
                info = process.info
                memory = info.get("memory_info")
                values.append(
                    ProcessInfo(
                        pid=int(info["pid"]),
                        name=str(info.get("name") or "unknown"),
                        status=str(info["status"]) if info.get("status") else None,
                        memory_bytes=int(memory.rss) if memory is not None else None,
                        thread_count=int(info["num_threads"])
                        if info.get("num_threads") is not None
                        else None,
                    )
                )
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                continue
        values.sort(key=lambda item: item.memory_bytes or 0, reverse=True)
        return tuple(values[:limit])


def default_wg_path() -> str:
    """返回 WireGuard 官方 Windows 安装位置。"""
    return str(Path("C:/Program Files/WireGuard/wg.exe"))


def default_docker_path() -> str:
    """返回 Docker Desktop CLI 的标准 Windows 安装位置。"""
    return str(Path("C:/Program Files/Docker/Docker/resources/bin/docker.exe"))
