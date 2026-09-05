"""macOS 固定命令路径与跨平台只读系统查询实现。"""

from __future__ import annotations

import shutil
import subprocess

from tunnelminion.platforms.windows.models import NetworkListener
from tunnelminion.platforms.windows.system import (
    CommandResult,
    CommandRunner,
    PsutilSystemReader,
    SubprocessCommandRunner,
    SystemReader,
)

__all__ = [
    "CommandResult",
    "CommandRunner",
    "MacOSSystemReader",
    "PsutilSystemReader",
    "SubprocessCommandRunner",
    "SystemReader",
    "default_docker_path",
    "default_wg_path",
]


class MacOSSystemReader(PsutilSystemReader):
    """优先使用 psutil，并在普通用户无权枚举套接字时降级到固定的 lsof 查询。"""

    def __init__(self, lsof_path: str | None = None) -> None:
        self._lsof_path = lsof_path or shutil.which("lsof") or "/usr/sbin/lsof"

    def listeners(self) -> tuple[NetworkListener, ...]:
        """读取监听端点；lsof 参数完全由程序固定，不接受用户输入。"""
        try:
            return super().listeners()
        except PermissionError:
            return self._lsof_listeners()

    def _lsof_listeners(self) -> tuple[NetworkListener, ...]:
        try:
            completed = subprocess.run(
                (
                    self._lsof_path,
                    "-nP",
                    "-iTCP",
                    "-sTCP:LISTEN",
                    "-iUDP",
                ),
                check=False,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=5,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
            raise PermissionError("macOS 无法执行只读 lsof 监听查询") from exc
        if completed.returncode not in {0, 1}:
            raise PermissionError("macOS lsof 监听查询失败")
        return self.parse_lsof_output(completed.stdout)

    @staticmethod
    def parse_lsof_output(stdout: str) -> tuple[NetworkListener, ...]:
        """解析固定格式的 lsof 输出，忽略不完整或非监听记录。"""
        values: dict[tuple[str, str, int, int | None], NetworkListener] = {}
        for line in stdout.splitlines()[1:]:
            columns = line.split()
            if len(columns) < 4:
                continue
            protocol_index = next(
                (index for index, value in enumerate(columns) if value in {"TCP", "UDP"}),
                None,
            )
            if protocol_index is None or protocol_index + 1 >= len(columns):
                continue
            protocol = columns[protocol_index].lower()
            if protocol == "tcp" and "(LISTEN)" not in columns[protocol_index + 2 :]:
                continue
            endpoint = columns[protocol_index + 1]
            if ":" not in endpoint or "->" in endpoint:
                continue
            address, raw_port = endpoint.rsplit(":", 1)
            try:
                port = int(raw_port)
                pid = int(columns[1])
            except ValueError:
                continue
            address = address.strip("[]")
            if address == "*":
                address = "0.0.0.0"
            listener = NetworkListener(
                protocol=protocol,
                address=address,
                port=port,
                pid=pid,
                process_name=columns[0],
            )
            values[(protocol, address, port, pid)] = listener
        return tuple(
            sorted(values.values(), key=lambda item: (item.port, item.protocol, item.address))
        )


def default_wg_path() -> str:
    """优先使用当前 macOS PATH 中的 WireGuard CLI。"""
    return shutil.which("wg") or "/opt/homebrew/bin/wg"


def default_docker_path() -> str:
    """优先使用当前 macOS PATH 中的 Docker CLI。"""
    return shutil.which("docker") or "/usr/local/bin/docker"
