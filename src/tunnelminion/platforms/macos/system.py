"""macOS 固定命令路径与跨平台只读系统查询实现。"""

from __future__ import annotations

import shutil

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
    "PsutilSystemReader",
    "SubprocessCommandRunner",
    "SystemReader",
    "default_docker_path",
    "default_wg_path",
]


def default_wg_path() -> str:
    """优先使用当前 macOS PATH 中的 WireGuard CLI。"""
    return shutil.which("wg") or "/opt/homebrew/bin/wg"


def default_docker_path() -> str:
    """优先使用当前 macOS PATH 中的 Docker CLI。"""
    return shutil.which("docker") or "/usr/local/bin/docker"
