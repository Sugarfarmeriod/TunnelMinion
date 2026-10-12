"""只在本机把 Python 监听进程的启动参数缩减为入口名。"""

from __future__ import annotations

import os
import re
from typing import TYPE_CHECKING

import psutil

if TYPE_CHECKING:
    from tunnelminion.platforms.windows.models import NetworkListener


def is_python_process(name: str | None) -> bool:
    """只接受 Python 解释器的完整进程名。"""
    return re.fullmatch(r"pythonw?(?:\d+(?:\.\d+)*)?(?:\.exe)?", name or "", re.I) is not None


def parse_python_entrypoint(arguments: list[str]) -> str | None:
    """只返回入口 basename 或模块名，不保留入口后的应用参数。"""
    index = 1
    while index < len(arguments):
        argument = arguments[index]
        if argument == "--":
            index += 1
            break
        if argument in {"-W", "-X"}:
            index += 2
            continue
        if argument.startswith(("-W", "-X")):
            index += 1
            continue
        if argument == "-m":
            module = arguments[index + 1] if index + 1 < len(arguments) else ""
            if (
                len(module) <= 80
                and all(part.isidentifier() for part in module.split("."))
                and module.split(".")[0] != "debugpy"
            ):
                return module
            return None
        if argument.startswith("-"):
            if len(argument) > 1 and all(char in "bBdEiIOPqRsSuvx" for char in argument[1:]):
                index += 1
                continue
            return None
        break
    if index >= len(arguments):
        return None
    path = arguments[index].replace("\\", "/")
    name = path.rsplit("/", 1)[-1]
    # shortcut: 调试包装只保留 Python 归属；有明确目标格式时再支持其具体入口。
    if "/debugpy/" in f"/{path.lower()}" or name.lower() in {"debugpy", "pydevd.py"}:
        return None
    return (
        name
        if 0 < len(name) <= 80 and name.isprintable() and name not in {"-", ".", ".."}
        else None
    )


def read_python_entrypoint(listener: NetworkListener) -> str | None:
    """仅查询提供 TCP 服务的 Python；读取失败时不输出原始错误或参数。"""
    if (
        listener.protocol != "tcp"
        or listener.pid is None
        or listener.pid == os.getpid()
        or not is_python_process(listener.process_name)
    ):
        return None
    try:
        process = psutil.Process(listener.pid)
        if not is_python_process(process.name()):
            return None
        return parse_python_entrypoint(process.cmdline())
    except (psutil.Error, OSError):
        return None
