"""从用户安装的监听程序提取名称，不保留路径或启动参数。"""

from __future__ import annotations

import os
from pathlib import Path
from typing import TYPE_CHECKING

import psutil

if TYPE_CHECKING:
    from tunnelminion.platforms.windows.models import NetworkListener


def read_program_name(listener: NetworkListener) -> str | None:
    """只精选用户目录和常见自行安装目录中的非应用包程序。"""
    if listener.pid is None or listener.pid == os.getpid():
        return None
    try:
        process = psutil.Process(listener.pid)
        name = process.name()
        if name != listener.process_name:
            return None
        path = process.exe().replace("\\", "/").lower()
        home = str(Path.home()).replace("\\", "/").lower().rstrip("/") + "/"
        # shortcut: 路径只用于精选，不证明业务用途；其他安装位置仍保留在完整清单。
        if not path.startswith((home, "/opt/", "/usr/local/")) or any(
            marker in path for marker in (".app/", "/appdata/")
        ):
            return None
        return (
            name
            if 0 < len(name) <= 80
            and name.isprintable()
            and not any(char in name for char in "/\\")
            else None
        )
    except (psutil.Error, OSError):
        return None
