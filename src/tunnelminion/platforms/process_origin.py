"""判断一个监听程序是怎么来的：终端启动、装在用户目录、系统自带、桌面应用或应用自启服务。

只依赖标准库和 psutil，评测脚本可以把本文件单独复制到其他电脑上采集事实。
路径和父进程名只在本机用于判断，不进入工具输出。
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

import psutil


class ProcessOrigin(StrEnum):
    """监听程序的来历；决定首页默认显示、待确认还是隐藏。"""

    TERMINAL = "terminal"
    USER_INSTALL = "user_install"
    SYSTEM = "system"
    DESKTOP_APP = "desktop_app"
    APP_SERVICE = "app_service"
    CONTAINER_RUNTIME = "container_runtime"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class ProcessFacts:
    """判断来历所需的本机事实；`ancestors` 从直接父进程开始向上排列。"""

    platform: str
    name: str
    exe: str | None
    ancestors: tuple[str, ...]
    home: str


# 交互式 shell、终端程序和终端复用器：在这些进程下面启动的程序视为用户亲手启动。
_TERMINALS = frozenset(
    {
        "alacritty",
        "bash",
        "cmd",
        "csh",
        "dash",
        "fish",
        "iterm2",
        "kitty",
        "ksh",
        "login",
        "nu",
        "openconsole",
        "powershell",
        "pwsh",
        "screen",
        "sh",
        "tcsh",
        "terminal",
        "tmux",
        "wezterm-gui",
        "windowsterminal",
        "zsh",
    }
)

# 容器运行环境自己的进程：端口应归到容器，而不是运行环境本身。
_CONTAINER_RUNTIMES = frozenset(
    {
        "com.docker.backend",
        "com.docker.build",
        "com.docker.vpnkit",
        "docker-proxy",
        "orbstack helper",
        "vpnkit",
        "wslrelay",
    }
)

_INTERPRETER = re.compile(
    r"(?:pythonw?(?:\d+(?:\.\d+)*)?|node|deno|bun|java|javaw|ruby|php|perl|dotnet)", re.I
)

_UNIX_SYSTEM_PREFIXES = ("/system/", "/usr/libexec/", "/usr/sbin/", "/sbin/", "/usr/bin/", "/bin/")
_UNIX_USER_PREFIXES = ("/opt/homebrew/", "/usr/local/", "/opt/")


def is_interpreter(name: str | None) -> bool:
    """Python、Node 等脚本解释器：用户的脚本通常以它们的名义监听端口。"""
    return _INTERPRETER.fullmatch(normalize_process_name(name or "")) is not None


def normalize_process_name(name: str) -> str:
    """去掉登录 shell 的前导 `-`、`.exe` 后缀和大小写差异。"""
    value = name.strip().lstrip("-").lower()
    return value[:-4] if value.endswith(".exe") else value


def _normalize_path(path: str) -> str:
    return path.replace("\\", "/").lower()


def classify_origin(facts: ProcessFacts) -> ProcessOrigin:
    """按固定顺序判断来历；不看程序具体叫什么，只看它从哪来。"""
    name = normalize_process_name(facts.name)
    ancestors = tuple(normalize_process_name(item) for item in facts.ancestors)
    windows = facts.platform == "windows"
    if name in _CONTAINER_RUNTIMES:
        return ProcessOrigin.CONTAINER_RUNTIME
    if any(item in _TERMINALS for item in ancestors):
        return ProcessOrigin.TERMINAL
    if facts.exe is None:
        # Windows 受保护的系统进程读不到路径；其他情况无法判断。
        return ProcessOrigin.SYSTEM if windows else ProcessOrigin.UNKNOWN
    path = _normalize_path(facts.exe)
    home = _normalize_path(facts.home).rstrip("/") + "/"
    if windows:
        return _classify_windows(name, path, home, ancestors)
    return _classify_unix(name, path, home)


def _classify_windows(name: str, path: str, home: str, ancestors: tuple[str, ...]) -> ProcessOrigin:
    if path[1:].startswith(":/windows/"):
        return ProcessOrigin.SYSTEM
    if "services" in ancestors:
        return ProcessOrigin.APP_SERVICE
    if is_interpreter(name):
        return ProcessOrigin.USER_INSTALL
    if "/appdata/" in path or "/program files" in path or "/programdata/" in path:
        return ProcessOrigin.DESKTOP_APP
    if "explorer" in ancestors:
        return ProcessOrigin.DESKTOP_APP
    if path.startswith(home):
        return ProcessOrigin.USER_INSTALL
    return ProcessOrigin.UNKNOWN


def _classify_unix(name: str, path: str, home: str) -> ProcessOrigin:
    if ".app/contents/" in path:
        return ProcessOrigin.DESKTOP_APP
    if path.startswith(home):
        # ~/Library 由应用自己管理，不是用户亲手装的程序。
        return (
            ProcessOrigin.DESKTOP_APP
            if path.startswith(home + "library/")
            else ProcessOrigin.USER_INSTALL
        )
    if path.startswith(_UNIX_USER_PREFIXES):
        return ProcessOrigin.USER_INSTALL
    if path.startswith(_UNIX_SYSTEM_PREFIXES) or path.startswith("/library/apple/"):
        return ProcessOrigin.SYSTEM
    if is_interpreter(name):
        return ProcessOrigin.USER_INSTALL
    return ProcessOrigin.UNKNOWN


def current_platform() -> str:
    """返回 `windows`、`darwin` 或 `linux`。"""
    return {"win32": "windows", "darwin": "darwin"}.get(sys.platform, "linux")


def _same_process_name(actual: str, expected: str) -> bool:
    # lsof 可能截断进程名，所以只要求一方是另一方的前缀。
    left, right = normalize_process_name(actual), normalize_process_name(expected)
    return left.startswith(right) or right.startswith(left)


def read_process_facts(pid: int, expected_name: str | None = None) -> ProcessFacts | None:
    """读取一个进程的路径和父进程链；进程已退出、名字已变或完全无权读取时返回 None。"""
    try:
        process = psutil.Process(pid)
        name = process.name()
        if expected_name is not None and not _same_process_name(name, expected_name):
            return None
        try:
            exe: str | None = process.exe() or None
        except (psutil.AccessDenied, psutil.ZombieProcess, OSError):
            exe = None
        ancestors: list[str] = []
        created = process.create_time()
        current = process
        for _ in range(8):
            parent = current.parent()
            # PID 被复用时，"父进程"会比子进程晚创建，此时停止向上追。
            if parent is None or parent.create_time() > created:
                break
            ancestors.append(parent.name())
            current, created = parent, parent.create_time()
    except (psutil.Error, OSError):
        return None
    return ProcessFacts(
        platform=current_platform(),
        name=name,
        exe=exe,
        ancestors=tuple(ancestors),
        home=str(Path.home()),
    )


def read_process_origin(pid: int, expected_name: str | None = None) -> ProcessOrigin | None:
    """读取并判断来历；读不到时返回 None，由调用方按"未知"处理。"""
    facts = read_process_facts(pid, expected_name)
    return classify_origin(facts) if facts is not None else None
