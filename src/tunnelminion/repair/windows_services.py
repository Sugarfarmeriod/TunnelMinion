"""Windows 服务的只读查询、固定的启动和停止，以及主人对单个服务的一次性授权。

授权只在主人点开关时做：弹一次 Windows 管理员确认，用 `sc.exe sdset` 给当前用户加上启停
这一个服务的权限（关掉时去掉）。TunnelMinion 自己始终以普通账户运行。
"""

from __future__ import annotations

import re
import subprocess
import sys
import time
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any, Literal, cast

import psutil

from tunnelminion.platforms.windows.system import (
    CommandResult,
    CommandRunner,
    SubprocessCommandRunner,
)
from tunnelminion.repair.contracts import (
    WINDOWS_SERVICE_NAME_PATTERN,
    RepairCommand,
    WindowsServiceInfo,
)
from tunnelminion.repair.processes import redact_log_text

_NAME = re.compile(WINDOWS_SERVICE_NAME_PATTERN)
_SDDL = re.compile(r"^[A-Za-z0-9;:()\-]+$")
_SID = re.compile(r"^S-1-[0-9-]+$")
# 启动、停止、查询状态和读权限：只够启停这一个服务。
_GRANT_RIGHTS = "RPWPLCRC"
_GRANT_CACHE_SECONDS = 60.0
_START_TYPES: dict[str, Literal["automatic", "manual", "disabled"]] = {
    "automatic": "automatic",
    "manual": "manual",
    "disabled": "disabled",
}


def binary_from_command_line(command: str) -> str:
    """服务配置里的启动命令去掉引号和参数，只留可执行文件路径。"""
    value = command.strip()
    if value.startswith('"'):
        return value[1:].split('"', 1)[0]
    lowered = value.casefold()
    end = lowered.find(".exe")
    return value[: end + 4] if end >= 0 else value.split(" ", 1)[0]


def grant_ace(sid: str) -> str:
    return f"(A;;{_GRANT_RIGHTS};;;{sid})"


def has_grant(sddl: str, sid: str) -> bool:
    """当前用户有没有一条允许启动和停止的权限。"""
    for rights, trustee in re.findall(r"\(A;[^;]*;([A-Z]+);[^;]*;[^;]*;([^)]*)\)", sddl):
        pairs = {rights[index : index + 2] for index in range(0, len(rights), 2)}
        if trustee == sid and {"RP", "WP"} <= pairs:
            return True
    return False


def with_grant(sddl: str, sid: str, *, granted: bool) -> str:
    """加上或去掉我们加的那一条；加在访问控制列表末尾、审计部分之前。"""
    ace = grant_ace(sid)
    sddl = sddl.replace(ace, "")
    if not granted:
        return sddl
    audit = sddl.find("S:")
    return sddl + ace if audit < 0 else sddl[:audit] + ace + sddl[audit:]


class UnsupportedWindowsServices:
    """不是 Windows 时：认不出任何服务，修法不可用。"""

    def unsupported_reason(self) -> str | None:
        return "只有 Windows 上才有 Windows 服务这种修法。"

    def services_for_pids(self, pids: frozenset[int]) -> dict[int, str]:
        return {}

    def inspect(self, name: str) -> WindowsServiceInfo | None:
        return None

    async def set_granted(self, name: str, *, granted: bool) -> bool:
        return False

    async def start(self, name: str) -> RepairCommand:
        raise ValueError("unsupported")

    async def stop(self, name: str) -> RepairCommand:
        raise ValueError("unsupported")


def _psutil_service_iter() -> Any:
    """用到时才取 psutil 的 Windows 专用函数：其他平台的 psutil 没有它。"""
    return cast(Any, psutil).win_service_iter()


def _psutil_service_get(name: str) -> Any:
    return cast(Any, psutil).win_service_get(name)


class WindowsServiceManager:
    """用 psutil 读服务状态，用 `sc.exe` 读权限、启动和停止。"""

    def __init__(
        self,
        runner: CommandRunner | None = None,
        *,
        run_sync: Callable[[tuple[str, ...], float], CommandResult] | None = None,
        service_iter: Callable[[], Any] | None = None,
        service_get: Callable[[str], Any] | None = None,
        process_factory: Callable[[int], psutil.Process] = psutil.Process,
        clock: Callable[[], datetime] | None = None,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self._runner = runner or SubprocessCommandRunner()
        self._run_sync = run_sync or SubprocessCommandRunner._run_sync  # pyright: ignore[reportPrivateUsage]
        self._service_iter = service_iter or _psutil_service_iter
        self._service_get = service_get or _psutil_service_get
        self._process_factory = process_factory
        self._clock = clock or (lambda: datetime.now(UTC))
        self._monotonic = monotonic
        self._sid: str | None = None
        self._granted: dict[str, tuple[bool, float]] = {}

    def unsupported_reason(self) -> str | None:
        return None

    def services_for_pids(self, pids: frozenset[int]) -> dict[int, str]:
        if not pids:
            return {}
        by_pid: dict[int, str] = {}
        try:
            for service in self._service_iter():
                try:
                    pid = service.pid()
                except (psutil.Error, OSError):
                    continue
                if pid and _NAME.fullmatch(service.name()):
                    by_pid.setdefault(int(pid), service.name())
        except (psutil.Error, OSError):
            return {}
        result: dict[int, str] = {}
        for pid in pids:
            try:
                process = self._process_factory(pid)
                for _ in range(4):
                    if process.pid in by_pid:
                        result[pid] = by_pid[process.pid]
                        break
                    parent = process.parent()
                    if parent is None or parent.create_time() > process.create_time():
                        break
                    process = parent
            except (psutil.Error, OSError):
                continue
        return result

    def inspect(self, name: str) -> WindowsServiceInfo | None:
        if _NAME.fullmatch(name) is None:
            return None
        try:
            details = cast(dict[str, Any], self._service_get(name).as_dict())
        except (psutil.Error, OSError):
            return None
        start_type = _START_TYPES.get(str(details.get("start_type")))
        binary = binary_from_command_line(str(details.get("binpath") or ""))
        if start_type is None or not binary:
            return None
        pid = details.get("pid")
        return WindowsServiceInfo(
            name=name,
            display_name=str(details.get("display_name") or name)[:256],
            binary_path=binary[:1_024],
            start_type=start_type,
            running=details.get("status") == "running",
            pid=int(pid) if pid else None,
            granted=self._is_granted(name),
        )

    def _current_sid(self) -> str | None:
        if self._sid is None:
            try:
                result = self._run_sync(("whoami", "/user", "/fo", "csv", "/nh"), 10)
            except (OSError, subprocess.TimeoutExpired):
                return None
            sid = result.stdout.strip().rsplit(",", 1)[-1].strip().strip('"')
            if result.returncode == 0 and _SID.fullmatch(sid):
                self._sid = sid
        return self._sid

    def _read_sddl(self, name: str) -> str | None:
        try:
            result = self._run_sync(("sc.exe", "sdshow", name), 10)
        except (OSError, subprocess.TimeoutExpired):
            return None
        sddl = next((line.strip() for line in result.stdout.splitlines() if line.strip()), "")
        return sddl if result.returncode == 0 and _SDDL.fullmatch(sddl) else None

    def _is_granted(self, name: str) -> bool:
        cached = self._granted.get(name)
        now = self._monotonic()
        if cached is not None and now - cached[1] < _GRANT_CACHE_SECONDS:
            return cached[0]
        sid, sddl = self._current_sid(), self._read_sddl(name)
        granted = sid is not None and sddl is not None and has_grant(sddl, sid)
        self._granted[name] = (granted, now)
        return granted

    async def set_granted(self, name: str, *, granted: bool) -> bool:
        sid, sddl = self._current_sid(), self._read_sddl(name)
        if _NAME.fullmatch(name) is None or sid is None or sddl is None:
            return False
        updated = with_grant(sddl, sid, granted=granted)
        self._granted.pop(name, None)
        if updated == sddl:
            return True
        if _SDDL.fullmatch(updated) is None:
            return False
        # 服务名和权限串都只含受限字符，可以安全放进单引号。
        script = (
            "$p = Start-Process -FilePath sc.exe "
            f"-ArgumentList 'sdset','{name}','{updated}' "
            "-Verb RunAs -Wait -PassThru -WindowStyle Hidden; exit $p.ExitCode"
        )
        try:
            result = await self._runner.run(
                ("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script), 120
            )
        except (OSError, subprocess.TimeoutExpired):
            return False
        self._granted.pop(name, None)
        return result.returncode == 0 and self._is_granted(name) is granted

    async def start(self, name: str) -> RepairCommand:
        return await self._execute("start", name)

    async def stop(self, name: str) -> RepairCommand:
        return await self._execute("stop", name)

    async def _execute(self, action: str, name: str) -> RepairCommand:
        if _NAME.fullmatch(name) is None:
            raise ValueError("服务名无效")
        argv = ("sc.exe", action, name)
        started_at = self._clock()
        exit_code: int | None = None
        try:
            result = await self._runner.run(argv, 60)
            exit_code = result.returncode
            output = result.stdout + result.stderr
        except (OSError, subprocess.TimeoutExpired) as exc:
            output = str(exc)
        return RepairCommand(
            argv=argv,
            exit_code=exit_code,
            output_excerpt=redact_log_text(output)[-2000:],
            started_at=started_at,
            finished_at=self._clock(),
        )


def default_windows_services() -> UnsupportedWindowsServices | WindowsServiceManager:
    return WindowsServiceManager() if sys.platform == "win32" else UnsupportedWindowsServices()
