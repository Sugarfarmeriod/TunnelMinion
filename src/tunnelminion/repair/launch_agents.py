"""当前用户 macOS 后台服务（LaunchAgent）的只读识别和固定的 `launchctl kickstart`。

只看 `~/Library/LaunchAgents` 下直接存放、属于当前用户、组和其他人都不能写的 plist，
只在 `gui/<uid>` 域里查询和操作。plist 路径、程序路径和日志路径只在本机用于判断。
"""

from __future__ import annotations

import hashlib
import os
import plistlib
import re
import stat
import subprocess
import sys
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

import psutil

from tunnelminion.platforms.windows.system import CommandRunner
from tunnelminion.repair.contracts import (
    LAUNCH_AGENT_LABEL_PATTERN,
    LaunchAgentJob,
    LaunchAgentProblem,
    RepairCommand,
)
from tunnelminion.repair.processes import redact_log_text

LAUNCHCTL_PATH = "/bin/launchctl"
_LABEL = re.compile(LAUNCH_AGENT_LABEL_PATTERN)
_MAX_PLIST_BYTES = 256 * 1024
_MAX_PLISTS = 256
# 监听进程往上最多追这么多层父进程，找出拉起它的后台服务进程。
_MAX_ANCESTORS = 8
_PRINT_FIELD = re.compile(r"^\t(?P<name>[a-z][a-z ]*[a-z]) = (?P<value>.*)$")


@dataclass(frozen=True)
class _Plist:
    path: Path
    sha256: str
    safe: bool
    program: str | None
    log_paths: tuple[str, ...]


def _parent_pids(pid: int) -> tuple[int, ...]:
    try:
        process = psutil.Process(pid)
        created = process.create_time()
        result: list[int] = []
        for parent in process.parents()[:_MAX_ANCESTORS]:
            # 进程号被复用时"父进程"会比子进程晚创建，此时停止向上追。
            if parent.create_time() > created:
                break
            result.append(parent.pid)
            created = parent.create_time()
        return tuple(result)
    except (psutil.Error, OSError):
        return ()


def _current_uid() -> int:
    getuid = cast(Callable[[], int] | None, getattr(os, "getuid", None))
    return getuid() if getuid is not None else 0


class UnsupportedLaunchAgents:
    """不是 macOS 时：认不出任何后台服务，修法不可用。"""

    def unsupported_reason(self) -> str | None:
        return "只有 macOS 上才有后台服务（LaunchAgent）这种修法。"

    async def labels_for_pids(self, pids: frozenset[int]) -> dict[int, str]:
        return {}

    async def inspect(self, label: str) -> LaunchAgentJob | LaunchAgentProblem:
        return LaunchAgentProblem.MISSING

    async def kickstart(self, label: str, *, kill: bool = False) -> RepairCommand:
        raise ValueError("unsupported")

    def log_tail(self, job: LaunchAgentJob, *, lines: int) -> str:
        return ""


class MacLaunchAgentRuntime:
    """只读用户自己的 plist 和 `launchctl print`，执行时只有 `launchctl kickstart`。"""

    def __init__(
        self,
        runner: CommandRunner,
        *,
        uid: int | None = None,
        home: Path | None = None,
        launchctl_path: str = LAUNCHCTL_PATH,
        parent_pids: Callable[[int], tuple[int, ...]] = _parent_pids,
        lstat: Callable[[Path], os.stat_result] = os.lstat,
        clock: Callable[[], datetime] | None = None,
        platform: str = sys.platform,
    ) -> None:
        self._runner = runner
        self._uid = _current_uid() if uid is None else uid
        self._agents_dir = (Path.home() if home is None else home) / "Library" / "LaunchAgents"
        self._launchctl = launchctl_path
        self._parent_pids = parent_pids
        self._lstat = lstat
        self._clock = clock or (lambda: datetime.now(UTC))
        self._platform = platform

    @property
    def _domain(self) -> str:
        return f"gui/{self._uid}"

    def unsupported_reason(self) -> str | None:
        if self._platform != "darwin":
            return "只有 macOS 上才有后台服务（LaunchAgent）这种修法。"
        if self._uid == 0:
            return "TunnelMinion 以管理员身份运行时不修后台服务。"
        return None

    def _owned_by_user(self, info: os.stat_result) -> bool:
        return info.st_uid == self._uid and not info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)

    def _scan(self) -> dict[str, _Plist]:
        """按标签列出用户 plist；同一标签出现在多个文件里时都不认。"""
        try:
            info = self._lstat(self._agents_dir)
            if not stat.S_ISDIR(info.st_mode) or not self._owned_by_user(info):
                return {}
            paths = sorted(self._agents_dir.glob("*.plist"))[:_MAX_PLISTS]
        except OSError:
            return {}
        found: dict[str, _Plist] = {}
        duplicated: set[str] = set()
        for path in paths:
            try:
                info = self._lstat(path)
                # 符号链接和特殊文件不读内容，只按文件名记下，资格检查时说明它不合格。
                regular = stat.S_ISREG(info.st_mode) and info.st_size <= _MAX_PLIST_BYTES
                data = path.read_bytes()[:_MAX_PLIST_BYTES] if regular else b""
                value: object = plistlib.loads(data) if regular else {}
            except (OSError, ValueError, plistlib.InvalidFileException):
                continue
            if not isinstance(value, dict):
                continue
            content = cast(dict[str, object], value)
            label = content.get("Label") if regular else path.name.removesuffix(".plist")
            if not isinstance(label, str) or _LABEL.fullmatch(label) is None:
                continue
            if label in found:
                duplicated.add(label)
            found[label] = _Plist(
                path=path,
                sha256=hashlib.sha256(data).hexdigest(),
                safe=regular and self._owned_by_user(info),
                program=self._program(content),
                log_paths=tuple(
                    item
                    for name in ("StandardErrorPath", "StandardOutPath")
                    if isinstance(item := content.get(name), str) and 0 < len(item) <= 1_024
                ),
            )
        return {label: item for label, item in found.items() if label not in duplicated}

    @staticmethod
    def _program(content: dict[str, object]) -> str | None:
        program = content.get("Program")
        if isinstance(program, str) and program:
            return program[:1_024]
        arguments = content.get("ProgramArguments")
        if isinstance(arguments, list) and arguments:
            first = cast(list[object], arguments)[0]
            if isinstance(first, str) and first:
                return first[:1_024]
        return None

    async def _print(self, target: str) -> tuple[int, str] | None:
        try:
            result = await self._runner.run((self._launchctl, "print", target), 10)
        except (OSError, subprocess.TimeoutExpired):
            return None
        return result.returncode, result.stdout

    async def labels_for_pids(self, pids: frozenset[int]) -> dict[int, str]:
        if not pids or self.unsupported_reason() is not None:
            return {}
        plists = self._scan()
        if not plists:
            return {}
        printed = await self._print(self._domain)
        if printed is None or printed[0] != 0:
            return {}
        running: dict[int, str] = {}
        inside = False
        for line in printed[1].splitlines():
            if line == "\tservices = {":
                inside = True
                continue
            if inside and line.startswith("\t}"):
                break
            columns = line.split()
            if not inside or len(columns) < 3 or not columns[0].isdigit():
                continue
            pid, label = int(columns[0]), columns[-1]
            if pid > 0 and label in plists:
                running[pid] = label
        if not running:
            return {}
        labels: dict[int, str] = {}
        for pid in pids:
            for candidate in (pid, *self._parent_pids(pid)[:_MAX_ANCESTORS]):
                if candidate in running:
                    labels[pid] = running[candidate]
                    break
        return labels

    async def inspect(self, label: str) -> LaunchAgentJob | LaunchAgentProblem:
        if _LABEL.fullmatch(label) is None or self.unsupported_reason() is not None:
            return LaunchAgentProblem.MISSING
        plist = self._scan().get(label)
        if plist is None:
            return LaunchAgentProblem.MISSING
        if not plist.safe:
            return LaunchAgentProblem.UNSAFE
        if plist.program is None:
            return LaunchAgentProblem.INVALID
        printed = await self._print(f"{self._domain}/{label}")
        fields: dict[str, str] = {}
        if printed is not None and printed[0] == 0:
            for line in printed[1].splitlines():
                match = _PRINT_FIELD.match(line)
                if match is not None:
                    fields.setdefault(match.group("name"), match.group("value").strip())
        pid = fields.get("pid", "")
        exit_code = fields.get("last exit code", "")
        return LaunchAgentJob(
            label=label,
            uid=self._uid,
            plist_path=str(plist.path),
            plist_sha256=plist.sha256,
            program=plist.program,
            log_paths=plist.log_paths,
            loaded=printed is not None and printed[0] == 0,
            loaded_path=fields.get("path") or None,
            pid=int(pid) if pid.isdigit() and int(pid) > 0 else None,
            last_exit_code=(
                int(exit_code) if re.fullmatch(r"-?\d{1,10}", exit_code) is not None else None
            ),
        )

    async def kickstart(self, label: str, *, kill: bool = False) -> RepairCommand:
        if _LABEL.fullmatch(label) is None or self.unsupported_reason() is not None:
            raise ValueError("后台服务标签无效")
        argv = (
            (self._launchctl, "kickstart", "-k", f"{self._domain}/{label}")
            if kill
            else (self._launchctl, "kickstart", f"{self._domain}/{label}")
        )
        started_at = self._clock()
        exit_code: int | None = None
        try:
            result = await self._runner.run(argv, 15)
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

    def log_tail(self, job: LaunchAgentJob, *, lines: int) -> str:
        if lines <= 0:
            return ""
        parts: list[str] = []
        for raw in dict.fromkeys(job.log_paths):
            path = Path(raw)
            try:
                info = self._lstat(path)
                if (
                    not path.is_absolute()
                    or not stat.S_ISREG(info.st_mode)
                    or info.st_uid != self._uid
                ):
                    continue
                with path.open("rb") as stream:
                    stream.seek(max(0, info.st_size - 65536))
                    parts.append(stream.read(65536).decode("utf-8", errors="replace"))
            except OSError:
                continue
        text = "\n".join(parts)
        return "\n".join(redact_log_text(text).splitlines()[-lines:])[-4000:]
