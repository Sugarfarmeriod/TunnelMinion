"""只为已确认服务采集本机启动方式：Python 脚本和普通程序的启动方式，macOS 后台服务的标签
与端口，以及 Windows 服务的服务名与端口。"""

from __future__ import annotations

import os
import sys
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol

import psutil
from pydantic import AwareDatetime, BaseModel, ConfigDict, field_validator

from tunnelminion.agent.service_marks import ServiceMark, service_mark_keys
from tunnelminion.agent.service_observation import service_tier
from tunnelminion.agent.service_tiers import ServiceTier
from tunnelminion.agent.services import RemoteServiceSummary
from tunnelminion.platforms.process_origin import ProcessOrigin
from tunnelminion.platforms.python_entrypoint import is_python_process, parse_python_entrypoint
from tunnelminion.repair.contracts import (
    AnyLaunchRecord,
    LaunchAgentRecord,
    LaunchRecord,
    LaunchRecordStore,
    ProgramLaunchRecord,
    WindowsServiceRecord,
)

# 只记从终端或用户目录启动的普通程序：系统程序、桌面应用和应用自启的服务不记，也就不会去修。
_RELAUNCHABLE_ORIGINS = frozenset({ProcessOrigin.TERMINAL, ProcessOrigin.USER_INSTALL})


class ProcessLaunchFacts(BaseModel):
    """进程启动的本机事实，不含环境变量。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    interpreter: str
    arguments: tuple[str, ...]
    working_directory: str
    username: str
    started_at: AwareDatetime

    @field_validator("started_at")
    @classmethod
    def utc_started_at(cls, value: datetime) -> datetime:
        return value.astimezone(UTC)


class ProcessLaunchReader(Protocol):
    """读取一个 Python 进程的启动事实。"""

    def read(self, pid: int) -> ProcessLaunchFacts | None: ...


class PsutilProcessLaunchReader:
    """保留虚拟环境的解释器路径，不解析符号链接。"""

    def __init__(
        self,
        platform: str = sys.platform,
        process_factory: Callable[[int], psutil.Process] = psutil.Process,
    ) -> None:
        self._platform = platform
        self._process_factory = process_factory

    def read(self, pid: int) -> ProcessLaunchFacts | None:
        try:
            process = self._process_factory(pid)
            if not is_python_process(process.name()):
                return None
            command = process.cmdline()
            if not command:
                return None
            cwd = process.cwd()
            interpreter = self._interpreter(process, command, cwd)
            return ProcessLaunchFacts(
                interpreter=interpreter,
                arguments=tuple(command[1:]),
                working_directory=cwd,
                username=process.username(),
                started_at=datetime.fromtimestamp(process.create_time(), UTC),
            )
        except (psutil.Error, OSError):
            return None

    def _interpreter(self, process: psutil.Process, command: list[str], cwd: str) -> str:
        if self._platform == "win32":
            interpreter = process.exe()
            parent = process.parent()
            if (
                parent is not None
                and is_python_process(parent.name())
                and parent.cmdline()[1:] == command[1:]
            ):
                parent_interpreter = parent.exe()
                if parent_interpreter != interpreter:
                    interpreter = parent_interpreter
            return interpreter
        entry = Path(command[0])
        if entry.is_absolute():
            if entry.is_file():
                return str(entry)
        elif "/" in command[0] or "\\" in command[0]:
            entry = Path(cwd) / entry
            if entry.is_file():
                return os.path.normpath(str(entry))
        else:
            virtual_env = process.environ().get("VIRTUAL_ENV")
            if virtual_env:
                entry = Path(virtual_env) / "bin" / "python"
                if entry.is_file():
                    return str(entry)
        return process.exe()


class ProgramLaunchFacts(BaseModel):
    """普通程序启动的本机事实，不含环境变量；读不全时 `elevated` 为真。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    executable: str | None
    executable_size: int | None = None
    executable_mtime_ns: int | None = None
    arguments: tuple[str, ...] = ()
    working_directory: str | None = None
    username: str | None
    started_at: AwareDatetime
    elevated: bool = False

    @field_validator("started_at")
    @classmethod
    def utc_started_at(cls, value: datetime) -> datetime:
        return value.astimezone(UTC)


class ProgramLaunchReader(Protocol):
    """读取一个普通程序进程的启动事实。"""

    def read(self, pid: int) -> ProgramLaunchFacts | None: ...


class PsutilProgramLaunchReader:
    """当前账户读不到参数或工作目录时（例如它以管理员身份运行），只记账户和端口。"""

    def __init__(self, process_factory: Callable[[int], psutil.Process] = psutil.Process) -> None:
        self._process_factory = process_factory

    def read(self, pid: int) -> ProgramLaunchFacts | None:
        try:
            process = self._process_factory(pid)
            started_at = datetime.fromtimestamp(process.create_time(), UTC)
            try:
                username: str | None = process.username()
            except psutil.AccessDenied:
                username = None
            try:
                executable = process.exe() or None
                command = process.cmdline()
                cwd = process.cwd()
            except psutil.AccessDenied:
                return ProgramLaunchFacts(
                    executable=None, username=username, started_at=started_at, elevated=True
                )
            if executable is None or not command:
                return None
            stat = Path(executable).stat()
            return ProgramLaunchFacts(
                executable=executable,
                executable_size=stat.st_size,
                executable_mtime_ns=stat.st_mtime_ns,
                arguments=tuple(command[1:]),
                working_directory=cwd,
                username=username,
                started_at=started_at,
            )
        except (psutil.Error, OSError):
            return None


def _tcp_ports(inventory: Sequence[RemoteServiceSummary], pid: int) -> tuple[int, ...]:
    return tuple(
        sorted(
            {
                value.port
                for value in inventory
                if value.process_pid == pid and value.protocol == "tcp"
            }
        )
    )[:32]


class LaunchRecorder:
    """按稳定服务身份保存变动后的启动方式，单项失败不影响观察。"""

    def __init__(
        self,
        store: LaunchRecordStore,
        *,
        reader: ProcessLaunchReader | None = None,
        program_reader: ProgramLaunchReader | None = None,
        clock: Callable[[], datetime] | None = None,
        own_pid: int | None = None,
    ) -> None:
        self._store = store
        self._reader = reader if reader is not None else PsutilProcessLaunchReader()
        self._program_reader = (
            program_reader if program_reader is not None else PsutilProgramLaunchReader()
        )
        self._clock = clock or (lambda: datetime.now(UTC))
        self._own_pid = os.getpid() if own_pid is None else own_pid

    def _record_launch_agents(
        self,
        inventory: Sequence[RemoteServiceSummary],
        keys: Sequence[str],
        marks: Mapping[str, ServiceMark],
    ) -> int:
        """后台服务只记标签和端口；plist 和命令在生成计划时现读。"""
        ports: dict[str, set[int]] = {}
        shown: dict[str, bool] = {}
        for item, key in zip(inventory, keys, strict=True):
            label = item.launch_agent_label
            if (
                label is None
                or not key.startswith("launchd:")
                or item.protocol != "tcp"
                or item.process_pid == self._own_pid
            ):
                continue
            ports.setdefault(label, set()).add(item.port)
            shown[label] = shown.get(label, False) or service_tier(item, None) is ServiceTier.SHOW
        written = 0
        for label, values in ports.items():
            try:
                key = f"launchd:{label}"
                mark = marks.get(key)
                if not (
                    mark is ServiceMark.MINE or (shown[label] and mark is not ServiceMark.HIDDEN)
                ):
                    continue
                record = LaunchAgentRecord(
                    service_key=key,
                    label=label,
                    ports=tuple(sorted(values))[:32],
                    rule_shown=shown[label],
                    recorded_at=self._clock(),
                )
                existing = self._store.get(key)
                if existing is not None and existing.model_dump(
                    exclude={"recorded_at"}
                ) == record.model_dump(exclude={"recorded_at"}):
                    continue
                self._store.put(record)
                written += 1
            except Exception:
                continue
        return written

    def _put_changed(self, record: AnyLaunchRecord) -> int:
        """和已有记录除记录时间外完全一样时不写；返回写了几条。"""
        existing = self._store.get(record.service_key)
        if existing is not None and existing.model_dump(
            exclude={"recorded_at"}
        ) == record.model_dump(exclude={"recorded_at"}):
            return 0
        self._store.put(record)
        return 1

    def _record_programs(
        self,
        inventory: Sequence[RemoteServiceSummary],
        keys: Sequence[str],
        marks: Mapping[str, ServiceMark],
    ) -> int:
        """普通程序记启动方式；由 Windows 服务拉起的只记服务名和端口。"""
        written = 0
        seen: set[str] = set()
        for item, key in zip(inventory, keys, strict=True):
            pid = item.process_pid
            if (
                pid is None
                or pid == self._own_pid
                or key in seen
                or item.protocol != "tcp"
                or item.container_running is not None
                or not key.startswith("program:")
            ):
                continue
            try:
                mark = marks.get(key)
                rule_shown = service_tier(item, None) is ServiceTier.SHOW
                if not (
                    mark is ServiceMark.MINE or (rule_shown and mark is not ServiceMark.HIDDEN)
                ):
                    continue
                seen.add(key)
                if item.windows_service_name:
                    written += self._put_changed(
                        WindowsServiceRecord(
                            service_key=key,
                            service_name=item.windows_service_name,
                            ports=_tcp_ports(inventory, pid),
                            rule_shown=rule_shown,
                            recorded_at=self._clock(),
                        )
                    )
                    continue
                if item.origin not in _RELAUNCHABLE_ORIGINS:
                    continue
                facts = self._program_reader.read(pid)
                if facts is None:
                    continue
                written += self._put_changed(
                    ProgramLaunchRecord(
                        service_key=key,
                        executable=facts.executable,
                        executable_size=facts.executable_size,
                        executable_mtime_ns=facts.executable_mtime_ns,
                        arguments=facts.arguments,
                        working_directory=facts.working_directory,
                        ports=_tcp_ports(inventory, pid),
                        username=facts.username,
                        elevated=facts.elevated,
                        rule_shown=rule_shown,
                        process_id=pid,
                        process_started_at=facts.started_at,
                        recorded_at=self._clock(),
                    )
                )
            except Exception:
                continue
        return written

    def record(
        self, inventory: Sequence[RemoteServiceSummary], marks: Mapping[str, ServiceMark]
    ) -> int:
        written = 0
        facts_by_pid: dict[int, ProcessLaunchFacts | None] = {}
        seen: set[tuple[int, str]] = set()
        keys = service_mark_keys(inventory)
        written += self._record_launch_agents(inventory, keys, marks)
        written += self._record_programs(inventory, keys, marks)
        for item, key in zip(inventory, keys, strict=True):
            pid = item.process_pid
            if (
                not is_python_process(item.process_name)
                or pid is None
                or pid == self._own_pid
                or item.container_running is not None
                or item.protocol != "tcp"
                or not key.startswith("python:")
            ):
                continue
            try:
                mark = marks.get(key)
                rule_shown = service_tier(item, None) is ServiceTier.SHOW
                if not (
                    mark is ServiceMark.MINE or (rule_shown and mark is not ServiceMark.HIDDEN)
                ):
                    continue
                if (pid, key) in seen:
                    continue
                seen.add((pid, key))
                if pid not in facts_by_pid:
                    facts_by_pid[pid] = None
                    facts_by_pid[pid] = self._reader.read(pid)
                facts = facts_by_pid[pid]
                if facts is None:
                    continue
                entrypoint = parse_python_entrypoint([facts.interpreter, *facts.arguments])
                if entrypoint is None or any(
                    "tunnelminion" in value.lower()
                    for value in facts.arguments
                    if value.replace("\\", "/").rsplit("/", 1)[-1] == entrypoint
                ):
                    continue
                record = LaunchRecord(
                    service_key=key,
                    interpreter=facts.interpreter,
                    arguments=facts.arguments,
                    working_directory=facts.working_directory,
                    username=facts.username,
                    ports=tuple(
                        sorted(
                            {
                                value.port
                                for value in inventory
                                if value.process_pid == pid and value.protocol == "tcp"
                            }
                        )
                    ),
                    rule_shown=rule_shown,
                    process_id=pid,
                    process_started_at=facts.started_at,
                    recorded_at=self._clock(),
                )
                # 进程号和启动时间也要跟着更新：结束卡住的进程时要靠它们认准是同一个。
                written += self._put_changed(record)
            except Exception:
                continue
        return written
