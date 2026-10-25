"""只为已确认服务采集本机 Python 启动方式。"""

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
from tunnelminion.platforms.python_entrypoint import is_python_process, parse_python_entrypoint
from tunnelminion.repair.contracts import LaunchRecord, LaunchRecordStore


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


class LaunchRecorder:
    """按稳定服务身份保存变动后的启动方式，单项失败不影响观察。"""

    def __init__(
        self,
        store: LaunchRecordStore,
        *,
        reader: ProcessLaunchReader | None = None,
        clock: Callable[[], datetime] | None = None,
        own_pid: int | None = None,
    ) -> None:
        self._store = store
        self._reader = reader if reader is not None else PsutilProcessLaunchReader()
        self._clock = clock or (lambda: datetime.now(UTC))
        self._own_pid = os.getpid() if own_pid is None else own_pid

    def record(
        self, inventory: Sequence[RemoteServiceSummary], marks: Mapping[str, ServiceMark]
    ) -> int:
        written = 0
        facts_by_pid: dict[int, ProcessLaunchFacts | None] = {}
        seen: set[tuple[int, str]] = set()
        for item, key in zip(inventory, service_mark_keys(inventory), strict=True):
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
                existing = self._store.get(key)
                excluded = {"recorded_at", "process_started_at"}
                if existing is not None and existing.model_dump(
                    exclude=excluded
                ) == record.model_dump(exclude=excluded):
                    continue
                self._store.put(record)
                written += 1
            except Exception:
                continue
        return written
