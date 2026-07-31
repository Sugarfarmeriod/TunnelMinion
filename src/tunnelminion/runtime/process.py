"""跨平台 detached 进程、进程记录与操作锁。"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Protocol, Self
from uuid import UUID, uuid4

import psutil
from pydantic import BaseModel, ConfigDict, Field, model_validator

from tunnelminion.runtime.profile import (
    RuntimeComponent,
    atomic_write_private,
    prepare_private_directory,
    restrict_file_permissions,
)

PROCESS_RECORD_VERSION = "runtime-process/v1"


class ComponentLifecycle(StrEnum):
    """逐组件持久化生命周期。"""

    STARTING = "starting"
    RUNNING = "running"
    STOPPED = "stopped"
    FAILED = "failed"


class RuntimeProcessRecord(BaseModel):
    """验证 PID 所有权所需的最小非秘密记录。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = Field(default=PROCESS_RECORD_VERSION, frozen=True)
    component: RuntimeComponent
    pid: int = Field(gt=0)
    process_started_at: float = Field(gt=0)
    recorded_at: datetime
    executable: Path
    application_version: str = Field(min_length=1, max_length=80)
    data_dir_sha256: str = Field(pattern="^[0-9a-f]{64}$")
    instance_id: UUID
    lifecycle: ComponentLifecycle
    error_code: str | None = Field(default=None, min_length=1, max_length=128)

    @model_validator(mode="after")
    def validate_version(self) -> Self:
        if self.schema_version != PROCESS_RECORD_VERSION:
            raise ValueError("进程记录版本不受支持")
        return self

    @classmethod
    def starting(
        cls,
        component: RuntimeComponent,
        snapshot: ProcessSnapshot,
        application_version: str,
        data_dir: Path,
        instance_id: UUID | None = None,
    ) -> RuntimeProcessRecord:
        """从刚启动的实时进程生成绑定身份的记录。"""
        if snapshot.process_started_at is None or snapshot.executable is None:
            raise ValueError("新进程身份不可验证")
        return cls(
            component=component,
            pid=snapshot.pid,
            process_started_at=snapshot.process_started_at,
            recorded_at=datetime.now(UTC),
            executable=Path(snapshot.executable).resolve(),
            application_version=application_version,
            data_dir_sha256=hashlib.sha256(str(data_dir.resolve()).encode()).hexdigest(),
            instance_id=instance_id or uuid4(),
            lifecycle=ComponentLifecycle.STARTING,
        )


class ProcessRecordRepository:
    """按组件原子保存受限进程记录。"""

    def __init__(self, state_dir: Path) -> None:
        self._state_dir = state_dir

    def path(self, component: RuntimeComponent) -> Path:
        return self._state_dir / f"{component.value}.json"

    def load(self, component: RuntimeComponent) -> RuntimeProcessRecord | None:
        path = self.path(component)
        if not path.exists():
            return None
        return RuntimeProcessRecord.model_validate_json(path.read_text(encoding="utf-8"))

    def save(self, record: RuntimeProcessRecord) -> None:
        atomic_write_private(self.path(record.component), record.model_dump_json(indent=2))


class ProcessSnapshot(BaseModel):
    """实时进程的只读身份快照。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    pid: int = Field(gt=0)
    process_started_at: float | None = Field(default=None, gt=0)
    executable: str | None = None
    command_line: tuple[str, ...] | None = None
    running: bool = True


class ProcessAdapter(Protocol):
    """生命周期内核依赖的最小跨平台进程接口。"""

    def spawn(self, command: tuple[str, ...], log_path: Path) -> ProcessSnapshot: ...

    def inspect(self, pid: int) -> ProcessSnapshot | None: ...

    def terminate(self, pid: int) -> None: ...

    def wait(self, pid: int, timeout_seconds: float) -> bool: ...


class DetachedProcessAdapter:
    """创建脱离控制终端且不注册任何系统自启动项的子进程。"""

    def __init__(self, max_log_bytes: int = 5_000_000, log_backups: int = 3) -> None:
        if max_log_bytes < 1 or not 1 <= log_backups <= 10:
            raise ValueError("日志轮转参数无效")
        self._max_log_bytes = max_log_bytes
        self._log_backups = log_backups

    def spawn(self, command: tuple[str, ...], log_path: Path) -> ProcessSnapshot:
        prepare_private_directory(log_path.parent)
        self._rotate_log(log_path)
        log_path.touch(exist_ok=True)
        restrict_file_permissions(log_path)
        creationflags, start_new_session = detached_process_options()
        with Path(os.devnull).open("wb") as output:
            process = subprocess.Popen(
                command,
                stdin=subprocess.DEVNULL,
                stdout=output,
                stderr=subprocess.STDOUT,
                close_fds=True,
                creationflags=creationflags,
                start_new_session=start_new_session,
            )
        snapshot = self.inspect(process.pid)
        if snapshot is None:
            raise RuntimeError("子进程启动后立即退出")
        return snapshot

    def _rotate_log(self, path: Path) -> None:
        """在启动前执行固定数量的本地日志轮转。"""
        if not path.exists() or path.stat().st_size < self._max_log_bytes:
            return
        oldest = path.with_name(f"{path.name}.{self._log_backups}")
        oldest.unlink(missing_ok=True)
        for index in range(self._log_backups - 1, 0, -1):
            source = path.with_name(f"{path.name}.{index}")
            if source.exists():
                source.replace(path.with_name(f"{path.name}.{index + 1}"))
        path.replace(path.with_name(f"{path.name}.1"))

    def inspect(self, pid: int) -> ProcessSnapshot | None:
        try:
            process = psutil.Process(pid)
            return ProcessSnapshot(
                pid=pid,
                process_started_at=process.create_time(),
                executable=process.exe(),
                command_line=tuple(process.cmdline()),
                running=process.is_running() and process.status() != psutil.STATUS_ZOMBIE,
            )
        except psutil.NoSuchProcess:
            return None
        except (psutil.AccessDenied, OSError):
            return ProcessSnapshot(pid=pid)

    def terminate(self, pid: int) -> None:
        try:
            psutil.Process(pid).terminate()
        except psutil.NoSuchProcess:
            return

    def wait(self, pid: int, timeout_seconds: float) -> bool:
        try:
            psutil.Process(pid).wait(timeout=timeout_seconds)
        except psutil.NoSuchProcess:
            return True
        except psutil.TimeoutExpired:
            return False
        return True


class RuntimeOperationBusy(RuntimeError):
    """另一个 start/status/stop 操作仍持有当前 profile 锁。"""


class RuntimeOperationLock:
    """用独占文件防止多个控制命令并发改写同一状态。"""

    def __init__(self, state_dir: Path) -> None:
        self._path = state_dir / "operation.lock"
        self._descriptor: int | None = None

    def __enter__(self) -> RuntimeOperationLock:
        prepare_private_directory(self._path.parent)
        try:
            self._descriptor = os.open(
                self._path,
                os.O_CREAT | os.O_EXCL | os.O_WRONLY,
                0o600,
            )
        except FileExistsError as exc:
            raise RuntimeOperationBusy("另一个 runtime 操作正在进行") from exc
        payload = json.dumps({"pid": os.getpid(), "created_at": datetime.now(UTC).isoformat()})
        os.write(self._descriptor, payload.encode())
        os.fsync(self._descriptor)
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        del exc_type, exc, traceback
        if self._descriptor is not None:
            os.close(self._descriptor)
            self._descriptor = None
            self._path.unlink(missing_ok=True)


def runtime_identity_arguments(component: RuntimeComponent, instance_id: UUID) -> tuple[str, str]:
    """生成可由实时命令行联合验证且不含秘密的组件身份参数。"""
    return (
        f"--runtime-component={component.value}",
        f"--runtime-instance-id={instance_id}",
    )


def detached_process_options(platform_name: str | None = None) -> tuple[int, bool]:
    """返回 Windows/POSIX 的 detached 参数，不创建服务、计划任务或登录项。"""
    if (platform_name or os.name) != "nt":
        return 0, True
    flags = (
        getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        | getattr(subprocess, "DETACHED_PROCESS", 0)
        | getattr(subprocess, "CREATE_NO_WINDOW", 0)
    )
    return flags, False


def current_runtime_executable() -> Path:
    """返回当前冻结入口或解释器的绝对路径。"""
    return Path(sys.executable).resolve()
