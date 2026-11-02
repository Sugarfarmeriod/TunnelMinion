"""换包：停旧版、启动新版，新版起不来就退回旧版。

换包由一个独立进程执行（网页本身就是要被停掉的那个进程），也可以由命令行在前台执行。
只动程序版本指针和进程，不碰数据目录和秘密存储。
"""

from __future__ import annotations

import contextlib
import json
import os
import subprocess
import sys
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING, Protocol, cast

import psutil
from pydantic import BaseModel, ConfigDict, Field

from tunnelminion.runtime.install import (
    PACKAGE_MANIFEST_FILE,
    InstalledPackage,
    RuntimePackageInstaller,
)
from tunnelminion.runtime.profile import (
    FileRuntimeProfileRepository,
    RuntimeProfile,
    atomic_write_private,
    current_program_dir,
    prepare_private_directory,
    resolve_runtime_paths,
)

if TYPE_CHECKING:
    from tunnelminion.runtime.lifecycle import ManualLifecycleManager

UPDATE_RECORD_FILE = "update.json"
NO_REDIRECT_ENV = "TUNNELMINION_RUNTIME_NO_REDIRECT"
_START_TIMEOUT_SECONDS = 300.0


class UpdateOutcome(StrEnum):
    """一次换包的最终结果。"""

    UPDATED = "updated"
    ROLLED_BACK = "rolled_back"
    FAILED = "failed"


class UpdateRecord(BaseModel):
    """写在数据目录里的上一次换包结果，供网页重新打开后显示。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    outcome: UpdateOutcome
    from_package_id: str
    to_package_id: str
    release_tag: str | None = None
    error_code: str | None = Field(default=None, max_length=64)
    finished_at: datetime


class UpdateBusy(RuntimeError):
    """另一次更新正在进行。"""


class UpdateLock:
    """同一安装目录同一时间只允许一次更新；持有者进程已退出时接管旧锁。"""

    def __init__(self, install_root: Path) -> None:
        self._path = install_root / "update.lock"
        self._descriptor: int | None = None

    def __enter__(self) -> UpdateLock:
        prepare_private_directory(self._path.parent)
        for _attempt in range(2):
            try:
                self._descriptor = os.open(self._path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            except FileExistsError:
                if self._holder_alive():
                    raise UpdateBusy("另一次更新正在进行") from None
                self._path.unlink(missing_ok=True)
                continue
            os.write(self._descriptor, json.dumps({"pid": os.getpid()}).encode())
            return self
        raise UpdateBusy("另一次更新正在进行")

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        del exc_type, exc, traceback
        if self._descriptor is not None:
            os.close(self._descriptor)
            self._descriptor = None
            self._path.unlink(missing_ok=True)

    def _holder_alive(self) -> bool:
        try:
            pid = json.loads(self._path.read_text(encoding="utf-8")).get("pid")
        except (OSError, ValueError, AttributeError):
            return True
        return isinstance(pid, int) and pid > 0 and psutil.pid_exists(pid)


class RuntimeControl(Protocol):
    """换包时对本实例组件的停止、启动和确认。"""

    def stop(self) -> bool: ...  # pragma: no cover - Protocol 无运行时实现

    def stopped(self) -> bool: ...  # pragma: no cover - Protocol 无运行时实现

    def start(self, executable: Path) -> bool: ...  # pragma: no cover - Protocol 无运行时实现


def update_record_path(profile: RuntimeProfile) -> Path:
    """上一次换包结果的位置。"""
    return resolve_runtime_paths(profile.data_dir).state_dir / UPDATE_RECORD_FILE


def load_update_record(path: Path) -> UpdateRecord | None:
    """读取上一次换包结果；文件损坏时当作没有。"""
    try:
        return UpdateRecord.model_validate_json(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def running_package_identity(program_dir: Path | None = None) -> tuple[str, str] | None:
    """读正在运行的运行包的 ID 和构建提交；不是运行包时返回 None。"""
    program = program_dir or current_program_dir()
    try:
        raw = json.loads((program / PACKAGE_MANIFEST_FILE).read_text(encoding="utf-8"))
        manifest = cast(dict[str, dict[str, object]], raw)
        package_id = manifest["candidate"]["id"]
        revision = manifest["build"]["source_revision"]
    except (OSError, ValueError, KeyError, TypeError):
        return None
    if not isinstance(package_id, str) or not isinstance(revision, str):
        return None
    return package_id, revision


def adopt_running_package(
    installer: RuntimePackageInstaller,
    program_dir: Path | None = None,
) -> InstalledPackage:
    """确保正在运行的这一版也在版本目录里，作为换包失败时可以退回的旧版。"""
    program = (program_dir or current_program_dir()).resolve()
    manifest = program / PACKAGE_MANIFEST_FILE
    if not manifest.is_file():
        raise ValueError("当前程序不是运行包")
    return installer.stage(program, manifest)


def apply_switch(
    installer: RuntimePackageInstaller,
    control: RuntimeControl,
    target_package_id: str,
    fallback_package_id: str,
    record_path: Path,
    *,
    release_tag: str | None = None,
) -> UpdateRecord:
    """停掉当前组件，换到目标版本；目标起不来就停掉它、退回 fallback 版本再启动。"""
    target_executable = installer.executable(target_package_id)
    fallback_executable = installer.executable(fallback_package_id)

    def finish(outcome: UpdateOutcome, error_code: str | None = None) -> UpdateRecord:
        record = UpdateRecord(
            outcome=outcome,
            from_package_id=fallback_package_id,
            to_package_id=target_package_id,
            release_tag=release_tag,
            error_code=error_code,
            finished_at=datetime.now(UTC),
        )
        atomic_write_private(record_path, record.model_dump_json(indent=2))
        return record

    if not control.stop() or not control.stopped():
        # 停不干净就不换；已经停掉的组件用原来的版本拉回来。
        control.start(fallback_executable)
        return finish(UpdateOutcome.FAILED, "stop_failed")
    installer.activate(
        target_package_id,
        control.stopped,
        previous_package_id=fallback_package_id,
    )
    if control.start(target_executable):
        with contextlib.suppress(OSError, ValueError):
            installer.prune()
        return finish(UpdateOutcome.UPDATED)
    control.stop()
    if not control.stopped():
        return finish(UpdateOutcome.FAILED, "new_version_stuck")
    installer.activate(
        fallback_package_id,
        control.stopped,
        previous_package_id=target_package_id,
    )
    if control.start(fallback_executable):
        return finish(UpdateOutcome.ROLLED_BACK, "new_version_unhealthy")
    return finish(UpdateOutcome.FAILED, "rollback_failed")


class ProfileRuntimeControl:
    """真实的组件控制：停止和确认在本进程里做，启动交给目标版本自己的 `runtime start`。"""

    def __init__(
        self, profile_path: Path, *, start_timeout_seconds: float = _START_TIMEOUT_SECONDS
    ):
        self._profile_path = profile_path
        self._start_timeout = start_timeout_seconds

    def _manager(self) -> ManualLifecycleManager:
        # 延迟导入，避免命令行启动时加载整套运行时
        from tunnelminion.runtime.control import build_lifecycle_manager

        profile = FileRuntimeProfileRepository(self._profile_path, current_program_dir()).load()
        if profile is None:
            raise ValueError("runtime profile missing")
        return build_lifecycle_manager(
            profile, resolve_runtime_paths(profile.data_dir, self._profile_path)
        )

    def stop(self) -> bool:
        try:
            self._manager().stop()
        except (OSError, RuntimeError, ValueError):
            return False
        return True

    def stopped(self) -> bool:
        try:
            report = self._manager().status()
        except (OSError, RuntimeError, ValueError):
            return False
        return all(not item.process_present for item in report.components)

    def start(self, executable: Path) -> bool:
        environment = dict(os.environ)
        environment[NO_REDIRECT_ENV] = "1"
        try:
            completed = subprocess.run(
                (str(executable), "runtime", "start", "--profile", str(self._profile_path)),
                stdin=subprocess.DEVNULL,
                stdout=sys.stdout if sys.stdout is not None else subprocess.DEVNULL,
                stderr=subprocess.STDOUT,
                env=environment,
                timeout=self._start_timeout,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            return False
        return completed.returncode == 0
