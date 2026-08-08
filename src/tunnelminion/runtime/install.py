"""版本化运行包的安装、切换、失败切回和保留数据移除。"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
from enum import StrEnum
from pathlib import Path
from typing import Protocol, Self, cast
from uuid import uuid4

from platformdirs import user_data_path
from pydantic import BaseModel, ConfigDict, Field, JsonValue, model_validator

from tunnelminion.runtime.preflight import verify_runtime_package
from tunnelminion.runtime.profile import (
    atomic_write_private,
    ensure_program_data_separation,
    prepare_private_directory,
)

INSTALL_STATE_VERSION = "runtime-install/v1"
INSTALL_STATE_FILE = "runtime-install.json"
PACKAGE_MANIFEST_FILE = "runtime-package-manifest.json"
PACKAGE_SCHEMA_RELATIVE = Path("schemas/runtime-package-manifest-v1.schema.json")
_PACKAGE_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{0,159}$")


class InstalledPackage(BaseModel):
    """安装根目录内可证明归属的一个程序版本。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    package_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{0,159}$")
    application_version: str = Field(min_length=1, max_length=80)
    source_revision: str = Field(pattern="^[0-9a-f]{40}$")
    source_tree_sha256: str = Field(pattern="^[0-9a-f]{64}$")
    manifest_sha256: str = Field(pattern="^[0-9a-f]{64}$")
    program_directory: str


class RuntimeInstallState(BaseModel):
    """只包含程序版本指针和数据目录摘要的非秘密安装状态。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = Field(default=INSTALL_STATE_VERSION, frozen=True)
    data_dir_sha256: str = Field(pattern="^[0-9a-f]{64}$")
    current_package_id: str | None = None
    previous_package_id: str | None = None
    packages: tuple[InstalledPackage, ...] = ()

    @model_validator(mode="after")
    def validate_contract(self) -> Self:
        if self.schema_version != INSTALL_STATE_VERSION:
            raise ValueError("安装状态版本不受支持")
        ids = {item.package_id for item in self.packages}
        if len(ids) != len(self.packages):
            raise ValueError("安装状态包含重复程序版本")
        if self.current_package_id is not None and self.current_package_id not in ids:
            raise ValueError("当前程序版本不存在")
        if self.previous_package_id is not None and self.previous_package_id not in ids:
            raise ValueError("上一程序版本不存在")
        return self


class SwitchOutcome(StrEnum):
    """版本切换的稳定结果。"""

    ACTIVATED = "activated"
    ROLLED_BACK = "rolled-back"


class SwitchResult(BaseModel):
    """不包含数据或秘密正文的版本切换摘要。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    outcome: SwitchOutcome
    current_package_id: str
    attempted_package_id: str


class StoppedGuard(Protocol):
    """切换前后确认已无受管组件运行。"""

    def __call__(self) -> bool: ...


class PackageHealth(Protocol):
    """由调用方手动启动候选后返回整体健康结论。"""

    def __call__(self, program_dir: Path) -> bool: ...


def default_runtime_install_root() -> Path:
    """返回与持久数据目录不同的当前账户程序安装根目录。"""
    return Path(user_data_path("TunnelMinionRuntime", "TunnelMinion")).resolve()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _package_directory(package_id: str) -> str:
    """生成固定长度目录名，避免 Windows 深层依赖超过路径限制。"""
    digest = hashlib.sha256(package_id.encode()).hexdigest()
    return f"pkg-{digest[:24]}"


class RuntimePackageInstaller:
    """只操作版本化程序目录和非秘密安装元数据。"""

    def __init__(self, install_root: Path, data_dir: Path) -> None:
        self._install_root = install_root.expanduser().resolve()
        self._data_dir = data_dir.expanduser().resolve()
        ensure_program_data_separation(self._install_root, self._data_dir)
        self._versions = self._install_root / "versions"
        self._state_path = self._install_root / INSTALL_STATE_FILE

    def load(self) -> RuntimeInstallState:
        """读取安装状态；首次使用时返回空状态。"""
        if not self._state_path.exists():
            return RuntimeInstallState(data_dir_sha256=self._data_dir_sha256())
        state = RuntimeInstallState.model_validate_json(
            self._state_path.read_text(encoding="utf-8")
        )
        if state.data_dir_sha256 != self._data_dir_sha256():
            raise ValueError("安装状态属于另一个数据目录")
        return state

    def stage(self, package_root: Path, manifest_path: Path) -> InstalledPackage:
        """验证并并行复制一个新版本，不改变当前版本指针。"""
        source = package_root.resolve()
        manifest_source = manifest_path.resolve()
        schema = source / PACKAGE_SCHEMA_RELATIVE
        verify_runtime_package(source, manifest_source, schema, ("tunnelminion",))
        manifest = cast(
            dict[str, JsonValue], json.loads(manifest_source.read_text(encoding="utf-8"))
        )
        candidate = cast(dict[str, JsonValue], manifest["candidate"])
        build = cast(dict[str, JsonValue], manifest["build"])
        package_id = cast(str, candidate["id"])
        if _PACKAGE_ID.fullmatch(package_id) is None:
            raise ValueError("运行包 ID 无效")
        program_directory = f"versions/{_package_directory(package_id)}"
        target = self._install_root / program_directory
        manifest_sha256 = _sha256(manifest_source)
        existing = next(
            (item for item in self.load().packages if item.package_id == package_id), None
        )
        if existing is not None:
            if existing.manifest_sha256 != manifest_sha256 or not target.is_dir():
                raise ValueError("同名运行包与已安装清单不一致")
            return existing

        prepare_private_directory(self._versions)
        staging = self._versions / f".stage-{uuid4().hex[:12]}"
        installed = False
        try:
            shutil.copytree(source, staging, copy_function=shutil.copy2)
            shutil.copy2(manifest_source, staging / PACKAGE_MANIFEST_FILE)
            verify_runtime_package(
                staging,
                staging / PACKAGE_MANIFEST_FILE,
                staging / PACKAGE_SCHEMA_RELATIVE,
                (),
            )
            os.replace(staging, target)
            installed = True

            record = InstalledPackage(
                package_id=package_id,
                application_version=cast(str, candidate["application_version"]),
                source_revision=cast(str, build["source_revision"]),
                source_tree_sha256=cast(str, build["source_tree_sha256"]),
                manifest_sha256=manifest_sha256,
                program_directory=program_directory,
            )
            state = self.load()
            self._save(state.model_copy(update={"packages": (*state.packages, record)}))
        except BaseException:
            if staging.exists():
                shutil.rmtree(staging)
            if installed and target.exists():
                shutil.rmtree(target)
            raise
        return record

    def activate(self, package_id: str, stopped: StoppedGuard) -> RuntimeInstallState:
        """仅在组件已手工停止时原子切换当前程序指针。"""
        if not stopped():
            raise RuntimeError("切换前必须先手工停止所有组件")
        state = self.load()
        self._require_package(state, package_id)
        previous = (
            state.current_package_id
            if state.current_package_id != package_id
            else state.previous_package_id
        )
        updated = state.model_copy(
            update={
                "current_package_id": package_id,
                "previous_package_id": previous,
            }
        )
        self._save(updated)
        return updated

    def switch_with_health(
        self,
        package_id: str,
        stopped: StoppedGuard,
        health: PackageHealth,
    ) -> SwitchResult:
        """切换候选；健康失败且再次确认停止后只切回程序指针。"""
        before = self.load()
        previous = before.current_package_id
        activated = self.activate(package_id, stopped)
        program = self._program_dir(activated, package_id)
        if health(program):
            return SwitchResult(
                outcome=SwitchOutcome.ACTIVATED,
                current_package_id=package_id,
                attempted_package_id=package_id,
            )
        if previous is None:
            raise RuntimeError("候选不健康且没有可切回的上一版本")
        rolled_back = self.activate(previous, stopped)
        return SwitchResult(
            outcome=SwitchOutcome.ROLLED_BACK,
            current_package_id=cast(str, rolled_back.current_package_id),
            attempted_package_id=package_id,
        )

    def current_program_dir(self) -> Path | None:
        """返回当前版本目录，不解析或执行其中的命令。"""
        state = self.load()
        if state.current_package_id is None:
            return None
        return self._program_dir(state, state.current_package_id)

    def remove_program(self, stopped: StoppedGuard) -> tuple[str, ...]:
        """只移除安装状态证明属于程序的目录，保留数据目录和 SecretStore。"""
        if not stopped():
            raise RuntimeError("移除程序前必须先手工停止所有组件")
        state = self.load()
        removed: list[str] = []
        for package in state.packages:
            target = (self._install_root / package.program_directory).resolve()
            if self._versions.resolve() not in target.parents:
                raise ValueError("安装状态中的程序目录越界")
            if target.exists():
                shutil.rmtree(target)
                removed.append(package.package_id)
        self._state_path.unlink(missing_ok=True)
        if self._versions.exists() and not any(self._versions.iterdir()):
            self._versions.rmdir()
        if self._install_root.exists() and not any(self._install_root.iterdir()):
            self._install_root.rmdir()
        return tuple(removed)

    def _save(self, state: RuntimeInstallState) -> None:
        atomic_write_private(self._state_path, state.model_dump_json(indent=2))

    def _data_dir_sha256(self) -> str:
        return hashlib.sha256(str(self._data_dir).encode()).hexdigest()

    def _require_package(self, state: RuntimeInstallState, package_id: str) -> InstalledPackage:
        package = next((item for item in state.packages if item.package_id == package_id), None)
        if package is None:
            raise KeyError("runtime_package_not_installed")
        program = self._program_dir(state, package_id)
        verify_runtime_package(
            program,
            program / PACKAGE_MANIFEST_FILE,
            program / PACKAGE_SCHEMA_RELATIVE,
            (),
        )
        return package

    def _program_dir(self, state: RuntimeInstallState, package_id: str) -> Path:
        package = next(item for item in state.packages if item.package_id == package_id)
        path = (self._install_root / package.program_directory).resolve()
        if self._versions.resolve() not in path.parents:
            raise ValueError("程序目录越界")
        return path
