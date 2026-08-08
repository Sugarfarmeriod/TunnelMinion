"""非秘密 runtime profile、平台目录和原子持久化。"""

from __future__ import annotations

import os
import sys
import tempfile
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Protocol, Self

from platformdirs import user_config_path, user_data_path
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

RUNTIME_PROFILE_VERSION = "runtime-profile/v1"
RUNTIME_PROFILE_FILE = "runtime-profile.json"
RUNTIME_DIRECTORY = "runtime"


class RuntimeComponent(StrEnum):
    """可由手动运行入口管理的独立组件。"""

    LOCAL = "local"
    GATEWAY = "gateway"


class RuntimeBudgets(BaseModel):
    """进程与外部模型探测使用的硬超时预算。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    startup_timeout_seconds: float = Field(default=30.0, ge=1.0, le=120.0)
    stable_window_seconds: float = Field(default=2.0, ge=0.1, le=30.0)
    shutdown_timeout_seconds: float = Field(default=30.0, ge=1.0, le=120.0)
    model_health_timeout_seconds: float = Field(default=2.0, ge=0.1, le=10.0)


class RuntimeProfile(BaseModel):
    """只保存路径、组件、端口和预算的版本化非秘密配置。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = Field(default=RUNTIME_PROFILE_VERSION, frozen=True)
    data_dir: Path
    enabled_components: frozenset[RuntimeComponent] = frozenset({RuntimeComponent.LOCAL})
    local_port: int = Field(default=8000, ge=1024, le=65535)
    budgets: RuntimeBudgets = RuntimeBudgets()

    @field_validator("data_dir")
    @classmethod
    def validate_data_dir(cls, value: Path) -> Path:
        """profile 只接受不含父目录跳转的绝对数据目录。"""
        if not value.is_absolute():
            raise ValueError("runtime profile 数据目录必须是绝对路径")
        if ".." in value.parts:
            raise ValueError("runtime profile 数据目录不得包含父目录跳转")
        return value

    @model_validator(mode="after")
    def validate_contract(self) -> Self:
        if self.schema_version != RUNTIME_PROFILE_VERSION:
            raise ValueError("runtime profile 版本不受支持")
        if not self.enabled_components:
            raise ValueError("runtime profile 至少启用一个组件")
        return self

    def validate_program_boundary(self, program_dir: Path) -> None:
        """拒绝程序与数据目录任一方向的包含或完全重叠。"""
        ensure_program_data_separation(program_dir, self.data_dir)


@dataclass(frozen=True)
class RuntimePaths:
    """当前账户的 profile、数据、日志和状态路径。"""

    profile_file: Path
    data_dir: Path
    log_dir: Path
    state_dir: Path


def default_runtime_data_dir() -> Path:
    """返回与既有应用完全相同的平台标准用户数据目录。"""
    return Path(user_data_path("TunnelMinion", "TunnelMinion")).resolve()


def default_runtime_profile_path() -> Path:
    """返回平台标准用户配置目录中的非秘密 profile 路径。"""
    return Path(user_config_path("TunnelMinion", "TunnelMinion")).resolve() / RUNTIME_PROFILE_FILE


def current_program_dir() -> Path:
    """返回冻结包目录；源码运行时返回已安装包的源码根目录。"""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parents[2]


def resolve_runtime_paths(
    data_dir: Path | None = None,
    profile_file: Path | None = None,
) -> RuntimePaths:
    """解析平台默认路径，并把既有显式相对 `--data-dir` 规范为绝对路径。"""
    data = (data_dir or default_runtime_data_dir()).expanduser().resolve()
    profile = (profile_file or default_runtime_profile_path()).expanduser().resolve()
    runtime = data / RUNTIME_DIRECTORY
    return RuntimePaths(
        profile_file=profile,
        data_dir=data,
        log_dir=runtime / "logs",
        state_dir=runtime / "state",
    )


def ensure_program_data_separation(program_dir: Path, data_dir: Path) -> None:
    """拒绝程序与持久数据目录重叠，避免升级或移除破坏生产数据。"""
    program = program_dir.expanduser().resolve()
    data = data_dir.expanduser().resolve()
    if program == data or program in data.parents or data in program.parents:
        raise ValueError("程序目录与数据目录不得重叠")


def _requires_explicit_permissions() -> bool:
    """POSIX 需要显式 chmod，Windows 使用当前用户目录继承 ACL。"""
    return os.name != "nt"


def _restrict_permissions(path: Path, mode: int) -> None:
    """POSIX 显式收紧权限；Windows 继承当前用户标准目录 ACL。"""
    if _requires_explicit_permissions():
        os.chmod(path, mode)


def restrict_file_permissions(path: Path) -> None:
    """把现有运行时文件权限收紧到当前账户。"""
    _restrict_permissions(path, 0o600)


def _prepare_private_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    _restrict_permissions(path, 0o700)


def prepare_private_directory(path: Path) -> None:
    """创建只供当前账户使用的运行时目录。"""
    _prepare_private_directory(path)


def _atomic_write_private(path: Path, content: str) -> None:
    """在同一目录写私有临时文件并原子替换目标。"""
    _prepare_private_directory(path.parent)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        _restrict_permissions(temporary, 0o600)
        temporary.replace(path)
        _restrict_permissions(path, 0o600)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def atomic_write_private(path: Path, content: str) -> None:
    """向同目录临时文件写入后原子替换，并收紧当前账户权限。"""
    _atomic_write_private(path, content)


class RuntimeProfileRepository(Protocol):
    """非秘密 runtime profile 仓储。"""

    def load(self) -> RuntimeProfile | None: ...

    def save(self, profile: RuntimeProfile) -> None: ...

    def delete(self) -> None: ...


class FileRuntimeProfileRepository:
    """在用户配置目录中原子保存 runtime profile。"""

    def __init__(self, path: Path, program_dir: Path | None = None) -> None:
        self._path = path
        self._program_dir = program_dir or current_program_dir()

    def load(self) -> RuntimeProfile | None:
        if not self._path.exists():
            return None
        profile = RuntimeProfile.model_validate_json(self._path.read_text(encoding="utf-8"))
        profile.validate_program_boundary(self._program_dir)
        return profile

    def save(self, profile: RuntimeProfile) -> None:
        profile.validate_program_boundary(self._program_dir)
        _atomic_write_private(self._path, profile.model_dump_json(indent=2))

    def delete(self) -> None:
        self._path.unlink(missing_ok=True)
