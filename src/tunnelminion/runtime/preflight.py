"""运行包、配置、目录、端口和已有实例的脱敏预检。"""

from __future__ import annotations

import hashlib
import importlib
import json
import os
import socket
import tempfile
from contextlib import suppress
from enum import StrEnum
from pathlib import Path
from typing import cast

from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError as JsonSchemaValidationError
from pydantic import BaseModel, ConfigDict

from tunnelminion.agent.managed_node import FileManagedNodeConfigRepository
from tunnelminion.gateway.configuration import FileGatewayConfigurationRepository
from tunnelminion.model.configuration import FileModelConfigurationRepository
from tunnelminion.runtime.profile import (
    FileRuntimeProfileRepository,
    RuntimeComponent,
    RuntimePaths,
    RuntimeProfile,
)


class PreflightStatus(StrEnum):
    """单项预检的稳定状态。"""

    PASSED = "passed"
    WARNING = "warning"
    FAILED = "failed"


class PreflightCheck(BaseModel):
    """不包含配置正文或秘密的单项预检结果。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str
    status: PreflightStatus
    code: str
    port: int | None = None


class PreflightReport(BaseModel):
    """启动前确定性组件是否具备启动条件。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    deterministic_ready: bool
    checks: tuple[PreflightCheck, ...]


def _check(
    name: str, status: PreflightStatus, code: str, port: int | None = None
) -> PreflightCheck:
    return PreflightCheck(name=name, status=status, code=code, port=port)


def _load_schema(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("schema 根节点必须是对象")
    return cast(dict[str, object], value)


def _safe_package_path(package_root: Path, relative: str) -> Path:
    candidate = (package_root / relative).resolve()
    root = package_root.resolve()
    if candidate == root or root not in candidate.parents:
        raise ValueError("运行包清单路径越界")
    return candidate


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def verify_runtime_package(
    package_root: Path,
    manifest_path: Path,
    schema_path: Path,
    critical_imports: tuple[str, ...],
) -> None:
    """校验清单 schema、文件摘要、入口和关键运行时导入。"""
    raw = json.loads(manifest_path.read_text(encoding="utf-8"))
    Draft202012Validator(_load_schema(schema_path)).validate(raw)  # pyright: ignore[reportUnknownMemberType]
    if not isinstance(raw, dict):
        raise ValueError("运行包清单根节点必须是对象")
    manifest = cast(dict[str, object], raw)
    raw_files = manifest.get("files")
    if not isinstance(raw_files, list):
        raise ValueError("运行包清单缺少文件列表")
    files = cast(list[object], raw_files)
    seen: set[str] = set()
    for item in files:
        if not isinstance(item, dict):
            raise ValueError("运行包文件记录无效")
        record = cast(dict[str, object], item)
        relative = record.get("path")
        expected_hash = record.get("sha256")
        expected_size = record.get("size")
        if not isinstance(relative, str) or relative in seen:
            raise ValueError("运行包文件路径无效或重复")
        seen.add(relative)
        path = _safe_package_path(package_root, relative)
        if (
            not path.is_file()
            or path.stat().st_size != expected_size
            or _file_sha256(path) != expected_hash
        ):
            raise ValueError("运行包文件校验失败")
    entrypoint = manifest.get("entrypoint")
    if not isinstance(entrypoint, str) or entrypoint not in seen:
        raise ValueError("运行包入口未被清单覆盖")
    for module in critical_imports:
        importlib.import_module(module)


def _probe_directory_write(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    descriptor, name = tempfile.mkstemp(prefix=".runtime-preflight-", dir=path)
    temporary = Path(name)
    try:
        os.close(descriptor)
        temporary.write_bytes(b"ready")
    finally:
        temporary.unlink(missing_ok=True)


def _port_available(host: str, port: int) -> bool:
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    with socket.socket(family, socket.SOCK_STREAM) as listener:
        try:
            listener.bind((host, port))
        except OSError:
            return False
    return True


class RuntimePreflight:
    """只读取程序/配置/状态，并用可删除探针验证数据目录。"""

    def __init__(
        self,
        package_root: Path,
        manifest_path: Path,
        manifest_schema_path: Path,
        profile_schema_path: Path,
        *,
        critical_imports: tuple[str, ...] = ("tunnelminion", "pydantic_core._pydantic_core"),
    ) -> None:
        self._package_root = package_root
        self._manifest_path = manifest_path
        self._manifest_schema_path = manifest_schema_path
        self._profile_schema_path = profile_schema_path
        self._critical_imports = critical_imports

    def run(self, paths: RuntimePaths) -> PreflightReport:
        """执行不启动、不停止进程且不读取 SecretStore 的启动前检查。"""
        checks: list[PreflightCheck] = []
        try:
            verify_runtime_package(
                self._package_root,
                self._manifest_path,
                self._manifest_schema_path,
                self._critical_imports,
            )
            checks.append(_check("package", PreflightStatus.PASSED, "package_valid"))
        except (
            OSError,
            ValueError,
            ImportError,
            json.JSONDecodeError,
            JsonSchemaValidationError,
        ):
            checks.append(_check("package", PreflightStatus.FAILED, "package_invalid"))

        profile: RuntimeProfile | None = None
        try:
            profile = FileRuntimeProfileRepository(paths.profile_file, self._package_root).load()
            if profile is None:
                raise ValueError("runtime profile 不存在")
            Draft202012Validator(_load_schema(self._profile_schema_path)).validate(  # pyright: ignore[reportUnknownMemberType]
                profile.model_dump(mode="json")
            )
            if profile.data_dir.resolve() != paths.data_dir.resolve():
                raise ValueError("runtime profile 数据目录与解析结果不一致")
            checks.append(_check("profile", PreflightStatus.PASSED, "profile_valid"))
        except (OSError, ValueError, json.JSONDecodeError, JsonSchemaValidationError):
            checks.append(_check("profile", PreflightStatus.FAILED, "profile_invalid"))

        try:
            _probe_directory_write(paths.data_dir)
            checks.append(_check("data-dir", PreflightStatus.PASSED, "data_dir_writable"))
        except OSError:
            checks.append(_check("data-dir", PreflightStatus.FAILED, "data_dir_not_writable"))

        if profile is not None:
            checks.extend(self._config_checks(profile, paths))
            checks.extend(self._instance_and_port_checks(profile, paths))
        return PreflightReport(
            deterministic_ready=all(item.status is not PreflightStatus.FAILED for item in checks),
            checks=tuple(checks),
        )

    def _config_checks(self, profile: RuntimeProfile, paths: RuntimePaths) -> list[PreflightCheck]:
        checks: list[PreflightCheck] = []
        try:
            model = FileModelConfigurationRepository(paths.data_dir / "model.json").load()
            checks.append(
                _check(
                    "model-config",
                    PreflightStatus.PASSED if model is not None else PreflightStatus.WARNING,
                    "model_config_valid" if model is not None else "model_unconfigured",
                )
            )
        except (OSError, ValueError, json.JSONDecodeError):
            checks.append(_check("model-config", PreflightStatus.WARNING, "model_config_invalid"))

        try:
            managed = FileManagedNodeConfigRepository(paths.data_dir / "managed-node.json").load()
            checks.append(
                _check(
                    "managed-config",
                    PreflightStatus.PASSED if managed is not None else PreflightStatus.WARNING,
                    "managed_config_valid" if managed is not None else "managed_unconfigured",
                )
            )
        except (OSError, ValueError, json.JSONDecodeError):
            checks.append(
                _check("managed-config", PreflightStatus.FAILED, "managed_config_invalid")
            )

        try:
            gateway = FileGatewayConfigurationRepository(paths.data_dir / "gateway.json").load()
            required = RuntimeComponent.GATEWAY in profile.enabled_components
            checks.append(
                _check(
                    "gateway-config",
                    PreflightStatus.PASSED
                    if gateway is not None
                    else (PreflightStatus.FAILED if required else PreflightStatus.WARNING),
                    "gateway_config_valid"
                    if gateway is not None
                    else ("gateway_config_missing" if required else "gateway_disabled"),
                )
            )
        except (OSError, ValueError, json.JSONDecodeError):
            checks.append(
                _check("gateway-config", PreflightStatus.FAILED, "gateway_config_invalid")
            )
        return checks

    def _instance_and_port_checks(
        self, profile: RuntimeProfile, paths: RuntimePaths
    ) -> list[PreflightCheck]:
        checks: list[PreflightCheck] = []
        gateway = None
        with suppress(OSError, ValueError, json.JSONDecodeError):
            gateway = FileGatewayConfigurationRepository(paths.data_dir / "gateway.json").load()
        for component in sorted(profile.enabled_components):
            state_file = paths.state_dir / f"{component.value}.json"
            checks.append(
                _check(
                    f"{component.value}-instance",
                    PreflightStatus.FAILED if state_file.exists() else PreflightStatus.PASSED,
                    "existing_instance_record" if state_file.exists() else "no_instance_record",
                )
            )
            host, port = (
                ("127.0.0.1", profile.local_port)
                if component is RuntimeComponent.LOCAL
                else (
                    (gateway.bind.host, gateway.bind.port)
                    if gateway is not None
                    else ("127.0.0.1", 8787)
                )
            )
            available = _port_available(host, port)
            checks.append(
                _check(
                    f"{component.value}-port",
                    PreflightStatus.PASSED if available else PreflightStatus.FAILED,
                    "port_available" if available else "port_unavailable",
                    port,
                )
            )
        return checks
