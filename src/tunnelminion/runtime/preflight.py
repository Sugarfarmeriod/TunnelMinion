"""运行包、配置、目录、端口和已有实例的脱敏预检。"""

from __future__ import annotations

import hashlib
import importlib
import json
import os
import platform
import socket
import sys
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

_SUPPORTED_PLATFORMS = frozenset({"win32", "darwin"})
_EMBEDDED_MANIFEST_FILE = "runtime-package-manifest.json"
_MANIFEST_SCHEMAS = {
    "runtime-package-manifest/v1": "runtime-package-manifest-v1.schema.json",
    "runtime-package-manifest/v2": "runtime-package-manifest-v2.schema.json",
}
_ARCHITECTURE_ALIASES = {
    "amd64": "amd64",
    "x86_64": "amd64",
    "x64": "amd64",
    "arm64": "arm64",
    "aarch64": "arm64",
}


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


def _schema_for_manifest(
    manifest: dict[str, object], manifest_path: Path, schema_path: Path
) -> Path:
    """只按受信映射选择 schema，拒绝未知版本或版本/文件错配。"""
    version = manifest.get("schema_version")
    if not isinstance(version, str) or version not in _MANIFEST_SCHEMAS:
        raise ValueError("运行包 manifest 版本不受支持")
    expected = _MANIFEST_SCHEMAS[version]
    candidate = schema_path / expected if schema_path.is_dir() else schema_path
    if candidate.name != expected:
        raise ValueError("运行包 manifest 与 schema 版本不匹配")
    if candidate.resolve() == manifest_path.resolve():
        raise ValueError("运行包 manifest 不能充当 schema")
    return candidate


def _verify_v2_frontend(
    package_root: Path,
    manifest: dict[str, object],
    records: list[dict[str, object]],
) -> None:
    """交叉校验 v2 前端根、逐文件类型、数量与整体摘要。"""
    frontend = manifest.get("frontend")
    if not isinstance(frontend, dict):
        raise ValueError("v2 运行包缺少前端摘要")
    values = cast(dict[str, object], frontend)
    root_value = values.get("root")
    expected_digest = values.get("sha256")
    expected_count = values.get("file_count")
    if not isinstance(root_value, str):
        raise ValueError("v2 运行包前端根无效")
    frontend_root = _safe_package_path(package_root, root_value)
    if not frontend_root.is_dir() or not (frontend_root / "index.html").is_file():
        raise ValueError("v2 运行包前端缺少 index.html")
    prefix = f"{root_value.rstrip('/')}/"
    frontend_records = [record for record in records if record.get("type") == "frontend"]
    if any(
        not isinstance(record.get("path"), str) or not cast(str, record["path"]).startswith(prefix)
        for record in frontend_records
    ):
        raise ValueError("v2 运行包前端文件类型或根目录无效")
    paths = tuple(
        sorted(
            (path for path in frontend_root.rglob("*") if path.is_file()),
            key=lambda path: path.relative_to(frontend_root).as_posix(),
        )
    )
    digest = hashlib.sha256()
    for path in paths:
        digest.update(path.relative_to(frontend_root).as_posix().encode("utf-8"))
        digest.update(b"\0")
        digest.update(bytes.fromhex(_file_sha256(path)))
    if (
        len(paths) != expected_count
        or len(frontend_records) != expected_count
        or digest.hexdigest() != expected_digest
    ):
        raise ValueError("v2 运行包前端摘要或文件数不匹配")


def _verify_v2_semantics(
    package_root: Path,
    manifest: dict[str, object],
    records: list[dict[str, object]],
    entrypoint: str,
) -> None:
    """补足 JSON Schema 无法表达的 v2 类型与许可证交叉约束。"""
    entrypoint_records = [
        record
        for record in records
        if record.get("path") == entrypoint and record.get("type") == "entrypoint"
    ]
    if len(entrypoint_records) != 1:
        raise ValueError("v2 运行包入口类型无效")
    licenses = manifest.get("licenses")
    if not isinstance(licenses, list):
        raise ValueError("v2 运行包许可证清单无效")
    ecosystems: set[str] = set()
    for raw in cast(list[object], licenses):
        if not isinstance(raw, dict):
            raise ValueError("v2 运行包许可证记录无效")
        item = cast(dict[str, object], raw)
        ecosystem = item.get("ecosystem")
        license_name = item.get("license")
        if not isinstance(ecosystem, str) or not isinstance(license_name, str):
            raise ValueError("v2 运行包许可证来源无效")
        if "UNKNOWN" in license_name.upper():
            raise ValueError("v2 运行包包含未知许可证")
        ecosystems.add(ecosystem)
    if ecosystems != {"python", "npm"}:
        raise ValueError("v2 运行包必须同时记录 Python 与 npm 许可证来源")
    _verify_v2_frontend(package_root, manifest, records)


def canonical_runtime_architecture(value: str | None = None) -> str:
    """把双平台常见 CPU 名称收敛成可比较的稳定值。"""
    raw = (value or platform.machine()).strip().lower()
    try:
        return _ARCHITECTURE_ALIASES[raw]
    except KeyError as exc:
        raise ValueError("运行包 architecture 不受支持") from exc


def _verify_platform_and_architecture(manifest: dict[str, object]) -> None:
    """拒绝把其他操作系统或 CPU 的运行包放到当前机器执行。"""
    candidate = manifest.get("candidate")
    if not isinstance(candidate, dict):
        raise ValueError("运行包候选信息无效")
    values = cast(dict[str, object], candidate)
    candidate_platform = values.get("platform")
    candidate_architecture = values.get("architecture")
    if sys.platform not in _SUPPORTED_PLATFORMS or candidate_platform != sys.platform:
        raise ValueError("运行包 platform 与当前机器不匹配")
    if not isinstance(candidate_architecture, str) or (
        canonical_runtime_architecture(candidate_architecture) != canonical_runtime_architecture()
    ):
        raise ValueError("运行包 architecture 与当前机器不匹配")


def _verify_closed_file_set(
    package_root: Path,
    manifest_path: Path,
    listed: set[str],
) -> None:
    """逐项拒绝未入清单文件、符号链接和特殊文件。"""
    root = package_root.resolve()
    manifest = manifest_path.resolve()
    embedded_manifest = (root / _EMBEDDED_MANIFEST_FILE).resolve()
    actual: set[str] = set()
    for path in root.rglob("*"):
        if path.is_symlink():
            raise ValueError("运行包不得包含符号链接")
        if path.is_file():
            if path.resolve() == embedded_manifest:
                if (
                    manifest != embedded_manifest
                    and path.read_bytes() != manifest_path.read_bytes()
                ):
                    raise ValueError("包内清单与外部清单不一致")
                continue
            actual.add(path.relative_to(root).as_posix())
        elif not path.is_dir():
            raise ValueError("运行包不得包含特殊文件")
    if actual != listed:
        raise ValueError("运行包文件集合不闭合")


def verify_runtime_package(
    package_root: Path,
    manifest_path: Path,
    schema_path: Path,
    critical_imports: tuple[str, ...],
) -> None:
    """校验平台、CPU、闭合集合、摘要、入口和关键运行时导入。"""
    if package_root.is_symlink() or manifest_path.is_symlink() or schema_path.is_symlink():
        raise ValueError("运行包路径不得是符号链接")
    raw = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("运行包清单根节点必须是对象")
    manifest = cast(dict[str, object], raw)
    selected_schema = _schema_for_manifest(manifest, manifest_path, schema_path)
    Draft202012Validator(_load_schema(selected_schema)).validate(raw)  # pyright: ignore[reportUnknownMemberType]
    raw_files = manifest.get("files")
    if not isinstance(raw_files, list):
        raise ValueError("运行包清单缺少文件列表")
    files = cast(list[object], raw_files)
    records: list[dict[str, object]] = []
    seen: set[str] = set()
    for item in files:
        if not isinstance(item, dict):
            raise ValueError("运行包文件记录无效")
        record = cast(dict[str, object], item)
        records.append(record)
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
    if manifest.get("schema_version") == "runtime-package-manifest/v2":
        _verify_v2_semantics(package_root, manifest, records, entrypoint)
    _verify_platform_and_architecture(manifest)
    _verify_closed_file_set(package_root, manifest_path, seen)
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
        manifest_path: Path | None,
        manifest_schema_path: Path | None,
        profile_schema_path: Path,
        *,
        critical_imports: tuple[str, ...] = ("tunnelminion", "pydantic_core._pydantic_core"),
    ) -> None:
        if (manifest_path is None) != (manifest_schema_path is None):
            raise ValueError("运行包清单与 schema 必须同时提供")
        self._package_root = package_root
        self._manifest_path = manifest_path
        self._manifest_schema_path = manifest_schema_path
        self._profile_schema_path = profile_schema_path
        self._critical_imports = critical_imports

    def run(
        self,
        paths: RuntimePaths,
        *,
        active_components: frozenset[RuntimeComponent] = frozenset(),
    ) -> PreflightReport:
        """执行不启动、不停止进程且不读取 SecretStore 的启动前检查。"""
        checks: list[PreflightCheck] = []
        if self._manifest_path is None or self._manifest_schema_path is None:
            checks.append(_check("package", PreflightStatus.WARNING, "source_program_unverified"))
        else:
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
            checks.extend(self._instance_and_port_checks(profile, paths, active_components))
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
        self,
        profile: RuntimeProfile,
        paths: RuntimePaths,
        active_components: frozenset[RuntimeComponent],
    ) -> list[PreflightCheck]:
        checks: list[PreflightCheck] = []
        gateway = None
        with suppress(OSError, ValueError, json.JSONDecodeError):
            gateway = FileGatewayConfigurationRepository(paths.data_dir / "gateway.json").load()
        for component in sorted(profile.enabled_components):
            if component in active_components:
                checks.extend(
                    (
                        _check(
                            f"{component.value}-instance",
                            PreflightStatus.PASSED,
                            "owned_instance_running",
                        ),
                        _check(
                            f"{component.value}-port",
                            PreflightStatus.PASSED,
                            "owned_port_in_use",
                        ),
                    )
                )
                continue
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
