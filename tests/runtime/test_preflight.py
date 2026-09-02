"""运行包与节点启动预检测试。"""

from __future__ import annotations

import asyncio
import hashlib
import json
import platform
import socket
import sys
from pathlib import Path

import httpx
import pytest
from jsonschema.exceptions import ValidationError as JsonSchemaValidationError

import tunnelminion.runtime.preflight as preflight_module
from tunnelminion.agent.managed_node import FileManagedNodeConfigRepository, ManagedNodeConfig
from tunnelminion.coordinator.contracts import GatewayEndpoint
from tunnelminion.domain.identifiers import NetworkId, NodeId
from tunnelminion.domain.tools import Platform
from tunnelminion.gateway.configuration import (
    FileGatewayConfigurationRepository,
    GatewayConfiguration,
)
from tunnelminion.gateway.security import GatewayBindConfig
from tunnelminion.model.configuration import (
    FileModelConfigurationRepository,
)
from tunnelminion.model.openai_compatible import OpenAICompatibleConfig
from tunnelminion.runtime import (
    FileRuntimeProfileRepository,
    ModelHealthStatus,
    PreflightStatus,
    RuntimeComponent,
    RuntimePaths,
    RuntimePreflight,
    RuntimeProfile,
    probe_external_model,
    verify_runtime_package,
)
from tunnelminion.runtime.preflight import canonical_runtime_architecture


def _free_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def _package(tmp_path: Path) -> tuple[Path, Path]:
    root = tmp_path / "package"
    root.mkdir()
    entrypoint = root / "tunnelminion.bin"
    entrypoint.write_bytes(b"runtime")
    manifest = {
        "schema_version": "runtime-package-manifest/v1",
        "candidate": {
            "id": "onedir",
            "layout": "onedir-freeze",
            "platform": sys.platform,
            "architecture": platform.machine().lower(),
            "python_version": "3.12.11",
            "application_version": "0.1.0",
        },
        "build": {
            "source_revision": "a" * 40,
            "source_tree_sha256": "b" * 64,
            "lock_sha256": "c" * 64,
            "builder": "test",
        },
        "entrypoint": entrypoint.name,
        "entrypoint_args": [],
        "files": [
            {
                "path": entrypoint.name,
                "sha256": hashlib.sha256(b"runtime").hexdigest(),
                "size": len(b"runtime"),
            }
        ],
        "licenses": [],
    }
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    return root, manifest_path


def _v2_package(tmp_path: Path) -> tuple[Path, Path]:
    root = tmp_path / "package-v2"
    frontend = root / "ui"
    frontend.mkdir(parents=True)
    entrypoint = root / "tunnelminion.bin"
    entrypoint.write_bytes(b"runtime")
    index = frontend / "index.html"
    index.write_bytes(b"frontend")
    frontend_digest = hashlib.sha256()
    frontend_digest.update(b"index.html\0")
    frontend_digest.update(bytes.fromhex(hashlib.sha256(b"frontend").hexdigest()))
    manifest = {
        "schema_version": "runtime-package-manifest/v2",
        "candidate": {
            "id": "onedir-v2",
            "layout": "onedir-freeze",
            "platform": sys.platform,
            "architecture": canonical_runtime_architecture(),
            "python_version": "3.12.11",
            "application_version": "0.1.0",
        },
        "build": {
            "source_revision": "a" * 40,
            "source_tree_sha256": "b" * 64,
            "python_lock_sha256": "c" * 64,
            "npm_lock_sha256": "d" * 64,
            "builder": "test",
        },
        "frontend": {
            "root": "ui",
            "sha256": frontend_digest.hexdigest(),
            "file_count": 1,
        },
        "entrypoint": entrypoint.name,
        "entrypoint_args": [],
        "files": [
            {
                "path": entrypoint.name,
                "sha256": hashlib.sha256(b"runtime").hexdigest(),
                "size": len(b"runtime"),
                "type": "entrypoint",
            },
            {
                "path": "ui/index.html",
                "sha256": hashlib.sha256(b"frontend").hexdigest(),
                "size": len(b"frontend"),
                "type": "frontend",
            },
        ],
        "licenses": [
            {
                "ecosystem": "python",
                "name": "fastapi",
                "version": "1",
                "license": "MIT",
                "source": "installed-python-metadata",
            },
            {
                "ecosystem": "npm",
                "name": "react",
                "version": "1",
                "license": "MIT",
                "source": "frontend/package-lock.json",
            },
        ],
    }
    manifest_path = tmp_path / "manifest-v2.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    return root, manifest_path


def _preflight(tmp_path: Path, profile: RuntimeProfile) -> tuple[RuntimePreflight, RuntimePaths]:
    package_root, manifest_path = _package(tmp_path)
    profile_file = tmp_path / "config" / "runtime-profile.json"
    FileRuntimeProfileRepository(profile_file, package_root).save(profile)
    paths = RuntimePaths(
        profile_file=profile_file,
        data_dir=profile.data_dir,
        log_dir=profile.data_dir / "runtime" / "logs",
        state_dir=profile.data_dir / "runtime" / "state",
    )
    return (
        RuntimePreflight(
            package_root,
            manifest_path,
            Path("schemas/runtime-package-manifest-v1.schema.json"),
            Path("schemas/runtime-profile-v1.schema.json"),
            critical_imports=("tunnelminion",),
        ),
        paths,
    )


def test_manifest_verifies_hash_and_rejects_corruption(tmp_path: Path) -> None:
    package_root, manifest_path = _package(tmp_path)
    schema = Path("schemas/runtime-package-manifest-v1.schema.json")
    verify_runtime_package(package_root, manifest_path, schema, ("tunnelminion",))

    (package_root / "tunnelminion.bin").write_bytes(b"corrupt")
    with pytest.raises(ValueError, match="校验失败"):
        verify_runtime_package(package_root, manifest_path, schema, ())


def test_v2_manifest_selects_schema_directory_and_verifies_frontend(tmp_path: Path) -> None:
    package_root, manifest_path = _v2_package(tmp_path)
    verify_runtime_package(package_root, manifest_path, Path("schemas"), ())

    value = json.loads(manifest_path.read_text(encoding="utf-8"))
    value["frontend"]["sha256"] = "0" * 64
    manifest_path.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(ValueError, match="前端摘要"):
        verify_runtime_package(package_root, manifest_path, Path("schemas"), ())


def test_manifest_version_selection_fails_closed(tmp_path: Path) -> None:
    package_root, manifest_path = _v2_package(tmp_path)
    with pytest.raises(ValueError, match="版本不匹配"):
        verify_runtime_package(
            package_root,
            manifest_path,
            Path("schemas/runtime-package-manifest-v1.schema.json"),
            (),
        )

    value = json.loads(manifest_path.read_text(encoding="utf-8"))
    value["schema_version"] = "runtime-package-manifest/v99"
    manifest_path.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(ValueError, match="版本不受支持"):
        verify_runtime_package(package_root, manifest_path, Path("schemas"), ())


def test_manifest_cannot_be_used_as_its_own_schema(tmp_path: Path) -> None:
    package_root, source_manifest = _v2_package(tmp_path)
    manifest_path = tmp_path / "runtime-package-manifest-v2.schema.json"
    manifest_path.write_bytes(source_manifest.read_bytes())

    with pytest.raises(ValueError, match="不能充当 schema"):
        verify_runtime_package(package_root, manifest_path, manifest_path, ())


def test_embedded_manifest_is_not_counted_as_payload(tmp_path: Path) -> None:
    package_root, source_manifest = _v2_package(tmp_path)
    manifest_path = package_root / "runtime-package-manifest.json"
    manifest_path.write_bytes(source_manifest.read_bytes())

    verify_runtime_package(package_root, manifest_path, Path("schemas"), ())


@pytest.mark.parametrize(
    ("frontend", "error"),
    (
        (None, "缺少前端摘要"),
        ({"root": 1}, "前端根无效"),
        ({"root": "missing"}, "缺少 index.html"),
    ),
)
def test_v2_frontend_defensive_shapes_fail_closed(
    tmp_path: Path, frontend: object, error: str
) -> None:
    package_root, _ = _v2_package(tmp_path)
    manifest: dict[str, object] = {"frontend": frontend}

    with pytest.raises(ValueError, match=error):
        preflight_module._verify_v2_frontend(  # pyright: ignore[reportPrivateUsage]
            package_root, manifest, []
        )


def test_v2_frontend_rejects_typed_file_outside_root(tmp_path: Path) -> None:
    package_root, manifest_path = _v2_package(tmp_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    with pytest.raises(ValueError, match="文件类型或根目录"):
        preflight_module._verify_v2_frontend(  # pyright: ignore[reportPrivateUsage]
            package_root,
            manifest,
            [{"path": 1, "type": "frontend"}],
        )
    with pytest.raises(ValueError, match="文件类型或根目录"):
        preflight_module._verify_v2_frontend(  # pyright: ignore[reportPrivateUsage]
            package_root,
            manifest,
            [{"path": "outside.txt", "type": "frontend"}],
        )


@pytest.mark.parametrize(
    ("licenses", "error"),
    (
        (None, "许可证清单无效"),
        (["bad"], "许可证记录无效"),
        ([{"ecosystem": 1, "license": "MIT"}], "许可证来源无效"),
        ([{"ecosystem": "python", "license": 1}], "许可证来源无效"),
    ),
)
def test_v2_license_defensive_shapes_fail_closed(
    tmp_path: Path, licenses: object, error: str
) -> None:
    package_root, _ = _v2_package(tmp_path)
    manifest: dict[str, object] = {"licenses": licenses}
    records: list[dict[str, object]] = [{"path": "tunnelminion.bin", "type": "entrypoint"}]

    with pytest.raises(ValueError, match=error):
        preflight_module._verify_v2_semantics(  # pyright: ignore[reportPrivateUsage]
            package_root, manifest, records, "tunnelminion.bin"
        )


@pytest.mark.parametrize(
    ("mutation", "error"),
    (
        ("entrypoint", "入口类型"),
        ("frontend-count", "前端摘要"),
        ("unknown-license", "未知许可证"),
        ("missing-ecosystem", "许可证"),
    ),
)
def test_v2_semantic_cross_checks_fail_closed(tmp_path: Path, mutation: str, error: str) -> None:
    package_root, manifest_path = _v2_package(tmp_path)
    value = json.loads(manifest_path.read_text(encoding="utf-8"))
    if mutation == "entrypoint":
        value["files"][0]["type"] = "runtime"
    elif mutation == "frontend-count":
        value["frontend"]["file_count"] = 2
    elif mutation == "unknown-license":
        value["licenses"][0]["license"] = "UNKNOWN"
    else:
        value["licenses"][1]["ecosystem"] = "python"
    manifest_path.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(ValueError, match=error):
        verify_runtime_package(package_root, manifest_path, Path("schemas"), ())


def test_manifest_rejects_path_traversal(tmp_path: Path) -> None:
    package_root, manifest_path = _package(tmp_path)
    value = json.loads(manifest_path.read_text(encoding="utf-8"))
    value["entrypoint"] = "../outside"
    value["files"][0]["path"] = "../outside"
    manifest_path.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(JsonSchemaValidationError):
        verify_runtime_package(
            package_root,
            manifest_path,
            Path("schemas/runtime-package-manifest-v1.schema.json"),
            (),
        )


def test_manifest_rejects_unlisted_files_and_wrong_target(tmp_path: Path) -> None:
    package_root, manifest_path = _package(tmp_path)
    schema = Path("schemas/runtime-package-manifest-v1.schema.json")
    (package_root / "unlisted.txt").write_text("unexpected", encoding="utf-8")
    with pytest.raises(ValueError, match="集合不闭合"):
        verify_runtime_package(package_root, manifest_path, schema, ())
    (package_root / "unlisted.txt").unlink()

    internal_manifest = package_root / "other-manifest.json"
    internal_manifest.write_bytes(manifest_path.read_bytes())
    with pytest.raises(ValueError, match="集合不闭合"):
        verify_runtime_package(package_root, internal_manifest, schema, ())
    internal_manifest.unlink()

    value = json.loads(manifest_path.read_text(encoding="utf-8"))
    value["candidate"]["platform"] = "darwin" if sys.platform == "win32" else "win32"
    manifest_path.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(ValueError, match="platform"):
        verify_runtime_package(package_root, manifest_path, schema, ())

    value["candidate"]["platform"] = sys.platform
    value["candidate"]["architecture"] = (
        "arm64" if canonical_runtime_architecture() == "amd64" else "amd64"
    )
    manifest_path.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(ValueError, match="architecture"):
        verify_runtime_package(package_root, manifest_path, schema, ())


def test_runtime_architecture_rejects_unknown_value() -> None:
    with pytest.raises(ValueError, match="不受支持"):
        canonical_runtime_architecture("mystery-cpu")


def test_manifest_rejects_invalid_target_metadata_with_permissive_schema(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    package_root, manifest_path = _package(tmp_path)
    schema = tmp_path / "runtime-package-manifest-v1.schema.json"
    schema.write_text("{}", encoding="utf-8")
    value = json.loads(manifest_path.read_text(encoding="utf-8"))
    value["candidate"] = None
    manifest_path.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(ValueError, match="候选信息"):
        verify_runtime_package(package_root, manifest_path, schema, ())

    value["candidate"] = {
        "platform": sys.platform,
        "architecture": 123,
    }
    manifest_path.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(ValueError, match="architecture"):
        verify_runtime_package(package_root, manifest_path, schema, ())

    value["candidate"] = {
        "platform": "linux",
        "architecture": platform.machine().lower(),
    }
    manifest_path.write_text(json.dumps(value), encoding="utf-8")
    monkeypatch.setattr(preflight_module.sys, "platform", "linux")
    with pytest.raises(ValueError, match="platform"):
        verify_runtime_package(package_root, manifest_path, schema, ())


def test_manifest_rejects_symlink_and_special_file_shapes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    package_root, manifest_path = _package(tmp_path)
    schema = Path("schemas/runtime-package-manifest-v1.schema.json")
    path_type = type(package_root)
    original_is_symlink = path_type.is_symlink

    for target in (package_root, manifest_path, schema):

        def target_is_symlink(self: Path, selected: Path = target) -> bool:
            return self == selected or original_is_symlink(self)

        with monkeypatch.context() as scoped:
            scoped.setattr(
                path_type,
                "is_symlink",
                target_is_symlink,
            )
            with pytest.raises(ValueError, match="路径不得是符号链接"):
                verify_runtime_package(package_root, manifest_path, schema, ())

    entrypoint = package_root / "tunnelminion.bin"

    def entrypoint_is_symlink(self: Path) -> bool:
        return self == entrypoint or original_is_symlink(self)

    with monkeypatch.context() as scoped:
        scoped.setattr(
            path_type,
            "is_symlink",
            entrypoint_is_symlink,
        )
        with pytest.raises(ValueError, match="不得包含符号链接"):
            verify_runtime_package(package_root, manifest_path, schema, ())

    special = package_root / "special-entry"
    special.write_bytes(b"special")
    original_is_file = path_type.is_file
    original_is_dir = path_type.is_dir

    def special_is_file(self: Path) -> bool:
        return False if self == special else original_is_file(self)

    def special_is_dir(self: Path) -> bool:
        return False if self == special else original_is_dir(self)

    with monkeypatch.context() as scoped:
        scoped.setattr(
            path_type,
            "is_file",
            special_is_file,
        )
        scoped.setattr(
            path_type,
            "is_dir",
            special_is_dir,
        )
        with pytest.raises(ValueError, match="特殊文件"):
            verify_runtime_package(package_root, manifest_path, schema, ())


@pytest.mark.parametrize(
    "manifest,error",
    [
        ([], "根节点"),
        ({"schema_version": "runtime-package-manifest/v1"}, "缺少文件列表"),
        (
            {
                "schema_version": "runtime-package-manifest/v1",
                "files": ["bad"],
                "entrypoint": "app",
            },
            "文件记录无效",
        ),
        (
            {
                "schema_version": "runtime-package-manifest/v1",
                "files": [
                    {
                        "path": "app",
                        "sha256": hashlib.sha256(b"").hexdigest(),
                        "size": 0,
                    },
                    {
                        "path": "app",
                        "sha256": hashlib.sha256(b"").hexdigest(),
                        "size": 0,
                    },
                ],
                "entrypoint": "app",
            },
            "无效或重复",
        ),
        (
            {
                "schema_version": "runtime-package-manifest/v1",
                "files": [
                    {
                        "path": "app",
                        "sha256": hashlib.sha256(b"").hexdigest(),
                        "size": 0,
                    }
                ],
                "entrypoint": "other",
            },
            "入口未被清单覆盖",
        ),
    ],
)
def test_manifest_defensively_rejects_invalid_shapes(
    tmp_path: Path, manifest: object, error: str
) -> None:
    package_root = tmp_path / "package"
    package_root.mkdir()
    (package_root / "app").write_bytes(b"")
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    permissive_schema = tmp_path / "runtime-package-manifest-v1.schema.json"
    permissive_schema.write_text("{}", encoding="utf-8")
    with pytest.raises(ValueError, match=error):
        verify_runtime_package(package_root, manifest_path, permissive_schema, ())


def test_manifest_rejects_non_object_schema_and_package_root_path(tmp_path: Path) -> None:
    package_root, manifest_path = _package(tmp_path)
    list_schema = tmp_path / "runtime-package-manifest-v1.schema.json"
    list_schema.write_text("[]", encoding="utf-8")
    with pytest.raises(ValueError, match="schema 根节点"):
        verify_runtime_package(package_root, manifest_path, list_schema, ())

    permissive_schema = tmp_path / "runtime-package-manifest-v1.schema.json"
    permissive_schema.write_text("{}", encoding="utf-8")
    value = json.loads(manifest_path.read_text(encoding="utf-8"))
    value["files"][0]["path"] = "."
    value["entrypoint"] = "."
    manifest_path.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(ValueError, match="路径越界"):
        verify_runtime_package(package_root, manifest_path, permissive_schema, ())


def test_preflight_accepts_local_only_without_optional_configs(tmp_path: Path) -> None:
    profile = RuntimeProfile(data_dir=(tmp_path / "data").resolve(), local_port=_free_port())
    preflight, paths = _preflight(tmp_path, profile)
    report = preflight.run(paths)

    assert report.deterministic_ready
    assert {item.code for item in report.checks} >= {
        "package_valid",
        "profile_valid",
        "data_dir_writable",
        "model_unconfigured",
        "managed_unconfigured",
        "gateway_disabled",
        "port_available",
    }


def test_source_preflight_warns_and_accepts_owned_active_component(tmp_path: Path) -> None:
    profile = RuntimeProfile(data_dir=(tmp_path / "data").resolve(), local_port=_free_port())
    package_root, _ = _package(tmp_path)
    profile_file = tmp_path / "config" / "runtime-profile.json"
    FileRuntimeProfileRepository(profile_file, package_root).save(profile)
    paths = RuntimePaths(
        profile_file=profile_file,
        data_dir=profile.data_dir,
        log_dir=profile.data_dir / "runtime" / "logs",
        state_dir=profile.data_dir / "runtime" / "state",
    )
    preflight = RuntimePreflight(
        package_root,
        None,
        None,
        Path("schemas/runtime-profile-v1.schema.json"),
    )
    report = preflight.run(paths, active_components=frozenset({RuntimeComponent.LOCAL}))
    assert report.deterministic_ready
    assert {item.code for item in report.checks} >= {
        "source_program_unverified",
        "owned_instance_running",
        "owned_port_in_use",
    }

    with pytest.raises(ValueError, match="同时提供"):
        RuntimePreflight(
            package_root,
            tmp_path / "manifest.json",
            None,
            Path("schemas/runtime-profile-v1.schema.json"),
        )


def test_model_offline_does_not_block_deterministic_preflight(tmp_path: Path) -> None:
    data_dir = (tmp_path / "data").resolve()
    profile = RuntimeProfile(data_dir=data_dir, local_port=_free_port())
    preflight, paths = _preflight(tmp_path, profile)
    FileModelConfigurationRepository(data_dir / "model.json").save(
        OpenAICompatibleConfig(endpoint="http://offline.invalid/v1", model="fixture")
    )

    def offline(request: httpx.Request) -> httpx.Response:
        del request
        raise httpx.ConnectError("offline")

    report = preflight.run(paths)
    health = asyncio.run(
        probe_external_model(data_dir, 0.1, transport=httpx.MockTransport(offline))
    )
    assert report.deterministic_ready
    assert health.status is ModelHealthStatus.UNAVAILABLE


def test_preflight_gateway_requires_config_and_existing_instance_is_read_only(
    tmp_path: Path,
) -> None:
    profile = RuntimeProfile(
        data_dir=(tmp_path / "data").resolve(),
        local_port=_free_port(),
        enabled_components=frozenset({RuntimeComponent.LOCAL, RuntimeComponent.GATEWAY}),
    )
    preflight, paths = _preflight(tmp_path, profile)
    paths.state_dir.mkdir(parents=True)
    record = paths.state_dir / "local.json"
    record.write_text('{"pid": 1234, "token": "must-not-leak"}', encoding="utf-8")

    report = preflight.run(paths)
    serialized = report.model_dump_json()
    assert not report.deterministic_ready
    assert "gateway_config_missing" in serialized
    assert "existing_instance_record" in serialized
    assert "must-not-leak" not in serialized


def test_preflight_reports_occupied_port_without_owner_details(tmp_path: Path) -> None:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = int(listener.getsockname()[1])
        profile = RuntimeProfile(data_dir=(tmp_path / "data").resolve(), local_port=port)
        preflight, paths = _preflight(tmp_path, profile)
        report = preflight.run(paths)

    check = next(item for item in report.checks if item.name == "local-port")
    assert check.status is PreflightStatus.FAILED
    assert check.code == "port_unavailable"
    assert check.port == port


def test_preflight_reports_corrupt_manifest_profile_and_readonly_data(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    profile = RuntimeProfile(data_dir=(tmp_path / "data").resolve(), local_port=_free_port())
    preflight, paths = _preflight(tmp_path, profile)
    manifest_path = preflight._manifest_path  # pyright: ignore[reportPrivateUsage]
    assert manifest_path is not None
    manifest_path.write_text("{}", encoding="utf-8")
    paths.profile_file.write_text("{}", encoding="utf-8")

    def deny_write(path: Path) -> None:
        del path
        raise PermissionError("denied")

    monkeypatch.setattr("tunnelminion.runtime.preflight._probe_directory_write", deny_write)
    report = preflight.run(paths)
    assert {item.code for item in report.checks} == {
        "package_invalid",
        "profile_invalid",
        "data_dir_not_writable",
    }


def test_preflight_reports_missing_profile_and_path_mismatch(tmp_path: Path) -> None:
    profile = RuntimeProfile(data_dir=(tmp_path / "data").resolve(), local_port=_free_port())
    preflight, paths = _preflight(tmp_path, profile)
    paths.profile_file.unlink()
    missing = preflight.run(paths)
    assert "profile_invalid" in {item.code for item in missing.checks}

    FileRuntimeProfileRepository(paths.profile_file, tmp_path / "package").save(profile)
    mismatched = preflight.run(
        RuntimePaths(
            profile_file=paths.profile_file,
            data_dir=(tmp_path / "other-data").resolve(),
            log_dir=paths.log_dir,
            state_dir=paths.state_dir,
        )
    )
    assert "profile_invalid" in {item.code for item in mismatched.checks}


def test_preflight_reports_invalid_component_configs(tmp_path: Path) -> None:
    data_dir = (tmp_path / "data").resolve()
    profile = RuntimeProfile(data_dir=data_dir, local_port=_free_port())
    preflight, paths = _preflight(tmp_path, profile)
    data_dir.mkdir()
    for name in ("model.json", "managed-node.json", "gateway.json"):
        (data_dir / name).write_text("{}", encoding="utf-8")
    report = preflight.run(paths)
    assert {item.code for item in report.checks} >= {
        "model_config_invalid",
        "managed_config_invalid",
        "gateway_config_invalid",
    }


def test_preflight_accepts_valid_component_configs(tmp_path: Path) -> None:
    data_dir = (tmp_path / "data").resolve()
    profile = RuntimeProfile(
        data_dir=data_dir,
        local_port=_free_port(),
        enabled_components=frozenset({RuntimeComponent.LOCAL, RuntimeComponent.GATEWAY}),
    )
    preflight, paths = _preflight(tmp_path, profile)
    FileModelConfigurationRepository(data_dir / "model.json").save(
        OpenAICompatibleConfig(endpoint="http://10.77.0.2:8082/v1", model="fixture")
    )
    FileManagedNodeConfigRepository(data_dir / "managed-node.json").save(
        ManagedNodeConfig(
            coordinator_endpoint="http://10.77.0.1:8790",
            network_id=NetworkId.new(),
            node_id=NodeId.new(),
            display_name="fixture",
            platform=Platform.WINDOWS,
            gateway_endpoint=GatewayEndpoint(host="10.77.0.2", port=8787),
            pinned_fingerprints=frozenset({"a" * 64}),
        )
    )
    FileGatewayConfigurationRepository(data_dir / "gateway.json").save(
        GatewayConfiguration(bind=GatewayBindConfig(host="10.77.0.1", port=8787))
    )
    report = preflight.run(paths)
    assert {item.code for item in report.checks} >= {
        "model_config_valid",
        "managed_config_valid",
        "gateway_config_valid",
    }
