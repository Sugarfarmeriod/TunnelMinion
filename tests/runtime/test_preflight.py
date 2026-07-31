"""运行包与节点启动预检测试。"""

from __future__ import annotations

import asyncio
import hashlib
import json
import socket
from pathlib import Path

import httpx
import pytest
from jsonschema.exceptions import ValidationError as JsonSchemaValidationError

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
            "platform": "win32",
            "architecture": "amd64",
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


@pytest.mark.parametrize(
    "manifest,error",
    [
        ([], "根节点"),
        ({}, "缺少文件列表"),
        ({"files": ["bad"], "entrypoint": "app"}, "文件记录无效"),
        (
            {
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
    permissive_schema = tmp_path / "schema.json"
    permissive_schema.write_text("{}", encoding="utf-8")
    with pytest.raises(ValueError, match=error):
        verify_runtime_package(package_root, manifest_path, permissive_schema, ())


def test_manifest_rejects_non_object_schema_and_package_root_path(tmp_path: Path) -> None:
    package_root, manifest_path = _package(tmp_path)
    list_schema = tmp_path / "schema.json"
    list_schema.write_text("[]", encoding="utf-8")
    with pytest.raises(ValueError, match="schema 根节点"):
        verify_runtime_package(package_root, manifest_path, list_schema, ())

    permissive_schema = tmp_path / "permissive.json"
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
    preflight._manifest_path.write_text("{}", encoding="utf-8")  # pyright: ignore[reportPrivateUsage]
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
