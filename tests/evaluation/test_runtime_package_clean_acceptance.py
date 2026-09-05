"""运行包 fixture、manifest 与干净环境验收脚本测试。"""

from __future__ import annotations

import hashlib
import json
import platform
import shutil
import sys
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol, cast
from uuid import uuid4

import httpx
import pytest
from fastapi.testclient import TestClient
from pydantic import JsonValue
from scripts import run_runtime_package_clean_acceptance as acceptance
from scripts.runtime_package_fixture import create_fixture_application


class ApiClient(Protocol):
    """补足 TestClient 当前缺失的严格返回类型。"""

    def get(self, url: str) -> httpx.Response: ...


def _manifest(package_root: Path, entrypoint: str = "fixture.bin") -> dict[str, JsonValue]:
    payload = (package_root / entrypoint).read_bytes()
    return {
        "schema_version": "runtime-package-manifest/v1",
        "candidate": {
            "id": "fixture-candidate",
            "layout": "onedir-freeze",
            "platform": sys.platform,
            "architecture": platform.machine().lower(),
            "python_version": "3.12.0",
            "application_version": "0.1.0",
        },
        "build": {
            "source_revision": "a" * 40,
            "source_tree_sha256": "c" * 64,
            "lock_sha256": "b" * 64,
            "builder": "test",
        },
        "entrypoint": entrypoint,
        "entrypoint_args": [],
        "files": [
            {
                "path": entrypoint,
                "sha256": hashlib.sha256(payload).hexdigest(),
                "size": len(payload),
            }
        ],
        "licenses": [],
    }


def test_fixture_builds_real_local_and_gateway_apps(tmp_path: Path) -> None:
    local = cast(
        ApiClient,
        TestClient(
            create_fixture_application("local", tmp_path / "local"),
            base_url="http://127.0.0.1",
        ),
    )
    local_status = local.get("/__runtime_package_fixture__")
    assert local_status.status_code == 200
    assert local_status.json()["component"] == "local"
    assert len(local_status.json()["native_extensions"]) == 5
    assert local_status.json()["keyring_backend"].startswith("keyring.backends.")
    assert local.get("/api/resources/health").status_code == 200

    gateway = cast(
        ApiClient,
        TestClient(create_fixture_application("gateway", tmp_path / "gateway")),
    )
    gateway_status = gateway.get("/__runtime_package_fixture__")
    assert gateway_status.status_code == 200
    assert gateway_status.json()["component"] == "gateway"
    assert len(gateway_status.json()["native_extensions"]) == 5
    assert gateway.get("/v1/capabilities").status_code == 401

    with pytest.raises(ValueError, match="未知运行包 fixture 组件"):
        create_fixture_application("unknown", tmp_path / "unknown")


def test_manifest_requires_valid_platform_hash_and_confined_paths(tmp_path: Path) -> None:
    package_root = tmp_path / "package"
    package_root.mkdir()
    (package_root / "fixture.bin").write_bytes(b"fixture")
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(_manifest(package_root)), encoding="utf-8")
    schema = Path("schemas/runtime-package-manifest-v1.schema.json")

    loaded = acceptance.load_and_verify_manifest(package_root, manifest_path, schema)
    assert loaded["schema_version"] == acceptance.MANIFEST_VERSION

    extra = package_root / "unexpected.bin"
    extra.write_bytes(b"unexpected")
    with pytest.raises(ValueError, match="集合不闭合"):
        acceptance.load_and_verify_manifest(package_root, manifest_path, schema)
    extra.unlink()

    wrong_architecture = _manifest(package_root)
    candidate = cast(dict[str, JsonValue], wrong_architecture["candidate"])
    candidate["architecture"] = "arm64" if platform.machine().lower() != "arm64" else "amd64"
    manifest_path.write_text(json.dumps(wrong_architecture), encoding="utf-8")
    with pytest.raises(ValueError, match="architecture"):
        acceptance.load_and_verify_manifest(package_root, manifest_path, schema)

    wrong_platform = _manifest(package_root)
    candidate = cast(dict[str, JsonValue], wrong_platform["candidate"])
    candidate["platform"] = "darwin" if sys.platform == "win32" else "win32"
    manifest_path.write_text(json.dumps(wrong_platform), encoding="utf-8")
    with pytest.raises(ValueError, match="platform"):
        acceptance.load_and_verify_manifest(package_root, manifest_path, schema)

    bad_hash = _manifest(package_root)
    files = cast(list[dict[str, JsonValue]], bad_hash["files"])
    files[0]["sha256"] = "0" * 64
    manifest_path.write_text(json.dumps(bad_hash), encoding="utf-8")
    with pytest.raises(ValueError, match="文件校验失败"):
        acceptance.load_and_verify_manifest(package_root, manifest_path, schema)

    with pytest.raises(ValueError, match="逃逸运行包"):
        acceptance._safe_package_path(  # pyright: ignore[reportPrivateUsage]
            package_root, "../outside"
        )


def test_environment_and_path_checks_remove_development_injection(tmp_path: Path) -> None:
    cleaned = acceptance.sanitized_environment(
        {
            "KEEP": "yes",
            "PYTHONHOME": "bad",
            "PYTHONPATH": "bad",
            "VIRTUAL_ENV": "bad",
            "CONDA_PREFIX": "bad",
            "UV_PROJECT": "bad",
        }
    )
    assert cleaned == {"KEEP": "yes", "PYTHONNOUSERSITE": "1"}
    isolated = acceptance.isolated_product_environment(
        tmp_path / "empty-path", {"PATH": "node-bin", "PYTHONPATH": "bad"}
    )
    assert isolated["PATH"] == str((tmp_path / "empty-path").resolve())
    assert "PYTHONPATH" not in isolated
    assert isolated["HTTP_PROXY"] == "http://127.0.0.1:9"
    assert isolated["NO_PROXY"] == "127.0.0.1,localhost"
    assert acceptance._source_like_entries(  # pyright: ignore[reportPrivateUsage]
        [
            {"path": "_internal/app.py"},
            {"path": "frontend/src/App.tsx"},
            {"path": "_internal/app.js"},
        ]
    ) == ["_internal/app.py", "frontend/src/App.tsx"]
    forbidden = tmp_path / "repo"
    assert (
        acceptance._path_hits(  # pyright: ignore[reportPrivateUsage]
            [str(forbidden / "src"), ""], [forbidden]
        )
        == 1
    )
    assert (
        acceptance._path_hits(  # pyright: ignore[reportPrivateUsage]
            [str(tmp_path / "clean")], [forbidden]
        )
        == 0
    )

    package_root = tmp_path / "package"
    package_root.mkdir()
    packaged_script = package_root / "fixture.py"
    packaged_script.write_text("pass\n", encoding="utf-8")
    resolved_args = acceptance._resolve_entrypoint_args(  # pyright: ignore[reportPrivateUsage]
        package_root,
        ("fixture.py", "--flag"),
        {"fixture.py"},
    )
    assert resolved_args == [str(packaged_script.resolve()), "--flag"]
    expected_keyring_prefix = (
        "keyring.backends.Windows." if sys.platform == "win32" else "keyring.backends.macOS."
    )
    assert acceptance._is_native_keyring_backend(  # pyright: ignore[reportPrivateUsage]
        expected_keyring_prefix + "Native"
    )
    assert not acceptance._is_native_keyring_backend(  # pyright: ignore[reportPrivateUsage]
        "keyring.backends.fail.Keyring"
    )


def test_runtime_package_evidence_is_minimal_and_requires_sections() -> None:
    evidence = acceptance._runtime_package_evidence(  # pyright: ignore[reportPrivateUsage]
        {
            "local": {
                "package": {
                    "kind": "standalone",
                    "version": "0.1.0",
                    "manifest_schema": "runtime-package-manifest/v2",
                    "private_path": "must-not-escape",
                }
            }
        }
    )
    assert evidence == {
        "kind": "standalone",
        "version": "0.1.0",
        "manifest_schema": "runtime-package-manifest/v2",
    }
    with pytest.raises(ValueError, match="local"):
        acceptance._runtime_package_evidence({})  # pyright: ignore[reportPrivateUsage]
    with pytest.raises(ValueError, match="package"):
        acceptance._runtime_package_evidence(  # pyright: ignore[reportPrivateUsage]
            {"local": {}}
        )


@pytest.mark.parametrize(
    ("destroy_data", "raise_on_repeat", "expected_passed"),
    (
        (False, False, True),
        (True, False, False),
        (False, True, False),
    ),
)
def test_product_lifecycle_uses_only_public_commands_and_preserves_data(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    destroy_data: bool,
    raise_on_repeat: bool,
    expected_passed: bool,
) -> None:
    package_root = tmp_path / "program"
    package_root.mkdir()
    entrypoint = package_root / "tunnelminion.bin"
    entrypoint.write_bytes(b"runtime")
    (package_root / acceptance.INSTALLED_MANIFEST_FILE).write_text("{}", encoding="utf-8")
    data_dir = tmp_path / "data"
    working_dir = tmp_path / "work"
    working_dir.mkdir()
    commands: list[tuple[str, ...]] = []
    stopped = False

    def runtime_body(state: str) -> dict[str, JsonValue]:
        return {
            "runtime": {
                "state": state,
                "components": [
                    {"component": "gateway", "state": state, "pid": 101},
                    {"component": "local", "state": state, "pid": 102},
                ],
            }
        }

    def run_public_command(
        actual_entrypoint: Path,
        arguments: Sequence[str],
        actual_working_dir: Path,
        environment: Mapping[str, str],
        input_text: str | None = None,
    ) -> tuple[int, dict[str, JsonValue] | None, str]:
        nonlocal stopped
        assert actual_entrypoint == entrypoint
        assert actual_working_dir == working_dir
        assert environment["PATH"] == str((working_dir / "empty-path").resolve())
        command = tuple(arguments)
        commands.append(command)
        if command[0] == "gateway-configure":
            assert input_text is not None and input_text.startswith("tmn_")
            secrets = data_dir / "gateway-secrets"
            secrets.mkdir(parents=True)
            (data_dir / "gateway.json").write_bytes(b"gateway-configuration")
            (secrets / "credentials.json").write_bytes(b"encrypted-test-credential")
            body: dict[str, JsonValue] = {"local_node_id": "test"}
        elif command[:2] == ("runtime", "configure"):
            body = {"schema_version": "runtime-profile/v1"}
        elif command[:2] == ("runtime", "start"):
            if raise_on_repeat and sum(item[:2] == ("runtime", "start") for item in commands) == 2:
                raise OSError("simulated command failure")
            body = runtime_body("running")
        elif command[:2] == ("runtime", "status"):
            body = runtime_body("stopped" if stopped else "running")
        elif command[:2] == ("runtime", "stop"):
            stopped = True
            body = runtime_body("stopped")
        elif command[:2] == ("runtime-package", "stage"):
            body = {"status": "staged", "package_id": "candidate"}
        elif command[:2] == ("runtime-package", "activate"):
            body = {"status": "activated", "current_package_id": "candidate"}
        elif command[:2] == ("runtime-package", "status"):
            body = {"status": "ready", "current_package_id": "candidate"}
        else:
            if destroy_data:
                shutil.rmtree(data_dir)
                (data_dir / "gateway-secrets").mkdir(parents=True)
            body = {
                "status": "removed",
                "data_preserved": True,
                "secret_store_preserved": True,
            }
        return 0, body, json.dumps(body)

    def read_json(url: str, timeout_seconds: float) -> tuple[int, dict[str, JsonValue]]:
        del timeout_seconds
        if url.endswith("/api/resources/overview"):
            return 200, {
                "local": {
                    "package": {
                        "kind": "standalone",
                        "version": "0.1.0",
                        "manifest_schema": "runtime-package-manifest/v2",
                    }
                }
            }
        assert url.endswith("/v1/capabilities")
        return 401, {"detail": "unauthorized"}

    def wait_for_status(url: str, expected: int, timeout_seconds: float) -> int:
        del url, timeout_seconds
        return expected

    monkeypatch.setattr(acceptance, "_run_public_command", run_public_command)
    monkeypatch.setattr(acceptance, "_available_port", lambda: 55122)
    monkeypatch.setattr(acceptance, "_private_host_and_port", lambda: ("10.0.0.8", 55123))
    monkeypatch.setattr(acceptance, "_wait_for_status", wait_for_status)
    monkeypatch.setattr(acceptance, "_read_json", read_json)

    report = acceptance.run_product_lifecycle(
        entrypoint,
        package_root,
        "candidate",
        data_dir,
        working_dir,
    )

    assert report["passed"] is expected_passed
    assert report["public_cli"] is True
    assert report["idempotent_start"] is (not raise_on_repeat)
    assert report["data_preserved"] is (not destroy_data)
    assert report["secret_store_preserved"] is (not destroy_data)
    assert report["process_cleanup_confirmed"] is True
    data_evidence = cast(dict[str, JsonValue], report["data_evidence"])
    secret_evidence = cast(dict[str, JsonValue], report["secret_store_evidence"])
    assert (data_evidence["before"] == data_evidence["after"]) is (not destroy_data)
    assert (secret_evidence["before"] == secret_evidence["after"]) is (not destroy_data)
    assert stopped is True
    assert not any("runtime-child" in command for command in commands)
    assert [command[:2] for command in commands[1:]] == [
        ("runtime", "configure"),
        ("runtime", "start"),
        ("runtime", "start"),
        ("runtime", "status"),
        ("runtime", "stop"),
        ("runtime", "status"),
        ("runtime-package", "stage"),
        ("runtime-package", "activate"),
        ("runtime-package", "status"),
        ("runtime-package", "remove"),
    ]


@pytest.mark.parametrize("owned", (True, False))
def test_cleanup_terminates_only_exact_runtime_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    owned: bool,
) -> None:
    data_dir = tmp_path / "data"
    state = data_dir / "runtime" / "state"
    state.mkdir(parents=True)
    entrypoint = tmp_path / "program" / "tunnelminion.bin"
    entrypoint.parent.mkdir()
    entrypoint.write_bytes(b"runtime")
    instance_id = uuid4()
    record = {
        "schema_version": "runtime-process/v1",
        "component": "local",
        "pid": 4321,
        "process_started_at": 123.0,
        "recorded_at": datetime.now(UTC).isoformat(),
        "executable": str(entrypoint.resolve()),
        "application_version": "0.1.0",
        "data_dir_sha256": hashlib.sha256(str(data_dir.resolve()).encode()).hexdigest(),
        "instance_id": str(instance_id),
        "lifecycle": "running",
        "error_code": None,
    }
    (state / "local.json").write_text(json.dumps(record), encoding="utf-8")
    terminated = False

    class Process:
        def cmdline(self) -> list[str]:
            return [
                str(entrypoint),
                "--runtime-component=local",
                f"--runtime-instance-id={instance_id if owned else uuid4()}",
            ]

        def create_time(self) -> float:
            return 123.0

        def exe(self) -> str:
            return str(entrypoint.resolve())

        def terminate(self) -> None:
            nonlocal terminated
            terminated = True

        def wait(self, timeout: float) -> None:
            assert timeout == 10

    def process_factory(pid: int) -> Process:
        assert pid == 4321
        return Process()

    monkeypatch.setattr(acceptance.psutil, "Process", process_factory)

    assert (
        acceptance._cleanup_owned_runtime_processes(  # pyright: ignore[reportPrivateUsage]
            entrypoint, data_dir
        )
        is owned
    )
    assert terminated is owned


def test_acceptance_relocates_package_and_reports_program_data_boundary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    package_root = tmp_path / "package"
    package_root.mkdir()
    (package_root / "fixture.bin").write_bytes(b"fixture")
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(_manifest(package_root)), encoding="utf-8")

    def passed_component(
        entrypoint: Path,
        entrypoint_args: Sequence[str],
        component: str,
        data_dir: Path,
        working_dir: Path,
        forbidden_paths: Sequence[Path],
    ) -> dict[str, JsonValue]:
        assert entrypoint.name == "fixture.bin"
        assert entrypoint_args == []
        assert data_dir.parent == working_dir.parent
        assert tuple(forbidden_paths) in {(tmp_path / "forbidden",), ()}
        return {"component": component, "passed": True}

    monkeypatch.setattr(acceptance, "run_component", passed_component)
    report = acceptance.run_acceptance(
        package_root,
        manifest_path,
        Path("schemas/runtime-package-manifest-v1.schema.json"),
        (tmp_path / "forbidden",),
    )
    assert report["passed"] is True
    assert report["program_data_entries"] == []
    assert report["source_entries"] == []

    (package_root / "model.json").write_text("{}", encoding="utf-8")
    manifest = _manifest(package_root)
    files = cast(list[dict[str, JsonValue]], manifest["files"])
    files.append(
        {
            "path": "model.json",
            "sha256": hashlib.sha256(b"{}").hexdigest(),
            "size": 2,
        }
    )
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    report = acceptance.run_acceptance(
        package_root,
        manifest_path,
        Path("schemas/runtime-package-manifest-v1.schema.json"),
        (),
    )
    assert report["passed"] is False
    assert report["program_data_entries"] == ["model.json"]


def test_cli_writes_report_and_check_exit_code(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    report: dict[str, JsonValue] = {"passed": False}

    def failed_acceptance(
        package_root: Path,
        manifest_path: Path,
        schema_path: Path,
        forbidden_paths: Sequence[Path],
    ) -> dict[str, JsonValue]:
        del package_root, manifest_path, schema_path, forbidden_paths
        return report

    monkeypatch.setattr(acceptance, "run_acceptance", failed_acceptance)
    output = tmp_path / "report.json"
    result = acceptance.main(
        [
            "--package-root",
            str(tmp_path),
            "--manifest",
            str(tmp_path / "manifest.json"),
            "--output",
            str(output),
            "--check",
        ]
    )
    assert result == 1
    assert json.loads(output.read_text(encoding="utf-8")) == report
    assert json.loads(capsys.readouterr().out) == report
