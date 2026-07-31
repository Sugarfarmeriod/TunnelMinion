"""运行包 fixture、manifest 与干净环境验收脚本测试。"""

from __future__ import annotations

import hashlib
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Protocol, cast

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
            "architecture": "test",
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
    local = cast(ApiClient, TestClient(create_fixture_application("local", tmp_path / "local")))
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

    wrong_platform = _manifest(package_root)
    candidate = cast(dict[str, JsonValue], wrong_platform["candidate"])
    candidate["platform"] = "darwin" if sys.platform == "win32" else "win32"
    manifest_path.write_text(json.dumps(wrong_platform), encoding="utf-8")
    with pytest.raises(ValueError, match="平台与当前系统不匹配"):
        acceptance.load_and_verify_manifest(package_root, manifest_path, schema)

    bad_hash = _manifest(package_root)
    files = cast(list[dict[str, JsonValue]], bad_hash["files"])
    files[0]["sha256"] = "0" * 64
    manifest_path.write_text(json.dumps(bad_hash), encoding="utf-8")
    with pytest.raises(ValueError, match="摘要不匹配"):
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

    (package_root / "model.json").write_text("{}", encoding="utf-8")
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
