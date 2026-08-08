"""双平台运行包 CI 暂存与汇总证据测试。"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from scripts.stage_runtime_package_ci import stage_runtime_package
from scripts.verify_runtime_package_matrix import verify_runtime_package_matrix


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")


def test_runtime_package_ci_staging_is_clean_and_confined(tmp_path: Path) -> None:
    output = tmp_path / "outside-output"
    package = output / "candidate"
    package.mkdir(parents=True)
    (package / "tunnelminion.bin").write_bytes(b"package")
    manifest = tmp_path / "manifest.json"
    summary = tmp_path / "summary.json"
    _write_json(manifest, {"schema_version": "runtime-package-manifest/v2"})
    _write_json(summary, {"package_id": "candidate"})
    destination = tmp_path / "staging"
    destination.mkdir()
    (destination / "stale.txt").write_text("stale", encoding="utf-8")

    staged = stage_runtime_package(output, manifest, summary, destination)

    assert staged == destination.resolve()
    assert not (staged / "stale.txt").exists()
    assert (staged / "package" / "tunnelminion.bin").read_bytes() == b"package"
    assert (staged / "manifest.json").is_file()
    assert (staged / "build-summary.json").is_file()

    _write_json(summary, {"package_id": "../escape"})
    with pytest.raises(ValueError, match="无效包目录"):
        stage_runtime_package(output, manifest, summary, destination)


def _write_target(
    root: Path,
    *,
    platform_value: str,
    architecture: str,
    frontend_digest: str,
    frontend_count: int,
    python_lock: str = "p" * 64,
) -> Path:
    directory = root / f"{platform_value}-{architecture}"
    package_id = f"candidate-{platform_value}-{architecture}"
    manifest = {
        "schema_version": "runtime-package-manifest/v2",
        "candidate": {
            "id": package_id,
            "platform": platform_value,
            "architecture": architecture,
        },
        "build": {},
        "frontend": {"sha256": frontend_digest, "file_count": frontend_count},
        "licenses": [
            {"ecosystem": "python", "license": "MIT"},
            {"ecosystem": "npm", "license": "MIT"},
        ],
    }
    manifest_path = directory / "manifest.json"
    _write_json(manifest_path, manifest)
    manifest_digest = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    _write_json(
        directory / "build-summary.json",
        {
            "package_id": package_id,
            "platform": platform_value,
            "architecture": architecture,
            "source_revision": "a" * 40,
            "python_lock_sha256": python_lock,
            "npm_lock_sha256": "n" * 64,
            "frontend_dist_sha256": frontend_digest,
            "frontend_file_count": frontend_count,
            "manifest_sha256": manifest_digest,
            "unknown_license_count": 0,
        },
    )
    _write_json(
        directory / "clean-acceptance.json",
        {
            "manifest_sha256": manifest_digest,
            "passed": True,
            "program_data_entries": [],
            "source_entries": [],
            "components": [
                {
                    "health_status": 200,
                    "app_status": 200,
                    "node_available": False,
                    "source_environment_present": False,
                    "external_http_proxy_blocked": True,
                }
            ],
        },
    )
    return directory


def test_runtime_package_matrix_requires_exact_matching_platform_evidence(tmp_path: Path) -> None:
    digest = "f" * 64
    receipt = tmp_path / "frontend-receipt.json"
    _write_json(receipt, {"dist_sha256": digest, "file_count": 3})
    evidence = tmp_path / "evidence"
    _write_target(
        evidence,
        platform_value="win32",
        architecture="amd64",
        frontend_digest=digest,
        frontend_count=3,
    )
    _write_target(
        evidence,
        platform_value="darwin",
        architecture="arm64",
        frontend_digest=digest,
        frontend_count=3,
    )

    summary = verify_runtime_package_matrix(evidence, receipt)

    assert summary["passed"] is True
    assert summary["frontend_dist_sha256"] == digest
    assert summary["targets"] == [
        {"platform": "darwin", "architecture": "arm64", "passed": True},
        {"platform": "win32", "architecture": "amd64", "passed": True},
    ]

    windows = evidence / "win32-amd64" / "build-summary.json"
    broken = json.loads(windows.read_text(encoding="utf-8"))
    broken["frontend_dist_sha256"] = "0" * 64
    _write_json(windows, broken)
    with pytest.raises(ValueError, match="唯一前端回执"):
        verify_runtime_package_matrix(evidence, receipt)


def test_runtime_package_matrix_rejects_lock_or_isolation_drift(tmp_path: Path) -> None:
    digest = "f" * 64
    receipt = tmp_path / "frontend-receipt.json"
    _write_json(receipt, {"dist_sha256": digest, "file_count": 1})
    evidence = tmp_path / "evidence"
    _write_target(
        evidence,
        platform_value="win32",
        architecture="amd64",
        frontend_digest=digest,
        frontend_count=1,
    )
    mac = _write_target(
        evidence,
        platform_value="darwin",
        architecture="arm64",
        frontend_digest=digest,
        frontend_count=1,
        python_lock="q" * 64,
    )
    with pytest.raises(ValueError, match="同一源码与锁文件"):
        verify_runtime_package_matrix(evidence, receipt)

    mac_summary = json.loads((mac / "build-summary.json").read_text(encoding="utf-8"))
    mac_summary["python_lock_sha256"] = "p" * 64
    _write_json(mac / "build-summary.json", mac_summary)
    acceptance = json.loads((mac / "clean-acceptance.json").read_text(encoding="utf-8"))
    acceptance["components"][0]["node_available"] = True
    _write_json(mac / "clean-acceptance.json", acceptance)
    with pytest.raises(ValueError, match="隔离运行证据"):
        verify_runtime_package_matrix(evidence, receipt)
