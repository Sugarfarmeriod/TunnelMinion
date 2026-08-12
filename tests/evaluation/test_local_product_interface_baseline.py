"""固定本机产品迁移前后的可复核接口与双平台验收基线。"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Protocol, cast

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from tunnelminion.app import build_windows_application
from tunnelminion.macos_app import build_macos_local_application

ROOT = Path(__file__).resolve().parents[2]
BASELINE_PATH = ROOT / "evaluations" / "baselines" / "local-product-interface-v1.json"


class ApiClient(Protocol):
    """补齐 Starlette TestClient 当前缺失的严格返回类型。"""

    def get(self, url: str) -> httpx.Response: ...


def _load_json(path: Path) -> dict[str, Any]:
    return cast(dict[str, Any], json.loads(path.read_text(encoding="utf-8")))


def _sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def _canonical_openapi(app: FastAPI) -> bytes:
    return json.dumps(app.openapi(), ensure_ascii=False, sort_keys=True).encode("utf-8")


def test_baseline_freezes_legacy_openapi_and_csp_without_secret_reads(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    baseline = _load_json(BASELINE_PATH)
    assert baseline["schema_version"] == "local-product-interface-baseline/v1"
    assert baseline["fixture_policy"] == {
        "isolated_temporary_data": True,
        "secret_store_reads_allowed": False,
        "customer_network_changes_allowed": False,
    }

    def reject_secret_read(*_arguments: object, **_keywords: object) -> None:
        raise AssertionError("本机产品基线 fixture 不得读取秘密")

    monkeypatch.setattr("keyring.get_password", reject_secret_read)
    applications = (
        build_windows_application(tmp_path / "windows").app,
        build_macos_local_application(tmp_path / "macos").app,
    )
    for application in applications:
        openapi = _canonical_openapi(application)
        assert len(openapi) == baseline["openapi"]["canonical_json_bytes"]
        assert hashlib.sha256(openapi).hexdigest() == baseline["openapi"]["sha256"]
        assert set(baseline["openapi"]["critical_paths"]) <= set(application.openapi()["paths"])

        client = cast(ApiClient, TestClient(application, base_url="http://127.0.0.1"))
        for expected in baseline["legacy_pages"]:
            response = client.get(expected["route"])
            alias = client.get(expected["alias"])
            assert response.status_code == expected["status"]
            assert len(response.content) == expected["bytes"]
            assert hashlib.sha256(response.content).hexdigest() == expected["sha256"]
            assert (
                response.headers.get("content-security-policy")
                == expected["content_security_policy"]
            )
            assert alias.content == response.content


def test_baseline_references_exact_platform_evidence_and_metrics() -> None:
    baseline = _load_json(BASELINE_PATH)
    packages = baseline["packages"]
    for expected in packages.values():
        summary_path = ROOT / expected["acceptance_summary"]
        manifest_path = ROOT / expected["manifest"]
        assert _sha256(summary_path) == expected["acceptance_summary_sha256"]
        assert _sha256(manifest_path) == expected["manifest_sha256"]
        manifest = _load_json(manifest_path)
        assert manifest["schema_version"] == "runtime-package-manifest/v2"
        assert manifest["candidate"]["id"] == expected["package_id"]
        assert expected["clean_acceptance_passed"] is True

    windows = _load_json(ROOT / packages["windows_amd64"]["acceptance_summary"])
    macos = _load_json(ROOT / packages["macos_arm64"]["acceptance_summary"])
    assert (
        windows["acceptance"]["frontend_size"]["total_gzip_bytes"]
        == baseline["initial_bundle"]["gzip_bytes"]
    )
    for key, value in baseline["overview_latency_ms"]["windows_chromium"].items():
        assert windows["acceptance"]["browser"]["latency_ms"][key] == value
    for key, value in baseline["overview_latency_ms"]["macos_webkit"].items():
        assert macos["overview_latency_ms"][key] == value
    assert windows["acceptance"]["package_secret_scan"]["hits"] == []
    assert macos["security"]["fixture_contains_secrets"] is False
    assert macos["security"]["scanner_result"].startswith("no API key")
