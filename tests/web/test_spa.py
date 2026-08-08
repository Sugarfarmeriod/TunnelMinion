"""React SPA 静态交付边界测试。"""

from __future__ import annotations

from pathlib import Path
from typing import Protocol, cast

import httpx
import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

from tunnelminion.web import spa
from tunnelminion.web.spa import create_spa_router, default_spa_root, resolve_spa_asset


class ApiClient(Protocol):
    """屏蔽 TestClient 当前缺失的严格类型标注。"""

    def get(self, url: str) -> httpx.Response: ...


def _client(tmp_path: Path) -> ApiClient:
    (tmp_path / "assets").mkdir()
    (tmp_path / "index.html").write_text("<main>app</main>", encoding="utf-8")
    (tmp_path / "assets" / "main-hash.js").write_text("export {};", encoding="utf-8")
    app = FastAPI()
    app.include_router(create_spa_router(tmp_path))
    return cast(ApiClient, TestClient(app))


def test_spa_serves_entry_deep_routes_and_immutable_assets(tmp_path: Path) -> None:
    client = _client(tmp_path)

    for path in ("/app", "/app/", "/app/operations/example"):
        response = client.get(path)
        assert response.status_code == 200
        assert response.headers["cache-control"] == "no-store"
        csp = response.headers["content-security-policy"]
        assert "script-src 'self'" in csp
        assert "'unsafe-inline'" not in csp

    asset = client.get("/app-assets/assets/main-hash.js")
    assert asset.status_code == 200
    assert asset.headers["cache-control"] == "public, max-age=31536000, immutable"
    assert asset.headers["x-content-type-options"] == "nosniff"


def test_spa_does_not_swallow_api_or_missing_assets(tmp_path: Path) -> None:
    client = _client(tmp_path)

    api = client.get("/api/does-not-exist")
    assert api.status_code == 404
    assert api.headers["content-type"].startswith("application/json")
    assert client.get("/app-assets/assets/missing.js").status_code == 404


def test_spa_fails_closed_for_missing_build_and_path_escape(tmp_path: Path) -> None:
    empty = tmp_path / "empty"
    empty.mkdir()
    app = FastAPI()
    app.include_router(create_spa_router(empty))
    response = cast(ApiClient, TestClient(app)).get("/app")
    assert response.status_code == 503
    assert response.json()["detail"]["code"] == "frontend_unavailable"

    outside = tmp_path / "outside.js"
    outside.write_text("secret", encoding="utf-8")
    with pytest.raises(HTTPException) as caught:
        resolve_spa_asset(empty, "../outside.js")
    assert caught.value.status_code == 404


def test_default_spa_root_prefers_package_then_source_staging(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    package = tmp_path / "package"
    ui = package / "ui"
    ui.mkdir(parents=True)
    (ui / "index.html").write_text("package", encoding="utf-8")
    def package_files(_package: str) -> Path:
        return package

    monkeypatch.setattr(spa.resources, "files", package_files)
    assert default_spa_root() == ui

    (ui / "index.html").unlink()
    repository = tmp_path / "repository"
    fake_module = repository / "src" / "tunnelminion" / "web" / "spa.py"
    source_staging = repository / "build" / "frontend-dist"
    source_staging.mkdir(parents=True)
    (source_staging / "index.html").write_text("source", encoding="utf-8")
    monkeypatch.setattr(spa, "__file__", str(fake_module))
    assert default_spa_root() == source_staging

    (source_staging / "index.html").unlink()
    assert default_spa_root() == ui
