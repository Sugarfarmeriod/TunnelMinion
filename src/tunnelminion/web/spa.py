"""React 本地产品界面的静态资源与深路由交付。"""

from __future__ import annotations

import os
from collections.abc import Mapping
from importlib import resources
from pathlib import Path

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse, RedirectResponse

_DEFAULT_UI_ENV = "TUNNELMINION_DEFAULT_UI"
_UI_ENTRYPOINTS = {
    "react": "/app/overview",
    "legacy": "/resources",
}

_CSP = "; ".join(
    (
        "default-src 'self'",
        "script-src 'self'",
        "style-src 'self'",
        "connect-src 'self'",
        "img-src 'self' data:",
        "font-src 'self'",
        "object-src 'none'",
        "base-uri 'none'",
        "frame-ancestors 'none'",
        "form-action 'self'",
    )
)
_INDEX_HEADERS = {
    "Cache-Control": "no-store",
    "Content-Security-Policy": _CSP,
    "X-Content-Type-Options": "nosniff",
}
_ASSET_HEADERS = {
    "Cache-Control": "public, max-age=31536000, immutable",
    "X-Content-Type-Options": "nosniff",
}


def default_spa_root() -> Path:
    """优先使用 package 资源；源码开发时回退到统一暂存目录。"""
    packaged = Path(str(resources.files("tunnelminion.web").joinpath("ui")))
    if (packaged / "index.html").is_file():
        return packaged
    source_staging = Path(__file__).resolve().parents[3] / "build" / "frontend-dist"
    if (source_staging / "index.html").is_file():
        return source_staging
    return packaged


def default_ui_entrypoint(environment: Mapping[str, str] | None = None) -> str:
    """选择默认界面；回退只改变入口，不迁移或删除任何用户数据。"""
    source = os.environ if environment is None else environment
    selected = source.get(_DEFAULT_UI_ENV, "react").strip().lower()
    try:
        return _UI_ENTRYPOINTS[selected]
    except KeyError as error:
        allowed = ", ".join(sorted(_UI_ENTRYPOINTS))
        raise ValueError(f"{_DEFAULT_UI_ENV} 必须是以下值之一：{allowed}") from error


def create_spa_router(asset_root: Path | None = None) -> APIRouter:
    """创建默认入口及只匹配 `/app/*` 与 `/app-assets/*` 的静态路由。"""
    root = (asset_root or default_spa_root()).resolve()
    index = root / "index.html"
    router = APIRouter()

    def spa_entry() -> FileResponse:
        if not index.is_file():
            raise HTTPException(status_code=503, detail={"code": "frontend_unavailable"})
        return FileResponse(index, media_type="text/html", headers=_INDEX_HEADERS)

    def static_asset(asset_path: str) -> FileResponse:
        candidate = resolve_spa_asset(root, asset_path)
        if not candidate.is_file():
            raise HTTPException(status_code=404, detail={"code": "asset_not_found"})
        return FileResponse(candidate, headers=_ASSET_HEADERS)

    def default_entry() -> RedirectResponse:
        return RedirectResponse(default_ui_entrypoint(), status_code=307)

    router.add_api_route("/", default_entry, methods=["GET"], response_class=RedirectResponse)
    router.add_api_route("/app", spa_entry, methods=["GET"], response_class=FileResponse)
    router.add_api_route("/app/", spa_entry, methods=["GET"], response_class=FileResponse)
    router.add_api_route(
        "/app/{route_path:path}",
        spa_entry,
        methods=["GET"],
        response_class=FileResponse,
    )
    router.add_api_route(
        "/app-assets/{asset_path:path}",
        static_asset,
        methods=["GET"],
        response_class=FileResponse,
    )
    return router


def resolve_spa_asset(root: Path, asset_path: str) -> Path:
    """解析静态资源路径，并拒绝目录逃逸。"""
    candidate = (root / asset_path).resolve()
    if candidate == root or root not in candidate.parents:
        raise HTTPException(status_code=404, detail={"code": "asset_not_found"})
    return candidate
