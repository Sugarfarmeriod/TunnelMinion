"""React 本地产品界面的静态资源与深路由交付。"""

from __future__ import annotations

from importlib import resources
from pathlib import Path

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse

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


def create_spa_router(asset_root: Path | None = None) -> APIRouter:
    """创建只匹配 `/app/*` 与 `/app-assets/*` 的静态路由。"""
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
