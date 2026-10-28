"""为 Playwright 启动使用隔离数据目录的真实本机 FastAPI 应用。"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from tempfile import TemporaryDirectory

import uvicorn
from fastapi import FastAPI

from prepare_local_product_package_fixture import seed_operation
from stage_frontend import stage_frontend
from tunnelminion.app import build_windows_application
from tunnelminion.gateway.configuration import (
    GatewaySecretStoreKind,
    configure_gateway_secret_store,
)
from tunnelminion.macos_app import build_macos_local_application


def build_application(data_dir: Path, *, read_only_preview: bool = False) -> FastAPI:
    """按当前验收平台装配与产品入口相同的 FastAPI 应用。"""
    if sys.platform == "darwin":
        application = build_macos_local_application(data_dir, read_only_preview=read_only_preview)
        seed_operation(application.operation_control_service, application.node.node_id)
        return application.app
    application = build_windows_application(data_dir, read_only_preview=read_only_preview)
    seed_operation(application.operation_control_service, application.node_id)
    return application.app


def main() -> int:
    """暂存生产前端并在环回地址启动隔离的验收服务器。"""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=4174)
    parser.add_argument("--read-only-preview", action="store_true")
    args = parser.parse_args()

    repository = Path(__file__).resolve().parents[1]
    stage_frontend(
        repository / "frontend" / "dist",
        repository / "build" / "frontend-dist",
    )
    with TemporaryDirectory(prefix="tunnelminion-playwright-") as temporary:
        # 验收里会建立机主身份；密钥只写进临时目录，不碰系统钥匙串。
        configure_gateway_secret_store(Path(temporary), GatewaySecretStoreKind.RESTRICTED_FILE)
        application = build_application(Path(temporary), read_only_preview=args.read_only_preview)
        uvicorn.run(
            application,
            host=args.host,
            port=args.port,
            log_level="warning",
            access_log=False,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
