"""为 Playwright 启动使用隔离数据目录的真实本机 FastAPI 应用。"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from tempfile import TemporaryDirectory

import uvicorn
from fastapi import FastAPI

from stage_frontend import stage_frontend
from tunnelminion.app import build_windows_application
from tunnelminion.macos_app import build_macos_local_application


def build_application(data_dir: Path) -> FastAPI:
    """按当前验收平台装配与产品入口相同的 FastAPI 应用。"""
    if sys.platform == "darwin":
        return build_macos_local_application(data_dir).app
    return build_windows_application(data_dir).app


def main() -> int:
    """暂存生产前端并在环回地址启动隔离的验收服务器。"""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=4174)
    args = parser.parse_args()

    repository = Path(__file__).resolve().parents[1]
    stage_frontend(
        repository / "frontend" / "dist",
        repository / "build" / "frontend-dist",
    )
    with TemporaryDirectory(prefix="tunnelminion-playwright-") as temporary:
        application = build_application(Path(temporary))
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
