"""供运行包 spike 使用的最小真实本地应用与 Gateway 启动入口。"""

from __future__ import annotations

import argparse
import importlib
import os
import site
import sys
from collections.abc import Sequence
from pathlib import Path

import keyring
import uvicorn
from fastapi import FastAPI

from tunnelminion.domain.identifiers import NodeId
from tunnelminion.gateway.configuration import (
    FileGatewayConfigurationRepository,
    GatewayConfigurationService,
    GatewayPeerConfig,
    GatewayPeerInput,
    GatewaySecretStoreKind,
    configure_gateway_secret_store,
)
from tunnelminion.gateway.security import GatewayBindConfig

NATIVE_EXTENSION_MODULES = (
    "cryptography.hazmat.bindings._rust",
    "orjson",
    "pydantic_core._pydantic_core",
    "zstandard.backend_c",
)


def _native_extension_modules() -> tuple[str, ...]:
    """加载运行时关键原生扩展，缺失时让 fixture 启动失败。"""
    platform_module = "psutil._psutil_windows" if sys.platform == "win32" else "psutil._psutil_osx"
    modules = (*NATIVE_EXTENSION_MODULES, platform_module)
    for module in modules:
        importlib.import_module(module)
    return modules


def _build_local_application(data_dir: Path) -> FastAPI:
    """使用当前平台真实应用组装器创建环回应用。"""
    if sys.platform == "darwin":
        from tunnelminion.macos_app import build_macos_local_application

        return build_macos_local_application(data_dir).app
    from tunnelminion.app import build_windows_application

    return build_windows_application(data_dir).app


def _build_gateway_application(data_dir: Path) -> FastAPI:
    """用隔离 fixture 身份配置真实 Gateway app，但不绑定伪造的 WireGuard 地址。"""
    peer_id = NodeId.new()
    repository = FileGatewayConfigurationRepository(data_dir / "gateway.json")
    service = GatewayConfigurationService(
        repository,
        configure_gateway_secret_store(data_dir, GatewaySecretStoreKind.RESTRICTED_FILE),
    )
    service.configure_local(GatewayBindConfig(host="10.254.254.1", port=8787))
    service.provision_peer(
        GatewayPeerInput(
            peer=GatewayPeerConfig(
                node_id=peer_id,
                host="10.254.254.2",
                allowed_tools=frozenset({"get_node_summary"}),
            ),
            token="tmn_" + "fixture-" + "x" * 32,
        )
    )
    from tunnelminion.macos_app import build_macos_gateway_application

    return build_macos_gateway_application(data_dir).app


def create_fixture_application(component: str, data_dir: Path) -> FastAPI:
    """创建真实组件并增加只供打包验收读取的环境观测端点。"""
    native_extensions = _native_extension_modules()
    keyring_backend = keyring.get_keyring().__class__
    if component == "local":
        app = _build_local_application(data_dir)
    elif component == "gateway":
        app = _build_gateway_application(data_dir)
    else:
        raise ValueError("未知运行包 fixture 组件")

    @app.get("/__runtime_package_fixture__", include_in_schema=False)
    async def package_fixture_status() -> dict[str, object]:
        return {
            "component": component,
            "pythonpath_present": bool(os.environ.get("PYTHONPATH")),
            "user_site_enabled": bool(site.ENABLE_USER_SITE),
            "sys_path": tuple(sys.path),
            "executable": sys.executable,
            "keyring_backend": f"{keyring_backend.__module__}.{keyring_backend.__qualname__}",
            "native_extensions": native_extensions,
        }

    _ = package_fixture_status
    return app


def main(argv: Sequence[str] | None = None) -> int:
    """启动一个只绑定环回地址的打包验收组件。"""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--component", choices=("local", "gateway"), required=True)
    parser.add_argument("--data-dir", type=Path, required=True)
    parser.add_argument("--port", type=int, required=True, choices=range(1024, 65536))
    args = parser.parse_args(argv)
    app = create_fixture_application(args.component, args.data_dir)
    uvicorn.run(app, host="127.0.0.1", port=args.port, log_level="warning")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
