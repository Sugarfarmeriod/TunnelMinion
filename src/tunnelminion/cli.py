"""TunnelMinion 本地节点启动命令。"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

import uvicorn

_MACOS_READ_ONLY_TOOLS = (
    "get_wireguard_status",
    "list_network_listeners",
    "get_process_summary",
    "list_docker_services",
    "probe_service_reachability",
    "get_node_summary",
)
_SUPPORTED_REMOTE_OPERATIONS = ("share_local_http_service",)
_UNINSTALL_CONFIRMATION = "DELETE-TUNNELMINION-DATA"


def _export_data(values: list[str]) -> int:
    """把不含凭据与工具正文的允许列表数据导出为 JSON。"""
    parser = argparse.ArgumentParser(description="导出 TunnelMinion 脱敏数据")
    parser.add_argument("export")
    parser.add_argument("--data-dir", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(values)
    from tunnelminion.app import default_data_dir
    from tunnelminion.operations import write_safe_export

    root = args.data_dir or default_data_dir()
    write_safe_export(root, args.output)
    print(json.dumps({"status": "exported", "output": str(args.output)}, ensure_ascii=False))
    return 0


def _uninstall_data(values: list[str]) -> int:
    """经明确确认后删除 TunnelMinion 凭据和自有数据。"""
    parser = argparse.ArgumentParser(description="彻底清理 TunnelMinion 自有数据")
    parser.add_argument("uninstall")
    parser.add_argument("--data-dir", type=Path)
    parser.add_argument("--confirm", required=True)
    args = parser.parse_args(values)
    if args.confirm != _UNINSTALL_CONFIRMATION:
        parser.error(f"--confirm 必须精确填写 {_UNINSTALL_CONFIRMATION}")

    from tunnelminion.app import default_data_dir
    from tunnelminion.operations import uninstall_owned_data

    root = args.data_dir or default_data_dir()
    removed = uninstall_owned_data(root)
    print(
        json.dumps(
            {"status": "uninstalled", "removed_entries": len(removed)},
            ensure_ascii=False,
        )
    )
    return 0


def _configure_gateway(values: list[str]) -> int:
    """从标准输入接收一次性 token，配置 B 网关而不回显秘密。"""
    parser = argparse.ArgumentParser(description="配置 macOS 只读 Tool Gateway")
    parser.add_argument("gateway-configure")
    parser.add_argument("--data-dir", type=Path)
    parser.add_argument("--bind-host", required=True)
    parser.add_argument("--bind-port", type=int, default=8787)
    parser.add_argument("--peer-node-id", required=True)
    parser.add_argument("--peer-host", required=True)
    parser.add_argument("--peer-port", type=int, default=8787)
    parser.add_argument("--allowed-tool", action="append", choices=_MACOS_READ_ONLY_TOOLS)
    parser.add_argument(
        "--allowed-operation",
        action="append",
        choices=_SUPPORTED_REMOTE_OPERATIONS,
    )
    parser.add_argument(
        "--secret-store",
        choices=("keyring", "restricted-file"),
        default="keyring",
    )
    args = parser.parse_args(values)

    from tunnelminion.app import default_data_dir, load_or_create_node_id
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

    token = sys.stdin.read().strip()
    root = args.data_dir or default_data_dir()
    local_node_id = load_or_create_node_id(root / "node-id")
    service = GatewayConfigurationService(
        FileGatewayConfigurationRepository(root / "gateway.json"),
        configure_gateway_secret_store(root, GatewaySecretStoreKind(args.secret_store)),
    )
    service.configure_local(GatewayBindConfig(host=args.bind_host, port=args.bind_port))
    view = service.provision_peer(
        GatewayPeerInput(
            peer=GatewayPeerConfig(
                node_id=NodeId(args.peer_node_id),
                host=args.peer_host,
                port=args.peer_port,
                allowed_tools=frozenset(args.allowed_tool or _MACOS_READ_ONLY_TOOLS),
                allowed_operations=frozenset(args.allowed_operation or ()),
            ),
            token=token,
        )
    )
    print(
        json.dumps(
            {"local_node_id": str(local_node_id), "gateway": view.model_dump(mode="json")},
            ensure_ascii=False,
        )
    )
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    """启动本地面板，或按配置启动只绑定 WireGuard 地址的 macOS 网关。"""
    values = list(sys.argv[1:] if argv is None else argv)
    if values and values[0] == "export":
        return _export_data(values)
    if values and values[0] == "uninstall":
        return _uninstall_data(values)
    if values and values[0] == "gateway-configure":
        return _configure_gateway(values)
    if values and values[0] == "gateway":
        parser = argparse.ArgumentParser(description="启动 macOS 只读 Tool Gateway")
        parser.add_argument("gateway")
        parser.add_argument("--data-dir", type=Path)
        args = parser.parse_args(values)
        from tunnelminion.macos_app import build_macos_gateway_application

        bundle = build_macos_gateway_application(args.data_dir)
        uvicorn.run(
            bundle.app,
            host=bundle.bind.host,
            port=bundle.bind.port,
        )
        return 0
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8765, choices=range(1024, 65536))
    parser.add_argument("--data-dir", type=Path)
    args = parser.parse_args(values)
    if args.data_dir is not None:
        if sys.platform == "darwin":
            from tunnelminion.macos_app import build_macos_local_application

            application = build_macos_local_application(args.data_dir).app
        else:
            from tunnelminion.app import build_windows_application

            application = build_windows_application(args.data_dir).app
        uvicorn.run(application, host="127.0.0.1", port=args.port)
        return 0
    factory = (
        "tunnelminion.macos_app:create_macos_app"
        if sys.platform == "darwin"
        else "tunnelminion.app:create_app"
    )
    uvicorn.run(
        factory,
        factory=True,
        host="127.0.0.1",
        port=args.port,
    )
    return 0
