"""TunnelMinion 本地节点启动命令。"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
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


def _enroll_with_coordinator(values: list[str]) -> int:
    """从标准输入接收一次性 token，并只输出不含秘密的注册摘要。"""
    parser = argparse.ArgumentParser(description="向已固定指纹的 Coordinator 注册节点")
    parser.add_argument("coordinator-enroll")
    parser.add_argument("--data-dir", type=Path)
    args = parser.parse_args(values)

    from tunnelminion.agent.coordinator import HttpCoordinatorTransport
    from tunnelminion.agent.managed_node import (
        MANAGED_NODE_CONFIG_FILE,
        FileManagedNodeConfigRepository,
        enroll_managed_node,
        managed_node_secret_store,
    )
    from tunnelminion.app import default_data_dir
    from tunnelminion.coordinator.client_credentials import AgentRefreshCredentialStore

    root = args.data_dir or default_data_dir()
    config = FileManagedNodeConfigRepository(root / MANAGED_NODE_CONFIG_FILE).load()
    if config is None:
        parser.error("缺少 managed-node.json，无法执行 enrollment")
    if not config.enabled:
        parser.error("managed node 已禁用，无法执行 enrollment")
    token = sys.stdin.read().strip()
    if not token:
        parser.error("必须通过标准输入提供一次性 enrollment token")
    try:
        credentials = AgentRefreshCredentialStore(
            managed_node_secret_store(root, config.secret_store)
        )
        response = asyncio.run(
            enroll_managed_node(
                config,
                token,
                HttpCoordinatorTransport(config.coordinator_client_config()),
                credentials,
            )
        )
    finally:
        token = ""
    print(
        json.dumps(
            {
                "status": "enrolled",
                "network_id": str(response.identity.network_id),
                "node_id": str(response.identity.node_id),
                "credential_id": str(response.credential_id),
                "server_revision": response.server_revision,
            },
            ensure_ascii=False,
        )
    )
    return 0


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


def _approve_operation(values: list[str]) -> int:
    """由目标节点本地 CLI 记录一次性批准，不通过聊天或远端 API 授权。"""
    parser = argparse.ArgumentParser(description="批准一项本地待授权操作")
    parser.add_argument("operation-approve")
    parser.add_argument("--data-dir", type=Path)
    parser.add_argument("--operation-id", required=True)
    parser.add_argument("--valid-seconds", type=int, default=300)
    parser.add_argument("--operator", default="target-local-cli")
    args = parser.parse_args(values)
    if not 1 <= args.valid_seconds <= 86_400:
        parser.error("--valid-seconds 必须在 1 到 86400 之间")

    from tunnelminion.app import default_data_dir
    from tunnelminion.domain.identifiers import OperationId
    from tunnelminion.macos_app import build_macos_local_application
    from tunnelminion.web.operations import ApproveInput

    root = args.data_dir or default_data_dir()
    bundle = build_macos_local_application(root)
    summary = bundle.operation_control_service.approve(
        OperationId(args.operation_id),
        ApproveInput(
            operator=args.operator,
            expires_at=datetime.now(UTC) + timedelta(seconds=args.valid_seconds),
        ),
    )
    print(summary.model_dump_json())
    return 0


def _create_operation_preauthorization(values: list[str]) -> int:
    """由目标节点本地 CLI 创建全部维度受限的临时 L2 预授权。"""
    parser = argparse.ArgumentParser(description="创建本地临时服务共享预授权")
    parser.add_argument("operation-preauthorize")
    parser.add_argument("--data-dir", type=Path)
    parser.add_argument("--request-peer-id", required=True)
    parser.add_argument("--service-id", required=True)
    parser.add_argument("--service-fingerprint", required=True)
    parser.add_argument("--minimum-port", type=int, required=True)
    parser.add_argument("--maximum-port", type=int, required=True)
    parser.add_argument("--maximum-duration", type=int, required=True)
    parser.add_argument("--valid-seconds", type=int, default=300)
    parser.add_argument("--operator", default="target-local-cli")
    args = parser.parse_args(values)
    if not 1 <= args.valid_seconds <= 86_400:
        parser.error("--valid-seconds 必须在 1 到 86400 之间")

    from tunnelminion.app import default_data_dir
    from tunnelminion.domain.identifiers import NodeId
    from tunnelminion.macos_app import build_macos_local_application
    from tunnelminion.web.operations import PreauthorizationInput

    now = datetime.now(UTC)
    root = args.data_dir or default_data_dir()
    bundle = build_macos_local_application(root)
    authorization = bundle.operation_control_service.create_preauthorization(
        PreauthorizationInput(
            request_peer_id=NodeId(args.request_peer_id),
            tool_name="share_local_http_service",
            service_ids=frozenset({args.service_id}),
            service_fingerprints=frozenset({args.service_fingerprint}),
            minimum_port=args.minimum_port,
            maximum_port=args.maximum_port,
            maximum_duration_seconds=args.maximum_duration,
            valid_from=now,
            valid_until=now + timedelta(seconds=args.valid_seconds),
            created_by=args.operator,
            confirm_peer=True,
            confirm_tool=True,
            confirm_service=True,
            confirm_port=True,
            confirm_duration=True,
            confirm_validity=True,
        )
    )
    print(authorization.model_dump_json())
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
    if values and values[0] == "coordinator-enroll":
        return _enroll_with_coordinator(values)
    if values and values[0] == "operation-approve":
        return _approve_operation(values)
    if values and values[0] == "operation-preauthorize":
        return _create_operation_preauthorization(values)
    if values and values[0] == "gateway":
        parser = argparse.ArgumentParser(description="启动 macOS 只读 Tool Gateway")
        parser.add_argument("gateway")
        parser.add_argument("--data-dir", type=Path)
        parser.add_argument("--enable-safe-sharing", action="store_true")
        parser.add_argument("--sharing-min-port", type=int, default=18_880)
        parser.add_argument("--sharing-max-port", type=int, default=18_899)
        parser.add_argument("--sharing-max-duration", type=int, default=3600)
        parser.add_argument("--sharing-gateway-port", type=int)
        args = parser.parse_args(values)
        from tunnelminion.macos_app import (
            SafeSharingGatewaySettings,
            build_macos_gateway_application,
        )

        sharing = (
            SafeSharingGatewaySettings(
                minimum_port=args.sharing_min_port,
                maximum_port=args.sharing_max_port,
                maximum_duration_seconds=args.sharing_max_duration,
                bind_port_override=args.sharing_gateway_port,
            )
            if args.enable_safe_sharing
            else None
        )
        bundle = build_macos_gateway_application(args.data_dir, safe_sharing=sharing)
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
