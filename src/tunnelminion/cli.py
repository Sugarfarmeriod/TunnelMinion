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


def _runtime_command(values: list[str]) -> int:
    """配置或执行不注册系统自启动项的手工 runtime 操作。"""
    parser = argparse.ArgumentParser(description="手工管理 TunnelMinion 常驻组件")
    parser.add_argument("runtime")
    parser.add_argument("action", choices=("configure", "start", "status", "stop"))
    parser.add_argument("--profile", type=Path)
    parser.add_argument("--data-dir", type=Path)
    parser.add_argument("--local-port", type=int, default=8000, choices=range(1024, 65536))
    parser.add_argument("--enable-gateway", action="store_true")
    args = parser.parse_args(values)

    from tunnelminion.runtime.control import (
        build_lifecycle_manager,
        profile_summary,
        runtime_control_view,
    )
    from tunnelminion.runtime.process import RuntimeOperationBusy
    from tunnelminion.runtime.profile import (
        FileRuntimeProfileRepository,
        RuntimeComponent,
        RuntimeProfile,
        current_program_dir,
        default_runtime_data_dir,
        default_runtime_profile_path,
        resolve_runtime_paths,
    )

    profile_path = (args.profile or default_runtime_profile_path()).expanduser().resolve()
    repository = FileRuntimeProfileRepository(profile_path, current_program_dir())
    if args.action == "configure":
        components = {RuntimeComponent.LOCAL}
        if args.enable_gateway:
            components.add(RuntimeComponent.GATEWAY)
        try:
            profile = RuntimeProfile(
                data_dir=(args.data_dir or default_runtime_data_dir()).expanduser().resolve(),
                enabled_components=frozenset(components),
                local_port=args.local_port,
            )
            repository.save(profile)
        except (OSError, ValueError):
            print(
                json.dumps(
                    {"status": "failed", "error_code": "runtime_profile_invalid"},
                    ensure_ascii=False,
                )
            )
            return 2
        print(profile_summary(profile))
        return 0

    try:
        profile = repository.load()
    except (OSError, ValueError):
        profile = None
    if profile is None:
        print(
            json.dumps(
                {"status": "failed", "error_code": "runtime_profile_invalid"},
                ensure_ascii=False,
            )
        )
        return 2
    paths = resolve_runtime_paths(profile.data_dir, profile_path)
    manager = build_lifecycle_manager(profile, paths)
    try:
        report = getattr(manager, args.action)()
    except RuntimeOperationBusy:
        print(
            json.dumps(
                {"status": "failed", "error_code": "runtime_operation_busy"},
                ensure_ascii=False,
            )
        )
        return 2
    view = runtime_control_view(report, profile, paths)
    print(view.model_dump_json())
    return report.exit_code


def _runtime_child(values: list[str]) -> int:
    """运行单个真实组件，并把启动异常收敛为零秘密稳定错误。"""
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("runtime-child")
    parser.add_argument("--runtime-component", choices=("local", "gateway"), required=True)
    parser.add_argument("--runtime-instance-id", required=True)
    parser.add_argument("--data-dir", type=Path, required=True)
    parser.add_argument("--local-port", type=int, required=True, choices=range(1024, 65536))
    parser.add_argument("--runtime-log-file", type=Path, required=True)
    args = parser.parse_args(values)

    from uuid import UUID

    from tunnelminion.runtime.logging import runtime_log_config, write_runtime_event

    try:
        UUID(args.runtime_instance_id)
        if args.runtime_component == "gateway":
            from tunnelminion.macos_app import build_macos_gateway_application

            bundle = build_macos_gateway_application(args.data_dir)
            application = bundle.app
            host = bundle.bind.host
            port = bundle.bind.port
        else:
            host = "127.0.0.1"
            port = args.local_port
            if sys.platform == "darwin":
                from tunnelminion.macos_app import build_macos_local_application

                application = build_macos_local_application(args.data_dir).app
            else:
                from tunnelminion.app import build_windows_application

                application = build_windows_application(args.data_dir).app
        uvicorn.run(
            application,
            host=host,
            port=port,
            access_log=False,
            log_config=runtime_log_config(args.runtime_log_file),
        )
    except Exception:
        write_runtime_event(args.runtime_log_file, "component_start_failed")
        print(
            json.dumps(
                {"status": "failed", "error_code": "component_start_failed"},
                ensure_ascii=False,
            ),
            file=sys.stderr,
        )
        return 2
    return 0


def _managed_status(values: list[str]) -> int:
    """输出常规节点的脱敏 managed 状态，并用稳定代码表示本地读取失败。"""
    parser = argparse.ArgumentParser(description="查看 managed node 脱敏状态")
    parser.add_argument("managed-status")
    parser.add_argument("--data-dir", type=Path)
    args = parser.parse_args(values)

    from pydantic import ValidationError

    from tunnelminion.agent.managed_node import (
        MANAGED_NODE_CONFIG_FILE,
        FileManagedNodeConfigRepository,
        managed_node_secret_store,
        managed_node_status,
    )
    from tunnelminion.app import default_data_dir
    from tunnelminion.coordinator.client_credentials import AgentRefreshCredentialStore

    root = args.data_dir or default_data_dir()
    try:
        config = FileManagedNodeConfigRepository(root / MANAGED_NODE_CONFIG_FILE).load()
    except (OSError, ValidationError, ValueError):
        print(
            json.dumps(
                {"status": "unavailable", "error_code": "managed_config_invalid"},
                ensure_ascii=False,
            )
        )
        return 2
    if config is None or not config.enabled:
        status = managed_node_status(config)
    else:
        try:
            credentials = AgentRefreshCredentialStore(
                managed_node_secret_store(root, config.secret_store)
            )
            status = managed_node_status(config, credentials)
        except (OSError, RuntimeError, ValueError):
            status = managed_node_status(config, error_code="secret_store_unavailable")
    print(status.model_dump_json())
    return 0


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
    if values and values[0] == "runtime":
        return _runtime_command(values)
    if values and values[0] == "runtime-child":
        return _runtime_child(values)
    if values and values[0] == "export":
        return _export_data(values)
    if values and values[0] == "uninstall":
        return _uninstall_data(values)
    if values and values[0] == "gateway-configure":
        return _configure_gateway(values)
    if values and values[0] == "coordinator-enroll":
        return _enroll_with_coordinator(values)
    if values and values[0] == "managed-status":
        return _managed_status(values)
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
