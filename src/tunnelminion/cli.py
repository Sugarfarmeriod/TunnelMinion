"""TunnelMinion 本地节点启动命令。"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from collections.abc import Callable, Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

import uvicorn

from tunnelminion.repair.service import RepairService

_SUPPORTED_REMOTE_OPERATIONS = ("share_local_http_service",)
_UNINSTALL_CONFIRMATION = "DELETE-TUNNELMINION-DATA"


def _local_repair_service(data_dir: Path | None) -> RepairService:
    from importlib import import_module

    factory = cast(
        Callable[[Path | None], RepairService],
        import_module("tunnelminion.repair.local").build_local_repair_service,
    )
    return factory(data_dir)


_repair_service_factory: Callable[[Path | None], RepairService] = _local_repair_service


def _repair_command(values: list[str]) -> int:
    """由本机命令行提出、批准或拒绝固定修法。"""
    from tunnelminion.domain.identifiers import OperationId
    from tunnelminion.operation.contracts import OperationStatus
    from tunnelminion.repair.contracts import RepairKind, RepairOrigin, RepairOriginKind
    from tunnelminion.repair.eligibility import RepairRefusal

    command = values[0]
    parser = argparse.ArgumentParser()
    parser.add_argument(command)
    parser.add_argument("--data-dir", type=Path)
    if command == "repair-propose":
        parser.add_argument("--service-key", required=True)
        parser.add_argument(
            "--kind", choices=tuple(kind.value for kind in RepairKind), required=True
        )
        parser.add_argument("--reason", required=True)
    elif command != "repair-list":
        parser.add_argument("--repair-id", required=True)
        if command == "repair-reject":
            parser.add_argument("--reason")
    args = parser.parse_args(values)
    service = _repair_service_factory(args.data_dir)
    if command == "repair-propose":
        try:
            record = asyncio.run(
                service.propose(
                    args.service_key,
                    RepairKind(args.kind),
                    args.reason,
                    RepairOrigin(kind=RepairOriginKind.LOCAL_CLI),
                    actor="local-cli",
                )
            )
        except RepairRefusal as exc:
            print(f"修不了：{exc.error.message}")
            if exc.error.next_step:
                print(exc.error.next_step)
            return 1
        print(f"已生成修复 {record.plan.operation_id}：{record.plan.action_summary}")
        print(
            f"运行 tunnelminion repair-approve --repair-id {record.plan.operation_id} "
            "批准（10 分钟内有效）。"
        )
        return 0
    if command == "repair-list":
        records = service.list()
        for record in records:
            print(
                f"{record.plan.operation_id}  {record.status.value}  "
                f"{record.plan.service_name}  {record.plan.action_summary}"
            )
        if not records:
            print("还没有修复记录。")
        return 0
    try:
        repair_id = OperationId(args.repair_id)
    except ValueError:
        print("修复不存在")
        return 1
    try:
        if command == "repair-reject":
            service.reject(repair_id, operator="local-cli", reason=args.reason)
            print(f"已拒绝修复 {repair_id}，什么都不会做。")
            return 0
        service.approve(repair_id, operator="local-cli")
    except KeyError:
        print("修复不存在")
        return 1
    except ValueError:
        print("这个修复现在不等批准")
        return 1
    record = asyncio.run(service.execute(repair_id))
    if record.status is OperationStatus.SUCCEEDED:
        print(f"修好了：{record.plan.action_summary}")
    else:
        assert record.error is not None
        print(f"没修好：{record.error.message}")
        if record.error.next_step:
            print(record.error.next_step)
    if record.verification is not None:
        for check in record.verification.checks:
            print(f"- {check.detail}")
        if record.verification.log_excerpt:
            print("日志要点：")
            print(record.verification.log_excerpt)
    return 0 if record.status is OperationStatus.SUCCEEDED else 1


def _retain_local_application_owner(application: object, bundle: object) -> None:
    """把常规本地 managed owner 绑定到裸 FastAPI 应用。"""
    state = getattr(application, "state", None)
    owner = getattr(bundle, "managed_node", None)
    if state is not None and owner is not None:
        state.managed_node = owner


def _runtime_port(value: str) -> int:
    """解析 runtime 本地端口，同时保持帮助文本简短。"""
    port = int(value)
    if not 1024 <= port <= 65535:
        raise argparse.ArgumentTypeError("端口必须在 1024 到 65535 之间")
    return port


def _runtime_command(values: list[str]) -> int:
    """配置或执行不注册系统自启动项的手工 runtime 操作。"""
    parser = argparse.ArgumentParser(description="手工管理 TunnelMinion 常驻组件")
    parser.add_argument("runtime")
    parser.add_argument("action", choices=("configure", "start", "status", "stop"))
    parser.add_argument("--profile", type=Path)
    parser.add_argument("--data-dir", type=Path)
    parser.add_argument("--local-port", type=_runtime_port, default=8000)
    parser.add_argument("--enable-gateway", action="store_true")
    parser.add_argument("--read-only-preview", action="store_true")
    args = parser.parse_args(values)

    from tunnelminion.runtime.control import (
        build_lifecycle_manager,
        build_runtime_preflight,
        profile_summary,
        runtime_control_view,
    )
    from tunnelminion.runtime.lifecycle import ComponentRuntimeState
    from tunnelminion.runtime.preflight import PreflightStatus
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
        if args.read_only_preview:
            parser.error("预览开关只用于运行，不写入 profile")
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
    if args.read_only_preview and profile.enabled_components != frozenset({RuntimeComponent.LOCAL}):
        print(json.dumps({"status": "failed", "error_code": "preview_requires_local"}))
        return 2
    manager = build_lifecycle_manager(profile, paths, read_only_preview=args.read_only_preview)
    preflight_report = None
    try:
        if args.action == "start":
            current = manager.status()
            active_components = frozenset(
                item.component
                for item in current.components
                if item.state is ComponentRuntimeState.RUNNING
            )
            preflight_report = build_runtime_preflight().run(
                paths,
                active_components=active_components,
            )
            global_failure = any(
                item.status is PreflightStatus.FAILED
                and item.name in {"package", "profile", "data-dir"}
                for item in preflight_report.checks
            )
            if global_failure:
                print(
                    json.dumps(
                        {
                            "status": "failed",
                            "error_code": "runtime_preflight_failed",
                            "preflight": preflight_report.model_dump(mode="json"),
                        },
                        ensure_ascii=False,
                        separators=(",", ":"),
                    )
                )
                return 2
        report = getattr(manager, args.action)()
    except RuntimeOperationBusy:
        print(
            json.dumps(
                {"status": "failed", "error_code": "runtime_operation_busy"},
                ensure_ascii=False,
            )
        )
        return 2
    view = runtime_control_view(report, profile, paths, read_only_preview=args.read_only_preview)
    if preflight_report is None:
        print(view.model_dump_json())
    else:
        output = view.model_dump(mode="json")
        output["preflight"] = preflight_report.model_dump(mode="json")
        print(json.dumps(output, ensure_ascii=False, separators=(",", ":")))
    return report.exit_code


def _runtime_package_command(values: list[str]) -> int:
    """管理与生产数据分离的版本化程序目录。"""
    parser = argparse.ArgumentParser(description="安装、切换或移除 TunnelMinion 运行包")
    parser.add_argument("runtime-package")
    subparsers = parser.add_subparsers(dest="action", required=True)

    def add_common(target: argparse.ArgumentParser) -> None:
        target.add_argument("--profile", type=Path)
        target.add_argument("--install-root", type=Path)

    stage_parser = subparsers.add_parser("stage", help="校验并并行放置新版本")
    add_common(stage_parser)
    stage_parser.add_argument("--package-root", type=Path, required=True)
    stage_parser.add_argument("--manifest", type=Path, required=True)
    activate_parser = subparsers.add_parser("activate", help="在组件停止后切换版本")
    add_common(activate_parser)
    activate_parser.add_argument("--package-id", required=True)
    status_parser = subparsers.add_parser("status", help="查看当前和上一程序版本")
    add_common(status_parser)
    remove_parser = subparsers.add_parser("remove", help="只移除程序并保留数据和秘密")
    add_common(remove_parser)
    args = parser.parse_args(values)

    from tunnelminion.runtime.install import (
        RuntimePackageInstaller,
        default_runtime_install_root,
    )
    from tunnelminion.runtime.process import DetachedProcessAdapter, ProcessRecordRepository
    from tunnelminion.runtime.profile import (
        FileRuntimeProfileRepository,
        current_program_dir,
        default_runtime_profile_path,
        resolve_runtime_paths,
    )

    profile_path = (args.profile or default_runtime_profile_path()).expanduser().resolve()
    try:
        profile = FileRuntimeProfileRepository(profile_path, current_program_dir()).load()
        if profile is None:
            raise ValueError("runtime profile missing")
        paths = resolve_runtime_paths(profile.data_dir, profile_path)
        installer = RuntimePackageInstaller(
            args.install_root or default_runtime_install_root(),
            profile.data_dir,
        )
    except (OSError, ValueError):
        print(json.dumps({"status": "failed", "error_code": "runtime_profile_invalid"}))
        return 2

    records = ProcessRecordRepository(paths.state_dir)
    processes = DetachedProcessAdapter()

    def stopped() -> bool:
        try:
            return all(
                (record := records.load(component)) is None or processes.inspect(record.pid) is None
                for component in profile.enabled_components
            )
        except (OSError, ValueError):
            return False

    try:
        if args.action == "stage":
            package = installer.stage(args.package_root, args.manifest)
            output: dict[str, object] = {
                "status": "staged",
                "package_id": package.package_id,
                "application_version": package.application_version,
                "manifest_sha256": package.manifest_sha256,
            }
        elif args.action == "activate":
            state = installer.activate(args.package_id, stopped)
            output = {
                "status": "activated",
                "current_package_id": state.current_package_id,
                "previous_package_id": state.previous_package_id,
            }
        elif args.action == "status":
            state = installer.load()
            program = installer.current_program_dir()
            output = {
                "status": "ready",
                "current_package_id": state.current_package_id,
                "previous_package_id": state.previous_package_id,
                "installed_package_ids": [item.package_id for item in state.packages],
                "current_program_directory": str(program) if program is not None else None,
                "data_dir_sha256": state.data_dir_sha256,
            }
        else:
            removed = installer.remove_program(stopped)
            output = {
                "status": "removed",
                "removed_package_ids": list(removed),
                "data_preserved": True,
                "secret_store_preserved": True,
            }
    except RuntimeError:
        print(json.dumps({"status": "failed", "error_code": "runtime_components_running"}))
        return 2
    except (KeyError, OSError, ValueError):
        print(json.dumps({"status": "failed", "error_code": "runtime_package_invalid"}))
        return 2
    print(json.dumps(output, ensure_ascii=False, separators=(",", ":")))
    return 0


def _runtime_child(values: list[str]) -> int:
    """运行单个真实组件，并把启动异常收敛为零秘密稳定错误。"""
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("runtime-child")
    parser.add_argument("--runtime-component", choices=("local", "gateway"), required=True)
    parser.add_argument("--runtime-instance-id", required=True)
    parser.add_argument("--data-dir", type=Path, required=True)
    parser.add_argument("--local-port", type=int, required=True, choices=range(1024, 65536))
    parser.add_argument("--runtime-log-file", type=Path, required=True)
    parser.add_argument("--read-only-preview", action="store_true")
    args = parser.parse_args(values)

    from uuid import UUID

    from tunnelminion.runtime.logging import runtime_log_config, write_runtime_event

    try:
        UUID(args.runtime_instance_id)
        if args.runtime_component == "gateway":
            if args.read_only_preview:
                raise ValueError("预览模式只允许本机页面")
            if sys.platform == "darwin":
                from tunnelminion.macos_app import build_macos_gateway_application

                bundle = build_macos_gateway_application(args.data_dir)
            else:
                from tunnelminion.app import build_windows_gateway_application

                bundle = build_windows_gateway_application(args.data_dir)
            application = bundle.app
            host = bundle.bind.host
            port = bundle.bind.port
        else:
            host = "127.0.0.1"
            port = args.local_port
            if sys.platform == "darwin":
                from tunnelminion.macos_app import build_macos_local_application

                bundle = build_macos_local_application(
                    args.data_dir, read_only_preview=args.read_only_preview
                )
            else:
                from tunnelminion.app import build_windows_application

                bundle = build_windows_application(
                    args.data_dir, read_only_preview=args.read_only_preview
                )
            application = bundle.app
            _retain_local_application_owner(application, bundle)
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
    from tunnelminion.app import default_data_dir, load_or_create_node_id
    from tunnelminion.domain.model_borrowing import DEFAULT_DAILY_TOKEN_QUOTA
    from tunnelminion.gateway.configuration import DEFAULT_GATEWAY_TOOLS

    parser = argparse.ArgumentParser(description="配置只读 Tool Gateway 与对端")
    parser.add_argument("gateway-configure")
    parser.add_argument("--data-dir", type=Path)
    parser.add_argument("--bind-host", required=True)
    parser.add_argument("--bind-port", type=int, default=8787)
    parser.add_argument("--peer-node-id", required=True)
    parser.add_argument("--peer-platform", choices=("windows", "macos"), required=True)
    parser.add_argument("--peer-host", required=True)
    parser.add_argument("--peer-port", type=int, default=8787)
    parser.add_argument("--allowed-tool", action="append", choices=DEFAULT_GATEWAY_TOOLS)
    parser.add_argument(
        "--allowed-operation",
        action="append",
        choices=_SUPPORTED_REMOTE_OPERATIONS,
    )
    parser.add_argument(
        "--allow-delegation",
        action="store_true",
        help="允许这个对端把问题交给本机的 Agent 处理（默认不允许）",
    )
    parser.add_argument(
        "--allow-model-borrowing",
        action="store_true",
        help="允许这个对端借用本机配置的模型（默认不允许）",
    )
    parser.add_argument("--daily-quota", type=int, default=DEFAULT_DAILY_TOKEN_QUOTA)
    parser.add_argument(
        "--secret-store",
        choices=("keyring", "restricted-file"),
        default="keyring",
    )
    args = parser.parse_args(values)

    from tunnelminion.domain.identifiers import NodeId
    from tunnelminion.domain.tools import Platform
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
                platform=Platform(args.peer_platform),
                host=args.peer_host,
                port=args.peer_port,
                allowed_tools=frozenset(args.allowed_tool or DEFAULT_GATEWAY_TOOLS),
                allowed_operations=frozenset(args.allowed_operation or ()),
                allow_delegation=args.allow_delegation,
                allow_model_borrowing=args.allow_model_borrowing,
                daily_quota=args.daily_quota,
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


def _invite(values: list[str]) -> int:
    """生成仅可用一次的邀请码，必要时配置本机网关地址。"""
    from tunnelminion.agent.invites import InviteService
    from tunnelminion.app import default_data_dir, load_or_create_node_id
    from tunnelminion.domain.invites import InvitePermissions
    from tunnelminion.domain.model_borrowing import DEFAULT_DAILY_TOKEN_QUOTA
    from tunnelminion.domain.tools import Platform
    from tunnelminion.gateway.configuration import (
        FileGatewayConfigurationRepository,
        GatewayConfigurationService,
        GatewaySecretStoreKind,
        configure_gateway_secret_store,
        gateway_secret_store,
    )
    from tunnelminion.gateway.security import GatewayBindConfig
    from tunnelminion.memory.sqlite import SQLiteStores

    parser = argparse.ArgumentParser(description="生成 TunnelMinion 邀请码")
    parser.add_argument("invite")
    parser.add_argument("--data-dir", type=Path)
    parser.add_argument("--bind-host")
    parser.add_argument("--bind-port", type=int, default=8787)
    parser.add_argument("--allow-delegation", action="store_true")
    parser.add_argument("--allow-model-borrowing", action="store_true")
    parser.add_argument("--daily-quota", type=int, default=DEFAULT_DAILY_TOKEN_QUOTA)
    parser.add_argument("--secret-store", choices=("keyring", "restricted-file"))
    args = parser.parse_args(values)
    permissions = InvitePermissions(
        allow_delegation=args.allow_delegation,
        allow_model_borrowing=args.allow_model_borrowing,
        daily_quota=args.daily_quota,
    )
    root = args.data_dir or default_data_dir()
    configuration = GatewayConfigurationService(
        FileGatewayConfigurationRepository(root / "gateway.json"),
        (
            configure_gateway_secret_store(root, GatewaySecretStoreKind(args.secret_store))
            if args.secret_store is not None
            else gateway_secret_store(root)
        ),
    )
    if not configuration.view().configured:
        if args.bind_host is None:
            print("本机网关还没有配置，请加上 --bind-host <本机组网地址>")
            return 2
        configuration.configure_local(GatewayBindConfig(host=args.bind_host, port=args.bind_port))
    service = InviteService(
        load_or_create_node_id(root / "node-id"),
        Platform.MACOS if sys.platform == "darwin" else Platform.WINDOWS,
        configuration,
        SQLiteStores.open(root / "runtime.sqlite3").invites,
    )
    code = service.create(permissions).encode()
    print(
        f"邀请码（24 小时内有效，只能用一次）：\n{code}\n\n"
        f"在要加入的电脑上运行：\ntunnelminion join {code}\n\n"
        "提醒：网关要保持运行，对方才能加入。"
    )
    if args.allow_model_borrowing:
        print(
            f"对方借用模型时，他发出的问题会经过本机的模型；每天额度 {args.daily_quota} 个 token。"
        )
    return 0


def _model_usage(values: list[str]) -> int:
    """只读输出本地当天各对端的模型用量。"""
    import sqlite3
    from contextlib import closing
    from datetime import date

    from tunnelminion.app import default_data_dir
    from tunnelminion.domain.identifiers import NodeId
    from tunnelminion.domain.model_borrowing import ModelUsageRecord

    parser = argparse.ArgumentParser(description="查看今日模型借用用量")
    parser.add_argument("model-usage")
    parser.add_argument("--data-dir", type=Path)
    args = parser.parse_args(values)
    path = (args.data_dir or default_data_dir()) / "runtime.sqlite3"
    if not path.is_file():
        return 0
    with closing(sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True)) as connection:
        if not connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='model_usage'"
        ).fetchone():
            return 0
        today = date.today()
        rows = connection.execute(
            "SELECT peer_node_id, calls, tokens FROM model_usage WHERE day=? ORDER BY peer_node_id",
            (today.isoformat(),),
        ).fetchall()
    for peer, calls, tokens in rows:
        print(
            ModelUsageRecord(
                peer_node_id=NodeId(peer), day=today, calls=calls, tokens=tokens
            ).model_dump_json()
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


def _borrow_model(values: list[str]) -> int:
    """验证并启用固定对端的借用模型。"""
    parser = argparse.ArgumentParser()
    parser.add_argument("model-borrow")
    parser.add_argument("--from", dest="peer_node_id", required=True)
    parser.add_argument("--data-dir", type=Path)
    args = parser.parse_args(values)

    from tunnelminion.app import build_windows_node
    from tunnelminion.domain.identifiers import NodeId
    from tunnelminion.macos_app import build_macos_local_application

    service = (
        build_macos_local_application(args.data_dir).node.model_service
        if sys.platform == "darwin"
        else build_windows_node(args.data_dir).model_service
    )
    view = asyncio.run(service.borrow(NodeId(args.peer_node_id)))
    print(view.model_dump_json())
    return 0


def _join(values: list[str]) -> int:
    """解析邀请码并加入对方电脑。"""
    from tunnelminion.agent.join import JoinError, join
    from tunnelminion.domain.invites import InviteCode
    from tunnelminion.gateway.client import InviteHandshakeError
    from tunnelminion.gateway.configuration import GatewaySecretStoreKind

    parser = argparse.ArgumentParser(description="用邀请码加入对方电脑")
    parser.add_argument("join")
    parser.add_argument("code")
    parser.add_argument("--data-dir", type=Path)
    parser.add_argument("--host")
    parser.add_argument("--bind-port", type=_runtime_port, default=8787)
    parser.add_argument("--secret-store", choices=("keyring", "restricted-file"))
    model = parser.add_mutually_exclusive_group()
    model.add_argument("--use-borrowed-model", dest="use_borrowed_model", action="store_true")
    model.add_argument("--keep-model", dest="use_borrowed_model", action="store_false")
    parser.set_defaults(use_borrowed_model=None)
    args = parser.parse_args(values)
    try:
        code = InviteCode.decode(args.code)
    except ValueError:
        print("这不是有效的邀请码", file=sys.stderr)
        return 1
    try:
        asyncio.run(
            join(
                code,
                data_dir=args.data_dir,
                host_override=args.host,
                bind_port=args.bind_port,
                secret_store_kind=(
                    GatewaySecretStoreKind(args.secret_store)
                    if args.secret_store is not None
                    else None
                ),
                use_borrowed_model=args.use_borrowed_model,
            )
        )
    except JoinError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    except InviteHandshakeError as exc:
        message = {
            "invalid": "邀请码无效、已过期或已被使用",
            "rate_limited": "对方电脑暂时拒绝了请求，请稍后再试",
            "unreachable": (
                f"连不上对方电脑（{code.host}:{code.port}）。请确认组网已连通、对方的网关正在运行"
            ),
            "bad_response": "这不是有效的邀请码",
        }[exc.reason]
        print(message, file=sys.stderr)
        return 1
    except ValueError:
        print("这不是有效的邀请码", file=sys.stderr)
        return 1
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    """启动本地面板，或按配置启动只绑定 WireGuard 地址的 macOS 网关。"""
    values = list(sys.argv[1:] if argv is None else argv)
    if values and values[0] == "runtime":
        return _runtime_command(values)
    if values and values[0] == "runtime-package":
        return _runtime_package_command(values)
    if values and values[0] == "runtime-child":
        return _runtime_child(values)
    if values and values[0] == "export":
        return _export_data(values)
    if values and values[0] == "uninstall":
        return _uninstall_data(values)
    if values and values[0] == "gateway-configure":
        return _configure_gateway(values)
    if values and values[0] == "invite":
        return _invite(values)
    if values and values[0] == "model-usage":
        return _model_usage(values)
    if values and values[0] == "coordinator-enroll":
        return _enroll_with_coordinator(values)
    if values and values[0] == "managed-status":
        return _managed_status(values)
    if values and values[0] == "operation-approve":
        return _approve_operation(values)
    if values and values[0] in {"repair-propose", "repair-list", "repair-approve", "repair-reject"}:
        return _repair_command(values)
    if values and values[0] == "operation-preauthorize":
        return _create_operation_preauthorization(values)
    if values and values[0] == "model-borrow":
        return _borrow_model(values)
    if values and values[0] == "join":
        return _join(values)
    if values and values[0] == "gateway":
        parser = argparse.ArgumentParser(description="启动只读 Tool Gateway")
        parser.add_argument("gateway")
        parser.add_argument("--data-dir", type=Path)
        parser.add_argument("--enable-safe-sharing", action="store_true")
        parser.add_argument("--sharing-min-port", type=int, default=18_880)
        parser.add_argument("--sharing-max-port", type=int, default=18_899)
        parser.add_argument("--sharing-max-duration", type=int, default=3600)
        parser.add_argument("--sharing-gateway-port", type=int)
        args = parser.parse_args(values)
        if sys.platform != "darwin":
            if args.enable_safe_sharing:
                raise SystemExit("Windows 网关暂不支持临时 HTTP 共享")
            from tunnelminion.app import build_windows_gateway_application

            windows = build_windows_gateway_application(args.data_dir)
            uvicorn.run(windows.app, host=windows.bind.host, port=windows.bind.port)
            return 0
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
    parser.add_argument("--port", type=_runtime_port, default=8765)
    parser.add_argument("--data-dir", type=Path)
    args = parser.parse_args(values)
    if args.data_dir is not None:
        if sys.platform == "darwin":
            from tunnelminion.macos_app import build_macos_local_application

            bundle = build_macos_local_application(args.data_dir)
        else:
            from tunnelminion.app import build_windows_application

            bundle = build_windows_application(args.data_dir)
        application = bundle.app
        _retain_local_application_owner(application, bundle)
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
