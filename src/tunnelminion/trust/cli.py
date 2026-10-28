"""机主身份命令；确认恢复码前不创建本机文件或写入秘密。"""

from __future__ import annotations

import argparse
import asyncio
import getpass
import sys
from collections.abc import Callable
from pathlib import Path

from pydantic import ValidationError

from tunnelminion.app import default_data_dir, load_or_create_node_id
from tunnelminion.domain.identifiers import NodeId
from tunnelminion.domain.tools import Platform
from tunnelminion.domain.trust import InvalidJoinCodeError, JoinCode, JoinCodeKind
from tunnelminion.gateway.configuration import (
    FileGatewayConfigurationRepository,
    GatewayConfigurationService,
    GatewaySecretStoreKind,
    configure_gateway_secret_store,
    gateway_secret_store,
)
from tunnelminion.gateway.names import NodeNameConfiguration, load_node_name
from tunnelminion.gateway.security import GatewayBindConfig
from tunnelminion.memory.sqlite import SQLiteStores, SQLiteTrustStore
from tunnelminion.model.secrets import (
    KeyringSecretStore,
    RestrictedFileSecretStore,
    SecretStoreError,
)
from tunnelminion.trust.contracts import (
    AlreadyInitializedError,
    DevicePermissions,
    IdentityError,
    IdentityStatus,
)
from tunnelminion.trust.devices import OwnDevicesService
from tunnelminion.trust.join import join_owner
from tunnelminion.trust.keys import InitializationKeys, PrivateKey
from tunnelminion.trust.recovery import check_recovery_devices, recover_owner, recovery_key
from tunnelminion.trust.service import OwnerIdentityService, ensure_no_identity_keys
from tunnelminion.trust.signatures import VerificationError


def _print_status(status: IdentityStatus, as_json: bool) -> None:
    if as_json:
        print(status.model_dump_json(indent=2))
    elif status.owner_fingerprint is None:
        print("本机身份尚未初始化")
    else:
        print(f"机主指纹：{status.owner_fingerprint}")
        print(f"本机持有机主密钥：{'是' if status.has_owner_key else '否'}")
        if status.removed:
            print("本机已被移出我的电脑，已停止使用通行证")
        print(f"我的电脑名单版本：{status.roster_version}")
        print(f"我信任的人名单版本：{status.trust_list_version}")
        for device in status.devices:
            print(f"{device.display_name}（{device.node_id}）：{device.host}:{device.port}")


def _normalized_code(value: str) -> str:
    return "".join(char for char in value.upper() if char != "-" and not char.isspace())


def _confirm_recovery_code(read: Callable[[str], str], code: str) -> bool:
    """请机主把恢复码完整输入一遍；忽略大小写、空格和连字符。"""
    return _normalized_code(read("抄好后，请把恢复码完整输入一遍：")) == _normalized_code(code)


def owner_command(values: list[str], *, input_fn: Callable[[str], str] | None = None) -> int:
    """管理机主身份、我的电脑及其本机权限。"""
    parser = argparse.ArgumentParser(description="管理本机机主身份")
    parser.add_argument("owner")
    commands = parser.add_subparsers(dest="action", required=True)
    init = commands.add_parser("init", help="初始化本机机主身份")
    init.add_argument("--data-dir", type=Path)
    init.add_argument("--secret-store", choices=("keyring", "restricted-file"))
    init.add_argument("--bind-host")
    init.add_argument("--bind-port", type=int, default=8787)
    init.add_argument("--display-name")
    init.add_argument("--reset", action="store_true")
    status = commands.add_parser("status", help="查看本机身份和名单")
    status.add_argument("--data-dir", type=Path)
    status.add_argument("--json", action="store_true")
    invite = commands.add_parser("invite", help="生成加入我的电脑的一次性加入码")
    invite.add_argument("--data-dir", type=Path)
    join = commands.add_parser("join", help="加入我的电脑")
    join.add_argument("code")
    join.add_argument("--data-dir", type=Path)
    join.add_argument("--secret-store", choices=("keyring", "restricted-file"))
    join.add_argument("--bind-host")
    join.add_argument("--bind-port", type=int)
    join.add_argument("--reset", action="store_true")
    recover = commands.add_parser("recover", help="用交互输入的恢复码更换机主密钥")
    recover.add_argument("--data-dir", type=Path)
    recover.add_argument("--remove", type=NodeId, action="append", default=[])
    remove = commands.add_parser("remove", help="移除我的一台电脑")
    remove.add_argument("node_id", type=NodeId)
    remove.add_argument("--data-dir", type=Path)
    permissions = commands.add_parser("device-permissions", help="收紧本机对我的电脑的权限")
    permissions.add_argument("node_id", type=NodeId)
    permissions.add_argument("--data-dir", type=Path)
    permissions.add_argument("--no-proxy-repair-approval", action="store_true")
    permissions.add_argument("--no-delegation", action="store_true")
    permissions.add_argument("--no-model-borrowing", action="store_true")
    permissions.add_argument("--daily-quota", type=int)
    args = parser.parse_args(values)
    root = args.data_dir or default_data_dir()
    database = root / "runtime.sqlite3"
    try:
        reset = args.action in ("init", "join") and args.reset
        if reset:
            # 这里只确认；真正清掉旧身份要等新身份准备好，和写入新身份放在同一个事务里。
            confirmation = (input_fn or input)("这会清除本机现有身份。请输入“重置”确认：")
            if confirmation.strip() != "重置":
                print("未确认重置，本机身份未改动")
                return 2
        if args.action == "recover":
            if not SQLiteTrustStore.is_initialized(database):
                raise IdentityError("本机身份尚未初始化")
            roster = SQLiteTrustStore.read_roster(database)
            node_id = NodeId((root / "node-id").read_text(encoding="utf-8").strip())
            removed = tuple(args.remove)
            check_recovery_devices(roster, node_id, removed)
            key = recovery_key(roster, (input_fn or getpass.getpass)("请输入恢复码："))
            new_owner, new_recovery = PrivateKey.generate(), PrivateKey.generate()
            code = new_recovery.recovery_code()
            print(f"恢复码（只显示这一次，请抄写并妥善保管）：\n{code}")
            if not _confirm_recovery_code(input_fn or input, code):
                print("确认不符，未保存身份或密钥")
                return 2
            service = OwnDevicesService(
                node_id, SQLiteStores.open(database).trust, gateway_secret_store(root)
            )
            targets = recover_owner(service, key, new_owner, new_recovery, removed)
            failed = asyncio.run(service.push(targets))
            print("已恢复机主身份并更换密钥，旧恢复码已作废")
            for target in failed:
                print(f"这次没推到 {target}，下次接触时会同步")
            return 0
        if args.action == "join":
            asyncio.run(
                join_owner(
                    JoinCode.decode(args.code, JoinCodeKind.OWNER),
                    root,
                    host_override=args.bind_host,
                    port_override=args.bind_port,
                    secret_store_kind=GatewaySecretStoreKind(args.secret_store)
                    if args.secret_store
                    else None,
                    reset=reset,
                )
            )
            print("已加入我的电脑，可以启动本机网关")
            return 0
        if args.action == "status":
            view = (
                OwnerIdentityService(
                    SQLiteStores.open(database).trust, gateway_secret_store(root)
                ).status()
                if SQLiteTrustStore.is_initialized(database)
                else IdentityStatus()
            )
            _print_status(view, args.json)
            return 0
        if args.action in ("invite", "remove", "device-permissions"):
            if not SQLiteTrustStore.is_initialized(database):
                raise IdentityError("本机身份尚未初始化")
            service = OwnDevicesService(
                NodeId((root / "node-id").read_text(encoding="utf-8").strip()),
                SQLiteStores.open(database).trust,
                gateway_secret_store(root),
            )
            if args.action == "invite":
                print(service.invite().encode())
            elif args.action == "remove":
                targets = service.remove(args.node_id)
                failed = asyncio.run(service.push(targets))
                print("已从我的电脑移除指定节点")
                for node_id in failed:
                    print(f"这次没推到 {node_id}，下次接触时会同步")
            else:
                current = service.store.device_permissions(args.node_id)
                service.restrict(
                    args.node_id,
                    DevicePermissions(
                        allow_proxy_repair_approval=current.allow_proxy_repair_approval
                        and not args.no_proxy_repair_approval,
                        allow_delegation=current.allow_delegation and not args.no_delegation,
                        allow_model_borrowing=current.allow_model_borrowing
                        and not args.no_model_borrowing,
                        daily_quota=args.daily_quota
                        if args.daily_quota is not None
                        else current.daily_quota,
                    ),
                )
                print("已收紧这台电脑在本机的权限")
            return 0
        if not reset and SQLiteTrustStore.is_initialized(database):
            raise AlreadyInitializedError("本机身份已经初始化，不能重复初始化")
        previous_secrets = gateway_secret_store(root)
        secrets = (
            RestrictedFileSecretStore(root / "gateway-secrets")
            if args.secret_store == "restricted-file"
            else KeyringSecretStore()
            if args.secret_store == "keyring"
            else gateway_secret_store(root)
        )
        if not reset:
            ensure_no_identity_keys(secrets)
        configuration = FileGatewayConfigurationRepository(root / "gateway.json").load()
        if configuration is None and args.bind_host is None:
            print("本机网关还没有配置，请加上 --bind-host <本机组网地址>")
            return 2
        bind = (
            configuration.bind
            if configuration is not None
            else GatewayBindConfig(host=args.bind_host, port=args.bind_port)
        )
        platform = (
            Platform.MACOS
            if sys.platform == "darwin"
            else Platform.WINDOWS
            if sys.platform == "win32"
            else Platform.LINUX
        )
        name = NodeNameConfiguration(
            display_name=(
                args.display_name
                if args.display_name is not None
                else load_node_name(root, platform, persist_default=False)
            )
        ).display_name
        keys = InitializationKeys.generate()
        print(f"恢复码（只显示这一次，请抄写并妥善保管）：\n{keys.recovery_code}")
        if not _confirm_recovery_code(input_fn or input, keys.recovery_code):
            print("确认不符，未保存身份或密钥")
            return 2
        view = OwnerIdentityService(SQLiteStores.open(database).trust, secrets).init(
            load_or_create_node_id(root / "node-id"),
            bind,
            name,
            keys,
            platform,
            replace=reset,
            previous_secrets=previous_secrets if reset else None,
        )
        # 身份写入成功后才记下秘密后端的选择，失败时原来的选择不变。
        if args.secret_store is not None:
            configure_gateway_secret_store(root, GatewaySecretStoreKind(args.secret_store))
        # 本机还没有网关配置时，按这次的组网地址写一份，之后可以直接启动网关。
        if configuration is None:
            GatewayConfigurationService(
                FileGatewayConfigurationRepository(root / "gateway.json"), secrets
            ).configure_local(bind)
        _print_status(view, False)
        return 0
    except (EOFError, KeyboardInterrupt):
        print("已取消，未保存身份或密钥")
        return 2
    except (IdentityError, SecretStoreError, VerificationError, InvalidJoinCodeError) as exc:
        print(str(exc))
        return 2
    except ValidationError:
        print("本机身份配置无效，请检查组网地址、端口和显示名")
        return 2
