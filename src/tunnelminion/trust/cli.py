"""机主身份命令；确认恢复码前不创建本机文件或写入秘密。"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Callable
from pathlib import Path

from pydantic import ValidationError

from tunnelminion.app import default_data_dir, load_or_create_node_id
from tunnelminion.domain.tools import Platform
from tunnelminion.gateway.configuration import (
    FileGatewayConfigurationRepository,
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
from tunnelminion.trust.contracts import AlreadyInitializedError, IdentityError, IdentityStatus
from tunnelminion.trust.keys import InitializationKeys
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
        print(f"我的电脑名单版本：{status.roster_version}")
        print(f"我信任的人名单版本：{status.trust_list_version}")
        for device in status.devices:
            print(f"{device.display_name}（{device.node_id}）：{device.host}:{device.port}")


def owner_command(values: list[str], *, input_fn: Callable[[str], str] | None = None) -> int:
    """`tunnelminion owner init|status`。"""
    parser = argparse.ArgumentParser(description="管理本机机主身份")
    parser.add_argument("owner")
    commands = parser.add_subparsers(dest="action", required=True)
    init = commands.add_parser("init", help="初始化本机机主身份")
    init.add_argument("--data-dir", type=Path)
    init.add_argument("--secret-store", choices=("keyring", "restricted-file"))
    init.add_argument("--bind-host")
    init.add_argument("--bind-port", type=int, default=8787)
    init.add_argument("--display-name")
    status = commands.add_parser("status", help="查看本机身份和名单")
    status.add_argument("--data-dir", type=Path)
    status.add_argument("--json", action="store_true")
    args = parser.parse_args(values)
    root = args.data_dir or default_data_dir()
    database = root / "runtime.sqlite3"
    try:
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
        if SQLiteTrustStore.is_initialized(database):
            raise AlreadyInitializedError("本机身份已经初始化，不能重复初始化")
        secrets = (
            RestrictedFileSecretStore(root / "gateway-secrets")
            if args.secret_store == "restricted-file"
            else KeyringSecretStore()
            if args.secret_store == "keyring"
            else gateway_secret_store(root)
        )
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
        confirmation = (input_fn or input)("抄好后，请输入恢复码前 4 个字符：")
        if confirmation.strip().upper() != keys.recovery_code[:4]:
            print("确认不符，未保存身份或密钥")
            return 2
        if args.secret_store is not None:
            secrets = configure_gateway_secret_store(
                root, GatewaySecretStoreKind(args.secret_store)
            )
        view = OwnerIdentityService(SQLiteStores.open(database).trust, secrets).init(
            load_or_create_node_id(root / "node-id"), bind, name, keys, platform
        )
        _print_status(view, False)
        return 0
    except (EOFError, KeyboardInterrupt):
        print("已取消，未保存身份或密钥")
        return 2
    except (IdentityError, SecretStoreError, VerificationError) as exc:
        print(str(exc))
        return 2
    except ValidationError:
        print("本机身份配置无效，请检查组网地址、端口和显示名")
        return 2
