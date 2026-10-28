"""朋友配对、权限管理和逐条确认的旧式配对迁移。"""

from __future__ import annotations

import argparse
import asyncio
import json
from collections.abc import Callable
from pathlib import Path

from pydantic import ValidationError

from tunnelminion.app import default_data_dir
from tunnelminion.domain.trust import JoinCode, JoinCodeKind
from tunnelminion.gateway.configuration import (
    FileGatewayConfigurationRepository,
    GatewayConfigurationService,
    gateway_secret_store,
)
from tunnelminion.memory.sqlite import SQLiteTrustStore
from tunnelminion.model.secrets import SecretStoreError
from tunnelminion.trust.devices import OwnDevicesService
from tunnelminion.trust.friends import FriendsService
from tunnelminion.trust.local import friend_peers, update_friend_permissions
from tunnelminion.trust.local import load_devices as load_local_devices


def load_devices(root: Path) -> OwnDevicesService:
    return load_local_devices(root, gateway_secret_store(root))


def friend_command(values: list[str]) -> int:
    parser = argparse.ArgumentParser(description="按人管理朋友配对")
    parser.add_argument("friend")
    commands = parser.add_subparsers(dest="action", required=True)
    for name in ("invite", "join", "remove", "list", "permissions", "restrict", "rename"):
        command = commands.add_parser(name)
        command.add_argument("--data-dir", type=Path)
        if name == "join":
            command.add_argument("code")
        if name in ("join", "invite"):
            command.add_argument("--display-name")
        if name in ("remove", "permissions", "restrict", "rename"):
            command.add_argument("person")
        if name == "rename":
            command.add_argument("new_name")
        if name == "list":
            command.add_argument("--json", action="store_true")
        if name in ("permissions", "restrict"):
            borrowing = command.add_mutually_exclusive_group()
            borrowing.add_argument("--allow-model-borrowing", dest="borrowing", action="store_true")
            borrowing.add_argument("--no-model-borrowing", dest="borrowing", action="store_false")
            command.set_defaults(borrowing=None)
            command.add_argument("--no-delegation", action="store_true")
            command.add_argument("--daily-quota", type=int)
    args = parser.parse_args(values)
    root = args.data_dir or default_data_dir()
    try:
        devices = load_devices(root)
        service = FriendsService(devices)
        if args.action == "invite":
            print(service.invite(args.display_name).encode())
            return 0
        if args.action == "join":
            asyncio.run(
                service.join(JoinCode.decode(args.code, JoinCodeKind.FRIEND), args.display_name)
            )
            print("已和朋友按人配对")
            return 0
        if args.action == "list":
            configuration = GatewayConfigurationService(
                FileGatewayConfigurationRepository(root / "gateway.json"),
                devices.secrets,
                owner_devices=devices,
            )
            people = friend_peers(devices, configuration)
            if args.json:
                print(
                    json.dumps(
                        [
                            {
                                "owner_fingerprint": friend.friend_fingerprint,
                                "display_name": friend.display_name,
                                "permissions": friend.permissions.model_dump(),
                                "devices": [
                                    device.model_dump(mode="json") for device in friend.devices
                                ],
                                "conflicting_devices": list(friend.conflicting),
                            }
                            for friend in people
                        ],
                        ensure_ascii=False,
                        indent=2,
                    )
                )
            else:
                for friend in people:
                    print(f"{friend.display_name}（{friend.friend_fingerprint}）")
                    for node_id in friend.conflicting:
                        print(f"  {node_id}：和其他朋友的电脑编号冲突，暂不认")
                    for device in friend.devices:
                        print(
                            f"  {device.display_name}："
                            f"可提问={'是' if device.allow_delegation else '否'}，"
                            f"可借模型={'是' if device.allow_model_borrowing else '否'}，"
                            f"每日额度={device.daily_quota}"
                        )
            return 0
        if args.action == "remove":
            service.remove(args.person)
            print("已移除朋友")
        elif args.action == "rename":
            service.rename(args.person, args.new_name)
            print("已修改朋友的显示名")
        else:
            update_friend_permissions(
                service,
                args.person,
                close_delegation=args.no_delegation,
                allow_model_borrowing=args.borrowing,
                daily_quota=args.daily_quota,
                restrict=args.action == "restrict",
            )
            if args.action == "restrict":
                print("已收紧朋友在本机的权限")
                return 0
            print("已更新朋友的默认权限")
        failed = asyncio.run(devices.push())
        for node_id in failed:
            print(f"这次没推到 {node_id}，下次接触时会同步")
        return 0
    except ValidationError:
        print("朋友配置无效，请检查显示名和每日额度")
        return 2
    except (ValueError, SecretStoreError) as exc:
        print(str(exc))
        return 2


def peers_command(values: list[str], *, input_fn: Callable[[str], str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="逐条确认迁移旧式配对")
    parser.add_argument("peers")
    parser.add_argument("action", choices=("migrate",))
    parser.add_argument("--data-dir", type=Path)
    args = parser.parse_args(values)
    root = args.data_dir or default_data_dir()
    try:
        repository = FileGatewayConfigurationRepository(root / "gateway.json")
        config = repository.load()
        if config is None or not config.peers:
            print("没有旧式配对")
            return 0
        devices = (
            load_devices(root)
            if SQLiteTrustStore.is_initialized(root / "runtime.sqlite3")
            else None
        )
        service = GatewayConfigurationService(
            repository, gateway_secret_store(root), owner_devices=devices
        )
        for peer in config.peers:
            print(f"旧式配对：{peer.display_name or peer.node_id}（{peer.host}:{peer.port}）")
        for peer in config.peers:
            if devices is not None and devices.roster().device(peer.node_id) is not None:
                answer = (input_fn or input)(
                    f"删除 {peer.display_name or peer.node_id} 的旧令牌和旧配置？[y/N] "
                )
                if answer.strip().lower() in ("y", "yes", "是"):
                    service.revoke_peer(peer.node_id)
                    print("已删除这条旧式配对")
                else:
                    print("已保留这条旧式配对")
            else:
                print(
                    f"{peer.display_name or peer.node_id}："
                    "请改用 tunnelminion friend invite 按人配对"
                )
        return 0
    except (EOFError, KeyboardInterrupt):
        print("已取消，未确认的旧式配对均保留")
        return 2
    except ValidationError:
        print("旧式配对配置无效，请检查本机网关配置")
        return 2
    except (ValueError, SecretStoreError) as exc:
        print(str(exc))
        return 2
