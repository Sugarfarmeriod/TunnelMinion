"""命令行和本机网页共用的机主身份操作；只处理本机数据目录，不负责问答和显示。"""

from __future__ import annotations

import ipaddress
import socket
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import psutil
from pydantic import BaseModel, ConfigDict, ValidationError

from tunnelminion.agent.join import detect_local_host
from tunnelminion.domain.identifiers import NodeId
from tunnelminion.domain.tools import Platform
from tunnelminion.domain.trust import (
    FRIEND_JOIN_CODE_PREFIX,
    FriendPermissions,
    JoinCode,
    JoinCodeKind,
)
from tunnelminion.gateway.configuration import (
    FileGatewayConfigurationRepository,
    GatewayConfigurationService,
    GatewayPeerView,
)
from tunnelminion.gateway.names import NodeNameConfiguration, load_node_name, save_node_name
from tunnelminion.gateway.security import GatewayBindConfig
from tunnelminion.memory.sqlite import SQLiteStores, SQLiteTrustStore
from tunnelminion.model.secrets import SecretStore
from tunnelminion.trust.contracts import (
    AlreadyInitializedError,
    DevicePermissions,
    IdentityError,
    IdentityStatus,
)
from tunnelminion.trust.devices import OwnDevicesService
from tunnelminion.trust.friends import FriendsService
from tunnelminion.trust.keys import InitializationKeys
from tunnelminion.trust.passes import RequestPassVerifier
from tunnelminion.trust.service import OwnerIdentityService, ensure_no_identity_keys

DEFAULT_BIND_PORT = 8787
INVALID_SETUP = "本机身份配置无效，请检查组网地址、端口和显示名"


class BindHostRequiredError(IdentityError):
    """本机还没有网关配置，建立身份时必须给出组网地址。"""


def current_platform() -> Platform:
    if sys.platform == "darwin":
        return Platform.MACOS
    if sys.platform == "win32":
        return Platform.WINDOWS
    return Platform.LINUX


def normalized_recovery_code(value: str) -> str:
    """比较恢复码时忽略大小写、空格和连字符。"""
    return "".join(char for char in value.upper() if char != "-" and not char.isspace())


def load_devices(root: Path, secrets: SecretStore) -> OwnDevicesService:
    """读取已建立的本机身份；没有身份时不创建任何文件。"""
    database = root / "runtime.sqlite3"
    if not SQLiteTrustStore.is_initialized(database):
        raise IdentityError("本机身份尚未初始化")
    return OwnDevicesService(
        NodeId((root / "node-id").read_text(encoding="utf-8").strip()),
        SQLiteStores.open(database).trust,
        secrets,
    )


def gateway_bind(root: Path) -> GatewayBindConfig | None:
    """本机已有网关配置时，组网地址和端口以它为准。"""
    configuration = FileGatewayConfigurationRepository(root / "gateway.json").load()
    return configuration.bind if configuration is not None else None


@dataclass(frozen=True)
class SetupPlan:
    """建立身份前已经核对过的地址、名字和秘密存储；还没有写入任何东西。"""

    root: Path
    bind: GatewayBindConfig
    display_name: str
    display_name_given: bool
    secrets: SecretStore
    previous_secrets: SecretStore
    reset: bool
    write_gateway: bool


def plan_setup(
    root: Path,
    secrets: SecretStore,
    previous_secrets: SecretStore,
    *,
    host: str | None,
    port: int | None,
    display_name: str | None,
    reset: bool = False,
) -> SetupPlan:
    """核对能否建立身份；本机已有网关配置时忽略传入的地址和端口。"""
    if not reset and SQLiteTrustStore.is_initialized(root / "runtime.sqlite3"):
        raise AlreadyInitializedError("本机身份已经初始化，不能重复初始化")
    if not reset:
        ensure_no_identity_keys(secrets)
    existing = gateway_bind(root)
    try:
        if existing is not None:
            bind = existing
        elif host is None:
            raise BindHostRequiredError("本机网关还没有配置，请填写本机组网地址")
        else:
            bind = GatewayBindConfig(host=host, port=port or DEFAULT_BIND_PORT)
        name = NodeNameConfiguration(
            display_name=display_name
            if display_name is not None
            else load_node_name(root, current_platform(), persist_default=False)
        ).display_name
    except ValidationError:
        raise IdentityError(INVALID_SETUP) from None
    return SetupPlan(
        root=root,
        bind=bind,
        display_name=name,
        display_name_given=display_name is not None,
        secrets=secrets,
        previous_secrets=previous_secrets,
        reset=reset,
        write_gateway=existing is None,
    )


def initialize(plan: SetupPlan, keys: InitializationKeys, node_id: NodeId) -> IdentityStatus:
    """恢复码确认后落盘：写身份、按需写网关配置和电脑名。"""
    root = plan.root
    view = OwnerIdentityService(
        SQLiteStores.open(root / "runtime.sqlite3").trust, plan.secrets
    ).init(
        node_id,
        plan.bind,
        plan.display_name,
        keys,
        current_platform(),
        replace=plan.reset,
        previous_secrets=plan.previous_secrets if plan.reset else None,
    )
    # 本机还没有网关配置时，按这次的组网地址写一份，之后可以直接启动网关。
    if plan.write_gateway:
        GatewayConfigurationService(
            FileGatewayConfigurationRepository(root / "gateway.json"), plan.secrets
        ).configure_local(plan.bind)
    if plan.display_name_given:
        save_node_name(root, plan.display_name)
    return view


def address_candidates() -> tuple[str, ...]:
    """本机网卡上可以给网关用的私有地址。"""
    found: set[str] = set()
    for addresses in psutil.net_if_addrs().values():
        for address in addresses:
            if address.family not in (socket.AF_INET, socket.AF_INET6):
                continue
            try:
                GatewayBindConfig(host=address.address)
            except ValidationError:
                continue
            if ipaddress.ip_address(address.address).is_link_local:
                continue
            found.add(address.address)
    return tuple(sorted(found, key=lambda value: (ipaddress.ip_address(value).version, value)))


class CodeInspection(BaseModel):
    """粘贴的加入码或配对码里可以公开的内容，不含令牌。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: JoinCodeKind
    owner_fingerprint: str
    inviter_host: str
    inviter_port: int
    expires_at: datetime
    expired: bool
    suggested_host: str | None
    suggested_port: int
    bind_locked: bool


def decode_code(value: str) -> JoinCode:
    """按前缀判断是加入码还是配对码。"""
    kind = (
        JoinCodeKind.FRIEND
        if value.strip().startswith(FRIEND_JOIN_CODE_PREFIX)
        else JoinCodeKind.OWNER
    )
    return JoinCode.decode(value, kind)


def inspect_code(root: Path, value: str, *, now: datetime | None = None) -> CodeInspection:
    """解析码并按对方地址推测本机组网地址，不发送数据包。"""
    code = decode_code(value)
    existing = gateway_bind(root)
    suggested: str | None
    if existing is not None:
        suggested = existing.host
    else:
        try:
            suggested = detect_local_host(code.host, code.port)
            GatewayBindConfig(host=suggested)
        except (OSError, ValidationError):
            suggested = None
    return CodeInspection(
        kind=code.kind,
        owner_fingerprint=code.owner_fingerprint,
        inviter_host=code.host,
        inviter_port=code.port,
        expires_at=code.expires_at,
        expired=code.expires_at <= (now or datetime.now(UTC)),
        suggested_host=suggested,
        suggested_port=existing.port if existing is not None else DEFAULT_BIND_PORT,
        bind_locked=existing is not None,
    )


@dataclass(frozen=True)
class FriendPeers:
    """一个朋友，他名单上本机认的电脑，以及因编号冲突暂不认的电脑。"""

    friend_fingerprint: str
    display_name: str
    permissions: FriendPermissions
    devices: tuple[GatewayPeerView, ...]
    conflicting: tuple[str, ...]


def friend_peers(
    devices: OwnDevicesService, configuration: GatewayConfigurationService
) -> tuple[FriendPeers, ...]:
    """按朋友整理他的电脑；多个朋友名单里出现同一个节点 ID 时两边都不认。"""
    peers = {str(peer.node_id): peer for peer in configuration.view().peers}
    rosters = {friend.owner_fingerprint: roster.devices for friend, roster in devices.friends()}
    verifier = RequestPassVerifier(devices)
    conflicting: set[str] = set()
    for entries in rosters.values():
        for entry in entries:
            if str(entry.node_id) not in peers:
                policy = verifier.friend_peer(entry.node_id)
                if policy is None:
                    conflicting.add(str(entry.node_id))
                    continue
                peers[str(entry.node_id)] = GatewayPeerView(
                    node_id=entry.node_id,
                    relationship="friend",
                    platform=entry.platform,
                    display_name=entry.display_name,
                    host=entry.host,
                    port=entry.port,
                    allowed_tools=policy.allowed_tools,
                    allowed_operations=policy.allowed_operations,
                    allow_delegation=policy.allow_delegation,
                    allow_model_borrowing=policy.allow_model_borrowing,
                    daily_quota=policy.daily_quota,
                    credential_configured=devices.active(),
                )
    return tuple(
        FriendPeers(
            friend_fingerprint=friend.owner_fingerprint,
            display_name=friend.display_name,
            permissions=friend.permissions,
            devices=tuple(
                peers[str(device.node_id)]
                for device in rosters.get(friend.owner_fingerprint, ())
                if str(device.node_id) in peers
            ),
            conflicting=tuple(
                str(device.node_id)
                for device in rosters.get(friend.owner_fingerprint, ())
                if str(device.node_id) in conflicting
            ),
        )
        for friend in devices.trusted_people()
    )


def restrict_device(
    devices: OwnDevicesService,
    node_id: NodeId,
    *,
    allow_delegation: bool | None = None,
    allow_model_borrowing: bool | None = None,
    allow_proxy_repair_approval: bool | None = None,
    daily_quota: int | None = None,
) -> DevicePermissions:
    """在本机现有限制上修改；没给的项保持不变，已经关掉的不能再打开。"""
    current = devices.store.device_permissions(node_id)
    permissions = DevicePermissions(
        allow_delegation=current.allow_delegation if allow_delegation is None else allow_delegation,
        allow_model_borrowing=current.allow_model_borrowing
        if allow_model_borrowing is None
        else allow_model_borrowing,
        allow_proxy_repair_approval=current.allow_proxy_repair_approval
        if allow_proxy_repair_approval is None
        else allow_proxy_repair_approval,
        daily_quota=current.daily_quota if daily_quota is None else daily_quota,
    )
    devices.restrict(node_id, permissions)
    return permissions


def update_friend_permissions(
    service: FriendsService,
    person: str,
    *,
    close_delegation: bool = False,
    allow_model_borrowing: bool | None = None,
    daily_quota: int | None = None,
    restrict: bool = False,
) -> None:
    """改朋友的默认权限（写进签名名单），或者只在本机收紧。"""
    friend = service.resolve(person)
    current = friend.permissions
    if restrict:
        local = service.devices.store.friend_permissions(friend.owner_fingerprint)
        current = FriendPermissions(
            allow_delegation=current.allow_delegation and local.allow_delegation,
            allow_model_borrowing=current.allow_model_borrowing and local.allow_model_borrowing,
            daily_quota=min(current.daily_quota, local.daily_quota),
        )
    permissions = FriendPermissions(
        allow_delegation=current.allow_delegation and not close_delegation,
        allow_model_borrowing=current.allow_model_borrowing
        if allow_model_borrowing is None
        else allow_model_borrowing,
        daily_quota=current.daily_quota if daily_quota is None else daily_quota,
    )
    if restrict:
        service.restrict(person, permissions)
    else:
        service.permissions(person, permissions)
