"""本机网页上的机主身份与朋友配对；业务规则全部在 `trust` 服务层。"""

from __future__ import annotations

import asyncio
import logging
import secrets
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Lock
from typing import NoReturn

import httpx
from fastapi import APIRouter, HTTPException, Response
from pydantic import BaseModel, ConfigDict, Field

from tunnelminion.domain.identifiers import NodeId
from tunnelminion.domain.tools import Platform
from tunnelminion.domain.trust import InvalidJoinCodeError, JoinCodeKind
from tunnelminion.gateway.configuration import (
    FileGatewayConfigurationRepository,
    GatewayConfigurationService,
    gateway_secret_store,
)
from tunnelminion.gateway.names import load_node_name
from tunnelminion.memory.sqlite import SQLiteStores, SQLiteTrustStore
from tunnelminion.model.secrets import SecretStoreApprovalPendingError, SecretStoreError
from tunnelminion.trust.contracts import AlreadyInitializedError, IdentityError
from tunnelminion.trust.devices import OwnDevicesService
from tunnelminion.trust.friends import FriendsService
from tunnelminion.trust.join import join_owner
from tunnelminion.trust.keys import InitializationKeys
from tunnelminion.trust.local import (
    CodeInspection,
    SetupPlan,
    address_candidates,
    decode_code,
    friend_peers,
    gateway_bind,
    initialize,
    inspect_code,
    normalized_recovery_code,
    plan_setup,
    restrict_device,
    update_friend_permissions,
)
from tunnelminion.trust.service import OwnerIdentityService
from tunnelminion.trust.signatures import VerificationError

SETUP_LIFETIME = timedelta(minutes=10)
_NO_STORE = {"Cache-Control": "no-store"}


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class BindView(_Strict):
    host: str
    port: int


class DevicePermissionsView(_Strict):
    allow_delegation: bool
    allow_model_borrowing: bool
    allow_proxy_repair_approval: bool


class OwnDeviceView(_Strict):
    node_id: NodeId
    display_name: str
    platform: Platform | None
    host: str
    port: int
    is_local: bool
    permissions: DevicePermissionsView


class FriendDeviceView(_Strict):
    node_id: NodeId
    display_name: str
    platform: Platform | None


class FriendView(_Strict):
    owner_fingerprint: str
    display_name: str
    allow_model_borrowing: bool
    devices: tuple[FriendDeviceView, ...]
    conflicting_devices: tuple[str, ...]


class LegacyPeerView(_Strict):
    node_id: NodeId
    display_name: str
    platform: Platform | None
    host: str
    port: int
    allow_proxy_repair_approval: bool


class IdentityOverview(_Strict):
    """网页上"电脑与朋友"所需的全部内容，不含私钥、令牌和恢复码。"""

    initialized: bool
    local_display_name: str
    owner_fingerprint: str | None = None
    has_owner_key: bool = False
    removed: bool = False
    roster_version: int | None = None
    trust_list_version: int | None = None
    bind: BindView | None
    address_candidates: tuple[str, ...]
    devices: tuple[OwnDeviceView, ...] = ()
    friends: tuple[FriendView, ...] = ()
    legacy_peers: tuple[LegacyPeerView, ...] = ()


class SetupRequest(_Strict):
    host: str | None = Field(default=None, max_length=64)
    port: int | None = None
    display_name: str | None = Field(default=None, max_length=200)


class SetupStarted(_Strict):
    setup_id: str
    recovery_code: str = Field(repr=False)
    expires_at: datetime


class SetupConfirmation(_Strict):
    recovery_code: str = Field(max_length=512, repr=False)


class CodeRequest(_Strict):
    code: str = Field(max_length=8192, repr=False)


class OwnerJoinBody(_Strict):
    code: str = Field(max_length=8192, repr=False)
    host: str | None = Field(default=None, max_length=64)
    port: int | None = None


class FriendInviteBody(_Strict):
    display_name: str | None = Field(default=None, max_length=200)


class FriendJoinBody(_Strict):
    code: str = Field(max_length=8192, repr=False)
    display_name: str | None = Field(default=None, max_length=200)


class FriendRenameBody(_Strict):
    display_name: str = Field(max_length=200)


class DevicePermissionsBody(_Strict):
    allow_delegation: bool | None = None
    allow_model_borrowing: bool | None = None
    allow_proxy_repair_approval: bool | None = None


class FriendPermissionsBody(_Strict):
    allow_model_borrowing: bool


class ProxyApprovalBody(_Strict):
    allowed: bool


class IssuedCode(_Strict):
    code: str = Field(repr=False)
    expires_at: datetime


class PushResult(_Strict):
    """名单已在本机改好；这些电脑这次没推到，下次接触时会同步。"""

    unreached: tuple[str, ...]


@dataclass
class _PendingSetup:
    setup_id: str
    plan: SetupPlan
    keys: InitializationKeys
    expires_at: datetime


class PendingSetups:
    """待确认的身份只放在进程内存里，同一时刻最多一份。"""

    def __init__(self, clock: Callable[[], datetime]) -> None:
        self._clock = clock
        self._lock = Lock()
        self._pending: _PendingSetup | None = None

    def start(self, plan: SetupPlan) -> SetupStarted:
        keys = InitializationKeys.generate()
        pending = _PendingSetup(
            setup_id=secrets.token_urlsafe(18),
            plan=plan,
            keys=keys,
            expires_at=self._clock() + SETUP_LIFETIME,
        )
        with self._lock:
            self._pending = pending
        return SetupStarted(
            setup_id=pending.setup_id,
            recovery_code=keys.recovery_code,
            expires_at=pending.expires_at,
        )

    def take(self, setup_id: str, recovery_code: str) -> _PendingSetup:
        """恢复码一致时取走；不一致时保留，可以再输。"""
        with self._lock:
            pending = self._pending
            if pending is None or not secrets.compare_digest(pending.setup_id, setup_id):
                _fail(410, "setup_expired", "这次设置已经作废，请重新开始")
            if pending.expires_at <= self._clock():
                self._pending = None
                _fail(410, "setup_expired", "这次设置已经超过 10 分钟，请重新开始")
            if not secrets.compare_digest(
                normalized_recovery_code(recovery_code).encode(),
                normalized_recovery_code(pending.keys.recovery_code).encode(),
            ):
                _fail(400, "recovery_code_mismatch", "输入的恢复码和刚才显示的不一致，请再核对一遍")
            self._pending = None
            return pending

    def cancel(self, setup_id: str) -> None:
        with self._lock:
            if self._pending is not None and self._pending.setup_id == setup_id:
                self._pending = None


logger = logging.getLogger(__name__)

SECRET_STORE_UNAVAILABLE = (
    "这台电脑的系统钥匙串打不开，密钥存不进去。如果 TunnelMinion 是通过 ssh 远程启动的，"
    "系统不让它用钥匙串：请在这台电脑的桌面上（Mac 用“终端”App）重新启动 TunnelMinion 后再试"
)


def _fail(status: int, code: str, message: str) -> NoReturn:
    raise HTTPException(status_code=status, detail={"code": code, "message": message})


def _node(value: str) -> NodeId:
    try:
        return NodeId(value)
    except ValueError:
        _fail(404, "device_not_found", "没有这台电脑")


def _identity_failure(exc: Exception) -> NoReturn:
    if isinstance(exc, AlreadyInitializedError):
        _fail(409, "already_initialized", str(exc))
    if isinstance(exc, InvalidJoinCodeError):
        _fail(400, "invalid_code", str(exc))
    if isinstance(exc, SecretStoreApprovalPendingError):
        _fail(503, "keychain_approval_pending", str(exc))
    if isinstance(exc, SecretStoreError):
        # 底层原因只写进本机日志：常见的是 TunnelMinion 从 ssh 会话里启动，系统不让它用钥匙串。
        logger.warning("系统钥匙串操作失败：%s（%r）", exc, exc.__cause__)
        _fail(500, "secret_store_unavailable", SECRET_STORE_UNAVAILABLE)
    if isinstance(exc, VerificationError):
        _fail(400, "verification_failed", str(exc))
    _fail(400, "identity_error", str(exc))


def create_identity_router(
    root: Path,
    node_id: NodeId,
    platform: Platform,
    *,
    transport: httpx.AsyncBaseTransport | None = None,
    clock: Callable[[], datetime] | None = None,
) -> APIRouter:
    """挂在本机请求守卫之下；每次请求按数据目录现读，命令行的修改立即可见。"""
    router = APIRouter()
    now = clock or (lambda: datetime.now(UTC))
    pending = PendingSetups(now)

    def configuration() -> GatewayConfigurationService:
        return GatewayConfigurationService(
            FileGatewayConfigurationRepository(root / "gateway.json"), gateway_secret_store(root)
        )

    def initialized() -> bool:
        return SQLiteTrustStore.is_initialized(root / "runtime.sqlite3")

    def devices() -> OwnDevicesService:
        if not initialized():
            _fail(409, "not_initialized", "本机还没有机主身份")
        return OwnDevicesService(
            node_id,
            SQLiteStores.open(root / "runtime.sqlite3").trust,
            gateway_secret_store(root),
            transport=transport,
        )

    def names(owner: OwnDevicesService, unreached: tuple[NodeId, ...]) -> PushResult:
        known = {
            str(device.node_id): device.display_name
            for device in (
                *owner.roster().devices,
                *(device for _, roster in owner.friends() for device in roster.devices),
            )
        }
        return PushResult(unreached=tuple(known.get(str(item), str(item)) for item in unreached))

    def overview() -> IdentityOverview:
        bind = gateway_bind(root)
        config = configuration()
        base = IdentityOverview(
            initialized=False,
            local_display_name=load_node_name(root, platform, persist_default=False),
            bind=BindView(host=bind.host, port=bind.port) if bind is not None else None,
            address_candidates=address_candidates(),
            legacy_peers=tuple(
                LegacyPeerView(
                    node_id=peer.node_id,
                    display_name=config.peer_display_name(peer.node_id),
                    platform=peer.platform,
                    host=peer.host,
                    port=peer.port,
                    allow_proxy_repair_approval=peer.allow_proxy_repair_approval,
                )
                for peer in config.view().peers
                if peer.relationship == "legacy" and peer.node_id != node_id
            ),
        )
        if not initialized():
            return base
        owner = devices()
        status = OwnerIdentityService(owner.store, owner.secrets).status()
        config = GatewayConfigurationService(
            FileGatewayConfigurationRepository(root / "gateway.json"),
            owner.secrets,
            owner_devices=owner,
        )
        return base.model_copy(
            update={
                "initialized": True,
                "owner_fingerprint": status.owner_fingerprint,
                "has_owner_key": status.has_owner_key,
                "removed": status.removed,
                "roster_version": status.roster_version,
                "trust_list_version": status.trust_list_version,
                "devices": tuple(
                    OwnDeviceView(
                        node_id=device.node_id,
                        display_name=device.display_name,
                        platform=device.platform,
                        host=device.host,
                        port=device.port,
                        is_local=device.node_id == node_id,
                        permissions=DevicePermissionsView.model_validate(
                            owner.store.device_permissions(device.node_id).model_dump(
                                exclude={"daily_quota"}
                            )
                        ),
                    )
                    for device in status.devices
                ),
                "friends": tuple(
                    FriendView(
                        owner_fingerprint=friend.friend_fingerprint,
                        display_name=friend.display_name,
                        allow_model_borrowing=friend.permissions.allow_model_borrowing,
                        devices=tuple(
                            FriendDeviceView(
                                node_id=device.node_id,
                                display_name=device.display_name or str(device.node_id),
                                platform=device.platform,
                            )
                            for device in friend.devices
                        ),
                        conflicting_devices=friend.conflicting,
                    )
                    for friend in friend_peers(owner, config)
                ),
            }
        )

    def read_identity() -> IdentityOverview:
        try:
            return overview()
        except (IdentityError, SecretStoreError) as exc:
            _identity_failure(exc)

    def inspect(body: CodeRequest) -> CodeInspection:
        try:
            return inspect_code(root, body.code, now=now())
        except InvalidJoinCodeError as exc:
            _identity_failure(exc)

    def start_setup(body: SetupRequest, response: Response) -> SetupStarted:
        response.headers.update(_NO_STORE)
        store = gateway_secret_store(root)
        try:
            plan = plan_setup(
                root,
                store,
                store,
                host=body.host,
                port=body.port,
                display_name=body.display_name,
            )
        except (IdentityError, SecretStoreError) as exc:
            _identity_failure(exc)
        return pending.start(plan)

    def confirm_setup(
        setup_id: str, body: SetupConfirmation, response: Response
    ) -> IdentityOverview:
        response.headers.update(_NO_STORE)
        taken = pending.take(setup_id, body.recovery_code)
        try:
            initialize(taken.plan, taken.keys, node_id)
            return overview()
        except (IdentityError, SecretStoreError) as exc:
            _identity_failure(exc)

    def cancel_setup(setup_id: str) -> None:
        pending.cancel(setup_id)

    async def join(body: OwnerJoinBody) -> IdentityOverview:
        try:
            code = decode_code(body.code)
            if code.kind is not JoinCodeKind.OWNER:
                _fail(400, "invalid_code", "这是朋友的配对码，请选“我是朋友”")
            await join_owner(
                code, root, host_override=body.host, port_override=body.port, transport=transport
            )
            return overview()
        except (IdentityError, SecretStoreError, InvalidJoinCodeError, VerificationError) as exc:
            _identity_failure(exc)

    def invite_device(response: Response) -> IssuedCode:
        response.headers.update(_NO_STORE)
        try:
            code = devices().invite()
        except (IdentityError, SecretStoreError) as exc:
            _identity_failure(exc)
        return IssuedCode(code=code.encode(), expires_at=code.expires_at)

    async def remove_device(device_id: str) -> PushResult:
        owner = devices()
        try:
            targets = await asyncio.to_thread(owner.remove, _node(device_id))
        except (IdentityError, SecretStoreError) as exc:
            _identity_failure(exc)
        return names(owner, await owner.push(targets))

    def restrict(value: str, body: DevicePermissionsBody) -> IdentityOverview:
        owner = devices()
        device_id = _node(value)
        if owner.roster().device(device_id) is None or device_id == node_id:
            _fail(404, "device_not_found", "我的电脑名单里没有这台电脑")
        try:
            restrict_device(owner, device_id, **body.model_dump())
            return overview()
        except IdentityError as exc:
            _identity_failure(exc)

    def invite_friend(body: FriendInviteBody, response: Response) -> IssuedCode:
        response.headers.update(_NO_STORE)
        try:
            code = FriendsService(devices()).invite(body.display_name or None)
        except (IdentityError, SecretStoreError) as exc:
            _identity_failure(exc)
        return IssuedCode(code=code.encode(), expires_at=code.expires_at)

    async def join_friend(body: FriendJoinBody) -> IdentityOverview:
        try:
            code = decode_code(body.code)
            if code.kind is not JoinCodeKind.FRIEND:
                _fail(400, "invalid_code", "这是加入我的电脑用的加入码，请选“加入我的电脑”")
            await FriendsService(devices()).join(code, body.display_name or None)
            return overview()
        except (IdentityError, SecretStoreError, InvalidJoinCodeError, VerificationError) as exc:
            _identity_failure(exc)

    async def changed(owner: OwnDevicesService) -> PushResult:
        return names(owner, await owner.push())

    async def rename_friend(fingerprint: str, body: FriendRenameBody) -> PushResult:
        owner = devices()
        try:
            await asyncio.to_thread(FriendsService(owner).rename, fingerprint, body.display_name)
        except (IdentityError, SecretStoreError) as exc:
            _identity_failure(exc)
        return await changed(owner)

    async def friend_permissions(fingerprint: str, body: FriendPermissionsBody) -> PushResult:
        owner = devices()
        try:
            await asyncio.to_thread(
                update_friend_permissions,
                FriendsService(owner),
                fingerprint,
                allow_model_borrowing=body.allow_model_borrowing,
            )
        except (IdentityError, SecretStoreError) as exc:
            _identity_failure(exc)
        return await changed(owner)

    async def remove_friend(fingerprint: str) -> PushResult:
        owner = devices()
        try:
            await asyncio.to_thread(FriendsService(owner).remove, fingerprint)
        except (IdentityError, SecretStoreError) as exc:
            _identity_failure(exc)
        return await changed(owner)

    def proxy_approval(value: str, body: ProxyApprovalBody) -> IdentityOverview:
        config = configuration()
        peer_id = _node(value)
        if config.relationship(peer_id) != "legacy":
            _fail(404, "peer_not_found", "没有这条旧式配对")
        try:
            config.set_proxy_repair_approval(peer_id, body.allowed)
        except KeyError:
            _fail(404, "peer_not_found", "没有这条旧式配对")
        return overview()

    router.add_api_route("/api/identity", read_identity, methods=["GET"])
    router.add_api_route("/api/identity/codes:inspect", inspect, methods=["POST"])
    router.add_api_route("/api/identity/setup", start_setup, methods=["POST"])
    router.add_api_route("/api/identity/setup/{setup_id}:confirm", confirm_setup, methods=["POST"])
    router.add_api_route(
        "/api/identity/setup/{setup_id}", cancel_setup, methods=["DELETE"], status_code=204
    )
    router.add_api_route("/api/identity/owner:join", join, methods=["POST"])
    router.add_api_route("/api/identity/owner:invite", invite_device, methods=["POST"])
    router.add_api_route("/api/identity/devices/{device_id}", remove_device, methods=["DELETE"])
    router.add_api_route("/api/identity/devices/{value}/permissions", restrict, methods=["PUT"])
    router.add_api_route("/api/identity/friends:invite", invite_friend, methods=["POST"])
    router.add_api_route("/api/identity/friends:join", join_friend, methods=["POST"])
    router.add_api_route("/api/identity/friends/{fingerprint}", rename_friend, methods=["PATCH"])
    router.add_api_route(
        "/api/identity/friends/{fingerprint}/permissions", friend_permissions, methods=["PUT"]
    )
    router.add_api_route("/api/identity/friends/{fingerprint}", remove_friend, methods=["DELETE"])
    router.add_api_route(
        "/api/identity/legacy-peers/{value}/proxy-approval", proxy_approval, methods=["PUT"]
    )
    return router
