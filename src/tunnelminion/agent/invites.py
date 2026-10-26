"""邀请码的签发、一次性接纳与运行中网关授权。"""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from datetime import UTC, datetime
from threading import Lock
from typing import Protocol

from tunnelminion.domain.identifiers import NodeId
from tunnelminion.domain.invites import (
    INVITE_LIFETIME,
    InvalidInviteCodeError,
    InviteAcceptance,
    InviteAccepted,
    InviteCode,
    InvitePermissions,
    platform_display_name,
)
from tunnelminion.domain.tools import Platform
from tunnelminion.gateway.configuration import (
    DEFAULT_GATEWAY_TOOLS,
    GatewayConfigurationService,
    GatewayPeerConfig,
    GatewayPeerInput,
    generate_gateway_token,
)
from tunnelminion.gateway.security import (
    GatewayBindConfig,
    GatewayPeerPolicy,
    GatewaySecurityPolicy,
)


class InviteStore(Protocol):
    """只保存令牌摘要，原子消费尚未过期的邀请码。"""

    def create(
        self,
        digest: bytes,
        permissions: InvitePermissions,
        created_at: datetime,
        expires_at: datetime,
    ) -> None: ...

    def accept(self, digest: bytes, node_id: NodeId, now: datetime) -> InvitePermissions | None: ...


class InMemoryInviteStore:
    """测试用的一次性邀请码存储。"""

    def __init__(self) -> None:
        self._invites: dict[bytes, tuple[InvitePermissions, datetime]] = {}
        self._lock = Lock()

    def create(
        self,
        digest: bytes,
        permissions: InvitePermissions,
        created_at: datetime,
        expires_at: datetime,
    ) -> None:
        with self._lock:
            self._invites[digest] = permissions, expires_at

    def accept(self, digest: bytes, node_id: NodeId, now: datetime) -> InvitePermissions | None:
        with self._lock:
            invite = self._invites.get(digest)
            if invite is None or invite[1] <= now:
                return None
            return self._invites.pop(digest)[0]


class InviteService:
    """沿用网关配对凭据，接纳后立即更新当前安全策略。"""

    def __init__(
        self,
        node_id: NodeId,
        platform: Platform,
        configuration: GatewayConfigurationService,
        store: InviteStore,
        security_policy: GatewaySecurityPolicy | None = None,
        *,
        clock: Callable[[], datetime] | None = None,
        display_name: Callable[[], str] | None = None,
    ) -> None:
        self._node_id = node_id
        self._platform = platform
        self._configuration = configuration
        self._store = store
        self._security_policy = security_policy
        self._clock = clock or (lambda: datetime.now(UTC))
        self._display_name = display_name or (lambda: platform_display_name(platform))

    def create(self, permissions: InvitePermissions) -> InviteCode:
        """签发邀请码；数据库只登记令牌摘要。"""
        bind = self._configuration.view().bind
        if bind is None:
            raise RuntimeError("本机网关还没有配置，请加上 --bind-host <本机组网地址>")
        now = self._clock()
        code = InviteCode(
            node_id=self._node_id,
            platform=self._platform,
            host=bind.host,
            port=bind.port,
            token=generate_gateway_token(),
            permissions=permissions,
            expires_at=now + INVITE_LIFETIME,
        )
        self._store.create(
            hashlib.sha256(code.token.encode()).digest(), permissions, now, code.expires_at
        )
        return code

    def accept(self, token: str, acceptance: InviteAcceptance, client_host: str) -> InviteAccepted:
        """校验来源并消费邀请码，配对令牌仅进入现有秘密存储。"""
        if client_host != acceptance.host or acceptance.node_id == self._node_id:
            raise InvalidInviteCodeError("邀请码无效、已过期或已被使用")
        GatewayBindConfig(host=acceptance.host, port=acceptance.port)
        permissions = self._store.accept(
            hashlib.sha256(token.encode()).digest(), acceptance.node_id, self._clock()
        )
        if permissions is None:
            raise InvalidInviteCodeError("邀请码无效、已过期或已被使用")
        peer = GatewayPeerConfig(
            node_id=acceptance.node_id,
            platform=acceptance.platform,
            display_name=acceptance.display_name or platform_display_name(acceptance.platform),
            host=acceptance.host,
            port=acceptance.port,
            allowed_tools=frozenset(DEFAULT_GATEWAY_TOOLS),
            allow_delegation=permissions.allow_delegation,
            allow_model_borrowing=permissions.allow_model_borrowing,
            daily_quota=permissions.daily_quota,
        )
        self._configuration.provision_peer(GatewayPeerInput(peer=peer, token=token))
        if self._security_policy is not None:
            self._security_policy.upsert_static_peer(
                GatewayPeerPolicy.from_token(
                    peer.node_id,
                    token,
                    peer.allowed_tools,
                    source_host=peer.host,
                    allow_delegation=peer.allow_delegation,
                    allow_model_borrowing=peer.allow_model_borrowing,
                    daily_quota=peer.daily_quota,
                )
            )
        return InviteAccepted(
            inviter_node_id=self._node_id,
            inviter_display_name=self._display_name(),
            permissions=permissions,
        )
