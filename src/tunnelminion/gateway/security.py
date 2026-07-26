"""节点认证、只读允许列表、速率限制和 WireGuard 绑定约束。"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
from collections import defaultdict, deque
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from time import monotonic

from pydantic import BaseModel, ConfigDict, Field, field_validator

from tunnelminion.agent.coordinator import CoordinatorCache
from tunnelminion.coordinator.contracts import DirectoryFreshness, NodeStatus
from tunnelminion.coordinator.identity import (
    AssertionVerificationError,
    OfflineAssertionVerifier,
)
from tunnelminion.domain.identifiers import NodeId
from tunnelminion.network.path_controller import (
    GatewayPathEndpoint,
    select_gateway_endpoint,
)


class GatewayBindConfig(BaseModel):
    """只允许网关绑定明确私有 WireGuard 地址。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    host: str
    port: int = Field(default=8787, ge=1024, le=65535)

    @field_validator("host")
    @classmethod
    def validate_wireguard_host(cls, value: str) -> str:
        address = ipaddress.ip_address(value)
        if (
            not address.is_private
            or address.is_loopback
            or address.is_unspecified
            or address.is_multicast
        ):
            raise ValueError("Tool Gateway 只能绑定明确的私有 WireGuard 地址")
        return value


class GatewayLimits(BaseModel):
    """网关独立于工具定义的外层资源预算。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    requests_per_minute: int = Field(default=60, ge=1, le=10_000)
    max_timeout_seconds: float = Field(default=30, gt=0, le=300)
    max_response_bytes: int = Field(default=512_000, ge=512, le=10_000_000)


class GatewayAuthenticationKind(StrEnum):
    """网关明确区分静态凭据与 Coordinator 管理身份。"""

    STATIC = "static"
    COORDINATOR = "coordinator"


@dataclass(frozen=True)
class GatewayPeerPolicy:
    """只保存认证令牌摘要，不保留可重放明文。"""

    node_id: NodeId
    token_digest: bytes
    allowed_tools: frozenset[str]
    allowed_operations: frozenset[str] = frozenset()
    source_host: str | None = None
    authentication_kind: GatewayAuthenticationKind = GatewayAuthenticationKind.STATIC

    @classmethod
    def from_token(
        cls,
        node_id: NodeId,
        token: str,
        allowed_tools: Iterable[str],
        allowed_operations: Iterable[str] = (),
        *,
        source_host: str | None = None,
    ) -> GatewayPeerPolicy:
        """把独立应用令牌立即转换为 SHA-256 摘要。"""
        if len(token) < 32:
            raise ValueError("节点认证令牌至少需要 32 个字符")
        tools = frozenset(allowed_tools)
        if not tools:
            raise ValueError("节点至少需要一个允许的只读工具")
        return cls(
            node_id,
            hashlib.sha256(token.encode()).digest(),
            tools,
            frozenset(allowed_operations),
            source_host,
        )


@dataclass(frozen=True)
class GatewayManagedPeerPolicy:
    """本机管理员为 Coordinator 节点设置的最终允许列表。"""

    node_id: NodeId
    allowed_tools: frozenset[str]
    allowed_operations: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        if not self.allowed_tools:
            raise ValueError("Coordinator-managed peer 至少需要一个允许的只读工具")


class GatewaySecurityPolicy:
    """使用常量时间摘要比较认证 peer，并应用每节点滑动窗口限流。"""

    def __init__(
        self,
        peers: Iterable[GatewayPeerPolicy],
        limits: GatewayLimits | None = None,
        *,
        managed_peers: Iterable[GatewayManagedPeerPolicy] = (),
        coordinator_cache: CoordinatorCache | None = None,
        pinned_fingerprints: Iterable[str] = (),
        clock: Callable[[], float] = monotonic,
        wall_clock: Callable[[], datetime] | None = None,
        managed_path_endpoint: (
            Callable[[NodeId, datetime], GatewayPathEndpoint | None] | None
        ) = None,
    ) -> None:
        values = tuple(peers)
        managed = tuple(managed_peers)
        if not values and not managed:
            raise ValueError("Tool Gateway 至少需要一个已配置 peer")
        if len({str(item.node_id) for item in values}) != len(values):
            raise ValueError("Tool Gateway peer node ID 不得重复")
        if len({str(item.node_id) for item in managed}) != len(managed):
            raise ValueError("Tool Gateway managed peer node ID 不得重复")
        if managed and coordinator_cache is None:
            raise ValueError("Coordinator-managed peer 必须配置本地授权缓存")
        self._peers = values
        self._managed = {str(item.node_id): item for item in managed}
        self._coordinator_cache = coordinator_cache
        self._pinned_fingerprints = frozenset(pinned_fingerprints)
        self.limits = limits or GatewayLimits()
        self._clock = clock
        self._wall_clock = wall_clock or (lambda: datetime.now(UTC))
        self._managed_path_endpoint = managed_path_endpoint
        self._requests: defaultdict[str, deque[float]] = defaultdict(deque)

    def authenticate(
        self,
        authorization: str | None,
        *,
        audience: str = "tool-gateway",
    ) -> GatewayPeerPolicy | None:
        """先兼容静态 token，再以本地缓存离线验证 managed assertion。"""
        if authorization is None or not authorization.startswith("Bearer "):
            return None
        credential = authorization.removeprefix("Bearer ")
        candidate = hashlib.sha256(credential.encode()).digest()
        matched: GatewayPeerPolicy | None = None
        for peer in self._peers:
            if hmac.compare_digest(candidate, peer.token_digest):
                matched = peer
        if matched is not None:
            return matched
        return self._authenticate_managed(credential, audience)

    def _authenticate_managed(
        self,
        assertion: str,
        audience: str,
    ) -> GatewayPeerPolicy | None:
        cache = self._coordinator_cache
        if cache is None:
            return None
        view = cache.read()
        now = self._wall_clock()
        if view is None or not view.is_fresh(now):
            return None
        try:
            verified = OfflineAssertionVerifier(
                view.verification_keys,
                self._pinned_fingerprints,
                clock=lambda: now,
            ).verify(
                assertion,
                audience=audience,
                network_id=view.network_id,
            )
        except AssertionVerificationError:
            return None
        managed = self._managed.get(str(verified.node_id))
        if managed is None:
            return None
        node = next(
            (item for item in view.nodes if item.identity.node_id == verified.node_id),
            None,
        )
        if (
            node is None
            or node.status is not NodeStatus.ONLINE
            or node.freshness is not DirectoryFreshness.FRESH
        ):
            return None
        path_endpoint = (
            self._managed_path_endpoint(managed.node_id, now)
            if self._managed_path_endpoint is not None
            else None
        )
        selected_path = (
            select_gateway_endpoint((path_endpoint,), now=now)
            if path_endpoint is not None
            else None
        )
        return GatewayPeerPolicy(
            node_id=managed.node_id,
            token_digest=b"",
            allowed_tools=managed.allowed_tools,
            allowed_operations=managed.allowed_operations,
            source_host=(
                selected_path.host
                if selected_path is not None
                else node.identity.gateway_endpoint.host
            ),
            authentication_kind=GatewayAuthenticationKind.COORDINATOR,
        )

    def consume(self, peer: GatewayPeerPolicy) -> bool:
        """按 peer 应用过去 60 秒内的请求数上限。"""
        now = self._clock()
        window = self._requests[str(peer.node_id)]
        while window and now - window[0] >= 60:
            window.popleft()
        if len(window) >= self.limits.requests_per_minute:
            return False
        window.append(now)
        return True
