"""节点认证、只读允许列表、速率限制和 WireGuard 绑定约束。"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
from collections import defaultdict, deque
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from time import monotonic

from pydantic import BaseModel, ConfigDict, Field, field_validator

from tunnelminion.domain.identifiers import NodeId


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


@dataclass(frozen=True)
class GatewayPeerPolicy:
    """只保存认证令牌摘要，不保留可重放明文。"""

    node_id: NodeId
    token_digest: bytes
    allowed_tools: frozenset[str]
    allowed_operations: frozenset[str] = frozenset()
    source_host: str | None = None

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


class GatewaySecurityPolicy:
    """使用常量时间摘要比较认证 peer，并应用每节点滑动窗口限流。"""

    def __init__(
        self,
        peers: Iterable[GatewayPeerPolicy],
        limits: GatewayLimits | None = None,
        *,
        clock: Callable[[], float] = monotonic,
    ) -> None:
        values = tuple(peers)
        if not values:
            raise ValueError("Tool Gateway 至少需要一个已配置 peer")
        if len({str(item.node_id) for item in values}) != len(values):
            raise ValueError("Tool Gateway peer node ID 不得重复")
        self._peers = values
        self.limits = limits or GatewayLimits()
        self._clock = clock
        self._requests: defaultdict[str, deque[float]] = defaultdict(deque)

    def authenticate(self, authorization: str | None) -> GatewayPeerPolicy | None:
        """验证 Bearer 令牌，但不在错误或审计中返回令牌。"""
        if authorization is None or not authorization.startswith("Bearer "):
            return None
        candidate = hashlib.sha256(authorization.removeprefix("Bearer ").encode()).digest()
        matched: GatewayPeerPolicy | None = None
        for peer in self._peers:
            if hmac.compare_digest(candidate, peer.token_digest):
                matched = peer
        return matched

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
