"""A/B peer、WireGuard 地址和独立网关凭据的本地配置生命周期。"""

from __future__ import annotations

import secrets
from enum import StrEnum
from pathlib import Path
from typing import Protocol

from pydantic import BaseModel, ConfigDict, Field

from tunnelminion.domain.identifiers import NodeId
from tunnelminion.gateway.security import (
    GatewayBindConfig,
    GatewayLimits,
    GatewayPeerPolicy,
    GatewaySecurityPolicy,
)
from tunnelminion.model.secrets import (
    KeyringSecretStore,
    RestrictedFileSecretStore,
    SecretStore,
)

GATEWAY_TOKEN_PREFIX = "tmn_"
_SECRET_STORE_MARKER = "gateway-secret-store"


class GatewaySecretStoreKind(StrEnum):
    """网关凭据后端；受限文件必须由用户显式选择。"""

    KEYRING = "keyring"
    RESTRICTED_FILE = "restricted-file"


def configure_gateway_secret_store(root: Path, kind: GatewaySecretStoreKind) -> SecretStore:
    """持久化非秘密后端选择并返回对应秘密存储。"""
    root.mkdir(parents=True, exist_ok=True)
    marker = root / _SECRET_STORE_MARKER
    temporary = marker.with_suffix(".tmp")
    temporary.write_text(kind.value, encoding="utf-8")
    temporary.replace(marker)
    return gateway_secret_store(root)


def gateway_secret_store(root: Path) -> SecretStore:
    """读取已显式选择的网关秘密后端，默认使用操作系统密钥环。"""
    marker = root / _SECRET_STORE_MARKER
    kind = (
        GatewaySecretStoreKind(marker.read_text(encoding="utf-8").strip())
        if marker.exists()
        else GatewaySecretStoreKind.KEYRING
    )
    if kind is GatewaySecretStoreKind.RESTRICTED_FILE:
        return RestrictedFileSecretStore(root / "gateway-secrets")
    return KeyringSecretStore()


class GatewayPeerConfig(BaseModel):
    """可安全落盘的显式远端 peer 与允许列表。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    node_id: NodeId
    host: str
    port: int = Field(default=8787, ge=1024, le=65535)
    allowed_tools: frozenset[str] = Field(min_length=1)

    def endpoint(self) -> str:
        """返回只含私网地址的 HTTP endpoint。"""
        validated = GatewayBindConfig(host=self.host, port=self.port)
        return f"http://{validated.host}:{validated.port}"


class GatewayConfiguration(BaseModel):
    """不含任何可重放凭据的网关配置文件。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    bind: GatewayBindConfig
    limits: GatewayLimits = Field(default_factory=GatewayLimits)
    peers: tuple[GatewayPeerConfig, ...] = ()


class GatewayPeerInput(BaseModel):
    """本机用户预配 peer 时一次性提交的明文应用令牌。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    peer: GatewayPeerConfig
    token: str = Field(min_length=36, max_length=512)


class GatewayPeerView(BaseModel):
    """永不返回明文 token 的 peer 视图。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    node_id: NodeId
    host: str
    port: int
    allowed_tools: frozenset[str]
    credential_configured: bool


class GatewayConfigurationView(BaseModel):
    """本机管理页和启动诊断可安全读取的配置摘要。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    configured: bool
    bind: GatewayBindConfig | None = None
    limits: GatewayLimits | None = None
    peers: tuple[GatewayPeerView, ...] = ()


class GatewayConfigurationRepository(Protocol):
    """只保存非秘密网关配置。"""

    def load(self) -> GatewayConfiguration | None: ...

    def save(self, value: GatewayConfiguration) -> None: ...

    def delete(self) -> None: ...


class FileGatewayConfigurationRepository:
    """以原子替换写入不含凭据的 JSON 配置。"""

    def __init__(self, path: Path) -> None:
        self._path = path

    def load(self) -> GatewayConfiguration | None:
        if not self._path.exists():
            return None
        return GatewayConfiguration.model_validate_json(self._path.read_text(encoding="utf-8"))

    def save(self, value: GatewayConfiguration) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self._path.with_suffix(f"{self._path.suffix}.tmp")
        temporary.write_text(value.model_dump_json(indent=2), encoding="utf-8")
        temporary.replace(self._path)

    def delete(self) -> None:
        self._path.unlink(missing_ok=True)


def gateway_token_name(node_id: NodeId) -> str:
    """构造不会包含秘密的操作系统密钥环条目名。"""
    return f"gateway-peer-token:{node_id}"


def generate_gateway_token() -> str:
    """生成与 WireGuard 密钥格式明显不同的一次性应用令牌。"""
    return f"{GATEWAY_TOKEN_PREFIX}{secrets.token_urlsafe(32)}"


class GatewayConfigurationService:
    """协调非秘密 peer 配置与操作系统密钥环中的应用令牌。"""

    def __init__(
        self,
        repository: GatewayConfigurationRepository,
        secret_store: SecretStore,
    ) -> None:
        self._repository = repository
        self._secrets = secret_store

    def configure_local(
        self, bind: GatewayBindConfig, limits: GatewayLimits | None = None
    ) -> GatewayConfigurationView:
        """配置明确 WireGuard 监听地址，不接受通配或环回地址。"""
        existing = self._repository.load()
        value = GatewayConfiguration(
            bind=bind,
            limits=limits or (existing.limits if existing is not None else GatewayLimits()),
            peers=existing.peers if existing is not None else (),
        )
        self._repository.save(value)
        return self.view()

    def provision_peer(self, value: GatewayPeerInput) -> GatewayConfigurationView:
        """保存显式 peer；token 只进入当前系统账户的密钥环。"""
        if not value.token.startswith(GATEWAY_TOKEN_PREFIX):
            raise ValueError("网关凭据必须是独立生成的 tmn_ 应用令牌")
        config = self._require_config()
        _ = value.peer.endpoint()
        peers = (
            *(item for item in config.peers if item.node_id != value.peer.node_id),
            value.peer,
        )
        self._secrets.set(gateway_token_name(value.peer.node_id), value.token)
        self._repository.save(config.model_copy(update={"peers": peers}))
        return self.view()

    def revoke_peer(self, node_id: NodeId) -> GatewayConfigurationView:
        """同时删除 peer 非秘密配置和本机凭据。"""
        config = self._require_config()
        peers = tuple(item for item in config.peers if item.node_id != node_id)
        if len(peers) == len(config.peers):
            raise KeyError("gateway_peer_not_found")
        self._repository.save(config.model_copy(update={"peers": peers}))
        self._secrets.delete(gateway_token_name(node_id))
        return self.view()

    def view(self) -> GatewayConfigurationView:
        """返回不含 token 的配置摘要。"""
        config = self._repository.load()
        if config is None:
            return GatewayConfigurationView(configured=False)
        peers = tuple(
            GatewayPeerView(
                node_id=item.node_id,
                host=item.host,
                port=item.port,
                allowed_tools=item.allowed_tools,
                credential_configured=(
                    self._secrets.get(gateway_token_name(item.node_id)) is not None
                ),
            )
            for item in config.peers
        )
        return GatewayConfigurationView(
            configured=True,
            bind=config.bind,
            limits=config.limits,
            peers=peers,
        )

    def build_security_policy(self) -> GatewaySecurityPolicy:
        """启动网关时从密钥环加载 peer token，并立即转换为摘要。"""
        config = self._require_config()
        policies: list[GatewayPeerPolicy] = []
        for peer in config.peers:
            token = self._secrets.get(gateway_token_name(peer.node_id))
            if token is None:
                raise RuntimeError(f"peer {peer.node_id} 缺少网关凭据")
            policies.append(GatewayPeerPolicy.from_token(peer.node_id, token, peer.allowed_tools))
        return GatewaySecurityPolicy(policies, config.limits)

    def delete(self) -> None:
        """删除 TunnelMinion 自己的 peer 凭据和配置，不接触 WireGuard。"""
        config = self._repository.load()
        if config is not None:
            for peer in config.peers:
                self._secrets.delete(gateway_token_name(peer.node_id))
        self._repository.delete()

    def _require_config(self) -> GatewayConfiguration:
        config = self._repository.load()
        if config is None:
            raise RuntimeError("尚未配置本机 Tool Gateway WireGuard 地址")
        return config
