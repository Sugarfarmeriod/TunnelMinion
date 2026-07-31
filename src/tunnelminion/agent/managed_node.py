"""常规节点的非秘密 managed 配置、状态与 enrollment 边界。"""

from __future__ import annotations

import hashlib
import os
from enum import StrEnum
from pathlib import Path
from typing import Protocol, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from tunnelminion.agent.coordinator import (
    CoordinatorClientConfig,
    CoordinatorEnrollmentClient,
    CoordinatorTransport,
)
from tunnelminion.coordinator.client_credentials import AgentRefreshCredentialStore
from tunnelminion.coordinator.contracts import (
    GatewayEndpoint,
    NodeIdentity,
    NodeRegistrationResponse,
)
from tunnelminion.domain.identifiers import NetworkId, NodeId
from tunnelminion.domain.tools import Platform
from tunnelminion.model.secrets import (
    KeyringSecretStore,
    RestrictedFileSecretStore,
    SecretStore,
)

MANAGED_NODE_CONFIG_VERSION = "managed-node/v1"
MANAGED_NODE_CONFIG_FILE = "managed-node.json"


class ManagedNodeSecretStoreKind(StrEnum):
    """Coordinator refresh 凭据允许使用的本机秘密存储。"""

    KEYRING = "keyring"
    RESTRICTED_FILE = "restricted-file"


class ManagedNodeState(StrEnum):
    """普通启动和资源页共享的最小配置/enrollment 状态。"""

    UNCONFIGURED = "unconfigured"
    DISABLED = "disabled"
    ENROLLMENT_REQUIRED = "enrollment-required"
    READY = "ready"
    UNAVAILABLE = "unavailable"


class ServiceObservationConfig(BaseModel):
    """确定性服务观察的非秘密开关与硬预算。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    listeners_enabled: bool = True
    processes_enabled: bool = True
    docker_enabled: bool = True
    active_probe_enabled: bool = False
    interval_seconds: float = Field(default=30, ge=5, le=3600)
    timeout_seconds: float = Field(default=10, gt=0, le=60)
    max_services: int = Field(default=1024, ge=1, le=1024)
    max_snapshot_bytes: int = Field(default=262_144, ge=1024, le=1_000_000)


class ManagedNodeConfig(BaseModel):
    """可写入普通 JSON 的 managed node 配置；schema 不声明任何秘密字段。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = Field(default=MANAGED_NODE_CONFIG_VERSION, frozen=True)
    enabled: bool = True
    coordinator_endpoint: str
    network_id: NetworkId
    node_id: NodeId
    display_name: str = Field(min_length=1, max_length=80)
    platform: Platform
    gateway_endpoint: GatewayEndpoint
    pinned_fingerprints: frozenset[str] = Field(min_length=1, max_length=8)
    secret_store: ManagedNodeSecretStoreKind = ManagedNodeSecretStoreKind.KEYRING
    request_timeout_seconds: float = Field(default=5, gt=0, le=30)
    sync_interval_seconds: float = Field(default=15, gt=0, le=300)
    base_backoff_seconds: float = Field(default=1, gt=0, le=30)
    max_backoff_seconds: float = Field(default=60, gt=0, le=600)
    cache_ttl_seconds: int = Field(default=120, ge=1, le=3600)
    services: ServiceObservationConfig = ServiceObservationConfig()

    @model_validator(mode="after")
    def validate_contract(self) -> Self:
        if self.schema_version != MANAGED_NODE_CONFIG_VERSION:
            raise ValueError("managed node 配置版本不受支持")
        if self.max_backoff_seconds < self.base_backoff_seconds:
            raise ValueError("最大退避不得小于基础退避")
        self.coordinator_client_config()
        return self

    def coordinator_client_config(self) -> CoordinatorClientConfig:
        """复用现有 Coordinator URL、指纹和预算校验。"""
        return CoordinatorClientConfig(
            endpoint=self.coordinator_endpoint,
            network_id=self.network_id,
            node_id=self.node_id,
            pinned_fingerprints=self.pinned_fingerprints,
            request_timeout_seconds=self.request_timeout_seconds,
            sync_interval_seconds=self.sync_interval_seconds,
            base_backoff_seconds=self.base_backoff_seconds,
            max_backoff_seconds=self.max_backoff_seconds,
            max_services=self.services.max_services,
            max_snapshot_bytes=self.services.max_snapshot_bytes,
            cache_ttl_seconds=self.cache_ttl_seconds,
        )

    def identity(self) -> NodeIdentity:
        """构造注册与同步共享的稳定公开身份。"""
        return NodeIdentity(
            network_id=self.network_id,
            node_id=self.node_id,
            display_name=self.display_name,
            platform=self.platform,
            gateway_endpoint=self.gateway_endpoint,
        )

    def device_identity_hash(self) -> str:
        """从本机稳定 node 身份构造不含秘密的幂等设备摘要。"""
        value = f"{MANAGED_NODE_CONFIG_VERSION}:{self.platform}:{self.node_id}"
        return hashlib.sha256(value.encode()).hexdigest()


class ManagedNodeStatus(BaseModel):
    """资源页可安全展示的 managed 配置/enrollment 摘要。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    configured: bool
    enabled: bool = False
    state: ManagedNodeState
    schema_version: str | None = None
    network_id: NetworkId | None = None
    node_id: NodeId | None = None
    platform: Platform | None = None
    credential_configured: bool = False
    last_error_code: str | None = Field(default=None, min_length=1, max_length=128)


class ManagedNodeConfigRepository(Protocol):
    """managed node 非秘密配置仓储。"""

    def load(self) -> ManagedNodeConfig | None: ...

    def save(self, config: ManagedNodeConfig) -> None: ...

    def delete(self) -> None: ...


class FileManagedNodeConfigRepository:
    """以原子替换保存版本化 managed node JSON。"""

    def __init__(self, path: Path) -> None:
        self._path = path

    def load(self) -> ManagedNodeConfig | None:
        if not self._path.exists():
            return None
        return ManagedNodeConfig.model_validate_json(self._path.read_text(encoding="utf-8"))

    def save(self, config: ManagedNodeConfig) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self._path.with_suffix(f"{self._path.suffix}.tmp")
        temporary.write_text(config.model_dump_json(indent=2), encoding="utf-8")
        if os.name != "nt":
            os.chmod(temporary, 0o600)
        temporary.replace(self._path)

    def delete(self) -> None:
        self._path.unlink(missing_ok=True)


def managed_node_secret_store(
    data_dir: Path,
    kind: ManagedNodeSecretStoreKind,
) -> SecretStore:
    """按显式配置选择操作系统 keyring 或当前账户受限文件。"""
    if kind is ManagedNodeSecretStoreKind.KEYRING:
        return KeyringSecretStore()
    return RestrictedFileSecretStore(data_dir / "coordinator-secrets")


def managed_node_status(
    config: ManagedNodeConfig | None,
    credentials: AgentRefreshCredentialStore | None = None,
    *,
    error_code: str | None = None,
) -> ManagedNodeStatus:
    """不读取或回显 refresh 正文，只报告凭据是否存在。"""
    if config is None:
        return ManagedNodeStatus(
            configured=False,
            state=(
                ManagedNodeState.UNAVAILABLE
                if error_code is not None
                else ManagedNodeState.UNCONFIGURED
            ),
            last_error_code=error_code,
        )
    if not config.enabled:
        return ManagedNodeStatus(
            configured=True,
            state=ManagedNodeState.DISABLED,
            schema_version=config.schema_version,
            network_id=config.network_id,
            node_id=config.node_id,
            platform=config.platform,
            last_error_code=error_code,
        )
    credential_configured = (
        credentials.load(config.network_id, config.node_id) is not None
        if credentials is not None
        else False
    )
    state = (
        ManagedNodeState.UNAVAILABLE
        if error_code is not None
        else ManagedNodeState.READY
        if credential_configured
        else ManagedNodeState.ENROLLMENT_REQUIRED
    )
    return ManagedNodeStatus(
        configured=True,
        enabled=True,
        state=state,
        schema_version=config.schema_version,
        network_id=config.network_id,
        node_id=config.node_id,
        platform=config.platform,
        credential_configured=credential_configured,
        last_error_code=error_code,
    )


async def enroll_managed_node(
    config: ManagedNodeConfig,
    token: str,
    transport: CoordinatorTransport,
    credentials: AgentRefreshCredentialStore,
) -> NodeRegistrationResponse:
    """执行一次显式 enrollment；调用方负责只从标准输入取得 token。"""
    client = CoordinatorEnrollmentClient(
        config.coordinator_client_config(),
        transport,
        credentials,
    )
    return await client.enroll(
        config.identity(),
        device_identity_hash=config.device_identity_hash(),
        enrollment_token=token,
    )
