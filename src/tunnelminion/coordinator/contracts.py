"""Coordinator v1 控制面协议契约；不包含任何工具或操作数据面正文。"""

from __future__ import annotations

import ipaddress
from datetime import datetime
from enum import StrEnum
from typing import Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from tunnelminion.domain.identifiers import (
    CoordinatorAuditId,
    EnrollmentTokenId,
    NetworkId,
    NodeId,
    RefreshCredentialId,
    ServiceId,
    SnapshotId,
)
from tunnelminion.domain.tools import Platform, RiskLevel
from tunnelminion.domain.versioning import ProtocolVersion

COORDINATOR_PROTOCOL = ProtocolVersion(major=1, minor=0)
ASSERTION_ALGORITHM = "EdDSA"
ASSERTION_TTL_SECONDS = 120
ASSERTION_AUDIENCES = frozenset({"coordinator-agent", "tool-gateway", "operation-gateway"})


class NodeStatus(StrEnum):
    """由 Coordinator 服务器时间与治理状态确定的节点状态。"""

    ONLINE = "online"
    STALE = "stale"
    OFFLINE = "offline"
    REVOKED = "revoked"
    INCOMPATIBLE = "incompatible"


class DirectoryFreshness(StrEnum):
    """目录记录对调用方可表达的新鲜度。"""

    FRESH = "fresh"
    STALE = "stale"
    OFFLINE = "offline"
    REVOKED = "revoked"


class SnapshotKind(StrEnum):
    """逐节点完整快照类别。"""

    CAPABILITY = "capability"
    SERVICE = "service"


class CapabilityAvailability(StrEnum):
    """能力摘要的确定性本地可用性。"""

    AVAILABLE = "available"
    DEGRADED = "degraded"
    UNAVAILABLE = "unavailable"


class ServiceProtocol(StrEnum):
    """服务目录首版支持的协议摘要。"""

    TCP = "tcp"
    HTTP = "http"
    HTTPS = "https"


class ServiceAccessibility(StrEnum):
    """节点观察到的服务监听范围，不等同于真实可达性。"""

    LOOPBACK = "loopback"
    NETWORK = "network"
    UNKNOWN = "unknown"


class ServiceLifecycle(StrEnum):
    """完整快照收敛后的服务生命周期。"""

    ACTIVE = "active"
    STOPPED = "stopped"


class CoordinatorErrorCode(StrEnum):
    """跨实现稳定的 Coordinator 协议错误码。"""

    VERSION_INCOMPATIBLE = "version_incompatible"
    UNAUTHENTICATED = "unauthenticated"
    FORBIDDEN = "forbidden"
    CONFLICT = "conflict"
    OUT_OF_ORDER = "out_of_order"
    SNAPSHOT_TOO_LARGE = "snapshot_too_large"
    FULL_SYNC_REQUIRED = "full_sync_required"
    INVALID_CURSOR = "invalid_cursor"
    RATE_LIMITED = "rate_limited"


class CoordinatorAuditAction(StrEnum):
    """不含秘密的 Coordinator 控制面审计动作。"""

    NODE_REGISTERED = "node_registered"
    HEARTBEAT_ACCEPTED = "heartbeat_accepted"
    CAPABILITIES_REPLACED = "capabilities_replaced"
    SERVICES_REPLACED = "services_replaced"
    CREDENTIAL_ROTATED = "credential_rotated"
    NODE_REVOKED = "node_revoked"
    DIRECTORY_READ = "directory_read"


class CoordinatorAuditResult(StrEnum):
    """控制面动作终态。"""

    SUCCEEDED = "succeeded"
    REJECTED = "rejected"


class GatewayEndpoint(BaseModel):
    """目录可发布的私有直连 Gateway endpoint。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    host: str
    port: int = Field(default=8787, ge=1024, le=65535)

    @field_validator("host")
    @classmethod
    def validate_private_host(cls, value: str) -> str:
        """拒绝公网、通配、环回与组播地址。"""
        address = ipaddress.ip_address(value)
        if (
            not address.is_private
            or address.is_loopback
            or address.is_unspecified
            or address.is_multicast
        ):
            raise ValueError("Coordinator 目录只接受明确的私有直连地址")
        return value


class NodeIdentity(BaseModel):
    """节点注册、心跳和目录共享的最小稳定身份。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    network_id: NetworkId
    node_id: NodeId
    display_name: str = Field(min_length=1, max_length=80)
    platform: Platform
    gateway_endpoint: GatewayEndpoint
    protocol: ProtocolVersion = COORDINATOR_PROTOCOL


class HeartbeatRequest(BaseModel):
    """Agent 发出的有界心跳；客户端时间只用于诊断。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    protocol: ProtocolVersion = COORDINATOR_PROTOCOL
    network_id: NetworkId
    node_id: NodeId
    sent_at: datetime
    last_server_revision: int = Field(default=0, ge=0)


class HeartbeatResponse(BaseModel):
    """Coordinator 以服务器接收时间确认节点状态。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    protocol: ProtocolVersion = COORDINATOR_PROTOCOL
    received_at: datetime
    node_status: NodeStatus
    server_revision: int = Field(ge=0)


class CapabilitySummary(BaseModel):
    """可以进入目录的最小工具能力摘要。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(pattern=r"^[a-z][a-z0-9_]{2,63}$")
    version: ProtocolVersion
    platform: Platform
    risk_level: RiskLevel
    availability: CapabilityAvailability
    schema_hash: str = Field(pattern=r"^[0-9a-f]{64}$")


class ServiceSummary(BaseModel):
    """不含业务正文、环境或完整进程参数的服务摘要。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    service_id: ServiceId
    protocol: ServiceProtocol
    host: str = Field(min_length=1, max_length=255)
    port: int = Field(ge=1, le=65535)
    accessibility: ServiceAccessibility
    source: str = Field(min_length=1, max_length=64)
    confidence: float = Field(ge=0, le=1)
    observed_at: datetime
    lifecycle: ServiceLifecycle = ServiceLifecycle.ACTIVE


class SnapshotEnvelope(BaseModel):
    """两类完整快照共享的幂等与单调字段。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    protocol: ProtocolVersion = COORDINATOR_PROTOCOL
    network_id: NetworkId
    node_id: NodeId
    snapshot_id: SnapshotId
    sequence: int = Field(ge=1)
    idempotency_key: str = Field(pattern=r"^snapkey_[0-9a-f]{64}$")
    generated_at: datetime


class CapabilitySnapshot(SnapshotEnvelope):
    """逐节点完整能力快照。"""

    kind: SnapshotKind = SnapshotKind.CAPABILITY
    capabilities: tuple[CapabilitySummary, ...] = Field(max_length=256)

    @model_validator(mode="after")
    def validate_kind(self) -> Self:
        if self.kind is not SnapshotKind.CAPABILITY:
            raise ValueError("能力快照 kind 必须为 capability")
        return self


class ServiceSnapshot(SnapshotEnvelope):
    """逐节点完整服务快照。"""

    kind: SnapshotKind = SnapshotKind.SERVICE
    services: tuple[ServiceSummary, ...] = Field(max_length=1024)

    @model_validator(mode="after")
    def validate_kind(self) -> Self:
        if self.kind is not SnapshotKind.SERVICE:
            raise ValueError("服务快照 kind 必须为 service")
        return self


class SnapshotReceipt(BaseModel):
    """快照提交后的单调修订确认。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    protocol: ProtocolVersion = COORDINATOR_PROTOCOL
    snapshot_id: SnapshotId
    sequence: int = Field(ge=1)
    server_revision: int = Field(ge=1)
    duplicate: bool = False
    received_at: datetime


class DirectoryNodeSummary(BaseModel):
    """目录查询可返回的有界节点摘要。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    identity: NodeIdentity
    status: NodeStatus
    freshness: DirectoryFreshness
    last_received_at: datetime | None
    capability_count: int = Field(ge=0)
    service_count: int = Field(ge=0)
    server_revision: int = Field(ge=0)


class DirectoryQuery(BaseModel):
    """稳定分页目录查询；network 始终由认证身份复核。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    protocol: ProtocolVersion = COORDINATOR_PROTOCOL
    network_id: NetworkId
    node_id: NodeId | None = None
    node_status: NodeStatus | None = None
    platform: Platform | None = None
    tool_name: str | None = Field(default=None, pattern=r"^[a-z][a-z0-9_]{2,63}$")
    service_protocol: ServiceProtocol | None = None
    service_port: int | None = Field(default=None, ge=1, le=65535)
    freshness: DirectoryFreshness | None = None
    page_size: int = Field(default=50, ge=1, le=200)
    cursor: str | None = Field(default=None, min_length=16, max_length=512)


class DirectoryPage(BaseModel):
    """某一修订上的稳定有界节点页。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    protocol: ProtocolVersion = COORDINATOR_PROTOCOL
    server_revision: int = Field(ge=0)
    generated_at: datetime
    nodes: tuple[DirectoryNodeSummary, ...] = Field(max_length=200)
    next_cursor: str | None = Field(default=None, min_length=16, max_length=512)
    full_sync_required: bool = False


class CoordinatorError(BaseModel):
    """不泄露内部状态或其他 network 存在性的稳定错误。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    code: CoordinatorErrorCode
    message: str = Field(min_length=1, max_length=200)
    retryable: bool = False


class CoordinatorErrorResponse(BaseModel):
    """Coordinator v1 失败响应。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    protocol: ProtocolVersion = COORDINATOR_PROTOCOL
    error: CoordinatorError


class CoordinatorAuditRecord(BaseModel):
    """只记录身份、修订、动作、结果、错误和有界计数。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    audit_id: CoordinatorAuditId
    network_id: NetworkId
    node_id: NodeId | None
    server_revision: int = Field(ge=0)
    action: CoordinatorAuditAction
    result: CoordinatorAuditResult
    error_code: CoordinatorErrorCode | None = None
    item_count: int = Field(default=0, ge=0, le=10_000)
    occurred_at: datetime


class EnrollmentTokenRequest(BaseModel):
    """本机管理员创建一次性 enrollment token 的有界请求。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    network_id: NetworkId
    expires_in_seconds: int = Field(default=600, ge=30, le=3600)
    max_uses: int = Field(default=1, ge=1, le=10)


class EnrollmentTokenCreated(BaseModel):
    """仅在创建响应出现一次的完整 enrollment token。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    token_id: EnrollmentTokenId
    network_id: NetworkId
    token: str = Field(min_length=43, max_length=512, repr=False)
    expires_at: datetime
    max_uses: int = Field(ge=1, le=10)


class NodeRegistrationRequest(BaseModel):
    """Agent 首次注册提交的稳定身份与一次性材料。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    identity: NodeIdentity
    device_identity_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    enrollment_token: str = Field(min_length=43, max_length=512, repr=False)
    idempotency_key: str = Field(pattern=r"^regkey_[0-9a-f]{64}$")


class NodeRegistrationResponse(BaseModel):
    """注册或幂等恢复后返回的节点身份与新 refresh 凭据。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    protocol: ProtocolVersion = COORDINATOR_PROTOCOL
    identity: NodeIdentity
    credential_id: RefreshCredentialId
    refresh_credential: str = Field(min_length=43, max_length=512, repr=False)
    server_revision: int = Field(ge=1)
    issued_at: datetime


class RefreshAuthentication(BaseModel):
    """节点使用 keyring 内 refresh 凭据完成控制面认证。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    protocol: ProtocolVersion = COORDINATOR_PROTOCOL
    network_id: NetworkId
    node_id: NodeId
    refresh_credential: str = Field(min_length=43, max_length=512, repr=False)


class RegisteredNodeView(BaseModel):
    """管理员和服务层可读取的不含凭据节点视图。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    identity: NodeIdentity
    device_identity_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    status: NodeStatus
    server_revision: int = Field(ge=1)
    created_at: datetime
    revoked_at: datetime | None = None


class SigningKeyMetadata(BaseModel):
    """SQLite 只保存秘密后端引用、公钥和轮换时间，不保存私钥正文。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    key_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{2,63}$")
    private_key_reference: str = Field(min_length=1, max_length=200)
    public_key: str = Field(pattern=r"^[A-Za-z0-9_-]{43}$")
    fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    activates_at: datetime
    retires_at: datetime | None = None
    destroyed_at: datetime | None = None
