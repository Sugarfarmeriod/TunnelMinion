"""受管网络使用的严格、可序列化且不包含秘密的领域契约。"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from datetime import datetime
from enum import StrEnum
from typing import Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from tunnelminion.domain.identifiers import NetworkId, NodeId, ResourceId
from tunnelminion.domain.versioning import ProtocolVersion

NETWORK_PROTOCOL_VERSION = ProtocolVersion(major=1, minor=0)
MAX_NETWORK_PEERS = 32
MAX_ENDPOINT_CANDIDATES = 8
MAX_PLAN_STEPS = 32
MAX_CONFIG_BYTES = 65_536
_PUBLIC_KEY = re.compile(r"^[A-Za-z0-9+/]{43}=$")
_HASH = re.compile(r"^sha256:[0-9a-f]{64}$")


def canonical_sha256(value: object) -> str:
    """为无秘密结构生成稳定 SHA-256。"""
    canonical = json.dumps(
        value,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return f"sha256:{hashlib.sha256(canonical.encode()).hexdigest()}"


def _validate_host_route(value: str) -> str:
    route = ipaddress.ip_network(value, strict=True)
    if route.prefixlen != route.max_prefixlen:
        raise ValueError("首版只允许单节点 host route")
    return str(route)


def _validate_interface_address(value: str) -> str:
    address = ipaddress.ip_interface(value)
    if address.network.prefixlen != address.max_prefixlen:
        raise ValueError("受管接口地址必须使用 host 前缀")
    return str(address)


class ProviderKind(StrEnum):
    """首轮支持的平台 Provider。"""

    WINDOWS = "windows"
    MACOS = "macos"


class ProviderMode(StrEnum):
    """平台适配器的只读与受管模式。"""

    OBSERVE_ONLY = "observe_only"
    MANAGED = "managed"


class OwnershipState(StrEnum):
    """实时资源相对本地账本的所有权状态。"""

    ABSENT = "absent"
    OBSERVED_USER = "observed_user"
    MANAGED_OWNED = "managed_owned"
    OWNERSHIP_CONFLICT = "ownership_conflict"
    OWNERSHIP_UNKNOWN = "ownership_unknown"


class NetworkAction(StrEnum):
    """Provider 可执行的固定变化类型。"""

    CREATE = "create"
    UPDATE = "update"
    STOP = "stop"
    REMOVE = "remove"


class PlanStepKind(StrEnum):
    """跨平台计划允许的固定原子步骤。"""

    WRITE_CONFIG = "write_config"
    CREATE_INTERFACE = "create_interface"
    CONFIGURE_ADDRESS = "configure_address"
    CONFIGURE_PEER = "configure_peer"
    ADD_HOST_ROUTE = "add_host_route"
    STOP_INTERFACE = "stop_interface"
    REMOVE_INTERFACE = "remove_interface"
    DELETE_CONFIG = "delete_config"
    DELETE_SECRET = "delete_secret"


class NetworkErrorCode(StrEnum):
    """Provider 和状态机使用的稳定脱敏错误码。"""

    INVALID_CONFIG = "invalid_config"
    VERSION_INCOMPATIBLE = "version_incompatible"
    PROVIDER_UNAVAILABLE = "provider_unavailable"
    PERMISSION_DENIED = "permission_denied"
    AUTHORIZATION_REQUIRED = "authorization_required"
    ROUTE_NOT_ALLOWED = "route_not_allowed"
    ADDRESS_CONFLICT = "address_conflict"
    NAME_CONFLICT = "name_conflict"
    OWNERSHIP_CONFLICT = "ownership_conflict"
    APPLY_FAILED = "apply_failed"
    VERIFY_FAILED = "verify_failed"
    ROLLBACK_FAILED = "rollback_failed"
    CANCELLED = "cancelled"
    RECOVERY_REQUIRED = "recovery_required"


class ReceiptStatus(StrEnum):
    """一次 Provider 调用的结果。"""

    APPLIED = "applied"
    VERIFIED = "verified"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"
    CANCELLED = "cancelled"
    MANUAL_INTERVENTION = "manual_intervention"


class RelayRole(StrEnum):
    """节点在受管 network 中的显式 relay 角色。"""

    NONE = "none"
    CAPABLE = "capable"
    ACTIVE = "active"


class CandidateSource(StrEnum):
    """不接受模型文本的 endpoint 来源。"""

    ADMIN_EXPLICIT = "admin_explicit"
    NODE_OBSERVED = "node_observed"
    STUN_SAME_SOCKET = "stun_same_socket"


class KeyLifecycle(StrEnum):
    """受管 WireGuard 公钥生命周期。"""

    PENDING = "pending"
    ACTIVE = "active"
    RETIRED = "retired"


class LeaseStatus(StrEnum):
    """地址租约状态。"""

    RESERVED = "reserved"
    ACTIVE = "active"
    RELEASED = "released"


class AcknowledgementStage(StrEnum):
    """Agent 对 desired config 的逐阶段确认。"""

    PENDING = "pending"
    AWAITING_AUTHORIZATION = "awaiting_authorization"
    APPLYING = "applying"
    APPLIED = "applied"
    VERIFIED = "verified"
    ROLLED_BACK = "rolled_back"
    OWNERSHIP_CONFLICT = "ownership_conflict"
    MANUAL_INTERVENTION = "manual_intervention"


class NetworkError(BaseModel):
    """可进入审计与页面的脱敏错误。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    code: NetworkErrorCode
    message: str = Field(min_length=1, max_length=500)
    retryable: bool = False
    correlation_id: str = Field(min_length=1, max_length=128)


class EndpointCandidate(BaseModel):
    """带认证来源和有效期的有限 UDP endpoint 候选。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    host: str = Field(min_length=1, max_length=255)
    port: int = Field(ge=1, le=65535)
    source: CandidateSource
    observed_at: datetime
    expires_at: datetime

    @model_validator(mode="after")
    def validate_candidate(self) -> Self:
        ipaddress.ip_address(self.host)
        if self.expires_at <= self.observed_at:
            raise ValueError("endpoint 候选过期时间必须晚于观察时间")
        return self


class AddressLease(BaseModel):
    """Coordinator 分配的稳定 host address。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    network_id: NetworkId
    node_id: NodeId
    address: str
    pool: str
    revision: int = Field(ge=1)
    status: LeaseStatus

    @model_validator(mode="after")
    def validate_address(self) -> Self:
        address = ipaddress.ip_interface(self.address)
        pool = ipaddress.ip_network(self.pool, strict=True)
        if address.ip not in pool:
            raise ValueError("租约地址必须属于地址池")
        if address.network.prefixlen != address.max_prefixlen:
            raise ValueError("租约必须使用 host 前缀")
        return self


class NetworkIdentity(BaseModel):
    """节点可提交给 Coordinator 的最小公共网络身份。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    network_id: NetworkId
    node_id: NodeId
    provider: ProviderKind
    public_key: str = Field(pattern=_PUBLIC_KEY.pattern)
    key_lifecycle: KeyLifecycle
    secret_reference_configured: bool
    lease: AddressLease | None = None
    candidates: tuple[EndpointCandidate, ...] = Field(
        default=(), max_length=MAX_ENDPOINT_CANDIDATES
    )
    relay_role: RelayRole = RelayRole.NONE

    @model_validator(mode="after")
    def validate_identity(self) -> Self:
        if self.lease is not None and (
            self.lease.network_id != self.network_id or self.lease.node_id != self.node_id
        ):
            raise ValueError("地址租约必须属于相同 network/node")
        return self


class LocalNetworkKeyMaterial(BaseModel):
    """本机生成的公共身份与不透明秘密引用；私钥正文永不离开秘密存储。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    secret_reference: str = Field(min_length=3, max_length=224, repr=False)
    public_key: str = Field(pattern=_PUBLIC_KEY.pattern)
    public_key_hash: str = Field(pattern=_HASH.pattern)


class ApprovedRouteOverlap(BaseModel):
    """签名配置允许覆盖的一条既有 IPv4 宽路由及其观察指纹。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    route: str
    observation_fingerprint: str = Field(pattern=_HASH.pattern)

    @model_validator(mode="after")
    def validate_route(self) -> Self:
        network = ipaddress.ip_network(self.route, strict=True)
        if not isinstance(network, ipaddress.IPv4Network) or not 1 <= network.prefixlen < 32:
            raise ValueError("允许覆盖的既有路由必须是非默认 IPv4 宽路由")
        if str(network) != self.route:
            raise ValueError("允许覆盖的既有路由必须使用规范形式")
        return self


class PeerConfiguration(BaseModel):
    """desired config 中单个 peer 的公共配置。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    node_id: NodeId
    public_key: str = Field(pattern=_PUBLIC_KEY.pattern)
    allowed_host_routes: tuple[str, ...] = Field(min_length=1, max_length=8)
    candidates: tuple[EndpointCandidate, ...] = Field(
        default=(), max_length=MAX_ENDPOINT_CANDIDATES
    )
    persistent_keepalive_seconds: int | None = Field(default=None, ge=1, le=120)
    relay_role: RelayRole = RelayRole.NONE

    @model_validator(mode="after")
    def validate_routes(self) -> Self:
        normalized = tuple(_validate_host_route(value) for value in self.allowed_host_routes)
        if len(set(normalized)) != len(normalized):
            raise ValueError("peer host route 不得重复")
        return self


class DesiredNetworkConfig(BaseModel):
    """签名前、可由 Provider 消费的无秘密目标配置。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    protocol_version: ProtocolVersion = NETWORK_PROTOCOL_VERSION
    network_id: NetworkId
    target_node_id: NodeId
    provider: ProviderKind
    revision: int = Field(ge=1)
    parent_revision: int = Field(ge=0)
    interface_name: str = Field(pattern=r"^tmn-[a-z0-9-]{1,48}$")
    address: str
    listen_port: int | None = Field(default=None, ge=1, le=65535)
    peers: tuple[PeerConfiguration, ...] = Field(min_length=1, max_length=MAX_NETWORK_PEERS)
    allowed_route_overlaps: tuple[ApprovedRouteOverlap, ...] = Field(
        default=(),
        max_length=32,
    )
    relay_policy: RelayRole = RelayRole.NONE

    @model_validator(mode="after")
    def validate_config(self) -> Self:
        if not NETWORK_PROTOCOL_VERSION.is_compatible_with(self.protocol_version):
            raise ValueError("网络协议主版本不兼容")
        _validate_interface_address(self.address)
        if self.parent_revision >= self.revision:
            raise ValueError("父 revision 必须小于目标 revision")
        peer_ids = [str(peer.node_id) for peer in self.peers]
        if str(self.target_node_id) in peer_ids or len(set(peer_ids)) != len(peer_ids):
            raise ValueError("peer 节点必须唯一且不能等于目标节点")
        requested = {
            ipaddress.ip_interface(self.address).ip,
            *(
                ipaddress.ip_network(route, strict=True).network_address
                for peer in self.peers
                for route in peer.allowed_host_routes
            ),
        }
        overlap_keys = {
            (overlap.route, overlap.observation_fingerprint)
            for overlap in self.allowed_route_overlaps
        }
        if len(overlap_keys) != len(self.allowed_route_overlaps):
            raise ValueError("允许覆盖的既有路由不得重复")
        if any(
            not any(address in ipaddress.ip_network(overlap.route) for address in requested)
            for overlap in self.allowed_route_overlaps
        ):
            raise ValueError("允许覆盖的既有路由必须与目标地址直接相关")
        if len(self.model_dump_json().encode()) > MAX_CONFIG_BYTES:
            raise ValueError("desired config 超出字节预算")
        return self


class ManagedResourceOwnership(BaseModel):
    """本地账本与实时系统共同验证的资源所有权。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    resource_id: ResourceId
    network_id: NetworkId
    node_id: NodeId
    provider: ProviderKind
    interface_name: str = Field(min_length=1, max_length=64)
    stable_interface_id: str = Field(min_length=1, max_length=256)
    creation_nonce: str = Field(pattern=r"^[0-9a-f]{32}$")
    public_key_hash: str = Field(pattern=_HASH.pattern)
    parent_revision: int = Field(ge=0)
    desired_config_hash: str = Field(pattern=_HASH.pattern)
    system_fingerprint: str = Field(pattern=_HASH.pattern)


class NetworkObservation(BaseModel):
    """Provider 重新读取系统后返回的脱敏状态。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    provider: ProviderKind
    mode: ProviderMode
    interface_name: str = Field(min_length=1, max_length=64)
    stable_interface_id: str | None = Field(default=None, min_length=1, max_length=256)
    addresses: tuple[str, ...] = Field(default=(), max_length=16)
    host_routes: tuple[str, ...] = Field(default=(), max_length=64)
    public_key_hash: str | None = Field(default=None, pattern=_HASH.pattern)
    ownership: OwnershipState
    system_fingerprint: str = Field(pattern=_HASH.pattern)
    observed_at: datetime

    @model_validator(mode="after")
    def validate_network_values(self) -> Self:
        for value in self.addresses:
            ipaddress.ip_interface(value)
        for value in self.host_routes:
            ipaddress.ip_network(value, strict=True)
        if self.ownership is OwnershipState.MANAGED_OWNED and self.stable_interface_id is None:
            raise ValueError("受管资源必须具有稳定接口 ID")
        return self


class NetworkPlanStep(BaseModel):
    """一项可回执、可取消和可逆的固定步骤。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    index: int = Field(ge=0, lt=MAX_PLAN_STEPS)
    kind: PlanStepKind
    target: str = Field(min_length=1, max_length=256)
    expected_effect: str = Field(min_length=1, max_length=500)
    rollback_kind: PlanStepKind | None = None
    cancellation_safe_before: bool = True


class NetworkPlan(BaseModel):
    """可预览、可哈希且不包含秘密的 Provider 计划。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    action: NetworkAction
    desired: DesiredNetworkConfig
    observed_fingerprint: str = Field(pattern=_HASH.pattern)
    ownership: ManagedResourceOwnership | None = None
    steps: tuple[NetworkPlanStep, ...] = Field(min_length=1, max_length=MAX_PLAN_STEPS)
    plan_hash: str = Field(pattern=_HASH.pattern)

    @model_validator(mode="after")
    def validate_plan(self) -> Self:
        if tuple(step.index for step in self.steps) != tuple(range(len(self.steps))):
            raise ValueError("计划步骤索引必须连续")
        if self.action is not NetworkAction.CREATE and self.ownership is None:
            raise ValueError("非创建计划必须携带所有权证据")
        expected = compute_plan_hash(
            action=self.action,
            desired=self.desired,
            observed_fingerprint=self.observed_fingerprint,
            ownership=self.ownership,
            steps=self.steps,
        )
        if self.plan_hash != expected:
            raise ValueError("计划哈希与稳定字段不一致")
        return self


def compute_plan_hash(
    *,
    action: NetworkAction,
    desired: DesiredNetworkConfig,
    observed_fingerprint: str,
    ownership: ManagedResourceOwnership | None,
    steps: tuple[NetworkPlanStep, ...],
) -> str:
    """计算 Provider 计划的稳定哈希。"""
    return canonical_sha256(
        {
            "action": action,
            "desired": desired.model_dump(mode="json"),
            "observed_fingerprint": observed_fingerprint,
            "ownership": ownership.model_dump(mode="json") if ownership else None,
            "steps": [step.model_dump(mode="json") for step in steps],
        }
    )


class StepReceipt(BaseModel):
    """单个已确认步骤的无秘密回执。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    index: int = Field(ge=0, lt=MAX_PLAN_STEPS)
    kind: PlanStepKind
    succeeded: bool
    system_receipt_hash: str = Field(pattern=_HASH.pattern)


class ProviderReceipt(BaseModel):
    """Provider apply/rollback 的幂等回执。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    idempotency_key: str = Field(pattern=r"^netop_[0-9a-f]{64}$")
    plan_hash: str = Field(pattern=_HASH.pattern)
    revision: int = Field(ge=1)
    status: ReceiptStatus
    steps: tuple[StepReceipt, ...] = Field(default=(), max_length=MAX_PLAN_STEPS)
    observation_after: NetworkObservation | None = None
    error: NetworkError | None = None

    @model_validator(mode="after")
    def validate_receipt(self) -> Self:
        indexes = tuple(step.index for step in self.steps)
        if indexes != tuple(range(len(indexes))):
            raise ValueError("回执步骤必须从零连续")
        if self.status in {
            ReceiptStatus.FAILED,
            ReceiptStatus.CANCELLED,
            ReceiptStatus.MANUAL_INTERVENTION,
        }:
            if self.error is None:
                raise ValueError("失败回执必须包含错误")
        elif self.error is not None:
            raise ValueError("非失败回执不得包含错误")
        return self


class VerificationResult(BaseModel):
    """独立重新观察后得到的 Provider 验证结果。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    plan_hash: str = Field(pattern=_HASH.pattern)
    revision: int = Field(ge=1)
    succeeded: bool
    checked_dimensions: tuple[str, ...] = Field(min_length=1, max_length=16)
    observation: NetworkObservation
    error: NetworkError | None = None

    @model_validator(mode="after")
    def validate_result(self) -> Self:
        if self.succeeded == (self.error is not None):
            raise ValueError("验证成功状态与错误字段不一致")
        return self


class SignedDesiredConfig(BaseModel):
    """绑定目标、父 revision 与有效期的 Coordinator 签名 envelope。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    config: DesiredNetworkConfig
    key_id: str = Field(min_length=1, max_length=128)
    key_fingerprint: str = Field(pattern=_HASH.pattern)
    issued_at: datetime
    expires_at: datetime
    signature: str = Field(min_length=80, max_length=128)

    @model_validator(mode="after")
    def validate_envelope(self) -> Self:
        if self.expires_at <= self.issued_at:
            raise ValueError("签名配置过期时间必须晚于签发时间")
        return self


class NetworkAcknowledgement(BaseModel):
    """Agent 对配置 revision 的脱敏阶段确认。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    network_id: NetworkId
    node_id: NodeId
    revision: int = Field(ge=1)
    stage: AcknowledgementStage
    plan_hash: str | None = Field(default=None, pattern=_HASH.pattern)
    receipt_hash: str | None = Field(default=None, pattern=_HASH.pattern)
    error: NetworkError | None = None
    acknowledged_at: datetime
