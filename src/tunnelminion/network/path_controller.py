"""受管网络的确定性候选探测、直连验证与防抖路径控制器。"""

from __future__ import annotations

import asyncio
import ipaddress
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import ClassVar, Protocol, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from tunnelminion.domain.identifiers import NetworkId, NodeId
from tunnelminion.network.contracts import (
    CandidateSource,
    EndpointCandidate,
    ProviderKind,
    canonical_sha256,
)


class NetworkPathType(StrEnum):
    """调用方可明确区分的路径类型。"""

    DIRECT = "direct"
    RELAYED = "relayed"
    STATIC = "static"
    OFFLINE = "offline"


class DirectPathErrorCode(StrEnum):
    """不泄露 endpoint 的稳定直连失败码。"""

    NO_APPROVED_CANDIDATE = "no_approved_candidate"
    ENDPOINT_UNREACHABLE = "endpoint_unreachable"
    HANDSHAKE_STALE = "handshake_stale"
    HOST_ROUTE_MISSING = "host_route_missing"
    TARGET_UNREACHABLE = "target_unreachable"
    REVISION_ROLLED_BACK = "revision_rolled_back"
    PERMISSION_DENIED = "permission_denied"
    UNSUPPORTED = "unsupported"
    TIMEOUT = "timeout"
    PROVIDER_UNAVAILABLE = "provider_unavailable"
    PATH_UNAVAILABLE = "path_unavailable"
    CANCELLED = "cancelled"


class CandidateProbePolicy(BaseModel):
    """本机管理员确定的候选范围和有界探测预算。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    approved_networks: tuple[str, ...] = Field(min_length=1, max_length=16)
    allowed_sources: frozenset[CandidateSource] = frozenset(
        {
            CandidateSource.ADMIN_EXPLICIT,
            CandidateSource.STUN_SAME_SOCKET,
            CandidateSource.NODE_OBSERVED,
        }
    )
    max_candidates: int = Field(default=4, ge=1, le=8)
    per_candidate_timeout_seconds: float = Field(default=1.0, gt=0, le=5)
    target_timeout_seconds: float = Field(default=2.0, gt=0, le=10)
    approved_ports: tuple[int, ...] = Field(default=(), max_length=32)
    min_refresh_interval_seconds: float = Field(default=30.0, gt=0, le=3600)
    max_handshake_age_seconds: int = Field(default=180, ge=5, le=3600)

    @model_validator(mode="after")
    def validate_networks(self) -> Self:
        for value in self.approved_networks:
            network = ipaddress.ip_network(value, strict=True)
            if network.prefixlen == 0 or network.is_multicast:
                raise ValueError("候选策略不能批准默认路由或组播网段")
        if len(set(self.approved_ports)) != len(self.approved_ports):
            raise ValueError("候选端口不得重复")
        if any(not 1 <= port <= 65535 for port in self.approved_ports):
            raise ValueError("候选端口必须位于有效端口范围")
        return self


class DirectPathEvidence(BaseModel):
    """联合 endpoint、handshake、host route 与目标探测的脱敏证据。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    network_id: NetworkId
    node_id: NodeId
    plan_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    authorization_revision: int = Field(ge=1)
    provider: ProviderKind
    revision: int = Field(ge=1)
    target_host_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    target_port: int = Field(ge=1, le=65535)
    route_identity_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    candidate_count: int = Field(ge=0, le=8)
    selected_candidate_hash: str | None = Field(
        default=None,
        pattern=r"^sha256:[0-9a-f]{64}$",
    )
    selected_candidate_source: CandidateSource | None = None
    endpoint_probe_at: datetime | None = None
    endpoint_probe_succeeded: bool = False
    last_handshake_at: datetime | None = None
    handshake_probe_at: datetime | None = None
    handshake_fresh: bool = False
    host_route_probe_at: datetime | None = None
    host_route_present: bool = False
    target_probe_at: datetime | None = None
    target_probe_succeeded: bool = False
    verified: bool
    stable_error_code: DirectPathErrorCode | None = None
    source: str = Field(default="unknown", min_length=1, max_length=128)
    observed_at: datetime
    freshness_ttl_seconds: int = Field(default=180, ge=1, le=3600)
    expires_at: datetime

    @model_validator(mode="after")
    def validate_result(self) -> Self:
        timestamps = (
            self.endpoint_probe_at,
            self.handshake_probe_at,
            self.host_route_probe_at,
            self.target_probe_at,
            self.observed_at,
            self.expires_at,
        )
        if any(
            value is not None and (value.tzinfo is None or value.utcoffset() != timedelta(0))
            for value in timestamps
        ):
            raise ValueError("direct path evidence 时间必须使用 timezone-aware UTC")
        if self.expires_at != self.observed_at + timedelta(seconds=self.freshness_ttl_seconds):
            raise ValueError("direct path evidence freshness TTL 必须绑定 observed_at")
        if self.authorization_revision != self.revision:
            raise ValueError("path evidence authorization revision 必须精确绑定 revision")
        dimensions = (
            self.endpoint_probe_succeeded,
            self.handshake_fresh,
            self.host_route_present,
            self.target_probe_succeeded,
        )
        if self.verified != all(dimensions):
            raise ValueError("direct 验证结果必须与四项证据一致")
        if self.verified == (self.stable_error_code is not None):
            raise ValueError("direct 验证成功状态与错误码不一致")
        return self


class PathProbe(Protocol):
    """固定网络探测边界；实现不得调用模型。"""

    async def endpoint(
        self,
        candidate: EndpointCandidate,
        timeout_seconds: float,
    ) -> bool: ...  # pragma: no cover - Protocol

    async def target(
        self,
        host: str,
        port: int,
        timeout_seconds: float,
    ) -> bool: ...  # pragma: no cover - Protocol


class DirectPathVerifier:
    """只消费结构化候选和实时系统事实，不接受 prompt/对话 endpoint。"""

    _SOURCE_PRIORITY: ClassVar[dict[CandidateSource, int]] = {
        CandidateSource.ADMIN_EXPLICIT: 0,
        CandidateSource.STUN_SAME_SOCKET: 1,
        CandidateSource.NODE_OBSERVED: 2,
    }

    def __init__(self, policy: CandidateProbePolicy, probe: PathProbe) -> None:
        self._policy = policy
        self._probe = probe

    async def verify(
        self,
        *,
        network_id: NetworkId,
        node_id: NodeId,
        plan_hash: str,
        authorization_revision: int,
        provider: ProviderKind,
        revision: int,
        candidates: tuple[EndpointCandidate, ...],
        last_handshake_at: datetime | None,
        observed_host_routes: tuple[str, ...],
        expected_host_route: str,
        target_host: str,
        target_port: int,
        now: datetime,
        freshness_ttl_seconds: int = 180,
    ) -> DirectPathEvidence:
        current = self.aware(now)
        self._validate_target(target_host, target_port)
        if not self._target_is_approved(target_host, target_port):
            raise ValueError("path target 不在授权的 network/port 范围")
        expected_route = ipaddress.ip_network(expected_host_route, strict=True)
        if expected_route.prefixlen != expected_route.max_prefixlen:
            raise ValueError("path expected host route 必须是精确 host route")
        if not any(
            expected_route.version == approved.version
            and int(expected_route.network_address) >= int(approved.network_address)
            and int(expected_route.broadcast_address) <= int(approved.broadcast_address)
            for approved in (
                ipaddress.ip_network(item, strict=True) for item in self._policy.approved_networks
            )
        ):
            raise ValueError("path expected host route 不在授权 network 范围")
        ranked = self._rank_candidates(candidates, current)
        selected: EndpointCandidate | None = None
        endpoint_probe_at: datetime | None = None
        for candidate in ranked:
            endpoint_probe_at = current
            if await self._probe.endpoint(
                candidate,
                self._policy.per_candidate_timeout_seconds,
            ):
                selected = candidate
                break
        handshake_fresh = self._handshake_fresh(last_handshake_at, current)
        route_present = expected_host_route in {
            str(ipaddress.ip_network(item, strict=True)) for item in observed_host_routes
        }
        target_probe_at = current if selected is not None else None
        target_succeeded = (
            await self._probe.target(
                target_host,
                target_port,
                self._policy.target_timeout_seconds,
            )
            if selected is not None
            else False
        )
        verified = selected is not None and handshake_fresh and route_present and target_succeeded
        return DirectPathEvidence(
            network_id=network_id,
            node_id=node_id,
            plan_hash=plan_hash,
            authorization_revision=authorization_revision,
            provider=provider,
            revision=revision,
            target_host_hash=canonical_sha256({"host": target_host}),
            target_port=target_port,
            route_identity_hash=canonical_sha256({"host_route": expected_host_route}),
            candidate_count=len(ranked),
            selected_candidate_hash=(
                canonical_sha256(selected.model_dump(mode="json")) if selected is not None else None
            ),
            selected_candidate_source=selected.source if selected is not None else None,
            endpoint_probe_at=endpoint_probe_at,
            endpoint_probe_succeeded=selected is not None,
            last_handshake_at=last_handshake_at,
            handshake_probe_at=current,
            handshake_fresh=handshake_fresh,
            host_route_probe_at=current,
            host_route_present=route_present,
            target_probe_at=target_probe_at,
            target_probe_succeeded=target_succeeded,
            verified=verified,
            stable_error_code=self._error_code(
                ranked=ranked,
                selected=selected,
                handshake_fresh=handshake_fresh,
                route_present=route_present,
                target_succeeded=target_succeeded,
            ),
            source="structured-candidate",
            observed_at=current,
            freshness_ttl_seconds=freshness_ttl_seconds,
            expires_at=current + timedelta(seconds=freshness_ttl_seconds),
        )

    def _target_is_approved(self, host: str, port: int) -> bool:
        address = ipaddress.ip_address(host)
        networks = tuple(
            ipaddress.ip_network(value, strict=True) for value in self._policy.approved_networks
        )
        return port in self._policy.approved_ports and any(
            address in network for network in networks
        )

    @staticmethod
    def _validate_target(host: str, port: int) -> None:
        address = ipaddress.ip_address(host)
        if address.is_unspecified or address.is_multicast:
            raise ValueError("path target 不能使用通配或组播地址")
        if not (address.is_private or address.is_loopback or address.is_link_local):
            raise ValueError("path target 必须属于私有、环回或链路本地地址")
        if not 1 <= port <= 65535:
            raise ValueError("path target 端口无效")

    def _rank_candidates(
        self,
        candidates: tuple[EndpointCandidate, ...],
        now: datetime,
    ) -> tuple[EndpointCandidate, ...]:
        approved_networks = tuple(
            ipaddress.ip_network(value, strict=True) for value in self._policy.approved_networks
        )
        accepted = (
            item
            for item in candidates
            if item.source in self._policy.allowed_sources
            and item.expires_at.astimezone(UTC) > now
            and (not self._policy.approved_ports or item.port in self._policy.approved_ports)
            and any(ipaddress.ip_address(item.host) in network for network in approved_networks)
        )
        ranked = sorted(
            accepted,
            key=lambda item: (
                self._SOURCE_PRIORITY[item.source],
                -item.observed_at.timestamp(),
                item.host,
                item.port,
            ),
        )
        return tuple(ranked[: self._policy.max_candidates])

    def _handshake_fresh(
        self,
        last_handshake_at: datetime | None,
        now: datetime,
    ) -> bool:
        if last_handshake_at is None or last_handshake_at.tzinfo is None:
            return False
        age = now - last_handshake_at.astimezone(UTC)
        return timedelta(0) <= age <= timedelta(seconds=self._policy.max_handshake_age_seconds)

    @staticmethod
    def _error_code(
        *,
        ranked: tuple[EndpointCandidate, ...],
        selected: EndpointCandidate | None,
        handshake_fresh: bool,
        route_present: bool,
        target_succeeded: bool,
    ) -> DirectPathErrorCode | None:
        if not ranked:
            return DirectPathErrorCode.NO_APPROVED_CANDIDATE
        if selected is None:
            return DirectPathErrorCode.ENDPOINT_UNREACHABLE
        if not handshake_fresh:
            return DirectPathErrorCode.HANDSHAKE_STALE
        if not route_present:
            return DirectPathErrorCode.HOST_ROUTE_MISSING
        if not target_succeeded:
            return DirectPathErrorCode.TARGET_UNREACHABLE
        return None

    @staticmethod
    def aware(value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("路径验证时钟必须包含时区")
        return value.astimezone(UTC)


class PathControllerPolicy(BaseModel):
    """失败/恢复阈值与最小驻留时间。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    consecutive_failure_threshold: int = Field(default=3, ge=2, le=10)
    consecutive_success_threshold: int = Field(default=2, ge=2, le=10)
    minimum_dwell_seconds: int = Field(default=30, ge=0, le=3600)


class PathSelection(BaseModel):
    """单节点当前选择；不包含 endpoint、密钥或完整 route。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    network_id: NetworkId | None = None
    node_id: NodeId | None = None
    plan_hash: str | None = Field(default=None, pattern=r"^sha256:[0-9a-f]{64}$")
    authorization_revision: int | None = Field(default=None, ge=1)
    path_type: NetworkPathType
    provider: ProviderKind
    revision: int = Field(ge=1)
    last_known_good_revision: int | None = Field(default=None, ge=1)
    candidate_count: int = Field(ge=0, le=8)
    consecutive_failures: int = Field(ge=0, le=10_000)
    consecutive_successes: int = Field(ge=0, le=10_000)
    selected_at: datetime
    last_evidence_at: datetime
    stable_error_code: DirectPathErrorCode | None = None
    target_host_hash: str | None = Field(default=None, pattern=r"^sha256:[0-9a-f]{64}$")
    target_port: int | None = Field(default=None, ge=1, le=65535)
    route_identity_hash: str | None = Field(default=None, pattern=r"^sha256:[0-9a-f]{64}$")
    expires_at: datetime | None = None

    @model_validator(mode="after")
    def validate_binding(self) -> Self:
        for value in (self.selected_at, self.last_evidence_at, self.expires_at):
            if value is not None and (value.tzinfo is None or value.utcoffset() != timedelta(0)):
                raise ValueError("path selection 时间必须使用 timezone-aware UTC")
        if self.path_type is NetworkPathType.DIRECT:
            if any(
                value is None
                for value in (
                    self.network_id,
                    self.node_id,
                    self.plan_hash,
                    self.authorization_revision,
                    self.target_host_hash,
                    self.target_port,
                    self.route_identity_hash,
                    self.expires_at,
                )
            ):
                raise ValueError("direct path selection 必须绑定完整目标身份")
            assert self.network_id is not None
            assert self.node_id is not None
            assert self.plan_hash is not None
            assert self.authorization_revision is not None
            assert self.target_host_hash is not None
            assert self.target_port is not None
            assert self.route_identity_hash is not None
            assert self.expires_at is not None
            if self.authorization_revision != self.revision:
                raise ValueError(
                    "direct path selection authorization revision 必须精确绑定 revision"
                )
            if self.expires_at <= self.last_evidence_at:
                raise ValueError("direct path selection TTL 必须晚于最后证据时间")
        return self


class DirectPathController:
    """单并发、带 hysteresis 的 direct/static 控制器。"""

    def __init__(
        self,
        policy: PathControllerPolicy,
        *,
        initial: PathSelection,
        rollback_revision: Callable[[int, int], Awaitable[None]] | None = None,
    ) -> None:
        self._policy = policy
        self._selection = initial
        self._rollback_revision = rollback_revision
        self._lock = asyncio.Lock()

    @property
    def selection(self) -> PathSelection:
        return self._selection

    async def reconcile(
        self,
        evidence: DirectPathEvidence,
        *,
        fallback: NetworkPathType = NetworkPathType.STATIC,
    ) -> PathSelection:
        if fallback not in {NetworkPathType.STATIC, NetworkPathType.OFFLINE}:
            raise ValueError("direct 阶段只允许 static 或 offline 回退")
        async with self._lock:
            current = self._selection
            if (
                current.plan_hash is not None
                and current.revision == evidence.revision
                and (
                    current.network_id != evidence.network_id
                    or current.node_id != evidence.node_id
                    or current.plan_hash != evidence.plan_hash
                    or current.authorization_revision != evidence.authorization_revision
                    or current.provider is not evidence.provider
                )
            ):
                raise ValueError("path selection 与 evidence 的 network/node/plan 绑定冲突")
            if evidence.revision < current.revision:
                raise ValueError("路径 revision 不得倒退")
            dwell_elapsed = (
                evidence.observed_at - current.selected_at
            ).total_seconds() >= self._policy.minimum_dwell_seconds
            if evidence.verified:
                successes = current.consecutive_successes + 1
                failures = 0
                should_switch = (
                    current.path_type is not NetworkPathType.DIRECT
                    and successes >= self._policy.consecutive_success_threshold
                    and dwell_elapsed
                )
                path_type = NetworkPathType.DIRECT if should_switch else current.path_type
                last_good = (
                    evidence.revision
                    if path_type is NetworkPathType.DIRECT
                    else current.last_known_good_revision
                )
                selected_at = evidence.observed_at if should_switch else current.selected_at
                error = None if path_type is NetworkPathType.DIRECT else current.stable_error_code
                revision = (
                    evidence.revision if path_type is NetworkPathType.DIRECT else current.revision
                )
            else:
                successes = 0
                failures = current.consecutive_failures + 1
                should_switch = (
                    current.path_type is NetworkPathType.DIRECT
                    and failures >= self._policy.consecutive_failure_threshold
                    and dwell_elapsed
                )
                path_type = fallback if should_switch else current.path_type
                selected_at = evidence.observed_at if should_switch else current.selected_at
                last_good = current.last_known_good_revision
                revision = current.revision
                error = evidence.stable_error_code
                if (
                    should_switch
                    and evidence.revision > current.revision
                    and current.last_known_good_revision is not None
                    and self._rollback_revision is not None
                ):
                    await self._rollback_revision(
                        evidence.revision,
                        current.last_known_good_revision,
                    )
                    error = DirectPathErrorCode.REVISION_ROLLED_BACK
            keep_current_direct_binding = (
                current.path_type is NetworkPathType.DIRECT
                and not evidence.verified
                and not should_switch
            )
            binding = current if keep_current_direct_binding else None
            self._selection = PathSelection(
                network_id=binding.network_id if binding is not None else evidence.network_id,
                node_id=binding.node_id if binding is not None else evidence.node_id,
                plan_hash=binding.plan_hash if binding is not None else evidence.plan_hash,
                authorization_revision=(
                    binding.authorization_revision
                    if binding is not None
                    else evidence.authorization_revision
                ),
                path_type=path_type,
                provider=binding.provider if binding is not None else evidence.provider,
                revision=revision,
                last_known_good_revision=last_good,
                candidate_count=evidence.candidate_count,
                consecutive_failures=failures,
                consecutive_successes=successes,
                selected_at=selected_at,
                last_evidence_at=(
                    binding.last_evidence_at if binding is not None else evidence.observed_at
                ),
                stable_error_code=error,
                target_host_hash=(
                    binding.target_host_hash if binding is not None else evidence.target_host_hash
                ),
                target_port=binding.target_port if binding is not None else evidence.target_port,
                route_identity_hash=(
                    binding.route_identity_hash
                    if binding is not None
                    else evidence.route_identity_hash
                ),
                expires_at=binding.expires_at if binding is not None else evidence.expires_at,
            )
            return self._selection


class GatewayPathEndpoint(BaseModel):
    """供目录/Gateway 选择的已分类 endpoint。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    host: str
    port: int = Field(ge=1, le=65535)
    path_type: NetworkPathType
    revision: int = Field(ge=0)
    verified_at: datetime | None = None
    expires_at: datetime | None = None

    @model_validator(mode="after")
    def validate_endpoint(self) -> Self:
        address = ipaddress.ip_address(self.host)
        if address.is_unspecified or address.is_multicast:
            raise ValueError("Gateway 路径不能使用通配或组播地址")
        if self.path_type is NetworkPathType.DIRECT and (
            self.verified_at is None or self.expires_at is None
        ):
            raise ValueError("managed direct endpoint 必须包含验证新鲜度")
        return self


def select_gateway_endpoint(
    endpoints: tuple[GatewayPathEndpoint, ...],
    *,
    now: datetime,
) -> GatewayPathEndpoint | None:
    """优先 fresh direct，其次 relayed，最后 static；offline 不可选。"""
    current = DirectPathVerifier.aware(now)
    selectable = tuple(
        item
        for item in endpoints
        if item.path_type is not NetworkPathType.OFFLINE
        and (
            item.path_type is not NetworkPathType.DIRECT
            or (item.expires_at is not None and item.expires_at.astimezone(UTC) > current)
        )
    )
    priority = {
        NetworkPathType.DIRECT: 0,
        NetworkPathType.RELAYED: 1,
        NetworkPathType.STATIC: 2,
        NetworkPathType.OFFLINE: 3,
    }
    return min(
        selectable,
        key=lambda item: (
            priority[item.path_type],
            -item.revision,
            item.host,
            item.port,
        ),
        default=None,
    )
