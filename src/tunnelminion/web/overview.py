"""本机产品总览的强类型、脱敏聚合契约。"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from enum import StrEnum
from typing import Annotated, Literal, TypeVar

from fastapi import APIRouter
from pydantic import AwareDatetime, BaseModel, ConfigDict, Field

from tunnelminion.coordinator.contracts import (
    ServiceAccessibility,
    ServiceLifecycle,
    ServiceProtocol,
)
from tunnelminion.domain.identifiers import NodeId, ServiceId
from tunnelminion.domain.tools import Platform
from tunnelminion.network.contracts import ProviderKind

StableErrorCode = Annotated[
    str,
    Field(
        min_length=1,
        max_length=128,
        pattern=r"^[a-z][a-z0-9_-]*$",
    ),
]


class OverviewFreshness(StrEnum):
    """服务端已经判定的证据新鲜度。"""

    LIVE = "live"
    FRESH = "fresh"
    STALE = "stale"
    EXPIRED = "expired"
    UNAVAILABLE = "unavailable"
    NOT_APPLICABLE = "not_applicable"
    UNKNOWN = "unknown"


class OverviewSource(StrEnum):
    """总览允许公开的证据来源，不包含文件路径或 endpoint。"""

    LOCAL_RUNTIME = "local_runtime"
    MODEL_CONFIGURATION = "model_configuration"
    COORDINATOR_SYNC = "coordinator_sync"
    COORDINATOR_DIRECTORY = "coordinator_directory"
    NETWORK_PATH_EVIDENCE = "network_path_evidence"
    LOCAL_OBSERVATION = "local_observation"
    AGGREGATED = "aggregated"
    UNKNOWN = "unknown"


class OverviewError(BaseModel):
    """只返回稳定码和可重试性，不返回异常正文。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    code: StableErrorCode
    retryable: bool = False


class OverviewSection(BaseModel):
    """每个总览 section 共享的证据边界。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    source: OverviewSource
    evidence_at: AwareDatetime | None = None
    freshness: OverviewFreshness
    error: OverviewError | None = None


class RuntimeState(StrEnum):
    """本机进程状态，不代表 peer 或模型可用。"""

    RUNNING = "running"
    STARTING = "starting"
    STOPPING = "stopping"
    STOPPED = "stopped"
    DEGRADED = "degraded"
    UNKNOWN = "unknown"


class RuntimeReadiness(StrEnum):
    """本机 API 对确定性功能的 readiness。"""

    READY = "ready"
    DEGRADED = "degraded"
    UNAVAILABLE = "unavailable"
    UNKNOWN = "unknown"


class RuntimePackageKind(StrEnum):
    """运行来源；生产端不需要据此猜测平台。"""

    SOURCE = "source"
    WHEEL = "wheel"
    STANDALONE = "standalone"
    UNKNOWN = "unknown"


class RuntimePackageOverview(BaseModel):
    """不含安装路径、构建主机或签名材料的 package 摘要。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: Literal["tunnelminion"] = "tunnelminion"
    kind: RuntimePackageKind
    version: str | None = Field(default=None, min_length=1, max_length=64)
    manifest_schema: str | None = Field(
        default=None,
        min_length=3,
        max_length=128,
        pattern=r"^[a-z][a-z0-9-]*/v[1-9][0-9]*$",
    )


class LocalRuntimeOverview(OverviewSection):
    """本机 runtime、版本和交付形态。"""

    runtime: RuntimeState
    platform: Platform | None = None
    version: str | None = Field(default=None, min_length=1, max_length=64)
    package: RuntimePackageOverview
    readiness: RuntimeReadiness


class ModelStatus(StrEnum):
    """模型配置与可用性状态。"""

    UNCONFIGURED = "unconfigured"
    AVAILABLE = "available"
    UNAVAILABLE = "unavailable"
    UNKNOWN = "unknown"


class ModelOverview(OverviewSection):
    """模型状态；不返回 endpoint、model 名或密钥。"""

    configured: bool | None
    status: ModelStatus


class CoordinatorOverviewState(StrEnum):
    """区分未配置、装配故障、认证故障和目录事实。"""

    UNCONFIGURED = "unconfigured"
    CONFIG_INVALID = "config_invalid"
    CREDENTIAL_MISSING = "credential_missing"
    SYNC_NOT_STARTED = "sync_not_started"
    CONNECTING = "connecting"
    READY = "ready"
    STALE = "stale"
    OFFLINE = "offline"
    INCOMPATIBLE = "incompatible"
    MANAGED_AUTH_EXPIRED = "managed_auth_expired"
    UNKNOWN = "unknown"


class CoordinatorOverview(OverviewSection):
    """Coordinator 同步与目录状态，不含 refresh 凭据或验证 key。"""

    configured: bool | None
    state: CoordinatorOverviewState
    revision: int | None = Field(default=None, ge=0)
    last_success_at: AwareDatetime | None = None


class EvidenceStatus(StrEnum):
    """单项网络证据的已判定结果。"""

    PASSED = "passed"
    FAILED = "failed"
    MISSING = "missing"
    UNKNOWN = "unknown"


class NetworkEvidenceOverview(BaseModel):
    """不包含 endpoint、完整 route 或 peer 公钥的证据维度。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    status: EvidenceStatus
    observed_at: AwareDatetime | None = None


class NetworkPathOverviewState(StrEnum):
    """当前网络路径，不把本机进程状态当作 peer 可达。"""

    UNCONFIGURED = "unconfigured"
    PENDING = "pending"
    DIRECT = "direct"
    RELAYED = "relayed"
    STATIC = "static"
    OFFLINE = "offline"
    UNKNOWN = "unknown"


class NetworkPathOverview(OverviewSection):
    """handshake、host route 和目标探测三项独立证据。"""

    configured: bool | None
    state: NetworkPathOverviewState
    provider: ProviderKind | None = None
    revision: int | None = Field(default=None, ge=0)
    handshake: NetworkEvidenceOverview
    route: NetworkEvidenceOverview
    probe: NetworkEvidenceOverview


class KnownNodeState(StrEnum):
    """总览可展示的节点状态，包含未来枚举的安全回退。"""

    LOCAL = "local"
    ONLINE = "online"
    STALE = "stale"
    OFFLINE = "offline"
    REVOKED = "revoked"
    INCOMPATIBLE = "incompatible"
    UNKNOWN = "unknown"


class KnownNodeOverview(BaseModel):
    """不含 Gateway endpoint、认证断言或验证 key 的节点摘要。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    node_id: NodeId
    display_name: str = Field(min_length=1, max_length=80)
    platform: Platform | None = None
    state: KnownNodeState
    source: OverviewSource
    evidence_at: AwareDatetime | None = None
    freshness: OverviewFreshness
    service_count: int = Field(default=0, ge=0, le=1024)


class KnownNodesOverview(OverviewSection):
    """有界节点集合。"""

    items: tuple[KnownNodeOverview, ...] = Field(default=(), max_length=200)


class KnownServiceState(StrEnum):
    """服务可用性与 lifecycle 分开表达。"""

    AVAILABLE = "available"
    DEGRADED = "degraded"
    UNAVAILABLE = "unavailable"
    STOPPED = "stopped"
    UNKNOWN = "unknown"


class KnownServiceOverview(BaseModel):
    """服务摘要只公开访问地址，不公开进程参数、环境或探测正文。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    service_id: ServiceId
    node_id: NodeId
    display_name: str | None = Field(default=None, min_length=1, max_length=80)
    protocol: ServiceProtocol | None = None
    port: int | None = Field(default=None, ge=1, le=65535)
    access_address: str | None = Field(default=None, min_length=1, max_length=320)
    accessibility: ServiceAccessibility | None = None
    lifecycle: ServiceLifecycle | None = None
    state: KnownServiceState
    source: OverviewSource
    evidence_at: AwareDatetime | None = None
    freshness: OverviewFreshness


class KnownServicesOverview(OverviewSection):
    """有界服务集合。"""

    items: tuple[KnownServiceOverview, ...] = Field(default=(), max_length=1024)


class ResourceOverview(BaseModel):
    """React 总览唯一消费的服务端聚合契约。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["resource-overview/v1"] = "resource-overview/v1"
    generated_at: AwareDatetime
    local: LocalRuntimeOverview
    model: ModelOverview
    coordinator: CoordinatorOverview
    network_path: NetworkPathOverview
    nodes: KnownNodesOverview
    services: KnownServicesOverview


SectionT = TypeVar("SectionT", bound=OverviewSection)


class OverviewService:
    """逐 section 聚合 callback；一个 provider 失败不会抹掉其他事实。"""

    def __init__(
        self,
        *,
        local: Callable[[], LocalRuntimeOverview] | None = None,
        model: Callable[[], ModelOverview] | None = None,
        coordinator: Callable[[], CoordinatorOverview] | None = None,
        network_path: Callable[[], NetworkPathOverview] | None = None,
        nodes: Callable[[], KnownNodesOverview] | None = None,
        services: Callable[[], KnownServicesOverview] | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._local = local
        self._model = model
        self._coordinator = coordinator
        self._network_path = network_path
        self._nodes = nodes
        self._services = services
        self._clock = clock or (lambda: datetime.now(UTC))

    def view(self) -> ResourceOverview:
        """返回完整快照；异常正文不会进入响应。"""
        generated_at = self._clock()
        if generated_at.tzinfo is None:
            raise ValueError("总览时钟必须包含时区")
        return ResourceOverview(
            generated_at=generated_at.astimezone(UTC),
            local=self._resolve(
                self._local,
                LocalRuntimeOverview,
                self._local_fallback,
            ),
            model=self._resolve(
                self._model,
                ModelOverview,
                self._model_fallback,
            ),
            coordinator=self._resolve(
                self._coordinator,
                CoordinatorOverview,
                self._coordinator_fallback,
            ),
            network_path=self._resolve(
                self._network_path,
                NetworkPathOverview,
                self._network_path_fallback,
            ),
            nodes=self._resolve(
                self._nodes,
                KnownNodesOverview,
                self._nodes_fallback,
            ),
            services=self._resolve(
                self._services,
                KnownServicesOverview,
                self._services_fallback,
            ),
        )

    @staticmethod
    def _resolve(
        provider: Callable[[], SectionT] | None,
        expected: type[SectionT],
        fallback: Callable[[OverviewError], SectionT],
    ) -> SectionT:
        if provider is None:
            return fallback(OverviewError(code="overview_provider_missing", retryable=False))
        try:
            return expected.model_validate(provider())
        except Exception:
            return fallback(OverviewError(code="overview_provider_failed", retryable=True))

    @staticmethod
    def _local_fallback(error: OverviewError) -> LocalRuntimeOverview:
        return LocalRuntimeOverview(
            source=OverviewSource.UNKNOWN,
            freshness=OverviewFreshness.UNKNOWN,
            error=error,
            runtime=RuntimeState.UNKNOWN,
            package=RuntimePackageOverview(kind=RuntimePackageKind.UNKNOWN),
            readiness=RuntimeReadiness.UNKNOWN,
        )

    @staticmethod
    def _model_fallback(error: OverviewError) -> ModelOverview:
        return ModelOverview(
            source=OverviewSource.UNKNOWN,
            freshness=OverviewFreshness.UNKNOWN,
            error=error,
            configured=None,
            status=ModelStatus.UNKNOWN,
        )

    @staticmethod
    def _coordinator_fallback(error: OverviewError) -> CoordinatorOverview:
        return CoordinatorOverview(
            source=OverviewSource.UNKNOWN,
            freshness=OverviewFreshness.UNKNOWN,
            error=error,
            configured=None,
            state=CoordinatorOverviewState.UNKNOWN,
        )

    @staticmethod
    def _network_path_fallback(error: OverviewError) -> NetworkPathOverview:
        unknown = NetworkEvidenceOverview(status=EvidenceStatus.UNKNOWN)
        return NetworkPathOverview(
            source=OverviewSource.UNKNOWN,
            freshness=OverviewFreshness.UNKNOWN,
            error=error,
            configured=None,
            state=NetworkPathOverviewState.UNKNOWN,
            handshake=unknown,
            route=unknown,
            probe=unknown,
        )

    @staticmethod
    def _nodes_fallback(error: OverviewError) -> KnownNodesOverview:
        return KnownNodesOverview(
            source=OverviewSource.UNKNOWN,
            freshness=OverviewFreshness.UNKNOWN,
            error=error,
        )

    @staticmethod
    def _services_fallback(error: OverviewError) -> KnownServicesOverview:
        return KnownServicesOverview(
            source=OverviewSource.UNKNOWN,
            freshness=OverviewFreshness.UNKNOWN,
            error=error,
        )


def create_overview_router(service: OverviewService) -> APIRouter:
    """创建可由 Windows/macOS 应用工厂显式挂载的只读路由。"""
    router = APIRouter()

    def overview() -> ResourceOverview:
        return service.view()

    router.add_api_route(
        "/api/resources/overview",
        overview,
        methods=["GET"],
        response_model=ResourceOverview,
    )
    return router
