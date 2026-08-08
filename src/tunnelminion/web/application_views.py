"""Windows/macOS 本机应用共享的强类型、脱敏视图装配。"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import UTC, datetime

from tunnelminion import __version__
from tunnelminion.agent.coordinator import (
    CoordinatorAuthorizationView,
    CoordinatorCache,
    CoordinatorSyncStatus,
    SyncPhase,
)
from tunnelminion.agent.managed_application import ManagedNodeApplication
from tunnelminion.agent.managed_node import ManagedNodeState
from tunnelminion.agent.network_sync import ManagedNetworkSyncPhase
from tunnelminion.coordinator import contracts as coordinator_contracts
from tunnelminion.domain.identifiers import NodeId
from tunnelminion.domain.tools import Platform
from tunnelminion.model.configuration import ModelConfigurationService
from tunnelminion.model.contracts import ProviderErrorCode
from tunnelminion.web import overview as overview_contracts
from tunnelminion.web.resources import CoordinatorResourceState, coordinator_resource_view

Clock = Callable[[], datetime]
_COORDINATOR_STATES = {
    CoordinatorResourceState.UNCONFIGURED: overview_contracts.CoordinatorOverviewState.UNCONFIGURED,
    CoordinatorResourceState.CONNECTING: overview_contracts.CoordinatorOverviewState.CONNECTING,
    CoordinatorResourceState.READY: overview_contracts.CoordinatorOverviewState.READY,
    CoordinatorResourceState.STALE: overview_contracts.CoordinatorOverviewState.STALE,
    CoordinatorResourceState.OFFLINE: overview_contracts.CoordinatorOverviewState.OFFLINE,
    CoordinatorResourceState.INCOMPATIBLE: overview_contracts.CoordinatorOverviewState.INCOMPATIBLE,
    CoordinatorResourceState.MANAGED_AUTH_EXPIRED: (
        overview_contracts.CoordinatorOverviewState.MANAGED_AUTH_EXPIRED
    ),
}
_NODE_STATES = {
    coordinator_contracts.NodeStatus.ONLINE: overview_contracts.KnownNodeState.ONLINE,
    coordinator_contracts.NodeStatus.STALE: overview_contracts.KnownNodeState.STALE,
    coordinator_contracts.NodeStatus.OFFLINE: overview_contracts.KnownNodeState.OFFLINE,
    coordinator_contracts.NodeStatus.REVOKED: overview_contracts.KnownNodeState.REVOKED,
    coordinator_contracts.NodeStatus.INCOMPATIBLE: overview_contracts.KnownNodeState.INCOMPATIBLE,
}
_FRESHNESS = {
    coordinator_contracts.DirectoryFreshness.FRESH: overview_contracts.OverviewFreshness.FRESH,
    coordinator_contracts.DirectoryFreshness.STALE: overview_contracts.OverviewFreshness.STALE,
    coordinator_contracts.DirectoryFreshness.OFFLINE: (
        overview_contracts.OverviewFreshness.UNAVAILABLE
    ),
    coordinator_contracts.DirectoryFreshness.REVOKED: (
        overview_contracts.OverviewFreshness.NOT_APPLICABLE
    ),
}


@dataclass(frozen=True)
class CoordinatorResourceBindings:
    """`create_resource_router` 可直接消费的 Coordinator 依赖。"""

    coordinator_status: Callable[[], CoordinatorSyncStatus] | None
    coordinator_cache: CoordinatorCache | None


@dataclass(frozen=True)
class ApplicationViewBindings:
    """应用工厂一次构造、两个资源路由分别消费的视图依赖。"""

    overview_service: overview_contracts.OverviewService
    resource_bindings: CoordinatorResourceBindings


def build_application_view_bindings(
    *,
    node_id: NodeId,
    platform: Platform,
    model_service: ModelConfigurationService,
    managed: ManagedNodeApplication,
    clock: Clock | None = None,
    runtime_package: overview_contracts.RuntimePackageOverview | None = None,
) -> ApplicationViewBindings:
    """把桌面应用已有状态转换为不含 endpoint、凭据和进程参数的 callback。"""
    adapter = _ApplicationViewAdapter(
        node_id,
        platform,
        model_service,
        managed,
        clock or (lambda: datetime.now(UTC)),
        runtime_package
        or overview_contracts.RuntimePackageOverview(
            kind=overview_contracts.RuntimePackageKind.SOURCE,
            version=__version__,
        ),
    )
    return ApplicationViewBindings(adapter.overview_service(), adapter.resource_bindings())


class _ApplicationViewAdapter:
    def __init__(
        self,
        node_id: NodeId,
        platform: Platform,
        model_service: ModelConfigurationService,
        managed: ManagedNodeApplication,
        clock: Clock,
        package: overview_contracts.RuntimePackageOverview,
    ) -> None:
        self.node_id = node_id
        self.platform = platform
        self.model_service = model_service
        self.managed = managed
        self.clock = clock
        self.package = package

    def overview_service(self) -> overview_contracts.OverviewService:
        return overview_contracts.OverviewService(
            local=self.local,
            model=self.model,
            coordinator=self.coordinator,
            network_path=self.network_path,
            nodes=self.nodes,
            services=self.services,
            clock=self.clock,
        )

    def local(self) -> overview_contracts.LocalRuntimeOverview:
        return overview_contracts.LocalRuntimeOverview(
            source=overview_contracts.OverviewSource.LOCAL_RUNTIME,
            evidence_at=self.now(),
            freshness=overview_contracts.OverviewFreshness.LIVE,
            runtime=overview_contracts.RuntimeState.RUNNING,
            platform=self.platform,
            version=__version__,
            package=self.package,
            readiness=overview_contracts.RuntimeReadiness.READY,
        )

    def model(self) -> overview_contracts.ModelOverview:
        now = self.now()
        try:
            view = self.model_service.view()
        except (OSError, ValueError):
            return overview_contracts.ModelOverview(
                source=overview_contracts.OverviewSource.MODEL_CONFIGURATION,
                evidence_at=now,
                freshness=overview_contracts.OverviewFreshness.UNAVAILABLE,
                error=overview_contracts.OverviewError(code="model_config_invalid"),
                configured=None,
                status=overview_contracts.ModelStatus.UNKNOWN,
            )
        status = overview_contracts.ModelStatus(view.status)
        error = view.error_code or ProviderErrorCode.INVALID_RESPONSE
        return overview_contracts.ModelOverview(
            source=overview_contracts.OverviewSource.MODEL_CONFIGURATION,
            evidence_at=now,
            freshness=(
                overview_contracts.OverviewFreshness.FRESH
                if status is overview_contracts.ModelStatus.AVAILABLE
                else overview_contracts.OverviewFreshness.NOT_APPLICABLE
                if status is overview_contracts.ModelStatus.UNCONFIGURED
                else overview_contracts.OverviewFreshness.UNAVAILABLE
            ),
            error=(
                overview_contracts.OverviewError(
                    code=error.value,
                    retryable=error
                    in {ProviderErrorCode.NETWORK_UNREACHABLE, ProviderErrorCode.TIMEOUT},
                )
                if status is overview_contracts.ModelStatus.UNAVAILABLE
                else None
            ),
            configured=status is not overview_contracts.ModelStatus.UNCONFIGURED,
            status=status,
        )

    def coordinator(self) -> overview_contracts.CoordinatorOverview:
        now = self.now()
        configured, explicit, error = self.managed_state()
        if explicit is not None:
            freshness = overview_contracts.OverviewFreshness.UNKNOWN
            if explicit is overview_contracts.CoordinatorOverviewState.UNCONFIGURED:
                freshness = overview_contracts.OverviewFreshness.NOT_APPLICABLE
            elif explicit in {
                overview_contracts.CoordinatorOverviewState.CONFIG_INVALID,
                overview_contracts.CoordinatorOverviewState.CREDENTIAL_MISSING,
            }:
                freshness = overview_contracts.OverviewFreshness.UNAVAILABLE
            return overview_contracts.CoordinatorOverview(
                source=overview_contracts.OverviewSource.COORDINATOR_SYNC,
                evidence_at=now,
                freshness=freshness,
                error=overview_contracts.OverviewError(code=error) if error else None,
                configured=configured,
                state=explicit,
            )
        coordinator = self.managed.coordinator
        if coordinator is None:  # pragma: no cover - managed_state 已处理
            raise RuntimeError("Coordinator 装配状态不一致")
        status = coordinator.directory.status
        cache = coordinator.coordinator_cache
        resource = coordinator_resource_view(status, cache, now=now)
        state = _COORDINATOR_STATES[resource.state]
        if (
            state is overview_contracts.CoordinatorOverviewState.CONNECTING
            and status.last_success_at is None
            and status.phase in {SyncPhase.IDLE, SyncPhase.STOPPED}
        ):
            state = overview_contracts.CoordinatorOverviewState.SYNC_NOT_STARTED
        fallback = {
            overview_contracts.CoordinatorOverviewState.SYNC_NOT_STARTED: (
                "coordinator_sync_not_started"
            ),
            overview_contracts.CoordinatorOverviewState.STALE: "coordinator_directory_stale",
            overview_contracts.CoordinatorOverviewState.OFFLINE: "coordinator_offline",
            overview_contracts.CoordinatorOverviewState.INCOMPATIBLE: "coordinator_incompatible",
            overview_contracts.CoordinatorOverviewState.MANAGED_AUTH_EXPIRED: (
                "coordinator_auth_expired"
            ),
        }.get(state)
        error_code = status.last_error_code or fallback
        cached = cache.read()
        return overview_contracts.CoordinatorOverview(
            source=(
                overview_contracts.OverviewSource.COORDINATOR_DIRECTORY
                if cached is not None
                else overview_contracts.OverviewSource.COORDINATOR_SYNC
            ),
            evidence_at=cached.generated_at if cached is not None else status.last_success_at,
            freshness=self.coordinator_freshness(state),
            error=(
                overview_contracts.OverviewError(
                    code=error_code,
                    retryable=state
                    in {
                        overview_contracts.CoordinatorOverviewState.CONNECTING,
                        overview_contracts.CoordinatorOverviewState.STALE,
                        overview_contracts.CoordinatorOverviewState.OFFLINE,
                    },
                )
                if error_code is not None
                else None
            ),
            configured=True,
            state=state,
            revision=resource.server_revision,
            last_success_at=status.last_success_at,
        )

    def network_path(self) -> overview_contracts.NetworkPathOverview:
        _, explicit, error = self.managed_state()
        if explicit is overview_contracts.CoordinatorOverviewState.UNCONFIGURED:
            return self.empty_path(
                False,
                overview_contracts.NetworkPathOverviewState.UNCONFIGURED,
                error,
            )
        if explicit is overview_contracts.CoordinatorOverviewState.CONFIG_INVALID:
            return self.empty_path(
                None,
                overview_contracts.NetworkPathOverviewState.UNKNOWN,
                error,
                True,
            )
        if explicit is overview_contracts.CoordinatorOverviewState.CREDENTIAL_MISSING:
            return self.empty_path(True, overview_contracts.NetworkPathOverviewState.PENDING, error)
        network = self.managed.network
        if network is None:
            return self.empty_path(
                True,
                overview_contracts.NetworkPathOverviewState.PENDING,
                "network_sync_not_started",
            )
        status = network.status
        checkpoint = network.synchronizer.checkpoint
        envelope = checkpoint.pending_config or checkpoint.last_known_good
        revision = status.pending_revision or status.applied_revision
        revision = max(revision, envelope.config.revision) if envelope is not None else revision
        pending = revision == 0 or status.phase in {
            ManagedNetworkSyncPhase.FETCHING,
            ManagedNetworkSyncPhase.PENDING,
        }
        error = status.last_error_code or (
            "network_sync_not_started"
            if status.last_success_at is None
            else "network_path_evidence_missing"
        )
        result = self.empty_path(
            True,
            overview_contracts.NetworkPathOverviewState.PENDING
            if pending
            else overview_contracts.NetworkPathOverviewState.UNKNOWN,
            error,
        )
        return result.model_copy(
            update={
                "source": overview_contracts.OverviewSource.COORDINATOR_SYNC,
                "evidence_at": status.last_success_at,
                "freshness": (
                    overview_contracts.OverviewFreshness.STALE
                    if status.control_plane_stale
                    or status.phase
                    in {ManagedNetworkSyncPhase.STALE, ManagedNetworkSyncPhase.BACKOFF}
                    else overview_contracts.OverviewFreshness.UNKNOWN
                ),
                "provider": envelope.config.provider if envelope is not None else None,
                "revision": revision,
            }
        )

    def nodes(self) -> overview_contracts.KnownNodesOverview:
        now = self.now()
        snapshot = self.local_service_snapshot()
        items = [
            overview_contracts.KnownNodeOverview(
                node_id=self.node_id,
                display_name=(
                    self.managed.config.display_name
                    if self.managed.config is not None
                    and self.managed.config.node_id == self.node_id
                    else "本机"
                ),
                platform=self.platform,
                state=overview_contracts.KnownNodeState.LOCAL,
                source=overview_contracts.OverviewSource.LOCAL_OBSERVATION,
                evidence_at=now,
                freshness=overview_contracts.OverviewFreshness.LIVE,
                service_count=len(snapshot.services) if snapshot is not None else 0,
            )
        ]
        cached = self.cache()
        if cached is not None:
            items.extend(
                overview_contracts.KnownNodeOverview(
                    node_id=item.identity.node_id,
                    display_name=item.identity.display_name,
                    platform=item.identity.platform,
                    state=_NODE_STATES[item.status],
                    source=overview_contracts.OverviewSource.COORDINATOR_DIRECTORY,
                    evidence_at=item.last_received_at,
                    freshness=_FRESHNESS[item.freshness],
                    service_count=item.service_count,
                )
                for item in cached.nodes
                if item.identity.node_id != self.node_id
            )
        return overview_contracts.KnownNodesOverview(
            source=(
                overview_contracts.OverviewSource.AGGREGATED
                if cached is not None
                else overview_contracts.OverviewSource.LOCAL_OBSERVATION
            ),
            evidence_at=now,
            freshness=self.worst(item.freshness for item in items),
            items=tuple(sorted(items, key=lambda item: str(item.node_id))),
        )

    def services(self) -> overview_contracts.KnownServicesOverview:
        items: list[overview_contracts.KnownServiceOverview] = []
        snapshot = self.local_service_snapshot()
        if snapshot is not None:
            items.extend(
                self.service_view(service, self.node_id, overview_contracts.KnownNodeState.LOCAL)
                for service in snapshot.services
            )
        cached = self.cache()
        if cached is not None:
            for node in cached.nodes:
                if node.identity.node_id != self.node_id:
                    items.extend(
                        self.service_view(service, node.identity.node_id, _NODE_STATES[node.status])
                        for service in node.services
                    )
        times = tuple(item.evidence_at for item in items if item.evidence_at is not None)
        return overview_contracts.KnownServicesOverview(
            source=(
                overview_contracts.OverviewSource.AGGREGATED
                if snapshot is not None and cached is not None
                else overview_contracts.OverviewSource.COORDINATOR_DIRECTORY
                if cached is not None
                else overview_contracts.OverviewSource.LOCAL_OBSERVATION
            ),
            evidence_at=max(times, default=None),
            freshness=self.worst(item.freshness for item in items),
            items=tuple(sorted(items, key=lambda item: (str(item.node_id), str(item.service_id)))),
        )

    def service_view(
        self,
        service: coordinator_contracts.ServiceSummary,
        node_id: NodeId,
        node_state: overview_contracts.KnownNodeState,
    ) -> overview_contracts.KnownServiceOverview:
        state = overview_contracts.KnownServiceState.UNKNOWN
        if service.lifecycle is coordinator_contracts.ServiceLifecycle.STOPPED:
            state = overview_contracts.KnownServiceState.STOPPED
        elif node_state in {
            overview_contracts.KnownNodeState.OFFLINE,
            overview_contracts.KnownNodeState.REVOKED,
        }:
            state = overview_contracts.KnownServiceState.UNAVAILABLE
        elif node_state is overview_contracts.KnownNodeState.STALE:
            state = overview_contracts.KnownServiceState.DEGRADED
        elif node_state in {
            overview_contracts.KnownNodeState.LOCAL,
            overview_contracts.KnownNodeState.ONLINE,
        }:
            state = overview_contracts.KnownServiceState.AVAILABLE
        return overview_contracts.KnownServiceOverview(
            service_id=service.service_id,
            node_id=node_id,
            protocol=service.protocol,
            port=service.port,
            accessibility=service.accessibility,
            lifecycle=service.lifecycle,
            state=state,
            source=(
                overview_contracts.OverviewSource.LOCAL_OBSERVATION
                if node_state is overview_contracts.KnownNodeState.LOCAL
                else overview_contracts.OverviewSource.COORDINATOR_DIRECTORY
            ),
            evidence_at=service.observed_at,
            freshness=(
                overview_contracts.OverviewFreshness.STALE
                if state is overview_contracts.KnownServiceState.DEGRADED
                else overview_contracts.OverviewFreshness.UNAVAILABLE
                if state is overview_contracts.KnownServiceState.UNAVAILABLE
                else overview_contracts.OverviewFreshness.FRESH
            ),
        )

    def empty_path(
        self,
        configured: bool | None,
        state: overview_contracts.NetworkPathOverviewState,
        error: str | None,
        unknown: bool = False,
    ) -> overview_contracts.NetworkPathOverview:
        evidence = overview_contracts.NetworkEvidenceOverview(
            status=(
                overview_contracts.EvidenceStatus.UNKNOWN
                if unknown
                else overview_contracts.EvidenceStatus.MISSING
            )
        )
        return overview_contracts.NetworkPathOverview(
            source=(
                overview_contracts.OverviewSource.COORDINATOR_SYNC
                if configured
                else overview_contracts.OverviewSource.LOCAL_OBSERVATION
            ),
            freshness=(
                overview_contracts.OverviewFreshness.NOT_APPLICABLE
                if configured is False
                else overview_contracts.OverviewFreshness.UNKNOWN
            ),
            error=(
                overview_contracts.OverviewError(
                    code=error,
                    retryable=error == "network_sync_not_started",
                )
                if error
                else None
            ),
            configured=configured,
            state=state,
            handshake=evidence,
            route=evidence,
            probe=evidence,
        )

    def resource_bindings(self) -> CoordinatorResourceBindings:
        coordinator = self.managed.coordinator
        if coordinator is not None:
            return CoordinatorResourceBindings(
                lambda: coordinator.directory.status,
                coordinator.coordinator_cache,
            )
        configured, _, error = self.managed_state()
        if configured is False and error is None:
            return CoordinatorResourceBindings(None, None)
        cache = CoordinatorCache()
        status = CoordinatorSyncStatus(
            phase=SyncPhase.STOPPED,
            last_error_code=error or "coordinator_sync_not_started",
        )
        return CoordinatorResourceBindings(lambda: status, cache)

    def managed_state(
        self,
    ) -> tuple[bool | None, overview_contracts.CoordinatorOverviewState | None, str | None]:
        enrollment = self.managed.enrollment
        error = enrollment.last_error_code
        if self.managed.config is None:
            return (
                (None, overview_contracts.CoordinatorOverviewState.CONFIG_INVALID, error)
                if error
                else (False, overview_contracts.CoordinatorOverviewState.UNCONFIGURED, None)
            )
        if error in {"managed_config_invalid", "identity_mismatch"} or not enrollment.configured:
            return (
                True,
                overview_contracts.CoordinatorOverviewState.CONFIG_INVALID,
                error or "managed_config_invalid",
            )
        if not self.managed.config.enabled or enrollment.state is ManagedNodeState.DISABLED:
            return (
                True,
                overview_contracts.CoordinatorOverviewState.UNCONFIGURED,
                "coordinator_disabled",
            )
        if not enrollment.credential_configured or error == "secret_store_unavailable":
            return (
                True,
                overview_contracts.CoordinatorOverviewState.CREDENTIAL_MISSING,
                error or "coordinator_credential_missing",
            )
        if self.managed.coordinator is None:
            return (
                True,
                overview_contracts.CoordinatorOverviewState.SYNC_NOT_STARTED,
                "coordinator_sync_not_started",
            )
        return True, None, None

    def cache(self) -> CoordinatorAuthorizationView | None:
        return (
            self.managed.coordinator.coordinator_cache.read()
            if self.managed.coordinator is not None
            else None
        )

    def local_service_snapshot(self):  # pyright: ignore[reportUnknownParameterType]
        return (
            self.managed.coordinator.service_cache.read()
            if self.managed.coordinator is not None
            else None
        )

    def now(self) -> datetime:
        value = self.clock()
        if value.tzinfo is None:
            raise ValueError("应用视图时钟必须包含时区")
        return value.astimezone(UTC)

    @staticmethod
    def coordinator_freshness(
        state: overview_contracts.CoordinatorOverviewState,
    ) -> overview_contracts.OverviewFreshness:
        if state is overview_contracts.CoordinatorOverviewState.READY:
            return overview_contracts.OverviewFreshness.FRESH
        if state is overview_contracts.CoordinatorOverviewState.STALE:
            return overview_contracts.OverviewFreshness.STALE
        if state is overview_contracts.CoordinatorOverviewState.MANAGED_AUTH_EXPIRED:
            return overview_contracts.OverviewFreshness.EXPIRED
        if state in {
            overview_contracts.CoordinatorOverviewState.OFFLINE,
            overview_contracts.CoordinatorOverviewState.INCOMPATIBLE,
        }:
            return overview_contracts.OverviewFreshness.UNAVAILABLE
        return overview_contracts.OverviewFreshness.UNKNOWN

    @staticmethod
    def worst(
        values: Iterable[overview_contracts.OverviewFreshness],
    ) -> overview_contracts.OverviewFreshness:
        rank = {
            overview_contracts.OverviewFreshness.LIVE: 0,
            overview_contracts.OverviewFreshness.FRESH: 1,
            overview_contracts.OverviewFreshness.NOT_APPLICABLE: 2,
            overview_contracts.OverviewFreshness.STALE: 3,
            overview_contracts.OverviewFreshness.EXPIRED: 4,
            overview_contracts.OverviewFreshness.UNAVAILABLE: 5,
            overview_contracts.OverviewFreshness.UNKNOWN: 6,
        }
        return max(
            tuple(values),
            key=rank.__getitem__,
            default=overview_contracts.OverviewFreshness.UNKNOWN,
        )
