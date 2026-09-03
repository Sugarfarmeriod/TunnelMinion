"""Windows/macOS 本机应用共享的强类型、脱敏视图装配。"""

from __future__ import annotations

import json
import sys
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from ipaddress import IPv6Address, ip_address
from pathlib import Path
from typing import cast

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
from tunnelminion.agent.service_observation import ServiceObservationSnapshot
from tunnelminion.coordinator import contracts as coordinator_contracts
from tunnelminion.domain.identifiers import NodeId
from tunnelminion.domain.tools import Platform
from tunnelminion.model.configuration import ModelConfigurationService
from tunnelminion.model.contracts import ProviderErrorCode
from tunnelminion.network.path_controller import (
    DirectPathEvidence,
    PathSelection,
)
from tunnelminion.network.path_status import ManagedPathFreshness, ManagedPathStatus
from tunnelminion.runtime.profile import current_program_dir
from tunnelminion.web import overview as overview_contracts
from tunnelminion.web.resources import (
    CoordinatorResourceState,
    ManagedPathResourceView,
    coordinator_resource_view,
)

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
_PACKAGE_MANIFEST_FILE = "runtime-package-manifest.json"
_NETWORK_PATH_EVIDENCE_STALE_AFTER = timedelta(seconds=180)
_NETWORK_PATH_EVIDENCE_STALE = "network_path_evidence_stale"


@dataclass(frozen=True)
class CoordinatorResourceBindings:
    """`create_resource_router` 可直接消费的控制面与路径依赖。"""

    coordinator_status: Callable[[], CoordinatorSyncStatus] | None
    coordinator_cache: CoordinatorCache | None
    network_path: Callable[[], ManagedPathResourceView]


@dataclass(frozen=True)
class NetworkPathViewBindings:
    """真实路径选择、证据和本机授权的只读 callback。"""

    selection: Callable[[], PathSelection | None]
    evidence: Callable[[], DirectPathEvidence | None]
    authorization: Callable[[], str]


@dataclass(frozen=True)
class ApplicationViewBindings:
    """应用工厂一次构造、两个资源路由分别消费的视图依赖。"""

    overview_service: overview_contracts.OverviewService
    resource_bindings: CoordinatorResourceBindings


@dataclass(frozen=True)
class _PathSnapshot:
    """同一 revision 的路径事实及其当前时效。"""

    selection: PathSelection
    evidence: DirectPathEvidence | None
    freshness: overview_contracts.OverviewFreshness


def build_application_view_bindings(
    *,
    node_id: NodeId,
    platform: Platform,
    model_service: ModelConfigurationService,
    managed: ManagedNodeApplication,
    network_path: NetworkPathViewBindings | None = None,
    managed_path_status: Callable[[], ManagedPathStatus | None] | None = None,
    incidents: Callable[[], overview_contracts.IncidentsOverview] | None = None,
    local_services: Callable[[], ServiceObservationSnapshot | None] | None = None,
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
        runtime_package or detect_runtime_package(),
        network_path,
        managed_path_status,
        incidents,
        local_services,
    )
    return ApplicationViewBindings(adapter.overview_service(), adapter.resource_bindings())


def detect_runtime_package(
    program_dir: Path | None = None,
    *,
    frozen: bool | None = None,
) -> overview_contracts.RuntimePackageOverview:
    """从已安装清单判断交付形态；损坏清单只降级显示，不阻断本机页面。"""
    program = (program_dir or current_program_dir()).resolve()
    manifest_path = program / _PACKAGE_MANIFEST_FILE
    is_frozen = getattr(sys, "frozen", False) if frozen is None else frozen
    if manifest_path.is_file():
        try:
            raw = json.loads(manifest_path.read_text(encoding="utf-8"))
            if not isinstance(raw, dict):
                raise ValueError("运行包清单必须是对象")
            manifest = cast(dict[str, object], raw)
            candidate_value = manifest.get("candidate")
            if not isinstance(candidate_value, dict):
                raise ValueError("运行包清单缺少 candidate")
            candidate = cast(dict[str, object], candidate_value)
            schema = manifest.get("schema_version")
            version = candidate.get("application_version")
            if not isinstance(schema, str) or not isinstance(version, str):
                raise ValueError("运行包清单缺少版本摘要")
            return overview_contracts.RuntimePackageOverview(
                kind=overview_contracts.RuntimePackageKind.STANDALONE,
                version=version,
                manifest_schema=schema,
            )
        except (OSError, ValueError, json.JSONDecodeError):
            return overview_contracts.RuntimePackageOverview(
                kind=overview_contracts.RuntimePackageKind.UNKNOWN,
                version=__version__,
            )
    return overview_contracts.RuntimePackageOverview(
        kind=(
            overview_contracts.RuntimePackageKind.STANDALONE
            if is_frozen
            else overview_contracts.RuntimePackageKind.SOURCE
        ),
        version=__version__,
    )


class _ApplicationViewAdapter:
    def __init__(
        self,
        node_id: NodeId,
        platform: Platform,
        model_service: ModelConfigurationService,
        managed: ManagedNodeApplication,
        clock: Clock,
        package: overview_contracts.RuntimePackageOverview,
        network_path: NetworkPathViewBindings | None = None,
        managed_path_status: Callable[[], ManagedPathStatus | None] | None = None,
        incidents: Callable[[], overview_contracts.IncidentsOverview] | None = None,
        local_services: Callable[[], ServiceObservationSnapshot | None] | None = None,
    ) -> None:
        self.node_id = node_id
        self.platform = platform
        self.model_service = model_service
        self.managed = managed
        self.path_bindings = network_path
        self.managed_path_status_provider = managed_path_status
        self.incidents_provider = incidents
        self.local_services_provider = local_services
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
            incidents=self.incidents_provider,
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
        managed_path = self.current_managed_path_status()
        if managed_path is not None:
            return self.managed_path_overview(managed_path)
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
        path = self.path_snapshot()
        if path is not None:
            selection = path.selection
            evidence = path.evidence
            path_error = (
                evidence.stable_error_code.value
                if evidence is not None and evidence.stable_error_code is not None
                else _NETWORK_PATH_EVIDENCE_STALE
                if path.freshness is overview_contracts.OverviewFreshness.STALE
                else selection.stable_error_code.value
                if selection.stable_error_code is not None
                else None
            )
            return overview_contracts.NetworkPathOverview(
                source=overview_contracts.OverviewSource.NETWORK_PATH_EVIDENCE,
                evidence_at=(
                    evidence.observed_at if evidence is not None else selection.last_evidence_at
                ),
                freshness=path.freshness,
                error=(
                    overview_contracts.OverviewError(code=path_error)
                    if path_error is not None
                    else None
                ),
                configured=True,
                state=overview_contracts.NetworkPathOverviewState(selection.path_type.value),
                provider=selection.provider,
                revision=selection.revision,
                handshake=self.evidence_view(
                    evidence.handshake_fresh if evidence is not None else None,
                    evidence.last_handshake_at if evidence is not None else None,
                ),
                route=self.evidence_view(
                    evidence.host_route_present if evidence is not None else None,
                    evidence.observed_at if evidence is not None else None,
                ),
                probe=self.evidence_view(
                    evidence.target_probe_succeeded if evidence is not None else None,
                    (
                        evidence.target_probe_at or evidence.observed_at
                        if evidence is not None
                        else None
                    ),
                ),
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
        try:
            is_ipv6 = isinstance(ip_address(service.host), IPv6Address)
        except ValueError:
            is_ipv6 = False
        address_host = f"[{service.host}]" if is_ipv6 else service.host
        return overview_contracts.KnownServiceOverview(
            service_id=service.service_id,
            node_id=node_id,
            protocol=service.protocol,
            port=service.port,
            access_address=f"{service.protocol.value}://{address_host}:{service.port}",
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
                self.network_path_resource,
            )
        configured, _, error = self.managed_state()
        if configured is False and error is None:
            return CoordinatorResourceBindings(None, None, self.network_path_resource)
        cache = CoordinatorCache()
        status = CoordinatorSyncStatus(
            phase=SyncPhase.STOPPED,
            last_error_code=error or "coordinator_sync_not_started",
        )
        return CoordinatorResourceBindings(lambda: status, cache, self.network_path_resource)

    def network_path_resource(self) -> ManagedPathResourceView:
        """让 legacy 资源接口与 overview 消费同一份真实路径快照。"""
        path = self.path_snapshot()
        authorization = self.path_authorization()
        if path is not None:
            selection = path.selection
            evidence = path.evidence
            return ManagedPathResourceView(
                configured=True,
                provider=selection.provider,
                revision=selection.revision,
                authorization_state=authorization,
                path_type=selection.path_type,
                candidate_count=(
                    evidence.candidate_count if evidence is not None else selection.candidate_count
                ),
                handshake_fresh=evidence.handshake_fresh if evidence is not None else False,
                host_route_present=(evidence.host_route_present if evidence is not None else False),
                target_probe_succeeded=(
                    evidence.target_probe_succeeded if evidence is not None else False
                ),
                last_handshake_at=(evidence.last_handshake_at if evidence is not None else None),
                last_probe_at=evidence.target_probe_at if evidence is not None else None,
                stable_error_code=(
                    evidence.stable_error_code.value
                    if evidence is not None and evidence.stable_error_code is not None
                    else _NETWORK_PATH_EVIDENCE_STALE
                    if path.freshness is overview_contracts.OverviewFreshness.STALE
                    else selection.stable_error_code.value
                    if selection.stable_error_code is not None
                    else None
                ),
            )
        overview = self.network_path()
        return ManagedPathResourceView(
            configured=overview.configured is True,
            provider=overview.provider,
            revision=overview.revision or 0,
            authorization_state=authorization,
            stable_error_code=overview.error.code if overview.error is not None else None,
        )

    def path_snapshot(self) -> _PathSnapshot | None:
        """只组合同 provider/revision 的真实选择与证据，拒绝混合陈旧事实。"""
        if self.path_bindings is None:
            return None
        selection = self.path_bindings.selection()
        if selection is None:
            return None
        evidence = self.path_bindings.evidence()
        if evidence is not None and (
            evidence.provider is not selection.provider or evidence.revision != selection.revision
        ):
            evidence = None
        freshness = overview_contracts.OverviewFreshness.UNKNOWN
        if evidence is not None:
            observed_at = evidence.observed_at
            age = (
                self.now() - observed_at.astimezone(UTC) if observed_at.tzinfo is not None else None
            )
            freshness = (
                overview_contracts.OverviewFreshness.FRESH
                if age is not None and timedelta(0) <= age <= _NETWORK_PATH_EVIDENCE_STALE_AFTER
                else overview_contracts.OverviewFreshness.STALE
            )
        return _PathSnapshot(selection, evidence, freshness)

    def path_authorization(self) -> str:
        if self.path_bindings is not None:
            return self.path_bindings.authorization()
        _, explicit, _ = self.managed_state()
        if explicit is overview_contracts.CoordinatorOverviewState.UNCONFIGURED:
            return "unconfigured"
        if explicit is overview_contracts.CoordinatorOverviewState.CONFIG_INVALID:
            return "configuration-invalid"
        if explicit is overview_contracts.CoordinatorOverviewState.CREDENTIAL_MISSING:
            return "credential-missing"
        if explicit is overview_contracts.CoordinatorOverviewState.SYNC_NOT_STARTED:
            return "sync-not-started"
        return "unknown"

    def current_managed_path_status(self) -> ManagedPathStatus | None:
        """读取一次持久化状态并按当前时钟投影，不触发平台探测。"""
        if self.managed_path_status_provider is None:
            return None
        status = self.managed_path_status_provider()
        return (
            status.at(self.now(), stale_error_code=_NETWORK_PATH_EVIDENCE_STALE)
            if status is not None
            else None
        )

    def managed_path_overview(
        self,
        status: ManagedPathStatus,
    ) -> overview_contracts.NetworkPathOverview:
        """把受管路径状态投影为 Overview，不回退到较旧路径事实。"""
        evidence = status.evidence
        freshness = {
            ManagedPathFreshness.UNVERIFIED: overview_contracts.OverviewFreshness.UNKNOWN,
            ManagedPathFreshness.FRESH: overview_contracts.OverviewFreshness.FRESH,
            ManagedPathFreshness.STALE: overview_contracts.OverviewFreshness.STALE,
        }[status.freshness]
        return overview_contracts.NetworkPathOverview(
            source=overview_contracts.OverviewSource.NETWORK_PATH_EVIDENCE,
            evidence_at=status.observed_at,
            freshness=freshness,
            error=(
                overview_contracts.OverviewError(code=status.stable_error_code)
                if status.stable_error_code is not None
                else None
            ),
            configured=True,
            state=overview_contracts.NetworkPathOverviewState(status.path_type.value),
            provider=status.provider,
            revision=status.revision,
            handshake=self.evidence_view(
                evidence.handshake_fresh if evidence is not None else None,
                evidence.last_handshake_at if evidence is not None else None,
            ),
            route=self.evidence_view(
                evidence.host_route_present if evidence is not None else None,
                evidence.observed_at if evidence is not None else None,
            ),
            probe=self.evidence_view(
                evidence.target_probe_succeeded if evidence is not None else None,
                evidence.target_probe_at if evidence is not None else None,
            ),
        )

    @staticmethod
    def evidence_view(
        passed: bool | None,
        observed_at: datetime | None,
    ) -> overview_contracts.NetworkEvidenceOverview:
        return overview_contracts.NetworkEvidenceOverview(
            status=(
                overview_contracts.EvidenceStatus.MISSING
                if passed is None
                else overview_contracts.EvidenceStatus.PASSED
                if passed
                else overview_contracts.EvidenceStatus.FAILED
            ),
            observed_at=observed_at,
        )

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
        if self.local_services_provider is not None:
            return self.local_services_provider()
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
