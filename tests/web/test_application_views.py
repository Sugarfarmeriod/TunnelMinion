"""Windows/macOS 共用产品视图装配测试。"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import cast

import pytest
from tests.agent.test_coordinator import key_set
from tests.coordinator.test_directory import service_summary
from tests.coordinator.test_registry import NETWORK, NOW, identity

from tunnelminion.agent.coordinator import (
    CoordinatorAuthorizationView,
    CoordinatorCache,
    CoordinatorSyncStatus,
    SyncPhase,
)
from tunnelminion.agent.managed_application import ManagedNodeApplication
from tunnelminion.agent.managed_coordinator import (
    ManagedCoordinatorLoops,
    ServiceSnapshotCache,
)
from tunnelminion.agent.managed_network_runtime import ManagedNetworkSyncLoop
from tunnelminion.agent.managed_node import (
    ManagedNodeConfig,
    ManagedNodeState,
    ManagedNodeStatus,
)
from tunnelminion.agent.network_sync import (
    ManagedNetworkSyncCheckpoint,
    ManagedNetworkSyncPhase,
    ManagedNetworkSyncStatus,
)
from tunnelminion.agent.service_observation import ServiceObservationSnapshot
from tunnelminion.coordinator.contracts import (
    DirectoryFreshness,
    DirectoryNodeSummary,
    GatewayEndpoint,
    NodeStatus,
    ServiceLifecycle,
)
from tunnelminion.domain.identifiers import NetworkId, NodeId, ServiceId
from tunnelminion.domain.tools import Platform
from tunnelminion.model.configuration import (
    ModelConfigurationService,
    ModelConfigurationView,
)
from tunnelminion.model.contracts import ProviderErrorCode
from tunnelminion.network.contracts import (
    DesiredNetworkConfig,
    PeerConfiguration,
    ProviderKind,
    SignedDesiredConfig,
)
from tunnelminion.network.path_controller import (
    DirectPathErrorCode,
    DirectPathEvidence,
    NetworkPathType,
    PathSelection,
)
from tunnelminion.web import application_views as views
from tunnelminion.web.overview import (
    CoordinatorOverviewState,
    EvidenceStatus,
    KnownNodeState,
    KnownServiceState,
    ModelStatus,
    NetworkPathOverviewState,
    OverviewFreshness,
    OverviewSource,
    RuntimePackageKind,
    RuntimePackageOverview,
)

LOCAL_NODE = NodeId("node_0123456789abcdef0123456789abcdef")
REMOTE_NODE = identity().node_id


class FakeModelService:
    """只实现装配层读取的脱敏模型视图。"""

    def __init__(
        self,
        view: ModelConfigurationView | None = None,
        error: Exception | None = None,
    ) -> None:
        self.value = view or ModelConfigurationView(status="unconfigured")
        self.error = error

    def view(self) -> ModelConfigurationView:
        if self.error is not None:
            raise self.error
        return self.value


@dataclass
class FakeDirectoryLoop:
    status: CoordinatorSyncStatus


@dataclass
class FakeCoordinatorLoops:
    directory: FakeDirectoryLoop
    coordinator_cache: CoordinatorCache
    service_cache: ServiceSnapshotCache
    services: object = object()


@dataclass
class FakeSynchronizer:
    checkpoint: ManagedNetworkSyncCheckpoint


@dataclass
class FakeNetworkLoop:
    status: ManagedNetworkSyncStatus
    synchronizer: FakeSynchronizer


def config(*, enabled: bool = True, node_id: NodeId = LOCAL_NODE) -> ManagedNodeConfig:
    return ManagedNodeConfig(
        enabled=enabled,
        coordinator_endpoint="http://10.77.0.1:8790",
        network_id=NETWORK,
        node_id=node_id,
        display_name="本机 A",
        platform=Platform.WINDOWS,
        gateway_endpoint=GatewayEndpoint(host="10.77.0.2", port=8787),
        pinned_fingerprints=frozenset({"a" * 64}),
    )


def enrollment(
    value: ManagedNodeConfig | None,
    *,
    state: ManagedNodeState | None = None,
    credential: bool = True,
    configured: bool | None = None,
    error: str | None = None,
) -> ManagedNodeStatus:
    return ManagedNodeStatus(
        configured=(value is not None if configured is None else configured),
        enabled=value.enabled if value is not None else False,
        state=state
        or (
            ManagedNodeState.READY
            if value is not None
            else ManagedNodeState.UNAVAILABLE
            if error
            else ManagedNodeState.UNCONFIGURED
        ),
        schema_version=value.schema_version if value is not None else None,
        network_id=value.network_id if value is not None else None,
        node_id=value.node_id if value is not None else None,
        platform=value.platform if value is not None else None,
        credential_configured=credential,
        last_error_code=error,
    )


def managed(
    value: ManagedNodeConfig | None = None,
    *,
    status: ManagedNodeStatus | None = None,
    coordinator: FakeCoordinatorLoops | None = None,
    network: FakeNetworkLoop | None = None,
) -> ManagedNodeApplication:
    return ManagedNodeApplication(
        config=value,
        enrollment=status or enrollment(value),
        coordinator=cast(ManagedCoordinatorLoops | None, coordinator),
        network=cast(ManagedNetworkSyncLoop | None, network),
    )


def model_service(
    view: ModelConfigurationView | None = None,
    error: Exception | None = None,
) -> ModelConfigurationService:
    return cast(ModelConfigurationService, FakeModelService(view, error))


def bindings(
    application: ManagedNodeApplication,
    *,
    model: ModelConfigurationService | None = None,
    package: RuntimePackageOverview | None = None,
    network_path: views.NetworkPathViewBindings | None = None,
    clock: views.Clock | None = None,
    clock_none: bool = False,
) -> views.ApplicationViewBindings:
    arguments: dict[str, object] = {
        "node_id": LOCAL_NODE,
        "platform": Platform.WINDOWS,
        "model_service": model or model_service(),
        "managed": application,
    }
    if not clock_none:
        arguments["clock"] = clock or (lambda: NOW)
    if package is not None:
        arguments["runtime_package"] = package
    if network_path is not None:
        arguments["network_path"] = network_path
    return views.build_application_view_bindings(**arguments)  # pyright: ignore[reportArgumentType]


def directory_node(
    state: NodeStatus = NodeStatus.ONLINE,
    freshness: DirectoryFreshness = DirectoryFreshness.FRESH,
    *,
    node_id: NodeId = REMOTE_NODE,
    lifecycle: ServiceLifecycle = ServiceLifecycle.ACTIVE,
) -> DirectoryNodeSummary:
    remote_identity = identity().model_copy(
        update={"node_id": node_id, "display_name": f"节点 {state.value}"}
    )
    service = service_summary(ServiceId.new()).model_copy(update={"lifecycle": lifecycle})
    return DirectoryNodeSummary(
        identity=remote_identity,
        status=state,
        freshness=freshness,
        last_received_at=NOW,
        services=(service,),
        capability_count=0,
        service_count=1,
        server_revision=7,
    )


def coordinator_loops(
    status: CoordinatorSyncStatus,
    *,
    nodes: tuple[DirectoryNodeSummary, ...] | None = None,
    expires_at: datetime = NOW + timedelta(minutes=5),
    local_services: bool = False,
) -> FakeCoordinatorLoops:
    cache = CoordinatorCache()
    if nodes is not None:
        cache.replace(
            CoordinatorAuthorizationView(
                network_id=NETWORK,
                generated_at=NOW,
                expires_at=expires_at,
                nodes=nodes,
                verification_keys=key_set(),
            )
        )
    service_cache = ServiceSnapshotCache()
    if local_services:
        service_cache.replace(
            ServiceObservationSnapshot(
                observed_at=NOW,
                services=(service_summary(ServiceId.new()),),
            )
        )
    return FakeCoordinatorLoops(FakeDirectoryLoop(status), cache, service_cache)


def network_loop(
    *,
    phase: ManagedNetworkSyncPhase = ManagedNetworkSyncPhase.IDLE,
    applied: int = 0,
    pending: int | None = None,
    success: bool = False,
    error: str | None = None,
    stale: bool = False,
    envelope: SignedDesiredConfig | None = None,
) -> FakeNetworkLoop:
    checkpoint = ManagedNetworkSyncCheckpoint(
        network_id=NETWORK,
        node_id=LOCAL_NODE,
        phase=phase,
        applied_revision=applied,
        pending_config=envelope if pending is not None else None,
        last_known_good=envelope if pending is None and applied else None,
        updated_at=NOW,
    )
    status = ManagedNetworkSyncStatus(
        phase=phase,
        applied_revision=applied,
        pending_revision=pending,
        last_success_at=NOW if success else None,
        last_error_code=error,
        consecutive_failures=1 if error else 0,
        next_backoff_seconds=1 if error else 0,
        control_plane_stale=stale,
        full_sync_count=0,
    )
    return FakeNetworkLoop(status, FakeSynchronizer(checkpoint))


def signed_config(*, revision: int = 4, parent: int = 0) -> SignedDesiredConfig:
    remote = NodeId("node_fedcba9876543210fedcba9876543210")
    desired = DesiredNetworkConfig(
        network_id=NETWORK,
        target_node_id=LOCAL_NODE,
        provider=ProviderKind.WINDOWS,
        revision=revision,
        parent_revision=parent,
        interface_name="tmn-test",
        address="10.77.0.2/32",
        peers=(
            PeerConfiguration(
                node_id=remote,
                public_key="A" * 43 + "=",
                allowed_host_routes=("10.77.0.3/32",),
            ),
        ),
    )
    return SignedDesiredConfig(
        config=desired,
        key_id="test-key",
        key_fingerprint="sha256:" + "a" * 64,
        issued_at=NOW,
        expires_at=NOW + timedelta(minutes=10),
        signature="A" * 80,
    )


def path_selection(
    *,
    provider: ProviderKind = ProviderKind.WINDOWS,
    revision: int = 4,
    error: DirectPathErrorCode | None = None,
) -> PathSelection:
    return PathSelection(
        network_id=NetworkId("network_0123456789abcdef0123456789abcdef"),
        node_id=LOCAL_NODE,
        plan_hash="sha256:" + "a" * 64,
        authorization_revision=revision,
        path_type=NetworkPathType.DIRECT,
        provider=provider,
        revision=revision,
        last_known_good_revision=revision,
        candidate_count=1,
        consecutive_failures=0,
        consecutive_successes=2,
        selected_at=NOW,
        last_evidence_at=NOW,
        stable_error_code=error,
        target_host_hash="sha256:" + "c" * 64,
        target_port=8787,
        route_identity_hash="sha256:" + "d" * 64,
        expires_at=NOW + timedelta(seconds=180),
    )


def path_evidence(
    *,
    provider: ProviderKind = ProviderKind.WINDOWS,
    revision: int = 4,
    verified: bool = True,
    observed_at: datetime = NOW,
) -> DirectPathEvidence:
    return DirectPathEvidence(
        network_id=NetworkId("network_0123456789abcdef0123456789abcdef"),
        node_id=LOCAL_NODE,
        plan_hash="sha256:" + "a" * 64,
        authorization_revision=revision,
        provider=provider,
        revision=revision,
        target_host_hash="sha256:" + "c" * 64,
        target_port=8787,
        route_identity_hash="sha256:" + "d" * 64,
        candidate_count=1,
        selected_candidate_hash="sha256:" + "b" * 64,
        endpoint_probe_at=NOW,
        endpoint_probe_succeeded=True,
        last_handshake_at=NOW,
        handshake_fresh=verified,
        host_route_present=verified,
        target_probe_at=NOW,
        target_probe_succeeded=verified,
        verified=verified,
        stable_error_code=None if verified else DirectPathErrorCode.HANDSHAKE_STALE,
        observed_at=observed_at,
        expires_at=observed_at + timedelta(seconds=180),
    )


def test_unconfigured_defaults_are_local_only_and_resource_callbacks_are_absent() -> None:
    result = bindings(managed()).overview_service.view()
    resources = bindings(managed()).resource_bindings

    assert result.local.runtime.value == "running"
    assert result.local.package.kind is RuntimePackageKind.SOURCE
    assert result.model.status is ModelStatus.UNCONFIGURED
    assert result.coordinator.state is CoordinatorOverviewState.UNCONFIGURED
    assert result.network_path.state is NetworkPathOverviewState.UNCONFIGURED
    assert result.network_path.handshake.status is EvidenceStatus.MISSING
    assert result.nodes.items[0].display_name == "本机"
    assert result.services.items == ()
    assert result.services.freshness is OverviewFreshness.UNKNOWN
    assert resources.coordinator_status is None
    assert resources.coordinator_cache is None


def test_runtime_package_detection_uses_installed_manifest(tmp_path: Path) -> None:
    manifest = {
        "schema_version": "runtime-package-manifest/v2",
        "candidate": {"application_version": "1.2.3"},
    }
    (tmp_path / "runtime-package-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

    package = views.detect_runtime_package(tmp_path, frozen=True)

    assert package.kind is RuntimePackageKind.STANDALONE
    assert package.version == "1.2.3"
    assert package.manifest_schema == "runtime-package-manifest/v2"


@pytest.mark.parametrize("payload", ("[]", "{}", '{"candidate": {}}', "{"))
def test_runtime_package_detection_degrades_for_invalid_manifest(
    tmp_path: Path, payload: str
) -> None:
    (tmp_path / "runtime-package-manifest.json").write_text(payload, encoding="utf-8")

    package = views.detect_runtime_package(tmp_path, frozen=True)

    assert package.kind is RuntimePackageKind.UNKNOWN
    assert package.manifest_schema is None


def test_runtime_package_detection_distinguishes_raw_freeze_and_source(tmp_path: Path) -> None:
    assert views.detect_runtime_package(tmp_path, frozen=True).kind is RuntimePackageKind.STANDALONE
    assert views.detect_runtime_package(tmp_path, frozen=False).kind is RuntimePackageKind.SOURCE


@pytest.mark.parametrize(
    ("model_view", "expected", "freshness", "retryable"),
    (
        (ModelConfigurationView(status="available"), ModelStatus.AVAILABLE, "fresh", False),
        (
            ModelConfigurationView(
                status="unavailable",
                error_code=ProviderErrorCode.NETWORK_UNREACHABLE,
            ),
            ModelStatus.UNAVAILABLE,
            "unavailable",
            True,
        ),
        (
            ModelConfigurationView(status="unavailable"),
            ModelStatus.UNAVAILABLE,
            "unavailable",
            False,
        ),
    ),
)
def test_model_states(
    model_view: ModelConfigurationView,
    expected: ModelStatus,
    freshness: str,
    retryable: bool,
) -> None:
    result = bindings(managed(), model=model_service(model_view)).overview_service.view().model

    assert result.status is expected
    assert result.freshness.value == freshness
    if result.error is not None:
        assert result.error.retryable is retryable


@pytest.mark.parametrize("error", (OSError("path"), ValueError("broken")))
def test_model_configuration_errors_are_redacted(error: Exception) -> None:
    result = bindings(managed(), model=model_service(error=error)).overview_service.view().model

    assert result.status is ModelStatus.UNKNOWN
    assert result.configured is None
    assert result.error is not None and result.error.code == "model_config_invalid"
    assert "broken" not in result.model_dump_json()


@pytest.mark.parametrize(
    ("application", "state", "configured", "path_status"),
    (
        (
            managed(status=enrollment(None, error="managed_config_invalid")),
            CoordinatorOverviewState.CONFIG_INVALID,
            None,
            EvidenceStatus.UNKNOWN,
        ),
        (
            managed(
                config(enabled=False),
                status=enrollment(config(enabled=False), state=ManagedNodeState.DISABLED),
            ),
            CoordinatorOverviewState.UNCONFIGURED,
            True,
            EvidenceStatus.MISSING,
        ),
        (
            managed(config(), status=enrollment(config(), credential=False)),
            CoordinatorOverviewState.CREDENTIAL_MISSING,
            True,
            EvidenceStatus.MISSING,
        ),
        (
            managed(config()),
            CoordinatorOverviewState.SYNC_NOT_STARTED,
            True,
            EvidenceStatus.MISSING,
        ),
    ),
)
def test_managed_setup_states_remain_distinct(
    application: ManagedNodeApplication,
    state: CoordinatorOverviewState,
    configured: bool | None,
    path_status: EvidenceStatus,
) -> None:
    result = bindings(application)
    overview = result.overview_service.view()

    assert overview.coordinator.state is state
    assert overview.coordinator.configured is configured
    assert overview.network_path.handshake.status is path_status
    assert overview.network_path.route.status is path_status
    assert overview.network_path.probe.status is path_status
    assert result.resource_bindings.coordinator_status is not None
    assert result.resource_bindings.coordinator_cache is not None


@pytest.mark.parametrize(
    ("application", "configured", "authorization", "error"),
    (
        (managed(), False, "unconfigured", None),
        (
            managed(status=enrollment(None, error="managed_config_invalid")),
            False,
            "configuration-invalid",
            "managed_config_invalid",
        ),
        (
            managed(config(), status=enrollment(config(), credential=False)),
            True,
            "credential-missing",
            "coordinator_credential_missing",
        ),
        (
            managed(config()),
            True,
            "sync-not-started",
            "network_sync_not_started",
        ),
    ),
)
def test_network_resource_binding_preserves_managed_setup_state(
    application: ManagedNodeApplication,
    configured: bool,
    authorization: str,
    error: str | None,
) -> None:
    resource = bindings(application).resource_bindings.network_path()

    assert resource.configured is configured
    assert resource.authorization_state == authorization
    assert resource.stable_error_code == error


def test_real_path_selection_evidence_and_authorization_feed_both_views() -> None:
    selection = path_selection()
    evidence = path_evidence()
    path = views.NetworkPathViewBindings(
        selection=lambda: selection,
        evidence=lambda: evidence,
        authorization=lambda: "authorized-l3",
    )
    result = bindings(managed(config()), network_path=path)

    overview = result.overview_service.view().network_path
    resource = result.resource_bindings.network_path()
    assert overview.state is NetworkPathOverviewState.DIRECT
    assert overview.source is OverviewSource.NETWORK_PATH_EVIDENCE
    assert overview.freshness is OverviewFreshness.FRESH
    assert overview.handshake.status is EvidenceStatus.PASSED
    assert overview.route.status is EvidenceStatus.PASSED
    assert overview.probe.status is EvidenceStatus.PASSED
    assert resource.configured is True
    assert resource.authorization_state == "authorized-l3"
    assert resource.path_type is NetworkPathType.DIRECT
    assert resource.handshake_fresh is True
    assert resource.host_route_present is True
    assert resource.target_probe_succeeded is True


def test_path_binding_does_not_mix_mismatched_or_missing_evidence() -> None:
    selection = path_selection(error=DirectPathErrorCode.TARGET_UNREACHABLE)
    mismatched = path_evidence(revision=5)
    path = views.NetworkPathViewBindings(
        selection=lambda: selection,
        evidence=lambda: mismatched,
        authorization=lambda: "awaiting-authorization",
    )
    result = bindings(managed(config()), network_path=path)

    overview = result.overview_service.view().network_path
    resource = result.resource_bindings.network_path()
    assert overview.freshness is OverviewFreshness.UNKNOWN
    assert overview.handshake.status is EvidenceStatus.MISSING
    assert overview.error is not None
    assert overview.error.code == "target_unreachable"
    assert resource.candidate_count == 1
    assert resource.last_handshake_at is None
    assert resource.stable_error_code == "target_unreachable"


def test_path_evidence_expires_and_refreshes_without_losing_history() -> None:
    current = NOW
    evidence = path_evidence(observed_at=NOW - timedelta(seconds=181))
    path = views.NetworkPathViewBindings(
        selection=path_selection,
        evidence=lambda: evidence,
        authorization=lambda: "authorized-l3",
    )

    stale = bindings(
        managed(config()),
        network_path=path,
        clock=lambda: current,
    )
    stale_overview = stale.overview_service.view().network_path
    stale_resource = stale.resource_bindings.network_path()
    assert stale_overview.freshness is OverviewFreshness.STALE
    assert stale_overview.evidence_at == evidence.observed_at
    assert stale_overview.handshake.status is EvidenceStatus.PASSED
    assert stale_overview.error is not None
    assert stale_overview.error.code == "network_path_evidence_stale"
    assert stale_resource.last_handshake_at == NOW
    assert stale_resource.stable_error_code == "network_path_evidence_stale"

    evidence = path_evidence(observed_at=current)
    refreshed = (
        bindings(
            managed(config()),
            network_path=path,
            clock=lambda: current,
        )
        .overview_service.view()
        .network_path
    )
    assert refreshed.freshness is OverviewFreshness.FRESH
    assert refreshed.error is None


def test_empty_path_selection_falls_back_to_managed_sync_state() -> None:
    path = views.NetworkPathViewBindings(
        selection=lambda: None,
        evidence=lambda: path_evidence(),
        authorization=lambda: "awaiting-authorization",
    )
    result = bindings(managed(config()), network_path=path)

    overview = result.overview_service.view().network_path
    resource = result.resource_bindings.network_path()
    assert overview.state is NetworkPathOverviewState.PENDING
    assert overview.error is not None
    assert overview.error.code == "network_sync_not_started"
    assert resource.authorization_state == "awaiting-authorization"


def test_failed_real_path_evidence_remains_explicit() -> None:
    selection = path_selection()
    evidence = path_evidence(verified=False)
    path = views.NetworkPathViewBindings(
        selection=lambda: selection,
        evidence=lambda: evidence,
        authorization=lambda: "authorized-l3",
    )
    overview = bindings(managed(config()), network_path=path).overview_service.view().network_path

    assert overview.handshake.status is EvidenceStatus.FAILED
    assert overview.route.status is EvidenceStatus.FAILED
    assert overview.probe.status is EvidenceStatus.FAILED
    assert overview.error is not None
    assert overview.error.code == "handshake_stale"


def test_additional_config_and_credential_failure_branches() -> None:
    invalid = config(node_id=REMOTE_NODE)
    cases = (
        managed(invalid, status=enrollment(invalid, configured=False)),
        managed(invalid, status=enrollment(invalid, error="identity_mismatch")),
        managed(config(), status=enrollment(config(), error="secret_store_unavailable")),
    )

    states = tuple(bindings(item).overview_service.view().coordinator.state for item in cases)
    assert states == (
        CoordinatorOverviewState.CONFIG_INVALID,
        CoordinatorOverviewState.CONFIG_INVALID,
        CoordinatorOverviewState.CREDENTIAL_MISSING,
    )


@pytest.mark.parametrize(
    ("status", "nodes", "expires_at", "expected", "freshness"),
    (
        (
            CoordinatorSyncStatus(phase=SyncPhase.IDLE),
            None,
            NOW + timedelta(minutes=5),
            CoordinatorOverviewState.SYNC_NOT_STARTED,
            OverviewFreshness.UNKNOWN,
        ),
        (
            CoordinatorSyncStatus(phase=SyncPhase.SYNCING),
            None,
            NOW + timedelta(minutes=5),
            CoordinatorOverviewState.CONNECTING,
            OverviewFreshness.UNKNOWN,
        ),
        (
            CoordinatorSyncStatus(phase=SyncPhase.IDLE, last_success_at=NOW, server_revision=7),
            (directory_node(),),
            NOW + timedelta(minutes=5),
            CoordinatorOverviewState.READY,
            OverviewFreshness.FRESH,
        ),
        (
            CoordinatorSyncStatus(phase=SyncPhase.BACKOFF, last_error_code="offline"),
            (directory_node(NodeStatus.STALE, DirectoryFreshness.STALE),),
            NOW + timedelta(minutes=5),
            CoordinatorOverviewState.STALE,
            OverviewFreshness.STALE,
        ),
        (
            CoordinatorSyncStatus(phase=SyncPhase.IDLE),
            (directory_node(NodeStatus.OFFLINE, DirectoryFreshness.OFFLINE),),
            NOW + timedelta(minutes=5),
            CoordinatorOverviewState.OFFLINE,
            OverviewFreshness.UNAVAILABLE,
        ),
        (
            CoordinatorSyncStatus(phase=SyncPhase.IDLE),
            (directory_node(NodeStatus.INCOMPATIBLE, DirectoryFreshness.OFFLINE),),
            NOW + timedelta(minutes=5),
            CoordinatorOverviewState.INCOMPATIBLE,
            OverviewFreshness.UNAVAILABLE,
        ),
        (
            CoordinatorSyncStatus(phase=SyncPhase.IDLE),
            (directory_node(),),
            NOW,
            CoordinatorOverviewState.MANAGED_AUTH_EXPIRED,
            OverviewFreshness.EXPIRED,
        ),
    ),
)
def test_coordinator_state_matrix(
    status: CoordinatorSyncStatus,
    nodes: tuple[DirectoryNodeSummary, ...] | None,
    expires_at: datetime,
    expected: CoordinatorOverviewState,
    freshness: OverviewFreshness,
) -> None:
    loops = coordinator_loops(status, nodes=nodes, expires_at=expires_at)
    result = bindings(managed(config(), coordinator=loops)).overview_service.view().coordinator

    assert result.state is expected
    assert result.freshness is freshness
    assert result.configured is True


def test_stale_coordinator_cache_recovers_through_live_factory_bindings() -> None:
    coordinator = coordinator_loops(
        CoordinatorSyncStatus(
            phase=SyncPhase.BACKOFF,
            last_success_at=NOW - timedelta(minutes=5),
            last_error_code="offline",
            server_revision=6,
        ),
        nodes=(directory_node(NodeStatus.STALE, DirectoryFreshness.STALE),),
    )
    result = bindings(managed(config(), coordinator=coordinator))
    assert result.overview_service.view().coordinator.state is CoordinatorOverviewState.STALE

    coordinator.directory.status = CoordinatorSyncStatus(
        phase=SyncPhase.IDLE,
        last_success_at=NOW,
        server_revision=7,
    )
    coordinator.coordinator_cache.replace(
        CoordinatorAuthorizationView(
            network_id=NETWORK,
            generated_at=NOW,
            expires_at=NOW + timedelta(minutes=5),
            nodes=(directory_node(),),
            verification_keys=key_set(),
        )
    )

    recovered = result.overview_service.view().coordinator
    callback = result.resource_bindings.coordinator_status
    assert recovered.state is CoordinatorOverviewState.READY
    assert recovered.freshness is OverviewFreshness.FRESH
    assert recovered.last_success_at == NOW
    assert callback is not None and callback().server_revision == 7


def test_real_caches_are_redacted_and_resource_bindings_remain_live() -> None:
    remote_nodes = (
        directory_node(node_id=LOCAL_NODE),
        directory_node(NodeStatus.ONLINE, DirectoryFreshness.FRESH),
        directory_node(
            NodeStatus.REVOKED,
            DirectoryFreshness.REVOKED,
            node_id=NodeId("node_11111111111111111111111111111111"),
        ),
        directory_node(
            NodeStatus.STALE,
            DirectoryFreshness.STALE,
            node_id=NodeId("node_22222222222222222222222222222222"),
            lifecycle=ServiceLifecycle.STOPPED,
        ),
    )
    coordinator = coordinator_loops(
        CoordinatorSyncStatus(phase=SyncPhase.IDLE, last_success_at=NOW, server_revision=7),
        nodes=remote_nodes,
        local_services=True,
    )
    result = bindings(managed(config(), coordinator=coordinator))
    overview = result.overview_service.view()

    assert {item.state for item in overview.nodes.items} >= {
        KnownNodeState.LOCAL,
        KnownNodeState.ONLINE,
        KnownNodeState.REVOKED,
        KnownNodeState.STALE,
    }
    assert {item.state for item in overview.services.items} >= {
        KnownServiceState.AVAILABLE,
        KnownServiceState.UNAVAILABLE,
        KnownServiceState.STOPPED,
    }
    assert overview.nodes.source is OverviewSource.AGGREGATED
    assert overview.services.source is OverviewSource.AGGREGATED
    callback = result.resource_bindings.coordinator_status
    assert callback is not None and callback().server_revision == 7
    assert result.resource_bindings.coordinator_cache is coordinator.coordinator_cache
    assert result.resource_bindings.network_path().authorization_state == "unknown"
    serialized = overview.model_dump_json().lower()
    for forbidden in (
        "coordinator_endpoint",
        "gateway_endpoint",
        "10.77.0.1",
        "10.77.0.2",
        "private_key",
        "refresh_credential",
        "process_args",
    ):
        assert forbidden not in serialized


def test_service_sources_empty_cache_and_unknown_node_state() -> None:
    cached_only = coordinator_loops(
        CoordinatorSyncStatus(phase=SyncPhase.IDLE, last_success_at=NOW),
        nodes=(),
    )
    cached_view = bindings(managed(config(), coordinator=cached_only)).overview_service.view()
    assert cached_view.services.source is OverviewSource.COORDINATOR_DIRECTORY
    assert cached_view.services.items == ()

    local_only = coordinator_loops(
        CoordinatorSyncStatus(phase=SyncPhase.IDLE),
        local_services=True,
    )
    local_only.coordinator_cache = CoordinatorCache()
    local_view = bindings(managed(config(), coordinator=local_only)).overview_service.view()
    assert local_view.services.source is OverviewSource.LOCAL_OBSERVATION

    adapter = views._ApplicationViewAdapter(  # pyright: ignore[reportPrivateUsage]
        LOCAL_NODE,
        Platform.WINDOWS,
        model_service(),
        managed(),
        lambda: NOW,
        RuntimePackageOverview(kind=RuntimePackageKind.SOURCE),
    )
    unknown = adapter.service_view(
        service_summary(ServiceId.new()),
        REMOTE_NODE,
        KnownNodeState.INCOMPATIBLE,
    )
    assert unknown.state is KnownServiceState.UNKNOWN


@pytest.mark.parametrize(
    ("network", "state", "freshness", "provider", "revision"),
    (
        (
            network_loop(),
            NetworkPathOverviewState.PENDING,
            OverviewFreshness.UNKNOWN,
            None,
            0,
        ),
        (
            network_loop(
                phase=ManagedNetworkSyncPhase.FETCHING,
                pending=4,
                envelope=signed_config(),
            ),
            NetworkPathOverviewState.PENDING,
            OverviewFreshness.UNKNOWN,
            ProviderKind.WINDOWS,
            4,
        ),
        (
            network_loop(
                applied=4,
                success=True,
                envelope=signed_config(),
            ),
            NetworkPathOverviewState.UNKNOWN,
            OverviewFreshness.UNKNOWN,
            ProviderKind.WINDOWS,
            4,
        ),
        (
            network_loop(
                phase=ManagedNetworkSyncPhase.BACKOFF,
                error="offline",
            ),
            NetworkPathOverviewState.PENDING,
            OverviewFreshness.STALE,
            None,
            0,
        ),
        (
            network_loop(stale=True),
            NetworkPathOverviewState.PENDING,
            OverviewFreshness.STALE,
            None,
            0,
        ),
    ),
)
def test_network_sync_never_fabricates_path_evidence(
    network: FakeNetworkLoop,
    state: NetworkPathOverviewState,
    freshness: OverviewFreshness,
    provider: ProviderKind | None,
    revision: int,
) -> None:
    loops = coordinator_loops(CoordinatorSyncStatus(phase=SyncPhase.IDLE))
    result = bindings(managed(config(), coordinator=loops, network=network)).overview_service.view()

    assert result.network_path.state is state
    assert result.network_path.freshness is freshness
    assert result.network_path.provider is provider
    assert result.network_path.revision == revision
    assert result.network_path.handshake.status is EvidenceStatus.MISSING
    assert result.network_path.route.status is EvidenceStatus.MISSING
    assert result.network_path.probe.status is EvidenceStatus.MISSING


def test_explicit_package_default_clock_and_naive_clock() -> None:
    package = RuntimePackageOverview(kind=RuntimePackageKind.STANDALONE, version="1.2.3")
    actual = bindings(managed(), package=package, clock_none=True).overview_service.view()
    assert actual.local.package is package

    adapter = views._ApplicationViewAdapter(  # pyright: ignore[reportPrivateUsage]
        LOCAL_NODE,
        Platform.WINDOWS,
        model_service(),
        managed(),
        lambda: NOW.replace(tzinfo=None),
        package,
    )
    with pytest.raises(ValueError, match="时区"):
        adapter.now()


def test_helper_branch_tables_cover_all_freshness_values() -> None:
    adapter = views._ApplicationViewAdapter(  # pyright: ignore[reportPrivateUsage]
        LOCAL_NODE,
        Platform.WINDOWS,
        model_service(),
        managed(),
        lambda: NOW,
        RuntimePackageOverview(kind=RuntimePackageKind.SOURCE),
    )
    assert (
        adapter.coordinator_freshness(CoordinatorOverviewState.CONNECTING)
        is OverviewFreshness.UNKNOWN
    )
    assert adapter.worst(()) is OverviewFreshness.UNKNOWN
    assert adapter.worst(tuple(OverviewFreshness)) is OverviewFreshness.UNKNOWN
