"""Coordinator 能力/服务快照收敛、目录过滤与分页测试。"""

from __future__ import annotations

import base64
import json
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from pathlib import Path

import pytest
from tests.coordinator.test_registry import (
    NETWORK,
    NOW,
    OTHER_NETWORK,
    MutableClock,
    authentication,
    enrollment,
    heartbeat_for,
    identity,
    registration,
    service,
)

from tunnelminion.coordinator.contracts import (
    CapabilityAvailability,
    CapabilitySnapshot,
    CapabilitySummary,
    CoordinatorAuditAction,
    CoordinatorErrorCode,
    DirectoryFreshness,
    DirectoryQuery,
    NodeStatus,
    RefreshAuthentication,
    ServiceAccessibility,
    ServiceLifecycle,
    ServiceProtocol,
    ServiceSnapshot,
    ServiceSummary,
)
from tunnelminion.coordinator.directory import (
    CoordinatorDirectoryService,
    DirectoryPolicy,
)
from tunnelminion.coordinator.registry import (
    CoordinatorRegistryService,
    RegistryError,
)
from tunnelminion.domain.identifiers import NodeId, ServiceId, SnapshotId
from tunnelminion.domain.tools import Platform, RiskLevel
from tunnelminion.domain.versioning import ProtocolVersion


def directory_stack(
    tmp_path: Path,
) -> tuple[
    MutableClock,
    CoordinatorRegistryService,
    CoordinatorDirectoryService,
    RefreshAuthentication,
]:
    clock = MutableClock()
    registry = service(tmp_path, clock)
    registry.create_network(NETWORK)
    token, _ = enrollment(registry)
    registered = registry.register(registration(token))
    auth = authentication(registered)
    registry.heartbeat(auth, heartbeat_for(auth))
    directory = CoordinatorDirectoryService(
        registry.store,
        registry,
        clock=clock.utcnow,
    )
    return clock, registry, directory, auth


def capability(
    *,
    name: str = "get_node_summary",
    minor: int = 0,
    platform: Platform = Platform.MACOS,
) -> CapabilitySummary:
    return CapabilitySummary(
        name=name,
        version=ProtocolVersion(major=1, minor=minor),
        platform=platform,
        risk_level=RiskLevel.READ_ONLY,
        availability=CapabilityAvailability.AVAILABLE,
        schema_hash="a" * 64,
    )


def capability_snapshot(
    auth: RefreshAuthentication,
    *,
    sequence: int = 1,
    key_character: str = "a",
    capabilities: tuple[CapabilitySummary, ...] | None = None,
    protocol: ProtocolVersion | None = None,
) -> CapabilitySnapshot:
    return CapabilitySnapshot(
        protocol=protocol or ProtocolVersion(major=1, minor=0),
        network_id=auth.network_id,
        node_id=auth.node_id,
        snapshot_id=SnapshotId.new(),
        sequence=sequence,
        idempotency_key=f"snapkey_{key_character * 64}",
        generated_at=NOW,
        capabilities=capabilities or (capability(),),
    )


def service_summary(
    service_id: ServiceId,
    *,
    port: int = 8082,
    protocol: ServiceProtocol = ServiceProtocol.HTTP,
    accessibility: ServiceAccessibility = ServiceAccessibility.LOOPBACK,
) -> ServiceSummary:
    return ServiceSummary(
        service_id=service_id,
        protocol=protocol,
        host="127.0.0.1",
        port=port,
        accessibility=accessibility,
        source="list_network_listeners",
        confidence=1,
        observed_at=NOW,
    )


def service_snapshot(
    auth: RefreshAuthentication,
    *,
    sequence: int = 1,
    key_character: str = "b",
    services: tuple[ServiceSummary, ...] = (),
) -> ServiceSnapshot:
    return ServiceSnapshot(
        network_id=auth.network_id,
        node_id=auth.node_id,
        snapshot_id=SnapshotId.new(),
        sequence=sequence,
        idempotency_key=f"snapkey_{key_character * 64}",
        generated_at=NOW,
        services=services,
    )


def test_capability_snapshot_is_atomic_idempotent_and_monotonic(tmp_path: Path) -> None:
    _, registry, directory, auth = directory_stack(tmp_path)
    first = capability_snapshot(auth)
    receipt = directory.replace_capabilities(auth, first)
    duplicate = directory.replace_capabilities(auth, first)
    assert duplicate.model_copy(update={"duplicate": False}) == receipt
    assert duplicate.duplicate is True

    changed_same_key = first.model_copy(
        update={"capabilities": (capability(name="list_docker_services"),)}
    )
    with pytest.raises(RegistryError) as conflict:
        directory.replace_capabilities(auth, changed_same_key)
    assert conflict.value.code is CoordinatorErrorCode.CONFLICT

    with pytest.raises(RegistryError) as out_of_order:
        directory.replace_capabilities(
            auth,
            capability_snapshot(auth, sequence=1, key_character="c"),
        )
    assert out_of_order.value.code is CoordinatorErrorCode.OUT_OF_ORDER

    second = capability_snapshot(
        auth,
        sequence=2,
        key_character="d",
        capabilities=(capability(name="list_docker_services", minor=2),),
    )
    second_receipt = directory.replace_capabilities(auth, second)
    assert second_receipt.server_revision == receipt.server_revision + 1
    with registry.store.connect() as connection:
        rows = connection.execute("SELECT name, version_minor FROM capability_directory").fetchall()
    assert [(row["name"], row["version_minor"]) for row in rows] == [("list_docker_services", 2)]
    audit = registry.audit_records(NETWORK)[-1]
    assert audit.action is CoordinatorAuditAction.CAPABILITIES_REPLACED
    assert audit.item_count == 1


def test_service_snapshot_marks_disappeared_service_stopped(tmp_path: Path) -> None:
    _, registry, directory, auth = directory_stack(tmp_path)
    first_service = ServiceId.new()
    second_service = ServiceId.new()
    first = service_snapshot(
        auth,
        services=(
            service_summary(first_service),
            service_summary(second_service, port=8787),
        ),
    )
    first_receipt = directory.replace_services(auth, first)
    second = service_snapshot(
        auth,
        sequence=2,
        key_character="c",
        services=(service_summary(second_service, port=8788),),
    )
    second_receipt = directory.replace_services(auth, second)
    assert second_receipt.server_revision == first_receipt.server_revision + 1
    with registry.store.connect() as connection:
        rows = connection.execute(
            "SELECT service_id, port, lifecycle FROM service_directory ORDER BY service_id"
        ).fetchall()
    by_id = {row["service_id"]: (row["port"], row["lifecycle"]) for row in rows}
    assert by_id[str(first_service)][1] == ServiceLifecycle.STOPPED.value
    assert by_id[str(second_service)] == (8788, ServiceLifecycle.ACTIVE.value)


def test_snapshot_rejects_binding_version_size_and_revoked_auth(tmp_path: Path) -> None:
    _, registry, directory, auth = directory_stack(tmp_path)
    snapshot = capability_snapshot(auth)
    with pytest.raises(RegistryError) as binding:
        directory.replace_capabilities(
            auth,
            snapshot.model_copy(update={"node_id": NodeId.new()}),
        )
    assert binding.value.code is CoordinatorErrorCode.FORBIDDEN
    with pytest.raises(RegistryError) as version:
        directory.replace_capabilities(
            auth,
            capability_snapshot(
                auth,
                protocol=ProtocolVersion(major=2, minor=0),
            ),
        )
    assert version.value.code is CoordinatorErrorCode.VERSION_INCOMPATIBLE

    tiny = CoordinatorDirectoryService(
        registry.store,
        registry,
        policy=DirectoryPolicy(max_snapshot_bytes=1024),
    )
    large = capability_snapshot(
        auth,
        capabilities=tuple(capability(name=f"tool_{index:03d}") for index in range(100)),
    )
    with pytest.raises(RegistryError) as oversized:
        tiny.replace_capabilities(auth, large)
    assert oversized.value.code is CoordinatorErrorCode.SNAPSHOT_TOO_LARGE

    registry.revoke_node(NETWORK, snapshot.node_id, reason="lost")
    with pytest.raises(RegistryError) as revoked:
        directory.replace_capabilities(auth, snapshot)
    assert revoked.value.code is CoordinatorErrorCode.UNAUTHENTICATED


def test_snapshot_rechecks_credential_inside_write_transaction(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, registry, directory, auth = directory_stack(tmp_path)
    original = registry.authenticate_refresh

    def rotate_after_auth(authentication: RefreshAuthentication) -> object:
        result = original(authentication)
        registry.rotate_refresh(authentication)
        return result

    monkeypatch.setattr(registry, "authenticate_refresh", rotate_after_auth)
    with pytest.raises(RegistryError) as invalidated:
        directory.replace_capabilities(auth, capability_snapshot(auth))
    assert invalidated.value.code is CoordinatorErrorCode.UNAUTHENTICATED


def test_directory_filters_paginates_and_invalidates_old_revision(tmp_path: Path) -> None:
    clock, registry, directory, first_auth = directory_stack(tmp_path)
    auths = [first_auth]
    for index in range(2):
        token, _ = enrollment(registry)
        registered = registry.register(
            registration(
                token,
                identity(
                    display_name=f"node-{index}",
                    node_id=NodeId.new(),
                ),
                device=f"{index + 1}" * 64,
                key=f"{index + 2}" * 64,
            )
        )
        auth = authentication(registered)
        registry.heartbeat(auth, heartbeat_for(auth))
        auths.append(auth)
    for index, auth in enumerate(auths):
        directory.replace_capabilities(
            auth,
            capability_snapshot(
                auth,
                key_character=chr(ord("d") + index),
                capabilities=(
                    capability(
                        name="list_docker_services",
                        minor=index,
                    ),
                ),
            ),
        )
        directory.replace_services(
            auth,
            service_snapshot(
                auth,
                key_character=str(7 + index),
                services=(
                    service_summary(
                        ServiceId.new(),
                        port=8080 + index,
                        accessibility=ServiceAccessibility.NETWORK,
                    ),
                ),
            ),
        )

    query = DirectoryQuery(
        network_id=NETWORK,
        tool_name="list_docker_services",
        tool_version=ProtocolVersion(major=1, minor=1),
        service_protocol=ServiceProtocol.HTTP,
        service_accessibility=ServiceAccessibility.NETWORK,
        freshness=DirectoryFreshness.FRESH,
        page_size=1,
    )
    first_page = directory.query(first_auth, query)
    assert len(first_page.nodes) == 1
    assert first_page.next_cursor is not None
    second_page = directory.query(
        first_auth,
        query.model_copy(update={"cursor": first_page.next_cursor}),
    )
    assert len(second_page.nodes) == 1
    assert second_page.nodes[0].identity.node_id != first_page.nodes[0].identity.node_id
    exact = directory.query(
        first_auth,
        DirectoryQuery(
            network_id=NETWORK,
            node_id=first_page.nodes[0].identity.node_id,
            node_status=NodeStatus.ONLINE,
            platform=Platform.MACOS,
            service_port=first_page.nodes[0].identity.gateway_endpoint.port - 207,
        ),
    )
    assert len(exact.nodes) <= 1

    clock.now += timedelta(seconds=1)
    directory.replace_capabilities(
        auths[-1],
        capability_snapshot(
            auths[-1],
            sequence=2,
            key_character="a",
        ),
    )
    invalidated = directory.query(
        first_auth,
        query.model_copy(update={"cursor": first_page.next_cursor}),
    )
    assert invalidated.full_sync_required is True
    assert invalidated.nodes == ()

    other_query = query.model_copy(update={"network_id": OTHER_NETWORK})
    with pytest.raises(RegistryError) as forbidden:
        directory.query(first_auth, other_query)
    assert forbidden.value.code is CoordinatorErrorCode.FORBIDDEN


def test_directory_freshness_propagates_status_and_snapshot_ttl(tmp_path: Path) -> None:
    clock, registry, directory, auth = directory_stack(tmp_path)
    directory.replace_capabilities(auth, capability_snapshot(auth))
    fresh = directory.query(
        auth,
        DirectoryQuery(network_id=NETWORK),
    )
    assert fresh.nodes[0].freshness is DirectoryFreshness.FRESH

    clock.now += timedelta(seconds=120)
    stale_snapshot = directory.query(
        auth,
        DirectoryQuery(network_id=NETWORK, freshness=DirectoryFreshness.STALE),
    )
    assert stale_snapshot.nodes[0].freshness is DirectoryFreshness.STALE
    stale_service = directory.query(
        auth,
        DirectoryQuery(
            network_id=NETWORK,
            service_protocol=ServiceProtocol.HTTP,
            freshness=DirectoryFreshness.STALE,
        ),
    )
    assert stale_service.nodes == ()

    clock.now = NOW + timedelta(seconds=30)
    registry.refresh_node_states(NETWORK)
    stale_node = directory.query(auth, DirectoryQuery(network_id=NETWORK))
    assert stale_node.nodes[0].status is NodeStatus.STALE
    clock.now = NOW + timedelta(seconds=90)
    registry.refresh_node_states(NETWORK)
    offline = directory.query(auth, DirectoryQuery(network_id=NETWORK))
    assert offline.nodes[0].freshness is DirectoryFreshness.OFFLINE
    registry.revoke_node(NETWORK, offline.nodes[0].identity.node_id, reason="lost")
    with pytest.raises(RegistryError):
        directory.query(auth, DirectoryQuery(network_id=NETWORK))


def test_directory_exposes_revoked_and_offline_freshness_to_other_node(
    tmp_path: Path,
) -> None:
    clock, registry, directory, first_auth = directory_stack(tmp_path)
    token, _ = enrollment(registry)
    second_registered = registry.register(
        registration(
            token,
            identity(node_id=NodeId.new(), display_name="second"),
            device="c" * 64,
            key="d" * 64,
        )
    )
    second_auth = authentication(second_registered)
    registry.heartbeat(second_auth, heartbeat_for(second_auth))
    no_snapshot = directory.query(
        first_auth,
        DirectoryQuery(network_id=NETWORK, freshness=DirectoryFreshness.STALE),
    )
    assert second_auth.node_id in tuple(node.identity.node_id for node in no_snapshot.nodes)
    registry.revoke_node(NETWORK, second_auth.node_id, reason="lost")
    revoked = directory.query(
        first_auth,
        DirectoryQuery(network_id=NETWORK, freshness=DirectoryFreshness.REVOKED),
    )
    assert revoked.nodes[0].freshness is DirectoryFreshness.REVOKED

    clock.now += timedelta(seconds=90)
    registry.refresh_node_states(NETWORK)
    offline = directory.query(
        first_auth,
        DirectoryQuery(network_id=NETWORK, freshness=DirectoryFreshness.OFFLINE),
    )
    assert offline.nodes[0].freshness is DirectoryFreshness.OFFLINE


def test_concurrent_same_sequence_accepts_once(tmp_path: Path) -> None:
    _, _, directory, auth = directory_stack(tmp_path)
    snapshots = (
        capability_snapshot(auth, key_character="a"),
        capability_snapshot(auth, key_character="b"),
    )

    def submit(snapshot: CapabilitySnapshot) -> str:
        try:
            directory.replace_capabilities(auth, snapshot)
            return "accepted"
        except RegistryError as exc:
            return exc.code.value

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = tuple(pool.map(submit, snapshots))
    assert results.count("accepted") == 1
    assert results.count(CoordinatorErrorCode.OUT_OF_ORDER.value) == 1


def test_directory_configuration_cursor_and_clock_fail_closed(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        DirectoryPolicy(max_snapshot_bytes=100)
    with pytest.raises(ValueError):
        DirectoryPolicy(snapshot_ttl_seconds=0)

    first_registry = service(tmp_path / "first")
    second_registry = service(tmp_path / "second")
    with pytest.raises(ValueError, match="共享"):
        CoordinatorDirectoryService(first_registry.store, second_registry)

    _, registry, directory, auth = directory_stack(tmp_path / "valid")
    with pytest.raises(RegistryError) as cursor:
        directory.query(
            auth,
            DirectoryQuery(network_id=NETWORK, cursor="invalid-cursor-value"),
        )
    assert cursor.value.code is CoordinatorErrorCode.INVALID_CURSOR
    non_mapping = base64.urlsafe_b64encode(json.dumps([0] * 20).encode()).rstrip(b"=").decode()
    with pytest.raises(RegistryError):
        directory.query(
            auth,
            DirectoryQuery(network_id=NETWORK, cursor=non_mapping),
        )
    wrong_binding = (
        base64.urlsafe_b64encode(
            json.dumps(
                {
                    "network_id": str(OTHER_NETWORK),
                    "revision": 1,
                    "after_node": str(auth.node_id),
                    "filter_hash": "wrong",
                }
            ).encode()
        )
        .rstrip(b"=")
        .decode()
    )
    with pytest.raises(RegistryError):
        directory.query(
            auth,
            DirectoryQuery(network_id=NETWORK, cursor=wrong_binding),
        )
    with registry.store.connect() as connection:
        connection.execute("DELETE FROM revisions WHERE network_id=?", (str(NETWORK),))
    with pytest.raises(RegistryError) as missing:
        directory.query(auth, DirectoryQuery(network_id=NETWORK))
    assert missing.value.code is CoordinatorErrorCode.FORBIDDEN

    naive = CoordinatorDirectoryService(
        registry.store,
        registry,
        clock=lambda: NOW.replace(tzinfo=None),
    )
    with pytest.raises(ValueError, match="时区"):
        naive.query(auth, DirectoryQuery(network_id=NETWORK))
