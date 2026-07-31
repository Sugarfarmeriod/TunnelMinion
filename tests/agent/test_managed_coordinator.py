"""Coordinator 目录循环与完整服务缓存接线测试。"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

import pytest
from pydantic import JsonValue

from tunnelminion.agent.coordinator import CoordinatorSyncStatus, CoordinatorTransport, SyncPhase
from tunnelminion.agent.managed_coordinator import (
    CoordinatorDirectoryLoop,
    CoordinatorSynchronizer,
    ServiceObservationLoop,
    ServiceObserver,
    ServiceSnapshotCache,
    build_managed_coordinator_loops,
)
from tunnelminion.agent.managed_node import ManagedNodeConfig
from tunnelminion.agent.service_observation import (
    ServiceObservationSnapshot,
    ServiceObservationStatus,
)
from tunnelminion.coordinator.client_credentials import AgentRefreshCredentialStore
from tunnelminion.coordinator.contracts import (
    CapabilityAvailability,
    CapabilitySummary,
    GatewayEndpoint,
    ServiceAccessibility,
    ServiceProtocol,
    ServiceSummary,
)
from tunnelminion.domain.identifiers import NetworkId, NodeId, ServiceId
from tunnelminion.domain.tools import Platform, RiskLevel
from tunnelminion.domain.versioning import ProtocolVersion
from tunnelminion.platforms.windows.models import Availability, CollectionResult
from tunnelminion.tools.contracts import ToolCancellationToken
from tunnelminion.tools.registry import ToolRegistry

NOW = datetime(2026, 7, 31, tzinfo=UTC)


def service() -> ServiceSummary:
    return ServiceSummary(
        service_id=ServiceId("service_0123456789abcdef0123456789abcdef"),
        protocol=ServiceProtocol.TCP,
        host="10.77.0.2",
        port=8787,
        accessibility=ServiceAccessibility.NETWORK,
        source="list_network_listeners",
        confidence=0.5,
        observed_at=NOW,
    )


def capability() -> CapabilitySummary:
    return CapabilitySummary(
        name="get_node_summary",
        version=ProtocolVersion(major=1, minor=0),
        platform=Platform.WINDOWS,
        risk_level=RiskLevel.READ_ONLY,
        availability=CapabilityAvailability.AVAILABLE,
        schema_hash="a" * 64,
    )


class FakeObserver:
    def __init__(self) -> None:
        self.interval_seconds = 0.001
        self.status = ServiceObservationStatus()
        self.calls = 0

    async def observe(self) -> ServiceObservationSnapshot:
        self.calls += 1
        self.status = ServiceObservationStatus(
            service_count=1,
            last_success_at=NOW,
        )
        return ServiceObservationSnapshot(observed_at=NOW, services=(service(),))


class FakeSynchronizer:
    def __init__(self) -> None:
        self.status = CoordinatorSyncStatus()
        self.calls: list[tuple[tuple[CapabilitySummary, ...], tuple[ServiceSummary, ...]]] = []

    async def sync_once(
        self,
        capabilities: tuple[CapabilitySummary, ...],
        services: tuple[ServiceSummary, ...],
    ) -> CoordinatorSyncStatus:
        self.calls.append((capabilities, services))
        self.status = (
            CoordinatorSyncStatus(
                phase=SyncPhase.BACKOFF,
                consecutive_failures=1,
                next_backoff_seconds=0.001,
                last_error_code="offline",
            )
            if len(self.calls) == 1
            else CoordinatorSyncStatus(
                phase=SyncPhase.IDLE,
                last_success_at=NOW,
                server_revision=3,
                capability_count=len(capabilities),
                service_count=len(services),
            )
        )
        return self.status


class EmptyAdapter:
    async def execute(
        self,
        arguments: dict[str, JsonValue],
        cancellation: ToolCancellationToken,
    ) -> JsonValue:
        del arguments, cancellation
        return cast(
            JsonValue,
            CollectionResult(availability=Availability.AVAILABLE).model_dump(mode="json"),
        )


class MemorySecrets:
    def __init__(self) -> None:
        self.values: dict[str, str] = {}

    def get(self, name: str) -> str | None:
        return self.values.get(name)

    def set(self, name: str, value: str) -> None:
        self.values[name] = value

    def delete(self, name: str) -> None:
        self.values.pop(name, None)


async def wait_until(predicate: object) -> None:
    for _ in range(200):
        if callable(predicate) and predicate():
            return
        await asyncio.sleep(0.001)
    raise AssertionError("等待 Coordinator 接线条件超时")


def test_service_loop_publishes_before_directory_and_recovers_backoff() -> None:
    async def scenario() -> None:
        cache = ServiceSnapshotCache()
        observer = FakeObserver()
        synchronizer = FakeSynchronizer()
        service_loop = ServiceObservationLoop(cast(ServiceObserver, observer), cache)
        directory_loop = CoordinatorDirectoryLoop(
            cast(CoordinatorSynchronizer, synchronizer),
            (capability(),),
            cache,
            sync_interval_seconds=1,
        )
        stop = asyncio.Event()
        directory_task = asyncio.create_task(directory_loop.run(stop))
        await asyncio.sleep(0)
        assert synchronizer.calls == []
        service_task = asyncio.create_task(service_loop.run(stop))
        await wait_until(lambda: len(synchronizer.calls) == 2)
        assert synchronizer.calls[0] == ((capability(),), (service(),))
        assert directory_loop.status.phase is SyncPhase.IDLE
        assert service_loop.status.service_count == 1
        stop.set()
        await asyncio.gather(directory_task, service_task)
        await directory_loop.checkpoint()
        await service_loop.checkpoint()

    asyncio.run(scenario())


def test_service_cache_rejects_partial_and_stop_before_first_snapshot() -> None:
    async def scenario() -> None:
        cache = ServiceSnapshotCache()
        assert cache.read() is None
        with pytest.raises(ValueError, match="不完整"):
            cache.replace(
                ServiceObservationSnapshot(
                    observed_at=NOW,
                    services=(),
                    complete=False,
                )
            )
        stop = asyncio.Event()
        waiting = asyncio.create_task(cache.wait_ready(stop))
        stop.set()
        assert not await waiting
        directory = CoordinatorDirectoryLoop(
            cast(CoordinatorSynchronizer, FakeSynchronizer()),
            (),
            ServiceSnapshotCache(),
            sync_interval_seconds=1,
        )
        await directory.run(stop)
        cache.replace(ServiceObservationSnapshot(observed_at=NOW, services=()))
        assert await cache.wait_ready(asyncio.Event())

    asyncio.run(scenario())


def test_directory_loop_validates_interval_and_fails_closed_on_corrupt_cache() -> None:
    synchronizer = FakeSynchronizer()
    with pytest.raises(ValueError, match="间隔"):
        CoordinatorDirectoryLoop(
            cast(CoordinatorSynchronizer, synchronizer),
            (),
            ServiceSnapshotCache(),
            sync_interval_seconds=0,
        )

    class CorruptCache(ServiceSnapshotCache):
        async def wait_ready(self, stop: asyncio.Event) -> bool:
            del stop
            return True

    async def scenario() -> None:
        loop = CoordinatorDirectoryLoop(
            cast(CoordinatorSynchronizer, synchronizer),
            (),
            CorruptCache(),
            sync_interval_seconds=1,
        )
        with pytest.raises(RuntimeError, match="没有完整快照"):
            await loop.run(asyncio.Event())

    asyncio.run(scenario())


def test_factory_injects_existing_credentials_checkpoint_and_platform_capabilities(
    tmp_path: Path,
) -> None:
    config = ManagedNodeConfig(
        coordinator_endpoint="http://10.77.0.1:8790",
        network_id=NetworkId.new(),
        node_id=NodeId.new(),
        display_name="Windows A",
        platform=Platform.WINDOWS,
        gateway_endpoint=GatewayEndpoint(host="10.77.0.2", port=8787),
        pinned_fingerprints=frozenset({"a" * 64}),
    )
    adapter = EmptyAdapter()
    loops = build_managed_coordinator_loops(
        tmp_path,
        config,
        cast(CoordinatorTransport, object()),
        AgentRefreshCredentialStore(MemorySecrets()),
        ToolRegistry(),
        adapter,
        adapter,
        adapter,
    )
    assert loops.directory.domain.value == "directory"
    assert loops.services.domain.value == "services"
    assert loops.directory.status.server_revision == 0
    assert loops.service_cache.read() is None
    assert loops.coordinator_cache.read() is None
