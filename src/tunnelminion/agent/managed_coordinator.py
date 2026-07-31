"""把服务观察与现有 Coordinator 同步器接入 managed runtime。"""

from __future__ import annotations

import asyncio
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from tunnelminion.agent.coordinator import (
    AgentCoordinatorSynchronizer,
    CoordinatorCache,
    CoordinatorCheckpointStore,
    CoordinatorSyncStatus,
    CoordinatorTransport,
    SyncPhase,
    render_capabilities,
)
from tunnelminion.agent.managed_node import ManagedNodeConfig
from tunnelminion.agent.managed_runtime import ManagedRuntimeDomain
from tunnelminion.agent.service_observation import (
    CollectionAdapter,
    DeterministicServiceObserver,
    ServiceObservationSnapshot,
    ServiceObservationStatus,
)
from tunnelminion.coordinator.client_credentials import AgentRefreshCredentialStore
from tunnelminion.coordinator.contracts import CapabilitySummary, ServiceSummary
from tunnelminion.tools.registry import ToolRegistry


class ServiceObserver(Protocol):
    """服务观察循环需要的最小边界。"""

    @property
    def status(self) -> ServiceObservationStatus: ...

    @property
    def interval_seconds(self) -> float: ...

    async def observe(self) -> ServiceObservationSnapshot: ...


class CoordinatorSynchronizer(Protocol):
    """现有 AgentCoordinatorSynchronizer 的可测试边界。"""

    @property
    def status(self) -> CoordinatorSyncStatus: ...

    async def sync_once(
        self,
        capabilities: Sequence[CapabilitySummary],
        services: Sequence[ServiceSummary],
    ) -> CoordinatorSyncStatus: ...


class ServiceSnapshotCache:
    """只发布完整快照，并让首轮心跳等待首份服务事实。"""

    def __init__(self) -> None:
        self._snapshot: ServiceObservationSnapshot | None = None
        self._ready = asyncio.Event()

    def replace(self, snapshot: ServiceObservationSnapshot) -> None:
        if not snapshot.complete:
            raise ValueError("不得缓存不完整服务快照")
        self._snapshot = snapshot
        self._ready.set()

    def read(self) -> ServiceObservationSnapshot | None:
        return self._snapshot

    async def wait_ready(self, stop: asyncio.Event) -> bool:
        if self._ready.is_set():
            return True
        ready = asyncio.create_task(self._ready.wait())
        stopped = asyncio.create_task(stop.wait())
        done, pending = await asyncio.wait((ready, stopped), return_when=asyncio.FIRST_COMPLETED)
        for task in pending:
            task.cancel()
        await asyncio.gather(*pending, return_exceptions=True)
        return ready in done and ready.result()


class ServiceObservationLoop:
    """按观察器预算刷新完整服务缓存。"""

    domain = ManagedRuntimeDomain.SERVICES

    def __init__(self, observer: ServiceObserver, cache: ServiceSnapshotCache) -> None:
        self._observer = observer
        self._cache = cache

    @property
    def status(self) -> ServiceObservationStatus:
        return self._observer.status

    async def run(self, stop: asyncio.Event) -> None:
        while not stop.is_set():
            self._cache.replace(await self._observer.observe())
            try:
                await asyncio.wait_for(stop.wait(), timeout=self._observer.interval_seconds)
            except TimeoutError:
                continue

    async def checkpoint(self) -> None:
        return None


class CoordinatorDirectoryLoop:
    """以首份完整服务快照启动现有心跳、能力、服务与目录顺序。"""

    domain = ManagedRuntimeDomain.DIRECTORY

    def __init__(
        self,
        synchronizer: CoordinatorSynchronizer,
        capabilities: Sequence[CapabilitySummary],
        services: ServiceSnapshotCache,
        *,
        sync_interval_seconds: float,
    ) -> None:
        if sync_interval_seconds <= 0:
            raise ValueError("Coordinator 同步间隔必须为正数")
        self._synchronizer = synchronizer
        self._capabilities = tuple(capabilities)
        self._services = services
        self._sync_interval_seconds = sync_interval_seconds

    @property
    def status(self) -> CoordinatorSyncStatus:
        return self._synchronizer.status

    async def run(self, stop: asyncio.Event) -> None:
        if not await self._services.wait_ready(stop):
            return
        while not stop.is_set():
            snapshot = self._services.read()
            if snapshot is None:
                raise RuntimeError("服务缓存就绪但没有完整快照")
            status = await self._synchronizer.sync_once(self._capabilities, snapshot.services)
            delay = (
                status.next_backoff_seconds
                if status.phase is SyncPhase.BACKOFF
                else self._sync_interval_seconds
            )
            try:
                await asyncio.wait_for(stop.wait(), timeout=delay)
            except TimeoutError:
                continue

    async def checkpoint(self) -> None:
        return None


@dataclass(frozen=True)
class ManagedCoordinatorLoops:
    """应用工厂可直接交给 ManagedNodeRuntime 的真实目录与服务循环。"""

    directory: CoordinatorDirectoryLoop
    services: ServiceObservationLoop
    service_cache: ServiceSnapshotCache
    coordinator_cache: CoordinatorCache


def build_managed_coordinator_loops(
    data_dir: Path,
    config: ManagedNodeConfig,
    transport: CoordinatorTransport,
    credentials: AgentRefreshCredentialStore,
    registry: ToolRegistry,
    listeners: CollectionAdapter,
    processes: CollectionAdapter,
    docker: CollectionAdapter,
) -> ManagedCoordinatorLoops:
    """注入既有凭据、checkpoint、能力渲染、服务观察和目录缓存。"""
    service_cache = ServiceSnapshotCache()
    coordinator_cache = CoordinatorCache()
    observer = DeterministicServiceObserver(
        config.node_id,
        config.services,
        listeners,
        processes,
        docker,
    )
    synchronizer = AgentCoordinatorSynchronizer(
        config.coordinator_client_config(),
        transport,
        credentials,
        CoordinatorCheckpointStore(data_dir / "coordinator-checkpoint.json"),
        coordinator_cache,
    )
    return ManagedCoordinatorLoops(
        directory=CoordinatorDirectoryLoop(
            synchronizer,
            render_capabilities(registry.capabilities(config.platform), config.platform),
            service_cache,
            sync_interval_seconds=config.sync_interval_seconds,
        ),
        services=ServiceObservationLoop(observer, service_cache),
        service_cache=service_cache,
        coordinator_cache=coordinator_cache,
    )
