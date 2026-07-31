"""Windows/macOS 常规应用共享的 managed node 组装。"""

from __future__ import annotations

from collections.abc import AsyncGenerator, Callable
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from dataclasses import dataclass
from pathlib import Path

from fastapi import FastAPI
from pydantic import JsonValue

from tunnelminion.agent.coordinator import (
    CoordinatorTransport,
    HttpCoordinatorTransport,
)
from tunnelminion.agent.managed_coordinator import (
    ManagedCoordinatorLoops,
    build_managed_coordinator_loops,
)
from tunnelminion.agent.managed_network_runtime import (
    ManagedNetworkSyncLoop,
    build_managed_network_sync_loop,
)
from tunnelminion.agent.managed_node import (
    MANAGED_NODE_CONFIG_FILE,
    FileManagedNodeConfigRepository,
    ManagedNodeConfig,
    ManagedNodeStatus,
    managed_node_secret_store,
    managed_node_status,
)
from tunnelminion.agent.managed_runtime import (
    MANAGED_RUNTIME_CHECKPOINT_FILE,
    FileManagedRuntimeCheckpointRepository,
    ManagedNodeRuntime,
)
from tunnelminion.agent.network_sync import (
    HttpManagedNetworkSyncTransport,
    ManagedNetworkSyncTransport,
)
from tunnelminion.agent.service_observation import CollectionAdapter
from tunnelminion.coordinator.client_credentials import AgentRefreshCredentialStore
from tunnelminion.domain.identifiers import NodeId
from tunnelminion.domain.tools import Platform
from tunnelminion.tools.registry import ToolRegistry


@dataclass(frozen=True)
class ManagedNodeApplication:
    """应用工厂持有的脱敏状态与可选后台运行时。"""

    config: ManagedNodeConfig | None
    enrollment: ManagedNodeStatus
    runtime: ManagedNodeRuntime | None = None
    coordinator: ManagedCoordinatorLoops | None = None
    network: ManagedNetworkSyncLoop | None = None

    def resource_payload(self) -> dict[str, JsonValue]:
        """生成不含 endpoint、凭据、签名和配置正文的分域资源状态。"""
        checkpoint = self.network.synchronizer.checkpoint if self.network is not None else None
        return {
            "enrollment": self.enrollment.model_dump(mode="json"),
            "runtime": (
                self.runtime.status.model_dump(mode="json") if self.runtime is not None else None
            ),
            "directory": (
                self.coordinator.directory.status.model_dump(mode="json")
                if self.coordinator is not None
                else None
            ),
            "services": (
                self.coordinator.services.status.model_dump(mode="json")
                if self.coordinator is not None
                else None
            ),
            "managed_config": (
                self.network.status.model_dump(mode="json") if self.network is not None else None
            ),
            "last_known_good_revision": (
                checkpoint.last_known_good.config.revision
                if checkpoint is not None and checkpoint.last_known_good is not None
                else None
            ),
        }


def build_managed_node_application(
    data_dir: Path,
    node_id: NodeId,
    platform: Platform,
    registry: ToolRegistry,
    listeners: CollectionAdapter,
    processes: CollectionAdapter,
    docker: CollectionAdapter,
    *,
    coordinator_transport: CoordinatorTransport | None = None,
    network_transport: ManagedNetworkSyncTransport | None = None,
) -> ManagedNodeApplication:
    """仅在显式配置且已 enrollment 时创建三个真实后台循环。"""
    config = FileManagedNodeConfigRepository(data_dir / MANAGED_NODE_CONFIG_FILE).load()
    if config is None:
        return ManagedNodeApplication(config=None, enrollment=managed_node_status(None))
    if config.node_id != node_id or config.platform is not platform:
        return ManagedNodeApplication(
            config=config,
            enrollment=managed_node_status(config, error_code="identity_mismatch"),
        )
    if not config.enabled:
        return ManagedNodeApplication(
            config=config,
            enrollment=managed_node_status(config),
        )
    credentials = AgentRefreshCredentialStore(
        managed_node_secret_store(data_dir, config.secret_store)
    )
    enrollment = managed_node_status(config, credentials)
    if not enrollment.credential_configured:
        return ManagedNodeApplication(config=config, enrollment=enrollment)
    coordinator_config = config.coordinator_client_config()
    coordinator = build_managed_coordinator_loops(
        data_dir,
        config,
        coordinator_transport or HttpCoordinatorTransport(coordinator_config),
        credentials,
        registry,
        listeners,
        processes,
        docker,
    )
    network = build_managed_network_sync_loop(
        data_dir,
        config,
        network_transport or HttpManagedNetworkSyncTransport(coordinator_config),
        credentials,
    )
    runtime = ManagedNodeRuntime(
        (coordinator.services, coordinator.directory, network),
        FileManagedRuntimeCheckpointRepository(data_dir / MANAGED_RUNTIME_CHECKPOINT_FILE),
        base_backoff_seconds=config.base_backoff_seconds,
        max_backoff_seconds=config.max_backoff_seconds,
    )
    return ManagedNodeApplication(
        config=config,
        enrollment=enrollment,
        runtime=runtime,
        coordinator=coordinator,
        network=network,
    )


def managed_application_lifespan(
    managed: ManagedNodeApplication,
) -> Callable[[FastAPI], AbstractAsyncContextManager[None]]:
    """未配置时零副作用，已就绪时严格托管 managed runtime。"""

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
        del app
        if managed.runtime is None:
            yield
            return
        await managed.runtime.start()
        try:
            yield
        finally:
            await managed.runtime.stop()

    return lifespan
