"""Windows/macOS 常规应用共享的 managed node 组装。"""

from __future__ import annotations

from collections.abc import AsyncGenerator, Callable
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from weakref import ref

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
from tunnelminion.agent.managed_path import (
    ManagedPathApplication,
    ManagedPathPlatformFactory,
    build_managed_path_application,
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
from tunnelminion.model.secrets import SecretStoreError
from tunnelminion.network.path_status import ManagedPathStatus
from tunnelminion.tools.registry import ToolRegistry


@dataclass(frozen=True)
class ManagedNodeApplication:
    """应用工厂持有的脱敏状态与可选后台运行时。"""

    config: ManagedNodeConfig | None
    enrollment: ManagedNodeStatus
    runtime: ManagedNodeRuntime | None = None
    coordinator: ManagedCoordinatorLoops | None = None
    network: ManagedNetworkSyncLoop | None = None
    managed_path: ManagedPathApplication | None = None

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
            "managed_path": (
                self.managed_path.resource_payload() if self.managed_path is not None else None
            ),
        }

    def current_managed_path_status(self) -> ManagedPathStatus | None:
        """返回现有 lifecycle 的持久化 path status，不触发平台读取。"""
        return (
            self.managed_path.current_managed_path_status()
            if self.managed_path is not None
            else None
        )

    def close(self) -> None:
        """显式释放常规应用持有的 managed path 本地资源。"""
        if self.managed_path is not None:
            self.managed_path.close()


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
    managed_path_platform_factory: ManagedPathPlatformFactory | None = None,
) -> ManagedNodeApplication:
    """仅在显式配置且已 enrollment 时创建三个真实后台循环。"""
    try:
        config = FileManagedNodeConfigRepository(data_dir / MANAGED_NODE_CONFIG_FILE).load()
    except (OSError, ValueError):
        return ManagedNodeApplication(
            config=None,
            enrollment=managed_node_status(None, error_code="managed_config_invalid"),
        )
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
    try:
        enrollment = managed_node_status(config, credentials)
    except (OSError, SecretStoreError):
        return ManagedNodeApplication(
            config=config,
            enrollment=managed_node_status(
                config,
                error_code="secret_store_unavailable",
            ),
        )
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
    managed_path = None
    if managed_path_platform_factory is not None:
        synchronizer = network.synchronizer
        managed_path = build_managed_path_application(
            data_dir,
            config.network_id,
            config.node_id,
            managed_path_platform_factory,
            revision_source=lambda: synchronizer.checkpoint.applied_revision,
            pending_source=lambda: synchronizer.checkpoint.pending_config,
            acknowledgements=network.acknowledgement_sink,
            commit_last_known_good=synchronizer.mark_verified,
        )
        network.attach_managed_path(managed_path)
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
        managed_path=managed_path,
    )


def managed_application_lifespan(
    managed: ManagedNodeApplication,
) -> Callable[[FastAPI], AbstractAsyncContextManager[None]]:
    """未配置时零副作用，已就绪时严格托管 managed runtime。"""
    managed_ref = ref(managed)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
        del app
        current = managed_ref()
        if current is None or current.runtime is None:
            yield
            return
        try:
            await current.runtime.start()
        except BaseException:
            current.close()
            raise
        try:
            yield
        finally:
            try:
                await current.runtime.stop()
            finally:
                current.close()

    return lifespan


def managed_resource_payload_callback(
    managed: ManagedNodeApplication,
) -> Callable[[], dict[str, JsonValue]]:
    """生成不把应用对象反向锁在 FastAPI 路由中的资源回调。"""
    managed_ref = ref(managed)

    def callback() -> dict[str, JsonValue]:
        current = managed_ref()
        return current.resource_payload() if current is not None else {}

    return callback


def managed_path_status_callback(
    managed: ManagedNodeApplication,
) -> Callable[[], ManagedPathStatus | None]:
    """生成只持有 weak reference 的 managed path 状态回调。"""
    managed_ref = ref(managed)

    def callback() -> ManagedPathStatus | None:
        current = managed_ref()
        return current.current_managed_path_status() if current is not None else None

    return callback
