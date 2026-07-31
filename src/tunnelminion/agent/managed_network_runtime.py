"""把既有签名 managed network 同步器接入 managed runtime。"""

from __future__ import annotations

import asyncio
from pathlib import Path

from tunnelminion.agent.managed_node import ManagedNodeConfig
from tunnelminion.agent.managed_runtime import ManagedRuntimeDomain
from tunnelminion.agent.network_sync import (
    ManagedNetworkSyncConfig,
    ManagedNetworkSynchronizer,
    ManagedNetworkSyncStatus,
    ManagedNetworkSyncTransport,
    SQLiteManagedNetworkSyncStore,
)
from tunnelminion.coordinator.client_credentials import AgentRefreshCredentialStore


class ManagedNetworkSyncLoop:
    """只拉取、验签和保存 pending；不创建授权也不调用 Provider。"""

    domain = ManagedRuntimeDomain.MANAGED_CONFIG

    def __init__(
        self,
        synchronizer: ManagedNetworkSynchronizer,
        store: SQLiteManagedNetworkSyncStore,
    ) -> None:
        self._synchronizer = synchronizer
        self._store = store

    @property
    def status(self) -> ManagedNetworkSyncStatus:
        return self._synchronizer.status

    @property
    def synchronizer(self) -> ManagedNetworkSynchronizer:
        return self._synchronizer

    async def run(self, stop: asyncio.Event) -> None:
        while not stop.is_set():
            status = await self._synchronizer.sync_once()
            delay = (
                status.next_backoff_seconds
                if status.next_backoff_seconds > 0
                else self._synchronizer.config.sync_interval_seconds
            )
            try:
                await asyncio.wait_for(stop.wait(), timeout=delay)
            except TimeoutError:
                continue

    async def checkpoint(self) -> None:
        self._store.assert_no_secret_material()


def build_managed_network_sync_loop(
    data_dir: Path,
    config: ManagedNodeConfig,
    transport: ManagedNetworkSyncTransport,
    credentials: AgentRefreshCredentialStore,
) -> ManagedNetworkSyncLoop:
    """复用 Coordinator key/ack transport、refresh 和 SQLite 恢复点。"""
    sync_config = ManagedNetworkSyncConfig(
        network_id=config.network_id,
        node_id=config.node_id,
        pinned_fingerprints=frozenset(
            f"sha256:{fingerprint}" for fingerprint in config.pinned_fingerprints
        ),
        request_timeout_seconds=config.request_timeout_seconds,
        sync_interval_seconds=config.sync_interval_seconds,
        base_backoff_seconds=config.base_backoff_seconds,
        max_backoff_seconds=config.max_backoff_seconds,
        max_config_bytes=config.services.max_snapshot_bytes,
    )
    store = SQLiteManagedNetworkSyncStore(data_dir / "network-sync.sqlite3")
    return ManagedNetworkSyncLoop(
        ManagedNetworkSynchronizer(sync_config, transport, credentials, store),
        store,
    )
