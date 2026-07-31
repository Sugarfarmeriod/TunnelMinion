"""managed network 同步循环的运行时接线测试。"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import cast

from tests.agent.test_network_sync import FakeNetworkSyncTransport, build, signed

from tunnelminion.agent.managed_network_runtime import (
    ManagedNetworkSyncLoop,
    build_managed_network_sync_loop,
)
from tunnelminion.agent.managed_node import ManagedNodeConfig
from tunnelminion.agent.network_sync import ManagedNetworkSyncTransport
from tunnelminion.coordinator.client_credentials import AgentRefreshCredentialStore
from tunnelminion.coordinator.contracts import GatewayEndpoint
from tunnelminion.domain.identifiers import NetworkId, NodeId
from tunnelminion.domain.tools import Platform


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
    raise AssertionError("等待 managed network 循环超时")


def test_loop_syncs_pending_with_backoff_and_stops_at_safe_point(tmp_path: Path) -> None:
    async def scenario() -> None:
        envelope, key = signed()
        transport = FakeNetworkSyncTransport(key, (envelope,))
        synchronizer, store, _ = build(tmp_path, transport, sync_interval=0.01)
        loop = ManagedNetworkSyncLoop(synchronizer, store)
        stop = asyncio.Event()
        task = asyncio.create_task(loop.run(stop))
        await wait_until(lambda: loop.status.pending_revision == 1)
        await wait_until(lambda: len(transport.pull_calls) >= 2)
        assert loop.domain.value == "managed-config"
        assert loop.synchronizer.checkpoint.pending_config == envelope
        stop.set()
        await task
        await loop.checkpoint()
        await loop.run(stop)

    asyncio.run(scenario())


def test_factory_translates_pinned_key_and_uses_non_secret_sqlite_checkpoint(
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
    loop = build_managed_network_sync_loop(
        tmp_path,
        config,
        cast(ManagedNetworkSyncTransport, object()),
        AgentRefreshCredentialStore(MemorySecrets()),
    )
    assert loop.synchronizer.config.pinned_fingerprints == frozenset({f"sha256:{'a' * 64}"})
    assert loop.status.applied_revision == 0
    asyncio.run(loop.checkpoint())
