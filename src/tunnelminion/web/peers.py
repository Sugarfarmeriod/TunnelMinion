"""本机地图的对端目录与内存服务缓存。"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncGenerator, Callable
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal

import httpx
from fastapi import APIRouter, FastAPI, HTTPException
from pydantic import BaseModel, ConfigDict

from tunnelminion.agent.coordinator import CoordinatorCache
from tunnelminion.coordinator.contracts import DirectoryFreshness, NodeStatus
from tunnelminion.domain.delegation import DelegationProposedRepair
from tunnelminion.domain.errors import ErrorCode
from tunnelminion.domain.identifiers import NodeId
from tunnelminion.domain.invites import platform_display_name
from tunnelminion.domain.tools import Platform
from tunnelminion.gateway.client import FixedGatewayClient, RemoteGatewayError
from tunnelminion.gateway.configuration import GatewayConfigurationService
from tunnelminion.gateway.contracts import GatewayErrorCode, GatewayServices, PeerServiceEntry
from tunnelminion.repair.contracts import REPAIR_TERMINAL_STATUSES
from tunnelminion.tools.audit import AuditSink
from tunnelminion.web.service_map import LocalServiceMap

PollOutcome = Literal["ok", "unreachable", "forbidden", "error"]
Lifespan = Callable[[FastAPI], AbstractAsyncContextManager[None]]


@dataclass(frozen=True)
class PeerCache:
    """只在当前进程内保留的最近清单和联系结果。"""

    snapshot: GatewayServices | None = None
    fetched_at: datetime | None = None
    outcome: PollOutcome | None = None
    last_seen_at: datetime | None = None
    reachable: bool | None = None
    services_visible: bool = True


class PeerServicePoller:
    """顺序刷新固定对端，重复触发时跳过整轮。"""

    def __init__(
        self,
        configuration: GatewayConfigurationService,
        node_id: NodeId,
        audit: AuditSink,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.configuration = configuration
        self._node_id = node_id
        self._audit = audit
        self._transport = transport
        self._cache: dict[str, PeerCache] = {}
        self._pending_repairs: dict[str, tuple[DelegationProposedRepair, ...]] = {}
        self._lock = asyncio.Lock()

    def pending_repairs(self, node_id: NodeId) -> tuple[DelegationProposedRepair, ...]:
        now = datetime.now(UTC)
        waiting = tuple(
            repair
            for repair in self._pending_repairs.get(str(node_id), ())
            if repair.status not in REPAIR_TERMINAL_STATUSES and repair.expires_at > now
        )
        self._pending_repairs[str(node_id)] = waiting
        return waiting

    def remember_repairs(
        self, node_id: NodeId, repairs: tuple[DelegationProposedRepair, ...]
    ) -> None:
        """只保存对端修复摘要，最新的最多三件。"""
        merged = {str(repair.repair_id): repair for repair in self.pending_repairs(node_id)}
        merged.update((str(repair.repair_id), repair) for repair in repairs)
        self._pending_repairs[str(node_id)] = tuple(
            sorted(merged.values(), key=lambda repair: repair.expires_at, reverse=True)
        )
        self._pending_repairs[str(node_id)] = self.pending_repairs(node_id)[:3]

    def read(self, node_id: NodeId) -> PeerCache:
        return self._cache.get(str(node_id), PeerCache())

    def services_view(
        self, value: str, coordinator_cache: CoordinatorCache | None = None
    ) -> PeerServicesView:
        """读取已知对端的缓存，不访问网络。"""
        peer = next(
            (peer for peer in self.configuration.view().peers if str(peer.node_id) == value),
            None,
        )
        if peer is None:
            directory = coordinator_cache.read() if coordinator_cache is not None else None
            if directory is not None:
                node = next(
                    (
                        node
                        for node in directory.nodes
                        if str(node.identity.node_id) == value
                        and node.identity.node_id != self._node_id
                    ),
                    None,
                )
                if node is not None:
                    return PeerServicesView(
                        node_id=node.identity.node_id,
                        display_name=node.identity.display_name,
                        host=None,
                    )
            raise HTTPException(404, "对端不存在")
        cached = self.read(peer.node_id)
        snapshot = cached.snapshot if cached.services_visible else None
        return PeerServicesView(
            node_id=peer.node_id,
            display_name=peer.display_name or platform_display_name(peer.platform),
            host=peer.host,
            observed_at=snapshot.observed_at if snapshot is not None else None,
            services=snapshot.services if snapshot is not None else (),
            fetched_at=cached.fetched_at,
            outcome=cached.outcome,
        )

    async def refresh(self) -> None:
        if self._lock.locked():
            return
        async with self._lock:
            peers = self.configuration.view().peers
            self._cache = {str(peer.node_id): self.read(peer.node_id) for peer in peers}
            for peer in peers:
                previous = self.read(peer.node_id)
                snapshot = previous.snapshot
                outcome: PollOutcome = "ok"
                reachable = True
                try:
                    endpoint, token = self.configuration.resolve_service_peer(peer.node_id)
                    client = FixedGatewayClient(
                        endpoint,
                        token,
                        self._node_id,
                        peer.node_id,
                        self._audit,
                        transport=self._transport,
                    )
                    async with asyncio.timeout(10):
                        snapshot = await client.get_services()
                    if "pending_repair_ids" in snapshot.model_fields_set:
                        self._pending_repairs[str(peer.node_id)] = tuple(
                            repair
                            for repair in self.pending_repairs(peer.node_id)
                            if repair.repair_id in snapshot.pending_repair_ids
                        )
                    else:
                        running = {
                            service.name
                            for service in snapshot.services
                            if service.state == "running"
                        }
                        self._pending_repairs[str(peer.node_id)] = tuple(
                            repair
                            for repair in self.pending_repairs(peer.node_id)
                            if repair.service_name not in running
                        )
                except RemoteGatewayError as exc:
                    if exc.code in {ErrorCode.NODE_UNREACHABLE, ErrorCode.REMOTE_TIMEOUT}:
                        outcome, reachable = "unreachable", False
                    elif exc.gateway_code is GatewayErrorCode.DELEGATION_NOT_ALLOWED:
                        outcome = "forbidden"
                    else:
                        outcome = "error"
                except TimeoutError:
                    outcome, reachable = "unreachable", False
                except (KeyError, ValueError, RuntimeError):
                    outcome, reachable = "error", False
                now = datetime.now(UTC)
                self._cache[str(peer.node_id)] = PeerCache(
                    snapshot=snapshot,
                    fetched_at=now,
                    outcome=outcome,
                    last_seen_at=now if reachable else previous.last_seen_at,
                    reachable=reachable,
                    services_visible=(
                        outcome == "ok" or (previous.services_visible and outcome != "forbidden")
                    ),
                )

    async def run(self) -> None:
        while True:
            await self.refresh()
            await asyncio.sleep(60)

    @asynccontextmanager
    async def lifespan(self, _app: FastAPI) -> AsyncGenerator[None]:
        # 运行期间才用邀请码加入的对端也要出现，所以没有对端时也保持轮询，只是不发请求。
        task = asyncio.create_task(self.run())
        try:
            yield
        finally:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)


class PeerSummary(BaseModel):
    """地图上的一台电脑，不含连接地址和凭据。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    node_id: NodeId
    display_name: str
    platform: Platform | None
    is_local: bool = False
    source: Literal["local", "gateway", "coordinator"]
    reachable: bool | None
    last_seen_at: datetime | None
    services_visible: bool
    service_count: int
    pending_repairs: tuple[DelegationProposedRepair, ...] = ()


def peer_services_lifespan(base: Lifespan, poller: PeerServicePoller) -> Lifespan:
    """随本机应用启动轮询，退出时取消正在进行的请求。"""

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncGenerator[None]:
        async with base(app), poller.lifespan(app):
            yield

    return lifespan


class PeersView(BaseModel):
    """本机在前，其余按连接状态和名字排序。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    peers: tuple[PeerSummary, ...]


class PeerServicesView(BaseModel):
    """本机缓存视图；只有这里向本机页面提供已配置的对端地址。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    node_id: NodeId
    display_name: str
    host: str | None
    observed_at: datetime | None = None
    services: tuple[PeerServiceEntry, ...] = ()
    fetched_at: datetime | None = None
    outcome: PollOutcome | None = None


def create_peers_router(
    node_id: NodeId,
    platform: Platform,
    display_name: Callable[[], str],
    poller: PeerServicePoller,
    local_services: Callable[[], LocalServiceMap],
    coordinator_cache: CoordinatorCache | None = None,
) -> APIRouter:
    """挂载到已有本机请求保护之下，不在请求中拉取远端服务。"""
    router = APIRouter()

    def list_peers() -> PeersView:
        local = local_services()
        own = PeerSummary(
            node_id=node_id,
            display_name=display_name(),
            platform=platform,
            is_local=True,
            source="local",
            reachable=True,
            last_seen_at=local.observed_at,
            services_visible=True,
            service_count=sum(entry.tier == "show" for entry in local.services),
        )
        peers: list[PeerSummary] = []
        known = {str(node_id)}
        for peer in poller.configuration.view().peers:
            known.add(str(peer.node_id))
            cached = poller.read(peer.node_id)
            visible = cached.services_visible
            peers.append(
                PeerSummary(
                    node_id=peer.node_id,
                    display_name=peer.display_name or platform_display_name(peer.platform),
                    platform=peer.platform,
                    source="gateway",
                    reachable=cached.reachable,
                    last_seen_at=cached.last_seen_at,
                    services_visible=visible,
                    service_count=len(cached.snapshot.services)
                    if visible and cached.snapshot
                    else 0,
                    pending_repairs=poller.pending_repairs(peer.node_id),
                )
            )
        directory = coordinator_cache.read() if coordinator_cache is not None else None
        if directory is not None:
            fresh = directory.is_fresh(datetime.now(UTC))
            for node in directory.nodes:
                if str(node.identity.node_id) in known:
                    continue
                peers.append(
                    PeerSummary(
                        node_id=node.identity.node_id,
                        display_name=node.identity.display_name,
                        platform=node.identity.platform,
                        source="coordinator",
                        reachable=fresh
                        and node.status is NodeStatus.ONLINE
                        and node.freshness is DirectoryFreshness.FRESH,
                        last_seen_at=node.last_received_at,
                        services_visible=False,
                        service_count=node.service_count,
                        pending_repairs=poller.pending_repairs(node.identity.node_id),
                    )
                )
        peers.sort(
            key=lambda peer: (
                0 if peer.reachable is True else 1 if peer.reachable is None else 2,
                peer.display_name.casefold(),
                str(peer.node_id),
            )
        )
        return PeersView(peers=(own, *peers))

    def peer_services(value: str) -> PeerServicesView:
        return poller.services_view(value, coordinator_cache)

    router.add_api_route("/api/peers", list_peers, response_model=PeersView)
    router.add_api_route(
        "/api/peers/{value}/services", peer_services, response_model=PeerServicesView
    )
    return router
