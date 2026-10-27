"""网关可导出的服务清单，沿用本机服务地图的分档。"""

from __future__ import annotations

import asyncio
import os
from collections.abc import Callable
from datetime import UTC, datetime

from tunnelminion.agent.service_marks import ServiceMark, ServiceMarkStore
from tunnelminion.agent.service_observation import DeterministicServiceObserver
from tunnelminion.domain.identifiers import NodeId
from tunnelminion.gateway.contracts import GatewayServices, PeerServiceEntry, ServicePort
from tunnelminion.web.service_map import build_local_service_map


class GatewayServiceReader:
    """按既有观察预算刷新，复用快照并重新应用最新标记。"""

    def __init__(
        self,
        node_id: NodeId,
        display_name: Callable[[], str],
        observer: DeterministicServiceObserver,
        marks: ServiceMarkStore,
    ) -> None:
        self._node_id = node_id
        self._display_name = display_name
        self._observer = observer
        self._marks = marks
        self._lock = asyncio.Lock()

    async def __call__(self) -> GatewayServices:
        async with self._lock:
            snapshot = self._observer.last_snapshot
            if (
                snapshot is None
                or (datetime.now(UTC) - snapshot.observed_at).total_seconds()
                >= self._observer.interval_seconds
            ):
                snapshot = await self._observer.observe()
            local = build_local_service_map(
                self._node_id, snapshot, self._marks.all(), excluded_pid=os.getpid()
            )
        return GatewayServices(
            node_id=self._node_id,
            display_name=self._display_name(),
            observed_at=snapshot.observed_at,
            services=tuple(
                PeerServiceEntry(
                    key=entry.key,
                    name=entry.name,
                    kind=entry.kind,
                    state=entry.state,
                    mark=entry.mark,
                    web_title=entry.web_title,
                    ports=tuple(
                        sorted(
                            {
                                (
                                    endpoint.port,
                                    endpoint.protocol,
                                    endpoint.has_web_page,
                                ): ServicePort(
                                    port=endpoint.port,
                                    protocol=endpoint.protocol,
                                    has_web_page=endpoint.has_web_page,
                                )
                                for endpoint in entry.endpoints
                            }.values(),
                            key=lambda port: (port.port, port.protocol, str(port.has_web_page)),
                        )
                    ),
                )
                for entry in local.services
                if entry.tier == "show" or entry.mark is ServiceMark.MINE
            ),
        )
