"""网关可导出的服务清单，沿用本机服务地图的分档。"""

from __future__ import annotations

import asyncio
import os
from collections.abc import Callable, Mapping
from datetime import UTC, datetime

from tunnelminion.agent.service_marks import ServiceMark, ServiceMarkStore
from tunnelminion.agent.service_observation import DeterministicServiceObserver
from tunnelminion.domain.identifiers import NodeId, OperationId
from tunnelminion.gateway.contracts import (
    GatewayServices,
    PeerServiceEntry,
    PeerServicePatrol,
    ServicePort,
)
from tunnelminion.web.service_map import build_local_service_map


class GatewayServiceReader:
    """按既有观察预算刷新，复用快照并重新应用最新标记。"""

    def __init__(
        self,
        node_id: NodeId,
        display_name: Callable[[], str],
        observer: DeterministicServiceObserver,
        marks: ServiceMarkStore,
        *,
        pending_repair_ids: Callable[[], tuple[OperationId, ...]] | None = None,
        patrol: Callable[[], Mapping[str, PeerServicePatrol]] | None = None,
    ) -> None:
        self._node_id = node_id
        self._display_name = display_name
        self._observer = observer
        self._marks = marks
        self._pending_repair_ids = pending_repair_ids or (lambda: ())
        self._patrol: Callable[[], Mapping[str, PeerServicePatrol]] = patrol or dict
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
        patrol = self._patrol()
        return GatewayServices(
            node_id=self._node_id,
            display_name=self._display_name(),
            observed_at=snapshot.observed_at,
            pending_repair_ids=self._pending_repair_ids(),
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
                    patrol=patrol.get(entry.key),
                )
                for entry in local.services
                if entry.tier == "show" or entry.mark is ServiceMark.MINE
            ),
        )
