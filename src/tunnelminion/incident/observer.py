"""模型外后台观察、incident 触发与单 run 调度。"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncGenerator, Awaitable, Callable
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from datetime import UTC, datetime
from typing import Protocol

from fastapi import FastAPI
from pydantic import BaseModel, ConfigDict

from tunnelminion.domain.identifiers import ServiceId
from tunnelminion.incident.contracts import Incident, NormalizedSnapshot, SnapshotSource
from tunnelminion.incident.snapshot import SnapshotDiffDetector, assemble_overview_snapshot
from tunnelminion.incident.storage import SQLiteIncidentStore
from tunnelminion.web.overview import ResourceOverview


class IncidentRunner(Protocol):
    """隔离后台调度与具体模型实现。"""

    async def run(self, incident: Incident) -> Incident: ...


class ObservationResult(BaseModel):
    """一次后台刷新产生的快照与 incident。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    snapshot: NormalizedSnapshot
    incidents: tuple[Incident, ...] = ()


class IncidentObservationService:
    """普通刷新只比较快照；只有确认事件才进入调查。"""

    def __init__(
        self,
        overview: Callable[[], ResourceOverview],
        store: SQLiteIncidentStore,
        *,
        detector: SnapshotDiffDetector | None = None,
        investigator: IncidentRunner | None = None,
        before_snapshot: Callable[[], Awaitable[None]] | None = None,
        interval_seconds: float = 30,
        watched_service_id: ServiceId | None = None,
    ) -> None:
        if not 1 <= interval_seconds <= 3600:
            raise ValueError("观察周期必须位于 1 到 3600 秒")
        self._overview = overview
        self._store = store
        self._detector = detector or SnapshotDiffDetector()
        self._investigator = investigator
        self._before_snapshot = before_snapshot
        self._interval_seconds = interval_seconds
        self._watched_service_id = watched_service_id
        self._baseline: NormalizedSnapshot | None = None
        self._baseline_stabilized = False
        self._active: set[str] = set()
        self._lock = asyncio.Lock()

    async def observe_once(self) -> ObservationResult:
        """保存一次快照，并串行调查本轮唯一事件集合。"""
        if self._before_snapshot is not None:
            await self._before_snapshot()
        if self._baseline is None:
            self._baseline = self._store.latest_snapshot()
            if self._baseline is not None:
                previous = self._baseline.services
                if (
                    self._watched_service_id is not None
                    and not any(item.service_id == self._watched_service_id for item in previous)
                ) or (
                    self._watched_service_id is None
                    and any(
                        item.source is SnapshotSource.STATIC_PEER_OBSERVATION for item in previous
                    )
                ):
                    # 切换观察范围时建立新基线，不把未观察对象当作消失。
                    self._baseline = None
            self._baseline_stabilized = self._baseline is not None
        snapshot = assemble_overview_snapshot(
            self._overview(),
            revision=self._store.next_revision(),
        )
        self._store.put_snapshot(snapshot)
        if self._baseline is None:
            self._baseline = snapshot
            return ObservationResult(snapshot=snapshot)
        if not self._baseline_stabilized:
            self._baseline = snapshot
            self._baseline_stabilized = True
            return ObservationResult(snapshot=snapshot)
        events = self._detector.compare(self._scope(self._baseline), self._scope(snapshot))
        values: list[Incident] = []
        for event in events:
            incident = self._store.record_event(event)
            values.append(await self._investigate_once(incident))
        if not self._detector.has_pending:
            self._baseline = snapshot
        return ObservationResult(snapshot=snapshot, incidents=tuple(values))

    def _scope(self, snapshot: NormalizedSnapshot) -> NormalizedSnapshot:
        """总览快照仍完整保存；显式端口模式只对指定对象触发调查。"""
        if self._watched_service_id is None:
            return snapshot
        services = tuple(
            item for item in snapshot.services if item.service_id == self._watched_service_id
        )
        node_ids = {str(item.node_id) for item in services}
        return snapshot.model_copy(
            update={
                "services": services,
                "nodes": tuple(item for item in snapshot.nodes if str(item.node_id) in node_ids),
            }
        )

    async def run(self, stop: asyncio.Event) -> None:
        """按有界周期运行，停止信号不会触发额外刷新。"""
        while not stop.is_set():
            try:
                await asyncio.wait_for(stop.wait(), timeout=self._interval_seconds)
            except TimeoutError:
                await self.observe_once()

    async def _investigate_once(self, incident: Incident) -> Incident:
        if self._investigator is None:
            return incident
        key = str(incident.incident_id)
        async with self._lock:
            if key in self._active:
                return incident
            self._active.add(key)
        try:
            return await self._investigator.run(incident)
        finally:
            async with self._lock:
                self._active.discard(key)


def incident_observation_lifespan(
    base: Callable[[FastAPI], AbstractAsyncContextManager[None]],
    observer: IncidentObservationService,
    store: SQLiteIncidentStore,
    *,
    clock: Callable[[], datetime] | None = None,
) -> Callable[[FastAPI], AbstractAsyncContextManager[None]]:
    """在现有本机 lifespan 内托管观察任务，停止时不重放或等待远端调用。"""
    now = clock or (lambda: datetime.now(UTC))

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
        async with base(app):
            store.recover_interrupted(at=now())
            stop = asyncio.Event()
            task = asyncio.create_task(observer.run(stop))
            try:
                yield
            finally:
                stop.set()
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)

    return lifespan
