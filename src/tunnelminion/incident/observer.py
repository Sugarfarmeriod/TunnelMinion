"""模型外后台观察、incident 触发与单 run 调度。"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncGenerator, Awaitable, Callable
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from datetime import UTC, datetime
from typing import Protocol

from fastapi import FastAPI
from pydantic import BaseModel, ConfigDict

from tunnelminion.incident.contracts import Incident, NormalizedSnapshot
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
    ) -> None:
        if not 1 <= interval_seconds <= 3600:
            raise ValueError("观察周期必须位于 1 到 3600 秒")
        self._overview = overview
        self._store = store
        self._detector = detector or SnapshotDiffDetector()
        self._investigator = investigator
        self._before_snapshot = before_snapshot
        self._interval_seconds = interval_seconds
        self._baseline: NormalizedSnapshot | None = None
        self._active: set[str] = set()
        self._lock = asyncio.Lock()

    async def observe_once(self) -> ObservationResult:
        """保存一次快照，并串行调查本轮唯一事件集合。"""
        if self._before_snapshot is not None:
            await self._before_snapshot()
        if self._baseline is None:
            self._baseline = self._store.latest_snapshot()
        snapshot = assemble_overview_snapshot(
            self._overview(),
            revision=self._store.next_revision(),
        )
        self._store.put_snapshot(snapshot)
        if self._baseline is None:
            self._baseline = snapshot
            return ObservationResult(snapshot=snapshot)
        events = self._detector.compare(self._baseline, snapshot)
        values: list[Incident] = []
        for event in events:
            incident = self._store.record_event(event)
            values.append(await self._investigate_once(incident))
        if not self._detector.has_pending:
            self._baseline = snapshot
        return ObservationResult(snapshot=snapshot, incidents=tuple(values))

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
