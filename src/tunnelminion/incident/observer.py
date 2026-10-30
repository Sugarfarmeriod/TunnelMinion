"""模型外后台观察、incident 触发与单 run 调度。"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncGenerator, Awaitable, Callable
from contextlib import AbstractAsyncContextManager, AsyncExitStack, asynccontextmanager
from datetime import UTC, datetime, timedelta
from typing import Protocol

from fastapi import FastAPI
from pydantic import BaseModel, ConfigDict

from tunnelminion.domain.identifiers import ServiceId
from tunnelminion.incident.contracts import (
    Incident,
    IncidentEventType,
    NormalizedSnapshot,
    SnapshotDiffEvent,
    SnapshotObjectKind,
    SnapshotSource,
)
from tunnelminion.incident.snapshot import SnapshotDiffDetector, assemble_overview_snapshot
from tunnelminion.incident.storage import SQLiteIncidentStore
from tunnelminion.web.overview import OverviewSource, ResourceOverview

logger = logging.getLogger(__name__)


def _log_exception(message: str, error: Exception) -> None:
    """保留异常类型与栈，省略可能携带秘密的正文及异常链。"""
    logger.error(
        message,
        exc_info=(RuntimeError, RuntimeError(type(error).__name__), error.__traceback__),
    )


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
        read_only_preview: bool = False,
        clock: Callable[[], datetime] | None = None,
        skip_investigation: Callable[[SnapshotDiffEvent], bool] | None = None,
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
        self.read_only_preview = read_only_preview
        self._clock = clock or (lambda: datetime.now(UTC))
        # 交给别处（巡检）调查的事件照常记录，但不在这里重复调查。
        self._skip_investigation = skip_investigation
        self._baseline: NormalizedSnapshot | None = None
        self._baseline_stabilized = False
        self._baseline_automatic_services: set[str] = set()
        self._active: dict[str, asyncio.Task[None]] = {}
        self._last_investigated: dict[str, datetime] = {}

    async def observe_once(self) -> ObservationResult:
        """保存快照与全部事件，符合条件的调查交给有界后台任务。"""
        if self._before_snapshot is not None:
            await self._before_snapshot()
        if self.read_only_preview:
            return ObservationResult(
                snapshot=assemble_overview_snapshot(
                    self._overview(), revision=self._store.next_revision()
                )
            )
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
        overview = self._overview()
        # 本地与目录的首页名称已由 select_service_presentations 按 show/mine 筛选。
        automatic_services = {
            str(item.service_id)
            for item in overview.services.items
            if item.display_name is not None
            and item.source
            in {OverviewSource.LOCAL_OBSERVATION, OverviewSource.COORDINATOR_DIRECTORY}
        }
        snapshot = assemble_overview_snapshot(
            overview,
            revision=self._store.next_revision(),
        )
        self._store.put_snapshot(snapshot)
        if self._baseline is None:
            self._baseline = snapshot
            self._baseline_automatic_services = automatic_services
            return ObservationResult(snapshot=snapshot)
        if not self._baseline_stabilized:
            self._baseline = snapshot
            self._baseline_stabilized = True
            self._baseline_automatic_services = automatic_services
            return ObservationResult(snapshot=snapshot)
        events = self._detector.compare(self._scope(self._baseline), self._scope(snapshot))
        values: list[Incident] = []
        for event in events:
            incident = self._store.record_event(event)
            values.append(incident)
            eligible = (
                self._baseline_automatic_services
                if event.event_type is IncidentEventType.SERVICE_REMOVED
                else automatic_services
            )
            if (
                event.object_kind is SnapshotObjectKind.SERVICE
                and event.object_id in eligible
                and (self._skip_investigation is None or not self._skip_investigation(event))
            ):
                self._schedule_investigation(incident)
        if not self._detector.has_pending:
            self._baseline = snapshot
            self._baseline_automatic_services = automatic_services
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

    async def run(self, stop: asyncio.Event, *, warm_up: bool = False) -> None:
        """按有界周期运行，停止信号不会触发额外刷新。

        `warm_up` 时先立刻刷新一次服务清单，让刚启动的页面不必空等一个周期；这次不留事件快照，
        基线仍由一个周期后的第一轮建立。
        """
        try:
            if warm_up and self._before_snapshot is not None and not stop.is_set():
                try:
                    await self._before_snapshot()
                except Exception as exc:
                    _log_exception("启动时刷新服务失败，下个周期重试", exc)
            while not stop.is_set():
                try:
                    await asyncio.wait_for(stop.wait(), timeout=self._interval_seconds)
                except TimeoutError:
                    try:
                        await self.observe_once()
                    except Exception as exc:
                        _log_exception("观察轮次失败，下个周期重试", exc)
        finally:
            await self.aclose()

    async def aclose(self) -> None:
        """取消并收齐当前后台调查。"""
        tasks = tuple(self._active.values())
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        self._active.clear()

    def _schedule_investigation(self, incident: Incident) -> None:
        if self._investigator is None:
            return
        key = str(incident.incident_id)
        if key in self._active or len(self._active) >= 2:
            return
        service_id = incident.event.object_id
        now = self._clock()
        previous = self._last_investigated.get(service_id)
        if previous is not None and now - previous < timedelta(hours=1):
            return
        self._last_investigated[service_id] = now
        self._active[key] = asyncio.create_task(
            self._investigate_once(incident, self._investigator)
        )

    async def _investigate_once(self, incident: Incident, runner: IncidentRunner) -> None:
        try:
            await runner.run(incident)
        except Exception as exc:
            _log_exception("自动调查失败", exc)
        finally:
            self._active.pop(str(incident.incident_id), None)


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
        async with AsyncExitStack() if observer.read_only_preview else base(app):
            if observer.read_only_preview:
                await observer.observe_once()
            else:
                store.recover_interrupted(at=now())
            stop = asyncio.Event()
            task = asyncio.create_task(observer.run(stop, warm_up=not observer.read_only_preview))
            try:
                yield
            finally:
                stop.set()
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
                await observer.aclose()

    return lifespan
