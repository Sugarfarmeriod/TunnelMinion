"""巡检测试替身：假的服务清单、网页探测和对话；修复用 `RepairHarness` 的假 Docker 和假进程。"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Awaitable, Callable
from datetime import datetime
from pathlib import Path
from typing import Literal

from tests.repair.factories import NODE, NOW
from tests.repair.fakes import RepairHarness

from tunnelminion.agent.conversation import (
    RunStatus,
    RunView,
    StartRunInput,
    ThreadContext,
    ThreadView,
)
from tunnelminion.domain.identifiers import RunId, ThreadId
from tunnelminion.domain.service_marks import ServiceMark
from tunnelminion.patrol.contracts import PatrolServiceView
from tunnelminion.patrol.service import PatrolService
from tunnelminion.patrol.storage import SQLitePatrolStore
from tunnelminion.repair.contracts import ManualStep
from tunnelminion.web.service_map import LocalServiceMap, ServiceEndpoint, ServiceEntry

PHOTOS = "docker:compose:photos"
SCRIPT = "python:app.py@8765"
PROGRAM = "program:notes@9000"
AGENT = "launchd:local.photos.web"


def entry(
    key: str = PHOTOS,
    *,
    state: Literal["running", "stopped"] = "running",
    ports: tuple[int, ...] = (8080,),
    web: bool | None = True,
    tier: Literal["show", "review", "hidden"] = "show",
    windows_service: bool = False,
) -> ServiceEntry:
    kind: Literal["docker", "python", "program"] = (
        "docker"
        if key.startswith("docker:")
        else "python"
        if key.startswith("python:")
        else "program"
    )
    return ServiceEntry(
        key=key,
        name={"docker": "相册", "python": "app.py", "program": "笔记"}[kind],
        kind=kind,
        launch_agent=key.startswith("launchd:"),
        windows_service=windows_service,
        tier=tier,
        state=state,
        endpoints=tuple(
            ServiceEndpoint(protocol="tcp", address="127.0.0.1", port=port, has_web_page=web)
            for port in ports
        ),
    )


class FakeConversations:
    def __init__(self) -> None:
        self.threads: dict[str, ThreadContext | None] = {}
        self.notes: list[tuple[ThreadId, str]] = []
        self.steps: list[tuple[ManualStep, ...]] = []
        self.questions: list[tuple[ThreadId, StartRunInput, str | None]] = []
        self.cancelled: list[RunId] = []
        self.start_error: Exception | None = None
        self.hang = False
        self.during_run: Callable[[ThreadId], Awaitable[None]] | None = None
        self.thread = ThreadId.new()

    def create_thread(self, *, context: ThreadContext | None = None) -> ThreadView:
        thread_id = ThreadId.new()
        self.threads[str(thread_id)] = context
        return ThreadView(
            thread_id=thread_id, created_at=NOW, updated_at=NOW, message_count=0, context=context
        )

    def append_notice(
        self, thread_id: ThreadId, text: str, *, manual_steps: tuple[ManualStep, ...] = ()
    ) -> bool:
        self.notes.append((thread_id, text))
        self.steps.append(manual_steps)
        return True

    async def start_run(
        self,
        thread_id: ThreadId,
        value: StartRunInput,
        *,
        context: ThreadContext | None = None,
        context_line: str | None = None,
    ) -> RunView:
        if self.start_error is not None:
            raise self.start_error
        self.questions.append((thread_id, value, context_line))
        self.thread = thread_id
        return RunView(
            run_id=RunId.new(), thread_id=thread_id, status=RunStatus.RUNNING, created_at=NOW
        )

    async def stream_events(self, run_id: RunId) -> AsyncIterator[object]:
        if self.during_run is not None:
            await self.during_run(self.thread)
        if self.hang:
            await asyncio.Event().wait()
        yield object()

    def cancel_run(self, run_id: RunId) -> RunView:
        self.cancelled.append(run_id)
        return RunView(
            run_id=run_id, thread_id=self.thread, status=RunStatus.CANCELLED, created_at=NOW
        )

    def texts(self) -> list[str]:
        return [text for _, text in self.notes]


class PatrolHarness:
    def __init__(self, tmp_path: Path) -> None:
        self.repairs = RepairHarness(tmp_path)
        self.repairs.marks[PHOTOS] = ServiceMark.MINE
        self.conversations = FakeConversations()
        self.store = SQLitePatrolStore(tmp_path / "patrol.sqlite3")
        self.entries: tuple[ServiceEntry, ...] = (entry(),)
        self.observed: datetime | None = NOW
        self.web: dict[int, int | None | Exception] = {}
        self.probed: list[int] = []
        # 端口到"连上后是否先回话"；不在这里的端口不说话。
        self.talk: dict[int, bool | None | Exception] = {}
        self.talk_probed: list[int] = []
        self.patrol = PatrolService(
            NODE,
            self.store,
            self.services,
            self.web_status,
            self.conversations,
            self.repairs.service,
            self.repairs.launch_records.get,
            talks_first=self.talks_first,
            windows_services=self.repairs.windows_services,
            clock=self.repairs.clock,
            investigation_wait_seconds=0.05,
        )

    def services(self) -> LocalServiceMap:
        return LocalServiceMap(node_id=NODE, observed_at=self.observed, services=self.entries)

    async def web_status(self, port: int) -> int | None:
        self.probed.append(port)
        value = self.web.get(port, 200)
        if isinstance(value, Exception):
            raise value
        return value

    async def talks_first(self, port: int) -> bool | None:
        self.talk_probed.append(port)
        value = self.talk.get(port, False)
        if isinstance(value, Exception):
            raise value
        return value

    async def rounds(self, count: int) -> None:
        for _ in range(count):
            await self.patrol.observe_once()
        await self.patrol.wait_idle()

    def view_of(self, key: str = PHOTOS) -> PatrolServiceView:
        return next(item for item in self.patrol.view().services if item.key == key)
