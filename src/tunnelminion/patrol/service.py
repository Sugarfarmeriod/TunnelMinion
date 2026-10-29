"""巡检循环：确认挂了、提醒、调查一次、提出修法，主人预先允许时自动修。

每轮只读本机服务缓存和本机网页首页状态码，不调模型。确认挂了以后才在一条新对话里调查一次；
自动修只是代主人点一次批准，执行前核对、执行、验证和限次都走现有修复流程。
"""

from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import AsyncGenerator, AsyncIterator, Awaitable, Callable
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Protocol

from fastapi import FastAPI

from tunnelminion.agent.conversation import (
    RunView,
    StartRunInput,
    ThreadContext,
    ThreadView,
)
from tunnelminion.domain.identifiers import NodeId, OperationId, RunId, ThreadId
from tunnelminion.model.contracts import ProviderError
from tunnelminion.operation.contracts import OperationStatus
from tunnelminion.patrol.contracts import (
    PATROL_AUTO_REPAIR_COOLDOWN_SECONDS,
    PATROL_CONFIRM_ROUNDS,
    PATROL_DAILY_INVESTIGATIONS,
    PATROL_INTERVAL_SECONDS,
    PATROL_INVESTIGATION_COOLDOWN_SECONDS,
    PATROL_INVESTIGATION_WAIT_SECONDS,
    PATROL_MAX_PROBES,
    PATROL_PROBE_TIMEOUT_SECONDS,
    PATROL_RECOVER_ROUNDS,
    REASON_TEXT,
    AutoRepairResult,
    AutoRepairView,
    PatrolReason,
    PatrolRecord,
    PatrolServiceView,
    PatrolStatus,
    PatrolView,
    repair_kind_for,
)
from tunnelminion.patrol.storage import SQLitePatrolStore
from tunnelminion.repair.contracts import (
    RepairErrorCode,
    RepairKind,
    RepairOrigin,
    RepairOriginKind,
    RepairRecord,
)
from tunnelminion.repair.eligibility import RepairRefusal
from tunnelminion.repair.service import OwnerPreapproval
from tunnelminion.web.service_map import LocalServiceMap, ServiceEntry

logger = logging.getLogger(__name__)

# 巡检调查和普通提问用同一组工具：只读工具加 propose_repair。
PATROL_TOOL_NAMES = (
    "get_node_summary",
    "list_network_listeners",
    "get_process_summary",
    "list_docker_services",
    "probe_service_reachability",
    "read_container_logs",
    "list_launch_records",
    "propose_repair",
)
_NOT_PAUSING_ERRORS = frozenset({RepairErrorCode.BUSY, RepairErrorCode.RATE_LIMITED})


class PatrolConversations(Protocol):
    """巡检用到的对话能力；由 `InMemoryConversationService` 提供。"""

    def create_thread(self, *, context: ThreadContext | None = None) -> ThreadView: ...

    def append_notice(self, thread_id: ThreadId, text: str) -> bool: ...

    async def start_run(
        self,
        thread_id: ThreadId,
        value: StartRunInput,
        *,
        context: ThreadContext | None = None,
        context_line: str | None = None,
    ) -> RunView: ...

    def stream_events(self, run_id: RunId) -> AsyncIterator[object]: ...

    def cancel_run(self, run_id: RunId) -> RunView: ...


class PatrolRepairs(Protocol):
    """巡检用到的修复能力；由 `RepairService` 提供。"""

    async def propose(
        self,
        service_key: str,
        kind: RepairKind,
        reason: str,
        origin: RepairOrigin,
        *,
        actor: str,
    ) -> RepairRecord: ...

    def list(self) -> tuple[RepairRecord, ...]: ...

    def approve_preauthorized(
        self, operation_id: OperationId, *, preapproval: OwnerPreapproval
    ) -> RepairRecord: ...

    async def execute(self, operation_id: OperationId) -> RepairRecord: ...


@dataclass
class _Streak:
    abnormal: int = 0
    healthy: int = 0


@dataclass
class _Round:
    """一轮里要处理的确认和恢复。"""

    confirmed: list[str] = field(default_factory=list[str])
    recovered: list[PatrolRecord] = field(default_factory=list[PatrolRecord])


def _ports(entry: ServiceEntry) -> tuple[int, ...]:
    return tuple(sorted({item.port for item in entry.endpoints}))


def _web_ports(entry: ServiceEntry) -> tuple[int, ...]:
    return tuple(sorted({item.port for item in entry.endpoints if item.has_web_page is True}))


def classify(
    record: PatrolRecord, entry: ServiceEntry | None, web_ok: bool | None
) -> PatrolReason | None:
    """按固定规则判断这一轮是否异常；正常返回 None。"""
    if entry is None:
        return PatrolReason.PORT_CLOSED
    if entry.state == "stopped":
        if entry.kind == "docker":
            return PatrolReason.CONTAINER_EXITED
        if entry.launch_agent:
            return PatrolReason.AGENT_EXITED
        if entry.kind == "python":
            return PatrolReason.SCRIPT_EXITED
        return PatrolReason.PORT_CLOSED
    if record.ports and not set(record.ports) & set(_ports(entry)):
        return PatrolReason.PORT_CLOSED
    if web_ok is False:
        return PatrolReason.WEB_FAILED
    return None


class PatrolService:
    def __init__(
        self,
        node_id: NodeId,
        store: SQLitePatrolStore,
        services: Callable[[], LocalServiceMap],
        web_status: Callable[[int], Awaitable[int | None]],
        conversations: PatrolConversations,
        repairs: PatrolRepairs,
        has_launch_record: Callable[[str], bool],
        *,
        clock: Callable[[], datetime] | None = None,
        interval_seconds: float = PATROL_INTERVAL_SECONDS,
        investigation_wait_seconds: float = PATROL_INVESTIGATION_WAIT_SECONDS,
    ) -> None:
        self._node_id = node_id
        self._store = store
        self._services = services
        self._web_status = web_status
        self._conversations = conversations
        self._repairs = repairs
        self._has_launch_record = has_launch_record
        self._clock = clock or (lambda: datetime.now(UTC))
        self._interval_seconds = interval_seconds
        self._investigation_wait_seconds = investigation_wait_seconds
        self._streaks: dict[str, _Streak] = {}
        self._tasks: dict[str, asyncio.Task[None]] = {}
        self._investigation_lock = asyncio.Lock()
        self._checked_at: datetime | None = None

    # ---- 每轮判定 ----

    async def _probe(self, port: int) -> bool:
        try:
            status = await asyncio.wait_for(
                self._web_status(port), timeout=PATROL_PROBE_TIMEOUT_SECONDS
            )
        except (TimeoutError, OSError):
            return False
        return status is not None and status < 500

    async def _web_checks(
        self, shown: dict[str, ServiceEntry], records: dict[str, PatrolRecord]
    ) -> dict[str, bool]:
        """每轮最多探 16 个入口；一个服务任意一个网页入口能打开就算正常。"""
        plan: list[tuple[str, int]] = []
        for key, entry in shown.items():
            if entry.state != "running":
                continue
            record = records.get(key)
            current = set(_ports(entry))
            remembered = set(record.web_ports) if record is not None else set[int]()
            ports = sorted((remembered & current) or set(_web_ports(entry)))
            plan.extend((key, port) for port in ports)
        plan = plan[:PATROL_MAX_PROBES]
        results = await asyncio.gather(*(self._probe(port) for _, port in plan))
        checks: dict[str, bool] = {}
        for (key, _), ok in zip(plan, results, strict=True):
            checks[key] = checks.get(key, False) or ok
        return checks

    async def observe_once(self) -> None:
        """跑一轮巡检；确认挂了的服务交给后台任务处理。"""
        current = self._services()
        if current.observed_at is None:
            return
        now = self._clock()
        self._checked_at = now
        records = {item.key: item for item in self._store.list_all()}
        present = {item.key: item for item in current.services}
        shown = {key: item for key, item in present.items() if item.tier == "show"}
        for key in records.keys() & present.keys() - shown.keys():
            # 标成隐藏或不再直接显示：不再巡检，开关一并失效。
            self._store.delete(key)
            self._streaks.pop(key, None)
            records.pop(key)
        checks = await self._web_checks(shown, records)
        outcome = _Round()
        for key in sorted(shown.keys() | (records.keys() - present.keys())):
            entry = shown.get(key)
            record = records.get(key)
            if record is None:
                assert entry is not None
                record = PatrolRecord(key=key, name=entry.name)
            updated = self._step(record, entry, checks.get(key), now, outcome)
            if updated is not None:
                self._store.put(updated)
        for record in outcome.recovered:
            if record.thread_id is not None:
                self._conversations.append_notice(
                    record.thread_id, f"巡检确认 {record.name} 已恢复正常。"
                )
        for key in outcome.confirmed:
            task = self._tasks.get(key)
            if task is None or task.done():
                self._tasks[key] = asyncio.create_task(self._handle_down(key))

    def _step(
        self,
        record: PatrolRecord,
        entry: ServiceEntry | None,
        web_ok: bool | None,
        now: datetime,
        outcome: _Round,
    ) -> PatrolRecord | None:
        streak = self._streaks.setdefault(record.key, _Streak())
        reason = classify(record, entry, web_ok)
        if reason is None:
            assert entry is not None
            streak.abnormal = 0
            streak.healthy += 1
            update: dict[str, object] = {
                "seen_running": True,
                "name": entry.name,
                "ports": _ports(entry),
                # 网页标题探测偶尔读不到，已经记住的网页入口只要端口还在就保留。
                "web_ports": tuple(
                    sorted(set(_web_ports(entry)) | (set(record.web_ports) & set(_ports(entry))))
                ),
            }
            if record.status in {PatrolStatus.SUSPECT, PatrolStatus.ACKNOWLEDGED} or (
                record.status is PatrolStatus.DOWN and streak.healthy >= PATROL_RECOVER_ROUNDS
            ):
                if record.status is PatrolStatus.DOWN:
                    outcome.recovered.append(record)
                update |= {
                    "status": PatrolStatus.OK,
                    "reason": None,
                    "down_since": None,
                    "confirmed_at": None,
                    "repair_id": None,
                }
            updated = record.model_copy(update=update)
            return updated if updated != record else None
        streak.healthy = 0
        if not record.seen_running:
            # 没见过正常运行的服务（可能本来就是主人有意停的），不提醒。
            return None
        if record.status in {PatrolStatus.DOWN, PatrolStatus.ACKNOWLEDGED}:
            return None
        streak.abnormal += 1
        if streak.abnormal >= PATROL_CONFIRM_ROUNDS:
            outcome.confirmed.append(record.key)
            return record.model_copy(
                update={
                    "status": PatrolStatus.DOWN,
                    "reason": reason,
                    "down_since": record.down_since or now,
                    "confirmed_at": now,
                    "thread_id": None,
                    "repair_id": None,
                }
            )
        return record.model_copy(
            update={
                "status": PatrolStatus.SUSPECT,
                "reason": reason,
                "down_since": record.down_since or now,
            }
        )

    # ---- 确认挂了以后 ----

    def _note(self, record: PatrolRecord, text: str) -> None:
        if record.thread_id is not None:
            self._conversations.append_notice(record.thread_id, text)

    def _save(self, record: PatrolRecord, **update: object) -> PatrolRecord:
        """只改这次处理负责的字段，不覆盖期间主人改过的开关。"""
        latest = self._store.get(record.key) or record
        updated = latest.model_copy(update=update)
        self._store.put(updated)
        return updated

    async def _handle_down(self, key: str) -> None:
        try:
            await self._handle_down_once(key)
        except Exception as exc:
            logger.error(
                "巡检处理失败",
                exc_info=(RuntimeError, RuntimeError(type(exc).__name__), exc.__traceback__),
            )

    async def _handle_down_once(self, key: str) -> None:
        record = self._store.get(key)
        if record is None or record.status is not PatrolStatus.DOWN or record.reason is None:
            return
        reason = REASON_TEXT[record.reason]
        context = ThreadContext(
            node_id=str(self._node_id), service_key=key, service_name=record.name
        )
        thread = self._conversations.create_thread(context=context)
        record = self._save(record, thread_id=thread.thread_id)
        since = (record.down_since or record.confirmed_at or self._clock()).astimezone()
        alert = (
            f"巡检发现 {record.name} 挂了：{reason}。"
            f"从 {since:%H:%M} 起连续 {PATROL_CONFIRM_ROUNDS} 次检查都不正常。"
        )
        self._note(record, alert)
        record = await self._investigate(record, context, reason)
        pending = self._pending_repair(record)
        kind = repair_kind_for(key)
        if pending is None and kind is not None:
            try:
                pending = await self._repairs.propose(
                    key,
                    kind,
                    f"巡检确认它挂了：{reason}。",
                    RepairOrigin(
                        kind=RepairOriginKind.PATROL,
                        thread_id=record.thread_id,
                        evidence=(alert[:300],),
                    ),
                    actor="patrol",
                )
            except RepairRefusal as exc:
                error = exc.error
                self._note(
                    record,
                    f"巡检想提出修法，但{error.message}"
                    + (f"{error.next_step}" if error.next_step else ""),
                )
                return
            except ValueError:
                self._note(record, "巡检没能为它生成修法，需要你手动处理。")
                return
        if pending is None:
            self._note(record, "这个服务没有现成的修法，需要你手动处理。")
            return
        record = self._save(record, repair_id=pending.plan.operation_id)
        await self._auto_repair(record, pending, reason)

    async def _investigate(
        self, record: PatrolRecord, context: ThreadContext, reason: str
    ) -> PatrolRecord:
        now = self._clock()
        if record.last_investigated_at is not None and now - record.last_investigated_at < (
            timedelta(seconds=PATROL_INVESTIGATION_COOLDOWN_SECONDS)
        ):
            self._note(record, "这个服务 1 小时内已经自动查过一次，这次没有再查原因。")
            return record
        async with self._investigation_lock:
            if not self._store.take_investigation(
                now.astimezone().date(), limit=PATROL_DAILY_INVESTIGATIONS
            ):
                self._note(record, "今天的自动调查次数已经用完，这次没有查原因。")
                return record
            record = self._save(record, last_investigated_at=now)
            assert record.thread_id is not None
            details = {
                "node_id": context.node_id,
                "service_name": record.name,
                "service_key": record.key,
                "ports": list(record.ports),
            }
            # 这句会以提问的形式显示在对话里，所以写明是巡检自动问的。
            question = (
                f"巡检自动提问：{record.name} 挂了（{reason}），请查明原因；能修的话提出修法。"
            )
            try:
                run = await self._conversations.start_run(
                    record.thread_id,
                    StartRunInput(question=question, tool_names=PATROL_TOOL_NAMES),
                    context=context,
                    context_line="关于："
                    + json.dumps(details, ensure_ascii=False, separators=(",", ":")),
                )
            except (ProviderError, ValueError, KeyError):
                self._note(record, "模型现在用不了，这次没有查原因。")
                return record
            try:
                async with asyncio.timeout(self._investigation_wait_seconds):
                    async for _ in self._conversations.stream_events(run.run_id):
                        pass
            except TimeoutError:
                self._conversations.cancel_run(run.run_id)
        return record

    def _pending_repair(self, record: PatrolRecord) -> RepairRecord | None:
        return next(
            (
                item
                for item in self._repairs.list()
                if item.plan.origin.thread_id == record.thread_id
                and item.plan.service_key == record.key
                and item.status is OperationStatus.AWAITING_AUTHORIZATION
            ),
            None,
        )

    async def _auto_repair(self, record: PatrolRecord, pending: RepairRecord, reason: str) -> None:
        if not record.auto_repair_enabled or record.auto_repair_enabled_on is None:
            return
        if record.auto_repair_paused:
            self._note(record, "这个服务的自动修已暂停（上次没修好），这次等你批准。")
            return
        if pending.plan.kind is not repair_kind_for(record.key):
            return
        now = self._clock()
        if record.last_auto_repair_at is not None and now - record.last_auto_repair_at < (
            timedelta(seconds=PATROL_AUTO_REPAIR_COOLDOWN_SECONDS)
        ):
            self._note(record, "这个服务 1 小时内已经自动修过一次，这次等你批准。")
            return
        try:
            self._repairs.approve_preauthorized(
                pending.plan.operation_id,
                preapproval=OwnerPreapproval(
                    enabled_on=record.auto_repair_enabled_on, reason=reason
                ),
            )
        except (KeyError, ValueError):
            return
        record = self._save(record, last_auto_repair_at=now)
        result = await self._repairs.execute(pending.plan.operation_id)
        if result.status is OperationStatus.SUCCEEDED:
            self._save(record, last_auto_repair_result=AutoRepairResult.SUCCEEDED)
            return
        if result.error is not None and result.error.code in _NOT_PAUSING_ERRORS:
            return
        self._save(
            record,
            last_auto_repair_result=AutoRepairResult.FAILED,
            auto_repair_paused=True,
        )
        self._note(
            record,
            "自动修没成功，已经暂停这个服务的自动修，不会再自动重试。看过以后重新打开开关才会恢复。",
        )

    # ---- 网页接口 ----

    def _auto_repair_view(self, key: str, record: PatrolRecord | None) -> AutoRepairView:
        kind = repair_kind_for(key)
        # 脚本和后台服务要见过它正常运行、有记录才有现成修法。
        available = kind is RepairKind.RESTART_CONTAINERS or (
            kind is not None and self._has_launch_record(key)
        )
        return AutoRepairView(
            available=available,
            kind=kind if available else None,
            enabled=record.auto_repair_enabled if record is not None else False,
            enabled_on=record.auto_repair_enabled_on if record is not None else None,
            paused=record.auto_repair_paused if record is not None else False,
            last_attempt_at=record.last_auto_repair_at if record is not None else None,
            last_result=record.last_auto_repair_result if record is not None else None,
        )

    def view(self) -> PatrolView:
        records = {item.key: item for item in self._store.list_all()}
        shown = {item.key: item for item in self._services().services if item.tier == "show"}
        values: list[PatrolServiceView] = []
        for key in sorted(shown.keys() | records.keys()):
            record = records.get(key)
            if record is None:
                record = PatrolRecord(key=key, name=shown[key].name)
            values.append(
                PatrolServiceView(
                    key=key,
                    name=record.name,
                    status=record.status,
                    reason=record.reason,
                    reason_text=REASON_TEXT[record.reason] if record.reason is not None else None,
                    down_since=record.down_since,
                    confirmed_at=record.confirmed_at,
                    thread_id=record.thread_id,
                    repair_id=record.repair_id,
                    auto_repair=self._auto_repair_view(key, records.get(key)),
                )
            )
        used = self._store.investigations_on(self._clock().astimezone().date())
        return PatrolView(
            checked_at=self._checked_at,
            investigations_left_today=max(0, PATROL_DAILY_INVESTIGATIONS - used),
            services=tuple(values),
        )

    def set_auto_repair(self, key: str, *, enabled: bool) -> PatrolView:
        """只由本机网页调用；没有现成修法或不在地图上的服务抛 `LookupError`。"""
        record = self._store.get(key)
        if record is None:
            entry = next(
                (
                    item
                    for item in self._services().services
                    if item.key == key and item.tier == "show"
                ),
                None,
            )
            if entry is None:
                raise KeyError(key)
            record = PatrolRecord(key=key, name=entry.name)
        if enabled and not self._auto_repair_view(key, record).available:
            raise LookupError(key)
        self._store.put(
            record.model_copy(
                update={
                    "auto_repair_enabled": enabled,
                    "auto_repair_enabled_on": self._clock().astimezone().date()
                    if enabled
                    else None,
                    "auto_repair_paused": False,
                }
            )
        )
        logger.info("巡检：%s 的“挂了可以自动修”已%s", key, "打开" if enabled else "关闭")
        return self.view()

    def acknowledge(self, key: str) -> PatrolView:
        """ "这次是我有意停的"：只对挂了或可疑的服务有效。"""
        record = self._store.get(key)
        if record is None:
            raise KeyError(key)
        if record.status not in {PatrolStatus.DOWN, PatrolStatus.SUSPECT}:
            raise ValueError(key)
        self._store.put(record.model_copy(update={"status": PatrolStatus.ACKNOWLEDGED}))
        self._streaks.pop(key, None)
        self._note(record, f"主人说这次是有意停的；{record.name} 再次正常运行之前不再提醒。")
        return self.view()

    # ---- 运行 ----

    async def run(self, stop: asyncio.Event) -> None:
        """按周期巡检；单轮出错只记日志，下个周期重试。"""
        try:
            while not stop.is_set():
                try:
                    await asyncio.wait_for(stop.wait(), timeout=self._interval_seconds)
                except TimeoutError:
                    try:
                        await self.observe_once()
                    except Exception as exc:
                        logger.error(
                            "巡检轮次失败，下个周期重试",
                            exc_info=(
                                RuntimeError,
                                RuntimeError(type(exc).__name__),
                                exc.__traceback__,
                            ),
                        )
        finally:
            await self.aclose()

    async def wait_idle(self) -> None:
        """等当前确认挂了以后的处理全部结束。"""
        await asyncio.gather(*self._tasks.values(), return_exceptions=True)

    async def aclose(self) -> None:
        tasks = tuple(self._tasks.values())
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        self._tasks.clear()


def patrol_lifespan(
    base: Callable[[FastAPI], AbstractAsyncContextManager[None]], patrol: PatrolService
) -> Callable[[FastAPI], AbstractAsyncContextManager[None]]:
    """在现有本机 lifespan 内托管巡检循环。"""

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
        async with base(app):
            stop = asyncio.Event()
            task = asyncio.create_task(patrol.run(stop))
            try:
                yield
            finally:
                stop.set()
                await asyncio.gather(task, return_exceptions=True)

    return lifespan
