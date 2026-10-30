"""巡检循环：确认挂了、提醒、调查一次、提出修法，主人预先允许时自动修。

每轮只读本机服务缓存和本机网页首页状态码，不调模型。确认挂了以后才在一条新对话里调查一次；
自动修只是代主人点一次批准，执行前核对、执行、验证和限次都走现有修复流程。
"""

from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import AsyncGenerator, AsyncIterator, Awaitable, Callable, Mapping
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
from tunnelminion.agent.service_marks import ServiceMark
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
    WindowsServiceView,
    repair_kind_for,
)
from tunnelminion.patrol.storage import SQLitePatrolStore
from tunnelminion.repair.contracts import (
    AnyLaunchRecord,
    ManualStep,
    ProgramLaunchRecord,
    RepairErrorCode,
    RepairKind,
    RepairOrigin,
    RepairOriginKind,
    RepairRecord,
    WindowsServiceInfo,
    WindowsServiceRecord,
    WindowsServiceRuntime,
)
from tunnelminion.repair.eligibility import RepairRefusal, check_windows_service_protected
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

    def append_notice(
        self, thread_id: ThreadId, text: str, *, manual_steps: tuple[ManualStep, ...] = ()
    ) -> bool: ...

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


class _Unknown:
    """这一轮探测看不清（连不上或探测超时），不参与判断。"""


_UNKNOWN = _Unknown()


@dataclass
class _Checks:
    """一个服务这一轮的探测结果；看不清的端口不在里面。

    `web`：端口到首页结果，True 能打开，False 返回服务器错误，None 连上后一直不回应。
    `talk`：端口到"连上后是否先回话"。
    """

    web: dict[int, bool | None] = field(default_factory=dict[int, bool | None])
    talk: dict[int, bool] = field(default_factory=dict[int, bool])


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
    record: PatrolRecord, entry: ServiceEntry | None, checks: _Checks | None = None
) -> PatrolReason | None:
    """按固定规则判断这一轮是否异常；正常返回 None。

    卡住只拿服务自己以前的样子比：以前能打开的网页现在不回应，或以前会先回话的端口现在不回话。
    """
    if entry is None:
        return PatrolReason.PORT_CLOSED
    if entry.state == "stopped":
        if entry.kind == "docker":
            return PatrolReason.CONTAINER_EXITED
        if entry.launch_agent:
            return PatrolReason.AGENT_EXITED
        if entry.windows_service:
            return PatrolReason.SERVICE_STOPPED
        if entry.kind == "python":
            return PatrolReason.SCRIPT_EXITED
        return PatrolReason.PROGRAM_EXITED
    if record.ports and not set(record.ports) & set(_ports(entry)):
        return PatrolReason.PORT_CLOSED
    checks = checks or _Checks()
    if checks.web and True not in checks.web.values():
        silent = any(
            result is None and port in record.web_ports for port, result in checks.web.items()
        )
        return PatrolReason.STUCK if silent else PatrolReason.WEB_FAILED
    if any(not talked and port in record.talk_ports for port, talked in checks.talk.items()):
        return PatrolReason.STUCK
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
        launch_record: Callable[[str], AnyLaunchRecord | None],
        *,
        talks_first: Callable[[int], Awaitable[bool | None]] | None = None,
        windows_services: WindowsServiceRuntime | None = None,
        marks: Callable[[], Mapping[str, ServiceMark]] = dict,
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
        self._launch_record = launch_record
        self._talks_first = talks_first
        self._windows_services = windows_services
        self._marks = marks
        self._clock = clock or (lambda: datetime.now(UTC))
        self._interval_seconds = interval_seconds
        self._investigation_wait_seconds = investigation_wait_seconds
        self._streaks: dict[str, _Streak] = {}
        self._tasks: dict[str, asyncio.Task[None]] = {}
        self._investigation_lock = asyncio.Lock()
        self._checked_at: datetime | None = None

    # ---- 每轮判定 ----

    async def _probe(self, port: int) -> bool | None | _Unknown:
        """首页能打开返回 True，服务器错误返回 False，连上以后一直一个字节都不回返回 None。

        连不上或探测本身超时只说明这一轮看不清，返回 `_UNKNOWN`，不算不回应：
        只是慢、或者只听组网地址不听本机地址的服务不会因此被判成卡住。
        """
        try:
            status = await asyncio.wait_for(
                self._web_status(port), timeout=PATROL_PROBE_TIMEOUT_SECONDS
            )
        except (TimeoutError, OSError):
            return _UNKNOWN
        return None if status is None else status < 500

    async def _talk(self, port: int) -> bool | None:
        """连上以后对方先说话返回 True，一直不说话返回 False；连不上或看不清返回 None。"""
        assert self._talks_first is not None
        try:
            return await asyncio.wait_for(
                self._talks_first(port), timeout=PATROL_PROBE_TIMEOUT_SECONDS
            )
        except (TimeoutError, OSError):
            return None

    async def _checks(
        self, shown: dict[str, ServiceEntry], records: dict[str, PatrolRecord]
    ) -> dict[str, _Checks]:
        """每轮最多探 16 个入口，网页优先；不是网页的端口只在以前会回话或还没探过时探。"""
        web_plan: list[tuple[str, int]] = []
        talk_plan: list[tuple[str, int]] = []
        for key, entry in shown.items():
            if entry.state != "running":
                continue
            record = records.get(key)
            current = set(_ports(entry))
            remembered = set(record.web_ports) if record is not None else set[int]()
            ports = sorted((remembered & current) or set(_web_ports(entry)))
            web_plan.extend((key, port) for port in ports)
            if self._talks_first is None:
                continue
            known = (
                set(record.web_ports) | set(record.quiet_ports)
                if record is not None
                else set[int]()
            )
            talking = set(record.talk_ports) if record is not None else set[int]()
            talk_plan.extend(
                (key, port)
                for port in sorted(current - set(ports))
                if port in talking or port not in known
            )
        web_plan = web_plan[:PATROL_MAX_PROBES]
        talk_plan = talk_plan[: PATROL_MAX_PROBES - len(web_plan)]
        web_results = await asyncio.gather(*(self._probe(port) for _, port in web_plan))
        talk_results = await asyncio.gather(*(self._talk(port) for _, port in talk_plan))
        checks: dict[str, _Checks] = {}
        for (key, port), result in zip(web_plan, web_results, strict=True):
            if not isinstance(result, _Unknown):
                checks.setdefault(key, _Checks()).web[port] = result
        for (key, port), talked in zip(talk_plan, talk_results, strict=True):
            if talked is not None:
                checks.setdefault(key, _Checks()).talk[port] = talked
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
        checks = await self._checks(shown, records)
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
        checks: _Checks | None,
        now: datetime,
        outcome: _Round,
    ) -> PatrolRecord | None:
        streak = self._streaks.setdefault(record.key, _Streak())
        reason = classify(record, entry, checks)
        if reason is None:
            assert entry is not None
            streak.abnormal = 0
            streak.healthy += 1
            current = set(_ports(entry))
            opened = {port for port, ok in (checks.web if checks else {}).items() if ok}
            talk = checks.talk if checks else {}
            talking = (set(record.talk_ports) | {p for p, t in talk.items() if t}) & current
            update: dict[str, object] = {
                "seen_running": True,
                "name": entry.name,
                "ports": _ports(entry),
                # 网页标题探测偶尔读不到，已经记住的网页入口只要端口还在就保留。
                "web_ports": tuple(
                    sorted((set(_web_ports(entry)) | opened | set(record.web_ports)) & current)
                ),
                "talk_ports": tuple(sorted(talking))[:32],
                "quiet_ports": tuple(
                    sorted(
                        (set(record.quiet_ports) | {p for p, t in talk.items() if not t})
                        & current - talking
                    )
                )[:32],
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
                    "repair_refusal": None,
                    "manual_steps": (),
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
                    "repair_refusal": None,
                    "manual_steps": (),
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

    def _note(
        self, record: PatrolRecord, text: str, manual_steps: tuple[ManualStep, ...] = ()
    ) -> None:
        if record.thread_id is not None:
            self._conversations.append_notice(record.thread_id, text, manual_steps=manual_steps)

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
        kind = self._kind_for(key, record.reason)
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
                text = f"巡检想提出修法，但{error.message}" + (
                    f"{error.next_step}" if error.next_step else ""
                )
                record = self._save(
                    record, repair_refusal=text[:1_000], manual_steps=error.manual_steps
                )
                self._note(record, text, error.manual_steps)
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
        if record.reason is PatrolReason.STUCK and not record.auto_repair_stuck_enabled:
            self._note(record, "卡住了要不要自动修需要单独打开，这次等你批准。")
            return
        if pending.plan.kind is not self._kind_for(record.key, record.reason):
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

    def _kind_for(self, key: str, reason: PatrolReason | None) -> RepairKind | None:
        windows = isinstance(self._launch_record(key), WindowsServiceRecord)
        return repair_kind_for(key, reason, windows_service=windows)

    def _windows_service_allowed(self, key: str, info: WindowsServiceInfo | None) -> bool:
        """主人标成"是我的服务"、不在保护名单里的服务才能授权。"""
        if info is None or self._marks().get(key) is not ServiceMark.MINE:
            return False
        try:
            check_windows_service_protected(info)
        except RepairRefusal:
            return False
        return True

    def _windows_service_view(self, key: str) -> WindowsServiceView | None:
        """能授权或已经授权过的 Windows 服务才显示开关；已授权但不再允许的只能撤回。"""
        record = self._launch_record(key)
        if not isinstance(record, WindowsServiceRecord) or self._windows_services is None:
            return None
        info = self._windows_services.inspect(record.service_name)
        granted = info is not None and info.granted
        allowed = self._windows_service_allowed(key, info)
        if not allowed and not granted:
            return None
        assert info is not None
        return WindowsServiceView(
            name=record.service_name,
            display_name=info.display_name,
            binary_path=info.binary_path,
            granted=granted,
            allowed=allowed,
        )

    def _auto_repair_view(self, key: str, record: PatrolRecord | None) -> AutoRepairView:
        kind = self._kind_for(key, None)
        launch = self._launch_record(key)
        # 脚本、程序和后台服务要见过它正常运行、有记录才有现成修法；
        # Windows 服务还要主人允许 Agent 启停它；以管理员身份运行的程序修不了。
        if kind is RepairKind.RESTART_CONTAINERS:
            available = True
        elif kind is RepairKind.RESTART_WINDOWS_SERVICE:
            service = self._windows_service_view(key)
            available = service is not None and service.granted
        elif isinstance(launch, ProgramLaunchRecord):
            available = not launch.elevated
        else:
            available = kind is not None and launch is not None
        return AutoRepairView(
            available=available,
            kind=kind if available else None,
            enabled=record.auto_repair_enabled if record is not None else False,
            enabled_on=record.auto_repair_enabled_on if record is not None else None,
            paused=record.auto_repair_paused if record is not None else False,
            last_attempt_at=record.last_auto_repair_at if record is not None else None,
            last_result=record.last_auto_repair_result if record is not None else None,
            stuck_available=available,
            stuck_enabled=record.auto_repair_stuck_enabled if record is not None else False,
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
                    repair_refusal=record.repair_refusal,
                    manual_steps=record.manual_steps,
                    auto_repair=self._auto_repair_view(key, records.get(key)),
                    windows_service=self._windows_service_view(key),
                )
            )
        used = self._store.investigations_on(self._clock().astimezone().date())
        return PatrolView(
            checked_at=self._checked_at,
            investigations_left_today=max(0, PATROL_DAILY_INVESTIGATIONS - used),
            services=tuple(values),
        )

    def set_auto_repair(self, key: str, *, enabled: bool, stuck: bool | None = None) -> PatrolView:
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
                    "auto_repair_stuck_enabled": enabled
                    and (record.auto_repair_stuck_enabled if stuck is None else stuck),
                }
            )
        )
        logger.info("巡检：%s 的“挂了可以自动修”已%s", key, "打开" if enabled else "关闭")
        return self.view()

    async def set_windows_service_grant(self, key: str, *, granted: bool) -> PatrolView:
        """弹一次管理员确认，允许或撤回 Agent 启停这个 Windows 服务。

        不是 Windows 服务抛 `KeyError`；授予时服务没标成"是我的服务"或在保护名单里抛
        `LookupError`；主人在确认框里拒绝时抛 `PermissionError`。撤回总是允许，并一并关掉
        这个服务的自动修。
        """
        record = self._launch_record(key)
        if not isinstance(record, WindowsServiceRecord) or self._windows_services is None:
            raise KeyError(key)
        if granted and not self._windows_service_allowed(
            key, self._windows_services.inspect(record.service_name)
        ):
            raise LookupError(key)
        if not await self._windows_services.set_granted(record.service_name, granted=granted):
            raise PermissionError(key)
        patrol = self._store.get(key)
        if not granted and patrol is not None and patrol.auto_repair_enabled:
            self.set_auto_repair(key, enabled=False)
        logger.info("巡检：%s 的 Windows 服务启停权限已%s", key, "授予" if granted else "撤回")
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
