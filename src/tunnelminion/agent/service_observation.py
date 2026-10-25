"""把平台只读适配器转换为有界、完整的 Coordinator 服务快照。"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
from collections.abc import Callable, Mapping
from contextlib import suppress
from datetime import UTC, datetime
from typing import Protocol, cast

from pydantic import BaseModel, ConfigDict, Field, JsonValue

from tunnelminion.agent.managed_node import ServiceObservationConfig
from tunnelminion.agent.service_marks import ServiceMark, service_mark_keys
from tunnelminion.agent.service_tiers import ServiceTier, decide_tier
from tunnelminion.agent.services import (
    EvidenceConfidence,
    RemoteServiceInventoryBuilder,
    RemoteServiceSummary,
    ServiceApplication,
    ToolObservation,
)
from tunnelminion.agent.services import (
    ServiceAccessibility as InventoryAccessibility,
)
from tunnelminion.coordinator.contracts import (
    ServiceAccessibility,
    ServiceProtocol,
    ServiceSummary,
)
from tunnelminion.domain.identifiers import NodeId, ServiceId, ToolRunId
from tunnelminion.platforms.python_entrypoint import is_python_process
from tunnelminion.platforms.windows.models import Availability, CollectionResult
from tunnelminion.tools.contracts import ToolCancellationToken, ToolExecutionStatus


class CollectionAdapter(Protocol):
    """Windows/macOS 现有列表适配器的只读执行边界。"""

    async def execute(
        self,
        arguments: dict[str, JsonValue],
        cancellation: ToolCancellationToken,
    ) -> JsonValue: ...


class ServiceObservationError(RuntimeError):
    """不携带平台输出正文的稳定服务观察错误。"""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class ServiceObservationSnapshot(BaseModel):
    """只有完整性可证明时才会交给 Coordinator 的快照。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    observed_at: datetime
    services: tuple[ServiceSummary, ...]
    display_names: dict[str, str] = Field(default_factory=dict, exclude=True)
    applications: dict[str, ServiceApplication] = Field(default_factory=dict, exclude=True)
    # "可能是服务"：等待用户一键确认；界面接入前只在本机保存，不对外输出。
    review_names: dict[str, str] = Field(default_factory=dict, exclude=True)
    # 合并后的端口清单：用户改了标记时据此立即重新分档，不必等下一轮观察。
    inventory: tuple[RemoteServiceSummary, ...] = Field(default=(), exclude=True)
    degraded_sources: tuple[str, ...] = ()
    disabled_sources: tuple[str, ...] = ()
    complete: bool = True


class ServiceObservationStatus(BaseModel):
    """资源页可显示的脱敏观察状态。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    service_count: int = Field(default=0, ge=0, le=1024)
    last_success_at: datetime | None = None
    last_error_code: str | None = Field(default=None, min_length=1, max_length=128)
    degraded_sources: tuple[str, ...] = ()
    disabled_sources: tuple[str, ...] = ()


def compute_observed_service_id(
    node_id: NodeId,
    protocol: ServiceProtocol,
    host: str,
    port: int,
) -> ServiceId:
    """按观察层实际持久化的传输端点生成稳定服务身份。"""
    canonical_host = "wildcard" if host in {"0.0.0.0", "::"} else host.lower()
    digest = hashlib.sha256(f"{node_id}:{protocol}:{canonical_host}:{port}".encode()).hexdigest()[
        :32
    ]
    return ServiceId(f"service_{digest}")


def compute_static_peer_service_id(node_id: NodeId, port: int) -> ServiceId:
    """显式静态对端按逻辑 TCP 端口定身份，地址变化不改变身份。"""
    digest = hashlib.sha256(f"static-peer:{node_id}:tcp:{port}".encode()).hexdigest()[:32]
    return ServiceId(f"service_{digest}")


def service_tier(
    item: RemoteServiceSummary,
    marks: Mapping[str, ServiceMark] | None = None,
    *,
    key: str | None = None,
) -> ServiceTier:
    """按来历和监听方式给一个端口分档，规则见 `decide_tier`；用户的标记优先。

    `key` 是这个端口的服务身份，由 `service_mark_keys` 按整份清单算出；没有时不看标记。
    """
    mark = marks.get(key) if marks and key is not None else None
    if mark is ServiceMark.HIDDEN:
        return ServiceTier.HIDE
    if mark is ServiceMark.MINE and (item.protocol == "tcp" or item.container_running is not None):
        return ServiceTier.SHOW
    if item.container_running is not None and not (item.container_name or "").strip():
        # 没有可用名字的容器无法让用户认出来。
        return ServiceTier.HIDE
    return decide_tier(
        protocol=item.protocol,
        address=item.address,
        # 没有进程号时名字无法对应到真实进程，不能单凭名字判断。
        process_name=item.process_name if item.process_pid is not None else None,
        origin=item.origin,
        container_running=item.container_running,
        has_web_page=item.has_web_page,
    )


def _application_id(node_id: NodeId, kind: str, key: str) -> str:
    return "application_" + hashlib.sha256(f"{node_id}:{kind}:{key}".encode()).hexdigest()[:32]


def _program_name(item: RemoteServiceSummary) -> str:
    # 网页标题最能说明这是什么，其次才是程序名。
    raw = (item.web_title or item.program_name or item.process_name or "").strip()
    name = raw[:-4] if raw.lower().endswith(".exe") else raw
    return name[:80] or "程序"


def service_presentation(
    node_id: NodeId, item: RemoteServiceSummary
) -> tuple[str, str, ServiceApplication | None]:
    """返回（用于判断归属冲突的完整名称, 显示名称, 所属应用）。"""
    if item.container_running is not None:
        # 同一 compose 项目的多个容器合并成一项；没有项目时按单个容器。
        group = (item.compose_project or item.container_name or "").strip()
        name = f"Docker · {group[:55]} · {item.port}"
        key = (
            f"compose:{item.compose_project}"
            if item.compose_project
            else (item.container_id or "").strip()
        )
        application = (
            ServiceApplication(
                group_id=_application_id(node_id, "docker", key), name=group[:80], kind="docker"
            )
            if key
            else None
        )
        return name, name, application
    if is_python_process(item.process_name):
        entry = item.python_entrypoint
        short = entry[:54] + "…" if entry and len(entry) > 55 else entry
        if item.web_title:
            name = label = f"{item.web_title} · {item.port}"
        else:
            name = f"Python · {entry} · {item.port}" if entry else f"Python 服务 · {item.port}"
            label = f"Python · {short} · {item.port}" if short else name
        application = (
            ServiceApplication(
                group_id=_application_id(node_id, "python", str(item.process_pid)),
                name=item.web_title or item.python_project_name or entry or "Python 程序",
                kind="python",
            )
            if item.process_pid is not None
            else None
        )
        return name, label, application
    program = _program_name(item)
    name = f"{program} · {item.port}"
    application = (
        ServiceApplication(
            group_id=_application_id(node_id, "program", str(item.process_pid)),
            name=program,
            kind="program",
        )
        if item.process_pid is not None
        else None
    )
    return name, name, application


def select_review_services(
    node_id: NodeId,
    services: tuple[RemoteServiceSummary, ...],
    *,
    excluded_pid: int | None = None,
    marks: Mapping[str, ServiceMark] | None = None,
) -> dict[str, str]:
    """ "可能是服务"：看不出是不是服务、需要用户一键确认的端口。"""
    return {
        str(
            compute_observed_service_id(
                node_id, ServiceProtocol(item.protocol), item.address, item.port
            )
        ): (service_presentation(node_id, item)[1])
        for item, key in zip(services, service_mark_keys(services), strict=True)
        if (excluded_pid is None or item.process_pid != excluded_pid)
        and service_tier(item, marks, key=key) is ServiceTier.REVIEW
    }


def select_service_presentations(
    node_id: NodeId,
    services: tuple[RemoteServiceSummary, ...],
    *,
    excluded_pid: int | None = None,
    marks: Mapping[str, ServiceMark] | None = None,
) -> tuple[dict[str, str], dict[str, ServiceApplication]]:
    """首页直接显示的服务：只按来历和容器归属判断，不按程序名写特例。"""
    names: dict[str, set[str]] = {}
    labels: dict[str, str] = {}
    applications: dict[str, set[ServiceApplication | None]] = {}
    for item, key in zip(services, service_mark_keys(services), strict=True):
        if excluded_pid is not None and item.process_pid == excluded_pid:
            continue
        if service_tier(item, marks, key=key) is not ServiceTier.SHOW:
            continue
        name, label, application = service_presentation(node_id, item)
        service_id = compute_observed_service_id(
            node_id, ServiceProtocol(item.protocol), item.address, item.port
        )
        names.setdefault(str(service_id), set()).add(name)
        # 显示裁剪不参与归属冲突判定。
        labels[str(service_id)] = label
        applications.setdefault(str(service_id), set()).add(application)
    selected_names = {
        service_id: labels[service_id] for service_id, values in names.items() if len(values) == 1
    }
    selected_applications = {
        service_id: application
        for service_id, values in applications.items()
        if service_id in selected_names
        and len(values) == 1
        and (application := next(iter(values))) is not None
    }
    return selected_names, selected_applications


def apply_service_marks(
    node_id: NodeId,
    snapshot: ServiceObservationSnapshot,
    marks: Mapping[str, ServiceMark],
    *,
    excluded_pid: int | None = None,
) -> ServiceObservationSnapshot:
    """按最新标记重新算出首页名称、应用分组和"可能是服务"，端口事实不变。"""
    names, applications = select_service_presentations(
        node_id, snapshot.inventory, excluded_pid=excluded_pid, marks=marks
    )
    return snapshot.model_copy(
        update={
            "display_names": names,
            "applications": applications,
            "review_names": select_review_services(
                node_id, snapshot.inventory, excluded_pid=excluded_pid, marks=marks
            ),
        }
    )


class DeterministicServiceObserver:
    """固定顺序采集监听、进程和 Docker，并拒绝部分或超预算快照。"""

    def __init__(
        self,
        node_id: NodeId,
        config: ServiceObservationConfig,
        listeners: CollectionAdapter,
        processes: CollectionAdapter,
        docker: CollectionAdapter,
        *,
        clock: Callable[[], datetime] | None = None,
        marks: Callable[[], Mapping[str, ServiceMark]] | None = None,
        launch_recorder: Callable[
            [tuple[RemoteServiceSummary, ...], Mapping[str, ServiceMark]], object
        ]
        | None = None,
    ) -> None:
        self._node_id = node_id
        self._marks = marks
        self._launch_recorder = launch_recorder
        self._config = config
        self._listeners = listeners
        self._processes = processes
        self._docker = docker
        self._clock = clock or (lambda: datetime.now(UTC))
        self._lock = asyncio.Lock()
        self._last_observed_at: datetime | None = None
        self._last_snapshot: ServiceObservationSnapshot | None = None
        self._status = ServiceObservationStatus(disabled_sources=self._disabled_sources())

    @property
    def status(self) -> ServiceObservationStatus:
        return self._status

    @property
    def last_snapshot(self) -> ServiceObservationSnapshot | None:
        return self._last_snapshot

    @property
    def interval_seconds(self) -> float:
        return self._config.interval_seconds

    async def observe(self) -> ServiceObservationSnapshot:
        if self._lock.locked():
            raise ServiceObservationError("concurrency_limited", "服务观察已在运行")
        async with self._lock:
            now = self._now()
            if (
                self._last_observed_at is not None
                and (now - self._last_observed_at).total_seconds() < self._config.interval_seconds
            ):
                raise ServiceObservationError("refresh_limited", "服务观察刷新过于频繁")
            try:
                async with asyncio.timeout(self._config.timeout_seconds):
                    listener = await self._collect(
                        "list_network_listeners",
                        self._listeners,
                        self._config.listeners_enabled,
                        arguments={
                            "include_python_entrypoint": True,
                            "include_program_names": True,
                            "include_python_project_name": True,
                            "include_process_origin": True,
                            "include_web_title": True,
                        },
                    )
                    process = await self._collect(
                        "get_process_summary",
                        self._processes,
                        self._config.processes_enabled,
                        arguments={"limit": self._config.max_services},
                    )
                    docker = await self._collect_docker()
                inventory = RemoteServiceInventoryBuilder().build(
                    self._node_id, listener, process, docker
                )
                services = self._summaries(inventory.services)
                self._validate_budget(services)
                marks: Mapping[str, ServiceMark] = self._marks() if self._marks is not None else {}
                snapshot = apply_service_marks(
                    self._node_id,
                    ServiceObservationSnapshot(
                        observed_at=now,
                        services=services,
                        inventory=inventory.services,
                        degraded_sources=inventory.unavailable_sources,
                        disabled_sources=self._disabled_sources(),
                    ),
                    marks,
                    excluded_pid=os.getpid(),
                )
            except TimeoutError as exc:
                self._mark_failure("observation_timeout")
                raise ServiceObservationError("observation_timeout", "服务观察超时") from exc
            except ServiceObservationError as exc:
                self._mark_failure(exc.code)
                raise
            except Exception as exc:
                self._mark_failure("observation_failed")
                raise ServiceObservationError("observation_failed", "无法证明服务快照完整") from exc
            self._last_observed_at = now
            self._last_snapshot = snapshot
            self._status = ServiceObservationStatus(
                service_count=len(services),
                last_success_at=now,
                degraded_sources=snapshot.degraded_sources,
                disabled_sources=snapshot.disabled_sources,
            )
            if self._launch_recorder is not None:
                with suppress(Exception):
                    await asyncio.to_thread(self._launch_recorder, snapshot.inventory, marks)
            return snapshot

    async def _collect(
        self,
        name: str,
        adapter: CollectionAdapter,
        enabled: bool,
        *,
        arguments: dict[str, JsonValue] | None = None,
    ) -> ToolObservation:
        if not enabled:
            output = CollectionResult(availability=Availability.AVAILABLE).model_dump(mode="json")
        else:
            output = await adapter.execute(arguments or {}, ToolCancellationToken())
        return ToolObservation(
            tool_name=name,
            tool_run_id=ToolRunId.new(),
            observed_at=self._now(),
            status=ToolExecutionStatus.SUCCESS,
            output=cast(JsonValue, output),
        )

    async def _collect_docker(self) -> ToolObservation:
        if not self._config.docker_enabled:
            return await self._collect("list_docker_services", self._docker, enabled=False)
        try:
            return await self._collect("list_docker_services", self._docker, enabled=True)
        except asyncio.CancelledError:
            raise
        except Exception:
            return ToolObservation(
                tool_name="list_docker_services",
                tool_run_id=ToolRunId.new(),
                observed_at=self._now(),
                status=ToolExecutionStatus.SUCCESS,
                output=cast(
                    JsonValue,
                    CollectionResult(
                        availability=Availability.UNAVAILABLE,
                        error_code="dependency_unavailable",
                    ).model_dump(mode="json"),
                ),
            )

    def _summaries(self, services: tuple[RemoteServiceSummary, ...]) -> tuple[ServiceSummary, ...]:
        values: dict[str, ServiceSummary] = {}
        for value in services:
            item = value
            protocol = ServiceProtocol.UDP if item.protocol == "udp" else ServiceProtocol.TCP
            service_id = compute_observed_service_id(
                self._node_id,
                protocol,
                item.address,
                item.port,
            )
            candidate = ServiceSummary(
                service_id=service_id,
                protocol=protocol,
                host=item.address,
                port=item.port,
                accessibility=self._accessibility(item.accessibility),
                source="+".join(evidence.tool_name for evidence in item.evidence),
                confidence=self._confidence(item.confidence),
                observed_at=item.evidence[0].observed_at,
            )
            existing = values.get(str(service_id))
            if existing is None or candidate.confidence > existing.confidence:
                values[str(service_id)] = candidate
        return tuple(
            sorted(values.values(), key=lambda item: (item.port, item.protocol, item.host))
        )

    def _validate_budget(self, services: tuple[ServiceSummary, ...]) -> None:
        if len(services) > self._config.max_services:
            raise ServiceObservationError("snapshot_too_large", "服务数量超过预算")
        encoded = json.dumps(
            [item.model_dump(mode="json") for item in services],
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        if len(encoded) > self._config.max_snapshot_bytes:
            raise ServiceObservationError("snapshot_too_large", "服务快照字节数超过预算")

    def _disabled_sources(self) -> tuple[str, ...]:
        return tuple(
            name
            for name, enabled in (
                ("list_network_listeners", self._config.listeners_enabled),
                ("get_process_summary", self._config.processes_enabled),
                ("list_docker_services", self._config.docker_enabled),
                ("active_probe", self._config.active_probe_enabled),
            )
            if not enabled
        )

    def _mark_failure(self, code: str) -> None:
        self._status = self._status.model_copy(update={"last_error_code": code})

    def _now(self) -> datetime:
        value = self._clock()
        if value.tzinfo is None:
            raise ServiceObservationError("invalid_clock", "服务观察时钟必须包含时区")
        return value

    @staticmethod
    def _accessibility(value: InventoryAccessibility) -> ServiceAccessibility:
        return (
            ServiceAccessibility.LOOPBACK
            if value is InventoryAccessibility.LOCAL_ONLY
            else ServiceAccessibility.NETWORK
            if value is InventoryAccessibility.NETWORK_LISTENING
            else ServiceAccessibility.UNKNOWN
        )

    @staticmethod
    def _confidence(value: EvidenceConfidence) -> float:
        return {
            EvidenceConfidence.HIGH: 0.95,
            EvidenceConfidence.MEDIUM: 0.75,
            EvidenceConfidence.LOW: 0.5,
        }[value]
