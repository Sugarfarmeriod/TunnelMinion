"""把平台只读适配器转换为有界、完整的 Coordinator 服务快照。"""

from __future__ import annotations

import asyncio
import hashlib
import json
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Protocol, cast

from pydantic import BaseModel, ConfigDict, Field, JsonValue

from tunnelminion.agent.managed_node import ServiceObservationConfig
from tunnelminion.agent.services import (
    EvidenceConfidence,
    RemoteServiceInventoryBuilder,
    RemoteServiceSummary,
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
    ) -> None:
        self._node_id = node_id
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
                snapshot = ServiceObservationSnapshot(
                    observed_at=now,
                    services=services,
                    degraded_sources=inventory.unavailable_sources,
                    disabled_sources=self._disabled_sources(),
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
            service_id = self._service_id(protocol, item.address, item.port)
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

    def _service_id(self, protocol: ServiceProtocol, host: str, port: int) -> ServiceId:
        canonical_host = "wildcard" if host in {"0.0.0.0", "::"} else host.lower()
        digest = hashlib.sha256(
            f"{self._node_id}:{protocol}:{canonical_host}:{port}".encode()
        ).hexdigest()[:32]
        return ServiceId(f"service_{digest}")

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
