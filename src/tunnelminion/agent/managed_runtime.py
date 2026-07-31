"""managed node 后台域的监督、停止与非秘密恢复边界。"""

from __future__ import annotations

import asyncio
import os
import re
from collections.abc import AsyncGenerator, Callable, Sequence
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Protocol, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

MANAGED_RUNTIME_CHECKPOINT_VERSION = "managed-runtime/v1"
MANAGED_RUNTIME_CHECKPOINT_FILE = "managed-runtime.json"
_SAFE_ERROR_CODE = re.compile(r"^[a-z][a-z0-9_]{0,127}$")


class ManagedRuntimeDomain(StrEnum):
    """彼此隔离的 managed node 后台故障域。"""

    DIRECTORY = "directory"
    SERVICES = "services"
    MANAGED_CONFIG = "managed-config"


class ManagedRuntimePhase(StrEnum):
    """整个监督器的生命周期阶段。"""

    STOPPED = "stopped"
    RUNNING = "running"
    STOPPING = "stopping"
    DEGRADED = "degraded"


class ManagedLoopPhase(StrEnum):
    """单个后台域的监督阶段。"""

    STOPPED = "stopped"
    RUNNING = "running"
    BACKOFF = "backoff"
    DEGRADED = "degraded"


class ManagedLoopStatus(BaseModel):
    """不含异常正文和秘密的单域状态。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    domain: ManagedRuntimeDomain
    phase: ManagedLoopPhase = ManagedLoopPhase.STOPPED
    restart_count: int = Field(default=0, ge=0)
    consecutive_failures: int = Field(default=0, ge=0)
    last_error_code: str | None = Field(default=None, min_length=1, max_length=128)
    next_backoff_seconds: float = Field(default=0, ge=0)


class ManagedNodeRuntimeStatus(BaseModel):
    """资源页可直接消费的脱敏运行时聚合状态。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    phase: ManagedRuntimePhase = ManagedRuntimePhase.STOPPED
    loops: tuple[ManagedLoopStatus, ...]
    last_error_code: str | None = Field(default=None, min_length=1, max_length=128)


class ManagedNodeRuntimeCheckpoint(BaseModel):
    """原子保存的非秘密监督状态。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = MANAGED_RUNTIME_CHECKPOINT_VERSION
    phase: ManagedRuntimePhase
    loops: tuple[ManagedLoopStatus, ...]
    updated_at: datetime

    @model_validator(mode="after")
    def validate_contract(self) -> Self:
        if self.schema_version != MANAGED_RUNTIME_CHECKPOINT_VERSION:
            raise ValueError("managed runtime checkpoint 版本不受支持")
        if self.updated_at.tzinfo is None:
            raise ValueError("managed runtime checkpoint 时间必须包含时区")
        return self


class ManagedNodeLoop(Protocol):
    """真实同步器和测试 fake 共享的最小可取消循环。"""

    @property
    def domain(self) -> ManagedRuntimeDomain: ...

    async def run(self, stop: asyncio.Event) -> None: ...

    async def checkpoint(self) -> None: ...


class FileManagedRuntimeCheckpointRepository:
    """以原子替换读写监督器 checkpoint。"""

    def __init__(self, path: Path) -> None:
        self._path = path

    def load(self) -> ManagedNodeRuntimeCheckpoint | None:
        if not self._path.exists():
            return None
        return ManagedNodeRuntimeCheckpoint.model_validate_json(
            self._path.read_text(encoding="utf-8")
        )

    def save(self, checkpoint: ManagedNodeRuntimeCheckpoint) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self._path.with_suffix(f"{self._path.suffix}.tmp")
        temporary.write_text(checkpoint.model_dump_json(indent=2), encoding="utf-8")
        if os.name != "nt":
            os.chmod(temporary, 0o600)
        temporary.replace(self._path)


class ManagedNodeRuntime:
    """以有界重启和停止超时监督多个互不依赖的后台域。"""

    def __init__(
        self,
        loops: Sequence[ManagedNodeLoop],
        checkpoint_repository: FileManagedRuntimeCheckpointRepository,
        *,
        max_restarts: int = 3,
        base_backoff_seconds: float = 1,
        max_backoff_seconds: float = 30,
        stop_timeout_seconds: float = 10,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        domains = tuple(loop.domain for loop in loops)
        if len(set(domains)) != len(domains):
            raise ValueError("managed runtime 后台域不得重复")
        if max_restarts < 0:
            raise ValueError("最大重启次数不得为负数")
        if base_backoff_seconds <= 0 or max_backoff_seconds < base_backoff_seconds:
            raise ValueError("managed runtime 退避预算无效")
        if stop_timeout_seconds <= 0:
            raise ValueError("managed runtime 停止超时必须为正数")
        self._loops = {loop.domain: loop for loop in loops}
        self._repository = checkpoint_repository
        self._max_restarts = max_restarts
        self._base_backoff_seconds = base_backoff_seconds
        self._max_backoff_seconds = max_backoff_seconds
        self._stop_timeout_seconds = stop_timeout_seconds
        self._clock = clock or (lambda: datetime.now(UTC))
        self._stop = asyncio.Event()
        self._tasks: dict[ManagedRuntimeDomain, asyncio.Task[None]] = {}
        self._last_error_code: str | None = None
        restored = checkpoint_repository.load()
        restored_by_domain = (
            {item.domain: item for item in restored.loops} if restored is not None else {}
        )
        self._statuses = {
            domain: ManagedLoopStatus(
                domain=domain,
                restart_count=restored_by_domain.get(
                    domain, ManagedLoopStatus(domain=domain)
                ).restart_count,
                last_error_code=(
                    "unclean_shutdown"
                    if restored is not None and restored.phase is not ManagedRuntimePhase.STOPPED
                    else restored_by_domain.get(
                        domain, ManagedLoopStatus(domain=domain)
                    ).last_error_code
                ),
            )
            for domain in domains
        }

    @property
    def status(self) -> ManagedNodeRuntimeStatus:
        statuses = tuple(self._statuses[domain] for domain in self._loops)
        if self._tasks and any(item.phase is ManagedLoopPhase.DEGRADED for item in statuses):
            phase = ManagedRuntimePhase.DEGRADED
        elif self._tasks:
            phase = (
                ManagedRuntimePhase.STOPPING if self._stop.is_set() else ManagedRuntimePhase.RUNNING
            )
        else:
            phase = ManagedRuntimePhase.STOPPED
        return ManagedNodeRuntimeStatus(
            phase=phase,
            loops=statuses,
            last_error_code=self._last_error_code,
        )

    async def start(self) -> None:
        """为每个域创建唯一受监督任务；重复启动 fail-closed。"""
        if self._tasks:
            raise RuntimeError("managed runtime 已启动")
        self._stop = asyncio.Event()
        self._last_error_code = None
        for domain, loop in self._loops.items():
            self._tasks[domain] = asyncio.create_task(
                self._supervise(loop),
                name=f"managed-node:{domain.value}",
            )
        try:
            self._persist()
        except Exception:
            self._last_error_code = "startup_failed"
            self._stop.set()
            for task in self._tasks.values():
                task.cancel()
            await asyncio.gather(*self._tasks.values(), return_exceptions=True)
            self._tasks.clear()
            raise

    async def stop(self) -> None:
        """阻止新轮次、等待安全点，并在超时后只取消监督任务。"""
        if not self._tasks:
            self._persist()
            return
        self._stop.set()
        tasks = tuple(self._tasks.values())
        try:
            async with asyncio.timeout(self._stop_timeout_seconds):
                await asyncio.gather(*tasks, return_exceptions=True)
        except TimeoutError:
            self._last_error_code = "stop_timeout"
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
        finally:
            self._tasks.clear()
            for domain, status in self._statuses.items():
                self._statuses[domain] = status.model_copy(
                    update={
                        "phase": ManagedLoopPhase.STOPPED,
                        "next_backoff_seconds": 0,
                    }
                )
            self._persist()

    async def _supervise(self, loop: ManagedNodeLoop) -> None:
        domain = loop.domain
        try:
            while not self._stop.is_set():
                current = self._statuses[domain]
                self._statuses[domain] = current.model_copy(
                    update={"phase": ManagedLoopPhase.RUNNING, "next_backoff_seconds": 0}
                )
                try:
                    await loop.run(self._stop)
                    if self._stop.is_set():
                        break
                    error_code = "unexpected_exit"
                except asyncio.CancelledError:
                    if self._stop.is_set():
                        break
                    current = self._statuses[domain]
                    self._statuses[domain] = current.model_copy(
                        update={
                            "phase": ManagedLoopPhase.DEGRADED,
                            "last_error_code": "loop_cancelled",
                        }
                    )
                    self._persist()
                    raise
                except Exception as exc:
                    error_code = self._stable_error_code(exc)
                current = self._statuses[domain]
                failures = current.consecutive_failures + 1
                if current.restart_count >= self._max_restarts:
                    self._statuses[domain] = current.model_copy(
                        update={
                            "phase": ManagedLoopPhase.DEGRADED,
                            "consecutive_failures": failures,
                            "last_error_code": error_code,
                            "next_backoff_seconds": 0,
                        }
                    )
                    self._persist()
                    await self._stop.wait()
                    break
                delay = min(
                    self._max_backoff_seconds,
                    self._base_backoff_seconds * (2**current.restart_count),
                )
                self._statuses[domain] = current.model_copy(
                    update={
                        "phase": ManagedLoopPhase.BACKOFF,
                        "restart_count": current.restart_count + 1,
                        "consecutive_failures": failures,
                        "last_error_code": error_code,
                        "next_backoff_seconds": delay,
                    }
                )
                self._persist()
                try:
                    await asyncio.wait_for(self._stop.wait(), timeout=delay)
                except TimeoutError:
                    continue
        finally:
            try:
                await loop.checkpoint()
            except Exception:
                self._statuses[domain] = self._statuses[domain].model_copy(
                    update={"last_error_code": "checkpoint_failed"}
                )

    def _persist(self) -> None:
        status = self.status
        self._repository.save(
            ManagedNodeRuntimeCheckpoint(
                phase=status.phase,
                loops=status.loops,
                updated_at=self._now(),
            )
        )

    def _now(self) -> datetime:
        value = self._clock()
        if value.tzinfo is None:
            raise ValueError("managed runtime 时钟必须包含时区")
        return value

    @staticmethod
    def _stable_error_code(exc: Exception) -> str:
        code = getattr(exc, "code", None)
        return (
            code if isinstance(code, str) and _SAFE_ERROR_CODE.fullmatch(code) else "loop_crashed"
        )


@asynccontextmanager
async def managed_node_lifespan(runtime: ManagedNodeRuntime) -> AsyncGenerator[None, None]:
    """供 Windows/macOS FastAPI 工厂复用的严格启停上下文。"""
    await runtime.start()
    try:
        yield
    finally:
        await runtime.stop()
