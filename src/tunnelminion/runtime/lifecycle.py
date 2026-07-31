"""手工 start/status/stop 的进程所有权与失败隔离内核。"""

from __future__ import annotations

import hashlib
import math
import time
from collections.abc import Callable
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import Protocol
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict

from tunnelminion.runtime.process import (
    ComponentLifecycle,
    ProcessAdapter,
    ProcessRecordRepository,
    ProcessSnapshot,
    RuntimeOperationLock,
    RuntimeProcessRecord,
)
from tunnelminion.runtime.profile import RuntimeComponent, RuntimePaths, RuntimeProfile


class ComponentRuntimeState(StrEnum):
    """用户可见的逐组件运行状态。"""

    RUNNING = "running"
    STOPPED = "stopped"
    FAILED = "failed"
    STALE = "stale"
    OWNERSHIP_CONFLICT = "ownership-conflict"


class OverallRuntimeState(StrEnum):
    """两个独立组件的汇总状态。"""

    RUNNING = "running"
    STOPPED = "stopped"
    DEGRADED = "degraded"
    FAILED = "failed"


class ComponentRuntimeStatus(BaseModel):
    """脱敏的逐组件状态。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    component: RuntimeComponent
    state: ComponentRuntimeState
    pid: int | None = None
    instance_id: UUID | None = None
    application_version: str | None = None
    process_started_at: float | None = None
    recorded_at: datetime | None = None
    executable_sha256: str | None = None
    data_dir_sha256: str | None = None
    error_code: str | None = None
    process_present: bool = False


class LifecycleReport(BaseModel):
    """手工生命周期操作的稳定结果与退出码。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    state: OverallRuntimeState
    components: tuple[ComponentRuntimeStatus, ...]
    exit_code: int


class ComponentHealthProbe(Protocol):
    """逐组件有界健康探针。"""

    def healthy(self, component: RuntimeComponent, pid: int) -> bool: ...


class AlwaysHealthyProbe:
    """供尚未接线组件健康端点时使用的进程存活探针。"""

    def healthy(self, component: RuntimeComponent, pid: int) -> bool:
        del component, pid
        return True


CommandFactory = Callable[[RuntimeComponent, UUID], tuple[str, ...]]
CheckpointProbe = Callable[[RuntimeComponent, RuntimeProcessRecord], bool]


class ComponentLaunchError(RuntimeError):
    """命令生成前发现的稳定逐组件启动错误。"""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _checkpoint_always_ready(component: RuntimeComponent, record: RuntimeProcessRecord) -> bool:
    del component, record
    return True


class ManualLifecycleManager:
    """对已启用组件执行幂等、所有权安全的手工生命周期操作。"""

    def __init__(
        self,
        profile: RuntimeProfile,
        paths: RuntimePaths,
        application_version: str,
        adapter: ProcessAdapter,
        command_factory: CommandFactory,
        *,
        health: ComponentHealthProbe | None = None,
        checkpoint_ready: CheckpointProbe | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._profile = profile
        self._paths = paths
        self._application_version = application_version
        self._adapter = adapter
        self._command_factory = command_factory
        self._health = health or AlwaysHealthyProbe()
        self._checkpoint_ready = checkpoint_ready or _checkpoint_always_ready
        self._sleep = sleep
        self._records = ProcessRecordRepository(paths.state_dir)

    def start(self) -> LifecycleReport:
        """逐组件幂等启动，部分失败时保留已经健康的另一组件。"""
        with RuntimeOperationLock(self._paths.state_dir):
            statuses = tuple(self._start_component(component) for component in self._components())
        return self._report(statuses, desired=ComponentRuntimeState.RUNNING)

    def status(self) -> LifecycleReport:
        """联合进程记录与实时身份返回 fail-closed 状态。"""
        with RuntimeOperationLock(self._paths.state_dir):
            statuses = tuple(self._status_component(component) for component in self._components())
        return self._report(statuses)

    def stop(self) -> LifecycleReport:
        """只正常终止可证明归属的进程，不执行强杀。"""
        with RuntimeOperationLock(self._paths.state_dir):
            statuses = tuple(self._stop_component(component) for component in self._components())
        return self._report(statuses, desired=ComponentRuntimeState.STOPPED)

    def _components(self) -> tuple[RuntimeComponent, ...]:
        return tuple(sorted(self._profile.enabled_components))

    def _start_component(self, component: RuntimeComponent) -> ComponentRuntimeStatus:
        current = self._status_component(component)
        if current.state is ComponentRuntimeState.RUNNING:
            return current
        if current.process_present or current.state is ComponentRuntimeState.OWNERSHIP_CONFLICT:
            return current

        instance_id = uuid4()
        try:
            command = self._command_factory(component, instance_id)
            snapshot = self._adapter.spawn(
                command,
                self._paths.log_dir / f"{component.value}.log",
            )
            record = RuntimeProcessRecord.starting(
                component,
                snapshot,
                self._application_version,
                self._paths.data_dir,
                instance_id,
            )
            self._records.save(record)
        except ComponentLaunchError as exc:
            return ComponentRuntimeStatus(
                component=component,
                state=ComponentRuntimeState.FAILED,
                error_code=exc.code,
            )
        except (OSError, RuntimeError, ValueError):
            return ComponentRuntimeStatus(
                component=component,
                state=ComponentRuntimeState.FAILED,
                error_code="spawn_failed",
            )

        if not self._stable(record):
            failed = record.model_copy(
                update={"lifecycle": ComponentLifecycle.FAILED, "error_code": "startup_unstable"}
            )
            self._records.save(failed)
            snapshot = self._adapter.inspect(record.pid)
            return self._view(failed, ComponentRuntimeState.FAILED, snapshot is not None)

        running = record.model_copy(update={"lifecycle": ComponentLifecycle.RUNNING})
        self._records.save(running)
        return self._view(running, ComponentRuntimeState.RUNNING, True)

    def _stable(self, record: RuntimeProcessRecord) -> bool:
        interval = 0.1
        attempts = max(
            1,
            math.ceil(self._profile.budgets.startup_timeout_seconds / interval),
        )
        for _attempt in range(attempts):
            if not self._is_owned(record, self._adapter.inspect(record.pid)):
                return False
            if self._health.healthy(record.component, record.pid):
                self._sleep(self._profile.budgets.stable_window_seconds)
                return self._is_owned(
                    record, self._adapter.inspect(record.pid)
                ) and self._health.healthy(record.component, record.pid)
            self._sleep(interval)
        return False

    def _status_component(self, component: RuntimeComponent) -> ComponentRuntimeStatus:
        try:
            record = self._records.load(component)
        except (OSError, ValueError):
            return ComponentRuntimeStatus(
                component=component,
                state=ComponentRuntimeState.FAILED,
                error_code="process_record_invalid",
            )
        if record is None:
            return ComponentRuntimeStatus(component=component, state=ComponentRuntimeState.STOPPED)
        if record.lifecycle is ComponentLifecycle.STOPPED:
            return self._view(record, ComponentRuntimeState.STOPPED, False)

        snapshot = self._adapter.inspect(record.pid)
        if snapshot is None or not snapshot.running:
            state = (
                ComponentRuntimeState.FAILED
                if record.lifecycle is ComponentLifecycle.FAILED
                else ComponentRuntimeState.STALE
            )
            return self._view(record, state, False)
        if not self._is_owned(record, snapshot):
            return self._view(record, ComponentRuntimeState.OWNERSHIP_CONFLICT, True)
        if record.lifecycle is ComponentLifecycle.FAILED:
            return self._view(record, ComponentRuntimeState.FAILED, True)
        if not self._health.healthy(component, record.pid):
            return self._view(record, ComponentRuntimeState.FAILED, True, "health_failed")
        return self._view(record, ComponentRuntimeState.RUNNING, True)

    def _stop_component(self, component: RuntimeComponent) -> ComponentRuntimeStatus:
        current = self._status_component(component)
        if current.state is ComponentRuntimeState.STOPPED:
            return current
        if current.state in {
            ComponentRuntimeState.STALE,
            ComponentRuntimeState.OWNERSHIP_CONFLICT,
        }:
            return current
        record = self._records.load(component)
        if record is None or not current.process_present:
            return current
        snapshot = self._adapter.inspect(record.pid)
        if not self._is_owned(record, snapshot):
            return self._view(
                record, ComponentRuntimeState.OWNERSHIP_CONFLICT, snapshot is not None
            )
        try:
            self._adapter.terminate(record.pid)
        except OSError:
            failed = record.model_copy(
                update={"lifecycle": ComponentLifecycle.FAILED, "error_code": "terminate_failed"}
            )
            self._records.save(failed)
            return self._view(failed, ComponentRuntimeState.FAILED, True)
        if not self._adapter.wait(record.pid, self._profile.budgets.shutdown_timeout_seconds):
            failed = record.model_copy(
                update={"lifecycle": ComponentLifecycle.FAILED, "error_code": "stop_timeout"}
            )
            self._records.save(failed)
            return self._view(failed, ComponentRuntimeState.FAILED, True)
        if not self._checkpoint_ready(component, record):
            failed = record.model_copy(
                update={"lifecycle": ComponentLifecycle.FAILED, "error_code": "checkpoint_missing"}
            )
            self._records.save(failed)
            return self._view(failed, ComponentRuntimeState.FAILED, False)
        stopped = record.model_copy(
            update={"lifecycle": ComponentLifecycle.STOPPED, "error_code": None}
        )
        self._records.save(stopped)
        return self._view(stopped, ComponentRuntimeState.STOPPED, False)

    def _is_owned(self, record: RuntimeProcessRecord, snapshot: ProcessSnapshot | None) -> bool:
        if snapshot is None or not snapshot.running:
            return False
        if snapshot.process_started_at is None or snapshot.executable is None:
            return False
        if abs(snapshot.process_started_at - record.process_started_at) > 0.01:
            return False
        if Path(snapshot.executable).resolve() != record.executable.resolve():
            return False
        if snapshot.command_line is None:
            return False
        expected = {
            f"--runtime-component={record.component.value}",
            f"--runtime-instance-id={record.instance_id}",
        }
        if not expected.issubset(snapshot.command_line):
            return False
        digest = hashlib.sha256(str(self._paths.data_dir.resolve()).encode()).hexdigest()
        return record.data_dir_sha256 == digest

    @staticmethod
    def _view(
        record: RuntimeProcessRecord,
        state: ComponentRuntimeState,
        process_present: bool,
        error_code: str | None = None,
    ) -> ComponentRuntimeStatus:
        return ComponentRuntimeStatus(
            component=record.component,
            state=state,
            pid=record.pid,
            instance_id=record.instance_id,
            application_version=record.application_version,
            process_started_at=record.process_started_at,
            recorded_at=record.recorded_at,
            executable_sha256=hashlib.sha256(str(record.executable).encode()).hexdigest(),
            data_dir_sha256=record.data_dir_sha256,
            error_code=error_code or record.error_code,
            process_present=process_present,
        )

    @staticmethod
    def _report(
        statuses: tuple[ComponentRuntimeStatus, ...],
        desired: ComponentRuntimeState | None = None,
    ) -> LifecycleReport:
        states = {item.state for item in statuses}
        if states == {ComponentRuntimeState.RUNNING}:
            overall = OverallRuntimeState.RUNNING
        elif states == {ComponentRuntimeState.STOPPED}:
            overall = OverallRuntimeState.STOPPED
        elif ComponentRuntimeState.RUNNING in states or ComponentRuntimeState.STOPPED in states:
            overall = OverallRuntimeState.DEGRADED
        else:
            overall = OverallRuntimeState.FAILED
        acceptable = (
            all(
                item.state in {ComponentRuntimeState.RUNNING, ComponentRuntimeState.STOPPED}
                for item in statuses
            )
            if desired is None
            else all(item.state is desired for item in statuses)
        )
        exit_code = 0 if acceptable else 1
        return LifecycleReport(state=overall, components=statuses, exit_code=exit_code)
