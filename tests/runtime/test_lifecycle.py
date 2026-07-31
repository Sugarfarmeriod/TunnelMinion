"""手工进程生命周期与所有权验证测试。"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from threading import Event, Thread
from uuid import UUID

import pytest
from pydantic import ValidationError

from tunnelminion.runtime.lifecycle import (
    ComponentLaunchError,
    ComponentRuntimeState,
    ManualLifecycleManager,
    OverallRuntimeState,
)
from tunnelminion.runtime.process import (
    ProcessRecordRepository,
    ProcessSnapshot,
    RuntimeOperationBusy,
    RuntimeOperationLock,
    RuntimeProcessRecord,
    runtime_identity_arguments,
)
from tunnelminion.runtime.profile import (
    RuntimeBudgets,
    RuntimeComponent,
    RuntimePaths,
    RuntimeProfile,
)


class FakeProcessAdapter:
    """可控制退出、PID 复用、停止超时和身份替换的假进程。"""

    def __init__(self) -> None:
        self.next_pid = 1000
        self.snapshots: dict[int, ProcessSnapshot] = {}
        self.spawned: list[tuple[str, ...]] = []
        self.terminate_calls: list[int] = []
        self.fail_components: set[str] = set()
        self.exit_immediately: set[str] = set()
        self.wait_result = True
        self.terminate_error = False

    def spawn(self, command: tuple[str, ...], log_path: Path) -> ProcessSnapshot:
        del log_path
        component = next(value for value in command if value.startswith("--runtime-component="))
        if component in self.fail_components:
            raise OSError("spawn failed")
        self.next_pid += 1
        snapshot = ProcessSnapshot(
            pid=self.next_pid,
            process_started_at=float(self.next_pid),
            executable=str(Path(command[0]).resolve()),
            command_line=command,
        )
        self.spawned.append(command)
        self.snapshots[snapshot.pid] = snapshot
        if component in self.exit_immediately:
            self.snapshots.pop(snapshot.pid)
        return snapshot

    def inspect(self, pid: int) -> ProcessSnapshot | None:
        return self.snapshots.get(pid)

    def terminate(self, pid: int) -> None:
        self.terminate_calls.append(pid)
        if self.terminate_error:
            raise OSError("denied")

    def wait(self, pid: int, timeout_seconds: float) -> bool:
        del timeout_seconds
        if self.wait_result:
            self.snapshots.pop(pid, None)
        return self.wait_result

    def exit(self, pid: int) -> None:
        self.snapshots.pop(pid, None)


class FakeHealth:
    def __init__(self) -> None:
        self.unhealthy: set[RuntimeComponent] = set()

    def healthy(self, component: RuntimeComponent, pid: int) -> bool:
        del pid
        return component not in self.unhealthy


class DelayedHealth(FakeHealth):
    def __init__(self, failures: int) -> None:
        super().__init__()
        self.failures = failures

    def healthy(self, component: RuntimeComponent, pid: int) -> bool:
        del component, pid
        if self.failures:
            self.failures -= 1
            return False
        return True


def _profile(tmp_path: Path, *components: RuntimeComponent) -> tuple[RuntimeProfile, RuntimePaths]:
    data_dir = (tmp_path / "data").resolve()
    profile = RuntimeProfile(
        data_dir=data_dir,
        enabled_components=frozenset(components or (RuntimeComponent.LOCAL,)),
        budgets=RuntimeBudgets(stable_window_seconds=0.1, shutdown_timeout_seconds=1),
    )
    return profile, RuntimePaths(
        profile_file=tmp_path / "profile.json",
        data_dir=data_dir,
        log_dir=data_dir / "runtime" / "logs",
        state_dir=data_dir / "runtime" / "state",
    )


def _command(component: RuntimeComponent, instance_id: UUID) -> tuple[str, ...]:
    return (sys.executable, "fixture", *runtime_identity_arguments(component, instance_id))


def _manager(
    tmp_path: Path,
    adapter: FakeProcessAdapter,
    *components: RuntimeComponent,
    health: FakeHealth | None = None,
    checkpoint: bool = True,
) -> ManualLifecycleManager:
    profile, paths = _profile(tmp_path, *components)
    return ManualLifecycleManager(
        profile,
        paths,
        "0.1.0",
        adapter,
        _command,
        health=health,
        checkpoint_ready=lambda component, record: checkpoint,
        sleep=lambda seconds: None,
    )


def test_start_is_idempotent_and_stop_is_graceful(tmp_path: Path) -> None:
    adapter = FakeProcessAdapter()
    manager = _manager(tmp_path, adapter, RuntimeComponent.LOCAL, RuntimeComponent.GATEWAY)
    started = manager.start()
    repeated = manager.start()
    status = manager.status()
    stopped = manager.stop()
    repeated_stop = manager.stop()

    assert started.state is OverallRuntimeState.RUNNING
    assert started.exit_code == 0
    assert repeated == status
    assert len(adapter.spawned) == 2
    assert stopped.state is OverallRuntimeState.STOPPED
    assert stopped.exit_code == 0
    assert len(adapter.terminate_calls) == 2
    assert repeated_stop.state is OverallRuntimeState.STOPPED


def test_default_health_and_checkpoint_probes_allow_normal_lifecycle(tmp_path: Path) -> None:
    adapter = FakeProcessAdapter()
    profile, paths = _profile(tmp_path, RuntimeComponent.LOCAL)
    manager = ManualLifecycleManager(
        profile, paths, "0.1.0", adapter, _command, sleep=lambda seconds: None
    )
    assert manager.start().state is OverallRuntimeState.RUNNING
    assert manager.stop().state is OverallRuntimeState.STOPPED


def test_partial_spawn_failure_keeps_healthy_component(tmp_path: Path) -> None:
    adapter = FakeProcessAdapter()
    adapter.fail_components.add("--runtime-component=gateway")
    manager = _manager(tmp_path, adapter, RuntimeComponent.LOCAL, RuntimeComponent.GATEWAY)
    report = manager.start()
    assert report.state is OverallRuntimeState.DEGRADED
    assert report.exit_code == 1
    assert [item.state for item in report.components] == [
        ComponentRuntimeState.FAILED,
        ComponentRuntimeState.RUNNING,
    ]
    assert adapter.terminate_calls == []


def test_startup_exit_and_unhealthy_process_fail_without_duplicate(tmp_path: Path) -> None:
    exiting = FakeProcessAdapter()
    exiting.exit_immediately.add("--runtime-component=local")
    exited = _manager(tmp_path / "exit", exiting).start()
    assert exited.components[0].error_code == "startup_unstable"
    assert not exited.components[0].process_present

    adapter = FakeProcessAdapter()
    health = FakeHealth()
    health.unhealthy.add(RuntimeComponent.LOCAL)
    manager = _manager(tmp_path / "health", adapter, health=health)
    first = manager.start()
    second = manager.start()
    assert first.components[0].state is ComponentRuntimeState.FAILED
    assert second.components[0].process_present
    assert len(adapter.spawned) == 1


def test_status_reports_health_loss_after_successful_start(tmp_path: Path) -> None:
    adapter = FakeProcessAdapter()
    health = FakeHealth()
    manager = _manager(tmp_path, adapter, health=health)
    assert manager.start().state is OverallRuntimeState.RUNNING
    health.unhealthy.add(RuntimeComponent.LOCAL)
    status = manager.status()
    assert status.components[0].state is ComponentRuntimeState.FAILED
    assert status.components[0].error_code == "health_failed"
    assert status.exit_code == 1


def test_start_waits_for_delayed_health_and_preserves_launch_error(tmp_path: Path) -> None:
    adapter = FakeProcessAdapter()
    delayed = DelayedHealth(2)
    manager = _manager(tmp_path / "delayed", adapter, health=delayed)
    assert manager.start().state is OverallRuntimeState.RUNNING

    profile, paths = _profile(tmp_path / "launch", RuntimeComponent.LOCAL)

    def rejected(component: RuntimeComponent, instance_id: UUID) -> tuple[str, ...]:
        del component, instance_id
        raise ComponentLaunchError("component_disabled")

    rejected_manager = ManualLifecycleManager(
        profile,
        paths,
        "0.1.0",
        FakeProcessAdapter(),
        rejected,
        sleep=lambda seconds: None,
    )
    failed = rejected_manager.start()
    assert failed.components[0].error_code == "component_disabled"


def test_status_distinguishes_stale_failed_and_invalid_record(tmp_path: Path) -> None:
    adapter = FakeProcessAdapter()
    manager = _manager(tmp_path / "stale", adapter)
    started = manager.start().components[0]
    assert started.pid is not None
    adapter.exit(started.pid)
    assert manager.status().components[0].state is ComponentRuntimeState.STALE

    failing = FakeProcessAdapter()
    health = FakeHealth()
    health.unhealthy.add(RuntimeComponent.LOCAL)
    failed_manager = _manager(tmp_path / "failed", failing, health=health)
    failed = failed_manager.start().components[0]
    assert failed.pid is not None
    failing.exit(failed.pid)
    assert failed_manager.status().components[0].state is ComponentRuntimeState.FAILED
    assert failed_manager.stop().components[0].state is ComponentRuntimeState.FAILED

    profile, paths = _profile(tmp_path / "invalid", RuntimeComponent.LOCAL)
    paths.state_dir.mkdir(parents=True)
    (paths.state_dir / "local.json").write_text("{}", encoding="utf-8")
    invalid = ManualLifecycleManager(
        profile, paths, "0.1.0", FakeProcessAdapter(), _command, sleep=lambda seconds: None
    ).status()
    assert invalid.components[0].error_code == "process_record_invalid"


@pytest.mark.parametrize("replacement", ["time", "executable", "arguments", "data"])
def test_pid_reuse_and_identity_replacement_fail_closed(tmp_path: Path, replacement: str) -> None:
    adapter = FakeProcessAdapter()
    manager = _manager(tmp_path, adapter)
    started = manager.start().components[0]
    assert started.pid is not None
    snapshot = adapter.snapshots[started.pid]
    if replacement == "time":
        snapshot = snapshot.model_copy(update={"process_started_at": 9999.0})
    elif replacement == "executable":
        snapshot = snapshot.model_copy(update={"executable": str(tmp_path / "foreign")})
    elif replacement == "arguments":
        snapshot = snapshot.model_copy(update={"command_line": (sys.executable, "foreign")})
    else:
        record_path = tmp_path / "data" / "runtime" / "state" / "local.json"
        record = json.loads(record_path.read_text(encoding="utf-8"))
        record["data_dir_sha256"] = "0" * 64
        record_path.write_text(json.dumps(record), encoding="utf-8")
    adapter.snapshots[started.pid] = snapshot

    status = manager.status()
    stopped = manager.stop()
    assert status.components[0].state is ComponentRuntimeState.OWNERSHIP_CONFLICT
    assert stopped.components[0].state is ComponentRuntimeState.OWNERSHIP_CONFLICT
    assert adapter.terminate_calls == []


def test_unknown_process_identity_is_never_terminated(tmp_path: Path) -> None:
    adapter = FakeProcessAdapter()
    manager = _manager(tmp_path, adapter)
    started = manager.start().components[0]
    assert started.pid is not None
    adapter.snapshots[started.pid] = ProcessSnapshot(pid=started.pid)
    assert manager.stop().components[0].state is ComponentRuntimeState.OWNERSHIP_CONFLICT
    assert adapter.terminate_calls == []


def test_missing_command_line_and_stop_time_identity_race_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    adapter = FakeProcessAdapter()
    manager = _manager(tmp_path / "missing", adapter)
    started = manager.start().components[0]
    assert started.pid is not None
    snapshot = adapter.snapshots[started.pid]
    adapter.snapshots[started.pid] = snapshot.model_copy(update={"command_line": None})
    assert manager.status().components[0].state is ComponentRuntimeState.OWNERSHIP_CONFLICT

    racing = FakeProcessAdapter()
    race_manager = _manager(tmp_path / "race", racing)
    raced = race_manager.start().components[0]
    assert raced.pid is not None
    original = racing.inspect
    calls = 0

    def replace_after_status(pid: int) -> ProcessSnapshot | None:
        nonlocal calls
        calls += 1
        value = original(pid)
        if calls == 2 and value is not None:
            return value.model_copy(update={"process_started_at": 9999.0})
        return value

    monkeypatch.setattr(racing, "inspect", replace_after_status)
    stopped = race_manager.stop().components[0]
    assert stopped.state is ComponentRuntimeState.OWNERSHIP_CONFLICT
    assert racing.terminate_calls == []


def test_stop_timeout_terminate_error_and_missing_checkpoint_are_fail_closed(
    tmp_path: Path,
) -> None:
    timeout_adapter = FakeProcessAdapter()
    timeout_manager = _manager(tmp_path / "timeout", timeout_adapter)
    _ = timeout_manager.start()
    timeout_adapter.wait_result = False
    timed_out = timeout_manager.stop().components[0]
    assert timed_out.error_code == "stop_timeout"
    assert timed_out.process_present

    error_adapter = FakeProcessAdapter()
    error_manager = _manager(tmp_path / "error", error_adapter)
    _ = error_manager.start()
    error_adapter.terminate_error = True
    assert error_manager.stop().components[0].error_code == "terminate_failed"

    checkpoint_adapter = FakeProcessAdapter()
    checkpoint_manager = _manager(tmp_path / "checkpoint", checkpoint_adapter, checkpoint=False)
    _ = checkpoint_manager.start()
    missing = checkpoint_manager.stop().components[0]
    assert missing.error_code == "checkpoint_missing"
    assert not missing.process_present


def test_process_record_round_trip_version_and_operation_lock(tmp_path: Path) -> None:
    adapter = FakeProcessAdapter()
    snapshot = adapter.spawn(_command(RuntimeComponent.LOCAL, UUID(int=1)), tmp_path / "log")
    record = RuntimeProcessRecord.starting(
        RuntimeComponent.LOCAL, snapshot, "0.1.0", tmp_path / "data", UUID(int=1)
    )
    repository = ProcessRecordRepository(tmp_path / "state")
    assert repository.load(RuntimeComponent.LOCAL) is None
    repository.save(record)
    assert repository.load(RuntimeComponent.LOCAL) == record
    with pytest.raises(ValidationError, match="版本不受支持"):
        RuntimeProcessRecord.model_validate(
            record.model_dump(mode="python") | {"schema_version": "runtime-process/v2"}
        )

    with (
        RuntimeOperationLock(tmp_path / "locked"),
        pytest.raises(RuntimeOperationBusy),
        RuntimeOperationLock(tmp_path / "locked"),
    ):
        pass
    assert not (tmp_path / "locked" / "operation.lock").exists()


def test_concurrent_start_and_stop_are_serialized(tmp_path: Path) -> None:
    adapter = FakeProcessAdapter()
    profile, paths = _profile(tmp_path, RuntimeComponent.LOCAL)
    entered = Event()
    release = Event()

    def blocking_sleep(seconds: float) -> None:
        del seconds
        entered.set()
        assert release.wait(5)

    manager = ManualLifecycleManager(
        profile, paths, "0.1.0", adapter, _command, sleep=blocking_sleep
    )
    thread = Thread(target=manager.start)
    thread.start()
    assert entered.wait(5)
    with pytest.raises(RuntimeOperationBusy):
        manager.stop()
    release.set()
    thread.join(5)
    assert not thread.is_alive()
    assert manager.status().state is OverallRuntimeState.RUNNING
