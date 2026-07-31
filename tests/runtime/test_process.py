"""跨平台 detached 进程适配器测试。"""

from __future__ import annotations

import sys
from contextlib import suppress
from pathlib import Path
from uuid import UUID

import psutil
import pytest

from tunnelminion.runtime.process import (
    DetachedProcessAdapter,
    ProcessSnapshot,
    RuntimeOperationLock,
    RuntimeProcessRecord,
    current_runtime_executable,
    detached_process_options,
    runtime_identity_arguments,
)
from tunnelminion.runtime.profile import RuntimeComponent


def test_detached_options_cover_windows_and_posix_without_autostart_registration() -> None:
    windows_flags, windows_session = detached_process_options("nt")
    posix_flags, posix_session = detached_process_options("posix")
    assert windows_flags >= 0
    assert not windows_session
    assert posix_flags == 0
    assert posix_session


def test_identity_arguments_and_current_executable_are_stable() -> None:
    instance_id = UUID(int=1)
    assert runtime_identity_arguments(RuntimeComponent.GATEWAY, instance_id) == (
        "--runtime-component=gateway",
        f"--runtime-instance-id={instance_id}",
    )
    assert current_runtime_executable() == Path(sys.executable).resolve()


def test_detached_adapter_spawns_inspects_terminates_and_waits(tmp_path: Path) -> None:
    adapter = DetachedProcessAdapter()
    identity = runtime_identity_arguments(RuntimeComponent.LOCAL, UUID(int=2))
    snapshot = adapter.spawn(
        (sys.executable, "-c", "import time; time.sleep(60)", *identity),
        tmp_path / "logs" / "local.log",
    )
    try:
        observed = adapter.inspect(snapshot.pid)
        assert observed is not None
        assert observed.running
        assert observed.command_line is not None
        assert set(identity).issubset(observed.command_line)
        assert not adapter.wait(snapshot.pid, 0.01)
        adapter.terminate(snapshot.pid)
        assert adapter.wait(snapshot.pid, 5)
        assert adapter.inspect(snapshot.pid) is None
    finally:
        with suppress(psutil.NoSuchProcess):
            psutil.Process(snapshot.pid).kill()
    assert (tmp_path / "logs" / "local.log").exists()


def test_adapter_handles_missing_and_uninspectable_process(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    adapter = DetachedProcessAdapter()

    def missing(pid: int) -> psutil.Process:
        raise psutil.NoSuchProcess(pid)

    monkeypatch.setattr(psutil, "Process", missing)
    assert adapter.inspect(12345) is None
    adapter.terminate(12345)
    assert adapter.wait(12345, 0.1)

    def denied(pid: int) -> psutil.Process:
        del pid
        raise psutil.AccessDenied()

    monkeypatch.setattr(psutil, "Process", denied)
    assert adapter.inspect(12345) == ProcessSnapshot(pid=12345)


def test_process_record_requires_inspectable_new_process(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="身份不可验证"):
        RuntimeProcessRecord.starting(
            RuntimeComponent.LOCAL,
            ProcessSnapshot(pid=1),
            "0.1.0",
            tmp_path,
        )


def test_detached_adapter_rejects_child_that_exits_before_inspection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    adapter = DetachedProcessAdapter()

    def vanished(pid: int) -> ProcessSnapshot | None:
        del pid
        return None

    monkeypatch.setattr(adapter, "inspect", vanished)
    with pytest.raises(RuntimeError, match="立即退出"):
        adapter.spawn(
            (sys.executable, "-c", "pass"),
            tmp_path / "logs" / "exited.log",
        )


def test_operation_lock_exit_without_enter_is_safe(tmp_path: Path) -> None:
    lock = RuntimeOperationLock(tmp_path)
    lock.__exit__(None, None, None)
    assert not (tmp_path / "operation.lock").exists()
