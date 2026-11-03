"""换包、失败自动退回、更新锁和真实组件控制的测试。"""

# pyright: reportUnknownLambdaType=false, reportUnknownArgumentType=false

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest
from tests.update.conftest import build_package

from tunnelminion.runtime.install import RuntimePackageInstaller
from tunnelminion.runtime.profile import FileRuntimeProfileRepository, RuntimeProfile
from tunnelminion.update import apply as apply_module
from tunnelminion.update.apply import (
    NO_REDIRECT_ENV,
    ProfileRuntimeControl,
    UpdateBusy,
    UpdateLock,
    UpdateOutcome,
    adopt_running_package,
    apply_switch,
    load_update_record,
    running_package_identity,
    update_record_path,
)


class FakeControl:
    """记录调用顺序；可以指定停止和启动的结果。"""

    def __init__(
        self,
        *,
        stop_ok: bool = True,
        stopped_after_stop: bool = True,
        start_results: dict[str, bool] | None = None,
    ) -> None:
        self.stop_ok = stop_ok
        self.stopped_after_stop = stopped_after_stop
        self.start_results = start_results or {}
        self.calls: list[str] = []
        self.running = True

    def stop(self) -> bool:
        self.calls.append("stop")
        if self.stopped_after_stop:
            self.running = False
        return self.stop_ok

    def stopped(self) -> bool:
        return not self.running

    def start(self, executable: Path) -> bool:
        name = executable.parent.name
        self.calls.append(f"start:{name}")
        ok = self.start_results.get(name, True)
        self.running = True
        return ok


def _installer(tmp_path: Path) -> tuple[RuntimePackageInstaller, str, str, str]:
    installer = RuntimePackageInstaller(tmp_path / "install", tmp_path / "data")
    old = build_package(tmp_path / "old", "pkg-old", b"old")
    new = build_package(tmp_path / "new", "pkg-new", b"new")
    old_record = installer.stage(old, old / "runtime-package-manifest.json")
    new_record = installer.stage(new, new / "runtime-package-manifest.json", release_tag="build-2")
    return (
        installer,
        old_record.package_id,
        new_record.package_id,
        installer.program_dir(new_record.package_id).name,
    )


def test_successful_switch_points_to_new_version_and_keeps_old(tmp_path: Path) -> None:
    installer, old, new, new_dir = _installer(tmp_path)
    control = FakeControl()
    record_path = tmp_path / "state" / "update.json"
    record = apply_switch(installer, control, new, old, record_path, release_tag="build-2")
    assert record.outcome is UpdateOutcome.UPDATED
    assert control.calls == ["stop", f"start:{new_dir}"]
    state = installer.load()
    assert (state.current_package_id, state.previous_package_id) == (new, old)
    assert load_update_record(record_path) == record


def test_unhealthy_new_version_rolls_back_to_old(tmp_path: Path) -> None:
    installer, old, new, new_dir = _installer(tmp_path)
    old_dir = installer.program_dir(old).name
    control = FakeControl(start_results={new_dir: False})
    record = apply_switch(installer, control, new, old, tmp_path / "update.json")
    assert record.outcome is UpdateOutcome.ROLLED_BACK
    assert record.error_code == "new_version_unhealthy"
    # 没传发布名时记下目标版本自己的发布名
    assert record.release_tag == "build-2"
    assert control.calls == ["stop", f"start:{new_dir}", "stop", f"start:{old_dir}"]
    state = installer.load()
    assert (state.current_package_id, state.previous_package_id) == (old, new)


def test_rollback_that_also_fails_is_reported(tmp_path: Path) -> None:
    installer, old, new, new_dir = _installer(tmp_path)
    old_dir = installer.program_dir(old).name
    control = FakeControl(start_results={new_dir: False, old_dir: False})
    record = apply_switch(installer, control, new, old, tmp_path / "update.json")
    assert (record.outcome, record.error_code) == (UpdateOutcome.FAILED, "rollback_failed")


def test_new_version_that_cannot_be_stopped_is_not_overlapped(tmp_path: Path) -> None:
    installer, old, new, new_dir = _installer(tmp_path)

    class Stuck(FakeControl):
        def stop(self) -> bool:
            self.calls.append("stop")
            if len(self.calls) == 1:
                self.running = False
            return True

    control = Stuck(start_results={new_dir: False})
    record = apply_switch(installer, control, new, old, tmp_path / "update.json")
    assert (record.outcome, record.error_code) == (UpdateOutcome.FAILED, "new_version_stuck")
    assert installer.load().current_package_id == new


@pytest.mark.parametrize(("stop_ok", "stopped"), [(False, True), (True, False)])
def test_failed_stop_keeps_old_version(tmp_path: Path, stop_ok: bool, stopped: bool) -> None:
    installer, old, new, _new_dir = _installer(tmp_path)
    old_dir = installer.program_dir(old).name
    control = FakeControl(stop_ok=stop_ok, stopped_after_stop=stopped)
    record = apply_switch(installer, control, new, old, tmp_path / "update.json")
    assert (record.outcome, record.error_code) == (UpdateOutcome.FAILED, "stop_failed")
    assert control.calls == ["stop", f"start:{old_dir}"]
    assert installer.load().current_package_id is None


def test_prune_errors_do_not_fail_a_successful_update(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    installer, old, new, _new_dir = _installer(tmp_path)

    def broken_prune() -> tuple[str, ...]:
        raise OSError("busy")

    monkeypatch.setattr(installer, "prune", broken_prune)
    record = apply_switch(installer, FakeControl(), new, old, tmp_path / "update.json")
    assert record.outcome is UpdateOutcome.UPDATED


def test_update_record_and_identity_helpers(tmp_path: Path) -> None:
    broken = tmp_path / "update.json"
    broken.write_text("{", encoding="utf-8")
    assert load_update_record(broken) is None
    assert load_update_record(tmp_path / "missing.json") is None

    profile = RuntimeProfile(data_dir=(tmp_path / "data").resolve())
    assert update_record_path(profile).name == "update.json"

    package = build_package(tmp_path / "pkg", "pkg-id", b"x", revision="e" * 40)
    assert running_package_identity(package) == ("pkg-id", "e" * 40)
    assert running_package_identity(tmp_path / "nowhere") is None
    manifest = package / "runtime-package-manifest.json"
    raw = json.loads(manifest.read_text(encoding="utf-8"))
    raw["candidate"]["id"] = 5
    manifest.write_text(json.dumps(raw), encoding="utf-8")
    assert running_package_identity(package) is None


def test_adopt_running_package_copies_it_once(tmp_path: Path) -> None:
    installer = RuntimePackageInstaller(tmp_path / "install", tmp_path / "data")
    package = build_package(tmp_path / "running", "pkg-running", b"run")
    first = adopt_running_package(installer, package)
    assert adopt_running_package(installer, package) == first
    with pytest.raises(ValueError, match="运行包"):
        adopt_running_package(installer, tmp_path)


def test_update_lock_is_exclusive_and_recovers_stale_lock(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with UpdateLock(tmp_path), pytest.raises(UpdateBusy):
        UpdateLock(tmp_path).__enter__()
    assert not (tmp_path / "update.lock").exists()

    lock = tmp_path / "update.lock"
    lock.write_text(json.dumps({"pid": 999_999_999}), encoding="utf-8")
    monkeypatch.setattr(apply_module.psutil, "pid_exists", lambda pid: False)
    with UpdateLock(tmp_path):
        assert json.loads(lock.read_text(encoding="utf-8"))["pid"] == os.getpid()
    assert not lock.exists()

    lock.write_text("garbage", encoding="utf-8")
    with pytest.raises(UpdateBusy):
        UpdateLock(tmp_path).__enter__()
    # 没拿到锁就退出时什么都不删
    UpdateLock(tmp_path).__exit__(None, None, None)
    assert lock.exists()


def test_update_lock_gives_up_when_stale_lock_keeps_coming_back(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    lock = tmp_path / "update.lock"
    lock.write_text(json.dumps({"pid": 1}), encoding="utf-8")
    monkeypatch.setattr(apply_module.psutil, "pid_exists", lambda pid: False)
    original_unlink = Path.unlink

    def unlink_then_recreate(self: Path, missing_ok: bool = False) -> None:
        original_unlink(self, missing_ok=missing_ok)
        if self == lock:
            lock.write_text(json.dumps({"pid": 1}), encoding="utf-8")

    monkeypatch.setattr(Path, "unlink", unlink_then_recreate)
    with pytest.raises(UpdateBusy):
        UpdateLock(tmp_path).__enter__()


def _profile(tmp_path: Path) -> Path:
    path = tmp_path / "profile.json"
    FileRuntimeProfileRepository(path, tmp_path / "program").save(
        RuntimeProfile(data_dir=(tmp_path / "data").resolve())
    )
    return path


def test_profile_control_stops_and_checks_through_lifecycle_manager(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    profile_path = _profile(tmp_path)
    monkeypatch.setattr(apply_module, "current_program_dir", lambda: tmp_path / "program")
    calls: list[str] = []
    components: list[SimpleNamespace] = [SimpleNamespace(process_present=False)]

    class Manager:
        def stop(self) -> None:
            calls.append("stop")

        def status(self) -> SimpleNamespace:
            return SimpleNamespace(components=components)

    monkeypatch.setattr(
        "tunnelminion.runtime.control.build_lifecycle_manager",
        lambda profile, paths: Manager(),
    )
    control = ProfileRuntimeControl(profile_path)
    assert control.stop()
    assert control.stopped()
    components.append(SimpleNamespace(process_present=True))
    assert not control.stopped()
    assert calls == ["stop"]


def test_profile_control_fails_closed_without_profile(tmp_path: Path) -> None:
    control = ProfileRuntimeControl(tmp_path / "missing.json")
    assert not control.stop()
    assert not control.stopped()


def test_profile_control_starts_target_version_without_redirect(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[tuple[tuple[str, ...], dict[str, str]]] = []

    def run(command: tuple[str, ...], **kwargs: object) -> SimpleNamespace:
        environment = kwargs["env"]
        assert isinstance(environment, dict)
        seen.append((command, environment))  # pyright: ignore[reportUnknownArgumentType]
        return SimpleNamespace(returncode=0 if len(seen) == 1 else 1)

    monkeypatch.setattr(apply_module.subprocess, "run", run)
    control = ProfileRuntimeControl(tmp_path / "profile.json")
    assert control.start(tmp_path / "new" / "tunnelminion")
    assert not control.start(tmp_path / "new" / "tunnelminion")
    command, environment = seen[0]
    assert command[1:4] == ("runtime", "start", "--profile")
    assert environment[NO_REDIRECT_ENV] == "1"

    def timeout(command: tuple[str, ...], **kwargs: object) -> SimpleNamespace:
        raise subprocess.TimeoutExpired(command, 1)

    monkeypatch.setattr(apply_module.subprocess, "run", timeout)
    assert not control.start(tmp_path / "new" / "tunnelminion")
    monkeypatch.setattr(apply_module.sys, "stdout", None)
    monkeypatch.setattr(
        apply_module.subprocess, "run", lambda command, **kwargs: SimpleNamespace(returncode=0)
    )
    assert control.start(tmp_path / "new" / "tunnelminion")
