"""用户后台服务运行时：只用假的 launchctl 输出和假的文件属性，不碰真实 launchd。"""

from __future__ import annotations

import asyncio
import os
import plistlib
import stat
import subprocess
from collections.abc import Callable
from pathlib import Path

import psutil
import pytest
from tests.repair.factories import NOW, launch_agent_job

from tunnelminion.platforms.windows.system import CommandResult
from tunnelminion.repair import launch_agents as module
from tunnelminion.repair.contracts import LaunchAgentJob, LaunchAgentProblem
from tunnelminion.repair.launch_agents import MacLaunchAgentRuntime, UnsupportedLaunchAgents

UID = 501


class FakeRunner:
    def __init__(self) -> None:
        self.results: dict[tuple[str, ...], CommandResult | Exception] = {}
        self.calls: list[tuple[tuple[str, ...], float]] = []

    async def run(self, command: tuple[str, ...], timeout_seconds: float) -> CommandResult:
        self.calls.append((command, timeout_seconds))
        result = self.results.get(command, CommandResult(returncode=113, stdout="", stderr=""))
        if isinstance(result, Exception):
            raise result
        return result


def printed(stdout: str, code: int = 0) -> CommandResult:
    return CommandResult(returncode=code, stdout=stdout, stderr="")


DOMAIN_PRINT = (
    "gui/501 = {\n"
    "\ttype = gui\n"
    "\tservices = {\n"
    "\t\t     123      0 \tlocal.photos.web\n"
    "\t\t       0      - \tlocal.idle\n"
    "\t\t     456      - \tnot.in.plists\n"
    "\t\t  broken line\n"
    "\t\t       -      - \tlocal.dash\n"
    "\t}\n"
    "\t\t     789      0 \tlocal.after.block\n"
    "}\n"
)


def job_print(label: str, path: Path, *, pid: int | None = None, exit_code: str = "1") -> str:
    lines = [
        f"gui/501/{label} = {{",
        "\tactive count = 0",
        f"\tpath = {path}",
        "\tstate = running" if pid else "\tstate = not running",
        f"\tlast exit code = {exit_code}",
        "\tenvironment = {",
        "\t\tpid = 9",
        "\t}",
    ]
    if pid:
        lines.insert(3, f"\tpid = {pid}")
    return "\n".join([*lines, "}"]) + "\n"


class Files:
    """把真实临时文件包装成 macOS 上的属主和权限。"""

    def __init__(self, home: Path) -> None:
        self.home = home
        self.agents = home / "Library" / "LaunchAgents"
        self.agents.mkdir(parents=True)
        self.overrides: dict[str, tuple[int | None, int | None]] = {}

    def plist(self, name: str, content: dict[str, object] | list[object]) -> Path:
        path = self.agents / name
        path.write_bytes(plistlib.dumps(content))
        return path

    def lstat(self, path: Path) -> os.stat_result:
        real = os.lstat(path)
        kind = stat.S_IFMT(real.st_mode)
        mode = kind | (0o755 if kind == stat.S_IFDIR else 0o644)
        uid = UID
        override = self.overrides.get(path.name)
        if override is not None:
            mode = override[0] if override[0] is not None else mode
            uid = override[1] if override[1] is not None else uid
        return os.stat_result(
            (mode, real.st_ino, real.st_dev, real.st_nlink, uid, 20, real.st_size, 0, 0, 0)
        )


def runtime(
    files: Files,
    runner: FakeRunner,
    *,
    parents: Callable[[int], tuple[int, ...]] = lambda pid: (),
    uid: int = UID,
    platform: str = "darwin",
) -> MacLaunchAgentRuntime:
    return MacLaunchAgentRuntime(
        runner,
        uid=uid,
        home=files.home,
        parent_pids=parents,
        lstat=files.lstat,
        clock=lambda: NOW,
        platform=platform,
    )


def agent(label: str, **extra: object) -> dict[str, object]:
    return {"Label": label, "ProgramArguments": ["/opt/homebrew/bin/python3", "-m"], **extra}


@pytest.fixture
def files(tmp_path: Path) -> Files:
    return Files(tmp_path)


def test_unsupported_reason_by_platform_and_account(files: Files) -> None:
    runner = FakeRunner()
    assert runtime(files, runner).unsupported_reason() is None
    assert "只有 macOS" in (runtime(files, runner, platform="win32").unsupported_reason() or "")
    assert "管理员" in (runtime(files, runner, uid=0).unsupported_reason() or "")


def test_unsupported_runtime_recognizes_nothing() -> None:
    agents = UnsupportedLaunchAgents()
    assert "只有 macOS" in (agents.unsupported_reason() or "")
    assert asyncio.run(agents.labels_for_pids(frozenset({1}))) == {}
    assert asyncio.run(agents.inspect("local.a")) is LaunchAgentProblem.MISSING
    with pytest.raises(ValueError):
        asyncio.run(agents.kickstart("local.a"))
    assert agents.log_tail(launch_agent_job(), lines=10) == ""


def test_labels_for_pids_maps_own_and_child_processes(files: Files) -> None:
    files.plist("local.photos.web.plist", agent("local.photos.web"))
    files.plist("local.idle.plist", agent("local.idle"))
    files.plist("local.after.block.plist", agent("local.after.block"))
    files.plist("local.dash.plist", agent("local.dash"))
    files.plist("not-a-dict.plist", ["x"])
    files.plist("bad-label.plist", agent("bad label"))
    (files.agents / "broken.plist").write_bytes(b"not a plist")
    (files.agents / "readme.txt").write_text("ignored")
    runner = FakeRunner()
    runner.results[("/bin/launchctl", "print", "gui/501")] = printed(DOMAIN_PRINT)
    parents = {900: (800, 123), 901: (1,)}
    agents = runtime(files, runner, parents=lambda pid: parents.get(pid, ()))
    labels = asyncio.run(agents.labels_for_pids(frozenset({123, 900, 901, 456, 789})))
    assert labels == {123: "local.photos.web", 900: "local.photos.web"}
    assert runner.calls == [(("/bin/launchctl", "print", "gui/501"), 10)]


def test_labels_for_pids_returns_nothing_when_unknown(files: Files) -> None:
    runner = FakeRunner()
    agents = runtime(files, runner)
    assert asyncio.run(agents.labels_for_pids(frozenset())) == {}
    assert asyncio.run(runtime(files, runner, uid=0).labels_for_pids(frozenset({1}))) == {}
    # 用户目录里没有任何 plist 时不调用 launchctl。
    assert asyncio.run(agents.labels_for_pids(frozenset({123}))) == {}
    assert runner.calls == []
    files.plist("local.photos.web.plist", agent("local.photos.web"))
    runner.results[("/bin/launchctl", "print", "gui/501")] = printed("", code=5)
    assert asyncio.run(agents.labels_for_pids(frozenset({123}))) == {}
    runner.results[("/bin/launchctl", "print", "gui/501")] = subprocess.TimeoutExpired("x", 10)
    assert asyncio.run(agents.labels_for_pids(frozenset({123}))) == {}
    runner.results[("/bin/launchctl", "print", "gui/501")] = printed("gui/501 = {\n}\n")
    assert asyncio.run(agents.labels_for_pids(frozenset({123}))) == {}


def test_duplicate_labels_and_unsafe_directories_are_ignored(files: Files) -> None:
    files.plist("a.plist", agent("local.photos.web"))
    files.plist("b.plist", agent("local.photos.web"))
    runner = FakeRunner()
    runner.results[("/bin/launchctl", "print", "gui/501")] = printed(DOMAIN_PRINT)
    agents = runtime(files, runner)
    assert asyncio.run(agents.labels_for_pids(frozenset({123}))) == {}
    assert asyncio.run(agents.inspect("local.photos.web")) is LaunchAgentProblem.MISSING
    (files.agents / "b.plist").unlink()
    files.overrides["LaunchAgents"] = (stat.S_IFDIR | 0o775, None)
    assert asyncio.run(agents.inspect("local.photos.web")) is LaunchAgentProblem.MISSING
    files.overrides["LaunchAgents"] = (stat.S_IFREG | 0o644, None)
    assert asyncio.run(agents.inspect("local.photos.web")) is LaunchAgentProblem.MISSING
    files.overrides["LaunchAgents"] = (None, 502)
    assert asyncio.run(agents.inspect("local.photos.web")) is LaunchAgentProblem.MISSING
    del files.overrides["LaunchAgents"]
    assert isinstance(asyncio.run(agents.inspect("local.photos.web")), LaunchAgentJob)


def test_missing_agents_directory(tmp_path: Path) -> None:
    agents = MacLaunchAgentRuntime(FakeRunner(), uid=UID, home=tmp_path, platform="darwin")
    assert asyncio.run(agents.inspect("local.photos.web")) is LaunchAgentProblem.MISSING


def test_inspect_reads_plist_and_launchd_state(files: Files) -> None:
    path = files.plist(
        "local.photos.web.plist",
        agent(
            "local.photos.web",
            StandardErrorPath="/Users/me/err.log",
            StandardOutPath="/Users/me/out.log",
        ),
    )
    runner = FakeRunner()
    target = ("/bin/launchctl", "print", "gui/501/local.photos.web")
    runner.results[target] = printed(job_print("local.photos.web", path, pid=321))
    job = asyncio.run(runtime(files, runner).inspect("local.photos.web"))
    assert isinstance(job, LaunchAgentJob)
    assert job.plist_path == str(path) and job.loaded_path == str(path)
    assert len(job.plist_sha256) == 64 and job.program == "/opt/homebrew/bin/python3"
    assert job.log_paths == ("/Users/me/err.log", "/Users/me/out.log")
    assert job.loaded and job.pid == 321 and job.last_exit_code == 1 and job.uid == UID
    runner.results[target] = printed(job_print("local.photos.web", path, exit_code="(never)"))
    job = asyncio.run(runtime(files, runner).inspect("local.photos.web"))
    assert isinstance(job, LaunchAgentJob) and job.pid is None and job.last_exit_code is None
    runner.results[target] = printed("Could not find service", code=113)
    job = asyncio.run(runtime(files, runner).inspect("local.photos.web"))
    assert isinstance(job, LaunchAgentJob) and not job.loaded and job.loaded_path is None
    runner.results[target] = OSError("boom")
    job = asyncio.run(runtime(files, runner).inspect("local.photos.web"))
    assert isinstance(job, LaunchAgentJob) and not job.loaded


def test_inspect_program_key_and_invalid_or_unsafe_plists(files: Files) -> None:
    runner = FakeRunner()
    agents = runtime(files, runner)
    files.plist("local.program.plist", {"Label": "local.program", "Program": "/usr/bin/true"})
    job = asyncio.run(agents.inspect("local.program"))
    assert isinstance(job, LaunchAgentJob) and job.program == "/usr/bin/true"
    files.plist("local.noprogram.plist", {"Label": "local.noprogram", "ProgramArguments": [1]})
    assert asyncio.run(agents.inspect("local.noprogram")) is LaunchAgentProblem.INVALID
    files.plist("local.empty.plist", {"Label": "local.empty", "ProgramArguments": []})
    assert asyncio.run(agents.inspect("local.empty")) is LaunchAgentProblem.INVALID
    files.plist("local.other.plist", agent("local.other"))
    files.overrides["local.other.plist"] = (None, 502)
    assert asyncio.run(agents.inspect("local.other")) is LaunchAgentProblem.UNSAFE
    files.plist("local.shared.plist", agent("local.shared"))
    files.overrides["local.shared.plist"] = (stat.S_IFREG | 0o664, None)
    assert asyncio.run(agents.inspect("local.shared")) is LaunchAgentProblem.UNSAFE
    files.plist("local.link.plist", agent("local.link"))
    files.overrides["local.link.plist"] = (stat.S_IFLNK | 0o777, None)
    assert asyncio.run(agents.inspect("local.link")) is LaunchAgentProblem.UNSAFE
    assert asyncio.run(agents.inspect("missing.label")) is LaunchAgentProblem.MISSING
    assert asyncio.run(agents.inspect("bad label")) is LaunchAgentProblem.MISSING
    assert asyncio.run(runtime(files, runner, uid=0).inspect("local.program")) is (
        LaunchAgentProblem.MISSING
    )
    assert runner.calls == [(("/bin/launchctl", "print", "gui/501/local.program"), 10)]


def test_kickstart_is_fixed_and_never_kills(files: Files) -> None:
    runner = FakeRunner()
    argv = ("/bin/launchctl", "kickstart", "gui/501/local.photos.web")
    runner.results[argv] = CommandResult(returncode=0, stdout="", stderr="token=abc")
    command = asyncio.run(runtime(files, runner).kickstart("local.photos.web"))
    assert command.argv == argv and "-k" not in command.argv
    assert command.exit_code == 0 and command.output_excerpt == "token=[REDACTED]"
    assert runner.calls == [(argv, 15)]
    runner.results[argv] = OSError("no launchctl")
    command = asyncio.run(runtime(files, runner).kickstart("local.photos.web"))
    assert command.exit_code is None and command.output_excerpt == "no launchctl"
    with pytest.raises(ValueError):
        asyncio.run(runtime(files, runner).kickstart("bad label; rm -rf"))
    with pytest.raises(ValueError):
        asyncio.run(runtime(files, runner, uid=0).kickstart("local.photos.web"))


def test_log_tail_reads_only_own_regular_files(files: Files) -> None:
    err = files.home / "err.log"
    err.write_text("x" * 70_000 + "\nstart\npassword=hunter2\nfailed\n")
    out = files.home / "out.log"
    out.write_text("out line\n")
    other = files.home / "other.log"
    other.write_text("secret\n")
    files.overrides["other.log"] = (None, 502)
    agents = runtime(files, FakeRunner())
    job = launch_agent_job(
        log_paths=(str(err), str(err)),
    )
    assert agents.log_tail(job, lines=0) == ""
    assert agents.log_tail(job, lines=2) == "password=[REDACTED]\nfailed"
    job = launch_agent_job(log_paths=("pyproject.toml", str(other), str(files.home / "gone.log")))
    assert agents.log_tail(job, lines=10) == ""
    folder = files.home / "folder"
    folder.mkdir()
    assert agents.log_tail(launch_agent_job(log_paths=(str(folder), str(out))), lines=5) == (
        "out line"
    )


class FakeProcess:
    def __init__(self, pid: int, created: float, parents: list[FakeProcess] | None = None) -> None:
        self.pid = pid
        self._created = created
        self._parents = parents or []

    def create_time(self) -> float:
        return self._created

    def parents(self) -> list[FakeProcess]:
        return self._parents


def test_parent_pids_stop_at_reused_pid(monkeypatch: pytest.MonkeyPatch) -> None:
    newer = FakeProcess(3, 50.0)
    process = FakeProcess(10, 20.0, [FakeProcess(5, 10.0), newer, FakeProcess(1, 1.0)])

    def current(pid: int) -> FakeProcess:
        return process

    monkeypatch.setattr(module.psutil, "Process", current)
    assert module._parent_pids(10) == (5,)  # pyright: ignore[reportPrivateUsage]
    process = FakeProcess(10, 20.0, [FakeProcess(5, 10.0), FakeProcess(1, 1.0)])
    assert module._parent_pids(10) == (5, 1)  # pyright: ignore[reportPrivateUsage]

    def missing(pid: int) -> FakeProcess:
        raise psutil.NoSuchProcess(pid)

    monkeypatch.setattr(module.psutil, "Process", missing)
    assert module._parent_pids(10) == ()  # pyright: ignore[reportPrivateUsage]


def test_current_uid_without_getuid(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(module.os, "getuid", lambda: 501, raising=False)
    assert module._current_uid() == 501  # pyright: ignore[reportPrivateUsage]
    monkeypatch.delattr(module.os, "getuid", raising=False)
    assert module._current_uid() == 0  # pyright: ignore[reportPrivateUsage]
