"""用假进程和假 Popen 验证后台启动与受限清理。"""

from __future__ import annotations

import asyncio
import errno
import http.client
import os
import socket
import ssl
import subprocess
import threading
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import BinaryIO, cast

import psutil
import pytest

from tunnelminion.platforms.windows.models import NetworkListener
from tunnelminion.platforms.windows.system import SystemReader
from tunnelminion.repair.contracts import (
    HostInspector,
    LaunchRecord,
    LocalVerifier,
    ProcessLauncher,
    SpawnedProcess,
)
from tunnelminion.repair.processes import (
    BackgroundProcessLauncher,
    PsutilHostInspector,
    SocketLocalVerifier,
    redact_log_text,
)

NOW = datetime(2026, 10, 25, tzinfo=UTC)


def launch_record() -> LaunchRecord:
    return LaunchRecord(
        service_key="python:app.py@8080",
        interpreter="fixture/python",
        arguments=("app.py", "--port", "8080"),
        working_directory="fixture/site",
        ports=(8080,),
        username="fixture-user",
        rule_shown=True,
        process_id=101,
        process_started_at=NOW,
        recorded_at=NOW,
    )


def spawned() -> SpawnedProcess:
    return SpawnedProcess(pid=101, started_at=NOW, log_path="fixture.log")


class FakeProcess:
    def __init__(self, pid: int = 101) -> None:
        self.pid = pid
        self.started = NOW.timestamp()
        self.running = True
        self.state = psutil.STATUS_RUNNING
        self.command = ["fixture/python", "app.py", "--port", "8080"]
        self.directory = os.path.join("fixture", "site", ".")
        self.descendants: list[psutil.Process] = []
        self.events: list[str] = []
        self.error: Exception | None = None

    def create_time(self) -> float:
        if self.error is not None:
            raise self.error
        return self.started

    def is_running(self) -> bool:
        return self.running

    def status(self) -> str:
        return self.state

    def children(self, recursive: bool = False) -> list[psutil.Process]:
        assert recursive
        return self.descendants

    def terminate(self) -> None:
        self.events.append("terminate")
        if self.error is not None:
            raise self.error

    def kill(self) -> None:
        self.events.append("kill")
        if self.error is not None:
            raise self.error

    def cmdline(self) -> list[str]:
        if self.error is not None:
            raise self.error
        return self.command

    def cwd(self) -> str:
        return self.directory

    def username(self) -> str:
        return "fixture-user"


def factory(process: FakeProcess | Exception) -> Callable[[int], psutil.Process]:
    def read(pid: int) -> psutil.Process:
        if isinstance(process, Exception):
            raise process
        return cast(psutil.Process, process)

    return read


class FakePopen:
    def __init__(self, *errors: OSError) -> None:
        self.errors = list(errors)
        self.calls: list[tuple[list[str], dict[str, object]]] = []
        self.child = cast(subprocess.Popen[bytes], FakeProcess())

    def __call__(self, argv: list[str], **kwargs: object) -> subprocess.Popen[bytes]:
        self.calls.append((argv, kwargs))
        if self.errors:
            raise self.errors.pop(0)
        output = cast(BinaryIO, kwargs["stdout"])
        assert output.mode == "ab" and not output.closed
        output.write(b"fixture-output\n")
        return self.child


@pytest.mark.parametrize("platform", ("win32", "darwin", "linux"))
def test_launch_keeps_record_and_account_and_detaches_without_shell(
    tmp_path: Path, platform: str
) -> None:
    popen = FakePopen()
    process = FakeProcess()
    environment = {"PATH": "fixture-bin", "KEEP": "yes", "TUNNELMINION_TOKEN": "fixture-secret"}
    launcher: ProcessLauncher = BackgroundProcessLauncher(
        platform, popen, factory(process), environment
    )
    path = tmp_path / "logs" / "script.log"
    first = launcher.launch(launch_record(), log_path=path)
    launcher.launch(launch_record(), log_path=path)
    assert first == SpawnedProcess(pid=101, started_at=NOW, log_path=str(path))
    assert path.read_bytes() == b"fixture-output\nfixture-output\n"
    argv, kwargs = popen.calls[0]
    assert argv == ["fixture/python", "app.py", "--port", "8080"]
    assert kwargs["cwd"] == "fixture/site"
    assert kwargs["stdin"] == subprocess.DEVNULL
    assert kwargs["stderr"] == subprocess.STDOUT
    assert kwargs["close_fds"] is True
    assert kwargs["env"] == {"PATH": "fixture-bin", "KEEP": "yes"}
    assert environment["TUNNELMINION_TOKEN"] == "fixture-secret"
    assert "shell" not in kwargs and "user" not in kwargs
    if platform == "win32":
        assert kwargs["creationflags"] == 0x01000000 | 0x00000200 | 0x08000000
        assert "start_new_session" not in kwargs
    else:
        assert kwargs["start_new_session"] is True and "creationflags" not in kwargs
    assert cast(BinaryIO, kwargs["stdout"]).closed
    assert popen.child in vars(launcher)["_children"]


@pytest.mark.parametrize("windows_error", (False, True))
def test_breakaway_access_denied_retries_without_breakaway(
    tmp_path: Path, windows_error: bool
) -> None:
    error = OSError(errno.EACCES, "fixture denied")
    if windows_error:
        error = OSError("fixture denied")
        error.winerror = 5
    popen = FakePopen(error)
    launcher = BackgroundProcessLauncher("win32", popen, factory(FakeProcess()), {})
    launcher.launch(launch_record(), log_path=tmp_path / "output.log")
    assert [call[1]["creationflags"] for call in popen.calls] == [0x09000200, 0x08000200]


@pytest.mark.parametrize(
    "platform,errors",
    (
        ("win32", (OSError(errno.ENOENT, "missing"),)),
        ("win32", (OSError(errno.EACCES, "denied"), OSError("retry failed"))),
        ("darwin", (OSError(errno.EACCES, "denied"),)),
    ),
)
def test_spawn_failures_are_os_errors(
    tmp_path: Path, platform: str, errors: tuple[OSError, ...]
) -> None:
    popen = FakePopen(*errors)
    with pytest.raises(OSError):
        BackgroundProcessLauncher(platform, popen, factory(FakeProcess()), {}).launch(
            launch_record(), log_path=tmp_path / "output.log"
        )
    assert len(popen.calls) == len(errors)


def test_defaults_use_current_environment_and_failed_identity_is_os_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("TUNNELMINION_TEST", "fixture-only")
    monkeypatch.setenv("FIXTURE_KEEP", "yes")
    popen = FakePopen()
    launcher = BackgroundProcessLauncher(
        popen=popen, process_factory=factory(psutil.NoSuchProcess(101))
    )
    with pytest.raises(OSError, match="启动时间"):
        launcher.launch(launch_record(), log_path=tmp_path / "output.log")
    assert cast(dict[str, str], popen.calls[0][1]["env"])["FIXTURE_KEEP"] == "yes"
    assert "TUNNELMINION_TEST" not in cast(dict[str, str], popen.calls[0][1]["env"])


@pytest.mark.parametrize(
    "running,status,offset,expected",
    (
        (True, psutil.STATUS_RUNNING, 0.0, True),
        (True, psutil.STATUS_RUNNING, 1.0, True),
        (True, psutil.STATUS_RUNNING, 1.01, False),
        (True, psutil.STATUS_RUNNING, -1.01, False),
        (False, psutil.STATUS_RUNNING, 0.0, False),
        (True, psutil.STATUS_ZOMBIE, 0.0, False),
    ),
)
def test_alive_checks_timestamp_and_zombies(
    running: bool, status: str, offset: float, expected: bool
) -> None:
    process = FakeProcess()
    process.running, process.state, process.started = running, status, NOW.timestamp() + offset
    assert (
        BackgroundProcessLauncher(process_factory=factory(process)).is_alive(spawned()) is expected
    )


@pytest.mark.parametrize(
    "error", (psutil.NoSuchProcess(101), psutil.AccessDenied(101), OSError("denied"))
)
def test_alive_unreadable_process_is_false(error: Exception) -> None:
    assert not BackgroundProcessLauncher(process_factory=factory(error)).is_alive(spawned())


@pytest.mark.parametrize("reused", (False, True))
def test_stop_leaves_missing_or_reused_pid_untouched(reused: bool) -> None:
    process = FakeProcess()
    process.started += 2
    launcher = BackgroundProcessLauncher(
        process_factory=factory(process if reused else psutil.NoSuchProcess(101))
    )
    assert launcher.stop(spawned())
    assert not process.events


@pytest.mark.parametrize("survives", (False, True))
def test_stop_terminates_tree_then_kills_survivors_with_bounded_wait(
    monkeypatch: pytest.MonkeyPatch, survives: bool
) -> None:
    parent, child = FakeProcess(), FakeProcess(102)
    parent.descendants = [cast(psutil.Process, child)]
    waits: list[tuple[list[psutil.Process], float]] = []

    def wait_procs(
        processes: list[psutil.Process], timeout: float
    ) -> tuple[list[psutil.Process], list[psutil.Process]]:
        waits.append((processes, timeout))
        if timeout == 5:
            return [cast(psutil.Process, child)], [cast(psutil.Process, parent)]
        return ([], processes) if survives else (processes, [])

    monkeypatch.setattr(psutil, "wait_procs", wait_procs)
    assert (
        BackgroundProcessLauncher(process_factory=factory(parent)).stop(spawned()) is not survives
    )
    assert child.events == ["terminate"] and parent.events == ["terminate", "kill"]
    assert waits == [
        ([cast(psutil.Process, child), cast(psutil.Process, parent)], 5),
        ([cast(psutil.Process, parent)], 3),
    ]


def test_stop_tolerates_disappearing_children_and_signal_failures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parent, child = FakeProcess(), FakeProcess(102)
    child.error = psutil.NoSuchProcess(102)
    parent.descendants = [cast(psutil.Process, child)]
    calls = 0

    def wait_procs(
        processes: list[psutil.Process], timeout: float
    ) -> tuple[list[psutil.Process], list[psutil.Process]]:
        nonlocal calls
        calls += 1
        return ([], [cast(psutil.Process, child)]) if calls == 1 else (processes, [])

    monkeypatch.setattr(psutil, "wait_procs", wait_procs)
    assert BackgroundProcessLauncher(process_factory=factory(parent)).stop(spawned())
    assert child.events == ["terminate", "kill"]


@pytest.mark.parametrize("error", (psutil.AccessDenied(101), OSError("denied")))
def test_stop_unverifiable_process_reports_failure(error: Exception) -> None:
    assert not BackgroundProcessLauncher(process_factory=factory(error)).stop(spawned())


def test_stop_graceful_exit_needs_no_kill(monkeypatch: pytest.MonkeyPatch) -> None:
    process = FakeProcess()

    def wait_procs(
        processes: list[psutil.Process], timeout: float
    ) -> tuple[list[psutil.Process], list[psutil.Process]]:
        return processes, []

    monkeypatch.setattr(psutil, "wait_procs", wait_procs)
    assert BackgroundProcessLauncher(process_factory=factory(process)).stop(spawned())
    assert process.events == ["terminate"]


def test_log_tail_reads_only_end_replaces_bad_utf8_and_bounds_output(tmp_path: Path) -> None:
    path = tmp_path / "output.log"
    launcher = BackgroundProcessLauncher()
    assert launcher.log_tail(path, lines=2) == ""
    assert launcher.log_tail(path, lines=0) == ""
    path.write_bytes(b"skip\n" * 20000 + b"old\n\xff\nsecret=fixture-secret\nlast")
    assert launcher.log_tail(path, lines=3) == "\ufffd\nsecret=[REDACTED]\nlast"
    assert len(launcher.log_tail(path, lines=100000)) <= 4000
    path.write_bytes(b"x" * 80000)
    assert launcher.log_tail(path, lines=1) == "x" * 4000


@pytest.mark.parametrize(
    "text,expected",
    (
        ("Authorization: Basic fixture-auth\nsafe", "Authorization: [REDACTED]\nsafe"),
        ("authorization : Bearer fixture-auth", "authorization : [REDACTED]"),
        ("Bearer fixture-bearer", "Bearer [REDACTED]"),
        ("TOKEN=fixture-value&ok=yes", "TOKEN=[REDACTED]&ok=yes"),
        ("password : 'fixture value'", "password : [REDACTED]"),
        ('{"api_key": "fixture value"}', '{"api_key": [REDACTED]}'),
        ("secret:fixture-value", "secret:[REDACTED]"),
        ("tmn_fixture-Token", "[REDACTED]"),
        ("normal text", "normal text"),
    ),
)
def test_common_credentials_are_redacted(text: str, expected: str) -> None:
    assert redact_log_text(text) == expected


class FakeReader:
    def __init__(self, *listeners: NetworkListener) -> None:
        self.values = listeners

    def listeners(self) -> tuple[NetworkListener, ...]:
        return self.values


def listener(*, pid: int | None = 101, protocol: str = "tcp", port: int = 8080) -> NetworkListener:
    return NetworkListener(
        protocol=protocol, address="::", port=port, pid=pid, process_name="fixture-python"
    )


def test_host_inspector_uses_listener_identity_and_normalizes_directory() -> None:
    reader = FakeReader(listener(protocol="udp"), listener(port=9000), listener())
    inspector: HostInspector = PsutilHostInspector(
        cast(SystemReader, reader), process_factory=factory(FakeProcess())
    )
    assert inspector.current_username() == "fixture-user"
    owner = inspector.port_owner(8080, launch_record())
    assert owner is not None and owner.matches_launch
    assert owner.pid == 101 and owner.process_name == "fixture-python"
    assert inspector.port_owner(9999) is None


@pytest.mark.parametrize(
    "case", ("no-launch", "no-pid", "wrong-args", "wrong-cwd", "denied", "exited", "os-error")
)
def test_port_owner_falls_back_to_listener_name_when_it_cannot_match(case: str) -> None:
    process = FakeProcess()
    if case == "wrong-args":
        process.command = ["python", "other.py"]
    if case == "wrong-cwd":
        process.directory = "other"
    errors: dict[str, Exception] = {
        "denied": psutil.AccessDenied(101),
        "exited": psutil.NoSuchProcess(101),
        "os-error": OSError("denied"),
    }
    reader = FakeReader(listener(pid=None if case == "no-pid" else 101))
    inspector = PsutilHostInspector(
        cast(SystemReader, reader), process_factory=factory(errors.get(case, process))
    )
    owner = inspector.port_owner(8080, None if case == "no-launch" else launch_record())
    assert owner is not None and not owner.matches_launch
    assert owner.process_name == "fixture-python"


def test_socket_probe_reaches_real_loopback_only() -> None:
    verifier: LocalVerifier = SocketLocalVerifier()
    with socket.socket() as server:
        server.bind(("127.0.0.1", 0))
        server.listen()
        port = server.getsockname()[1]
        assert asyncio.run(verifier.port_listening(port))


@pytest.mark.parametrize("ipv6_succeeds", (False, True))
def test_socket_probe_falls_back_to_ipv6_in_a_worker(
    monkeypatch: pytest.MonkeyPatch, ipv6_succeeds: bool
) -> None:
    calls: list[tuple[str, int]] = []
    caller = threading.get_ident()

    def connect(address: tuple[str, int], *, timeout: float) -> socket.socket:
        assert threading.get_ident() != caller and timeout == 1
        calls.append(address)
        if ipv6_succeeds and address[0] == "::1":
            return socket.socket()
        raise OSError("fixture refused")

    monkeypatch.setattr(socket, "create_connection", connect)
    assert asyncio.run(SocketLocalVerifier().port_listening(8080)) is ipv6_succeeds
    assert calls == [("127.0.0.1", 8080), ("::1", 8080)]


@pytest.mark.parametrize("succeeds_on", ("http", "https", None))
def test_web_probe_caps_reads_and_falls_back_to_unverified_https(
    monkeypatch: pytest.MonkeyPatch, succeeds_on: str | None
) -> None:
    caller = threading.get_ident()
    events: list[tuple[str, str]] = []

    class Response:
        status = 503

        def read(self, amount: int) -> bytes:
            assert amount == 16384
            return b"fixture-body"

    class Connection:
        def __init__(
            self, host: str, port: int, *, timeout: float, context: ssl.SSLContext | None = None
        ) -> None:
            assert threading.get_ident() != caller
            assert host == "127.0.0.1" and port == 8080 and timeout == 2
            self.scheme = "https" if context is not None else "http"
            if context is not None:
                assert not context.check_hostname and context.verify_mode == ssl.CERT_NONE

        def request(self, method: str, path: str) -> None:
            assert (method, path) == ("GET", "/")
            events.append((self.scheme, "request"))
            if self.scheme != succeeds_on:
                if self.scheme == "http":
                    raise http.client.BadStatusLine("fixture-invalid")
                raise OSError("fixture refused")

        def getresponse(self) -> Response:
            return Response()

        def close(self) -> None:
            events.append((self.scheme, "close"))

    monkeypatch.setattr(http.client, "HTTPConnection", Connection)
    monkeypatch.setattr(http.client, "HTTPSConnection", Connection)
    assert asyncio.run(SocketLocalVerifier().web_status(8080)) == (503 if succeeds_on else None)
    expected = [("http", "request"), ("http", "close")]
    if succeeds_on != "http":
        expected += [("https", "request"), ("https", "close")]
    assert events == expected
