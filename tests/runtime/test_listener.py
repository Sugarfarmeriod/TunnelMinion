from __future__ import annotations

import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import psutil
import pytest

import tunnelminion.runtime.listener as listener_module
from tunnelminion.gateway.configuration import (
    FileGatewayConfigurationRepository,
    GatewayConfiguration,
)
from tunnelminion.gateway.security import GatewayBindConfig
from tunnelminion.runtime.lifecycle import ReadinessResult
from tunnelminion.runtime.listener import (
    GatewayListenerOwnershipProbe,
    ListenerEndpoint,
    ListenerTarget,
)
from tunnelminion.runtime.profile import RuntimeComponent


@dataclass
class Connection:
    laddr: object
    type: int = 1
    status: str = psutil.CONN_LISTEN


class FakeProcess:
    def __init__(
        self, connections: tuple[object, ...] = (), error: BaseException | None = None
    ) -> None:
        self.connections = connections
        self.error = error

    def net_connections(self, kind: str = "inet") -> tuple[object, ...]:
        assert kind == "inet"
        if self.error is not None:
            raise self.error
        return self.connections


def _data_dir(tmp_path: Path, host: str = "10.77.0.1", port: int = 8787) -> Path:
    path = tmp_path / "data"
    FileGatewayConfigurationRepository(path / "gateway.json").save(
        GatewayConfiguration(bind=GatewayBindConfig(host=host, port=port))
    )
    return path


def _probe(
    tmp_path: Path,
    process: FakeProcess,
    *,
    lsof_path: str | None = None,
    command_runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> GatewayListenerOwnershipProbe:
    return GatewayListenerOwnershipProbe(
        _data_dir(tmp_path),
        process_factory=lambda pid: process,
        lsof_path=lsof_path,
        command_runner=command_runner,
    )


def test_owned_listener_is_ready_and_wrong_component_is_rejected(tmp_path: Path) -> None:
    probe = _probe(
        tmp_path,
        FakeProcess((Connection(("10.77.0.1", 8787)),)),
    )
    assert probe.readiness(RuntimeComponent.GATEWAY, 42, 0.5) == ReadinessResult(True)
    assert probe.healthy(RuntimeComponent.GATEWAY, 42)
    assert probe.readiness(RuntimeComponent.LOCAL, 42, 0.5) == ReadinessResult(
        False, "listener_probe_wrong_component"
    )


def test_gateway_listener_owned_by_runtime_child_maps_to_managed_parent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    processes = {
        42: FakeProcess(),
        43: FakeProcess((Connection(("10.77.0.1", 8787)),)),
    }

    def process(pid: int) -> FakeProcess:
        return processes[pid]

    def child_pids(pid: int, component: RuntimeComponent) -> tuple[int, ...]:
        assert pid == 42
        assert component is RuntimeComponent.GATEWAY
        return (43,)

    probe = GatewayListenerOwnershipProbe(
        _data_dir(tmp_path),
        process_factory=process,
    )
    monkeypatch.setattr(
        listener_module,
        "_runtime_child_pids",
        child_pids,
    )

    assert probe.readiness(RuntimeComponent.GATEWAY, 42, 0.5) == ReadinessResult(True)


@pytest.mark.parametrize(
    ("connections", "expected"),
    [
        ((Connection(("10.77.0.1", 8787), status="ESTABLISHED"),), "listener_missing"),
        ((Connection(("10.77.0.1", 8787), type=2, status="NONE"),), None),
        ((Connection(("127.0.0.1", 8787)),), "listener_missing"),
        ((Connection(("0.0.0.0", 8787)),), None),
        ((Connection(("10.77.0.1", 8787), type=2),), None),
    ],
)
def test_listener_matching_and_non_tcp_connections(
    tmp_path: Path,
    connections: tuple[Connection, ...],
    expected: str | None,
) -> None:
    probe = _probe(tmp_path, FakeProcess(connections))
    result = probe.readiness(RuntimeComponent.GATEWAY, 42, 0.5)
    if expected is None:
        assert result.ready
    else:
        assert result.error_code == expected


def test_foreign_listener_conflict_is_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    probe = _probe(tmp_path, FakeProcess(error=psutil.AccessDenied()))
    monkeypatch.setattr("tunnelminion.runtime.listener.sys.platform", "darwin")

    def foreign(
        pid: int,
        target: ListenerTarget,
        timeout: float,
    ) -> tuple[ListenerEndpoint, ...]:
        del pid, timeout
        return (ListenerEndpoint(target.host, target.port, 42),)

    monkeypatch.setattr(
        probe,
        "_lsof_endpoints",
        foreign,
    )
    result = probe.readiness(RuntimeComponent.GATEWAY, 43, 0.5)
    assert result == ReadinessResult(False, "ownership_conflict")


@pytest.mark.parametrize(
    "error",
    [psutil.AccessDenied(), psutil.NoSuchProcess(42), OSError("denied")],
)
def test_process_probe_error_is_sanitized(tmp_path: Path, error: BaseException) -> None:
    probe = _probe(tmp_path, FakeProcess(error=error))
    result = probe.readiness(RuntimeComponent.GATEWAY, 42, 0.5)
    assert result.error_code in {
        "listener_ownership_unverified",
        "process_missing",
    }


def test_missing_and_invalid_gateway_configuration_are_unready(tmp_path: Path) -> None:
    missing = GatewayListenerOwnershipProbe(
        tmp_path / "missing",
        process_factory=lambda pid: FakeProcess(),
    )
    assert missing.readiness(RuntimeComponent.GATEWAY, 42, 0.5) == ReadinessResult(
        False, "gateway_unconfigured"
    )

    invalid_dir = tmp_path / "invalid"
    invalid_dir.mkdir()
    (invalid_dir / "gateway.json").write_text("{}", encoding="utf-8")
    invalid = GatewayListenerOwnershipProbe(
        invalid_dir,
        process_factory=lambda pid: FakeProcess(),
    )
    assert invalid.readiness(RuntimeComponent.GATEWAY, 42, 0.5) == ReadinessResult(
        False, "gateway_unconfigured"
    )


def test_lsof_fallback_is_fixed_and_redacted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    commands: list[tuple[str, ...]] = []

    def runner(command: tuple[str, ...], **kwargs: object) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        assert kwargs.get("shell", False) is False
        return subprocess.CompletedProcess(
            command,
            0,
            "COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME\n"
            "Python 42 me 4u IPv4 0x1 0t0 TCP 10.77.0.1:8787 (LISTEN)\n"
            "bad\n"
            "bad-pid nope me 4u IPv4 0x1 0t0 TCP 10.77.0.1:8787 (LISTEN)\n"
            "Other 99 me 4u IPv4 0x1 0t0 TCP 10.77.0.1:8787 (LISTEN)\n"
            "missing-endpoint 42 me 4u IPv4 0x1 0t0 (LISTEN) TCP\n"
            "missing-colon 42 me 4u IPv4 0x1 0t0 TCP localhost (LISTEN)\n"
            "bad-port 42 me 4u IPv4 0x1 0t0 TCP 10.77.0.1:http (LISTEN)\n",
            "ignored-secret-body",
        )

    monkeypatch.setattr("tunnelminion.runtime.listener.sys.platform", "darwin")
    process = FakeProcess(error=psutil.AccessDenied())
    probe = _probe(tmp_path, process, lsof_path="/usr/sbin/lsof", command_runner=runner)
    result = probe.readiness(RuntimeComponent.GATEWAY, 42, 0.5)
    assert result == ReadinessResult(True)
    assert commands == [
        (
            "/usr/sbin/lsof",
            "-nP",
            "-a",
            "-p",
            "42",
            "-iTCP@10.77.0.1:8787",
            "-sTCP:LISTEN",
        )
    ]


@pytest.mark.parametrize(
    "runner_result",
    [
        FileNotFoundError(),
        subprocess.TimeoutExpired(("lsof",), 0.5),
        subprocess.CompletedProcess(("lsof",), 2, "", "denied"),
        subprocess.CompletedProcess(("lsof",), 1, "", ""),
    ],
)
def test_lsof_failure_returns_unverified(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    runner_result: BaseException | subprocess.CompletedProcess[str],
) -> None:
    def runner(command: tuple[str, ...], **kwargs: object) -> subprocess.CompletedProcess[str]:
        del command, kwargs
        if isinstance(runner_result, BaseException):
            raise runner_result
        return runner_result

    monkeypatch.setattr("tunnelminion.runtime.listener.sys.platform", "darwin")
    probe = _probe(
        tmp_path,
        FakeProcess(error=psutil.AccessDenied()),
        command_runner=runner,
    )
    result = probe.readiness(RuntimeComponent.GATEWAY, 42, 0.5)
    assert result == ReadinessResult(False, "listener_ownership_unverified")


def test_process_missing_does_not_run_lsof_and_is_reported(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    called = False

    def runner(command: tuple[str, ...], **kwargs: object) -> subprocess.CompletedProcess[str]:
        nonlocal called
        del command, kwargs
        called = True
        return subprocess.CompletedProcess(("lsof",), 0, "", "")

    monkeypatch.setattr("tunnelminion.runtime.listener.sys.platform", "darwin")
    probe = _probe(tmp_path, FakeProcess(error=psutil.NoSuchProcess(42)), command_runner=runner)
    assert probe.readiness(RuntimeComponent.GATEWAY, 42, 0.5) == ReadinessResult(
        False, "process_missing"
    )
    assert not called


def test_address_object_and_short_tuple_are_ignored_or_used(tmp_path: Path) -> None:
    class Address:
        ip = "10.77.0.1"
        port = 8787

    probe = _probe(
        tmp_path,
        FakeProcess(
            (
                Connection(Address()),
                Connection(("short",)),
                Connection((1, 2)),
                object(),
            )
        ),
    )
    assert probe.readiness(RuntimeComponent.GATEWAY, 42, 0.5) == ReadinessResult(True)


def test_target_dataclass_is_constructible() -> None:
    assert ListenerTarget("127.0.0.1", 8080) == ListenerTarget("127.0.0.1", 8080)
    assert ListenerEndpoint("127.0.0.1", 8080, 42).pid == 42


def test_runtime_child_filter_keeps_only_matching_component(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Child:
        def __init__(
            self,
            pid: int,
            command_line: list[str] | None = None,
            error: BaseException | None = None,
        ):
            self.pid = pid
            self.command_line = command_line or []
            self.error = error

        def cmdline(self) -> list[str]:
            if self.error is not None:
                raise self.error
            return self.command_line

    class Root:
        def children(self, recursive: bool) -> list[Child]:
            assert recursive
            return [
                Child(1, ["runtime-child", "--runtime-component=gateway"]),
                Child(2, ["runtime-child", "--runtime-component=local"]),
                Child(3, error=psutil.AccessDenied()),
            ]

    def process(pid: int) -> Root:
        del pid
        return Root()

    monkeypatch.setattr(listener_module.psutil, "Process", process)
    assert listener_module._runtime_child_pids(42, RuntimeComponent.GATEWAY) == (1,)  # pyright: ignore[reportPrivateUsage]


def test_runtime_child_filter_fails_closed_when_parent_is_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def missing(pid: int) -> object:
        del pid
        raise psutil.NoSuchProcess(42)

    monkeypatch.setattr(listener_module.psutil, "Process", missing)
    assert listener_module._runtime_child_pids(42, RuntimeComponent.GATEWAY) == ()  # pyright: ignore[reportPrivateUsage]
