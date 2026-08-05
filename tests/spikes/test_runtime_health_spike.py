from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import cast

import psutil
import pytest
from spikes.runtime_health.fixture import (
    FixtureScenario,
    PeerAcceptance,
    build_fixture_report,
)
from spikes.runtime_health.ownership import (
    ListenerEndpoint,
    ListenerTarget,
    OwnershipVerdict,
    ProcessSocketProbeResult,
    classify_listener_ownership,
    fixed_lsof_command,
    inspect_process_sockets,
    parse_lsof_listener_output,
)


def test_fixture_separates_hairpin_from_peer_acceptance() -> None:
    report = build_fixture_report()
    scenarios = cast(list[dict[str, object]], report["scenarios"])

    assert report["mode"] == "fake_no_system_writes"
    assert report["production_secret_store_read"] is False
    assert report["production_process_touched"] is False
    assert scenarios[0]["scenario"] == FixtureScenario.HAIRPIN_FAILED_PEER_REACHABLE
    assert scenarios[0]["peer_acceptance"] == PeerAcceptance.PEER_REACHABLE
    assert scenarios[1]["peer_acceptance"] == PeerAcceptance.PEER_UNREACHABLE
    assert report["conclusion"] == {
        "local_running_requires_process_and_listener_ownership": True,
        "peer_401_is_independent_acceptance_evidence": True,
        "hairpin_timeout_is_not_local_startup_failure": True,
        "listener_presence_is_not_peer_acceptance": True,
    }


@dataclass
class FakeConnection:
    laddr: tuple[str, int]
    type: int = 1
    status: str = psutil.CONN_LISTEN


class FakeProcess:
    def __init__(
        self, connections: tuple[object, ...] | None = None, error: BaseException | None = None
    ):
        self.connections = connections or ()
        self.error = error

    def net_connections(self, kind: str = "inet") -> tuple[object, ...]:
        assert kind == "inet"
        if self.error is not None:
            raise self.error
        return self.connections


def test_process_socket_probe_filters_non_listening_connections() -> None:
    result = inspect_process_sockets(
        42,
        process_factory=lambda pid: FakeProcess(
            (
                FakeConnection(("127.0.0.1", 8787)),
                FakeConnection(("127.0.0.1", 8788), status="ESTABLISHED"),
                FakeConnection(("127.0.0.1", 8789), type=2, status="NONE"),
                object(),
            )
        ),
    )
    assert result == ProcessSocketProbeResult(
        True,
        (ListenerEndpoint("127.0.0.1", 8787, 42), ListenerEndpoint("127.0.0.1", 8789, 42)),
    )


@pytest.mark.parametrize(
    ("error", "error_code"),
    [
        (psutil.AccessDenied(), "permission_denied"),
        (psutil.NoSuchProcess(42), "process_missing"),
        (OSError("socket"), "socket_probe_failed"),
    ],
)
def test_process_socket_probe_sanitizes_platform_errors(
    error: BaseException,
    error_code: str,
) -> None:
    result = inspect_process_sockets(42, process_factory=lambda pid: FakeProcess(error=error))
    assert result == ProcessSocketProbeResult(False, error_code=error_code)


def test_fixed_lsof_command_has_no_shell_or_user_supplied_flags() -> None:
    target = ListenerTarget("10.77.0.1", 8787)
    assert fixed_lsof_command("/usr/sbin/lsof", 42, target) == (
        "/usr/sbin/lsof",
        "-nP",
        "-a",
        "-p",
        "42",
        "-iTCP@10.77.0.1:8787",
        "-sTCP:LISTEN",
    )


def test_lsof_parser_keeps_only_expected_pid_listeners() -> None:
    output = """COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
Python 42 me 4u IPv4 0x1 0t0 TCP 10.77.0.1:8787 (LISTEN)
Other 43 me 4u IPv4 0x2 0t0 TCP 10.77.0.1:8787 (LISTEN)
Python 42 me 5u IPv4 0x3 0t0 TCP 127.0.0.1:8788 (ESTABLISHED)
bad 42 me 5u IPv4 0x3 0t0 TCP 10.77.0.1:not-port (LISTEN)
"""
    assert parse_lsof_listener_output(output, expected_pid=42) == (
        ListenerEndpoint("10.77.0.1", 8787, 42),
    )


def test_ownership_fails_closed_and_detects_foreign_listener() -> None:
    target = ListenerTarget("10.77.0.1", 8787)
    owned = ProcessSocketProbeResult(True, (ListenerEndpoint("10.77.0.1", 8787, 42),))
    foreign = ProcessSocketProbeResult(True, (ListenerEndpoint("10.77.0.1", 8787, 43),))
    unavailable = ProcessSocketProbeResult(False, error_code="permission_denied")

    assert (
        classify_listener_ownership(expected_pid=42, target=target, process_result=owned)
        is OwnershipVerdict.OWNED
    )
    assert (
        classify_listener_ownership(expected_pid=42, target=target, process_result=foreign)
        is OwnershipVerdict.CONFLICT
    )
    assert (
        classify_listener_ownership(
            expected_pid=42, target=target, process_result=owned.__class__(True, ())
        )
        is OwnershipVerdict.MISSING
    )
    assert (
        classify_listener_ownership(expected_pid=42, target=target, process_result=unavailable)
        is OwnershipVerdict.UNVERIFIED
    )
    assert (
        classify_listener_ownership(
            expected_pid=42,
            target=target,
            process_result=unavailable,
            fallback_endpoints=(ListenerEndpoint("10.77.0.1", 8787, 42),),
        )
        is OwnershipVerdict.OWNED
    )


@pytest.mark.parametrize(
    "factory",
    [
        lambda: ListenerTarget("", 8787),
        lambda: ListenerTarget("127.0.0.1", 0),
        lambda: ListenerTarget("127.0.0.1", 65536),
    ],
)
def test_spike_rejects_invalid_targets(factory: Callable[[], ListenerTarget]) -> None:
    with pytest.raises(ValueError):
        factory()


def test_spike_rejects_invalid_pid_and_lsof_path() -> None:
    target = ListenerTarget("127.0.0.1", 8000)
    with pytest.raises(ValueError):
        inspect_process_sockets(0)
    with pytest.raises(ValueError):
        fixed_lsof_command("", 42, target)
    with pytest.raises(ValueError):
        parse_lsof_listener_output("", expected_pid=0)
    with pytest.raises(ValueError):
        classify_listener_ownership(
            expected_pid=0,
            target=target,
            process_result=ProcessSocketProbeResult(True),
        )
