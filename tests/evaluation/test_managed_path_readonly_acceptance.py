"""阶段 2.5 管理员只读验收包装器的安全门禁。"""

from __future__ import annotations

import asyncio
import json
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

import pytest
import scripts.run_managed_path_readonly_acceptance as acceptance
from scripts.run_managed_path_readonly_acceptance import (
    AcceptanceRequest,
    PlatformRuntime,
    ReadOnlyCommandRunner,
    run_acceptance,
)

from tunnelminion.network.contracts import canonical_sha256
from tunnelminion.network.path_probe import PathProbePolicy, TargetProbe
from tunnelminion.platforms.windows.managed_system import (
    WindowsPeerSnapshot,
    WindowsTunnelSnapshot,
    WindowsWireGuardObserver,
)
from tunnelminion.platforms.windows.path_probe import WindowsPathProbe
from tunnelminion.platforms.windows.system import CommandResult

NOW = datetime(2026, 8, 22, 1, 0, tzinfo=UTC)
PEER = "sensitive-peer-public-key"
ENDPOINT = "192.168.50.10"


class Observer:
    def __init__(self, snapshot: WindowsTunnelSnapshot) -> None:
        self.snapshot = snapshot
        self.calls = 0

    async def observe(self, interface_name: str) -> WindowsTunnelSnapshot:
        assert interface_name == "HomeMac"
        self.calls += 1
        return self.snapshot


def snapshot() -> WindowsTunnelSnapshot:
    return WindowsTunnelSnapshot(
        interface_name="HomeMac",
        interface_present=True,
        interface_up=True,
        service_present=True,
        service_running=True,
        peers=(
            WindowsPeerSnapshot(
                public_key=PEER,
                endpoint_host=ENDPOINT,
                endpoint_port=51820,
                allowed_host_routes=("10.77.0.2/32",),
                latest_handshake_epoch=int(NOW.timestamp()),
            ),
        ),
        host_routes=("10.77.0.2/32",),
    )


def request(*, approved: bool = False, target_port: int = 18880) -> AcceptanceRequest:
    candidate_hash = canonical_sha256({"peer_public_key": PEER, "host": ENDPOINT, "port": 51820})
    return AcceptanceRequest(
        platform="windows",
        interface_name="HomeMac",
        peer_public_key=PEER,
        code_sha="a" * 40,
        approved_candidate_hash=candidate_hash if approved else None,
        target_host="10.77.0.2" if approved else None,
        target_port=target_port if approved else None,
    )


def runtime(
    observer: Observer,
    *,
    elevated: bool = True,
    route_hashes: list[str] | None = None,
    docker_ports: frozenset[int] = frozenset(),
    probe_calls: list[bool] | None = None,
) -> PlatformRuntime:
    values = route_hashes or ["sha256:" + "1" * 64]

    async def route_summary() -> tuple[str, int]:
        return (values.pop(0) if len(values) > 1 else values[0]), 0

    async def deployed_ports() -> tuple[frozenset[int], int]:
        return docker_ports, 1 if docker_ports else 0

    def probe_factory(
        policy: PathProbePolicy,
        target: TargetProbe,
    ) -> WindowsPathProbe:
        if probe_calls is not None:
            probe_calls.append(True)
        return WindowsPathProbe(
            cast(WindowsWireGuardObserver, observer),
            interface_name="HomeMac",
            peer_public_key=PEER,
            policy=policy,
            target_probe=target,
            clock=lambda: NOW,
        )

    return PlatformRuntime(
        observer=observer,
        probe_factory=probe_factory,
        route_summary=route_summary,
        docker_ports=deployed_ports,
        elevated=elevated,
        source_code="windows_production_path_probe",
    )


def test_command_whitelist_allows_only_fixed_readonly_argv() -> None:
    calls: list[tuple[str, ...]] = []

    async def executor(command: tuple[str, ...], timeout: float) -> CommandResult:
        assert timeout > 0
        calls.append(command)
        return CommandResult(returncode=0, stdout="", stderr="")

    tools = {
        "wg": Path("C:/WireGuard/wg.exe"),
        "sc": Path("C:/Windows/sc.exe"),
        "route": Path("C:/Windows/route.exe"),
        "docker": Path("C:/Docker/docker.exe"),
    }
    runner = ReadOnlyCommandRunner(
        platform="windows", tools=tools, interface_name="HomeMac", executor=executor
    )
    asyncio.run(runner.run((str(tools["wg"]), "show", "HomeMac", "peers"), 5))
    assert calls == [(str(tools["wg"]), "show", "HomeMac", "peers")]
    rejected = (
        (str(tools["wg"]), "set", "HomeMac", "peer", PEER),
        (str(tools["route"]), "add", "10.77.0.2"),
        ("sudo", str(tools["wg"]), "show"),
        (str(tools["docker"]), "run", "image"),
    )
    for command in rejected:
        with pytest.raises(ValueError, match="acceptance_command_rejected"):
            asyncio.run(runner.run(command, 5))


def test_macos_command_whitelist_rejects_privilege_and_write_commands() -> None:
    async def executor(command: tuple[str, ...], timeout: float) -> CommandResult:
        del command, timeout
        return CommandResult(returncode=0, stdout="", stderr="")

    tools = {
        "wg": Path("/usr/local/bin/wg"),
        "ifconfig": Path("/sbin/ifconfig"),
        "netstat": Path("/usr/sbin/netstat"),
        "docker": Path("/usr/local/bin/docker"),
    }
    runner = ReadOnlyCommandRunner(
        platform="macos", tools=tools, interface_name="utun9", executor=executor
    )
    asyncio.run(runner.run((str(tools["netstat"]), "-rn", "-f", "inet"), 10))
    for command in (
        ("sudo", str(tools["wg"]), "show", "interfaces"),
        ("/usr/local/bin/wg-quick", "up", "utun9"),
        ("/sbin/route", "add", "10.77.0.2"),
    ):
        with pytest.raises(ValueError, match="acceptance_command_rejected"):
            asyncio.run(runner.run(command, 5))


@pytest.mark.parametrize("host", ["10.77.0.3", "0.0.0.0", "*"])
def test_target_host_is_exactly_gated(host: str) -> None:
    value = request(approved=True)
    with pytest.raises(ValueError, match="target_host_rejected"):
        asyncio.run(run_acceptance(replace(value, target_host=host)))


def test_target_port_requires_reserved_range_or_deployed_docker_proof(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def target(host: str, port: int, timeout: float) -> bool:
        del host, port, timeout
        return True

    monkeypatch.setattr(acceptance, "tcp_target_probe", target)
    observer = Observer(snapshot())
    rejected = asyncio.run(
        run_acceptance(request(approved=True, target_port=8080), runtime=runtime(observer))
    )
    assert rejected["stable_error_code"] == "target_port_rejected"
    assert rejected["probe_executed"] is False

    observer = Observer(snapshot())
    accepted = asyncio.run(
        run_acceptance(
            request(approved=True, target_port=8080),
            runtime=runtime(observer, docker_ports=frozenset({8080})),
        )
    )
    assert accepted["stable_error_code"] != "target_port_rejected"


def test_non_administrator_fails_before_observation() -> None:
    observer = Observer(snapshot())
    report = asyncio.run(run_acceptance(request(), runtime=runtime(observer, elevated=False)))
    assert report["preflight"] == {
        "elevated": False,
        "stable_error_code": "permission_denied",
    }
    assert observer.calls == 0


def test_network_change_stops_before_production_probe_and_target() -> None:
    observer = Observer(snapshot())
    probe_calls: list[bool] = []
    report = asyncio.run(
        run_acceptance(
            request(approved=True),
            runtime=runtime(
                observer,
                route_hashes=["sha256:" + "1" * 64, "sha256:" + "2" * 64],
                probe_calls=probe_calls,
            ),
            clock=lambda: NOW,
        )
    )
    assert report["stable_error_code"] == "network_state_changed"
    assert report["network_state_unchanged"] is False
    assert report["after"] != report["before"]
    assert report["target_probe_executed"] is False
    assert probe_calls == []


def test_network_change_at_connect_guard_stops_target_probe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target_calls: list[bool] = []

    async def target(host: str, port: int, timeout: float) -> bool:
        del host, port, timeout
        target_calls.append(True)
        return True

    monkeypatch.setattr(acceptance, "tcp_target_probe", target)
    observer = Observer(snapshot())
    probe_calls: list[bool] = []
    report = asyncio.run(
        run_acceptance(
            request(approved=True),
            runtime=runtime(
                observer,
                route_hashes=[
                    "sha256:" + "1" * 64,
                    "sha256:" + "1" * 64,
                    "sha256:" + "2" * 64,
                ],
                probe_calls=probe_calls,
            ),
            clock=lambda: NOW,
        )
    )
    assert report["stable_error_code"] == "network_state_changed"
    assert report["network_state_unchanged"] is False
    assert report["after"] != report["before"]
    assert report["probe_executed"] is True
    assert report["target_probe_executed"] is False
    assert probe_calls == [True]
    assert target_calls == []


def test_preflight_output_contains_only_redacted_candidate_hash() -> None:
    report = asyncio.run(
        run_acceptance(request(), runtime=runtime(Observer(snapshot())), clock=lambda: NOW)
    )
    serialized = json.dumps(report, ensure_ascii=False)
    assert report["candidate_count"] == 1
    assert str(report["candidate_hash"]).startswith("sha256:")
    for forbidden in (PEER, ENDPOINT, "HomeMac", "10.77.0.2/32"):
        assert forbidden not in serialized


def test_approved_probe_uses_production_class_and_redacts_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target_calls: list[tuple[str, int]] = []

    async def target(host: str, port: int, timeout: float) -> bool:
        assert timeout == 2
        target_calls.append((host, port))
        return True

    monkeypatch.setattr(acceptance, "tcp_target_probe", target)
    report = asyncio.run(
        run_acceptance(
            request(approved=True), runtime=runtime(Observer(snapshot())), clock=lambda: NOW
        )
    )
    assert report["passed"] is True
    assert report["network_state_unchanged"] is True
    assert target_calls == [("10.77.0.2", 18880)]
    serialized = json.dumps(report, ensure_ascii=False)
    for forbidden in (PEER, ENDPOINT, "HomeMac", "10.77.0.2"):
        assert forbidden not in serialized
