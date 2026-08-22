"""Windows managed 固定命令、预检与 observe-only 联合观察测试。"""

from __future__ import annotations

import asyncio
import socket
from pathlib import Path

import pytest
from pydantic import ValidationError

from tunnelminion.network.contracts import ProviderMode
from tunnelminion.platforms.windows.managed_system import (
    FixedWindowsWireGuardCommands,
    WindowsPeerSnapshot,
    WindowsProviderPaths,
    WindowsWireGuardObserver,
    _is_observable_host_route,  # pyright: ignore[reportPrivateUsage]
    _safe_host_route,  # pyright: ignore[reportPrivateUsage]
    parse_safe_allowed_network,
    parse_wireguard_endpoint,
    peer_owns_unique_target,
    system_interface_index,
    windows_is_administrator,
    windows_route_contains_exact_host,
)
from tunnelminion.platforms.windows.models import (
    InterfaceSnapshot,
    NetworkListener,
    ProcessInfo,
)
from tunnelminion.platforms.windows.system import CommandResult


class FakeRunner:
    def __init__(self) -> None:
        self.results: dict[tuple[str, ...], CommandResult] = {}
        self.commands: list[tuple[str, ...]] = []

    async def run(
        self,
        command: tuple[str, ...],
        timeout_seconds: float,
    ) -> CommandResult:
        assert timeout_seconds > 0
        self.commands.append(command)
        return self.results.get(command, CommandResult(returncode=0, stdout="", stderr=""))


class FakeReader:
    def __init__(self, value: InterfaceSnapshot | None) -> None:
        self.value = value

    def interface(self, name: str) -> InterfaceSnapshot | None:
        assert name in {"HomeMac", "tmn-test-a"}
        return self.value

    def listeners(self) -> tuple[NetworkListener, ...]:
        raise AssertionError("observer 不应枚举监听")

    def processes(self, limit: int) -> tuple[ProcessInfo, ...]:
        raise AssertionError(f"observer 不应枚举进程：{limit}")


def paths(tmp_path: Path) -> WindowsProviderPaths:
    return WindowsProviderPaths(
        wireguard_exe=tmp_path / "wireguard.exe",
        wg_exe=tmp_path / "wg.exe",
        sc_exe=tmp_path / "sc.exe",
        route_exe=tmp_path / "route.exe",
        config_root=tmp_path / "configs",
    )


def commands(
    tmp_path: Path,
    runner: FakeRunner,
    *,
    platform: str = "nt",
    exists: bool = True,
    admin: bool = True,
) -> FixedWindowsWireGuardCommands:
    return FixedWindowsWireGuardCommands(
        paths(tmp_path),
        runner,
        path_exists=lambda _path: exists,
        is_administrator=lambda: admin,
        platform_name=platform,
    )


def test_paths_and_preflight_degrade_without_blocking_observation(tmp_path: Path) -> None:
    with pytest.raises(ValidationError, match="绝对路径"):
        WindowsProviderPaths(
            wireguard_exe=Path("wireguard.exe"),
            wg_exe=tmp_path / "wg.exe",
            sc_exe=tmp_path / "sc.exe",
            route_exe=tmp_path / "route.exe",
            config_root=tmp_path / "configs",
        )
    runner = FakeRunner()
    ready = commands(tmp_path, runner).preflight()
    assert ready.mode is ProviderMode.MANAGED
    assert ready.error_code is None

    unsupported = commands(tmp_path, runner, platform="posix").preflight()
    assert unsupported.mode is ProviderMode.OBSERVE_ONLY
    assert unsupported.error_code == "platform_unsupported"

    missing = commands(tmp_path, runner, exists=False).preflight()
    assert missing.error_code == "dependency_unavailable"

    denied = commands(tmp_path, runner, admin=False).preflight()
    assert denied.error_code == "permission_denied"
    assert not windows_is_administrator(platform_name="posix")
    assert windows_is_administrator(platform_name="nt", native_check=lambda: True)


def test_fixed_commands_reject_dynamic_fields_names_routes_and_paths(tmp_path: Path) -> None:
    runner = FakeRunner()
    fixed = commands(tmp_path, runner)
    config = fixed.config_path("tmn-test-a", 1)
    asyncio.run(fixed.install_tunnel("tmn-test-a", config))
    asyncio.run(fixed.uninstall_tunnel("tmn-test-a.r1"))
    asyncio.run(fixed.uninstall_tunnel("tmn-test-a"))
    asyncio.run(fixed.stop_tunnel("tmn-test-a"))
    asyncio.run(fixed.show("HomeMac", "peers"))
    asyncio.run(fixed.show("HomeMac", "endpoints"))
    asyncio.run(fixed.query_service("HomeMac"))
    asyncio.run(fixed.query_route("10.203.0.2/32"))
    asyncio.run(fixed.query_route("fd00::2/128"))
    asyncio.run(fixed.route_table())
    assert all(isinstance(command, tuple) for command in runner.commands)
    assert (str(fixed.paths.route_exe), "print", "-6", "fd00::2") in runner.commands
    assert all("powershell" not in " ".join(command).lower() for command in runner.commands)

    with pytest.raises(ValueError, match="观察字段"):
        asyncio.run(fixed.show("HomeMac", "private-key"))
    with pytest.raises(ValueError, match="接口名称"):
        asyncio.run(fixed.show("bad;&", "peers"))
    with pytest.raises(ValueError, match="接口名称"):
        asyncio.run(fixed.install_tunnel("HomeMac", config))
    with pytest.raises(ValueError, match="host route"):
        asyncio.run(fixed.query_route("10.203.0.0/24"))
    with pytest.raises(ValueError, match="revision"):
        fixed.config_path("tmn-test-a", 0)
    with pytest.raises(ValueError, match="固定受管目录"):
        asyncio.run(
            fixed.install_tunnel(
                "tmn-test-a",
                tmp_path / "outside.conf",
            )
        )


def test_observer_handles_absent_service_errors_and_wg_degradation(tmp_path: Path) -> None:
    runner = FakeRunner()
    fixed = commands(tmp_path, runner)
    sc = (str(fixed.paths.sc_exe), "query", "WireGuardTunnel$HomeMac")
    runner.results[sc] = CommandResult(returncode=1060, stdout="", stderr="")
    absent = asyncio.run(WindowsWireGuardObserver(FakeReader(None), fixed).observe("HomeMac"))
    assert not absent.interface_present
    assert absent.observed_error_code is None

    runner.results[sc] = CommandResult(returncode=5, stdout="", stderr="denied")
    errored = asyncio.run(WindowsWireGuardObserver(FakeReader(None), fixed).observe("HomeMac"))
    assert errored.observed_error_code == "service_query_failed"

    runner.results[sc] = CommandResult(returncode=0, stdout="STATE : 4 RUNNING", stderr="")
    public = (str(fixed.paths.wg_exe), "show", "HomeMac", "public-key")
    runner.results[public] = CommandResult(returncode=1, stdout="", stderr="denied")
    degraded = asyncio.run(
        WindowsWireGuardObserver(
            FakeReader(InterfaceSnapshot(name="HomeMac", is_up=True)),
            fixed,
        ).observe("HomeMac")
    )
    assert degraded.interface_present
    assert degraded.service_running
    assert degraded.observed_error_code == "wireguard_query_failed"


def test_observer_parses_bounded_peers_routes_handshakes_and_fingerprint(
    tmp_path: Path,
) -> None:
    runner = FakeRunner()
    fixed = commands(tmp_path, runner)
    prefix = (str(fixed.paths.wg_exe), "show", "tmn-test-a")
    runner.results[(str(fixed.paths.sc_exe), "query", "WireGuardTunnel$tmn-test-a")] = (
        CommandResult(returncode=0, stdout="RUNNING", stderr="")
    )
    runner.results[(*prefix, "public-key")] = CommandResult(
        returncode=0,
        stdout="own-public\n",
        stderr="",
    )
    runner.results[(*prefix, "peers")] = CommandResult(
        returncode=0,
        stdout="peer-a\npeer-b\n",
        stderr="",
    )
    runner.results[(*prefix, "endpoints")] = CommandResult(
        returncode=0,
        stdout="peer-a\t[fd00::10]:51820\npeer-b\t10.203.0.3:51821\n",
        stderr="",
    )
    runner.results[(*prefix, "allowed-ips")] = CommandResult(
        returncode=0,
        stdout="peer-a\t10.203.0.2/32\npeer-b\t10.203.0.3/32\nmalformed\n",
        stderr="",
    )
    runner.results[(*prefix, "latest-handshakes")] = CommandResult(
        returncode=0,
        stdout="peer-a\t123\npeer-b\tbad\n",
        stderr="",
    )
    runner.results[(str(fixed.paths.route_exe), "print", "10.203.0.2")] = CommandResult(
        returncode=0,
        stdout=(
            "IPv4 Route Table\n"
            "Active Routes:\n"
            "Network Destination        Netmask          Gateway       Interface  Metric\n"
            "10.203.0.2                255.255.255.255  On-link       10.203.0.1  1\n"
            "Persistent Routes:\n"
            "  None\n"
        ),
        stderr="",
    )
    runner.results[(str(fixed.paths.route_exe), "print", "10.203.0.3")] = CommandResult(
        returncode=1, stdout="", stderr=""
    )
    observer = WindowsWireGuardObserver(
        FakeReader(
            InterfaceSnapshot(
                name="tmn-test-a",
                is_up=True,
                addresses=("10.203.0.1", "fd00::1%7", "invalid"),
            )
        ),
        fixed,
        interface_index=lambda _name: 7,
    )
    snapshot = asyncio.run(observer.observe("tmn-test-a"))
    assert snapshot.service_running
    assert snapshot.addresses == ("10.203.0.1/32", "fd00::1/128")
    assert snapshot.host_routes == ("10.203.0.2/32",)
    assert snapshot.peers[0].latest_handshake_epoch == 123
    assert snapshot.peers[0].endpoint_host == "fd00::10"
    assert snapshot.peers[0].endpoint_port == 51820
    assert snapshot.peers[1].latest_handshake_epoch is None
    assert snapshot.public_key_hash is not None
    assert snapshot.stable_interface_id == "windows:tmn-test-a"
    assert (
        snapshot.system_fingerprint
        == snapshot.model_copy(
            update={
                "service_running": False,
                "peers": (
                    snapshot.peers[0].model_copy(update={"latest_handshake_epoch": 999}),
                    snapshot.peers[1],
                ),
            }
        ).system_fingerprint
    )


def test_observer_ignores_non_host_allowed_routes_before_querying(tmp_path: Path) -> None:
    runner = FakeRunner()
    fixed = commands(tmp_path, runner)
    prefix = (str(fixed.paths.wg_exe), "show", "tmn-test-a")
    runner.results[(str(fixed.paths.sc_exe), "query", "WireGuardTunnel$tmn-test-a")] = (
        CommandResult(returncode=0, stdout="RUNNING", stderr="")
    )
    runner.results[(*prefix, "public-key")] = CommandResult(
        returncode=0, stdout="own-public\n", stderr=""
    )
    runner.results[(*prefix, "peers")] = CommandResult(returncode=0, stdout="peer-a\n", stderr="")
    runner.results[(*prefix, "endpoints")] = CommandResult(
        returncode=0, stdout="peer-a\t10.203.0.3:51820\n", stderr=""
    )
    runner.results[(*prefix, "allowed-ips")] = CommandResult(
        returncode=0,
        stdout=(
            "peer-a\t10.203.0.2/32,10.203.0.0/24,0.0.0.0/0,"
            "224.0.0.0/4,224.0.0.1/32,255.255.255.255/32,*,malformed\n"
        ),
        stderr="",
    )
    runner.results[(*prefix, "latest-handshakes")] = CommandResult(
        returncode=0, stdout="peer-a\t123\n", stderr=""
    )
    route_command = (str(fixed.paths.route_exe), "print", "10.203.0.2")
    runner.results[route_command] = CommandResult(
        returncode=0,
        stdout=(
            "IPv4 Route Table\n"
            "Active Routes:\n"
            "Network Destination        Netmask          Gateway       Interface  Metric\n"
            "10.203.0.2                255.255.255.255  On-link       10.203.0.1  1\n"
            "Persistent Routes:\n"
        ),
        stderr="",
    )
    observer = WindowsWireGuardObserver(
        FakeReader(InterfaceSnapshot(name="tmn-test-a", is_up=True, addresses=("10.203.0.1",))),
        fixed,
        interface_index=lambda _name: 7,
    )

    snapshot = asyncio.run(observer.observe("tmn-test-a"))

    assert snapshot.peers[0].allowed_host_routes == ("10.203.0.2/32",)
    assert snapshot.peers[0].allowed_networks == ("10.203.0.2/32", "10.203.0.0/24")
    assert snapshot.host_routes == ("10.203.0.2/32",)
    assert [
        command
        for command in runner.commands
        if command[:2] == (str(fixed.paths.route_exe), "print")
    ] == [route_command]


def test_observer_uses_unique_broad_owner_but_queries_exact_target_route(
    tmp_path: Path,
) -> None:
    runner = FakeRunner()
    fixed = commands(tmp_path, runner)
    prefix = (str(fixed.paths.wg_exe), "show", "tmn-test-a")
    runner.results[(str(fixed.paths.sc_exe), "query", "WireGuardTunnel$tmn-test-a")] = (
        CommandResult(returncode=0, stdout="RUNNING", stderr="")
    )
    runner.results[(*prefix, "public-key")] = CommandResult(
        returncode=0, stdout="own-public\n", stderr=""
    )
    runner.results[(*prefix, "peers")] = CommandResult(returncode=0, stdout="peer-a\n", stderr="")
    runner.results[(*prefix, "endpoints")] = CommandResult(
        returncode=0, stdout="peer-a\t10.203.0.3:51820\n", stderr=""
    )
    runner.results[(*prefix, "allowed-ips")] = CommandResult(
        returncode=0, stdout="peer-a\t10.203.0.0/24\n", stderr=""
    )
    runner.results[(*prefix, "latest-handshakes")] = CommandResult(
        returncode=0, stdout="peer-a\t123\n", stderr=""
    )
    target_command = (str(fixed.paths.route_exe), "print", "10.203.0.2")
    runner.results[target_command] = CommandResult(
        returncode=0,
        stdout=(
            "IPv4 Route Table\n"
            "Active Routes:\n"
            "Network Destination        Netmask          Gateway       Interface  Metric\n"
            "10.203.0.2                255.255.255.255  On-link       10.203.0.1  1\n"
            "Persistent Routes:\n"
        ),
        stderr="",
    )
    observer = WindowsWireGuardObserver(
        FakeReader(InterfaceSnapshot(name="tmn-test-a", is_up=True, addresses=("10.203.0.1",))),
        fixed,
        interface_index=lambda _name: 7,
    )

    snapshot = asyncio.run(
        observer.observe_path(
            "tmn-test-a",
            peer_public_key="peer-a",
            expected_host_route="10.203.0.2/32",
        )
    )

    assert snapshot.peers[0].allowed_host_routes == ()
    assert snapshot.peers[0].allowed_networks == ("10.203.0.0/24",)
    assert snapshot.host_routes == ("10.203.0.2/32",)
    assert [
        command
        for command in runner.commands
        if command[:2] == (str(fixed.paths.route_exe), "print")
    ] == [target_command]


def test_observer_drops_overlapping_target_from_path_facts(
    tmp_path: Path,
) -> None:
    runner = FakeRunner()
    fixed = commands(tmp_path, runner)
    prefix = (str(fixed.paths.wg_exe), "show", "tmn-test-a")
    runner.results[(str(fixed.paths.sc_exe), "query", "WireGuardTunnel$tmn-test-a")] = (
        CommandResult(returncode=0, stdout="RUNNING", stderr="")
    )
    runner.results[(*prefix, "public-key")] = CommandResult(
        returncode=0, stdout="own-public\n", stderr=""
    )
    runner.results[(*prefix, "peers")] = CommandResult(
        returncode=0, stdout="peer-a\npeer-b\n", stderr=""
    )
    runner.results[(*prefix, "endpoints")] = CommandResult(
        returncode=0,
        stdout="peer-a\t10.203.0.3:51820\npeer-b\t10.203.0.4:51820\n",
        stderr="",
    )
    runner.results[(*prefix, "allowed-ips")] = CommandResult(
        returncode=0,
        stdout="peer-a\t10.203.0.0/24\npeer-b\t10.203.0.2/32\n",
        stderr="",
    )
    runner.results[(*prefix, "latest-handshakes")] = CommandResult(
        returncode=0, stdout="peer-a\t123\npeer-b\t123\n", stderr=""
    )
    observer = WindowsWireGuardObserver(
        FakeReader(InterfaceSnapshot(name="tmn-test-a", is_up=True, addresses=("10.203.0.1",))),
        fixed,
        interface_index=lambda _name: 7,
    )

    snapshot = asyncio.run(
        observer.observe_path(
            "tmn-test-a",
            peer_public_key="peer-a",
            expected_host_route="10.203.0.2/32",
        )
    )

    assert snapshot.host_routes == ()
    assert [
        command
        for command in runner.commands
        if command[:2] == (str(fixed.paths.route_exe), "print")
    ] == []


@pytest.mark.parametrize(
    "value",
    [
        "0.0.0.0/0",
        "0.0.0.0/1",
        "10.0.0.0/7",
        "224.0.0.0/4",
        "127.0.0.0/8",
        "malformed",
    ],
)
def test_safe_allowed_network_rejects_dangerous_or_special_values(value: str) -> None:
    assert parse_safe_allowed_network(value) is None


def test_peer_snapshot_rejects_invalid_and_duplicate_network_facts() -> None:
    with pytest.raises(ValidationError, match="安全的 IP network"):
        WindowsPeerSnapshot(public_key="peer", allowed_networks=("0.0.0.0/0",))
    with pytest.raises(ValidationError, match="host route 不得重复"):
        WindowsPeerSnapshot(
            public_key="peer",
            allowed_host_routes=("10.203.0.2/32", "10.203.0.2/32"),
        )
    with pytest.raises(ValidationError, match="IP network 不得重复"):
        WindowsPeerSnapshot(
            public_key="peer",
            allowed_networks=("10.203.0.0/24", "10.203.0.0/24"),
        )


def test_windows_network_helpers_fail_closed_for_invalid_targets() -> None:
    peer = WindowsPeerSnapshot(public_key="peer", allowed_networks=("10.203.0.0/24",))
    assert not _is_observable_host_route("malformed")
    assert _safe_host_route(None) is None
    assert _safe_host_route("malformed") is None
    assert _safe_host_route("10.203.0.0/24") is None
    assert _safe_host_route("10.203.0.2/32") == "10.203.0.2/32"
    assert not peer_owns_unique_target((peer,), "peer", "malformed")
    assert not peer_owns_unique_target((peer,), "peer", "10.203.0.0/24")
    assert not peer_owns_unique_target((peer,), "other", "10.203.0.2/32")


def test_windows_route_parser_accepts_exact_ipv4_and_ipv6_rows() -> None:
    ipv4 = (
        "IPv4 Route Table\n"
        "Active Routes:\n"
        "Network Destination        Netmask          Gateway       Interface  Metric\n"
        "10.203.0.2                255.255.255.255  10.203.0.254  10.203.0.1  2\n"
        "Persistent Routes:\n"
        "  None\n"
    )
    assert windows_route_contains_exact_host(
        ipv4,
        "10.203.0.2/32",
        interface_addresses=("10.203.0.1", "bad"),
        interface_index=None,
    )

    ipv6 = (
        "IPv6 Route Table\n"
        "Active Routes:\n"
        " If Metric Network Destination      Gateway\n"
        " 7  5 fd00::2/128                    On-link\n"
        "Persistent Routes:\n"
        "  None\n"
    )
    assert windows_route_contains_exact_host(
        ipv6,
        "fd00::2/128",
        interface_addresses=(),
        interface_index=7,
    )


@pytest.mark.parametrize(
    ("stdout", "host_route", "interface_addresses", "interface_index"),
    [
        (
            "IPv4 Route Table 10.203.0.2\n",
            "10.203.0.2/32",
            ("10.203.0.1",),
            None,
        ),
        (
            "Active Routes:\n"
            "Network Destination Netmask Gateway Interface Metric\n"
            "10.203.0.2 255.255.255.0 On-link 10.203.0.1 1\n",
            "10.203.0.2/32",
            ("10.203.0.1",),
            None,
        ),
        (
            "Active Routes:\n"
            "Network Destination Netmask Gateway Interface Metric\n"
            "malformed route row\n",
            "10.203.0.2/32",
            ("10.203.0.1",),
            None,
        ),
        (
            "Active Routes:\n"
            "Network Destination Netmask Gateway Interface Metric\n"
            "10.203.0.2 255.255.255.255 10.203.0.2 10.203.0.1 1\n",
            "10.203.0.2/32",
            ("10.203.0.1",),
            None,
        ),
        (
            "Active Routes:\n"
            "Network Destination Netmask Gateway Interface Metric\n"
            "10.203.0.2 255.255.255.255 On-link 10.203.0.99 1\n",
            "10.203.0.2/32",
            ("10.203.0.1",),
            None,
        ),
        (
            "Active Routes:\n"
            "Network Destination Netmask Gateway Interface Metric\n"
            "10.203.0.2 255.255.255.255 bad-gateway 10.203.0.1 1\n",
            "10.203.0.2/32",
            ("10.203.0.1",),
            None,
        ),
        (
            "Active Routes:\n"
            "Network Destination Netmask Gateway Interface Metric\n"
            "10.203.0.2 255.255.255.255 On-link 10.203.0.1 bad\n",
            "10.203.0.2/32",
            ("10.203.0.1",),
            None,
        ),
        (
            "Active Routes:\n"
            "Network Destination Netmask Gateway Interface Metric\n"
            "10.203.0.2 255.255.255.255 On-link 10.203.0.1 10000\n",
            "10.203.0.2/32",
            ("10.203.0.1",),
            None,
        ),
        (
            "Active Routes:\n"
            "Network Destination Netmask Gateway Interface Metric\n"
            "10.203.0.3 255.255.255.255 On-link 10.203.0.1 1\n"
            "Persistent Routes:\n"
            "10.203.0.2 255.255.255.255 On-link 10.203.0.1 1\n",
            "10.203.0.2/32",
            ("10.203.0.1",),
            None,
        ),
        (
            "Active Routes:\nIf Metric Network Destination Gateway\n7 5 fd00::2/64 On-link\n",
            "fd00::2/128",
            (),
            7,
        ),
        (
            "Active Routes:\nIf Metric Network Destination Gateway\nmalformed route row\n",
            "fd00::2/128",
            (),
            7,
        ),
        (
            "Active Routes:\nIf Metric Network Destination Gateway\n8 5 fd00::2/128 On-link\n",
            "fd00::2/128",
            (),
            7,
        ),
        (
            "Active Routes:\nIf Metric Network Destination Gateway\n7 5 fd00::2/128 On-link\n",
            "fd00::2/128",
            (),
            None,
        ),
        (
            "Active Routes:\nIf Metric Network Destination Gateway\n7 5 fd00::2/128 fd00::2\n",
            "fd00::2/128",
            (),
            7,
        ),
        (
            "Active Routes:\nIf Metric Network Destination Gateway\n7 5 fd00::2/128 bad-gateway\n",
            "fd00::2/128",
            (),
            7,
        ),
        (
            "Active Routes:\nIf Metric Network Destination Gateway\n7 bad fd00::2/128 On-link\n",
            "fd00::2/128",
            (),
            7,
        ),
        (
            "Active Routes:\nIf Metric Network Destination Gateway\nbad 5 fd00::2/128 On-link\n",
            "fd00::2/128",
            (),
            7,
        ),
    ],
)
def test_windows_route_parser_fails_closed_for_ambiguous_rows(
    stdout: str,
    host_route: str,
    interface_addresses: tuple[str, ...],
    interface_index: int | None,
) -> None:
    assert not windows_route_contains_exact_host(
        stdout,
        host_route,
        interface_addresses=interface_addresses,
        interface_index=interface_index,
    )


def test_windows_route_parser_rejects_invalid_target_and_interface_index(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert not windows_route_contains_exact_host(
        "Active Routes:\n",
        "not-a-route",
        interface_addresses=(),
        interface_index=1,
    )
    assert not windows_route_contains_exact_host(
        "Active Routes:\n",
        "10.203.0.0/24",
        interface_addresses=(),
        interface_index=1,
    )

    def available(_name: str) -> int:
        return 7

    monkeypatch.setattr(socket, "if_nametoindex", available)
    assert system_interface_index("tmn-test-a") == 7

    def denied(_name: str) -> int:
        raise OSError("denied")

    monkeypatch.setattr(socket, "if_nametoindex", denied)
    assert system_interface_index("tmn-test-a") is None


def test_peer_snapshot_rejects_non_host_route() -> None:
    with pytest.raises(ValidationError, match="host route"):
        WindowsPeerSnapshot(
            public_key="peer",
            allowed_host_routes=("10.203.0.0/24",),
        )


def test_peer_snapshot_rejects_partial_endpoint_and_parser_is_fail_closed() -> None:
    with pytest.raises(ValidationError, match="endpoint"):
        WindowsPeerSnapshot(public_key="peer", endpoint_host="10.0.0.1")
    for value in ("", "(none)", "<none>", "bad", "[fd00::1]", "10.0.0.1:not-port", "10.0.0.1:0"):
        assert parse_wireguard_endpoint(value) is None
