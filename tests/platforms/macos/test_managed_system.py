"""macOS 受管固定命令与只读观察测试。"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from tunnelminion.network.contracts import ProviderMode
from tunnelminion.platforms.macos.managed_system import (
    FixedMacOSWireGuardCommands,
    MacOSPeerSnapshot,
    MacOSProviderPaths,
    MacOSWireGuardObserver,
    _is_host_route,  # pyright: ignore[reportPrivateUsage]
    _safe_host_route,  # pyright: ignore[reportPrivateUsage]
    parse_wireguard_endpoint,
)
from tunnelminion.platforms.macos.system import CommandResult


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


class BindingRunner(FakeRunner):
    def __init__(self) -> None:
        super().__init__()
        self.binding: tuple[str, str] | None = None

    def bind_operation(self, plan_hash: str, creation_nonce: str) -> None:
        self.binding = (plan_hash, creation_nonce)

    def runtime_resources(self) -> tuple[str, ...]:
        return ("stage6:marker",)


def fixed(
    tmp_path: Path,
    runner: FakeRunner,
    *,
    exists: bool = True,
    uid: int = 0,
    platform_name: str = "darwin",
) -> FixedMacOSWireGuardCommands:
    return FixedMacOSWireGuardCommands(
        MacOSProviderPaths(
            wg=tmp_path / "wg",
            wg_quick=tmp_path / "wg-quick",
            ifconfig=tmp_path / "ifconfig",
            netstat=tmp_path / "netstat",
            config_root=tmp_path / "configs",
        ),
        runner,
        path_exists=lambda _path: exists,
        effective_uid=lambda: uid,
        platform_name=platform_name,
    )


def result(stdout: str = "", returncode: int = 0) -> CommandResult:
    return CommandResult(returncode=returncode, stdout=stdout, stderr="")


def test_paths_preflight_and_fixed_commands(tmp_path: Path) -> None:
    runner = FakeRunner()
    commands = fixed(tmp_path, runner)
    assert commands.preflight().mode is ProviderMode.MANAGED
    assert fixed(tmp_path, runner, platform_name="win32").preflight().error_code == (
        "platform_unsupported"
    )
    assert fixed(tmp_path, runner, exists=False).preflight().error_code == (
        "dependency_unavailable"
    )
    assert fixed(tmp_path, runner, uid=501).preflight().error_code == "permission_denied"

    config = commands.config_path("tmn-test-b", 1)
    asyncio.run(commands.interfaces())
    asyncio.run(commands.show("utun9", "public-key"))
    asyncio.run(commands.inspect_interface("utun9"))
    asyncio.run(commands.route_table())
    asyncio.run(commands.route_table("inet6"))
    asyncio.run(commands.up("tmn-test-b", config))
    asyncio.run(commands.down("tmn-test-b", config))
    assert all(isinstance(command, tuple) and "sudo" not in command for command in runner.commands)


def test_fixed_commands_delegate_optional_operation_binding(tmp_path: Path) -> None:
    runner = BindingRunner()
    commands = fixed(tmp_path, runner)

    commands.bind_operation(f"sha256:{'a' * 64}", "b" * 32)

    assert runner.binding == (f"sha256:{'a' * 64}", "b" * 32)
    assert commands.runtime_resources() == ("stage6:marker",)
    fixed(tmp_path, FakeRunner()).bind_operation(f"sha256:{'c' * 64}", "d" * 32)
    assert fixed(tmp_path, FakeRunner()).runtime_resources() == ()


def test_fixed_commands_reject_dynamic_values(tmp_path: Path) -> None:
    commands = fixed(tmp_path, FakeRunner())
    with pytest.raises(ValueError):
        MacOSProviderPaths(
            wg=Path("wg"),
            wg_quick=tmp_path / "wg-quick",
            ifconfig=tmp_path / "ifconfig",
            netstat=tmp_path / "netstat",
            config_root=tmp_path / "configs",
        )
    with pytest.raises(ValueError):
        asyncio.run(commands.show("utun9;id", "public-key"))
    with pytest.raises(ValueError):
        asyncio.run(commands.show("utun9", "private-key"))
    with pytest.raises(ValueError):
        asyncio.run(commands.route_table("bad"))
    with pytest.raises(ValueError):
        commands.config_path("utun4", 1)
    with pytest.raises(ValueError):
        commands.config_path("tmn-test-b", 0)
    with pytest.raises(ValueError):
        asyncio.run(commands.up("tmn-test-b", tmp_path / "outside.conf"))


def test_observer_reads_public_state_and_ignores_malformed_rows(tmp_path: Path) -> None:
    runner = FakeRunner()
    commands = fixed(tmp_path, runner)
    paths = commands.paths
    runner.results[(str(paths.wg), "show", "interfaces")] = result("utun4 utun9\n")
    runner.results[(str(paths.ifconfig), "utun9")] = result(
        "utun9: flags=8051<UP> mtu 1420\n"
        "\tinet 10.203.0.2 --> 10.203.0.2 netmask 0xffffffff\n"
        "\tinet 10.203.0.3 netmask 0xffffffff\n"
        "\tinet 10.203.0.4 unexpected layout\n"
        "\tinet bad netmask nope\n"
        "\tinet6 fd00::2 prefixlen 128\n"
        "\tinet6 fe80::1%utun9 prefixlen 64 scopeid 0x12\n"
        "\tinet6 fd00::3 prefixlen 129\n"
        "\tinet6 bad prefixlen nope\n"
        "\tstatus: active\n"
    )
    runner.results[(str(paths.wg), "show", "utun9", "public-key")] = result("public-b\n")
    runner.results[(str(paths.wg), "show", "utun9", "peers")] = result("peer-b\n")
    runner.results[(str(paths.wg), "show", "utun9", "endpoints")] = result(
        "peer-b\t[fd00::10]:51820\n"
    )
    runner.results[(str(paths.wg), "show", "utun9", "allowed-ips")] = result(
        "peer-b\t10.203.0.1/32,10.0.0.0/8,bad\n \n"
    )
    runner.results[(str(paths.wg), "show", "utun9", "latest-handshakes")] = result("peer-b\t123\n")
    runner.results[(str(paths.netstat), "-rn", "-f", "inet")] = result(
        "Destination Gateway Flags Netif Expire\n"
        "10.203.0.1 10.203.0.2 UH utun9\n"
        "10.0.0.0/8 link#1 UCS utun9\n"
        "not-a-route link#1 UCS utun9\n"
        "bad row\n"
    )
    runner.results[(str(paths.netstat), "-rn", "-f", "inet6")] = result(
        "Destination Gateway Flags Netif Expire\nfd00::2 fd00::1 UHS utun9\n"
    )
    snapshot = asyncio.run(MacOSWireGuardObserver(commands).observe("utun9"))
    assert snapshot.interface_up
    assert snapshot.addresses == (
        "10.203.0.2/32",
        "10.203.0.3/32",
        "fd00::2/128",
        "fe80::1/64",
    )
    assert snapshot.host_routes == ("10.203.0.1/32", "fd00::2/128")
    assert snapshot.peers[0].allowed_host_routes == ("10.203.0.1/32",)
    assert snapshot.peers[0].allowed_networks == ("10.203.0.1/32", "10.0.0.0/8")
    assert not snapshot.peers[0].allowed_networks_complete
    assert snapshot.peers[0].latest_handshake_epoch == 123
    assert snapshot.peers[0].endpoint_host == "fd00::10"
    assert snapshot.peers[0].endpoint_port == 51820
    assert snapshot.public_key_hash is not None
    assert snapshot.system_fingerprint.startswith("sha256:")

    path_snapshot = asyncio.run(
        MacOSWireGuardObserver(commands).observe_path(
            "utun9",
            peer_public_key="peer-b",
            expected_host_route="10.203.0.1/32",
        )
    )
    assert path_snapshot.host_routes == ("fd00::2/128",)

    filtered_snapshot = asyncio.run(
        MacOSWireGuardObserver(commands).observe_path(
            "utun9",
            peer_public_key="peer-b",
            expected_host_route="fd00::2/128",
        )
    )
    assert filtered_snapshot.host_routes == ("10.203.0.1/32",)

    runner.commands.clear()
    candidate_snapshot = asyncio.run(MacOSWireGuardObserver(commands).observe_candidates("utun9"))
    assert len(candidate_snapshot.peers) == 1
    assert candidate_snapshot.host_routes == ()
    assert not any(command[0] == str(paths.netstat) for command in runner.commands)


@pytest.mark.parametrize(
    "competing_route",
    ["10.203.0.2/32", "10.203.0.0/16", "0.0.0.0/0", "10.0.0.0/7", "malformed"],
)
def test_observer_rejects_competitor_after_eight_allowed_networks(
    tmp_path: Path,
    competing_route: str,
) -> None:
    runner = FakeRunner()
    commands = fixed(tmp_path, runner)
    paths = commands.paths
    runner.results[(str(paths.wg), "show", "interfaces")] = result("utun9\n")
    runner.results[(str(paths.ifconfig), "utun9")] = result(
        "utun9: flags=8051<UP> mtu 1420\n\tinet 10.203.0.1 netmask 0xffffffff\n"
    )
    runner.results[(str(paths.wg), "show", "utun9", "public-key")] = result("public\n")
    runner.results[(str(paths.wg), "show", "utun9", "peers")] = result("peer-a\npeer-b\n")
    runner.results[(str(paths.wg), "show", "utun9", "endpoints")] = result(
        "peer-a\t10.203.0.3:51820\npeer-b\t10.203.0.4:51820\n"
    )
    prior_networks = tuple(f"192.168.{index}.0/24" for index in range(8))
    runner.results[(str(paths.wg), "show", "utun9", "allowed-ips")] = result(
        f"peer-a\t10.203.0.0/24\npeer-b\t{','.join((*prior_networks, competing_route))}\n"
    )
    runner.results[(str(paths.wg), "show", "utun9", "latest-handshakes")] = result(
        "peer-a\t123\npeer-b\t123\n"
    )
    runner.results[(str(paths.netstat), "-rn", "-f", "inet")] = result(
        "Destination Gateway Flags Netif Expire\n10.203.0.2 10.203.0.1 UHS utun9\n"
    )
    runner.results[(str(paths.netstat), "-rn", "-f", "inet6")] = result()

    snapshot = asyncio.run(
        MacOSWireGuardObserver(commands).observe_path(
            "utun9",
            peer_public_key="peer-a",
            expected_host_route="10.203.0.2/32",
        )
    )

    assert snapshot.host_routes == ()


def test_observer_absent_permission_and_degraded_public_fields(tmp_path: Path) -> None:
    runner = FakeRunner()
    commands = fixed(tmp_path, runner)
    interfaces = (str(commands.paths.wg), "show", "interfaces")
    runner.results[interfaces] = result(returncode=1)
    denied = asyncio.run(MacOSWireGuardObserver(commands).observe("utun4"))
    assert denied.observed_error_code == "permission_denied"

    runner.results[interfaces] = result("utun4\n")
    runner.results[(str(commands.paths.ifconfig), "utun4")] = result("status: inactive\n")
    runner.results[(str(commands.paths.wg), "show", "utun4", "public-key")] = result(returncode=1)
    runner.results[(str(commands.paths.wg), "show", "utun4", "peers")] = result(
        "peer\t\npeer-invalid\t\n"
    )
    runner.results[(str(commands.paths.wg), "show", "utun4", "allowed-ips")] = result(returncode=1)
    runner.results[(str(commands.paths.wg), "show", "utun4", "latest-handshakes")] = result(
        "peer\t-1\npeer-invalid\tnot-an-integer\n"
    )
    runner.results[(str(commands.paths.netstat), "-rn", "-f", "inet")] = result(returncode=1)
    degraded = asyncio.run(MacOSWireGuardObserver(commands).observe("utun4"))
    assert not degraded.interface_up
    assert degraded.public_key_hash is None
    assert degraded.peers[0].latest_handshake_epoch is None
    assert degraded.observed_error_code == "permission_denied"

    runner.results[interfaces] = result("")
    assert not asyncio.run(MacOSWireGuardObserver(commands).observe("utun4")).interface_present


def test_macos_peer_endpoint_and_parser_are_fail_closed() -> None:
    with pytest.raises(ValueError, match="endpoint"):
        MacOSPeerSnapshot(public_key="peer", endpoint_port=51820)
    for value in ("", "(none)", "<none>", "bad", "[fd00::1]", "10.0.0.1:not-port", "10.0.0.1:0"):
        assert parse_wireguard_endpoint(value) is None
    assert not _is_host_route("bad")
    assert not _is_host_route("10.0.0.0/24")
    assert _safe_host_route(None) is None
    assert _safe_host_route("bad") is None
    assert _safe_host_route("10.0.0.0/24") is None
    assert _safe_host_route("10.0.0.1/32") == "10.0.0.1/32"
