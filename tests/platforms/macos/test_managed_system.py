"""macOS 受管固定命令与只读观察测试。"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from tunnelminion.network.contracts import ProviderMode
from tunnelminion.platforms.macos.managed_system import (
    FixedMacOSWireGuardCommands,
    MacOSProviderPaths,
    MacOSWireGuardObserver,
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
    asyncio.run(commands.up("tmn-test-b", config))
    asyncio.run(commands.down("tmn-test-b", config))
    assert all(isinstance(command, tuple) and "sudo" not in command for command in runner.commands)


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
        "\tinet 10.203.0.2 netmask 0xffffffff\n"
        "\tinet bad netmask nope\n"
        "\tstatus: active\n"
    )
    runner.results[(str(paths.wg), "show", "utun9", "public-key")] = result("public-b\n")
    runner.results[(str(paths.wg), "show", "utun9", "peers")] = result("peer-b\n")
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
    snapshot = asyncio.run(MacOSWireGuardObserver(commands).observe("utun9"))
    assert snapshot.interface_up
    assert snapshot.addresses == ("10.203.0.2/32",)
    assert snapshot.host_routes == ("10.203.0.1/32",)
    assert snapshot.peers[0].allowed_host_routes == ("10.203.0.1/32",)
    assert snapshot.peers[0].latest_handshake_epoch == 123
    assert snapshot.public_key_hash is not None
    assert snapshot.system_fingerprint.startswith("sha256:")


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
