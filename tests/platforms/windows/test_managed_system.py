"""Windows managed 固定命令、预检与 observe-only 联合观察测试。"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
from pydantic import ValidationError

from tunnelminion.network.contracts import ProviderMode
from tunnelminion.platforms.windows.managed_system import (
    FixedWindowsWireGuardCommands,
    WindowsPeerSnapshot,
    WindowsProviderPaths,
    WindowsWireGuardObserver,
    windows_is_administrator,
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
    asyncio.run(fixed.uninstall_tunnel("tmn-test-a"))
    asyncio.run(fixed.stop_tunnel("tmn-test-a"))
    asyncio.run(fixed.show("HomeMac", "peers"))
    asyncio.run(fixed.query_service("HomeMac"))
    asyncio.run(fixed.query_route("10.203.0.2/32"))
    asyncio.run(fixed.route_table())
    assert all(isinstance(command, tuple) for command in runner.commands)
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
        returncode=0, stdout="route 10.203.0.2 present", stderr=""
    )
    runner.results[(str(fixed.paths.route_exe), "print", "10.203.0.3")] = CommandResult(
        returncode=1, stdout="", stderr=""
    )
    observer = WindowsWireGuardObserver(
        FakeReader(
            InterfaceSnapshot(
                name="tmn-test-a",
                is_up=True,
                addresses=("10.203.0.1",),
            )
        ),
        fixed,
    )
    snapshot = asyncio.run(observer.observe("tmn-test-a"))
    assert snapshot.service_running
    assert snapshot.host_routes == ("10.203.0.2/32",)
    assert snapshot.peers[0].latest_handshake_epoch == 123
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


def test_peer_snapshot_rejects_non_host_route() -> None:
    with pytest.raises(ValidationError, match="host route"):
        WindowsPeerSnapshot(
            public_key="peer",
            allowed_host_routes=("10.203.0.0/24",),
        )
