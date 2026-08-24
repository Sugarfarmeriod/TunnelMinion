"""阶段 2.5 管理员只读验收包装器的安全门禁。"""

from __future__ import annotations

import asyncio
import json
import os
import stat
import subprocess
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

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
    FixedWindowsWireGuardCommands,
    WindowsPeerSnapshot,
    WindowsProviderPaths,
    WindowsTunnelSnapshot,
    WindowsWireGuardObserver,
)
from tunnelminion.platforms.windows.models import InterfaceSnapshot, NetworkListener, ProcessInfo
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


class AcceptanceObserverRunner:
    def __init__(self) -> None:
        self.results: dict[tuple[str, ...], CommandResult] = {}
        self.commands: list[tuple[str, ...]] = []

    async def run(self, command: tuple[str, ...], timeout_seconds: float) -> CommandResult:
        assert timeout_seconds > 0
        self.commands.append(command)
        return self.results.get(command, CommandResult(returncode=0, stdout="", stderr=""))


class AcceptanceObserverReader:
    def interface(self, name: str) -> InterfaceSnapshot | None:
        return InterfaceSnapshot(
            name=name,
            is_up=True,
            addresses=("10.77.0.1",),
        )

    def listeners(self) -> tuple[NetworkListener, ...]:
        raise AssertionError("验收 observer 不应枚举监听")

    def processes(self, limit: int) -> tuple[ProcessInfo, ...]:
        raise AssertionError(f"验收 observer 不应枚举进程：{limit}")


def actual_observer_with_competing_ninth_network(
    tmp_path: Path,
    competing_route: str,
) -> tuple[WindowsWireGuardObserver, AcceptanceObserverRunner]:
    runner = AcceptanceObserverRunner()
    paths = WindowsProviderPaths(
        wireguard_exe=tmp_path / "wireguard.exe",
        wg_exe=tmp_path / "wg.exe",
        sc_exe=tmp_path / "sc.exe",
        route_exe=tmp_path / "route.exe",
        config_root=tmp_path / "configs",
    )
    commands = FixedWindowsWireGuardCommands(paths, runner)
    prefix = (str(paths.wg_exe), "show", "HomeMac")
    runner.results[(str(paths.sc_exe), "query", "WireGuardTunnel$HomeMac")] = CommandResult(
        returncode=0,
        stdout="RUNNING",
        stderr="",
    )
    runner.results[(*prefix, "public-key")] = CommandResult(
        returncode=0, stdout="own-public\n", stderr=""
    )
    runner.results[(*prefix, "peers")] = CommandResult(
        returncode=0, stdout=f"{PEER}\nother-peer\n", stderr=""
    )
    runner.results[(*prefix, "endpoints")] = CommandResult(
        returncode=0,
        stdout=f"{PEER}\t{ENDPOINT}:51820\nother-peer\t192.168.50.11:51820\n",
        stderr="",
    )
    prior_networks = tuple(f"192.168.{index}.0/24" for index in range(8))
    runner.results[(*prefix, "allowed-ips")] = CommandResult(
        returncode=0,
        stdout=(
            f"{PEER}\t10.77.0.0/24\nother-peer\t{','.join((*prior_networks, competing_route))}\n"
        ),
        stderr="",
    )
    runner.results[(*prefix, "latest-handshakes")] = CommandResult(
        returncode=0,
        stdout=f"{PEER}\t{int(NOW.timestamp())}\nother-peer\t{int(NOW.timestamp())}\n",
        stderr="",
    )
    runner.results[(str(paths.route_exe), "print", "10.77.0.2")] = CommandResult(
        returncode=0,
        stdout=(
            "IPv4 Route Table\n"
            "Active Routes:\n"
            "Network Destination        Netmask          Gateway       Interface  Metric\n"
            "10.77.0.2                  255.255.255.255  On-link       10.77.0.1  1\n"
            "Persistent Routes:\n"
        ),
        stderr="",
    )
    return (
        WindowsWireGuardObserver(
            AcceptanceObserverReader(),
            commands,
            interface_index=lambda _name: 7,
        ),
        runner,
    )


class ChangingObserver(Observer):
    def __init__(self, initial: WindowsTunnelSnapshot, changed: WindowsTunnelSnapshot) -> None:
        super().__init__(initial)
        self.changed = changed

    async def observe(self, interface_name: str) -> WindowsTunnelSnapshot:
        if self.calls > 0:
            self.calls += 1
            return self.changed
        return await super().observe(interface_name)


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


def snapshot_with_peer_routes(*routes: tuple[str, tuple[str, ...]]) -> WindowsTunnelSnapshot:
    peers = tuple(
        WindowsPeerSnapshot(
            public_key=public_key,
            endpoint_host=ENDPOINT if public_key == PEER else "192.168.50.11",
            endpoint_port=51820,
            allowed_host_routes=allowed_routes,
            latest_handshake_epoch=int(NOW.timestamp()),
        )
        for public_key, allowed_routes in routes
    )
    return snapshot().model_copy(update={"peers": peers})


def snapshot_with_peer_networks(
    *networks: tuple[str, tuple[str, ...]],
) -> WindowsTunnelSnapshot:
    peers = tuple(
        WindowsPeerSnapshot(
            public_key=public_key,
            endpoint_host=ENDPOINT if public_key == PEER else "192.168.50.11",
            endpoint_port=51820,
            allowed_networks=allowed_networks,
            latest_handshake_epoch=int(NOW.timestamp()),
        )
        for public_key, allowed_networks in networks
    )
    return snapshot().model_copy(update={"peers": peers})


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
    route_returncodes: list[int] | None = None,
    docker_ports: frozenset[int] = frozenset(),
    probe_calls: list[bool] | None = None,
    route_calls: list[bool] | None = None,
) -> PlatformRuntime:
    values = route_hashes or ["sha256:" + "1" * 64]
    returncodes = route_returncodes or [0]

    async def route_summary() -> tuple[str, int]:
        if route_calls is not None:
            route_calls.append(True)
        return (
            values.pop(0) if len(values) > 1 else values[0],
            returncodes.pop(0) if len(returncodes) > 1 else returncodes[0],
        )

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


def test_default_git_runner_uses_fixed_path_and_clears_git_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixed_path = Path(r"C:\Program Files\Git\cmd\git.exe")
    captured: dict[str, object] = {}

    monkeypatch.setattr(acceptance, "_trusted_git_path", lambda: fixed_path)
    monkeypatch.setenv("PATH", r"C:\attacker\bin")
    for key in (
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_INDEX_FILE",
        "GIT_OBJECT_DIRECTORY",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_CONFIG_SYSTEM",
        "GIT_CONFIG_GLOBAL",
        "GIT_EXEC_PATH",
    ):
        monkeypatch.setenv(key, "attacker-controlled")

    def fake_run(command: tuple[str, ...], **kwargs: object) -> SimpleNamespace:
        captured["command"] = command
        captured.update(kwargs)
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(acceptance.subprocess, "run", fake_run)
    assert acceptance._default_git_runner(  # pyright: ignore[reportPrivateUsage]
        ("rev-parse", "--verify", "HEAD")
    ) == (0, "", "")

    command = cast(tuple[str, ...], captured["command"])
    assert command[0] == str(fixed_path)
    fixed_args = acceptance._GIT_FIXED_ARGS  # pyright: ignore[reportPrivateUsage]
    assert command[1 : 1 + len(fixed_args)] == fixed_args
    assert command[-3:] == ("rev-parse", "--verify", "HEAD")
    assert captured["shell"] is False
    assert captured["timeout"] == 5
    environment = cast(dict[str, str], captured["env"])
    assert environment["GIT_OPTIONAL_LOCKS"] == "0"
    assert all(
        not key.upper().startswith("GIT_") or key == "GIT_OPTIONAL_LOCKS" for key in environment
    )


def test_default_git_runner_rejects_unapproved_command_before_execution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        acceptance,
        "_trusted_git_path",
        lambda: (_ for _ in ()).throw(AssertionError("path lookup must not run")),
    )
    with pytest.raises(ValueError, match="git_command_rejected"):
        acceptance._default_git_runner(  # pyright: ignore[reportPrivateUsage]
            ("log", "--all")
        )


def test_default_git_runner_rejects_tool_timeout_and_missing_tool(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixed_path = Path(r"C:\Program Files\Git\cmd\git.exe")
    monkeypatch.setattr(acceptance, "_trusted_git_path", lambda: fixed_path)

    def timed_out(*args: object, **kwargs: object) -> SimpleNamespace:
        del args, kwargs
        raise subprocess.TimeoutExpired("git", 5)

    monkeypatch.setattr(acceptance.subprocess, "run", timed_out)
    with pytest.raises(ValueError, match="git_timeout"):
        acceptance._default_git_runner(  # pyright: ignore[reportPrivateUsage]
            ("rev-parse", "--verify", "HEAD")
        )

    def missing(*args: object, **kwargs: object) -> SimpleNamespace:
        del args, kwargs
        raise FileNotFoundError("git")

    monkeypatch.setattr(acceptance.subprocess, "run", missing)
    with pytest.raises(ValueError, match="git_tool_unavailable"):
        acceptance._default_git_runner(  # pyright: ignore[reportPrivateUsage]
            ("rev-parse", "--verify", "HEAD")
        )


def test_git_path_rejects_symlink_reparse_owner_and_acl_failures() -> None:
    rejected = {
        "git_tool_symlink",
        "git_tool_reparse",
        "git_tool_owner_untrusted",
        "git_tool_acl_untrusted",
    }

    for reason in rejected:

        def verifier(path: Path, reason: str = reason) -> None:
            del path
            raise ValueError(reason)

        with pytest.raises(ValueError, match="git_tool_untrusted_or_unavailable"):
            acceptance._select_trusted_git_path(  # pyright: ignore[reportPrivateUsage]
                (Path("/system/git"),), verifier
            )


def test_git_path_rejects_symlink_and_reparse_nodes_before_platform_checks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    node = Path("/system/git")

    def regular_node(path: Path) -> os.stat_result:
        del path
        return cast(
            os.stat_result,
            SimpleNamespace(st_mode=stat.S_IFREG, st_file_attributes=0),
        )

    def symlink_node(path: Path) -> bool:
        del path
        return True

    monkeypatch.setattr(
        acceptance.os,
        "lstat",
        cast(Any, regular_node),
    )
    monkeypatch.setattr(Path, "is_symlink", symlink_node)
    with pytest.raises(ValueError, match="git_tool_symlink"):
        acceptance._verify_path_node(  # pyright: ignore[reportPrivateUsage]
            node, expect_file=True
        )

    def non_symlink_node(path: Path) -> bool:
        del path
        return False

    def reparse_node(path: Path) -> os.stat_result:
        del path
        return cast(
            os.stat_result,
            SimpleNamespace(st_mode=stat.S_IFREG, st_file_attributes=0x400),
        )

    monkeypatch.setattr(Path, "is_symlink", non_symlink_node)
    monkeypatch.setattr(
        acceptance.os,
        "lstat",
        cast(Any, reparse_node),
    )
    with pytest.raises(ValueError, match="git_tool_reparse"):
        acceptance._verify_path_node(  # pyright: ignore[reportPrivateUsage]
            node, expect_file=True
        )


def test_macos_git_acl_and_owner_checks_fail_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    node = Path("/usr/bin/git")
    untrusted = cast(
        os.stat_result,
        SimpleNamespace(st_uid=501, st_mode=stat.S_IFREG | stat.S_IRUSR),
    )
    with pytest.raises(ValueError, match="git_tool_acl_untrusted"):
        acceptance._verify_macos_security(  # pyright: ignore[reportPrivateUsage]
            node, untrusted
        )

    def acl_listing(*args: object, **kwargs: object) -> SimpleNamespace:
        del args, kwargs
        return SimpleNamespace(
            returncode=0,
            stdout="-rwxr-xr-x+ 1 root wheel 1 Jan 1 00:00 /usr/bin/git\n",
        )

    monkeypatch.setattr(acceptance.subprocess, "run", acl_listing)
    root_owned = cast(
        os.stat_result,
        SimpleNamespace(st_uid=0, st_mode=stat.S_IFREG | stat.S_IRUSR),
    )
    with pytest.raises(ValueError, match="git_tool_acl_untrusted"):
        acceptance._verify_macos_security(  # pyright: ignore[reportPrivateUsage]
            node, root_owned
        )


def test_windows_trusted_sid_matching_does_not_accept_prefix_spoof() -> None:
    assert acceptance._trusted_windows_sid(  # pyright: ignore[reportPrivateUsage]
        "S-1-5-18"
    )
    assert acceptance._trusted_windows_sid(  # pyright: ignore[reportPrivateUsage]
        "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
    )
    assert not acceptance._trusted_windows_sid(  # pyright: ignore[reportPrivateUsage]
        "S-1-5-180"
    )


def test_windows_acl_explicit_deny_blocks_later_write_allow() -> None:
    write_mask = 0x40
    denied_then_allowed = (
        (1, write_mask, "S-1-5-32-545"),
        (0, write_mask, "S-1-5-32-545"),
    )
    allowed_then_denied = (
        (0, write_mask, "S-1-5-32-545"),
        (1, write_mask, "S-1-5-32-545"),
    )
    assert not acceptance._windows_untrusted_write_granted(  # pyright: ignore[reportPrivateUsage]
        denied_then_allowed, write_mask
    )
    assert (
        acceptance._windows_untrusted_write_granted(  # pyright: ignore[reportPrivateUsage]
            allowed_then_denied, write_mask
        )
        is True
    )
    assert acceptance._windows_untrusted_write_granted(  # pyright: ignore[reportPrivateUsage]
        ((0, write_mask, "S-1-5-32-545"),), write_mask
    )


@pytest.mark.parametrize(
    "denying_sid",
    [
        "S-1-1-0",
        "S-1-5-4",
        "S-1-5-11",
        "S-1-5-32-545",
        "S-1-5-32-546",
    ],
)
def test_windows_group_deny_does_not_cover_unknown_sid_allow(denying_sid: str) -> None:
    write_mask = 0x40
    assert acceptance._windows_untrusted_write_granted(  # pyright: ignore[reportPrivateUsage]
        (
            (1, write_mask, denying_sid),
            (0, write_mask, "S-1-5-21-111-222-333-444"),
        ),
        write_mask,
    )


def test_windows_ancestor_mask_rejects_component_replacement_not_child_creation() -> None:
    replacement_mask = acceptance._WINDOWS_REPLACE_COMPONENT_MASK  # pyright: ignore[reportPrivateUsage]
    assert acceptance._windows_untrusted_write_granted(  # pyright: ignore[reportPrivateUsage]
        ((0, 0x40, "S-1-5-32-545"),), replacement_mask
    )
    assert not acceptance._windows_untrusted_write_granted(  # pyright: ignore[reportPrivateUsage]
        ((0, 0x04, "S-1-5-32-545"),), replacement_mask
    )


def test_git_path_uses_strict_checks_for_replaceable_components_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = Path(r"C:\Program Files\Git\cmd\git.exe")
    observed: list[tuple[Path, bool, bool]] = []

    def verify(node: Path, *, expect_file: bool, strict_write: bool = True) -> None:
        observed.append((node, expect_file, strict_write))

    monkeypatch.setattr(acceptance, "_verify_path_node", verify)
    acceptance._verify_git_path(path)  # pyright: ignore[reportPrivateUsage]
    assert observed == [
        (path, True, True),
        (path.parent, False, True),
        (path.parent.parent, False, True),
        (path.parent.parent.parent, False, False),
        (path.parent.parent.parent.parent, False, False),
    ]


def test_standard_windows_program_files_git_path_passes_when_present() -> None:
    if os.name != "nt":
        pytest.skip("Windows-only fixed Git path")
    fixed_path = Path(r"C:\Program Files\Git\cmd\git.exe")
    if not fixed_path.exists():
        pytest.skip("standard system Git is not installed")
    acceptance._verify_git_path(fixed_path)  # pyright: ignore[reportPrivateUsage]


@pytest.mark.parametrize("host", ["10.77.0.3", "0.0.0.0", "*"])
def test_target_host_is_exactly_gated(host: str) -> None:
    value = request(approved=True)
    with pytest.raises(ValueError, match="target_host_rejected"):
        asyncio.run(run_acceptance(replace(value, target_host=host)))


@pytest.mark.parametrize("reserved_port", [7899, 8787])
def test_target_port_requires_reserved_range_or_deployed_docker_proof(
    monkeypatch: pytest.MonkeyPatch,
    reserved_port: int,
) -> None:
    async def target(host: str, port: int, timeout: float) -> bool:
        del host, port, timeout
        return True

    monkeypatch.setattr(acceptance, "tcp_target_probe", target)
    explicit = asyncio.run(
        run_acceptance(
            request(approved=True, target_port=reserved_port),
            runtime=runtime(Observer(snapshot())),
        )
    )
    assert explicit["stable_error_code"] != "target_port_rejected"

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


@pytest.mark.parametrize(
    ("initial", "expected_error"),
    [
        (snapshot_with_peer_routes((PEER, ())), "target_route_owner_mismatch"),
        (
            snapshot_with_peer_routes(
                (PEER, ("10.77.0.2/32",)),
                ("other-peer", ("10.77.0.2/32",)),
            ),
            "target_route_owner_mismatch",
        ),
    ],
)
def test_selected_peer_must_uniquely_own_target_route(
    initial: WindowsTunnelSnapshot, expected_error: str
) -> None:
    observer = Observer(initial)
    probe_calls: list[bool] = []
    report = asyncio.run(
        run_acceptance(request(approved=True), runtime=runtime(observer, probe_calls=probe_calls))
    )
    assert report["stable_error_code"] == expected_error
    assert report["target_route_owner_count"] in {0, 2}
    assert report["probe_executed"] is False
    assert report["target_probe_executed"] is False
    assert probe_calls == []


def test_selected_peer_may_uniquely_own_target_through_safe_broad_network(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def target(_host: str, _port: int, _timeout: float) -> bool:
        return True

    monkeypatch.setattr(acceptance, "tcp_target_probe", target)
    observer = Observer(snapshot_with_peer_networks((PEER, ("10.77.0.0/24",))))
    report = asyncio.run(
        run_acceptance(request(approved=True), runtime=runtime(observer), clock=lambda: NOW)
    )

    assert report["target_route_owner_count"] == 1
    assert report["probe_executed"] is True
    assert report["target_probe_executed"] is True
    assert report["stable_error_code"] is None
    assert cast(dict[str, object], report["path_evidence"])["host_route_present"] is True


def test_overlapping_safe_broad_networks_fail_closed_before_probe() -> None:
    observer = Observer(
        snapshot_with_peer_networks(
            (PEER, ("10.77.0.0/24",)),
            ("other-peer", ("10.77.0.0/16",)),
        )
    )
    report = asyncio.run(run_acceptance(request(approved=True), runtime=runtime(observer)))

    assert report["target_route_owner_count"] == 2
    assert report["stable_error_code"] == "target_route_owner_mismatch"
    assert report["probe_executed"] is False


@pytest.mark.parametrize(
    "competing_route",
    ["10.77.0.2/32", "10.77.0.0/16", "0.0.0.0/0", "10.0.0.0/7", "malformed"],
)
def test_wrapper_rejects_competing_ninth_network_before_route_or_probe(
    tmp_path: Path,
    competing_route: str,
) -> None:
    observer, command_runner = actual_observer_with_competing_ninth_network(
        tmp_path,
        competing_route,
    )
    probe_calls: list[bool] = []
    report = asyncio.run(
        run_acceptance(
            request(approved=True),
            runtime=runtime(cast(Observer, observer), probe_calls=probe_calls),
            clock=lambda: NOW,
        )
    )

    assert report["stable_error_code"] == "target_route_owner_mismatch"
    assert report["probe_executed"] is False
    assert report["target_probe_executed"] is False
    assert probe_calls == []
    assert [
        command for command in command_runner.commands if len(command) > 1 and command[1] == "print"
    ] == []


def test_broad_ownership_change_breaks_before_after_invariance() -> None:
    initial = snapshot_with_peer_networks((PEER, ("10.77.0.0/24",)))
    changed = snapshot_with_peer_networks((PEER, ("10.77.0.0/16",)))
    assert initial.system_fingerprint == changed.system_fingerprint
    assert initial.path_ownership_fingerprint != changed.path_ownership_fingerprint

    report = asyncio.run(
        run_acceptance(
            request(approved=True),
            runtime=runtime(ChangingObserver(initial, changed)),
            clock=lambda: NOW,
        )
    )

    assert report["stable_error_code"] == "network_state_changed"
    assert report["probe_executed"] is False


@pytest.mark.parametrize(
    "field",
    ["interface_present", "interface_up", "service_present", "service_running"],
)
def test_each_normalized_network_summary_field_change_fails_closed(field: str) -> None:
    initial = snapshot()
    changed = initial.model_copy(update={field: False})
    observer = ChangingObserver(initial, changed)
    report = asyncio.run(
        run_acceptance(request(approved=True), runtime=runtime(observer), clock=lambda: NOW)
    )
    assert report["stable_error_code"] == "network_state_changed"
    assert report["network_state_unchanged"] is False
    assert report["probe_executed"] is False
    assert report["target_probe_executed"] is False


def test_non_administrator_fails_before_observation() -> None:
    observer = Observer(snapshot())
    report = asyncio.run(run_acceptance(request(), runtime=runtime(observer, elevated=False)))
    assert report["preflight"] == {
        "elevated": False,
        "stable_error_code": "permission_denied",
    }
    assert observer.calls == 0


def test_non_administrator_accepts_approved_remote_target_connectivity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def target(host: str, port: int, timeout: float) -> bool:
        assert (host, port, timeout) == ("10.77.0.2", 18880, 2.0)
        return True

    def local_interface(interface: str, host: str) -> dict[str, object]:
        return {
            "interface_present": interface == "HomeMac",
            "interface_up": True,
            "address_count": 1,
            "address_hash": "sha256:" + "a" * 64,
            "target_is_local": host == "10.77.0.1",
        }

    monkeypatch.setattr(acceptance, "tcp_target_probe", target)
    monkeypatch.setattr(acceptance, "_local_interface_summary", local_interface)
    report = asyncio.run(
        run_acceptance(
            request(approved=True),
            runtime=runtime(Observer(snapshot()), elevated=False),
            clock=lambda: NOW,
        )
    )
    assert report["passed"] is True
    assert report["source_code"] == "target-connectivity"
    assert report["network_state_unchanged"] is True
    assert report["writes_performed"] is False


def test_non_administrator_rejects_local_target_before_connect(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def target(_host: str, _port: int, _timeout: float) -> bool:
        raise AssertionError("本机目标不得执行连接")

    def local_interface(_interface: str, host: str) -> dict[str, object]:
        return {
            "interface_present": True,
            "interface_up": True,
            "address_count": 1,
            "address_hash": "sha256:" + "a" * 64,
            "target_is_local": host == "10.77.0.1",
        }

    monkeypatch.setattr(acceptance, "tcp_target_probe", target)
    monkeypatch.setattr(acceptance, "_local_interface_summary", local_interface)
    report = asyncio.run(
        run_acceptance(
            replace(request(approved=True), target_host="10.77.0.1"),
            runtime=runtime(Observer(snapshot()), elevated=False),
            clock=lambda: NOW,
        )
    )
    assert report["passed"] is False
    assert report["stable_error_code"] == "local_target_rejected"
    assert report["target_probe_executed"] is False


def test_non_administrator_rejects_network_change_after_connect(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def target(_host: str, _port: int, _timeout: float) -> bool:
        return True

    def local_interface(_interface: str, _host: str) -> dict[str, object]:
        return {
            "interface_present": True,
            "interface_up": True,
            "address_count": 1,
            "address_hash": "sha256:" + "a" * 64,
            "target_is_local": False,
        }

    monkeypatch.setattr(acceptance, "tcp_target_probe", target)
    monkeypatch.setattr(acceptance, "_local_interface_summary", local_interface)
    report = asyncio.run(
        run_acceptance(
            request(approved=True),
            runtime=runtime(
                Observer(snapshot()),
                elevated=False,
                route_hashes=[
                    "sha256:" + "1" * 64,
                    "sha256:" + "1" * 64,
                    "sha256:" + "2" * 64,
                ],
            ),
            clock=lambda: NOW,
        )
    )
    assert report["passed"] is False
    assert report["stable_error_code"] == "network_state_changed"
    assert report["network_state_unchanged"] is False


def test_non_administrator_stops_before_connect_when_guard_changes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target_calls: list[bool] = []

    async def target(_host: str, _port: int, _timeout: float) -> bool:
        target_calls.append(True)
        return True

    def local_interface(_interface: str, _host: str) -> dict[str, object]:
        return {
            "interface_present": True,
            "interface_up": True,
            "address_count": 1,
            "address_hash": "sha256:" + "a" * 64,
            "target_is_local": False,
        }

    monkeypatch.setattr(acceptance, "tcp_target_probe", target)
    monkeypatch.setattr(acceptance, "_local_interface_summary", local_interface)
    report = asyncio.run(
        run_acceptance(
            request(approved=True),
            runtime=runtime(
                Observer(snapshot()),
                elevated=False,
                route_hashes=["sha256:" + "1" * 64, "sha256:" + "2" * 64],
            ),
            clock=lambda: NOW,
        )
    )
    assert report["stable_error_code"] == "network_state_changed"
    assert report["target_probe_executed"] is False
    assert target_calls == []


def test_non_administrator_rejects_failed_route_observation_before_connect(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target_calls: list[bool] = []

    async def target(_host: str, _port: int, _timeout: float) -> bool:
        target_calls.append(True)
        return True

    def local_interface(_interface: str, _host: str) -> dict[str, object]:
        return {
            "interface_present": True,
            "interface_up": True,
            "address_count": 1,
            "address_hash": "sha256:" + "a" * 64,
            "target_is_local": False,
        }

    monkeypatch.setattr(acceptance, "tcp_target_probe", target)
    monkeypatch.setattr(acceptance, "_local_interface_summary", local_interface)
    report = asyncio.run(
        run_acceptance(
            request(approved=True),
            runtime=runtime(
                Observer(snapshot()),
                elevated=False,
                route_returncodes=[1],
            ),
            clock=lambda: NOW,
        )
    )
    assert report["passed"] is False
    assert report["stable_error_code"] == "route_observation_failed"
    assert report["target_probe_executed"] is False
    assert target_calls == []


@pytest.mark.parametrize(
    ("error", "expected"),
    [
        (ValueError("acceptance_command_rejected"), "command_boundary_rejected"),
        (ValueError("trusted_checkout_unavailable"), "trusted_checkout"),
        (ValueError("route contains secret endpoint"), "platform_observation_failed"),
        (RuntimeError("programming detail with secret"), "acceptance_internal_error"),
    ],
)
def test_exception_mapping_is_stable_and_redacted(error: Exception, expected: str) -> None:
    code = acceptance._stable_error_code_from_exception(  # pyright: ignore[reportPrivateUsage]
        error
    )
    assert code == expected
    assert "secret" not in code


def test_main_maps_observer_failure_without_echoing_exception(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(acceptance.sys.stdin, "isatty", lambda: True)

    def evidence_path(_platform: str) -> Path:
        return Path("evidence.json")

    def trusted_revision(_path: Path) -> str:
        return "a" * 40

    def fake_getpass(_prompt: str) -> str:
        return PEER

    def no_write(*args: object, **kwargs: object) -> None:
        del args, kwargs

    monkeypatch.setattr(acceptance, "_evidence_path", evidence_path)
    monkeypatch.setattr(acceptance, "_trusted_checkout_revision", trusted_revision)
    monkeypatch.setattr(acceptance.getpass, "getpass", fake_getpass)

    async def fail_observation(*args: object, **kwargs: object) -> dict[str, object]:
        del args, kwargs
        raise ValueError("raw route output with endpoint")

    monkeypatch.setattr(acceptance, "run_acceptance", fail_observation)
    monkeypatch.setattr(acceptance, "_write_report", no_write)

    assert (
        acceptance.main(["--platform", "windows", "--interface", "HomeMac", "--code-sha", "a" * 40])
        == 1
    )
    output = capsys.readouterr().out
    assert "platform_observation_failed" in output
    assert "raw route output with endpoint" not in output


def test_approved_main_is_noninteractive_and_resolves_peer_from_hash(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: list[AcceptanceRequest] = []
    approved_hash = canonical_sha256({"peer_public_key": PEER, "host": ENDPOINT, "port": 51820})

    def evidence_path(_platform: str) -> Path:
        return Path("evidence.json")

    def trusted_revision(_path: Path) -> str:
        return "a" * 40

    def reject_getpass(_prompt: str) -> str:
        raise AssertionError("不得读取交互输入")

    def no_write(
        _report: dict[str, object],
        _platform: str | None,
        _output_path: Path | None = None,
    ) -> Path | None:
        return None

    monkeypatch.setattr(acceptance.sys.stdin, "isatty", lambda: False)
    monkeypatch.setattr(acceptance, "_evidence_path", evidence_path)
    monkeypatch.setattr(acceptance, "_trusted_checkout_revision", trusted_revision)
    monkeypatch.setattr(acceptance.getpass, "getpass", reject_getpass)

    async def accepted(req: AcceptanceRequest) -> dict[str, object]:
        captured.append(req)
        return {
            "schema_version": acceptance.SCHEMA_VERSION,
            "code_sha": req.code_sha,
            "platform_code": req.platform,
            "passed": True,
            "probe_executed": True,
            "writes_performed": False,
            "stable_error_code": None,
        }

    monkeypatch.setattr(acceptance, "run_acceptance", accepted)
    monkeypatch.setattr(acceptance, "_write_report", no_write)

    assert (
        acceptance.main(
            [
                "--platform",
                "windows",
                "--interface",
                "HomeMac",
                "--code-sha",
                "a" * 40,
                "--approve-candidate",
                approved_hash,
                "--target-host",
                "10.77.0.1",
                "--target-port",
                "18880",
            ]
        )
        == 0
    )
    assert len(captured) == 1
    assert captured[0].peer_public_key is None
    assert captured[0].approved_candidate_hash == approved_hash


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


def test_final_network_change_forces_path_evidence_unverified(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def target(host: str, port: int, timeout: float) -> bool:
        del host, port, timeout
        return True

    monkeypatch.setattr(acceptance, "tcp_target_probe", target)
    observer = Observer(snapshot())
    report = asyncio.run(
        run_acceptance(
            request(approved=True),
            runtime=runtime(
                observer,
                route_hashes=[
                    "sha256:" + "1" * 64,
                    "sha256:" + "1" * 64,
                    "sha256:" + "1" * 64,
                    "sha256:" + "2" * 64,
                ],
            ),
            clock=lambda: NOW,
        )
    )
    assert report["stable_error_code"] == "network_state_changed"
    assert report["passed"] is False
    assert report["probe_executed"] is True
    assert report["target_probe_executed"] is True
    evidence = report["path_evidence"]
    assert isinstance(evidence, dict)
    assert evidence["verified"] is False
    assert evidence["stable_error_code"] == "network_state_changed"


def test_preflight_output_contains_only_redacted_candidate_hash() -> None:
    report = asyncio.run(
        run_acceptance(request(), runtime=runtime(Observer(snapshot())), clock=lambda: NOW)
    )
    serialized = json.dumps(report, ensure_ascii=False)
    assert report["candidate_count"] == 1
    assert str(report["candidate_hash"]).startswith("sha256:")
    for forbidden in (PEER, ENDPOINT, "HomeMac", "10.77.0.2/32"):
        assert forbidden not in serialized


def test_approved_hash_uniquely_resolves_peer_without_interactive_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def target(_host: str, _port: int, _timeout: float) -> bool:
        return True

    monkeypatch.setattr(acceptance, "tcp_target_probe", target)
    approved = replace(request(approved=True), peer_public_key=None)
    report = asyncio.run(
        run_acceptance(approved, runtime=runtime(Observer(snapshot())), clock=lambda: NOW)
    )

    assert report["passed"] is True
    assert report["probe_executed"] is True
    serialized = json.dumps(report, ensure_ascii=False)
    assert PEER not in serialized


def test_production_runtime_is_rebuilt_with_uniquely_resolved_peer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    peer_bindings: list[str | None] = []

    def build_runtime(req: AcceptanceRequest, _executor: object) -> PlatformRuntime:
        peer_bindings.append(req.peer_public_key)
        return runtime(Observer(snapshot()))

    async def target(_host: str, _port: int, _timeout: float) -> bool:
        return True

    def trusted_revision(_path: Path) -> str:
        return "a" * 40

    monkeypatch.setattr(acceptance, "_windows_runtime", build_runtime)
    monkeypatch.setattr(acceptance, "_trusted_checkout_revision", trusted_revision)
    monkeypatch.setattr(acceptance, "tcp_target_probe", target)

    report = asyncio.run(
        run_acceptance(
            replace(request(approved=True), peer_public_key=None),
            clock=lambda: NOW,
        )
    )

    assert report["passed"] is True
    assert peer_bindings == [None, PEER]


@pytest.mark.parametrize("match_count", [0, 2])
def test_approved_hash_requires_exactly_one_matching_peer(
    monkeypatch: pytest.MonkeyPatch,
    match_count: int,
) -> None:
    duplicated = snapshot().model_copy(update={"peers": snapshot().peers * 2})
    probe_calls: list[bool] = []
    route_calls: list[bool] = []
    target_calls: list[bool] = []

    async def target(_host: str, _port: int, _timeout: float) -> bool:
        target_calls.append(True)
        return True

    monkeypatch.setattr(acceptance, "tcp_target_probe", target)
    approved = replace(
        request(approved=True),
        peer_public_key=None,
        approved_candidate_hash=(
            request(approved=True).approved_candidate_hash
            if match_count == 2
            else "sha256:" + "f" * 64
        ),
    )
    report = asyncio.run(
        run_acceptance(
            approved,
            runtime=runtime(
                Observer(duplicated if match_count == 2 else snapshot()),
                probe_calls=probe_calls,
                route_calls=route_calls,
            ),
            clock=lambda: NOW,
        )
    )

    assert report["stable_error_code"] == "candidate_approval_mismatch"
    assert report["probe_executed"] is False
    assert probe_calls == []
    assert route_calls == []
    assert target_calls == []


def test_missing_peer_without_approved_hash_is_rejected() -> None:
    with pytest.raises(ValueError, match="peer_key_rejected"):
        asyncio.run(
            run_acceptance(
                replace(request(), peer_public_key=None),
                runtime=runtime(Observer(snapshot())),
                clock=lambda: NOW,
            )
        )


def test_report_rejects_format_correct_but_untrusted_sha() -> None:
    with pytest.raises(ValueError, match="code_sha_mismatch"):
        acceptance._validate_report_code_sha(  # pyright: ignore[reportPrivateUsage]
            "a" * 40, "b" * 40
        )


def test_run_rejects_untrusted_sha_before_platform_runtime(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def trusted_revision(evidence_path: Path) -> str:
        del evidence_path
        return "b" * 40

    monkeypatch.setattr(
        acceptance,
        "_trusted_checkout_revision",
        trusted_revision,
    )
    report = asyncio.run(run_acceptance(request()))
    assert report["stable_error_code"] == "code_sha_mismatch"
    assert report["probe_executed"] is False


def test_trusted_checkout_rejects_dirty_worktree_and_returns_head() -> None:
    root = Path(acceptance.__file__).resolve().parents[1]
    evidence = root / "evaluations" / "platform" / "managed-path-readonly-test.json"

    def clean_git(command: tuple[str, ...]) -> tuple[int, str, str]:
        if command == ("rev-parse", "--show-toplevel"):
            return 0, str(root), ""
        if command == ("status", "--porcelain=v1", "--untracked-files=all"):
            return 0, "", ""
        if command == ("rev-parse", "--verify", "HEAD"):
            return 0, "b" * 40, ""
        raise AssertionError(command)

    assert (
        acceptance._trusted_checkout_revision(  # pyright: ignore[reportPrivateUsage]
            evidence, git_runner=clean_git
        )
        == "b" * 40
    )

    def evidence_git(command: tuple[str, ...]) -> tuple[int, str, str]:
        if command == ("rev-parse", "--show-toplevel"):
            return 0, str(root), ""
        if command == ("status", "--porcelain=v1", "--untracked-files=all"):
            return 0, "?? evaluations/platform/managed-path-readonly-test.json\n", ""
        if command == ("rev-parse", "--verify", "HEAD"):
            return 0, "b" * 40, ""
        raise AssertionError(command)

    assert (
        acceptance._trusted_checkout_revision(  # pyright: ignore[reportPrivateUsage]
            evidence, git_runner=evidence_git
        )
        == "b" * 40
    )

    def dirty_git(command: tuple[str, ...]) -> tuple[int, str, str]:
        if command == ("rev-parse", "--show-toplevel"):
            return 0, str(root), ""
        if command == ("status", "--porcelain=v1", "--untracked-files=all"):
            return 0, " M scripts/other.py\n", ""
        raise AssertionError(command)

    with pytest.raises(ValueError, match="checkout_dirty"):
        acceptance._trusted_checkout_revision(  # pyright: ignore[reportPrivateUsage]
            evidence, git_runner=dirty_git
        )


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
