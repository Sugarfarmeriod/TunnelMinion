"""人工启动的 Windows/macOS managed path 管理员只读验收包装器。"""

from __future__ import annotations

import argparse
import asyncio
import ctypes
import getpass
import ipaddress
import json
import os
import re
import stat
import subprocess
import sys
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Protocol, cast

from tunnelminion.domain.identifiers import NetworkId, NodeId
from tunnelminion.network.contracts import CandidateSource, EndpointCandidate, canonical_sha256
from tunnelminion.network.path_probe import (
    PathProbePolicy,
    PlatformPathProbe,
    TargetProbe,
    tcp_target_probe,
)
from tunnelminion.platforms.macos.managed_system import (
    FixedMacOSWireGuardCommands,
    MacOSProviderPaths,
    MacOSWireGuardObserver,
)
from tunnelminion.platforms.macos.path_probe import MacOSPathProbe
from tunnelminion.platforms.windows.managed_system import (
    FixedWindowsWireGuardCommands,
    WindowsProviderPaths,
    WindowsTunnelSnapshot,
    WindowsWireGuardObserver,
    parse_safe_allowed_network,
    windows_is_administrator,
)
from tunnelminion.platforms.windows.path_probe import WindowsPathProbe
from tunnelminion.platforms.windows.system import (
    CommandResult,
    PsutilSystemReader,
    SubprocessCommandRunner,
    default_docker_path,
)

SCHEMA_VERSION = "managed-path-readonly-evidence/v1"
TARGET_HOSTS = frozenset({"10.77.0.1", "10.77.0.2"})
RESERVED_TARGET_PORTS = frozenset({8787, *range(18880, 18900)})
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_CODE_SHA = re.compile(r"^[0-9a-f]{40}$")
_WINDOWS_INTERFACE = re.compile(r"^[A-Za-z0-9_. -]{1,64}$")
_MACOS_INTERFACE = re.compile(r"^(?:utun[0-9]+|tmn-[a-z0-9-]{1,48})$")
_WINDOWS_GIT_CANDIDATES = (
    Path(r"C:\Program Files\Git\cmd\git.exe"),
    Path(r"C:\Program Files\Git\bin\git.exe"),
    Path(r"C:\Program Files (x86)\Git\cmd\git.exe"),
)
_MACOS_GIT_CANDIDATES = (Path("/usr/bin/git"),)
_GIT_COMMANDS = frozenset(
    {
        ("rev-parse", "--show-toplevel"),
        ("rev-parse", "--verify", "HEAD"),
        ("status", "--porcelain=v1", "--untracked-files=all"),
    }
)
_GIT_FIXED_ARGS = (
    "--no-pager",
    "--no-optional-locks",
    "-c",
    "core.fsmonitor=false",
    "-c",
    "core.untrackedCache=false",
    "-c",
    "core.preloadIndex=false",
    "-c",
    f"core.hooksPath={os.devnull}",
)
_WINDOWS_WRITE_MASK = (
    0x00000002
    | 0x00000004
    | 0x00000010
    | 0x00000040
    | 0x00000100
    | 0x00010000
    | 0x00040000
    | 0x00080000
    | 0x10000000
    | 0x40000000
)
_WINDOWS_REPLACE_COMPONENT_MASK = (
    0x00000040 | 0x00010000 | 0x00040000 | 0x00080000 | 0x01000000 | 0x10000000
)
_TRUSTED_WINDOWS_SID_EXACT = frozenset({"S-1-5-18", "S-1-5-32-544"})
_TRUSTED_WINDOWS_SERVICE_SID_PREFIX = "S-1-5-80-"


class NetworkChangedError(RuntimeError):
    """前后只读摘要不一致；异常正文固定且不携带原始事实。"""


_REQUEST_ERROR_CODES = frozenset(
    {
        "platform_rejected",
        "interface_rejected",
        "peer_key_rejected",
        "code_sha_rejected",
        "code_sha_mismatch",
        "candidate_approval_rejected",
        "target_host_rejected",
        "target_port_rejected",
    }
)
_TRUSTED_CHECKOUT_ERROR_PREFIXES = (
    "checkout_",
    "evidence_path_",
    "git_",
    "trusted_checkout_",
)


def _stable_error_code_from_exception(exc: BaseException) -> str:
    """将预期边界错误映射为固定代码，绝不回显异常正文。"""
    if isinstance(exc, NetworkChangedError):
        return "network_state_changed"
    if isinstance(exc, ValueError):
        code = str(exc)
        if code in {"acceptance_command_rejected", "git_command_rejected"}:
            return "command_boundary_rejected"
        if code in _REQUEST_ERROR_CODES:
            return code
        if code.startswith(_TRUSTED_CHECKOUT_ERROR_PREFIXES):
            return "trusted_checkout"
        return "platform_observation_failed"
    if isinstance(exc, OSError):
        return "platform_observation_failed"
    return "acceptance_internal_error"


class Observer(Protocol):
    async def observe(self, interface_name: str) -> WindowsTunnelSnapshot: ...


class PathObserver(Protocol):
    async def observe_path(
        self,
        interface_name: str,
        *,
        peer_public_key: str,
        expected_host_route: str,
    ) -> WindowsTunnelSnapshot: ...


class CandidateObserver(Protocol):
    async def observe_candidates(self, interface_name: str) -> WindowsTunnelSnapshot: ...


Executor = Callable[[tuple[str, ...], float], Awaitable[CommandResult]]
GitRunner = Callable[[tuple[str, ...]], tuple[int, str, str]]


def _required_peer_public_key(value: str | None) -> str:
    if value is None:
        raise ValueError("peer_key_rejected")
    return value


@dataclass(frozen=True)
class AcceptanceRequest:
    platform: str
    interface_name: str
    peer_public_key: str | None
    code_sha: str
    approved_candidate_hash: str | None = None
    target_host: str | None = None
    target_port: int | None = None


@dataclass(frozen=True)
class PlatformRuntime:
    observer: Observer
    probe_factory: Callable[[PathProbePolicy, TargetProbe], PlatformPathProbe]
    route_summary: Callable[[], Awaitable[tuple[str, int]]]
    docker_ports: Callable[[], Awaitable[tuple[frozenset[int], int]]]
    elevated: bool
    source_code: str


class ReadOnlyCommandRunner:
    """验收进程的第二道固定 argv 白名单；任何写命令都在执行前拒绝。"""

    def __init__(
        self,
        *,
        platform: str,
        tools: dict[str, Path],
        interface_name: str,
        executor: Executor | None = None,
    ) -> None:
        self._platform = platform
        self._tools = {name: str(path) for name, path in tools.items()}
        self._interface_name = interface_name
        delegate = SubprocessCommandRunner()
        self._executor = executor or delegate.run

    async def run(self, command: tuple[str, ...], timeout_seconds: float) -> CommandResult:
        self._validate(command)
        return await self._executor(command, timeout_seconds)

    def _validate(self, command: tuple[str, ...]) -> None:
        allowed: set[tuple[str, ...]] = {
            (self._tools["docker"], "ps", "--no-trunc", "--format", "{{json .}}")
        }
        fields = ("public-key", "peers", "endpoints", "allowed-ips", "latest-handshakes")
        if self._platform == "windows":
            allowed.update(
                (self._tools["wg"], "show", self._interface_name, field) for field in fields
            )
            allowed.add((self._tools["sc"], "query", f"WireGuardTunnel${self._interface_name}"))
            allowed.add((self._tools["route"], "print", "-4"))
            allowed.update((self._tools["route"], "print", host) for host in TARGET_HOSTS)
        else:
            allowed.add((self._tools["wg"], "show", "interfaces"))
            allowed.update(
                (self._tools["wg"], "show", self._interface_name, field) for field in fields
            )
            allowed.add((self._tools["ifconfig"], self._interface_name))
            allowed.add((self._tools["netstat"], "-rn", "-f", "inet"))
            allowed.add((self._tools["netstat"], "-rn", "-f", "inet6"))
        if command not in allowed:
            raise ValueError("acceptance_command_rejected")


def _windows_runtime(request: AcceptanceRequest, executor: Executor | None) -> PlatformRuntime:
    paths = WindowsProviderPaths(
        wireguard_exe=Path(r"C:\Program Files\WireGuard\wireguard.exe"),
        wg_exe=Path(r"C:\Program Files\WireGuard\wg.exe"),
        sc_exe=Path(r"C:\Windows\System32\sc.exe"),
        route_exe=Path(r"C:\Windows\System32\route.exe"),
        config_root=Path(r"C:\ProgramData\TunnelMinion\acceptance-unused"),
    )
    tools = {
        "wg": paths.wg_exe,
        "sc": paths.sc_exe,
        "route": paths.route_exe,
        "docker": Path(default_docker_path()),
    }
    runner = ReadOnlyCommandRunner(
        platform="windows",
        tools=tools,
        interface_name=request.interface_name,
        executor=executor,
    )
    commands = FixedWindowsWireGuardCommands(paths, runner)
    observer = WindowsWireGuardObserver(PsutilSystemReader(), commands)

    async def route_summary() -> tuple[str, int]:
        result = await commands.route_table()
        return canonical_sha256({"stdout": result.stdout}), result.returncode

    return PlatformRuntime(
        observer=observer,
        probe_factory=lambda policy, target: WindowsPathProbe(
            observer,
            interface_name=request.interface_name,
            peer_public_key=_required_peer_public_key(request.peer_public_key),
            policy=policy,
            target_probe=target,
        ),
        route_summary=route_summary,
        docker_ports=lambda: _docker_ports(runner, tools["docker"]),
        elevated=windows_is_administrator() if os.name == "nt" else False,
        source_code="windows_production_path_probe",
    )


def _macos_runtime(request: AcceptanceRequest, executor: Executor | None) -> PlatformRuntime:
    paths = MacOSProviderPaths(
        wg=Path("/usr/local/bin/wg"),
        wg_quick=Path("/usr/local/bin/wg-quick"),
        ifconfig=Path("/sbin/ifconfig"),
        netstat=Path("/usr/sbin/netstat"),
        config_root=Path("/var/empty/tunnelminion-acceptance-unused"),
    )
    tools = {
        "wg": paths.wg,
        "ifconfig": paths.ifconfig,
        "netstat": paths.netstat,
        "docker": Path("/usr/local/bin/docker"),
    }
    runner = ReadOnlyCommandRunner(
        platform="macos",
        tools=tools,
        interface_name=request.interface_name,
        executor=executor,
    )
    commands = FixedMacOSWireGuardCommands(paths, runner)
    observer = MacOSWireGuardObserver(commands)

    async def route_summary() -> tuple[str, int]:
        ipv4 = await commands.route_table("inet")
        ipv6 = await commands.route_table("inet6")
        return (
            canonical_sha256({"ipv4": ipv4.stdout, "ipv6": ipv6.stdout}),
            max(ipv4.returncode, ipv6.returncode),
        )

    return PlatformRuntime(
        observer=observer,
        probe_factory=lambda policy, target: MacOSPathProbe(
            observer,
            interface_name=request.interface_name,
            peer_public_key=_required_peer_public_key(request.peer_public_key),
            policy=policy,
            target_probe=target,
        ),
        route_summary=route_summary,
        docker_ports=lambda: _docker_ports(runner, tools["docker"]),
        elevated=os.geteuid() == 0 if sys.platform == "darwin" else False,  # pyright: ignore
        source_code="macos_production_path_probe",
    )


async def _docker_ports(
    runner: ReadOnlyCommandRunner, docker_path: Path
) -> tuple[frozenset[int], int]:
    result = await runner.run((str(docker_path), "ps", "--no-trunc", "--format", "{{json .}}"), 10)
    if result.returncode != 0:
        return frozenset(), 0
    ports: set[int] = set()
    count = 0
    for line in result.stdout.splitlines():
        try:
            raw_value: object = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(raw_value, dict):
            continue
        value = cast(dict[str, object], raw_value)
        count += 1
        text = str(value.get("Ports", ""))
        ports.update(int(item) for item in re.findall(r"(?:^|[, ])(?:[^,]*:)?(\d+)->\d+/tcp", text))
    return frozenset(ports), count


async def _summary(
    runtime: PlatformRuntime,
    interface_name: str,
    *,
    peer_public_key: str | None = None,
    expected_host_route: str | None = None,
) -> tuple[dict[str, object], WindowsTunnelSnapshot]:
    if (
        peer_public_key is not None
        and expected_host_route is not None
        and hasattr(runtime.observer, "observe_path")
    ):
        snapshot = await cast(PathObserver, runtime.observer).observe_path(
            interface_name,
            peer_public_key=peer_public_key,
            expected_host_route=expected_host_route,
        )
    else:
        snapshot = await runtime.observer.observe(interface_name)
    route_hash, route_returncode = await runtime.route_summary()
    value: dict[str, object] = {
        "route_hash": route_hash,
        "route_query_succeeded": route_returncode == 0,
        "interface_present": snapshot.interface_present,
        "interface_up": snapshot.interface_up,
        "service_present": snapshot.service_present,
        "service_running": snapshot.service_running,
        "peer_count": len(snapshot.peers),
        "host_route_count": len(snapshot.host_routes),
        "stable_error_code": snapshot.observed_error_code,
    }
    value["summary_hash"] = canonical_sha256(
        {
            "system_fingerprint": snapshot.system_fingerprint,
            "path_ownership_fingerprint": snapshot.path_ownership_fingerprint,
            "route_hash": route_hash,
            "route_query_returncode": route_returncode,
            "route_query_succeeded": value["route_query_succeeded"],
            "interface_present": value["interface_present"],
            "interface_up": value["interface_up"],
            "service_present": value["service_present"],
            "service_running": value["service_running"],
            "peer_count": value["peer_count"],
            "host_route_count": value["host_route_count"],
            "stable_error_code": value["stable_error_code"],
        }
    )
    return value, snapshot


async def _candidate_snapshot(
    runtime: PlatformRuntime, interface_name: str
) -> WindowsTunnelSnapshot:
    if hasattr(runtime.observer, "observe_candidates"):
        return await cast(CandidateObserver, runtime.observer).observe_candidates(interface_name)
    return await runtime.observer.observe(interface_name)


def _candidate(
    snapshot: WindowsTunnelSnapshot, peer_public_key: str
) -> tuple[str, str, int] | None:
    peer = next((item for item in snapshot.peers if item.public_key == peer_public_key), None)
    if peer is None or peer.endpoint_host is None or peer.endpoint_port is None:
        return None
    candidate_hash = canonical_sha256(
        {"peer_public_key": peer_public_key, "host": peer.endpoint_host, "port": peer.endpoint_port}
    )
    return candidate_hash, peer.endpoint_host, peer.endpoint_port


def _approved_candidate(
    snapshot: WindowsTunnelSnapshot, approved_hash: str
) -> tuple[str, tuple[str, str, int]] | None:
    matches = tuple(
        (peer.public_key, candidate)
        for peer in snapshot.peers
        if (candidate := _candidate(snapshot, peer.public_key)) is not None
        and candidate[0] == approved_hash
    )
    return matches[0] if len(matches) == 1 else None


def _target_route_owner_count(snapshot: WindowsTunnelSnapshot, target_route: str) -> int:
    """统计安全 network 覆盖精确目标 host 的 peer 数量；调用方另行核对所选 peer。"""
    try:
        target = ipaddress.ip_network(target_route, strict=True)
    except ValueError:
        return 0
    if target.prefixlen != target.max_prefixlen:
        return 0
    if parse_safe_allowed_network(target_route) != target_route:
        return 0
    if any(not peer.allowed_networks_complete for peer in snapshot.peers):
        return 0
    owners = 0
    for peer in snapshot.peers:
        networks = (*peer.allowed_networks, *peer.allowed_host_routes)
        if any(
            target.network_address in ipaddress.ip_network(parsed, strict=True)
            for route in networks
            if (parsed := parse_safe_allowed_network(route)) is not None
        ):
            owners += 1
    return owners


def _selected_peer_owns_unique_target_route(
    snapshot: WindowsTunnelSnapshot,
    peer_public_key: str,
    target_route: str,
) -> bool:
    owners = _target_route_owner_count(snapshot, target_route)
    selected = next((peer for peer in snapshot.peers if peer.public_key == peer_public_key), None)
    if owners != 1 or selected is None:
        return False
    try:
        target = ipaddress.ip_network(target_route, strict=True)
    except ValueError:
        return False
    return target.prefixlen == target.max_prefixlen and any(
        target.network_address in ipaddress.ip_network(parsed, strict=True)
        for route in (*selected.allowed_networks, *selected.allowed_host_routes)
        if (parsed := parse_safe_allowed_network(route)) is not None
    )


def _base_report(request: AcceptanceRequest, started_at: datetime) -> dict[str, object]:
    return {
        "schema_version": SCHEMA_VERSION,
        "code_sha": request.code_sha,
        "platform_code": request.platform,
        "started_at": started_at.isoformat(),
        "writes_performed": False,
    }


async def run_acceptance(
    request: AcceptanceRequest,
    *,
    runtime: PlatformRuntime | None = None,
    executor: Executor | None = None,
    clock: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> dict[str, object]:
    """运行预检或已批准探测；报告永不包含原始系统事实。"""
    started_at = clock().astimezone(UTC)
    _validate_request(request)
    report = _base_report(request, started_at)
    if runtime is None:
        try:
            trusted_revision = _trusted_checkout_revision(_evidence_path(request.platform))
        except ValueError as exc:
            return _finish_failure(report, clock, str(exc))
        if request.code_sha != trusted_revision:
            return _finish_failure(report, clock, "code_sha_mismatch")
        selected_runtime = (
            _windows_runtime(request, executor)
            if request.platform == "windows"
            else _macos_runtime(request, executor)
        )
    else:
        selected_runtime = runtime
    if not selected_runtime.elevated:
        report.update(
            {
                "passed": False,
                "preflight": {"elevated": False, "stable_error_code": "permission_denied"},
                "finished_at": clock().astimezone(UTC).isoformat(),
            }
        )
        return report

    target_route = f"{request.target_host}/32" if request.target_host is not None else None
    peer_public_key = request.peer_public_key
    if peer_public_key is None:
        candidate_snapshot = await _candidate_snapshot(selected_runtime, request.interface_name)
        approved = _approved_candidate(
            candidate_snapshot, cast(str, request.approved_candidate_hash)
        )
        if approved is None:
            report.update(
                {
                    "preflight": {"elevated": True, "stable_error_code": None},
                    "candidate_count": 0,
                    "candidate_hash": None,
                    "source_code": selected_runtime.source_code,
                }
            )
            return _finish_failure(report, clock, "candidate_approval_mismatch")
        peer_public_key, discovered = approved
        if runtime is None:
            resolved_request = replace(request, peer_public_key=peer_public_key)
            selected_runtime = (
                _windows_runtime(resolved_request, executor)
                if request.platform == "windows"
                else _macos_runtime(resolved_request, executor)
            )
        before, snapshot = await _summary(
            selected_runtime,
            request.interface_name,
            peer_public_key=peer_public_key,
            expected_host_route=target_route,
        )
    else:
        before, snapshot = await _summary(
            selected_runtime,
            request.interface_name,
            peer_public_key=peer_public_key if target_route is not None else None,
            expected_host_route=target_route,
        )
        discovered = _candidate(snapshot, peer_public_key)
    report.update(
        {
            "preflight": {"elevated": True, "stable_error_code": None},
            "before": before,
            "candidate_count": 0 if discovered is None else 1,
            "candidate_hash": None if discovered is None else discovered[0],
            "source_code": selected_runtime.source_code,
        }
    )
    if request.approved_candidate_hash is None:
        report.update(
            {
                "passed": False,
                "probe_executed": False,
                "stable_error_code": (
                    "candidate_approval_required"
                    if discovered is not None
                    else "candidate_unavailable"
                ),
                "finished_at": clock().astimezone(UTC).isoformat(),
            }
        )
        return report
    if discovered is None or discovered[0] != request.approved_candidate_hash:
        return _finish_failure(report, clock, "candidate_approval_mismatch")

    assert request.target_host is not None and request.target_port is not None
    assert target_route is not None
    assert peer_public_key is not None
    reserved = request.target_port in RESERVED_TARGET_PORTS
    if reserved:
        docker_ports, docker_service_count = frozenset[int](), 0
    else:
        docker_ports, docker_service_count = await selected_runtime.docker_ports()
    docker_proven = request.target_port in docker_ports
    report["target_approval_hash"] = canonical_sha256(
        {"host": request.target_host, "port": request.target_port}
    )
    report["port_policy_code"] = "reserved_acceptance" if reserved else "deployed_docker"
    report["docker_service_count"] = docker_service_count
    if not (reserved or docker_proven):
        return _finish_failure(report, clock, "target_port_rejected")

    guarded, guarded_snapshot = await _summary(
        selected_runtime,
        request.interface_name,
        peer_public_key=peer_public_key,
        expected_host_route=target_route,
    )
    if guarded["summary_hash"] != before["summary_hash"]:
        report["after"] = guarded
        report["network_state_unchanged"] = False
        return _finish_failure(report, clock, "network_state_changed")

    target_route_owner_count = _target_route_owner_count(guarded_snapshot, target_route)
    report["target_route_owner_count"] = target_route_owner_count
    if not _selected_peer_owns_unique_target_route(guarded_snapshot, peer_public_key, target_route):
        return _finish_failure(report, clock, "target_route_owner_mismatch")

    target_called = False
    connect_guard_summary: dict[str, object] | None = None

    async def guarded_target(host: str, port: int, timeout_seconds: float) -> bool:
        nonlocal connect_guard_summary, target_called
        immediate, _ = await _summary(
            selected_runtime,
            request.interface_name,
            peer_public_key=peer_public_key,
            expected_host_route=target_route,
        )
        if immediate["summary_hash"] != before["summary_hash"]:
            connect_guard_summary = immediate
            raise NetworkChangedError("network_state_changed")
        target_called = True
        return await tcp_target_probe(host, port, timeout_seconds)

    _, endpoint_host, endpoint_port = discovered
    now = clock().astimezone(UTC)
    candidate = EndpointCandidate(
        host=endpoint_host,
        port=endpoint_port,
        source=CandidateSource.ADMIN_EXPLICIT,
        observed_at=now,
        expires_at=now + timedelta(minutes=3),
    )
    endpoint_address = ipaddress.ip_address(endpoint_host)
    endpoint_network = f"{endpoint_host}/{endpoint_address.max_prefixlen}"
    policy = PathProbePolicy(
        approved_networks=(endpoint_network, "10.77.0.0/24"),
        approved_ports=(endpoint_port, request.target_port),
    )
    probe = selected_runtime.probe_factory(policy, guarded_target)
    try:
        evidence = await probe.probe(
            network_id=NetworkId.new(),
            node_id=NodeId.new(),
            plan_hash=canonical_sha256({"acceptance": request.code_sha}),
            authorization_revision=1,
            revision=1,
            candidates=(candidate,),
            expected_host_route=target_route,
            target_host=request.target_host,
            target_port=request.target_port,
            now=now,
        )
    except NetworkChangedError:
        failed = _finish_failure(report, clock, "network_state_changed")
        failed["probe_executed"] = True
        failed["after"] = connect_guard_summary
        failed["network_state_unchanged"] = False
        return failed

    after, _ = await _summary(
        selected_runtime,
        request.interface_name,
        peer_public_key=peer_public_key,
        expected_host_route=target_route,
    )
    unchanged = after["summary_hash"] == before["summary_hash"]
    error = evidence.stable_error_code.value if evidence.stable_error_code is not None else None
    final_error = "network_state_changed" if not unchanged else error
    report.update(
        {
            "after": after,
            "network_state_unchanged": unchanged,
            "probe_executed": True,
            "target_probe_executed": target_called,
            "path_evidence": {
                "verified": bool(evidence.verified and unchanged),
                "stable_error_code": final_error,
                "source_hash": canonical_sha256({"source": evidence.source}),
                "candidate_count": evidence.candidate_count,
                "endpoint_probe_succeeded": evidence.endpoint_probe_succeeded,
                "handshake_fresh": evidence.handshake_fresh,
                "host_route_present": evidence.host_route_present,
                "target_probe_succeeded": evidence.target_probe_succeeded,
                "observed_at": evidence.observed_at.isoformat(),
                "expires_at": evidence.expires_at.isoformat(),
            },
            "stable_error_code": final_error,
            "passed": unchanged and evidence.verified,
            "finished_at": clock().astimezone(UTC).isoformat(),
        }
    )
    return report


def _finish_failure(
    report: dict[str, object], clock: Callable[[], datetime], error: str
) -> dict[str, object]:
    report.update(
        {
            "passed": False,
            "probe_executed": False,
            "target_probe_executed": False,
            "stable_error_code": error,
            "finished_at": clock().astimezone(UTC).isoformat(),
        }
    )
    return report


def _validate_request(request: AcceptanceRequest) -> None:
    if request.platform not in {"windows", "macos"}:
        raise ValueError("platform_rejected")
    interface_pattern = _WINDOWS_INTERFACE if request.platform == "windows" else _MACOS_INTERFACE
    if interface_pattern.fullmatch(request.interface_name) is None:
        raise ValueError("interface_rejected")
    if request.peer_public_key is None:
        if request.approved_candidate_hash is None:
            raise ValueError("peer_key_rejected")
    elif not request.peer_public_key or len(request.peer_public_key) > 128:
        raise ValueError("peer_key_rejected")
    if _CODE_SHA.fullmatch(request.code_sha) is None:
        raise ValueError("code_sha_rejected")
    if request.approved_candidate_hash is not None:
        if _SHA256.fullmatch(request.approved_candidate_hash) is None:
            raise ValueError("candidate_approval_rejected")
        if request.target_host not in TARGET_HOSTS:
            raise ValueError("target_host_rejected")
        if request.target_port is None or not 1 <= request.target_port <= 65535:
            raise ValueError("target_port_rejected")


def dry_run_report() -> dict[str, object]:
    return {
        "schema_version": SCHEMA_VERSION,
        "dry_run": True,
        "probe_executed": False,
        "writes_performed": False,
        "stable_error_code": "platform_and_candidate_approval_required",
    }


def _evidence_path(platform: str) -> Path:
    root = Path(__file__).resolve().parents[1] / "evaluations" / "platform"
    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    return root / f"managed-path-readonly-{platform}-{timestamp}.json"


def _default_git_runner(command: tuple[str, ...]) -> tuple[int, str, str]:
    if type(command) is not tuple or command not in _GIT_COMMANDS:
        raise ValueError("git_command_rejected")
    git_path = _trusted_git_path()
    environment = {
        key: value for key, value in os.environ.items() if not key.upper().startswith("GIT_")
    }
    environment["GIT_OPTIONAL_LOCKS"] = "0"
    try:
        completed = subprocess.run(
            (str(git_path), *_GIT_FIXED_ARGS, *command),
            cwd=Path(__file__).resolve().parents[1],
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=environment,
            shell=False,
            timeout=5,
        )
    except subprocess.TimeoutExpired as exc:
        raise ValueError("git_timeout") from exc
    except OSError as exc:
        raise ValueError("git_tool_unavailable") from exc
    return completed.returncode, completed.stdout, completed.stderr


def _trusted_git_path() -> Path:
    candidates = _WINDOWS_GIT_CANDIDATES if os.name == "nt" else _MACOS_GIT_CANDIDATES
    return _select_trusted_git_path(candidates, _verify_git_path)


def _select_trusted_git_path(
    candidates: tuple[Path, ...], verifier: Callable[[Path], None]
) -> Path:
    for candidate in candidates:
        try:
            verifier(candidate)
        except (OSError, ValueError):
            continue
        return candidate
    raise ValueError("git_tool_untrusted_or_unavailable")


def _verify_git_path(path: Path) -> None:
    if not path.is_absolute():
        raise ValueError("git_tool_path_rejected")
    try:
        _verify_path_node(path, expect_file=True, strict_write=True)
        strict_parents = {path.parent, path.parent.parent}
        for parent in path.parents:
            _verify_path_node(
                parent,
                expect_file=False,
                strict_write=parent in strict_parents,
            )
    except OSError as exc:
        raise ValueError("git_tool_unavailable") from exc


def _verify_path_node(path: Path, *, expect_file: bool, strict_write: bool = True) -> None:
    info = os.lstat(path)
    if path.is_symlink():
        raise ValueError("git_tool_symlink")
    attributes = getattr(info, "st_file_attributes", 0)
    if attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400):
        raise ValueError("git_tool_reparse")
    if expect_file:
        if not stat.S_ISREG(info.st_mode):
            raise ValueError("git_tool_not_regular")
    elif not stat.S_ISDIR(info.st_mode):
        raise ValueError("git_tool_parent_rejected")
    if os.name == "nt":
        _verify_windows_security(path, strict_write=strict_write)
    elif sys.platform == "darwin":
        _verify_macos_security(path, info)
    else:
        raise ValueError("git_tool_platform_unsupported")


def _verify_macos_security(path: Path, info: os.stat_result) -> None:
    if info.st_uid != 0 or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise ValueError("git_tool_acl_untrusted")
    try:
        listing = subprocess.run(
            ("/bin/ls", "-lde", str(path)),
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            shell=False,
            timeout=2,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ValueError("git_tool_security_unavailable") from exc
    if listing.returncode != 0 or not listing.stdout.splitlines():
        raise ValueError("git_tool_security_unavailable")
    permissions = listing.stdout.splitlines()[0].split(maxsplit=1)[0]
    if permissions.endswith("+"):
        raise ValueError("git_tool_acl_untrusted")


def _verify_windows_security(path: Path, *, strict_write: bool = True) -> None:
    if os.name != "nt":
        raise ValueError("git_tool_platform_unsupported")
    descriptor = ctypes.c_void_p()
    kernel32: Any = None
    try:
        advapi = ctypes.WinDLL("advapi32", use_last_error=True)
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        owner = ctypes.c_void_p()
        dacl = ctypes.c_void_p()
        get_security = advapi.GetNamedSecurityInfoW
        get_security.argtypes = [
            ctypes.c_wchar_p,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_void_p),
        ]
        get_security.restype = ctypes.c_uint32
        result = get_security(
            str(path),
            1,
            0x00000001 | 0x00000004,
            ctypes.byref(owner),
            None,
            ctypes.byref(dacl),
            None,
            ctypes.byref(descriptor),
        )
        if result != 0 or not owner.value or not dacl.value:
            raise ValueError("git_tool_acl_untrusted")
        sid_text = _windows_sid_text(advapi, owner)
        if not _trusted_windows_sid(sid_text):
            raise ValueError("git_tool_owner_untrusted")
        write_mask = _WINDOWS_WRITE_MASK if strict_write else _WINDOWS_REPLACE_COMPONENT_MASK
        _verify_windows_dacl(advapi, dacl, write_mask=write_mask)
    except ValueError:
        raise
    except (AttributeError, OSError, TypeError) as exc:
        raise ValueError("git_tool_security_unavailable") from exc
    finally:
        if kernel32 is not None and descriptor.value:
            local_free = kernel32.LocalFree
            local_free.argtypes = [ctypes.c_void_p]
            local_free.restype = ctypes.c_void_p
            local_free(descriptor)


def _windows_sid_text(advapi: object, sid: ctypes.c_void_p) -> str:
    convert = cast(Any, advapi).ConvertSidToStringSidW
    convert.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_wchar_p)]
    convert.restype = ctypes.c_int
    text_pointer = ctypes.c_wchar_p()
    if not convert(sid, ctypes.byref(text_pointer)) or not text_pointer.value:
        raise ValueError("git_tool_owner_untrusted")
    try:
        return text_pointer.value
    finally:
        local_free = ctypes.WinDLL("kernel32", use_last_error=True).LocalFree
        local_free.argtypes = [ctypes.c_void_p]
        local_free.restype = ctypes.c_void_p
        local_free(ctypes.cast(text_pointer, ctypes.c_void_p))


def _trusted_windows_sid(sid_text: str) -> bool:
    return sid_text in _TRUSTED_WINDOWS_SID_EXACT or sid_text.startswith(
        _TRUSTED_WINDOWS_SERVICE_SID_PREFIX
    )


def _windows_untrusted_write_granted(
    entries: Sequence[tuple[int, int, str]], write_mask: int
) -> bool:
    """按 ACL 顺序合并显式拒绝/允许，仅按同一 SID 的先置拒绝判断。"""
    denied_by_sid: dict[str, int] = {}
    allowed_by_sid: dict[str, int] = {}
    for ace_type, mask, sid_text in entries:
        relevant = mask & write_mask
        if not relevant:
            continue
        if ace_type == 1:
            denied_by_sid[sid_text] = denied_by_sid.get(sid_text, 0) | relevant
            continue
        if _trusted_windows_sid(sid_text):
            continue
        blocked = denied_by_sid.get(sid_text, 0)
        allowed_by_sid[sid_text] = allowed_by_sid.get(sid_text, 0) | (relevant & ~blocked)
    return any(allowed_by_sid.values())


def _verify_windows_dacl(
    advapi: object,
    dacl: ctypes.c_void_p,
    *,
    write_mask: int = _WINDOWS_WRITE_MASK,
) -> None:
    class Acl(ctypes.Structure):
        _fields_ = [
            ("revision", ctypes.c_ubyte),
            ("sbz1", ctypes.c_ubyte),
            ("size", ctypes.c_ushort),
            ("ace_count", ctypes.c_ushort),
            ("sbz2", ctypes.c_ushort),
        ]

    class AceHeader(ctypes.Structure):
        _fields_ = [
            ("ace_type", ctypes.c_ubyte),
            ("ace_flags", ctypes.c_ubyte),
            ("ace_size", ctypes.c_ushort),
        ]

    acl = ctypes.cast(dacl, ctypes.POINTER(Acl)).contents
    get_ace = cast(Any, advapi).GetAce
    get_ace.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.POINTER(ctypes.c_void_p)]
    get_ace.restype = ctypes.c_int
    entries: list[tuple[int, int, str]] = []
    for index in range(acl.ace_count):
        ace = ctypes.c_void_p()
        if not get_ace(dacl, index, ctypes.byref(ace)) or not ace.value:
            raise ValueError("git_tool_acl_untrusted")
        header = ctypes.cast(ace, ctypes.POINTER(AceHeader)).contents
        if header.ace_type not in (0, 1):
            raise ValueError("git_tool_acl_untrusted")
        if header.ace_flags & 0x08:
            continue
        if header.ace_size < ctypes.sizeof(AceHeader) + 4:
            raise ValueError("git_tool_acl_untrusted")
        mask = ctypes.c_uint32.from_address(ace.value + ctypes.sizeof(AceHeader)).value
        relevant = mask & write_mask
        if not relevant:
            continue
        sid = ctypes.c_void_p(ace.value + ctypes.sizeof(AceHeader) + 4)
        sid_text = _windows_sid_text(advapi, sid)
        entries.append((header.ace_type, mask, sid_text))
    if _windows_untrusted_write_granted(entries, write_mask):
        raise ValueError("git_tool_acl_untrusted")


def _trusted_checkout_revision(
    evidence_path: Path,
    *,
    git_runner: GitRunner | None = None,
) -> str:
    """读取可信 checkout 的 HEAD，并拒绝除指定新 evidence 外的预存修改。"""
    root = Path(__file__).resolve().parents[1]
    output = evidence_path.resolve()
    try:
        relative_output = output.relative_to(root).as_posix()
    except ValueError as exc:
        raise ValueError("evidence_path_rejected") from exc
    if output.exists():
        raise ValueError("evidence_path_preexisting")
    run_git = git_runner or _default_git_runner
    top_returncode, top_stdout, _ = run_git(("rev-parse", "--show-toplevel"))
    if top_returncode != 0 or Path(top_stdout.strip()).resolve() != root:
        raise ValueError("trusted_checkout_unavailable")
    status_returncode, status_stdout, _ = run_git(
        ("status", "--porcelain=v1", "--untracked-files=all")
    )
    if status_returncode != 0:
        raise ValueError("trusted_checkout_unavailable")
    for line in status_stdout.splitlines():
        if not line:
            continue
        status = line[:2]
        path = line[3:] if len(line) >= 4 else ""
        if status == "??" and path == relative_output:
            continue
        raise ValueError("checkout_dirty")
    head_returncode, head_stdout, _ = run_git(("rev-parse", "--verify", "HEAD"))
    revision = head_stdout.strip()
    if head_returncode != 0 or _CODE_SHA.fullmatch(revision) is None:
        raise ValueError("trusted_checkout_unavailable")
    return revision


def _write_report(
    report: dict[str, object], platform: str | None, output_path: Path | None = None
) -> Path | None:
    if platform is None:
        return None
    output = output_path or _evidence_path(platform)
    trusted_revision = _trusted_checkout_revision(output)
    _validate_report_code_sha(report.get("code_sha"), trusted_revision)
    try:
        with output.open("x", encoding="utf-8") as handle:
            json.dump(report, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
    except FileExistsError as exc:
        raise ValueError("evidence_path_preexisting") from exc
    return output


def _validate_report_code_sha(report_code_sha: object, trusted_revision: str) -> None:
    if report_code_sha != trusted_revision:
        raise ValueError("code_sha_mismatch")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--platform", choices=("windows", "macos"))
    parser.add_argument("--interface")
    parser.add_argument("--code-sha")
    parser.add_argument("--approve-candidate")
    parser.add_argument("--target-host", choices=tuple(sorted(TARGET_HOSTS)))
    parser.add_argument("--target-port", type=int)
    args = parser.parse_args(argv)
    output_path: Path | None = None
    if args.platform is None:
        report: dict[str, object] = dry_run_report()
    else:
        if args.interface is None or args.code_sha is None:
            parser.error("指定平台时必须提供 --interface 和 --code-sha")
        interactive_peer_required = args.approve_candidate is None
        if interactive_peer_required and not sys.stdin.isatty():
            report = {
                "schema_version": SCHEMA_VERSION,
                "code_sha": args.code_sha,
                "platform_code": args.platform,
                "passed": False,
                "probe_executed": False,
                "writes_performed": False,
                "stable_error_code": "interactive_terminal_required",
                "finished_at": datetime.now(UTC).isoformat(),
            }
            print(json.dumps(report, ensure_ascii=False, indent=2))
            return 1
        output_path = _evidence_path(args.platform)
        try:
            trusted_revision = _trusted_checkout_revision(output_path)
        except Exception as exc:
            report = {
                "schema_version": SCHEMA_VERSION,
                "code_sha": args.code_sha,
                "platform_code": args.platform,
                "passed": False,
                "probe_executed": False,
                "writes_performed": False,
                "stable_error_code": _stable_error_code_from_exception(exc),
                "finished_at": datetime.now(UTC).isoformat(),
            }
            print(json.dumps(report, ensure_ascii=False, indent=2))
            return 1
        if args.code_sha != trusted_revision:
            report = {
                "schema_version": SCHEMA_VERSION,
                "platform_code": args.platform,
                "passed": False,
                "probe_executed": False,
                "writes_performed": False,
                "stable_error_code": "code_sha_mismatch",
                "finished_at": datetime.now(UTC).isoformat(),
            }
            print(json.dumps(report, ensure_ascii=False, indent=2))
            return 1
        peer_public_key = (
            getpass.getpass("Peer public key（不会回显或保存）: ")
            if interactive_peer_required
            else None
        )
        try:
            report = asyncio.run(
                run_acceptance(
                    AcceptanceRequest(
                        platform=args.platform,
                        interface_name=args.interface,
                        peer_public_key=peer_public_key,
                        code_sha=trusted_revision,
                        approved_candidate_hash=args.approve_candidate,
                        target_host=args.target_host,
                        target_port=args.target_port,
                    )
                )
            )
        except Exception as exc:
            report = {
                "schema_version": SCHEMA_VERSION,
                "code_sha": args.code_sha,
                "platform_code": args.platform,
                "passed": False,
                "probe_executed": False,
                "writes_performed": False,
                "stable_error_code": _stable_error_code_from_exception(exc),
                "finished_at": datetime.now(UTC).isoformat(),
            }
    try:
        _write_report(report, args.platform, output_path if args.platform is not None else None)
    except Exception as exc:
        report.update(
            {
                "passed": False,
                "stable_error_code": _stable_error_code_from_exception(exc),
                "finished_at": datetime.now(UTC).isoformat(),
            }
        )
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if bool(report.get("passed", False)) or args.platform is None else 1


if __name__ == "__main__":
    raise SystemExit(main())
