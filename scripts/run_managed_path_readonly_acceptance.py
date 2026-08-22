"""人工启动的 Windows/macOS managed path 管理员只读验收包装器。"""

from __future__ import annotations

import argparse
import asyncio
import getpass
import ipaddress
import json
import os
import re
import sys
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Protocol, cast

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
RESERVED_TARGET_PORTS = frozenset(range(18880, 18900))
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_CODE_SHA = re.compile(r"^[0-9a-f]{40}$")
_WINDOWS_INTERFACE = re.compile(r"^[A-Za-z0-9_. -]{1,64}$")
_MACOS_INTERFACE = re.compile(r"^(?:utun[0-9]+|tmn-[a-z0-9-]{1,48})$")


class NetworkChangedError(RuntimeError):
    """前后只读摘要不一致；异常正文固定且不携带原始事实。"""


class Observer(Protocol):
    async def observe(self, interface_name: str) -> WindowsTunnelSnapshot: ...


Executor = Callable[[tuple[str, ...], float], Awaitable[CommandResult]]


@dataclass(frozen=True)
class AcceptanceRequest:
    platform: str
    interface_name: str
    peer_public_key: str
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
            peer_public_key=request.peer_public_key,
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
            peer_public_key=request.peer_public_key,
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
    runtime: PlatformRuntime, interface_name: str
) -> tuple[dict[str, object], WindowsTunnelSnapshot]:
    snapshot = await runtime.observer.observe(interface_name)
    route_hash, route_returncode = await runtime.route_summary()
    value: dict[str, object] = {
        "summary_hash": canonical_sha256(
            {
                "system_fingerprint": snapshot.system_fingerprint,
                "route_hash": route_hash,
                "route_returncode": route_returncode,
                "observed_error_code": snapshot.observed_error_code,
            }
        ),
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
    return value, snapshot


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
    selected_runtime = runtime or (
        _windows_runtime(request, executor)
        if request.platform == "windows"
        else _macos_runtime(request, executor)
    )
    report = _base_report(request, started_at)
    if not selected_runtime.elevated:
        report.update(
            {
                "passed": False,
                "preflight": {"elevated": False, "stable_error_code": "permission_denied"},
                "finished_at": clock().astimezone(UTC).isoformat(),
            }
        )
        return report

    before, snapshot = await _summary(selected_runtime, request.interface_name)
    discovered = _candidate(snapshot, request.peer_public_key)
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

    guarded, _ = await _summary(selected_runtime, request.interface_name)
    if guarded["summary_hash"] != before["summary_hash"]:
        report["after"] = guarded
        report["network_state_unchanged"] = False
        return _finish_failure(report, clock, "network_state_changed")

    target_called = False
    connect_guard_summary: dict[str, object] | None = None

    async def guarded_target(host: str, port: int, timeout_seconds: float) -> bool:
        nonlocal connect_guard_summary, target_called
        immediate, _ = await _summary(selected_runtime, request.interface_name)
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
            expected_host_route=f"{request.target_host}/32",
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

    after, _ = await _summary(selected_runtime, request.interface_name)
    unchanged = after["summary_hash"] == before["summary_hash"]
    error = evidence.stable_error_code.value if evidence.stable_error_code is not None else None
    report.update(
        {
            "after": after,
            "network_state_unchanged": unchanged,
            "probe_executed": True,
            "target_probe_executed": target_called,
            "path_evidence": {
                "verified": evidence.verified,
                "stable_error_code": error,
                "source_hash": canonical_sha256({"source": evidence.source}),
                "candidate_count": evidence.candidate_count,
                "endpoint_probe_succeeded": evidence.endpoint_probe_succeeded,
                "handshake_fresh": evidence.handshake_fresh,
                "host_route_present": evidence.host_route_present,
                "target_probe_succeeded": evidence.target_probe_succeeded,
                "observed_at": evidence.observed_at.isoformat(),
                "expires_at": evidence.expires_at.isoformat(),
            },
            "stable_error_code": error if unchanged else "network_state_changed",
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
    if not request.peer_public_key or len(request.peer_public_key) > 128:
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


def _write_report(report: dict[str, object], platform: str | None) -> Path | None:
    if platform is None:
        return None
    root = Path(__file__).resolve().parents[1] / "evaluations" / "platform"
    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    output = root / f"managed-path-readonly-{platform}-{timestamp}.json"
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return output


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--platform", choices=("windows", "macos"))
    parser.add_argument("--interface")
    parser.add_argument("--code-sha")
    parser.add_argument("--approve-candidate")
    parser.add_argument("--target-host", choices=tuple(sorted(TARGET_HOSTS)))
    parser.add_argument("--target-port", type=int)
    args = parser.parse_args(argv)
    if args.platform is None:
        report: dict[str, object] = dry_run_report()
    else:
        if args.interface is None or args.code_sha is None:
            parser.error("指定平台时必须提供 --interface 和 --code-sha")
        if not sys.stdin.isatty():
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
            _write_report(report, args.platform)
            print(json.dumps(report, ensure_ascii=False, indent=2))
            return 1
        peer_public_key = getpass.getpass("Peer public key（不会回显或保存）: ")
        try:
            report = asyncio.run(
                run_acceptance(
                    AcceptanceRequest(
                        platform=args.platform,
                        interface_name=args.interface,
                        peer_public_key=peer_public_key,
                        code_sha=args.code_sha,
                        approved_candidate_hash=args.approve_candidate,
                        target_host=args.target_host,
                        target_port=args.target_port,
                    )
                )
            )
        except Exception:
            report = {
                "schema_version": SCHEMA_VERSION,
                "code_sha": args.code_sha,
                "platform_code": args.platform,
                "passed": False,
                "probe_executed": False,
                "writes_performed": False,
                "stable_error_code": "acceptance_preflight_failed",
                "finished_at": datetime.now(UTC).isoformat(),
            }
    _write_report(report, args.platform)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if bool(report.get("passed", False)) or args.platform is None else 1


if __name__ == "__main__":
    raise SystemExit(main())
