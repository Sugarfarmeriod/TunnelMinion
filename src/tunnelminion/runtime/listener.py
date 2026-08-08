"""Gateway 监听器归属的跨平台只读探针。"""

from __future__ import annotations

import shutil
import subprocess
import sys
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, cast

import psutil

from tunnelminion.gateway.configuration import FileGatewayConfigurationRepository
from tunnelminion.runtime.lifecycle import ReadinessResult
from tunnelminion.runtime.profile import RuntimeComponent


@dataclass(frozen=True)
class ListenerTarget:
    """Gateway 配置中的监听地址。"""

    host: str
    port: int


@dataclass(frozen=True)
class ListenerEndpoint:
    """进程 socket 或固定 lsof 输出中的脱敏端点。"""

    host: str
    port: int
    pid: int


@dataclass(frozen=True)
class ProcessSocketResult:
    """进程专属 socket 查询结果。"""

    available: bool
    endpoints: tuple[ListenerEndpoint, ...] = ()
    error_code: str | None = None


class ProcessSocketReader(Protocol):
    """psutil.Process 的最小只读接口。"""

    def net_connections(self, kind: str = "inet") -> Iterable[object]: ...


ProcessFactory = Callable[[int], ProcessSocketReader]


def _address(value: object) -> tuple[str, int] | None:
    host = getattr(value, "ip", None)
    port = getattr(value, "port", None)
    if isinstance(host, str) and isinstance(port, int):
        return host, port
    if isinstance(value, tuple):
        raw_value = cast(tuple[object, ...], value)
        if len(raw_value) < 2:
            return None
        raw_host, raw_port = raw_value[0], raw_value[1]
        if isinstance(raw_host, str) and isinstance(raw_port, int):
            return raw_host, raw_port
    return None


def _inspect_process_sockets(
    pid: int,
    *,
    process_factory: ProcessFactory,
) -> ProcessSocketResult:
    try:
        connections = process_factory(pid).net_connections(kind="inet")
    except psutil.AccessDenied:
        return ProcessSocketResult(False, error_code="permission_denied")
    except psutil.NoSuchProcess:
        return ProcessSocketResult(False, error_code="process_missing")
    except OSError:
        return ProcessSocketResult(False, error_code="socket_probe_failed")

    endpoints: list[ListenerEndpoint] = []
    for connection in connections:
        local = _address(getattr(connection, "laddr", None))
        if local is None:
            continue
        status = getattr(connection, "status", None)
        connection_type = getattr(connection, "type", None)
        if connection_type == 1 and status != psutil.CONN_LISTEN:
            continue
        endpoints.append(ListenerEndpoint(local[0], local[1], pid))
    return ProcessSocketResult(True, tuple(endpoints))


def _lsof_command(path: str, pid: int, target: ListenerTarget) -> tuple[str, ...]:
    return (
        path,
        "-nP",
        "-a",
        "-p",
        str(pid),
        f"-iTCP@{target.host}:{target.port}",
        "-sTCP:LISTEN",
    )


def _parse_lsof(stdout: str, expected_pid: int) -> tuple[ListenerEndpoint, ...]:
    endpoints: set[ListenerEndpoint] = set()
    for line in stdout.splitlines()[1:]:
        columns = line.split()
        if len(columns) < 4 or "TCP" not in columns or "(LISTEN)" not in columns:
            continue
        try:
            pid = int(columns[1])
        except ValueError:
            continue
        if pid != expected_pid:
            continue
        protocol_index = columns.index("TCP")
        if protocol_index + 1 >= len(columns):
            continue
        endpoint = columns[protocol_index + 1]
        if ":" not in endpoint:
            continue
        host, raw_port = endpoint.rsplit(":", 1)
        try:
            port = int(raw_port)
        except ValueError:
            continue
        endpoints.add(ListenerEndpoint(host.strip("[]"), port, pid))
    return tuple(sorted(endpoints, key=lambda item: (item.port, item.host, item.pid)))


def _matches(endpoint: ListenerEndpoint, target: ListenerTarget) -> bool:
    return endpoint.port == target.port and endpoint.host in {
        target.host,
        "0.0.0.0",
        "::",
    }


def _runtime_child_pids(pid: int, component: RuntimeComponent) -> tuple[int, ...]:
    """兼容 Windows Python 启动 shim，限定在同一受管 runtime 子树内。"""
    try:
        children = psutil.Process(pid).children(recursive=True)
    except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
        return ()
    values: list[int] = []
    for child in children:
        try:
            command_line = child.cmdline()
        except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
            continue
        if (
            "runtime-child" in command_line
            and f"--runtime-component={component.value}" in command_line
        ):
            values.append(child.pid)
    return tuple(values)


class GatewayListenerOwnershipProbe:
    """验证 Gateway 进程拥有配置监听器，不发起 HTTP 或读取 token。"""

    def __init__(
        self,
        data_dir: Path,
        *,
        process_factory: ProcessFactory | None = None,
        lsof_path: str | None = None,
        command_runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
    ) -> None:
        self._data_dir = data_dir
        self._process_factory = process_factory or cast(ProcessFactory, psutil.Process)
        self._lsof_path = lsof_path or shutil.which("lsof") or "/usr/sbin/lsof"
        self._command_runner = command_runner

    def readiness(
        self,
        component: RuntimeComponent,
        pid: int,
        timeout_seconds: float,
    ) -> ReadinessResult:
        if component is not RuntimeComponent.GATEWAY:
            return ReadinessResult(False, "listener_probe_wrong_component")
        target = self._target()
        if target is None:
            return ReadinessResult(False, "gateway_unconfigured")
        process_result = _inspect_process_sockets(
            pid,
            process_factory=self._process_factory,
        )
        endpoints = process_result.endpoints
        if process_result.available and not any(
            _matches(endpoint, target) for endpoint in endpoints
        ):
            for child_pid in _runtime_child_pids(pid, RuntimeComponent.GATEWAY):
                child_result = _inspect_process_sockets(
                    child_pid,
                    process_factory=self._process_factory,
                )
                endpoints += tuple(
                    ListenerEndpoint(endpoint.host, endpoint.port, pid)
                    for endpoint in child_result.endpoints
                )
        if (
            not process_result.available
            and process_result.error_code != "process_missing"
            and sys.platform == "darwin"
        ):
            endpoints = self._lsof_endpoints(pid, target, timeout_seconds)
        if not process_result.available and not endpoints:
            return ReadinessResult(
                False,
                "listener_ownership_unverified"
                if process_result.error_code != "process_missing"
                else "process_missing",
            )
        if any(endpoint.pid != pid and _matches(endpoint, target) for endpoint in endpoints):
            return ReadinessResult(False, "ownership_conflict")
        if any(endpoint.pid == pid and _matches(endpoint, target) for endpoint in endpoints):
            return ReadinessResult(True)
        return ReadinessResult(False, "listener_missing")

    def healthy(self, component: RuntimeComponent, pid: int) -> bool:
        return self.readiness(component, pid, 0.5).ready

    def _target(self) -> ListenerTarget | None:
        try:
            config = FileGatewayConfigurationRepository(self._data_dir / "gateway.json").load()
        except (OSError, ValueError):
            return None
        if config is None:
            return None
        return ListenerTarget(config.bind.host, config.bind.port)

    def _lsof_endpoints(
        self,
        pid: int,
        target: ListenerTarget,
        timeout_seconds: float,
    ) -> tuple[ListenerEndpoint, ...]:
        try:
            completed = self._command_runner(
                _lsof_command(self._lsof_path, pid, target),
                check=False,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=max(0.01, timeout_seconds),
            )
        except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
            return ()
        if completed.returncode not in {0, 1}:
            return ()
        return _parse_lsof(completed.stdout, pid)
