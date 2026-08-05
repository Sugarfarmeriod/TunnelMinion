"""进程专属 socket 与固定参数 lsof 的无 shell 归属探针 spike。"""

from __future__ import annotations

import socket
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, cast

import psutil


class OwnershipVerdict(StrEnum):
    """监听器归属结论；不把端口存在降级成成功。"""

    OWNED = "owned"
    MISSING = "missing"
    CONFLICT = "ownership_conflict"
    UNVERIFIED = "listener_ownership_unverified"


@dataclass(frozen=True)
class ListenerTarget:
    """待验证的私有监听地址。"""

    host: str
    port: int

    def __post_init__(self) -> None:
        if not self.host or not 1 <= self.port <= 65535:
            raise ValueError("监听地址或端口无效")


@dataclass(frozen=True)
class ListenerEndpoint:
    """从进程 socket 或 lsof 输出清洗出的监听端点。"""

    host: str
    port: int
    pid: int


@dataclass(frozen=True)
class ProcessSocketProbeResult:
    """进程专属 socket API 的脱敏结果。"""

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


def inspect_process_sockets(
    pid: int,
    *,
    process_factory: ProcessFactory | None = None,
) -> ProcessSocketProbeResult:
    """读取当前账户可见的进程 socket；权限或 API 失败只返回稳定错误码。"""
    if pid <= 0:
        raise ValueError("PID 必须为正数")
    factory = process_factory or cast(ProcessFactory, psutil.Process)
    try:
        connections = factory(pid).net_connections(kind="inet")
    except psutil.AccessDenied:
        return ProcessSocketProbeResult(False, error_code="permission_denied")
    except psutil.NoSuchProcess:
        return ProcessSocketProbeResult(False, error_code="process_missing")
    except OSError:
        return ProcessSocketProbeResult(False, error_code="socket_probe_failed")

    endpoints: list[ListenerEndpoint] = []
    for connection in connections:
        local = _address(getattr(connection, "laddr", None))
        if local is None:
            continue
        status = getattr(connection, "status", None)
        connection_type = getattr(connection, "type", None)
        if connection_type == socket.SOCK_STREAM and status != psutil.CONN_LISTEN:
            continue
        endpoints.append(ListenerEndpoint(local[0], local[1], pid))
    return ProcessSocketProbeResult(True, tuple(endpoints))


def fixed_lsof_command(lsof_path: str, pid: int, target: ListenerTarget) -> tuple[str, ...]:
    """构造固定参数、无 shell 的 macOS lsof 降级命令。"""
    if not lsof_path or pid <= 0:
        raise ValueError("lsof 路径或 PID 无效")
    return (
        lsof_path,
        "-nP",
        "-a",
        "-p",
        str(pid),
        f"-iTCP@{target.host}:{target.port}",
        "-sTCP:LISTEN",
    )


def parse_lsof_listener_output(
    stdout: str,
    *,
    expected_pid: int,
) -> tuple[ListenerEndpoint, ...]:
    """仅解析固定 lsof 输出中的 TCP LISTEN 记录，不保留正文或错误信息。"""
    if expected_pid <= 0:
        raise ValueError("PID 必须为正数")
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


def classify_listener_ownership(
    *,
    expected_pid: int,
    target: ListenerTarget,
    process_result: ProcessSocketProbeResult,
    fallback_endpoints: tuple[ListenerEndpoint, ...] = (),
) -> OwnershipVerdict:
    """按 PID、地址和端口判断归属；无法证明时 fail closed。"""
    if expected_pid <= 0:
        raise ValueError("PID 必须为正数")
    endpoints = process_result.endpoints if process_result.available else fallback_endpoints
    if not process_result.available and not fallback_endpoints:
        return OwnershipVerdict.UNVERIFIED
    matches = [
        endpoint
        for endpoint in endpoints
        if endpoint.host in {target.host, "0.0.0.0", "::"} and endpoint.port == target.port
    ]
    if any(endpoint.pid != expected_pid for endpoint in matches):
        return OwnershipVerdict.CONFLICT
    if any(endpoint.pid == expected_pid for endpoint in matches):
        return OwnershipVerdict.OWNED
    return OwnershipVerdict.MISSING
