"""Windows psutil 与固定子进程查询测试。"""

from __future__ import annotations

import asyncio
import socket
import sys
from types import SimpleNamespace
from typing import Any, NamedTuple

import psutil
import pytest

from tunnelminion.platforms.windows.system import (
    PsutilSystemReader,
    SubprocessCommandRunner,
    default_docker_path,
    default_wg_path,
)


def test_subprocess_runner_and_default_paths() -> None:
    result = asyncio.run(
        SubprocessCommandRunner().run((sys.executable, "-c", "print('ready')"), timeout_seconds=5)
    )
    assert result.returncode == 0
    assert result.stdout.strip() == "ready"
    assert default_wg_path().replace("\\", "/").endswith("WireGuard/wg.exe")
    assert default_docker_path().replace("\\", "/").endswith("bin/docker.exe")


def test_interface_reader_handles_missing_and_ipv6_scope(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reader = PsutilSystemReader()

    def empty_stats() -> dict[str, Any]:
        return {}

    monkeypatch.setattr(psutil, "net_if_stats", empty_stats)
    assert reader.interface("HomeMac") is None

    stat = SimpleNamespace(isup=True)

    class Address(NamedTuple):
        family: socket.AddressFamily
        address: str

    def stats() -> dict[str, Any]:
        return {"HomeMac": stat}

    def addresses() -> dict[str, list[Address]]:
        return {
            "HomeMac": [
                Address(socket.AF_INET, "10.77.0.2"),
                Address(socket.AF_INET6, "fd00::2%52"),
                Address(socket.AF_LINK, "ignored"),
            ]
        }

    monkeypatch.setattr(psutil, "net_if_stats", stats)
    monkeypatch.setattr(psutil, "net_if_addrs", addresses)
    value = reader.interface("HomeMac")
    assert value is not None
    assert value.addresses == ("10.77.0.2", "fd00::2")


def test_listener_reader_filters_and_degrades_process_names(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Address(NamedTuple):
        ip: str
        port: int

    class Connection(NamedTuple):
        type: socket.SocketKind
        status: str
        laddr: Address | None
        pid: int | None

    values = [
        Connection(socket.SOCK_STREAM, "ESTABLISHED", Address("1.1.1.1", 1), 1),
        Connection(socket.SOCK_STREAM, psutil.CONN_LISTEN, None, 2),
        Connection(socket.SOCK_STREAM, psutil.CONN_LISTEN, Address("127.0.0.1", 90), 3),
        Connection(socket.SOCK_DGRAM, "NONE", Address("0.0.0.0", 53), 4),
        Connection(socket.SOCK_DGRAM, "NONE", Address("0.0.0.0", 54), None),
    ]

    def connections(kind: str) -> list[Connection]:
        assert kind == "inet"
        return values

    monkeypatch.setattr(psutil, "net_connections", connections)

    class Process:
        def __init__(self, pid: int) -> None:
            self._pid = pid

        def name(self) -> str:
            if self._pid == 4:
                raise psutil.AccessDenied(self._pid)
            return "server"

    monkeypatch.setattr(psutil, "Process", Process)
    listeners = PsutilSystemReader().listeners()
    assert [(item.port, item.process_name) for item in listeners] == [
        (53, None),
        (54, None),
        (90, "server"),
    ]

    def denied_connections(kind: str) -> list[Connection]:
        assert kind == "inet"
        raise psutil.AccessDenied(1)

    monkeypatch.setattr(psutil, "net_connections", denied_connections)
    with pytest.raises(PermissionError, match="无法枚举"):
        PsutilSystemReader().listeners()


def test_process_reader_sorts_limits_and_skips_denied(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Process:
        def __init__(self, info: dict[str, object] | None, denied: bool = False) -> None:
            self._info = info
            self._denied = denied

        @property
        def info(self) -> dict[str, object]:
            if self._denied:
                raise psutil.NoSuchProcess(999)
            assert self._info is not None
            return self._info

    memory = SimpleNamespace(rss=200)
    processes = [
        Process(
            {"pid": 1, "name": "small", "status": None, "memory_info": None, "num_threads": None}
        ),
        Process(
            {
                "pid": 2,
                "name": "large",
                "status": "running",
                "memory_info": memory,
                "num_threads": 4,
            }
        ),
        Process(None, denied=True),
    ]

    def process_iter(attrs: tuple[str, ...]) -> list[Process]:
        assert "pid" in attrs
        return processes

    monkeypatch.setattr(psutil, "process_iter", process_iter)
    values = PsutilSystemReader().processes(1)
    assert len(values) == 1
    assert values[0].name == "large"
    assert values[0].memory_bytes == 200
    assert values[0].thread_count == 4
