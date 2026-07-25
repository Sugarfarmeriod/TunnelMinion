"""macOS 普通用户监听端点降级读取测试。"""

from __future__ import annotations

import shutil
import subprocess

import psutil
import pytest

from tunnelminion.platforms.macos.system import MacOSSystemReader


def test_macos_reader_parses_fixed_lsof_listener_output() -> None:
    """lsof 输出只提取监听元数据，并去重、排序。"""
    output = """COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
Python  21968 mac 4u IPv4 0x1 0t0 TCP 127.0.0.1:18880 (LISTEN)
python3 21969 mac 5u IPv6 0x2 0t0 TCP [::1]:18881 (LISTEN)
mDNSRes 321 mac 6u IPv4 0x3 0t0 UDP *:5353
Python  21968 mac 4u IPv4 0x1 0t0 TCP 127.0.0.1:18880 (LISTEN)
Python  21968 mac 7u IPv4 0x4 0t0 TCP 127.0.0.1:18882 (ESTABLISHED)
bad
bad-pid nope mac 4u IPv4 0x1 0t0 TCP 127.0.0.1:9000 (LISTEN)
bad-port 12 mac 4u IPv4 0x1 0t0 TCP 127.0.0.1:http (LISTEN)
missing-protocol 12 mac 4u IPv4 0x1 0t0 SCTP 127.0.0.1:9000
missing-endpoint 12 mac 4u IPv4 0x1 0t0 TCP
missing-colon 12 mac 4u IPv4 0x1 0t0 TCP localhost (LISTEN)
"""

    listeners = MacOSSystemReader.parse_lsof_output(output)

    assert [(item.protocol, item.address, item.port) for item in listeners] == [
        ("udp", "0.0.0.0", 5353),
        ("tcp", "127.0.0.1", 18880),
        ("tcp", "::1", 18881),
    ]
    assert listeners[1].pid == 21968
    assert listeners[1].process_name == "Python"


def test_macos_reader_falls_back_to_fixed_lsof_command(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """psutil 权限不足时只执行程序内固定的 lsof 参数。"""
    commands: list[tuple[str, ...]] = []

    def denied(*args: object, **kwargs: object) -> object:
        del args, kwargs
        raise psutil.AccessDenied()

    def completed(
        command: tuple[str, ...],
        **kwargs: object,
    ) -> subprocess.CompletedProcess[str]:
        del kwargs
        commands.append(command)
        return subprocess.CompletedProcess(
            command,
            0,
            "COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME\n"
            "Python 21968 mac 4u IPv4 0x1 0t0 TCP 127.0.0.1:18880 (LISTEN)\n",
            "",
        )

    monkeypatch.setattr(psutil, "net_connections", denied)
    monkeypatch.setattr(subprocess, "run", completed)

    listeners = MacOSSystemReader("/usr/sbin/lsof").listeners()

    assert len(listeners) == 1
    assert commands == [
        (
            "/usr/sbin/lsof",
            "-nP",
            "-iTCP",
            "-sTCP:LISTEN",
            "-iUDP",
        )
    ]


def test_macos_reader_keeps_psutil_result_when_available(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """psutil 可读时不启动降级子进程。"""

    def no_connections(**kwargs: object) -> tuple[()]:
        del kwargs
        return ()

    monkeypatch.setattr(psutil, "net_connections", no_connections)

    def unexpected(*args: object, **kwargs: object) -> object:
        del args, kwargs
        raise AssertionError("不应调用 lsof")

    monkeypatch.setattr(subprocess, "run", unexpected)

    assert MacOSSystemReader("/usr/sbin/lsof").listeners() == ()


@pytest.mark.parametrize(
    "failure",
    [
        FileNotFoundError(),
        subprocess.TimeoutExpired(("lsof",), 5),
        subprocess.CompletedProcess(("lsof",), 2, "", "permission denied"),
    ],
)
def test_macos_reader_reports_lsof_failures_as_permission_degradation(
    monkeypatch: pytest.MonkeyPatch,
    failure: BaseException | subprocess.CompletedProcess[str],
) -> None:
    """lsof 缺失、超时或失败继续映射成现有的权限降级契约。"""

    def denied_connections(**kwargs: object) -> tuple[()]:
        del kwargs
        raise psutil.AccessDenied()

    monkeypatch.setattr(psutil, "net_connections", denied_connections)

    def fail(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        del args, kwargs
        if isinstance(failure, BaseException):
            raise failure
        return failure

    monkeypatch.setattr(subprocess, "run", fail)

    with pytest.raises(PermissionError):
        MacOSSystemReader("/usr/sbin/lsof").listeners()


def test_macos_reader_accepts_lsof_no_match_exit_code(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """lsof 以 1 表示没有匹配项时返回空集合。"""

    def denied_connections(**kwargs: object) -> tuple[()]:
        del kwargs
        raise psutil.AccessDenied()

    def no_matches(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        del args, kwargs
        return subprocess.CompletedProcess(("lsof",), 1, "", "")

    monkeypatch.setattr(psutil, "net_connections", denied_connections)
    monkeypatch.setattr(subprocess, "run", no_matches)

    assert MacOSSystemReader("/usr/sbin/lsof").listeners() == ()


@pytest.mark.parametrize("resolved", ["/opt/homebrew/bin/lsof", None])
def test_macos_reader_resolves_or_falls_back_to_standard_lsof_path(
    monkeypatch: pytest.MonkeyPatch,
    resolved: str | None,
) -> None:
    """未显式配置时只从 PATH 或系统标准位置解析 lsof。"""
    commands: list[tuple[str, ...]] = []

    def which(name: str) -> str | None:
        del name
        return resolved

    def denied_connections(**kwargs: object) -> tuple[()]:
        del kwargs
        raise psutil.AccessDenied()

    monkeypatch.setattr(shutil, "which", which)
    monkeypatch.setattr(psutil, "net_connections", denied_connections)

    def complete(
        command: tuple[str, ...],
        **kwargs: object,
    ) -> subprocess.CompletedProcess[str]:
        del kwargs
        commands.append(command)
        return subprocess.CompletedProcess(command, 1, "", "")

    monkeypatch.setattr(subprocess, "run", complete)

    assert MacOSSystemReader().listeners() == ()
    assert commands[0][0] == (resolved or "/usr/sbin/lsof")
