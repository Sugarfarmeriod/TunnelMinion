"""监听程序来历判断：只看从哪来、怎么启动，不看程序具体叫什么。"""

from __future__ import annotations

from dataclasses import dataclass, field

import psutil
import pytest

from tunnelminion.platforms import process_origin
from tunnelminion.platforms.process_origin import (
    ProcessFacts,
    ProcessOrigin,
    classify_origin,
    current_platform,
    is_interpreter,
    normalize_process_name,
    read_process_facts,
    read_process_origin,
)

MAC_HOME = "/Users/mac"
WIN_HOME = "C:\\Users\\me"


def mac(name: str, exe: str | None, *ancestors: str) -> ProcessFacts:
    return ProcessFacts("darwin", name, exe, ancestors, MAC_HOME)


def win(name: str, exe: str | None, *ancestors: str) -> ProcessFacts:
    return ProcessFacts("windows", name, exe, ancestors, WIN_HOME)


@pytest.mark.parametrize(
    ("facts", "expected"),
    [
        # 从终端启动：无论装在哪里
        (
            mac("llama-server", "/opt/homebrew/bin/llama-server", "-zsh", "login", "Terminal"),
            "terminal",
        ),
        (mac("Python", "/Library/Developer/Python.app/Contents/MacOS/Python", "-zsh"), "terminal"),
        (
            win(
                "node.exe", "C:\\Program Files\\nodejs\\node.exe", "pwsh.exe", "WindowsTerminal.exe"
            ),
            "terminal",
        ),
        # 终端已关，但装在用户自己的目录
        (
            mac("python3.12", "/Users/mac/.local/share/uv/tools/nanobot/bin/python", "launchd"),
            "user_install",
        ),
        (mac("gost", "/opt/homebrew/bin/gost", "launchd"), "user_install"),
        (mac("tool", "/usr/local/bin/tool", "launchd"), "user_install"),
        (mac("python3", "/nix/store/python3", "launchd"), "user_install"),
        (
            win(
                "python.exe",
                "C:\\Users\\me\\AppData\\Local\\Programs\\Python\\python.exe",
                "explorer.exe",
            ),
            "user_install",
        ),
        (win("tool.exe", "C:\\Users\\me\\bin\\tool.exe", "launcher.exe"), "user_install"),
        # 系统自带
        (
            mac(
                "ControlCenter",
                "/System/Library/CoreServices/ControlCenter.app/Contents/MacOS/ControlCenter",
                "launchd",
            ),
            "desktop_app",
        ),
        (mac("rapportd", "/usr/libexec/rapportd", "launchd"), "system"),
        (mac("helper", "/Library/Apple/System/helper", "launchd"), "system"),
        (win("sshd.exe", "C:\\WINDOWS\\System32\\OpenSSH\\sshd.exe", "services.exe"), "system"),
        (win("lsass.exe", None, "wininit.exe"), "system"),
        # 桌面应用及其后台助手
        (
            mac(
                "clash-verge", "/Applications/Clash Verge.app/Contents/MacOS/clash-verge", "launchd"
            ),
            "desktop_app",
        ),
        (
            mac("netdisk", "/Users/mac/Library/Application Support/netdisk/netdisk", "launchd"),
            "desktop_app",
        ),
        (
            mac("node", "/Applications/ChatGPT.app/Contents/Resources/node", "launchd"),
            "desktop_app",
        ),
        (win("steam.exe", "D:\\Program\\Steam\\steam.exe", "explorer.exe"), "desktop_app"),
        (
            win("EasyN2N.exe", "D:\\Program Files\\EasyN2N\\EasyN2N.exe", "launcher.exe"),
            "desktop_app",
        ),
        (
            win("Host.exe", "C:\\Users\\me\\AppData\\Local\\MathWorks\\Host.exe", "launcher.exe"),
            "desktop_app",
        ),
        # 应用自己注册的 Windows 服务
        (
            win(
                "sunshine.exe",
                "D:\\Program\\Sunshine\\Sunshine.exe",
                "sunshinesvc.exe",
                "services.exe",
            ),
            "app_service",
        ),
        # 容器运行环境
        (
            mac("OrbStack Helper", "/Applications/OrbStack.app/Contents/MacOS/helper", "launchd"),
            "container_runtime",
        ),
        (
            win("com.docker.backend.exe", "C:\\Program Files\\Docker\\backend.exe"),
            "container_runtime",
        ),
        # 读不出来历
        (mac("mystery", None, "launchd"), "unknown"),
        (mac("mystery", "/srv/mystery", "launchd"), "unknown"),
        (win("mystery.exe", "D:\\tools\\mystery.exe", "launcher.exe"), "unknown"),
    ],
)
def test_origin_is_decided_by_where_it_runs_from(facts: ProcessFacts, expected: str) -> None:
    assert classify_origin(facts) is ProcessOrigin(expected)


def test_same_program_name_gets_different_origins() -> None:
    """不按程序名写特例：同一个名字，来历不同结果就不同。"""
    terminal = mac("llama-server", "/opt/homebrew/bin/llama-server", "-zsh")
    bundled = mac("llama-server", "/Applications/Some.app/Contents/MacOS/llama-server", "launchd")
    assert classify_origin(terminal) is ProcessOrigin.TERMINAL
    assert classify_origin(bundled) is ProcessOrigin.DESKTOP_APP


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("python3.12", True),
        ("pythonw.exe", True),
        ("node.exe", True),
        ("java", True),
        ("python-helper", False),
        (None, False),
    ],
)
def test_interpreter_names_are_matched_exactly(name: str | None, expected: bool) -> None:
    assert is_interpreter(name) is expected


def test_name_normalization_handles_login_shells_and_exe_suffix() -> None:
    assert normalize_process_name("-zsh") == "zsh"
    assert normalize_process_name(" PowerShell.EXE ") == "powershell"


@pytest.mark.parametrize(
    ("value", "expected"), [("win32", "windows"), ("darwin", "darwin"), ("linux", "linux")]
)
def test_current_platform(monkeypatch: pytest.MonkeyPatch, value: str, expected: str) -> None:
    monkeypatch.setattr(process_origin.sys, "platform", value)
    assert current_platform() == expected


@dataclass
class FakeProcess:
    """可配置的 psutil.Process 替身。"""

    process_name: str
    path: str | BaseException | None
    created: float
    parent_process: FakeProcess | None = None
    calls: list[str] = field(default_factory=list[str])

    def name(self) -> str:
        return self.process_name

    def exe(self) -> str | None:
        if isinstance(self.path, BaseException):
            raise self.path
        return self.path

    def create_time(self) -> float:
        return self.created

    def parent(self) -> FakeProcess | None:
        return self.parent_process


def install(monkeypatch: pytest.MonkeyPatch, process: FakeProcess | BaseException) -> None:
    def factory(pid: int) -> FakeProcess:
        assert pid == 42
        if isinstance(process, BaseException):
            raise process
        return process

    monkeypatch.setattr(psutil, "Process", factory)
    monkeypatch.setattr(process_origin.Path, "home", lambda: process_origin.Path(MAC_HOME))
    monkeypatch.setattr(process_origin.sys, "platform", "darwin")


def test_reads_path_and_parent_chain_until_pid_reuse(monkeypatch: pytest.MonkeyPatch) -> None:
    # 最上面的"父进程"比子进程晚创建，说明 PID 已被复用，不能算进链里。
    reused = FakeProcess("bash", "/bin/bash", created=50)
    terminal = FakeProcess("Terminal", "/System/Terminal", created=5, parent_process=reused)
    shell = FakeProcess("-zsh", "/bin/zsh", created=10, parent_process=terminal)
    install(monkeypatch, FakeProcess("gost", "/opt/homebrew/bin/gost", 20, shell))
    facts = read_process_facts(42, "gost")
    assert facts == ProcessFacts(
        "darwin",
        "gost",
        "/opt/homebrew/bin/gost",
        ("-zsh", "Terminal"),
        str(process_origin.Path(MAC_HOME)),
    )
    assert read_process_origin(42, "gost") is ProcessOrigin.TERMINAL


def test_parent_chain_depth_is_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    top: FakeProcess | None = None
    for index in range(12):
        top = FakeProcess(f"p{index}", None, created=float(index), parent_process=top)
    assert top is not None
    install(monkeypatch, FakeProcess("leaf", None, created=100, parent_process=top))
    facts = read_process_facts(42)
    assert facts is not None and len(facts.ancestors) == 8


def test_unreadable_path_keeps_name_and_chain(monkeypatch: pytest.MonkeyPatch) -> None:
    install(monkeypatch, FakeProcess("guarded", psutil.AccessDenied(), created=1))
    facts = read_process_facts(42)
    assert facts is not None and facts.exe is None and facts.ancestors == ()


def test_empty_path_is_treated_as_unknown(monkeypatch: pytest.MonkeyPatch) -> None:
    install(monkeypatch, FakeProcess("blank", "", created=1))
    facts = read_process_facts(42)
    assert facts is not None and facts.exe is None


@pytest.mark.parametrize(
    ("actual", "expected"), [("python3.11", "python3.1"), ("gost", "gost.exe")]
)
def test_truncated_or_suffixed_names_still_match(
    monkeypatch: pytest.MonkeyPatch, actual: str, expected: str
) -> None:
    install(monkeypatch, FakeProcess(actual, "/opt/homebrew/bin/x", created=1))
    assert read_process_facts(42, expected) is not None


def test_pid_reuse_with_another_name_is_not_attributed(monkeypatch: pytest.MonkeyPatch) -> None:
    install(monkeypatch, FakeProcess("another", "/opt/homebrew/bin/x", created=1))
    assert read_process_facts(42, "gost") is None


@pytest.mark.parametrize("failure", [psutil.NoSuchProcess(42), psutil.AccessDenied(42), OSError()])
def test_vanished_or_denied_process_has_no_origin(
    monkeypatch: pytest.MonkeyPatch, failure: BaseException
) -> None:
    install(monkeypatch, failure)
    assert read_process_facts(42) is None
    assert read_process_origin(42) is None
