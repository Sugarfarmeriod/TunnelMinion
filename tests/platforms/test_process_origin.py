"""监听程序来历判断：只看从哪来、怎么启动，不看程序具体叫什么。"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import psutil
import pytest

from tunnelminion.platforms import process_origin
from tunnelminion.platforms.process_origin import (
    ProcessFacts,
    ProcessOrigin,
    classify_origin,
    current_platform,
    is_interpreter,
    is_windows_gui_program,
    normalize_process_name,
    read_process_facts,
    read_process_origin,
)

MAC_HOME = "/Users/mac"
WIN_HOME = "C:\\Users\\me"


def mac(name: str, exe: str | None, *ancestors: str) -> ProcessFacts:
    return ProcessFacts("darwin", name, exe, ancestors, MAC_HOME)


def win(name: str, exe: str | None, *ancestors: str, windowed: bool = False) -> ProcessFacts:
    return ProcessFacts("windows", name, exe, ancestors, WIN_HOME, windowed=windowed)


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
    ("facts", "expected"),
    [
        # 装在自定义目录的网盘后台进程：祖先是有窗口的网盘主程序。
        (
            win(
                "nethost.exe",
                "E:\\apps\\netdisk\\engine\\nethost.exe",
                "netengine.exe",
                "netdisk.exe",
                windowed=True,
            ),
            "desktop_app",
        ),
        # 装在用户目录但有窗口，仍是桌面应用。
        (
            win("chat.exe", "C:\\Users\\me\\chat\\chat.exe", "launcher.exe", windowed=True),
            "desktop_app",
        ),
        # 下面这些规则排在图形界面判断之前。
        (win("tool.exe", "E:\\apps\\tool.exe", "pwsh.exe", windowed=True), "terminal"),
        (
            win(
                "stream.exe", "E:\\apps\\stream.exe", "streamsvc.exe", "services.exe", windowed=True
            ),
            "app_service",
        ),
        (win("pythonw.exe", "E:\\py\\pythonw.exe", "launcher.exe", windowed=True), "user_install"),
        (win("svc.exe", "C:\\Windows\\svc.exe", "launcher.exe", windowed=True), "system"),
        # 没有窗口时保持原来的判断。
        (win("nethost.exe", "E:\\apps\\netdisk\\nethost.exe", "netengine.exe"), "unknown"),
    ],
)
def test_windowed_programs_are_desktop_apps_wherever_installed(
    facts: ProcessFacts, expected: str
) -> None:
    assert classify_origin(facts) is ProcessOrigin(expected)


def test_old_facts_without_windowed_field_keep_working() -> None:
    """评测脚本保存的旧事实数据没有 `windowed`，按不是图形界面程序处理。"""
    raw = {
        "platform": "windows",
        "name": "x.exe",
        "exe": "E:\\x.exe",
        "ancestors": ("launcher.exe",),
        "home": WIN_HOME,
    }
    facts = ProcessFacts(**raw)  # type: ignore[arg-type]
    assert facts.windowed is False
    assert classify_origin(facts) is ProcessOrigin.UNKNOWN


def write_pe(path: Path, subsystem: int, *, signature: bytes = b"PE\0\0") -> Path:
    """写一个只有判断所需字段的最小假 PE 文件。"""
    e_lfanew = 0x80
    data = bytearray(e_lfanew + 24 + 96)
    data[0:2] = b"MZ"
    data[60:64] = e_lfanew.to_bytes(4, "little")
    data[e_lfanew : e_lfanew + 4] = signature
    offset = e_lfanew + 24 + 68
    data[offset : offset + 2] = subsystem.to_bytes(2, "little")
    path.write_bytes(bytes(data))
    return path


def test_pe_subsystem_tells_gui_from_console(tmp_path: Path) -> None:
    assert is_windows_gui_program(str(write_pe(tmp_path / "gui.exe", 2)))
    assert not is_windows_gui_program(str(write_pe(tmp_path / "console.exe", 3)))


def test_unreadable_or_malformed_pe_is_not_gui(tmp_path: Path) -> None:
    missing = tmp_path / "missing.exe"
    not_pe = tmp_path / "script.sh"
    not_pe.write_bytes(b"#!/bin/sh\n" + b"\0" * 100)
    short = tmp_path / "short.exe"
    short.write_bytes(b"MZ")
    bad_signature = write_pe(tmp_path / "bad.exe", 2, signature=b"NE\0\0")
    # e_lfanew 指向文件末尾之外，读不到完整的 PE 头。
    truncated = tmp_path / "truncated.exe"
    truncated.write_bytes(b"MZ" + b"\0" * 58 + (4096).to_bytes(4, "little"))
    for path in (missing, not_pe, short, bad_signature, truncated):
        assert not is_windows_gui_program(str(path))


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


def chain(*programs: tuple[str, str | BaseException | None]) -> FakeProcess:
    """按"本进程、父进程、祖父进程……"的顺序搭一条进程链。"""
    parent: FakeProcess | None = None
    for index, (name, path) in enumerate(reversed(programs)):
        parent = FakeProcess(name, path, created=float(index), parent_process=parent)
    assert parent is not None
    return parent


def test_windows_facts_record_a_windowed_ancestor(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    host = write_pe(tmp_path / "nethost.exe", 3)
    engine = write_pe(tmp_path / "netengine.exe", 3)
    main = write_pe(tmp_path / "netdisk.exe", 2)
    install(
        monkeypatch,
        chain(
            ("nethost.exe", str(host)), ("netengine.exe", str(engine)), ("netdisk.exe", str(main))
        ),
    )
    monkeypatch.setattr(process_origin.sys, "platform", "win32")
    facts = read_process_facts(42)
    assert facts is not None and facts.windowed
    assert facts.ancestors == ("netengine.exe", "netdisk.exe")
    assert classify_origin(facts) is ProcessOrigin.DESKTOP_APP


def test_console_chain_is_not_windowed(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    tool = write_pe(tmp_path / "tool.exe", 3)
    install(monkeypatch, chain(("tool.exe", str(tool)), ("launcher.exe", str(tool))))
    monkeypatch.setattr(process_origin.sys, "platform", "win32")
    facts = read_process_facts(42)
    assert facts is not None and not facts.windowed


def test_system_programs_explorer_and_interpreters_do_not_count_as_windows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """它们是几乎所有进程的祖先或本身是图形子系统的解释器，不能说明端口属于桌面应用。"""
    checked: list[str] = []

    def everything_is_gui(path: str) -> bool:
        checked.append(path)
        return True

    monkeypatch.setattr(process_origin, "is_windows_gui_program", everything_is_gui)
    install(
        monkeypatch,
        chain(
            ("pythonw.exe", "E:\\py\\pythonw.exe"),
            ("guarded.exe", psutil.AccessDenied()),
            ("explorer.exe", "C:\\Windows\\explorer.exe"),
            ("Explorer.EXE", "E:\\shell\\explorer.exe"),
            ("svchost.exe", "C:\\WINDOWS\\System32\\svchost.exe"),
        ),
    )
    monkeypatch.setattr(process_origin.sys, "platform", "win32")
    facts = read_process_facts(42)
    assert facts is not None and not facts.windowed
    assert checked == []


def test_windowed_is_only_collected_on_windows(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    gui = write_pe(tmp_path / "gui.exe", 2)
    install(monkeypatch, chain(("gui", str(gui))))
    facts = read_process_facts(42)
    assert facts is not None and facts.platform == "darwin" and not facts.windowed
