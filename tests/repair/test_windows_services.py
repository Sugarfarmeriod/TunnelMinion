"""Windows 服务：只读查询、单个服务授权和固定的启停命令，全部用替身，不碰真实服务。"""

from __future__ import annotations

import asyncio
import re
import subprocess
from typing import Any

import psutil
import pytest
from tests.repair.factories import NOW

from tunnelminion.platforms.windows.system import CommandResult
from tunnelminion.repair.windows_services import (
    UnsupportedWindowsServices,
    WindowsServiceManager,
    binary_from_command_line,
    default_windows_services,
    grant_ace,
    has_grant,
    with_grant,
)

SID = "S-1-5-21-1-2-3-1001"
BASE = "D:(A;;CCLCSWLOCRRC;;;AU)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)"
AUDIT = "S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)"
# Windows 读回服务权限时把权限字母按这个顺序重排。
CANONICAL = ("CC", "DC", "LC", "SW", "RP", "WP", "DT", "LO", "CR", "SD", "RC", "WD", "WO")


def canonical(sddl: str) -> str:
    """模拟 `sc sdshow`：每一条的权限字母按规范顺序重排。"""

    def reorder(match: re.Match[str]) -> str:
        fields = match.group(1).split(";")
        rights = {fields[2][index : index + 2] for index in range(0, len(fields[2]), 2)}
        fields[2] = "".join(item for item in CANONICAL if item in rights)
        return "(" + ";".join(fields) + ")"

    return re.sub(r"\(([^()]*)\)", reorder, sddl)


class FakeService:
    def __init__(self, name: str, pid: int | None, details: dict[str, Any] | None = None) -> None:
        self._name = name
        self._pid = pid
        self._details = details

    def name(self) -> str:
        return self._name

    def pid(self) -> int | None:
        if self._pid == -1:
            raise psutil.AccessDenied()
        return self._pid

    def as_dict(self) -> dict[str, Any]:
        if self._details is None:
            raise psutil.NoSuchProcess(1)
        return self._details


class FakeProcess:
    def __init__(
        self,
        pid: int,
        created: float,
        parent: FakeProcess | None = None,
        exe: str = "C:\\Windows\\System32\\svchost.exe",
    ) -> None:
        self.pid = pid
        self._created = created
        self._parent = parent
        self._exe = exe

    def exe(self) -> str:
        return self._exe

    def parent(self) -> FakeProcess | None:
        return self._parent

    def create_time(self) -> float:
        return self._created


class FakeRunner:
    def __init__(self, returncode: int = 0, error: Exception | None = None) -> None:
        self.returncode = returncode
        self.error = error
        self.commands: list[tuple[str, ...]] = []

    async def run(self, command: tuple[str, ...], timeout_seconds: float) -> CommandResult:
        self.commands.append(command)
        if self.error is not None:
            raise self.error
        return CommandResult(returncode=self.returncode, stdout="SUCCESS token=abc", stderr="")


class Harness:
    def __init__(self) -> None:
        self.sddl = BASE + AUDIT
        self.whoami = f'"pc\\\\me","{SID}"'
        self.sync_error: Exception | None = None
        self.sync_code = 0
        self.runner = FakeRunner()
        self.now = 0.0
        self.services: list[FakeService] = []
        self.details: dict[str, dict[str, Any]] = {}
        self.files: set[str] = set()
        nssm = FakeProcess(100, 1, exe="D:\\Tools\\nssm.exe")
        winsw = FakeProcess(110, 1, exe="D:\\Apps\\myapp-service.exe")
        svchost = FakeProcess(120, 1)
        self.processes: dict[int, FakeProcess] = {
            100: nssm,
            200: FakeProcess(200, 2, nssm),
            210: FakeProcess(210, 3, FakeProcess(209, 2, nssm)),
            220: FakeProcess(220, 2, winsw),
            230: FakeProcess(230, 2, svchost),
            300: FakeProcess(300, 3, FakeProcess(301, 9, exe="D:\\Tools\\nssm.exe")),
        }
        self.manager = WindowsServiceManager(
            self.runner,
            run_sync=self.run_sync,
            service_iter=lambda: iter(self.services),
            service_get=self.service_get,
            process_factory=self.process,  # type: ignore[arg-type]
            path_exists=self.files.__contains__,
            clock=lambda: NOW,
            monotonic=lambda: self.now,
        )

    def run_sync(self, command: tuple[str, ...], timeout: float) -> CommandResult:
        if self.sync_error is not None:
            raise self.sync_error
        if command[0] == "whoami":
            return CommandResult(returncode=self.sync_code, stdout=self.whoami, stderr="")
        return CommandResult(
            returncode=self.sync_code, stdout=f"\n{canonical(self.sddl)}\n", stderr=""
        )

    def service_get(self, name: str) -> FakeService:
        return FakeService(name, None, self.details.get(name))

    def process(self, pid: int) -> FakeProcess:
        if pid not in self.processes:
            raise psutil.NoSuchProcess(pid)
        return self.processes[pid]


def details(**update: object) -> dict[str, Any]:
    value: dict[str, Any] = {
        "display_name": "Sunshine Service",
        "binpath": '"D:\\Program\\Sunshine\\tools\\sunshinesvc.exe" --flag',
        "start_type": "automatic",
        "status": "running",
        "pid": 100,
    }
    value.update(update)
    return value


def test_binary_path_and_sddl_helpers() -> None:
    assert binary_from_command_line('"C:\\a b\\x.exe" -k') == "C:\\a b\\x.exe"
    assert binary_from_command_line("C:\\a\\x.EXE -k") == "C:\\a\\x.EXE"
    assert binary_from_command_line("C:\\a\\run arg") == "C:\\a\\run"
    granted = with_grant(BASE + AUDIT, SID, granted=True)
    assert granted == BASE + grant_ace(SID) + AUDIT
    assert grant_ace(SID) == canonical(grant_ace(SID))
    assert has_grant(granted, SID) and not has_grant(BASE, SID)
    assert not has_grant(f"(A;;RPLC;;;{SID})", SID)
    assert not has_grant(f"(D;;RPWP;;;{SID})", SID)
    assert with_grant(BASE, SID, granted=True) == BASE + grant_ace(SID)
    assert with_grant(granted, SID, granted=False) == BASE + AUDIT
    # 旧写法、重排后的写法和重复的条目都按权限集合认出来一起去掉。
    messy = BASE + f"(A;;RPWPLCRC;;;{SID})(A;;LCRPWPRC;;;{SID})" + AUDIT
    assert with_grant(messy, SID, granted=False) == BASE + AUDIT
    assert with_grant(messy, SID, granted=True) == BASE + grant_ace(SID) + AUDIT
    # 主人自己另外加的权限不是我们加的，不动它；已有启停权限时也不再叠加。
    own = BASE + f"(A;;RPWPDT;;;{SID})"
    assert with_grant(own, SID, granted=False) == own
    assert with_grant(own, SID, granted=True) == own


def test_unsupported_platform() -> None:
    unsupported = UnsupportedWindowsServices()
    assert unsupported.unsupported_reason() is not None
    assert unsupported.services_for_pids(frozenset({1})) == {}
    assert unsupported.inspect("x") is None
    assert asyncio.run(unsupported.set_granted("x", granted=True)) is False
    with pytest.raises(ValueError):
        asyncio.run(unsupported.start("x"))
    with pytest.raises(ValueError):
        asyncio.run(unsupported.stop("x"))
    assert isinstance(
        default_windows_services(), WindowsServiceManager | UnsupportedWindowsServices
    )


def test_default_manager_reads_psutil_only_when_used(monkeypatch: pytest.MonkeyPatch) -> None:
    # 其他平台的 psutil 没有 Windows 服务函数：建对象不能出错，用到时才去取。
    monkeypatch.delattr(psutil, "win_service_iter", raising=False)
    monkeypatch.delattr(psutil, "win_service_get", raising=False)
    manager = WindowsServiceManager()
    service = FakeService("Sunshine", None)
    monkeypatch.setattr(psutil, "win_service_iter", lambda: [service], raising=False)
    asked: list[str] = []

    def service_get(name: str) -> FakeService:
        asked.append(name)
        return service

    monkeypatch.setattr(psutil, "win_service_get", service_get, raising=False)
    assert manager.services_for_pids(frozenset({1})) == {}
    manager.inspect("Sunshine")
    assert asked == ["Sunshine"]


def test_services_for_pids_only_trusts_the_service_or_its_wrapper_child() -> None:
    h = Harness()
    h.services = [
        FakeService("Sunshine", 100),
        FakeService("MyApp", 110),
        FakeService("Schedule", 120),
        FakeService("Reused", 301),
        FakeService("bad name!", 300),
        FakeService("Stopped", None),
        FakeService("Denied", -1),
    ]
    assert h.manager.unsupported_reason() is None
    assert h.manager.services_for_pids(frozenset()) == {}
    # 100 本身是服务进程；200 的直接父进程是 NSSM；210 隔了一层不算；
    # 220 的父进程是没配置文件的普通服务程序；230 的父进程是 svchost（计划任务这类）；
    # 300 的父进程比它晚创建（进程号被复用）；999 已退出。
    pids = frozenset({100, 200, 210, 220, 230, 300, 999})
    assert h.manager.services_for_pids(pids) == {100: "Sunshine", 200: "Sunshine"}
    # 旁边有同名 .xml 配置文件的是改了名的 WinSW。
    h.files.add("D:\\Apps\\myapp-service.xml")
    assert h.manager.services_for_pids(frozenset({220})) == {220: "MyApp"}

    def broken() -> Any:
        raise OSError

    h.manager._service_iter = broken  # pyright: ignore[reportPrivateUsage]
    assert h.manager.services_for_pids(frozenset({100})) == {}


def test_inspect_reads_config_state_and_grant() -> None:
    h = Harness()
    h.details["Sunshine"] = details()
    info = h.manager.inspect("Sunshine")
    assert info is not None
    assert info.binary_path == "D:\\Program\\Sunshine\\tools\\sunshinesvc.exe"
    assert info.running and info.pid == 100 and not info.granted
    h.details["Stopped"] = details(status="stopped", pid=0, display_name=None)
    stopped = h.manager.inspect("Stopped")
    assert stopped is not None and not stopped.running and stopped.pid is None
    assert stopped.display_name == "Stopped"
    assert h.manager.inspect("bad name!") is None
    assert h.manager.inspect("Missing") is None
    h.details["Odd"] = details(start_type="boot")
    assert h.manager.inspect("Odd") is None
    h.details["NoPath"] = details(binpath="")
    assert h.manager.inspect("NoPath") is None


def test_grant_state_is_cached_for_a_minute() -> None:
    h = Harness()
    h.details["Sunshine"] = details()
    h.sddl = BASE + grant_ace(SID)
    assert h.manager._is_granted("Sunshine")  # pyright: ignore[reportPrivateUsage]
    h.sddl = BASE
    assert h.manager._is_granted("Sunshine")  # pyright: ignore[reportPrivateUsage]
    h.now = 61
    assert not h.manager._is_granted("Sunshine")  # pyright: ignore[reportPrivateUsage]


@pytest.mark.parametrize(
    "problem", ["whoami_fails", "whoami_bad", "sync_error", "sddl_bad", "sddl_code"]
)
def test_unreadable_identity_or_sddl_means_not_granted(problem: str) -> None:
    h = Harness()
    if problem == "whoami_bad":
        h.whoami = "nonsense"
    elif problem == "sync_error":
        h.sync_error = subprocess.TimeoutExpired("x", 1)
    elif problem == "sddl_bad":
        h.sddl = "D:(A;;RP;;;AU) ; rm -rf"
    elif problem == "sddl_code":
        h.sddl = BASE
        h.manager._sid = SID  # pyright: ignore[reportPrivateUsage]
        h.sync_code = 5
    else:
        h.sync_code = 1
    assert not h.manager._is_granted("Sunshine")  # pyright: ignore[reportPrivateUsage]
    assert asyncio.run(h.manager.set_granted("Sunshine", granted=True)) is False


def test_set_granted_runs_one_elevated_sdset_and_rereads() -> None:
    h = Harness()

    async def run(command: tuple[str, ...], timeout_seconds: float) -> CommandResult:
        h.runner.commands.append(command)
        h.sddl = command[4].split("'")[5]
        return CommandResult(returncode=0, stdout="", stderr="")

    h.runner.run = run  # type: ignore[method-assign]
    assert asyncio.run(h.manager.set_granted("Sunshine", granted=True)) is True
    [command] = h.runner.commands
    assert command[:4] == ("powershell.exe", "-NoProfile", "-NonInteractive", "-Command")
    assert (
        "-Verb RunAs" in command[4]
        and f"'sdset','Sunshine','{BASE}{grant_ace(SID)}" in (command[4])
    )
    # 已经是要的样子时不再弹确认。
    assert asyncio.run(h.manager.set_granted("Sunshine", granted=True)) is True
    assert len(h.runner.commands) == 1
    # Windows 读回时已经重排了权限字母，撤回照样能撤掉，并且重新读一次确认真的没了。
    assert asyncio.run(h.manager.set_granted("Sunshine", granted=False)) is True
    assert f"'sdset','Sunshine','{BASE}{AUDIT}'" in h.runner.commands[-1][4]
    assert not has_grant(canonical(h.sddl), SID)
    assert asyncio.run(h.manager.set_granted("bad name!", granted=True)) is False


def test_revoke_fails_when_the_grant_is_not_ours() -> None:
    h = Harness()
    h.sddl = BASE + f"(A;;RPWPDT;;;{SID})" + AUDIT
    assert asyncio.run(h.manager.set_granted("Sunshine", granted=False)) is False
    assert h.runner.commands == []


def bad_grant(sddl: str, sid: str, *, granted: bool) -> str:
    return sddl + " ; bad"


@pytest.mark.parametrize("failure", ["declined", "error", "bad_sddl"])
def test_set_granted_reports_declined_or_failed(
    failure: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    h = Harness()
    if failure == "declined":
        h.runner.returncode = 1
    elif failure == "error":
        h.runner.error = OSError("no desktop")
    else:
        monkeypatch.setattr(
            "tunnelminion.repair.windows_services.with_grant",
            bad_grant,
        )
    assert asyncio.run(h.manager.set_granted("Sunshine", granted=True)) is False


def test_start_and_stop_use_fixed_sc_commands() -> None:
    h = Harness()
    command = asyncio.run(h.manager.start("Sunshine"))
    assert command.argv == ("sc.exe", "start", "Sunshine") and command.exit_code == 0
    assert "abc" not in command.output_excerpt
    assert asyncio.run(h.manager.stop("Sunshine")).argv == ("sc.exe", "stop", "Sunshine")
    h.runner.error = subprocess.TimeoutExpired("sc", 60)
    failed = asyncio.run(h.manager.start("Sunshine"))
    assert failed.exit_code is None and "timed out" in failed.output_excerpt
    with pytest.raises(ValueError):
        asyncio.run(h.manager.start("bad name!"))
