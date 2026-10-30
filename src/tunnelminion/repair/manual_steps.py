"""修不了时给主人照抄的步骤：只由本机代码按固定模板生成，不由模型编写，不含密钥。

步骤只显示、不执行。没有固定模板的情况只说明原因，不硬编命令。
"""

from __future__ import annotations

import re
import shlex
import sys
from threading import Lock

from tunnelminion.repair.contracts import ManualStep, ProcessLaunchRecord, ProgramLaunchRecord

# 一次对话回答里 propose_repair 拒绝时给出的步骤，回答写进对话时一并带上；按回答编号暂存。
_RUN_STEPS: dict[str, tuple[ManualStep, ...]] = {}
_RUN_STEPS_LOCK = Lock()
_RUN_STEPS_LIMIT = 64


def remember_run_steps(run_id: str, steps: tuple[ManualStep, ...]) -> None:
    """记下这次回答要附带的现成步骤；同一次回答只保留最后一次拒绝给出的步骤。"""
    with _RUN_STEPS_LOCK:
        _RUN_STEPS.pop(run_id, None)
        _RUN_STEPS[run_id] = steps
        while len(_RUN_STEPS) > _RUN_STEPS_LIMIT:
            _RUN_STEPS.pop(next(iter(_RUN_STEPS)))


def take_run_steps(run_id: str) -> tuple[ManualStep, ...]:
    with _RUN_STEPS_LOCK:
        return _RUN_STEPS.pop(run_id, ())


# 参数里看起来像密钥的部分换成这句，主人照抄时自己填回去。
SECRET_PLACEHOLDER = "（原来的值）"

_SECRET_OPTION = re.compile(
    r"(?i)^-{1,2}[a-z0-9_.-]*"
    r"(token|passw(?:or)?d|pass|pwd|secret|api[-_]?key|access[-_]?key|private[-_]?key|auth"
    r"|credential)[a-z0-9_.-]*$"
)
# 地址里带的账户密码，例如 `socks5://user:pass@host`。
_URL_PASSWORD = re.compile(r"(?i)(://[^/\s:@]*:)[^/\s@]+@")


def redact_arguments(arguments: tuple[str, ...]) -> tuple[str, ...]:
    """把 `--token=xxx`、`--password xxx` 和地址里的密码换成占位，其余参数原样保留。"""
    result: list[str] = []
    redact_next = False
    for argument in arguments:
        if redact_next and not argument.startswith("-"):
            result.append(SECRET_PLACEHOLDER)
            redact_next = False
            continue
        redact_next = False
        name, equals, _ = argument.partition("=")
        if _SECRET_OPTION.match(name):
            if equals:
                result.append(f"{name}={SECRET_PLACEHOLDER}")
                continue
            redact_next = True
        result.append(_URL_PASSWORD.sub(rf"\g<1>{SECRET_PLACEHOLDER}@", argument))
    return tuple(result)


# PowerShell 把直引号和这几种弯引号都当成单引号，单引号字符串里每一个都要双写。
_POWERSHELL_QUOTES = re.compile("(['\u2018\u2019\u201a\u201b])")


def _powershell_quote(value: str) -> str:
    return "'" + _POWERSHELL_QUOTES.sub(r"\1\1", value) + "'"


def launch_command(record: ProcessLaunchRecord, *, platform: str = sys.platform) -> str | None:
    """在原工作目录里按原参数重新运行的命令；启动信息读不全时返回 None。"""
    if isinstance(record, ProgramLaunchRecord):
        if record.elevated or record.executable is None or record.working_directory is None:
            return None
        executable, directory = record.executable, record.working_directory
    else:
        executable, directory = record.interpreter, record.working_directory
    arguments = redact_arguments(record.arguments)
    if platform == "win32":
        parts = " ".join(_powershell_quote(item) for item in arguments)
        command = f"Set-Location -LiteralPath {_powershell_quote(directory)}; & "
        return (command + _powershell_quote(executable) + (f" {parts}" if parts else ""))[:2_000]
    return (f"cd {shlex.quote(directory)} && " + shlex.join([executable, *arguments]))[:2_000]


def relaunch_steps(
    record: ProcessLaunchRecord, *, platform: str = sys.platform
) -> tuple[ManualStep, ...]:
    """在终端里自己重新运行；以管理员身份运行的读不全启动方式，只说明用管理员终端。"""
    command = launch_command(record, platform=platform)
    if command is None:
        elevated = isinstance(record, ProgramLaunchRecord) and record.elevated
        if not elevated:
            text = "在终端里按你原来的方式重新运行它"
        elif platform == "win32":
            text = "以管理员身份打开终端，按你原来的方式重新运行它"
        else:
            text = "在终端里用 sudo 按你原来的方式重新运行它"
        return (ManualStep(text=text),)
    if platform == "win32":
        return (ManualStep(text="打开 PowerShell，运行", command=command),)
    return (ManualStep(text="打开终端，运行", command=command),)


def port_owner_steps(port: int, *, platform: str = sys.platform) -> tuple[ManualStep, ...]:
    """查出是谁占着端口；只读，不结束任何程序。"""
    if platform == "win32":
        command = (
            f"Get-NetTCPConnection -LocalPort {port} -State Listen | "
            "ForEach-Object { Get-Process -Id $_.OwningProcess }"
        )
        return (ManualStep(text="打开 PowerShell，查出占着端口的程序", command=command),)
    return (
        ManualStep(
            text="打开终端，查出占着端口的程序", command=f"lsof -nP -iTCP:{port} -sTCP:LISTEN"
        ),
    )


def windows_service_steps(name: str, *, disabled: bool, running: bool) -> tuple[ManualStep, ...]:
    """以管理员身份启动或重启一个 Windows 服务；被禁用的先改成手动启动。"""
    quoted = _powershell_quote(name)
    if disabled:
        return (
            ManualStep(
                text="确实想用它的话，以管理员身份打开 PowerShell，运行",
                command=(
                    f"Set-Service -Name {quoted} -StartupType Manual; Start-Service -Name {quoted}"
                ),
            ),
        )
    action = "Restart-Service" if running else "Start-Service"
    return (
        ManualStep(text="以管理员身份打开 PowerShell，运行", command=f"{action} -Name {quoted}"),
    )


def system_launch_daemon_steps(label: str) -> tuple[ManualStep, ...]:
    """系统级后台服务需要管理员权限，由主人自己重启。"""
    return (
        ManualStep(
            text="如果它是系统级后台服务，在终端里运行（需要输入你的密码）",
            command=f"sudo launchctl kickstart -k system/{label}",
        ),
    )
