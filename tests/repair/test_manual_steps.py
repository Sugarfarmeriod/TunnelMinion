"""修不了时的现成步骤：固定模板、不含密钥。"""

from __future__ import annotations

from tests.repair.factories import NOW, launch_record

from tunnelminion.repair.contracts import ManualStep, ProgramLaunchRecord
from tunnelminion.repair.manual_steps import (
    SECRET_PLACEHOLDER,
    launch_command,
    port_owner_steps,
    redact_arguments,
    relaunch_steps,
    remember_run_steps,
    system_launch_daemon_steps,
    take_run_steps,
    windows_service_steps,
)


def program(**update: object) -> ProgramLaunchRecord:
    return ProgramLaunchRecord(
        service_key="program:gost@805",
        executable="/opt/tools/gost",
        executable_size=10,
        executable_mtime_ns=20,
        arguments=("-L", "tcp://:805/127.0.0.1:22"),
        working_directory="/home/me/it's here",
        ports=(805,),
        username="me",
        rule_shown=True,
        process_id=7,
        process_started_at=NOW,
        recorded_at=NOW,
    ).model_copy(update=update)


def test_secrets_in_arguments_are_replaced() -> None:
    redacted = redact_arguments(
        (
            "--token=abc",
            "--password",
            "hunter2",
            "--api-key",
            "--verbose",
            "-L",
            "socks5://user:pass@:1080",
            "--port",
            "80",
            "--secret",
        )
    )
    assert redacted == (
        f"--token={SECRET_PLACEHOLDER}",
        "--password",
        SECRET_PLACEHOLDER,
        "--api-key",
        "--verbose",
        "-L",
        f"socks5://user:{SECRET_PLACEHOLDER}@:1080",
        "--port",
        "80",
        "--secret",
    )


def test_launch_command_quotes_for_each_platform() -> None:
    record = program(arguments=("--token=abc", "x y"))
    assert launch_command(record, platform="darwin") == (
        f"cd '/home/me/it'\"'\"'s here' && /opt/tools/gost '--token={SECRET_PLACEHOLDER}' 'x y'"
    )
    assert launch_command(record, platform="win32") == (
        "Set-Location -LiteralPath '/home/me/it''s here'; & '/opt/tools/gost' "
        f"'--token={SECRET_PLACEHOLDER}' 'x y'"
    )
    assert launch_command(program(arguments=()), platform="win32") == (
        "Set-Location -LiteralPath '/home/me/it''s here'; & '/opt/tools/gost'"
    )
    # 弯引号在 PowerShell 里也算单引号，同样双写。
    curly = launch_command(program(arguments=("a\u2018b\u2019c\u201ad\u201be",)), platform="win32")
    assert curly is not None
    assert curly.endswith("'a\u2018\u2018b\u2019\u2019c\u201a\u201ad\u201b\u201be'")
    python = launch_command(launch_record(), platform="linux")
    assert python == "cd C:/work/site && C:/Python311/python.exe -m http.server 8765"
    assert launch_command(program(elevated=True, executable=None), platform="win32") is None


def test_relaunch_steps_for_normal_and_elevated_programs() -> None:
    assert relaunch_steps(program(), platform="win32")[0].text == "打开 PowerShell，运行"
    assert relaunch_steps(program(), platform="darwin")[0].text == "打开终端，运行"
    unreadable = program(elevated=True, executable=None, working_directory=None, username=None)
    assert relaunch_steps(unreadable, platform="win32") == (
        ManualStep(text="以管理员身份打开终端，按你原来的方式重新运行它"),
    )
    assert relaunch_steps(unreadable, platform="darwin") == (
        ManualStep(text="在终端里用 sudo 按你原来的方式重新运行它"),
    )


def test_relaunch_steps_without_template_only_explain() -> None:
    record = program()
    object.__setattr__(record, "working_directory", None)
    assert relaunch_steps(record, platform="linux") == (
        ManualStep(text="在终端里按你原来的方式重新运行它"),
    )


def test_port_owner_and_service_steps() -> None:
    assert "Get-NetTCPConnection -LocalPort 805" in (
        port_owner_steps(805, platform="win32")[0].command or ""
    )
    assert port_owner_steps(805, platform="darwin")[0].command == (
        "lsof -nP -iTCP:805 -sTCP:LISTEN"
    )
    assert windows_service_steps("Svc", disabled=False, running=True)[0].command == (
        "Restart-Service -Name 'Svc'"
    )
    assert windows_service_steps("Svc", disabled=False, running=False)[0].command == (
        "Start-Service -Name 'Svc'"
    )
    assert "StartupType Manual" in (
        windows_service_steps("Svc", disabled=True, running=False)[0].command or ""
    )
    assert system_launch_daemon_steps("local.web")[0].command == (
        "sudo launchctl kickstart -k system/local.web"
    )


def test_run_steps_are_taken_once_and_bounded() -> None:
    step = (ManualStep(text="打开终端，运行", command="echo hi"),)
    remember_run_steps("run_a", step)
    remember_run_steps("run_a", step)
    assert take_run_steps("run_a") == step
    assert take_run_steps("run_a") == ()
    for index in range(70):
        remember_run_steps(f"run_{index}", step)
    assert take_run_steps("run_0") == ()
    assert take_run_steps("run_69") == step
