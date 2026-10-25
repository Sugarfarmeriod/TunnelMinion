"""资格核对拒绝越界对象，错误不携带本机路径和命令。"""

from pathlib import Path

import pytest
from tests.repair.fakes import FakeHost, local_launch

from tunnelminion.repair.contracts import PortOwner, RepairErrorCode
from tunnelminion.repair.eligibility import RepairRefusal, check_python


@pytest.mark.parametrize(
    ("arguments", "code"),
    [
        (("-m", "tunnelminion"), RepairErrorCode.PROTECTED_TARGET),
        (("-m", "tunnelminion.cli"), RepairErrorCode.PROTECTED_TARGET),
        (("src/TunnelMinion/app.py",), RepairErrorCode.PROTECTED_TARGET),
        (("-c", "print(1)"), RepairErrorCode.UNSUPPORTED_LAUNCH),
        (("-i", "app.py"), RepairErrorCode.UNSUPPORTED_LAUNCH),
        (("-ui", "app.py"), RepairErrorCode.UNSUPPORTED_LAUNCH),
        (("-u",), RepairErrorCode.UNSUPPORTED_LAUNCH),
        (("-m",), RepairErrorCode.UNSUPPORTED_LAUNCH),
        (("--",), RepairErrorCode.UNSUPPORTED_LAUNCH),
        (("-m", "debugpy"), RepairErrorCode.UNSUPPORTED_LAUNCH),
        (("-m", "http.server", "-i"), RepairErrorCode.UNSUPPORTED_LAUNCH),
    ],
)
def test_python_protected_and_unsupported(
    tmp_path: Path, arguments: tuple[str, ...], code: RepairErrorCode
) -> None:
    launch = local_launch(tmp_path, arguments=arguments)
    with pytest.raises(RepairRefusal) as caught:
        check_python(launch, FakeHost())
    assert caught.value.error.code is code
    encoded = caught.value.error.model_dump_json()
    assert str(tmp_path) not in encoded
    assert "print(1)" not in encoded


@pytest.mark.parametrize("missing", ["interpreter", "working_directory", "entry", "account"])
def test_python_original_files_and_account_required(tmp_path: Path, missing: str) -> None:
    launch = local_launch(tmp_path)
    host = FakeHost()
    if missing == "interpreter":
        Path(launch.interpreter).unlink()
        code = RepairErrorCode.INTERPRETER_MISSING
    elif missing == "working_directory":
        launch = launch.model_copy(update={"working_directory": str(tmp_path / "absent")})
        code = RepairErrorCode.WORKING_DIRECTORY_MISSING
    elif missing == "entry":
        (tmp_path / "app.py").unlink()
        code = RepairErrorCode.ENTRY_MISSING
    else:
        host.username = "someone-else"
        code = RepairErrorCode.OTHER_ACCOUNT
    with pytest.raises(RepairRefusal) as caught:
        check_python(launch, host)
    assert caught.value.error.code is code
    assert str(tmp_path) not in str(caught.value)


@pytest.mark.parametrize(
    "arguments",
    [
        ("app.py", "--name", "value"),
        ("--", "app.py"),
        ("-W", "ignore", "-X", "dev", "-u", "app.py"),
        ("-Wignore", "-Xdev", "app.py"),
        ("-m", "http.server", "8765"),
    ],
)
def test_python_valid_original_launches(tmp_path: Path, arguments: tuple[str, ...]) -> None:
    launch = local_launch(tmp_path, arguments=arguments)
    host = FakeHost()
    check_python(launch, host)
    assert host.calls == [(8765, launch)]


def test_python_resolves_absolute_and_relative_entry(tmp_path: Path) -> None:
    entry = tmp_path / "app.py"
    launch = local_launch(tmp_path, arguments=(str(entry),))
    check_python(launch, FakeHost())


@pytest.mark.parametrize(
    "name", [None, "other.exe", "/private/other.exe", "bad\nname", "python -m private_module"]
)
def test_python_port_owned_by_another_program(tmp_path: Path, name: str | None) -> None:
    launch = local_launch(tmp_path)
    host = FakeHost()
    host.owners[8765] = PortOwner(pid=6, process_name=name, matches_launch=False)
    with pytest.raises(RepairRefusal) as caught:
        check_python(launch, host)
    error = caught.value.error
    assert error.code is RepairErrorCode.PORT_IN_USE
    assert (
        error.message
        == f"原来的端口 8765 现在被 {'other.exe' if name == 'other.exe' else '别的程序'} 占了。"
    )
    assert error.next_step == "先关掉占用这个端口的程序，Agent 不会去停它。"


def test_python_already_running(tmp_path: Path) -> None:
    launch = local_launch(tmp_path)
    host = FakeHost()
    host.owners[8765] = PortOwner(pid=6, process_name="python.exe", matches_launch=True)
    with pytest.raises(RepairRefusal) as caught:
        check_python(launch, host)
    assert caught.value.error.code is RepairErrorCode.ALREADY_RUNNING
