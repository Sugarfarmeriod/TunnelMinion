"""自行安装程序的本机名称投影，不读取参数或保存路径。"""

import os
from pathlib import Path

import psutil
import pytest

from tunnelminion.platforms.program_name import read_program_name
from tunnelminion.platforms.windows.models import NetworkListener


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("/opt/homebrew/bin/gost", "gost"),
        ("/usr/local/bin/gost", "gost"),
        ("/Users/test/.local/bin/gost", "gost"),
        ("/System/Library/gost", None),
        ("/usr/sbin/gost", None),
        ("/Users/test/Applications/Browser.app/Contents/MacOS/gost", None),
        ("/Users/test/AppData/Local/browser/gost", None),
    ],
)
def test_only_user_installed_program_basename_leaves_reader(
    monkeypatch: pytest.MonkeyPatch, path: str, expected: str | None
) -> None:
    class Process:
        def __init__(self, pid: int) -> None:
            assert pid == 42

        def name(self) -> str:
            return "gost"

        def exe(self) -> str:
            return path

    monkeypatch.setattr(Path, "home", lambda: Path("/Users/test"))
    monkeypatch.setattr(psutil, "Process", Process)
    listener = NetworkListener(
        protocol="udp", address="0.0.0.0", port=9527, pid=42, process_name="gost"
    )
    assert read_program_name(listener) == expected


@pytest.mark.parametrize("failure", [psutil.AccessDenied(), psutil.NoSuchProcess(42)])
def test_unreadable_process_keeps_unknown_name(
    monkeypatch: pytest.MonkeyPatch, failure: psutil.Error
) -> None:
    def denied(pid: int) -> object:
        raise failure

    monkeypatch.setattr(psutil, "Process", denied)
    assert (
        read_program_name(NetworkListener(protocol="tcp", address="0.0.0.0", port=805, pid=42))
        is None
    )


def test_pid_reuse_does_not_attribute_the_previous_program(monkeypatch: pytest.MonkeyPatch) -> None:
    class Process:
        def __init__(self, pid: int) -> None:
            assert pid == 42

        def name(self) -> str:
            return "another-program"

        def exe(self) -> str:
            raise AssertionError("名称已变，不再读取路径")

    monkeypatch.setattr(psutil, "Process", Process)
    assert (
        read_program_name(
            NetworkListener(
                protocol="tcp", address="0.0.0.0", port=805, pid=42, process_name="gost"
            )
        )
        is None
    )


@pytest.mark.parametrize("pid", [None, os.getpid()])
def test_unknown_owner_and_current_process_are_not_selected(pid: int | None) -> None:
    assert (
        read_program_name(NetworkListener(protocol="tcp", address="0.0.0.0", port=805, pid=pid))
        is None
    )


@pytest.mark.parametrize("name", ["", "a/b", "a\\b", "\x01", "x" * 81])
def test_invalid_name_is_not_exported(monkeypatch: pytest.MonkeyPatch, name: str) -> None:
    class Process:
        def __init__(self, pid: int) -> None:
            assert pid == 42

        def name(self) -> str:
            return name

        def exe(self) -> str:
            return "/opt/bin/program"

    monkeypatch.setattr(psutil, "Process", Process)
    assert (
        read_program_name(
            NetworkListener(protocol="tcp", address="0.0.0.0", port=805, pid=42, process_name=name)
        )
        is None
    )
