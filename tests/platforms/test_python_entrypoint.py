"""Python 入口名提取与本机参数读取的隐私边界。"""

from __future__ import annotations

import os
from pathlib import Path

import psutil
import pytest
from pydantic import ValidationError

from tunnelminion.platforms.python_entrypoint import (
    parse_python_entrypoint,
    read_python_entrypoint,
    read_python_project_name,
)
from tunnelminion.platforms.windows.models import NetworkListener


@pytest.mark.parametrize(
    "arguments,expected",
    [
        (["python", "/home/private/相册.py", "--token", "fixture-secret"], "相册.py"),
        (["python.exe", r"C:\private folder\server.py", "fixture-secret"], "server.py"),
        (["python", "-u", "-OO", "-bbE", "app.py"], "app.py"),
        (["python", "-W", "ignore", "-X", "utf8", "app.py"], "app.py"),
        (["python", "-Wignore", "-Xutf8", "app.py"], "app.py"),
        (["python", "--", "app.py"], "app.py"),
        (["python", "-m", "http.server", "fixture-secret"], "http.server"),
        (["python", "-m", "我的应用"], "我的应用"),
        (["python", "./project"], "project"),
        (["python", "bundle.pyz"], "bundle.pyz"),
        ([], None),
        (["python"], None),
        (["python", "--"], None),
        (["python", "-W"], None),
        (["python", "-X"], None),
        (["python", "-m"], None),
        (["python", "-m", ""], None),
        (["python", "-m", "bad/module"], None),
        (["python", "-m", "bad..module"], None),
        (["python", "-m", "a" * 81], None),
        (["python", "-m", "debugpy", "--listen", "5678", "app.py"], None),
        (["python", "-m", "debugpy.adapter"], None),
        (["python", "/vscode/debugpy/launcher", "5678", "--", "app.py"], None),
        (["python", r"C:\vscode\debugpy\__main__.py", "--connect", "5678"], None),
        (["python", "/ide/pydevd.py", "--file", "app.py"], None),
        (["python", "-c", "fixture-secret", "app.py"], None),
        (["python", "-cfixture-secret", "app.py"], None),
        (["python", "-", "app.py"], None),
        (["python", "--", "-"], None),
        (["python", "-Q", "app.py"], None),
        (["python", ""], None),
        (["python", "./"], None),
        (["python", ".."], None),
        (["python", "bad\nname.py"], None),
        (["python", "a" * 81], None),
    ],
)
def test_extracts_only_a_bounded_entry_name(arguments: list[str], expected: str | None) -> None:
    assert parse_python_entrypoint(arguments) == expected


@pytest.mark.parametrize(
    "entry", ["/private/app.py", r"C:\private\app.py", "bad\nname", "a" * 81, ""]
)
def test_listener_summary_rejects_paths_and_unbounded_entry_names(entry: str) -> None:
    with pytest.raises(ValidationError):
        NetworkListener(protocol="tcp", address="127.0.0.1", port=43123, python_entrypoint=entry)


@pytest.mark.parametrize(
    "protocol,pid,name",
    [
        ("udp", 101, "python"),
        ("tcp", None, "python"),
        ("tcp", os.getpid(), "python"),
        ("tcp", 101, "node"),
        ("tcp", 101, "python-helper"),
        ("tcp", 101, None),
    ],
)
def test_does_not_read_other_processes(
    monkeypatch: pytest.MonkeyPatch, protocol: str, pid: int | None, name: str | None
) -> None:
    def unexpected(pid: int) -> object:
        raise AssertionError(f"不应查询进程 {pid}")

    monkeypatch.setattr(psutil, "Process", unexpected)
    assert (
        read_python_project_name(
            NetworkListener(
                protocol=protocol, address="127.0.0.1", port=43123, pid=pid, process_name=name
            ),
            "app.py",
        )
        is None
    )
    assert (
        read_python_entrypoint(
            NetworkListener(
                protocol=protocol, address="127.0.0.1", port=43123, pid=pid, process_name=name
            )
        )
        is None
    )


@pytest.mark.parametrize("failure", [None, "changed", "denied", "exited"])
def test_rechecks_python_identity_and_keeps_raw_arguments_local(
    monkeypatch: pytest.MonkeyPatch, failure: str | None
) -> None:
    calls: list[str] = []

    class Process:
        def __init__(self, pid: int) -> None:
            assert pid == 101

        def name(self) -> str:
            return "node" if failure == "changed" else "Python3.14.EXE"

        def cmdline(self) -> list[str]:
            calls.append("cmdline")
            if failure == "denied":
                raise psutil.AccessDenied(101, msg="fixture-secret")
            if failure == "exited":
                raise psutil.NoSuchProcess(101, msg="fixture-secret")
            return ["python", "/private/project/相册.py", "--token=fixture-secret"]

    monkeypatch.setattr(psutil, "Process", Process)
    listener = NetworkListener(
        protocol="tcp", address="127.0.0.1", port=43123, pid=101, process_name="python"
    )
    result = read_python_entrypoint(listener)
    assert result == ("相册.py" if failure is None else None)
    assert calls == ([] if failure == "changed" else ["cmdline"])
    assert "private" not in str(result) and "fixture-secret" not in str(result)


@pytest.mark.parametrize(
    "case",
    [
        "absolute",
        "relative",
        "source",
        "ambiguous",
        "module",
        "changed_entry",
        "changed_process",
        "denied",
        "denied_cwd",
        "home",
        "root",
        "generic",
        "invalid",
        "long",
    ],
)
def test_generic_entry_keeps_only_bounded_project_name(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, case: str
) -> None:
    home = tmp_path / "home"
    project = tmp_path / "private-runtime" / "Wireguard Panel"
    directory = {
        "source": project / "src",
        "generic": project / "src" / "app",
        "home": home,
        "root": Path(tmp_path.anchor),
        "invalid": tmp_path / "bad\x01name",
        "long": tmp_path / ("x" * 81),
    }.get(case, project)
    arguments = ["python", str(directory / "app.py"), "--password", "fixture-secret"]
    if case in {"relative", "denied_cwd"}:
        arguments[1] = "app.py"
    if case == "ambiguous":
        arguments.append("app.py")
    if case == "module":
        arguments = ["python", "-m", "app.py"]
    if case == "changed_entry":
        arguments[1] = "other.py"
    calls: list[str] = []

    class Process:
        def __init__(self, pid: int) -> None:
            assert pid == 101

        def name(self) -> str:
            return "node" if case == "changed_process" else "python"

        def cmdline(self) -> list[str]:
            if case == "denied":
                raise psutil.AccessDenied(101)
            return arguments

        def cwd(self) -> str:
            calls.append("cwd")
            if case == "denied_cwd":
                raise psutil.AccessDenied(101)
            return str(project)

    monkeypatch.setattr(psutil, "Process", Process)
    monkeypatch.setattr(Path, "home", lambda: home)
    listener = NetworkListener(
        protocol="tcp", address="127.0.0.1", port=8787, pid=101, process_name="python"
    )
    result = read_python_project_name(listener, "app.py")
    assert result == ("Wireguard Panel" if case in {"absolute", "relative", "source"} else None)
    assert calls == (["cwd"] if case in {"relative", "denied_cwd"} else [])
    assert "private-runtime" not in str(result) and "fixture-secret" not in str(result)
    assert read_python_project_name(listener, "photo.py") is None
