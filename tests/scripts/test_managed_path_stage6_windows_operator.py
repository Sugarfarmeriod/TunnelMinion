from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import NoReturn, cast

import pytest

from scripts import managed_path_stage6_windows_operator as subject


class _Connection:
    def __init__(self, received: object | None = None) -> None:
        self.received = received
        self.sent: list[object] = []
        self.closed = False

    def send(self, value: object) -> None:
        if self.closed:
            raise AssertionError("cannot send after closing the pipe")
        self.sent.append(value)

    def recv(self) -> object:
        return self.received

    def close(self) -> None:
        self.closed = True


class _Listener:
    def __init__(self, connection: _Connection) -> None:
        self.connection = connection
        self.closed = False

    def accept(self) -> _Connection:
        return self.connection

    def close(self) -> None:
        self.closed = True


def test_user_identity_server_sends_private_material_once_without_printing_it(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    private_text = "private-material-for-test"
    connection = _Connection(
        {"returncode": 0, "stdout": "RECOVERED\n", "stderr": ""}
    )
    listener = _Listener(connection)
    captured: dict[str, object] = {}

    class _Process:
        @staticmethod
        def wait() -> int:
            return 0

    def existing_identity(_platform: str) -> SimpleNamespace:
        def read_identity(_name: str) -> str:
            return private_text

        return SimpleNamespace(get=read_identity)

    def token_hex(_size: int) -> str:
        return "a" * 32

    def build_listener(*_args: object, **_kwargs: object) -> _Listener:
        return listener

    def launch(command: tuple[str, ...]) -> _Process:
        captured["command"] = command
        return _Process()

    monkeypatch.setattr(
        subject,
        "_assert_existing_identity",
        existing_identity,
    )
    monkeypatch.setattr(subject.secrets, "token_hex", token_hex)
    monkeypatch.setattr(
        subject.multiprocessing.connection,
        "Listener",
        build_listener,
    )
    monkeypatch.setattr(subject.subprocess, "Popen", launch)

    assert subject._serve_identity("apply", "b" * 32) == 0  # pyright: ignore[reportPrivateUsage]

    output = capsys.readouterr().out
    assert private_text not in output
    assert "UAC" in output
    assert "RECOVERED" in output
    command = cast(tuple[str, ...], captured["command"])
    assert command[:5] == (
        "powershell.exe",
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-Command",
    )
    assert "Start-Process powershell.exe -Verb RunAs" in command[5]
    assert "IdentityPipeName" in command[5]
    assert private_text not in command[5]
    assert connection.sent == [private_text]
    assert connection.closed
    assert listener.closed


def test_elevated_process_receives_identity_only_over_pipe_and_stdin(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private_text = "private-material-for-test"
    connection = _Connection(private_text)
    captured: dict[str, object] = {}

    def run(command: list[str], **kwargs: object) -> SimpleNamespace:
        captured["command"] = command
        captured["kwargs"] = kwargs
        return SimpleNamespace(returncode=0, stdout="RECOVERED\n", stderr="")

    monkeypatch.setattr(subject, "_is_admin", lambda: True)

    def connect(*_args: object, **_kwargs: object) -> _Connection:
        return connection

    def path_exists(_self: Path) -> bool:
        return True

    monkeypatch.setattr(
        subject.multiprocessing.connection,
        "Client",
        connect,
    )
    monkeypatch.setattr(subject.subprocess, "run", run)
    monkeypatch.setattr(Path, "is_file", path_exists)

    assert (
        subject._run_elevated(  # pyright: ignore[reportPrivateUsage]
            "apply", "b" * 32, r"\\.\pipe\tunnelminion-stage6-test"
        )
        == 0
    )

    command = cast(list[str], captured["command"])
    assert private_text not in command
    assert "--identity-stdin" in command
    assert "--apply" in command
    assert captured["kwargs"] == {
        "input": private_text + "\n",
        "capture_output": True,
        "text": True,
        "encoding": "utf-8",
    }
    assert connection.sent == [
        {"returncode": 0, "stdout": "RECOVERED\n", "stderr": ""}
    ]
    assert connection.closed


def test_elevated_process_rejects_identity_echo(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private_text = "private-material-for-test"
    connection = _Connection(private_text)

    def connect(*_args: object, **_kwargs: object) -> _Connection:
        return connection

    def path_exists(_self: Path) -> bool:
        return True

    def run(*_args: object, **_kwargs: object) -> SimpleNamespace:
        return SimpleNamespace(returncode=0, stdout=private_text, stderr="")

    monkeypatch.setattr(subject, "_is_admin", lambda: True)
    monkeypatch.setattr(
        subject.multiprocessing.connection,
        "Client",
        connect,
    )
    monkeypatch.setattr(Path, "is_file", path_exists)
    monkeypatch.setattr(
        subject.subprocess,
        "run",
        run,
    )

    assert (
        subject._run_elevated(  # pyright: ignore[reportPrivateUsage]
            "recover", "b" * 32, r"\\.\pipe\tunnelminion-stage6-test"
        )
        == 1
    )
    assert private_text not in str(connection.sent)


def test_elevated_process_returns_sanitized_admin_exception(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private_text = "private-material-for-test"
    connection = _Connection(private_text)

    def connect(*_args: object, **_kwargs: object) -> _Connection:
        return connection

    def path_exists(_self: Path) -> bool:
        return True

    def run(*_args: object, **_kwargs: object) -> NoReturn:
        raise RuntimeError(f"failed near {private_text}")

    monkeypatch.setattr(subject, "_is_admin", lambda: True)
    monkeypatch.setattr(subject.multiprocessing.connection, "Client", connect)
    monkeypatch.setattr(Path, "is_file", path_exists)
    monkeypatch.setattr(subject.subprocess, "run", run)

    assert (
        subject._run_elevated(  # pyright: ignore[reportPrivateUsage]
            "recover", "b" * 32, r"\\.\pipe\tunnelminion-stage6-test"
        )
        == 1
    )
    assert private_text not in str(connection.sent)
    assert "RuntimeError" in str(connection.sent)
    assert "<redacted>" in str(connection.sent)


def test_elevated_process_rejects_non_admin_before_connecting(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(subject, "_is_admin", lambda: False)

    def reject_connect(*_args: object, **_kwargs: object) -> NoReturn:
        pytest.fail("must not connect without elevation")

    monkeypatch.setattr(
        subject.multiprocessing.connection,
        "Client",
        reject_connect,
    )

    with pytest.raises(SystemExit, match="已提升令牌"):
        subject._run_elevated(  # pyright: ignore[reportPrivateUsage]
            "recover", "b" * 32, r"\\.\pipe\tunnelminion-stage6-test"
        )
