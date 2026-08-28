"""macOS Stage 6 普通用户启动器的秘密边界测试。"""

from __future__ import annotations

from pathlib import Path

import pytest
import scripts.managed_path_stage6_macos_operator as subject

from tunnelminion.model.secrets import SecretStore

REPO_ROOT = Path(__file__).resolve().parents[2]


class _Pipe:
    def __init__(self) -> None:
        self.value = ""
        self.closed = False

    def write(self, value: str) -> None:
        self.value += value

    def flush(self) -> None:
        return None

    def close(self) -> None:
        self.closed = True


class _Store:
    def __init__(self, value: str) -> None:
        self._value = value

    def get(self, name: str) -> str | None:
        del name
        return self._value

    def set(self, name: str, value: str) -> None:
        del name, value

    def delete(self, name: str) -> None:
        del name


def test_launcher_passes_identity_only_through_anonymous_stdin(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private_text = "synthetic-private-material"
    pipe = _Pipe()
    captured: dict[str, object] = {}

    class Process:
        stdin = pipe

        @staticmethod
        def wait() -> int:
            return 7

    def popen(command: tuple[str, ...], **kwargs: object) -> Process:
        captured["command"] = command
        captured["kwargs"] = kwargs
        return Process()

    monkeypatch.setattr(subject.sys, "platform", "darwin")
    monkeypatch.setattr(subject.os, "geteuid", lambda: 501, raising=False)

    def identity(platform: str, *, backend: SecretStore | None = None) -> _Store:
        assert platform == "macos"
        assert backend is not None
        return _Store(private_text)

    monkeypatch.setattr(subject, "_assert_existing_identity", identity)
    monkeypatch.setattr(subject.subprocess, "Popen", popen)

    assert subject.main(["apply", "a" * 32]) == 7
    command = captured["command"]
    assert isinstance(command, tuple)
    assert command[0] == "/usr/bin/sudo"
    assert command[-3:] == ("--root", "apply", "a" * 32)
    assert private_text not in command
    assert captured["kwargs"] == {
        "stdin": subject.subprocess.PIPE,
        "text": True,
        "encoding": "utf-8",
    }
    assert pipe.value == private_text + "\n"
    assert pipe.closed is True


def test_launcher_rejects_root_before_reading_keychain(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(subject.sys, "platform", "darwin")
    monkeypatch.setattr(subject.os, "geteuid", lambda: 0, raising=False)

    def forbidden_identity(platform: str, *, backend: SecretStore | None = None) -> _Store:
        del platform, backend
        pytest.fail("Keychain must not be read as root")

    monkeypatch.setattr(subject, "_assert_existing_identity", forbidden_identity)

    with pytest.raises(SystemExit, match="普通登录用户"):
        subject.main(["apply", "a" * 32])


def test_operator_apply_prepares_isolated_execution_materials_before_launcher() -> None:
    script = (REPO_ROOT / "scripts" / "run_managed_path_stage6_operator.sh").read_text(
        encoding="utf-8"
    )
    install = '/usr/bin/sudo "$0" --root install "$barrier_id"'
    launcher = (
        'exec "$python_bin" -m scripts.managed_path_stage6_macos_operator "$mode" "$barrier_id"'
    )

    apply_branch = script.index('if [ "$mode" = "apply" ]; then')
    assert script.index(install, apply_branch) < script.index(launcher, apply_branch)
