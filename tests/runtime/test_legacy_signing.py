"""清理更早版本留下的本机签名钥匙串：只动这一项，失败不影响启动。"""

from __future__ import annotations

import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path

import pytest

from tunnelminion.runtime import legacy_signing
from tunnelminion.runtime.legacy_signing import (
    LEGACY_SIGNING_KEYCHAIN,
    legacy_signing_directory,
    remove_legacy_signing,
)


def _signed_before(home: Path) -> Path:
    directory = home / ".tunnelminion" / "code-signing"
    directory.mkdir(parents=True)
    (directory / LEGACY_SIGNING_KEYCHAIN).write_bytes(b"keychain")
    (directory / "identity.json").write_text("{}", encoding="utf-8")
    (directory / "keychain-password").write_text("fixture-password", encoding="utf-8")
    return directory


def test_old_signing_keychain_is_deleted_by_its_exact_path_then_the_directory(
    tmp_path: Path,
) -> None:
    directory = _signed_before(tmp_path)
    commands: list[tuple[str, ...]] = []

    def run(command: Sequence[str]) -> bool:
        commands.append(tuple(command))
        (directory / LEGACY_SIGNING_KEYCHAIN).unlink()
        return True

    assert remove_legacy_signing(home=tmp_path, platform_name="darwin", run=run)
    # 只删我们自己建的那一个钥匙串，不改搜索列表里的其他项。
    assert commands == [
        ("/usr/bin/security", "delete-keychain", str(directory / LEGACY_SIGNING_KEYCHAIN))
    ]
    assert not directory.exists()
    assert (tmp_path / ".tunnelminion").is_dir()

    # 清过以后再启动什么都不做。
    commands.clear()
    assert not remove_legacy_signing(home=tmp_path, platform_name="darwin", run=run)
    assert commands == []


def test_failed_delete_keeps_the_directory_for_the_next_start(tmp_path: Path) -> None:
    directory = _signed_before(tmp_path)
    assert not remove_legacy_signing(
        home=tmp_path, platform_name="darwin", run=lambda _command: False
    )
    assert (directory / LEGACY_SIGNING_KEYCHAIN).exists()

    # 钥匙串文件已经不在（主人手动删过），只剩目录：删目录即可。
    (directory / LEGACY_SIGNING_KEYCHAIN).unlink()
    assert remove_legacy_signing(home=tmp_path, platform_name="darwin", run=lambda _command: False)
    assert not directory.exists()


def test_nothing_happens_off_macos_or_without_the_old_directory(tmp_path: Path) -> None:
    _signed_before(tmp_path)

    def refuse(_command: Sequence[str]) -> bool:
        raise AssertionError("不该运行命令")

    assert not remove_legacy_signing(home=tmp_path, platform_name="win32", run=refuse)
    assert not remove_legacy_signing(home=tmp_path / "other", platform_name="darwin", run=refuse)
    assert (tmp_path / ".tunnelminion" / "code-signing").is_dir()


def test_command_runner_reports_failures_as_false(monkeypatch: pytest.MonkeyPatch) -> None:
    run = legacy_signing._run  # pyright: ignore[reportPrivateUsage]
    assert run((sys.executable, "-c", "pass"))
    assert not run((sys.executable, "-c", "raise SystemExit(1)"))
    assert not run(("tunnelminion-command-that-does-not-exist",))

    def slow(*_: object, **__: object) -> None:
        raise subprocess.TimeoutExpired("security", 30)

    monkeypatch.setattr(legacy_signing.subprocess, "run", slow)
    assert not run(("/usr/bin/security", "delete-keychain", "x"))


def test_default_directory_is_under_the_users_tunnelminion_folder(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    assert legacy_signing_directory() == tmp_path / ".tunnelminion" / "code-signing"
    assert (
        legacy_signing_directory(tmp_path / "x")
        == tmp_path / "x" / ".tunnelminion" / "code-signing"
    )
