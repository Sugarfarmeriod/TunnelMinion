"""macOS 秘密文件：只有本账户能读、原子写入、跨进程不互相覆盖，以及从钥匙串一次性迁移。"""

from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from keyring.errors import KeyringError, KeyringLocked

from tunnelminion.model import secrets
from tunnelminion.model.secrets import (
    KEYCHAIN_VAULT_ACCOUNT,
    FileSecretVault,
    KeyringAccess,
    KeyringSecretStore,
    SecretStoreApprovalPendingError,
    SecretStoreError,
    default_secret_directory,
    default_secret_vault,
)

MERGED = ("TunnelMinion", KEYCHAIN_VAULT_ACCOUNT)


class FakeKeychain:
    """按（服务名, 条目名）存值的假钥匙串；`failing` 里的条目读取时抛出给定的错误。"""

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.values: dict[tuple[str, str], str] = {}
        self.failing: dict[tuple[str, str], Exception] = {}
        self.reads: list[tuple[str, str]] = []
        self.writes: list[tuple[str, str]] = []
        self.deletes: list[tuple[str, str]] = []
        monkeypatch.setattr("keyring.get_password", self.get_password)
        monkeypatch.setattr("keyring.set_password", self.set_password)
        monkeypatch.setattr("keyring.delete_password", self.delete_password)

    def get_password(self, service: str, name: str) -> str | None:
        self.reads.append((service, name))
        error = self.failing.get((service, name))
        if error is not None:
            raise error
        return self.values.get((service, name))

    def set_password(self, service: str, name: str, value: str) -> None:
        self.writes.append((service, name))

    def delete_password(self, service: str, name: str) -> None:
        self.deletes.append((service, name))

    def merge(self, items: dict[str, dict[str, str]], settled: dict[str, list[str]]) -> None:
        self.values[MERGED] = json.dumps({"version": 1, "items": items, "settled": settled})


@pytest.fixture
def keychain(monkeypatch: pytest.MonkeyPatch) -> FakeKeychain:
    return FakeKeychain(monkeypatch)


def read_file(vault: FileSecretVault) -> dict[str, Any]:
    return json.loads(vault.path.read_text(encoding="utf-8"))


def store(vault: FileSecretVault, service: str = "TunnelMinion") -> KeyringSecretStore:
    return KeyringSecretStore(service, access=KeyringAccess(vault=vault))


def test_secrets_live_in_one_private_file_and_never_touch_the_keychain_on_write(
    keychain: FakeKeychain, tmp_path: Path
) -> None:
    vault = FileSecretVault(tmp_path / "secrets")
    model = store(vault)
    scoped = KeyringSecretStore("TunnelMinion/node", access=model._access)  # pyright: ignore[reportPrivateUsage]
    model.set("model-provider-api-key", "fixture-model")
    scoped.set("trust-owner-key", "fixture-owner")
    scoped.delete("trust-owner-key")

    assert read_file(vault)["items"] == {
        "TunnelMinion": {"model-provider-api-key": "fixture-model"},
        "TunnelMinion/node": {},
    }
    assert model.get("model-provider-api-key") == "fixture-model"
    assert scoped.get("trust-owner-key") is None
    assert keychain.writes == [] and keychain.deletes == [] and keychain.reads == []
    if os.name != "nt":
        assert vault.path.stat().st_mode & 0o777 == 0o600
        assert (tmp_path / "secrets").stat().st_mode & 0o777 == 0o700
    # 原子写入不留临时文件。
    assert sorted(item.name for item in (tmp_path / "secrets").iterdir()) == [
        "secrets.json",
        "secrets.lock",
    ]


def test_merged_keychain_item_is_read_and_copied_into_the_file(
    keychain: FakeKeychain, tmp_path: Path
) -> None:
    keychain.merge(
        {"TunnelMinion/node": {"trust-owner-key": "fixture-owner"}},
        {"TunnelMinion/node": ["trust-device-key", "trust-owner-key"]},
    )
    keychain.values[("TunnelMinion/node", "trust-device-key")] = "fixture-stale"
    scoped = store(FileSecretVault(tmp_path / "secrets"), "TunnelMinion/node")

    assert scoped.get("trust-owner-key") == "fixture-owner"
    # 合并条目记过已经删除的名字，不再去旧条目里找回来。
    assert scoped.get("trust-device-key") is None
    assert ("TunnelMinion/node", "trust-device-key") not in keychain.reads
    keychain.reads.clear()
    assert scoped.get("trust-owner-key") == "fixture-owner"
    assert keychain.reads == []


def test_merged_keychain_item_is_read_only_once_so_one_prompt_is_enough(
    keychain: FakeKeychain, tmp_path: Path
) -> None:
    """主人在弹框上只点了一次“允许”（不是“始终允许”）也够用：合并条目整个搬过来，不再读第二次。"""
    keychain.merge(
        {
            "TunnelMinion": {"model-provider-api-key": "fixture-model"},
            "TunnelMinion/node": {"trust-owner-key": "fixture-owner"},
        },
        {"TunnelMinion/node": ["trust-owner-key"]},
    )
    vault = FileSecretVault(tmp_path / "secrets")
    # 换包后先在网页里存过一个新值：文件里已有的以文件为准，不被钥匙串的旧值盖掉。
    vault.set("TunnelMinion", "model-provider-api-key", "fixture-new")
    assert vault.get("TunnelMinion/node", "trust-owner-key") == "fixture-owner"
    assert vault.get("TunnelMinion", "model-provider-api-key") == "fixture-new"
    assert vault.get("TunnelMinion", "unknown-name") is None
    assert keychain.reads.count(MERGED) == 1
    assert read_file(vault)["keychain_imported"] is True


def test_without_a_merged_item_only_the_legacy_items_are_asked(
    keychain: FakeKeychain, tmp_path: Path
) -> None:
    keychain.values[("TunnelMinion", "token")] = "fixture-token"
    vault = FileSecretVault(tmp_path / "secrets")
    assert vault.get("TunnelMinion", "token") == "fixture-token"
    assert vault.get("TunnelMinion", "other") is None
    assert keychain.reads == [MERGED, ("TunnelMinion", "token"), ("TunnelMinion", "other")]


def test_legacy_separate_items_are_found_when_the_merged_item_does_not_know_them(
    keychain: FakeKeychain, tmp_path: Path
) -> None:
    keychain.merge({}, {})
    keychain.values[("TunnelMinion", "model-provider-api-key")] = "fixture-model"
    vault = FileSecretVault(tmp_path / "secrets")
    model = store(vault)
    assert model.get("model-provider-api-key") == "fixture-model"
    assert model.get("never-saved") is None
    assert read_file(vault)["settled"] == {
        "TunnelMinion": ["model-provider-api-key", "never-saved"]
    }
    # 钥匙串里的条目原样留着。
    assert keychain.deletes == [] and keychain.writes == []
    keychain.reads.clear()
    assert model.get("never-saved") is None
    assert keychain.reads == []


@pytest.mark.parametrize(
    "failing",
    [MERGED, ("TunnelMinion/node", "trust-owner-key")],
    ids=["merged-item", "legacy-item"],
)
@pytest.mark.parametrize(
    "error",
    [KeyringError("interaction not allowed"), KeyringLocked("denied")],
    ids=["ssh-session", "denied"],
)
def test_an_unreadable_keychain_is_never_recorded_as_no_secret(
    keychain: FakeKeychain, tmp_path: Path, failing: tuple[str, str], error: Exception
) -> None:
    """从 ssh 启动或钥匙串拒绝访问时，绝不能把身份密钥记成“不存在”，否则会被重新生成。"""
    keychain.values[("TunnelMinion/node", "trust-owner-key")] = "fixture-owner"
    keychain.failing[failing] = error
    vault = FileSecretVault(tmp_path / "secrets")
    scoped = store(vault, "TunnelMinion/node")

    with pytest.raises(SecretStoreError):
        scoped.get("trust-owner-key")
    assert not vault.path.exists()

    # 钥匙串恢复以后照常迁移过来。
    keychain.failing.clear()
    assert scoped.get("trust-owner-key") == "fixture-owner"


def test_waiting_for_the_last_keychain_prompt_records_nothing(
    keychain: FakeKeychain, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    keychain.merge({"TunnelMinion": {"model-provider-api-key": "fixture-model"}}, {})
    release = threading.Event()
    original = keychain.get_password

    def prompt(service: str, name: str) -> str | None:
        release.wait(5)
        return original(service, name)

    monkeypatch.setattr("keyring.get_password", prompt)
    vault = FileSecretVault(tmp_path / "secrets")
    access = KeyringAccess(wait_seconds=0.05, vault=vault)
    model = KeyringSecretStore(access=access)

    with pytest.raises(SecretStoreApprovalPendingError):
        model.get("model-provider-api-key")
    assert not vault.path.exists()

    release.set()
    access.limit_wait(5)
    assert model.get("model-provider-api-key") == "fixture-model"
    assert read_file(vault)["items"]["TunnelMinion"] == {"model-provider-api-key": "fixture-model"}


def test_a_value_saved_while_migrating_wins(
    keychain: FakeKeychain, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    keychain.values[("TunnelMinion", "token")] = "fixture-old"
    original = keychain.get_password

    def racing(service: str, name: str) -> str | None:
        value = original(service, name)
        if (service, name) == ("TunnelMinion", "token"):
            # 读钥匙串期间另一个进程已经写入了新值。
            FileSecretVault(tmp_path / "secrets").set("TunnelMinion", "token", "fixture-new")
        return value

    monkeypatch.setattr("keyring.get_password", racing)
    vault = FileSecretVault(tmp_path / "secrets")
    assert vault.get("TunnelMinion", "token") == "fixture-new"


def test_concurrent_writers_do_not_lose_each_others_secrets(
    keychain: FakeKeychain, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = secrets.FileSecretVault._save  # pyright: ignore[reportPrivateUsage]

    def slow(self: FileSecretVault, data: dict[str, Any]) -> None:
        time.sleep(0.02)
        original(self, data)

    monkeypatch.setattr(secrets.FileSecretVault, "_save", slow)
    errors: list[BaseException] = []

    def writer(index: int) -> None:
        try:
            FileSecretVault(tmp_path / "secrets").set("TunnelMinion", f"name-{index}", "x")
        except BaseException as exc:  # pragma: no cover - 只在失败时用于诊断
            errors.append(exc)

    threads = [threading.Thread(target=writer, args=(index,)) for index in range(6)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert errors == []
    vault = FileSecretVault(tmp_path / "secrets")
    assert set(read_file(vault)["items"]["TunnelMinion"]) == {f"name-{i}" for i in range(6)}


def test_without_migration_unknown_names_are_simply_absent(
    keychain: FakeKeychain, tmp_path: Path
) -> None:
    vault = FileSecretVault(tmp_path / "secrets", migrate_from_keychain=False)
    assert vault.get("TunnelMinion", "anything") is None
    assert keychain.reads == []
    assert not vault.path.exists()


@pytest.mark.parametrize(
    "content",
    [
        "not json",
        json.dumps([1]),
        json.dumps({"version": 2, "items": {}, "settled": {}}),
        json.dumps({"version": 1, "items": [], "settled": {}}),
        json.dumps({"version": 1, "items": {"s": {"n": 1}}, "settled": {}}),
        json.dumps({"version": 1, "items": {"s": []}, "settled": {}}),
        json.dumps({"version": 1, "items": {}, "settled": {"s": "n"}}),
        json.dumps({"version": 1, "items": {}, "settled": {"s": [1]}}),
    ],
)
def test_unreadable_file_is_never_overwritten(
    keychain: FakeKeychain, tmp_path: Path, content: str
) -> None:
    vault = FileSecretVault(tmp_path / "secrets")
    vault.set("TunnelMinion", "seed", "x")
    vault.path.write_text(content, encoding="utf-8")
    model = store(vault)
    with pytest.raises(SecretStoreError, match="读取"):
        model.get("model-provider-api-key")
    with pytest.raises(SecretStoreError, match="保存"):
        model.set("model-provider-api-key", "fixture-model")
    with pytest.raises(SecretStoreError, match="删除"):
        model.delete("model-provider-api-key")
    assert vault.path.read_text(encoding="utf-8") == content


def test_unreadable_merged_keychain_item_blocks_migration_instead_of_guessing(
    keychain: FakeKeychain, tmp_path: Path
) -> None:
    keychain.values[MERGED] = "not json"
    vault = FileSecretVault(tmp_path / "secrets")
    with pytest.raises(SecretStoreError):
        store(vault).get("model-provider-api-key")
    assert not vault.path.exists()


def test_permissions_are_tightened_and_foreign_owner_is_refused(
    keychain: FakeKeychain,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    vault = FileSecretVault(tmp_path / "secrets")
    vault.set("TunnelMinion", "seed", "fixture-secret")
    changed: list[tuple[str, int]] = []
    owner = {"uid": 501}
    modes = {"secrets": 0o755, "secrets.json": 0o644}

    def owner_and_mode(path: Path) -> tuple[int, int]:
        return owner["uid"], modes[path.name]

    def chmod(path: str | Path, mode: int) -> None:
        changed.append((Path(path).name, mode))

    monkeypatch.setattr(secrets, "_owner_and_mode", owner_and_mode)
    monkeypatch.setattr(secrets.os, "getuid", lambda: 501, raising=False)
    monkeypatch.setattr(secrets.os, "chmod", chmod)

    # 权限过宽：像 SSH 私钥那样改回 0600 / 0700，写明原因，照常读取。
    assert vault.get("TunnelMinion", "seed") == "fixture-secret"
    assert ("secrets", 0o700) in changed and ("secrets.json", 0o600) in changed
    assert "别的账户也能读写" in caplog.text and "fixture-secret" not in caplog.text

    # 权限本来就对：不改动。
    changed.clear()
    modes.update({"secrets": 0o700, "secrets.json": 0o600})
    assert vault.get("TunnelMinion", "seed") == "fixture-secret"
    assert changed == []

    # 属主不是当前用户：拒绝读取。
    owner["uid"] = 0
    with pytest.raises(SecretStoreError):
        store(vault).get("seed")


def test_file_errors_are_reported_without_leaking_values(
    keychain: FakeKeychain, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    vault = FileSecretVault(tmp_path / "secrets")
    vault.set("TunnelMinion", "seed", "fixture-secret")

    def unreadable(*_: object, **__: object) -> str:
        raise PermissionError("denied")

    monkeypatch.setattr(Path, "read_text", unreadable)
    with pytest.raises(SecretStoreError, match="读取") as caught:
        store(vault).get("seed")
    assert "fixture-secret" not in str(caught.value)
    monkeypatch.undo()

    def unwritable(*_: object, **__: object) -> None:
        raise PermissionError("read-only")

    monkeypatch.setattr(secrets.os, "replace", unwritable)
    with pytest.raises(SecretStoreError, match="保存"):
        store(vault).set("seed", "fixture-new")
    assert vault.get("TunnelMinion", "seed") == "fixture-secret"
    assert not any(item.name.endswith(".tmp") for item in (tmp_path / "secrets").iterdir())
    monkeypatch.undo()

    blocked = tmp_path / "blocked"
    blocked.write_text("not a directory", encoding="utf-8")
    with pytest.raises(SecretStoreError, match="保存"):
        store(FileSecretVault(blocked / "secrets")).set("seed", "x")


def test_file_store_is_only_used_on_macos(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    assert default_secret_vault("win32") is None
    assert default_secret_directory() == tmp_path / ".tunnelminion" / "secrets"
    vault = default_secret_vault("darwin")
    assert isinstance(vault, FileSecretVault)
    assert vault.path == tmp_path / ".tunnelminion" / "secrets" / "secrets.json"


def test_windows_has_no_uid_so_owner_is_not_checked(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delattr(secrets.os, "getuid", raising=False)
    assert secrets._current_user() is None  # pyright: ignore[reportPrivateUsage]


@pytest.mark.parametrize("system", ["nt", "posix"])
def test_lock_uses_the_platform_file_lock(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, system: str
) -> None:
    calls: list[str] = []

    def locking(_descriptor: int, mode: int, _size: int) -> None:
        calls.append(f"locking-{mode}")

    def flock(_descriptor: int, mode: int) -> None:
        calls.append(f"flock-{mode}")

    modules = {
        "msvcrt": SimpleNamespace(LK_LOCK=1, LK_UNLCK=0, locking=locking),
        "fcntl": SimpleNamespace(LOCK_EX=2, LOCK_UN=8, flock=flock),
    }
    monkeypatch.setattr(secrets.importlib, "import_module", modules.__getitem__)
    monkeypatch.setattr(secrets.os, "name", system)
    descriptor = os.open(tmp_path / "lock", os.O_RDWR | os.O_CREAT)
    try:
        with secrets._exclusive(descriptor):  # pyright: ignore[reportPrivateUsage]
            calls.append("inside")
    finally:
        os.close(descriptor)
    expected = (
        ["locking-1", "inside", "locking-0"] if system == "nt" else ["flock-2", "inside", "flock-8"]
    )
    assert calls == expected
