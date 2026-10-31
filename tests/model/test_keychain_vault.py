"""钥匙串合并条目：所有秘密存一条、旧条目自动迁移、跨进程改动不互相覆盖。"""

from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from tunnelminion.model import secrets
from tunnelminion.model.secrets import (
    VAULT_ACCOUNT,
    KeychainVault,
    KeyringAccess,
    KeyringSecretStore,
    SecretStoreApprovalPendingError,
    SecretStoreError,
    default_keychain_vault,
)

VAULT = ("TunnelMinion", VAULT_ACCOUNT)


class FakeKeyring:
    """按（服务名, 条目名）存值的假钥匙串，记下每次读写。"""

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.values: dict[tuple[str, str], str] = {}
        self.reads: list[tuple[str, str]] = []
        self.writes: list[tuple[str, str]] = []
        self.deletes: list[tuple[str, str]] = []
        monkeypatch.setattr("keyring.get_password", self.get_password)
        monkeypatch.setattr("keyring.set_password", self.set_password)
        monkeypatch.setattr("keyring.delete_password", self.delete_password)

    def get_password(self, service: str, name: str) -> str | None:
        self.reads.append((service, name))
        return self.values.get((service, name))

    def set_password(self, service: str, name: str, value: str) -> None:
        self.writes.append((service, name))
        self.values[(service, name)] = value

    def delete_password(self, service: str, name: str) -> None:
        self.deletes.append((service, name))
        del self.values[(service, name)]

    def vault(self) -> dict[str, Any]:
        return json.loads(self.values[VAULT])


@pytest.fixture
def fake(monkeypatch: pytest.MonkeyPatch) -> FakeKeyring:
    return FakeKeyring(monkeypatch)


def store(tmp_path: Path, service: str = "TunnelMinion") -> KeyringSecretStore:
    access = KeyringAccess(vault=KeychainVault(tmp_path / "vault.lock"))
    return KeyringSecretStore(service, access=access)


def test_all_secrets_share_one_keychain_item(fake: FakeKeyring, tmp_path: Path) -> None:
    model = store(tmp_path)
    scoped = KeyringSecretStore("TunnelMinion/node", access=model._access)  # pyright: ignore[reportPrivateUsage]
    model.set("model-provider-api-key", "fixture-model")
    scoped.set("trust-owner-key", "fixture-owner")

    assert set(fake.values) == {VAULT}
    assert fake.vault()["items"] == {
        "TunnelMinion": {"model-provider-api-key": "fixture-model"},
        "TunnelMinion/node": {"trust-owner-key": "fixture-owner"},
    }
    assert model.get("model-provider-api-key") == "fixture-model"
    assert scoped.get("trust-owner-key") == "fixture-owner"


def test_legacy_items_are_read_once_moved_and_left_in_place(
    fake: FakeKeyring, tmp_path: Path
) -> None:
    fake.values[("TunnelMinion/node", "trust-owner-key")] = "fixture-owner"
    scoped = store(tmp_path, "TunnelMinion/node")

    assert scoped.get("trust-owner-key") == "fixture-owner"
    assert scoped.get("trust-owner-key") == "fixture-owner"
    assert scoped.get("never-saved") is None
    assert scoped.get("never-saved") is None

    # 每个旧条目只读一次；旧条目保留，不删除也不改写。
    assert fake.reads.count(("TunnelMinion/node", "trust-owner-key")) == 1
    assert fake.reads.count(("TunnelMinion/node", "never-saved")) == 1
    assert fake.values[("TunnelMinion/node", "trust-owner-key")] == "fixture-owner"
    assert fake.deletes == []
    assert fake.vault()["settled"] == {"TunnelMinion/node": ["never-saved", "trust-owner-key"]}


def test_deleted_secret_does_not_come_back_from_the_legacy_item(
    fake: FakeKeyring, tmp_path: Path
) -> None:
    fake.values[("TunnelMinion", "model-provider-api-key")] = "fixture-old"
    model = store(tmp_path)
    model.delete("model-provider-api-key")
    model.delete("model-provider-api-key")

    assert model.get("model-provider-api-key") is None
    assert ("TunnelMinion", "model-provider-api-key") not in fake.reads
    assert fake.values[("TunnelMinion", "model-provider-api-key")] == "fixture-old"


def test_waiting_for_approval_of_a_legacy_item_changes_nothing(
    fake: FakeKeyring, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake.values[("TunnelMinion", "model-provider-api-key")] = "fixture-model"
    release = threading.Event()
    original = fake.get_password

    def slow(service: str, name: str) -> str | None:
        if (service, name) != VAULT:
            release.wait(5)
        return original(service, name)

    monkeypatch.setattr("keyring.get_password", slow)
    access = KeyringAccess(wait_seconds=0.05, vault=KeychainVault(tmp_path / "vault.lock"))
    model = KeyringSecretStore(access=access)

    with pytest.raises(SecretStoreApprovalPendingError):
        model.get("model-provider-api-key")
    assert VAULT not in fake.values

    release.set()
    access.limit_wait(5)
    assert model.get("model-provider-api-key") == "fixture-model"
    assert fake.vault()["items"]["TunnelMinion"] == {"model-provider-api-key": "fixture-model"}


def test_a_value_saved_while_migrating_wins_over_the_legacy_value(
    fake: FakeKeyring, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake.values[("TunnelMinion", "token")] = "fixture-old"
    vault = KeychainVault(tmp_path / "vault.lock")
    original = fake.get_password

    def racing(service: str, name: str) -> str | None:
        value = original(service, name)
        if (service, name) == ("TunnelMinion", "token"):
            # 读旧条目期间另一个进程已经写入了新值。
            KeychainVault(tmp_path / "vault.lock").set("TunnelMinion", "token", "fixture-new")
        return value

    monkeypatch.setattr("keyring.get_password", racing)
    assert vault.get("TunnelMinion", "token") == "fixture-new"
    assert fake.vault()["items"]["TunnelMinion"] == {"token": "fixture-new"}


def test_concurrent_writers_do_not_lose_each_others_secrets(
    fake: FakeKeyring, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = fake.set_password

    def slow_write(service: str, name: str, value: str) -> None:
        time.sleep(0.02)
        original(service, name, value)

    monkeypatch.setattr("keyring.set_password", slow_write)
    errors: list[BaseException] = []

    def writer(index: int) -> None:
        try:
            KeychainVault(tmp_path / "vault.lock").set("TunnelMinion", f"name-{index}", "x")
        except BaseException as exc:  # pragma: no cover - 只在失败时用于诊断
            errors.append(exc)

    threads = [threading.Thread(target=writer, args=(index,)) for index in range(6)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert errors == []
    assert set(fake.vault()["items"]["TunnelMinion"]) == {f"name-{index}" for index in range(6)}


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
def test_unreadable_vault_is_never_overwritten(
    fake: FakeKeyring, tmp_path: Path, content: str
) -> None:
    fake.values[VAULT] = content
    model = store(tmp_path)
    with pytest.raises(SecretStoreError, match="读取"):
        model.get("model-provider-api-key")
    with pytest.raises(SecretStoreError, match="保存"):
        model.set("model-provider-api-key", "fixture-model")
    with pytest.raises(SecretStoreError, match="删除"):
        model.delete("model-provider-api-key")
    assert fake.values[VAULT] == content
    assert "fixture-model" not in str(fake.values)


def test_vault_is_only_used_on_macos(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    assert default_keychain_vault("win32") is None
    vault = default_keychain_vault("darwin")
    assert isinstance(vault, KeychainVault)
    assert vault._lock_path == tmp_path / ".tunnelminion" / "keychain-vault.lock"  # pyright: ignore[reportPrivateUsage]


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
        ["locking-1", "inside", "locking-0"]
        if system == "nt"
        else [
            "flock-2",
            "inside",
            "flock-8",
        ]
    )
    assert calls == expected
