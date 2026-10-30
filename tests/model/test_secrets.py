"""操作系统密钥环适配器测试。"""

from __future__ import annotations

import os
import threading
import time
from collections.abc import Callable
from pathlib import Path

import pytest
from keyring.errors import KeyringError

from tunnelminion.model.secrets import (
    KeyringAccess,
    KeyringSecretStore,
    RestrictedFileSecretStore,
    SecretStoreApprovalPendingError,
    SecretStoreError,
    shared_keyring_access,
    stop_waiting_for_keychain_approval,
)


def test_keyring_secret_store_round_trip(monkeypatch: pytest.MonkeyPatch) -> None:
    values: dict[tuple[str, str], str] = {}

    def get_password(service: str, name: str) -> str | None:
        return values.get((service, name))

    def set_password(service: str, name: str, value: str) -> None:
        values[(service, name)] = value

    def delete_password(service: str, name: str) -> None:
        values.pop((service, name))

    monkeypatch.setattr("keyring.get_password", get_password)
    monkeypatch.setattr("keyring.set_password", set_password)
    monkeypatch.setattr("keyring.delete_password", delete_password)
    store = KeyringSecretStore("test-service")
    assert store.get("api-key") is None
    store.set("api-key", "secret")
    assert store.get("api-key") == "secret"
    store.delete("api-key")
    store.delete("api-key")


@pytest.mark.parametrize(
    ("method", "message"), [("get", "读取"), ("set", "保存"), ("delete", "删除")]
)
def test_keyring_errors_are_sanitized(
    monkeypatch: pytest.MonkeyPatch, method: str, message: str
) -> None:
    def fail(*_: object) -> None:
        raise KeyringError("secret-value")

    monkeypatch.setattr("keyring.get_password", fail)
    monkeypatch.setattr("keyring.set_password", fail)
    store = KeyringSecretStore()
    with pytest.raises(SecretStoreError, match=message) as caught:
        if method == "get":
            store.get("api-key")
        elif method == "set":
            store.set("api-key", "secret-value")
        else:
            store.delete("api-key")
    assert "secret-value" not in str(caught.value)


def test_restricted_file_store_uses_hashed_names_and_account_only_permissions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """无头后端不把秘密名称写入文件名，并拒绝过宽权限。"""
    store = RestrictedFileSecretStore(tmp_path / "secrets")
    store.set("gateway-peer-token:node", "tmn_secret")
    files = tuple((tmp_path / "secrets").glob("*.secret"))
    assert len(files) == 1
    assert "gateway" not in files[0].name
    if os.name != "nt":
        assert files[0].stat().st_mode & 0o077 == 0
    assert store.get("gateway-peer-token:node") == "tmn_secret"

    files[0].chmod(0o644)
    monkeypatch.setattr("tunnelminion.model.secrets.os.name", "posix")
    with pytest.raises(SecretStoreError, match="权限过宽"):
        store.get("gateway-peer-token:node")
    store.delete("gateway-peer-token:node")
    assert store.get("gateway-peer-token:node") is None


def eventually(read: Callable[[], str | None]) -> str | None:
    """授权框点完后，后台读写在几毫秒内完成；最多等两秒。"""
    deadline = time.monotonic() + 2
    while True:
        try:
            return read()
        except SecretStoreApprovalPendingError:
            if time.monotonic() > deadline:
                raise
            time.sleep(0.01)


def test_waiting_keychain_answers_at_once_and_asks_each_entry_only_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """授权框没点时调用方不被卡住；同一条目在等的那次读取，后来的读取跟着等，不再另问系统。"""
    approved = threading.Event()
    asked: list[tuple[str, str]] = []

    def get_password(service: str, name: str) -> str | None:
        asked.append((service, name))
        approved.wait(5)
        return "secret"

    monkeypatch.setattr("keyring.get_password", get_password)
    store = KeyringSecretStore("svc", access=KeyringAccess(wait_seconds=0.05))

    for _ in range(3):
        with pytest.raises(SecretStoreApprovalPendingError, match="始终允许"):
            store.get("api-key")
    assert asked == [("svc", "api-key")]
    approved.set()
    assert eventually(lambda: store.get("api-key")) == "secret"


def test_waiting_writes_finish_after_approval_in_order(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """写入和删除等不到授权时同样立刻返回，后台按排队顺序做完。"""
    approved = threading.Event()
    values = {("svc", "token"): "old", ("svc", "other"): "gone"}

    def get_password(service: str, name: str) -> str | None:
        return values.get((service, name))

    def set_password(service: str, name: str, value: str) -> None:
        approved.wait(5)
        values[(service, name)] = value

    def delete_password(service: str, name: str) -> None:
        values.pop((service, name))

    monkeypatch.setattr("keyring.get_password", get_password)
    monkeypatch.setattr("keyring.set_password", set_password)
    monkeypatch.setattr("keyring.delete_password", delete_password)
    store = KeyringSecretStore("svc", access=KeyringAccess(wait_seconds=0.05))

    with pytest.raises(SecretStoreApprovalPendingError):
        store.set("token", "new")
    with pytest.raises(SecretStoreApprovalPendingError):
        store.delete("other")
    approved.set()
    # 队列按顺序执行：排在后面的这次读取返回时，前面的写入和删除都已做完。
    assert eventually(lambda: store.get("token")) == "new"
    assert values == {("svc", "token"): "new"}


def test_command_line_waits_for_approval_and_serving_processes_stop_waiting(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """命令行工具等主人点完弹框再继续；网页和网关开始服务后，等一秒就先回答“在等授权”。"""
    approved = threading.Event()

    def get_password(service: str, name: str) -> str | None:
        del service
        if name == "later":
            approved.wait(5)
        return name

    monkeypatch.setattr("keyring.get_password", get_password)
    threading.Timer(0.05, approved.set).start()
    assert KeyringSecretStore().get("later") == "later"

    approved.clear()
    stop_waiting_for_keychain_approval()
    started = time.monotonic()
    with pytest.raises(SecretStoreApprovalPendingError):
        shared_keyring_access().get("svc", "later")
    assert time.monotonic() - started < 3
    approved.set()
