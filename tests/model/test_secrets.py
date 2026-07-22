"""操作系统密钥环适配器测试。"""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from keyring.errors import KeyringError

from tunnelminion.model.secrets import (
    KeyringSecretStore,
    RestrictedFileSecretStore,
    SecretStoreError,
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
