"""仅在当前节点访问的模型秘密存储。"""

from __future__ import annotations

import hashlib
import os
from collections.abc import Callable
from contextlib import suppress
from pathlib import Path
from typing import Protocol

import keyring
from keyring.errors import KeyringError


class SecretStoreError(RuntimeError):
    """不回显秘密的本机密钥存储错误。"""


class SecretStore(Protocol):
    """模型配置服务依赖的最小秘密存储接口。"""

    def get(self, name: str) -> str | None:
        """读取当前节点的指定秘密。"""
        ...

    def set(self, name: str, value: str) -> None:
        """保存当前节点的指定秘密。"""
        ...

    def delete(self, name: str) -> None:
        """删除当前节点的指定秘密。"""
        ...


KEYRING_SERVICE_NAME = "TunnelMinion"


class KeyringSecretStore:
    """使用 Windows Credential Manager 或 macOS Keychain 保存秘密。"""

    def __init__(self, service_name: str = KEYRING_SERVICE_NAME) -> None:
        self._service_name = service_name

    def get(self, name: str) -> str | None:
        """从操作系统密钥环读取秘密。"""
        try:
            return keyring.get_password(self._service_name, name)
        except KeyringError as exc:
            raise SecretStoreError("无法读取本机模型密钥") from exc

    def set(self, name: str, value: str) -> None:
        """把秘密保存到操作系统密钥环。"""
        try:
            keyring.set_password(self._service_name, name, value)
        except KeyringError as exc:
            raise SecretStoreError("无法保存本机模型密钥") from exc

    def delete(self, name: str) -> None:
        """删除秘密；秘密原本不存在时同样视为成功。"""
        try:
            existing = keyring.get_password(self._service_name, name)
            if existing is not None:
                keyring.delete_password(self._service_name, name)
        except KeyringError as exc:
            raise SecretStoreError("无法删除本机模型密钥") from exc


class DataDirKeyringSecretStore:
    """只属于一个数据目录的钥匙串条目：服务名是 `TunnelMinion/<数据目录的节点编号>`。

    同一台电脑上的每个数据目录各用一组条目，互不覆盖，删掉一个数据目录也不会挡住另一个。
    更早的版本把所有数据目录的条目写在不带编号的服务名 `TunnelMinion` 下（`legacy`）：读取时本组
    没有、名字又不以 `isolated_prefix` 开头的条目，从旧服务名复制过来再用，旧条目原样保留（别的
    数据目录可能也在用）。以 `isolated_prefix` 开头的条目（身份密钥）从不自动沿用，由调用方核对
    数据库里的指纹后再迁移。

    `scope` 返回已有的节点编号（数据目录还没有时返回空，读取一律视为不存在）；`create_scope`
    在第一次写入时创建并返回它。
    """

    def __init__(
        self,
        scope: Callable[[], str | None],
        create_scope: Callable[[], str],
        *,
        isolated_prefix: str,
    ) -> None:
        self._scope = scope
        self._create_scope = create_scope
        self._isolated_prefix = isolated_prefix
        self.legacy = KeyringSecretStore()

    def get(self, name: str) -> str | None:
        scope = self._scope()
        if scope is None:
            return None
        store = self._store(scope)
        value = store.get(name)
        if value is None and not name.startswith(self._isolated_prefix):
            value = self.legacy.get(name)
            if value is not None:
                # 复制失败不影响这次读取，下次读取会再复制。
                with suppress(SecretStoreError):
                    store.set(name, value)
        return value

    def set(self, name: str, value: str) -> None:
        self._store(self._create_scope()).set(name, value)

    def delete(self, name: str) -> None:
        scope = self._scope()
        if scope is not None:
            self._store(scope).delete(name)

    @staticmethod
    def _store(scope: str) -> KeyringSecretStore:
        return KeyringSecretStore(f"{KEYRING_SERVICE_NAME}/{scope}")


class RestrictedFileSecretStore:
    """供无图形 Keychain 会话显式使用的当前账户受限秘密存储。"""

    def __init__(self, root: Path) -> None:
        self._root = root

    def get(self, name: str) -> str | None:
        """仅在文件没有组/其他账户权限时读取秘密。"""
        path = self._path(name)
        if not path.exists():
            return None
        if os.name != "nt" and path.stat().st_mode & 0o077:
            raise SecretStoreError("秘密文件权限过宽，已拒绝读取")
        return path.read_text(encoding="utf-8")

    def set(self, name: str, value: str) -> None:
        """以目录 700、文件 600 和原子替换保存秘密。"""
        self._root.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self._root, 0o700)
        path = self._path(name)
        temporary = path.with_suffix(".tmp")
        temporary.write_text(value, encoding="utf-8")
        os.chmod(temporary, 0o600)
        temporary.replace(path)
        os.chmod(path, 0o600)

    def delete(self, name: str) -> None:
        """删除当前名称对应的秘密文件。"""
        self._path(name).unlink(missing_ok=True)

    def _path(self, name: str) -> Path:
        digest = hashlib.sha256(name.encode()).hexdigest()
        return self._root / f"{digest}.secret"
