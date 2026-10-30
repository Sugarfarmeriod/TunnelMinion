"""仅在当前节点访问的模型秘密存储。"""

from __future__ import annotations

import hashlib
import os
import threading
from collections.abc import Callable
from concurrent.futures import Future
from contextlib import suppress
from pathlib import Path
from queue import SimpleQueue
from time import monotonic
from typing import Protocol, cast

import keyring
from keyring.errors import KeyringError


class SecretStoreError(RuntimeError):
    """不回显秘密的本机密钥存储错误。"""


KEYCHAIN_APPROVAL_HINT = (
    "系统钥匙串在等你授权：请在 Mac 屏幕上的钥匙串弹框点“始终允许”"
    "（可能连着弹几个，每个都点），点完马上就能用。"
)


class SecretStoreApprovalPendingError(SecretStoreError):
    """钥匙串读取在等系统授权框，调用方不必干等；后台读取会在主人点完后继续完成。"""

    def __init__(self) -> None:
        super().__init__(KEYCHAIN_APPROVAL_HINT)


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

_Job = tuple[Callable[[], object], "Future[object]"]


class KeyringAccess:
    """所有钥匙串读写都在一条后台线程里排队执行。

    macOS 换了未签名的运行包以后，每个条目第一次读写都会弹授权框，主人点之前系统调用一直不返回。
    放在后台线程里，调用方只是等结果，停止信号和 Ctrl+C 照常生效。

    - 读取最多等 `wait_seconds`（空表示等到完成）。对外服务的进程把它限制在一秒内，等不到时抛出
      `SecretStoreApprovalPendingError`，网页照常响应，后台照旧等主人点完。同一条目已有读取在排队
      时跟着等它，不会因为反复读取叠出多个弹框。读到的值不缓存，其他进程改过的密钥下次读取马上
      生效。
    - 写入和删除一律等到完成，调用方拿到的结果就是钥匙串里的实际状态，失败回滚不会被后到的写入
      覆盖。写入只在主人主动操作时发生；在事件循环里调用的地方用 `asyncio.to_thread`，网页不会
      因此卡住。

    授权框按条目计，换包后每个条目仍各弹一次。线程是守护线程，进程退出不等它。
    """

    def __init__(self, *, wait_seconds: float | None = None) -> None:
        self._wait_seconds = wait_seconds
        self._lock = threading.Lock()
        self._jobs: SimpleQueue[_Job] = SimpleQueue()
        self._worker: threading.Thread | None = None
        self._reads: dict[tuple[str, str], tuple[float, Future[object]]] = {}

    def limit_wait(self, seconds: float) -> None:
        """之后的读取最多等 `seconds` 秒。"""
        self._wait_seconds = seconds

    def get(self, service: str, name: str) -> str | None:
        """读取条目；同一条目已有读取在排队时跟着等它，不再另起一次。"""
        key = (service, name)
        with self._lock:
            pending = self._reads.get(key)
            if pending is None:
                pending = (monotonic(), self._submit(lambda: self._read(key)))
                self._reads[key] = pending
        return cast(str | None, self._result(*pending))

    def set(self, service: str, name: str, value: str) -> None:
        """写入条目，等到完成。"""
        self._submit(lambda: keyring.set_password(service, name, value)).result()

    def delete(self, service: str, name: str) -> None:
        """删除条目，等到完成；条目原本不存在时同样视为成功。"""
        self._submit(lambda: self._remove(service, name)).result()

    def _read(self, key: tuple[str, str]) -> str | None:
        try:
            return keyring.get_password(*key)
        finally:
            with self._lock:
                self._reads.pop(key, None)

    @staticmethod
    def _remove(service: str, name: str) -> None:
        if keyring.get_password(service, name) is not None:
            keyring.delete_password(service, name)

    def _result(self, started: float, future: Future[object]) -> object:
        remaining = (
            None
            if self._wait_seconds is None
            else max(0.0, started + self._wait_seconds - monotonic())
        )
        try:
            return future.result(timeout=remaining)
        except TimeoutError:
            raise SecretStoreApprovalPendingError from None

    def _submit(self, call: Callable[[], object]) -> Future[object]:
        future: Future[object] = Future()
        self._jobs.put((call, future))
        if self._worker is None:
            self._worker = threading.Thread(
                target=self._run, name="tunnelminion-keychain", daemon=True
            )
            self._worker.start()
        return future

    def _run(self) -> None:
        while True:
            call, future = self._jobs.get()
            future.set_running_or_notify_cancel()
            try:
                future.set_result(call())
            except BaseException as exc:
                future.set_exception(exc)


_shared_access = KeyringAccess()


def shared_keyring_access() -> KeyringAccess:
    """整个进程共用的钥匙串队列。"""
    return _shared_access


SERVING_KEYCHAIN_WAIT_SECONDS = 1.0


def stop_waiting_for_keychain_approval() -> None:
    """进程要对外服务时调用：之后钥匙串读取最多等一秒，等不到就先回答“在等授权”。

    命令行工具不调用，照旧等主人在弹框上点完再继续。
    """
    shared_keyring_access().limit_wait(SERVING_KEYCHAIN_WAIT_SECONDS)


class KeyringSecretStore:
    """使用 Windows Credential Manager 或 macOS Keychain 保存秘密。"""

    def __init__(
        self, service_name: str = KEYRING_SERVICE_NAME, *, access: KeyringAccess | None = None
    ) -> None:
        self._service_name = service_name
        self._access = access if access is not None else shared_keyring_access()

    def get(self, name: str) -> str | None:
        """从操作系统密钥环读取秘密。"""
        try:
            return self._access.get(self._service_name, name)
        except KeyringError as exc:
            raise SecretStoreError("无法读取本机模型密钥") from exc

    def set(self, name: str, value: str) -> None:
        """把秘密保存到操作系统密钥环。"""
        try:
            self._access.set(self._service_name, name, value)
        except KeyringError as exc:
            raise SecretStoreError("无法保存本机模型密钥") from exc

    def delete(self, name: str) -> None:
        """删除秘密；秘密原本不存在时同样视为成功。"""
        try:
            self._access.delete(self._service_name, name)
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
