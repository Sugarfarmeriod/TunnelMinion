"""仅在当前节点访问的模型秘密存储。"""

from __future__ import annotations

import hashlib
import importlib
import json
import logging
import os
import subprocess
import sys
import threading
from collections.abc import Callable, Generator
from concurrent.futures import Future
from contextlib import contextmanager, suppress
from pathlib import Path
from queue import SimpleQueue
from time import monotonic
from typing import Any, Protocol, cast

import keyring
from keyring.errors import KeyringError

logger = logging.getLogger(__name__)


class SecretStoreError(RuntimeError):
    """不回显秘密的本机密钥存储错误。"""


KEYCHAIN_APPROVAL_HINT = (
    "系统钥匙串在等你授权：请在 Mac 屏幕上的钥匙串弹框点“始终允许”"
    "（这是把密钥从钥匙串搬到本机文件的最后一次），点完马上就能用。"
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

    给了 `vault` 时读写都交给它（macOS 上是 `FileSecretVault`，秘密存成本账户的文件）；否则
    每个秘密各占系统密钥环的一条（Windows 凭据管理器）。线程是守护线程，进程退出不等它。
    """

    def __init__(
        self, *, wait_seconds: float | None = None, vault: SecretVault | None = None
    ) -> None:
        self._wait_seconds = wait_seconds
        self._vault = vault
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
        vault = self._vault
        if vault is None:
            self._submit(lambda: keyring.set_password(service, name, value)).result()
        else:
            self._submit(lambda: vault.set(service, name, value)).result()

    def delete(self, service: str, name: str) -> None:
        """删除条目，等到完成；条目原本不存在时同样视为成功。"""
        vault = self._vault
        if vault is None:
            self._submit(lambda: _remove_item(service, name)).result()
        else:
            self._submit(lambda: vault.delete(service, name)).result()

    def _read(self, key: tuple[str, str]) -> str | None:
        try:
            if self._vault is None:
                return keyring.get_password(*key)
            return self._vault.get(*key)
        finally:
            with self._lock:
                self._reads.pop(key, None)

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


def _remove_item(service: str, name: str) -> None:
    if keyring.get_password(service, name) is not None:
        keyring.delete_password(service, name)


class SecretVault(Protocol):
    """把所有秘密存在一处的后端；读写都在 `KeyringAccess` 的后台线程里调用。"""

    def get(self, service: str, name: str) -> str | None: ...

    def set(self, service: str, name: str, value: str) -> None: ...

    def delete(self, service: str, name: str) -> None: ...


# 更早的版本在 macOS 钥匙串里把所有秘密合存的那一条：服务名 `TunnelMinion`，账户 `all-secrets`。
KEYCHAIN_VAULT_ACCOUNT = "all-secrets"
_VAULT_VERSION = 1
SECRET_FILE_NAME = "secrets.json"
_LOCK_FILE_NAME = "secrets.lock"
# 文件里记下钥匙串的合并条目已经整个搬过来了，以后不再读它。
_IMPORTED = "keychain_imported"


class SecretFileError(KeyringError):
    """秘密文件读不了、写不了或内容读不懂；不覆盖它，以免丢掉里面的秘密。"""


def _empty_vault() -> dict[str, Any]:
    return {"version": _VAULT_VERSION, "items": {}, "settled": {}}


def _parse_vault(raw: str, source: str) -> dict[str, Any]:
    try:
        data = json.loads(raw)
    except ValueError as exc:
        raise SecretFileError(f"{source}的内容无法解析") from exc
    if not isinstance(data, dict) or not _valid_vault(cast(dict[str, Any], data)):
        raise SecretFileError(f"{source}的格式不受支持")
    return cast(dict[str, Any], data)


class FileSecretVault:
    """macOS 上把所有秘密存成本账户才能读的一个 JSON 文件，不再放进钥匙串。

    钥匙串按程序的指纹（cdhash）授权，没有 Apple 开发者证书的程序每换一个运行包都会重新弹授权框；
    存成文件以后换包不弹框，从 ssh 启动的进程也能用。保护级别和 Windows 凭据管理器一样：本账户下
    运行的程序都能读到，别的账户读不到。

    - 文件在 `directory/secrets.json`，目录 0700、文件 0600，先写临时文件再原子替换。内容格式和
      更早版本钥匙串里的合并条目相同：`items` 按服务名、条目名存值，`settled` 记下已经查过旧位置
      的名字。
    - 读取前检查属主和权限：属主不是当前用户时拒绝读取；权限比 0600 宽时像 SSH 私钥那样改回 0600
      （目录改回 0700），并写一条日志说明原因。
    - 改动先读后写，同一用户的网页、网关和命令行可能同时在改，所以改动时持有同目录 `secrets.lock`
      上的文件锁。

    迁移：第一次遇到文件里没有记录的名字时，把钥匙串的合并条目整个搬进文件（只读一次，主人点一次
    “允许”就够）；合并条目也不知道的名字，再去更早版本按条目分开存的旧条目找。找到就写进文件；钥匙串
    明确回答“条目不存在”才记为查过。钥匙串打不开（例如从 ssh 启动的进程）或在等
    授权框时，钥匙串调用抛错或一直不返回，这时什么都不写，下次读取再查，绝不把这个名字当成不存在：
    否则身份密钥会被当成没有而重新生成。钥匙串里的条目原样留着，删除它们也要过授权框。
    """

    def __init__(
        self,
        directory: Path,
        *,
        migrate_from_keychain: bool = True,
        keychain_has: Callable[[str, str], bool | None] | None = None,
    ) -> None:
        self._directory = directory
        self._path = directory / SECRET_FILE_NAME
        self._lock_path = directory / _LOCK_FILE_NAME
        self._migrate = migrate_from_keychain
        self._keychain_has = keychain_has or keychain_item_exists

    @property
    def path(self) -> Path:
        return self._path

    def get(self, service: str, name: str) -> str | None:
        data = self._load()
        if _known(data, service, name):
            return _items(data, service).get(name)
        if not self._migrate:
            return None
        # 钥匙串打不开、拒绝访问或不允许弹框时下面两步会抛错，文件什么都不改。
        imported = data.get(_IMPORTED) is True
        merged = None
        if not imported and self._exists(KEYRING_SERVICE_NAME, KEYCHAIN_VAULT_ACCOUNT):
            merged = _read_merged_keychain_item()
        legacy = None
        if (merged is None or not _known(merged, service, name)) and self._exists(service, name):
            legacy = keyring.get_password(service, name)
        with self._locked():
            data = self._load()
            if data.get(_IMPORTED) is not True:
                # 合并条目一次整个搬过来：主人只点了一次“允许”时，后面的名字不会再弹框。
                if merged is not None:
                    _absorb(data, merged)
                data[_IMPORTED] = True
            if not _known(data, service, name):
                if legacy is not None:
                    _items(data, service)[name] = legacy
                _settle(data, service, name)
            self._save(data)
            return _items(data, service).get(name)

    def _exists(self, service: str, name: str) -> bool:
        """先只查钥匙串里有没有这个条目：不读内容，不触发授权框，ssh 会话里也能查。

        条目存在时才去读内容，那一步可能弹框，或者在 ssh 会话里报错。查不清（`None`）时抛错，
        什么都不写，绝不当成“不存在”。
        """
        exists = self._keychain_has(service, name)
        if exists is None:
            raise SecretFileError("现在查不了钥匙串里有没有旧的密钥，请在 Mac 桌面上启动一次")
        return exists

    def set(self, service: str, name: str, value: str) -> None:
        with self._locked():
            data = self._load()
            _items(data, service)[name] = value
            _settle(data, service, name)
            self._save(data)

    def delete(self, service: str, name: str) -> None:
        with self._locked():
            data = self._load()
            _items(data, service).pop(name, None)
            _settle(data, service, name)
            self._save(data)

    def _load(self) -> dict[str, Any]:
        if not self._path.exists():
            return _empty_vault()
        self._check_private(self._directory, 0o700)
        self._check_private(self._path, 0o600)
        try:
            raw = self._path.read_text(encoding="utf-8")
        except OSError as exc:
            raise SecretFileError("秘密文件读不出来") from exc
        return _parse_vault(raw, "秘密文件")

    def _check_private(self, path: Path, mode: int) -> None:
        owner, current = _owner_and_mode(path)
        user = _current_user()
        if user is not None and owner != user:
            raise SecretFileError(f"{path.name} 的属主不是当前用户，已拒绝读取")
        if current & 0o077:
            logger.warning(
                "%s 的权限是 %o，别的账户也能读写，已改回 %o", path.name, current & 0o777, mode
            )
            os.chmod(path, mode)

    def _save(self, data: dict[str, Any]) -> None:
        text = json.dumps(data, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
        temporary = self._directory / f".{SECRET_FILE_NAME}.{os.getpid()}.tmp"
        try:
            descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                stream.write(text)
                stream.flush()
                os.fsync(stream.fileno())
            os.chmod(temporary, 0o600)
            os.replace(temporary, self._path)
        except OSError as exc:
            raise SecretFileError("秘密文件写不进去") from exc
        finally:
            temporary.unlink(missing_ok=True)

    @contextmanager
    def _locked(self) -> Generator[None, None, None]:
        try:
            self._directory.mkdir(parents=True, exist_ok=True, mode=0o700)
            os.chmod(self._directory, 0o700)
            descriptor = os.open(self._lock_path, os.O_RDWR | os.O_CREAT, 0o600)
        except OSError as exc:
            raise SecretFileError("秘密目录建不起来") from exc
        try:
            with _exclusive(descriptor):
                yield
        finally:
            os.close(descriptor)


def _owner_and_mode(path: Path) -> tuple[int, int]:
    stat = path.stat()
    return stat.st_uid, stat.st_mode & 0o777


def _current_user() -> int | None:
    """当前账户的 uid；Windows 没有 uid，返回 None，不检查属主。"""
    getuid = cast(Callable[[], int] | None, getattr(os, "getuid", None))
    return getuid() if getuid is not None else None


SECURITY = "/usr/bin/security"
# `security` 找不到条目时的退出码（errSecItemNotFound）。
_SECURITY_ITEM_NOT_FOUND = 44
_SECURITY_TIMEOUT_SECONDS = 10.0


def keychain_item_exists(service: str, name: str) -> bool | None:
    """用 `security find-generic-password -s 服务名 -a 条目名`（不带 -w/-g）只查条目在不在。

    只取属性、不取内容，不触发钥匙串的授权框。返回 True 存在、False 明确不存在、None 查不清
    （命令报了别的错、超时或者找不到 `security`）。
    """
    try:
        completed = subprocess.run(
            (SECURITY, "find-generic-password", "-s", service, "-a", name),
            check=False,
            capture_output=True,
            stdin=subprocess.DEVNULL,
            timeout=_SECURITY_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if completed.returncode == 0:
        return True
    if completed.returncode == _SECURITY_ITEM_NOT_FOUND:
        return False
    return None


def _read_merged_keychain_item() -> dict[str, Any] | None:
    """读钥匙串里的合并条目；钥匙串明确回答“不存在”时返回 None。

    keyring 只在 macOS 返回“条目不存在”时给 None；钥匙串打不开、拒绝访问、不允许弹框时抛出
    `KeyringError`，原样往外抛。
    """
    raw = keyring.get_password(KEYRING_SERVICE_NAME, KEYCHAIN_VAULT_ACCOUNT)
    return _parse_vault(raw, "钥匙串里的合并条目") if raw is not None else None


def _absorb(data: dict[str, Any], merged: dict[str, Any]) -> None:
    """把钥匙串合并条目里文件还没记的名字搬进文件，文件里已有的以文件为准。"""
    for service, values in cast(dict[str, dict[str, str]], merged["items"]).items():
        for name, value in values.items():
            if not _known(data, service, name):
                _items(data, service)[name] = value
                _settle(data, service, name)
    for service, names in cast(dict[str, list[str]], merged["settled"]).items():
        for name in names:
            if not _known(data, service, name):
                _settle(data, service, name)


def _valid_vault(data: dict[str, Any]) -> bool:
    items, settled = data.get("items"), data.get("settled")
    if data.get("version") != _VAULT_VERSION:
        return False
    if not isinstance(items, dict) or not isinstance(settled, dict):
        return False
    items_ok = all(
        isinstance(values, dict)
        and all(isinstance(value, str) for value in cast(dict[str, Any], values).values())
        for values in cast(dict[str, Any], items).values()
    )
    settled_ok = all(
        isinstance(names, list) and all(isinstance(name, str) for name in cast(list[Any], names))
        for names in cast(dict[str, Any], settled).values()
    )
    return items_ok and settled_ok


def _items(data: dict[str, Any], service: str) -> dict[str, str]:
    return cast(dict[str, str], data["items"].setdefault(service, {}))


def _known(data: dict[str, Any], service: str, name: str) -> bool:
    return name in _items(data, service) or name in data["settled"].get(service, ())


def _settle(data: dict[str, Any], service: str, name: str) -> None:
    names = cast(list[str], data["settled"].setdefault(service, []))
    if name not in names:
        names.append(name)
        names.sort()


@contextmanager
def _exclusive(descriptor: int) -> Generator[None, None, None]:
    """跨进程独占锁：Windows 用 `msvcrt.locking`，其他系统用 `fcntl.flock`。"""
    if os.name == "nt":
        msvcrt = cast(Any, importlib.import_module("msvcrt"))
        msvcrt.locking(descriptor, msvcrt.LK_LOCK, 1)
        try:
            yield
        finally:
            os.lseek(descriptor, 0, os.SEEK_SET)
            msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
    else:
        fcntl = cast(Any, importlib.import_module("fcntl"))
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)


def default_secret_directory() -> Path:
    """macOS 秘密文件所在的目录。"""
    return Path.home() / ".tunnelminion" / "secrets"


def default_secret_vault(platform: str = sys.platform) -> FileSecretVault | None:
    """只在 macOS 上把秘密存成文件。

    Windows 凭据管理器不按程序弹框，继续每个秘密各存一条。
    """
    if platform != "darwin":
        return None
    return FileSecretVault(default_secret_directory())


_shared_access = KeyringAccess(vault=default_secret_vault())


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
