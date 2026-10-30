"""后台程序的启动、结束卡住的进程、归属核对和环回验证。"""

from __future__ import annotations

import asyncio
import errno
import http.client
import os
import re
import socket
import ssl
import subprocess
import sys
from collections.abc import Callable, Mapping
from contextlib import suppress
from datetime import UTC, datetime
from functools import partial
from pathlib import Path

import psutil

from tunnelminion.platforms.windows.system import SystemReader
from tunnelminion.repair.contracts import (
    LaunchRecord,
    PortOwner,
    ProcessLaunchRecord,
    SpawnedProcess,
)


def redact_log_text(text: str) -> str:
    """去掉日志中常见的认证字段和令牌。"""
    text = re.sub(r"(?im)(\bauthorization[ \t]*:[ \t]*)[^\r\n]*", r"\1[REDACTED]", text)
    text = re.sub(r"(?i)\bBearer[ \t]+[^\s,;\"'<>]+", "Bearer [REDACTED]", text)
    text = re.sub(
        r"""(?i)(\b(?:token|password|api_key|secret)\b["']?[ \t]*[=:][ \t]*)"""
        r"""(?:"[^"\r\n]*"|'[^'\r\n]*'|[^\s,;&}\]"']+)""",
        r"\1[REDACTED]",
        text,
    )
    return re.sub(r"(?i)\btmn_[A-Za-z0-9_-]+", "[REDACTED]", text)


def _launch_argv(record: ProcessLaunchRecord) -> tuple[list[str], str]:
    if isinstance(record, LaunchRecord):
        return [record.interpreter, *record.arguments], record.working_directory
    if record.executable is None or record.working_directory is None:
        raise OSError("启动记录不完整")
    return [record.executable, *record.arguments], record.working_directory


class BackgroundProcessLauncher:
    """在当前账户下启动程序，仅清理本次拉起的进程树或和记录对得上的卡住进程。"""

    def __init__(
        self,
        platform: str = sys.platform,
        popen: Callable[..., subprocess.Popen[bytes]] = subprocess.Popen,
        process_factory: Callable[[int], psutil.Process] = psutil.Process,
        environ: Mapping[str, str] | None = None,
    ) -> None:
        self._platform = platform
        self._popen = popen
        self._process_factory = process_factory
        self._environ = os.environ if environ is None else environ
        # 保留句柄，避免运行中的 Popen 被回收并产生 ResourceWarning。
        self._children: list[subprocess.Popen[bytes]] = []

    def launch(self, record: ProcessLaunchRecord, *, log_path: Path) -> SpawnedProcess:
        argv, cwd = _launch_argv(record)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        env = {
            key: value
            for key, value in self._environ.items()
            if not key.startswith("TUNNELMINION_")
        }
        with log_path.open("ab") as output:
            spawn = partial(
                self._popen,
                argv,
                cwd=cwd,
                stdin=subprocess.DEVNULL,
                stdout=output,
                stderr=subprocess.STDOUT,
                close_fds=True,
                env=env,
            )
            if self._platform == "win32":
                breakaway = getattr(subprocess, "CREATE_BREAKAWAY_FROM_JOB", 0x01000000)
                flags = (
                    getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0x00000200)
                    | getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
                    | breakaway
                )
                try:
                    child = spawn(creationflags=flags)
                except OSError as exc:
                    if getattr(exc, "winerror", None) != 5 and exc.errno not in {
                        errno.EACCES,
                        errno.EPERM,
                    }:
                        raise
                    child = spawn(creationflags=flags & ~breakaway)
            else:
                child = spawn(start_new_session=True)
        self._children.append(child)
        try:
            started_at = datetime.fromtimestamp(self._process_factory(child.pid).create_time(), UTC)
        except (psutil.Error, OSError) as exc:
            raise OSError("无法核对新进程的启动时间") from exc
        return SpawnedProcess(pid=child.pid, started_at=started_at, log_path=str(log_path))

    def end_stuck(
        self,
        pid: int,
        started_at: datetime,
        launch: ProcessLaunchRecord,
        *,
        grace_seconds: float,
    ) -> bool | None:
        try:
            process = self._process_factory(pid)
            if abs(process.create_time() - started_at.timestamp()) > 1:
                return False
            # 动手前再核对一次：进程号和启动时间对得上，命令却变了，就不是记录里那个程序。
            if not _matches_launch(process, launch):
                return None
            processes = [*process.children(recursive=True), process]
            for target in processes:
                with suppress(psutil.Error, OSError):
                    target.terminate()
            _, alive = psutil.wait_procs(processes, timeout=grace_seconds)
            if not alive:
                return False
            for target in alive:
                with suppress(psutil.Error, OSError):
                    target.kill()
            _, alive = psutil.wait_procs(alive, timeout=3)
            return None if alive else True
        except psutil.NoSuchProcess:
            return False
        except (psutil.Error, OSError):
            return None

    def is_alive(self, spawned: SpawnedProcess) -> bool:
        try:
            process = self._process_factory(spawned.pid)
            return (
                process.is_running()
                and process.status() != psutil.STATUS_ZOMBIE
                and abs(process.create_time() - spawned.started_at.timestamp()) <= 1
            )
        except (psutil.Error, OSError):
            return False

    def stop(self, spawned: SpawnedProcess) -> bool:
        try:
            process = self._process_factory(spawned.pid)
            if abs(process.create_time() - spawned.started_at.timestamp()) > 1:
                return True
            processes = [*process.children(recursive=True), process]
            for target in processes:
                with suppress(psutil.Error, OSError):
                    target.terminate()
            _, alive = psutil.wait_procs(processes, timeout=5)
            for target in alive:
                with suppress(psutil.Error, OSError):
                    target.kill()
            _, alive = psutil.wait_procs(alive, timeout=3)
            return not alive
        except psutil.NoSuchProcess:
            return True
        except (psutil.Error, OSError):
            return False

    def log_tail(self, log_path: Path, *, lines: int) -> str:
        if lines <= 0:
            return ""
        try:
            with log_path.open("rb") as stream:
                stream.seek(0, os.SEEK_END)
                stream.seek(max(0, stream.tell() - 65536))
                text = stream.read(65536).decode("utf-8", errors="replace")
        except FileNotFoundError:
            return ""
        return "\n".join(redact_log_text(text).splitlines()[-lines:])[-4000:]


class PsutilHostInspector:
    """核对当前账户及 TCP 监听进程，不修改系统状态。"""

    def __init__(
        self,
        reader: SystemReader,
        *,
        process_factory: Callable[[int], psutil.Process] = psutil.Process,
    ) -> None:
        self._reader = reader
        self._process_factory = process_factory

    def current_username(self) -> str:
        return self._process_factory(os.getpid()).username()

    def port_owner(self, port: int, launch: ProcessLaunchRecord | None = None) -> PortOwner | None:
        for listener in self._reader.listeners():
            if listener.protocol != "tcp" or listener.port != port:
                continue
            matches_launch = False
            started_at: datetime | None = None
            if listener.pid is not None:
                try:
                    process = self._process_factory(listener.pid)
                    started_at = datetime.fromtimestamp(process.create_time(), UTC)
                    if launch is not None:
                        matches_launch = _matches_launch(process, launch)
                except (psutil.Error, OSError):
                    pass
            return PortOwner(
                pid=listener.pid,
                process_name=listener.process_name,
                matches_launch=matches_launch,
                started_at=started_at,
            )
        return None


def _same_path(left: str, right: str) -> bool:
    return os.path.normcase(os.path.normpath(left)) == os.path.normcase(os.path.normpath(right))


def _matches_launch(process: psutil.Process, launch: ProcessLaunchRecord) -> bool:
    """参数、工作目录和账户一致；普通程序还要求可执行文件一致。

    Python 脚本不比对解释器路径：Windows 虚拟环境里的 python.exe 只是转发器，真正监听端口的
    是它拉起的另一个解释器，记录里存的可能是转发器的路径。
    """
    if isinstance(launch, LaunchRecord):
        return (
            tuple(process.cmdline()[1:]) == launch.arguments
            and _same_path(process.cwd(), launch.working_directory)
            and process.username() == launch.username
        )
    if launch.elevated or launch.executable is None or launch.working_directory is None:
        return False
    return (
        _same_path(process.exe(), launch.executable)
        and tuple(process.cmdline()[1:]) == launch.arguments
        and _same_path(process.cwd(), launch.working_directory)
        and process.username() == launch.username
    )


# 巡检探测：连接最多等这么久；连上以后对方这么久一个字节都不回才算"不回应"。
# 只是慢的服务在这个时间内总会回点什么，不会被当成卡住。
PROBE_CONNECT_SECONDS = 2.0
PROBE_REPLY_SECONDS = 10.0
# 第一次回复不是 HTTP 时改试 HTTPS，这一步最多等这么久。
PROBE_TLS_SECONDS = 5.0
_STATUS_LINE = re.compile(rb"HTTP/\d(?:\.\d)? (\d{3})")


def _connect_loopback(port: int) -> socket.socket:
    """连本机环回地址，先 IPv4 后 IPv6；都连不上抛 `ConnectionError`。"""
    for host in ("127.0.0.1", "::1"):
        try:
            return socket.create_connection((host, port), timeout=PROBE_CONNECT_SECONDS)
        except OSError:
            continue
    raise ConnectionError(port)


class SocketLocalVerifier:
    """仅连接本机环回地址，阻塞 IO 在线程里运行；每一步都有自己的超时，线程总会自己结束。"""

    async def talks_first(self, port: int) -> bool | None:
        """连上以后不发任何东西：对方先说话返回 True，10 秒都不说话返回 False，连不上返回 None。"""
        return await asyncio.to_thread(self._talks_first, port)

    @staticmethod
    def _talks_first(port: int) -> bool | None:
        try:
            connection = _connect_loopback(port)
        except ConnectionError:
            return None
        with connection:
            connection.settimeout(PROBE_REPLY_SECONDS)
            try:
                return bool(connection.recv(1))
            except TimeoutError:
                return False
            except OSError:
                return None

    async def patrol_web_status(self, port: int) -> int | None:
        """巡检用的首页探测：返回 HTTP 状态码；连上以后 10 秒一个字节都不回返回 None。

        连不上、或者回了话但读不出状态码时抛 `ConnectionError`，表示这一轮看不清。
        先说 HTTP；只有对方很快回了非 HTTP 的内容或直接断开，才改试 HTTPS，超时后不再试。
        """
        return await asyncio.to_thread(self._patrol_web_status, port)

    @staticmethod
    def _patrol_web_status(port: int) -> int | None:
        with _connect_loopback(port) as connection:
            connection.settimeout(PROBE_REPLY_SECONDS)
            try:
                connection.sendall(
                    b"GET / HTTP/1.0\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
                )
                head = connection.recv(64)
            except TimeoutError:
                return None
            except OSError:
                head = b""
        matched = _STATUS_LINE.match(head)
        if matched is not None:
            return int(matched.group(1))
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        secure = http.client.HTTPSConnection(
            "127.0.0.1", port, timeout=PROBE_TLS_SECONDS, context=context
        )
        try:
            secure.request("GET", "/")
            return secure.getresponse().status
        except (OSError, http.client.HTTPException) as exc:
            raise ConnectionError(port) from exc
        finally:
            secure.close()

    async def port_listening(self, port: int) -> bool:
        return await asyncio.to_thread(self._port_listening, port)

    @staticmethod
    def _port_listening(port: int) -> bool:
        for host in ("127.0.0.1", "::1"):
            try:
                with socket.create_connection((host, port), timeout=1):
                    return True
            except OSError:
                continue
        return False

    async def web_status(self, port: int) -> int | None:
        return await asyncio.to_thread(self._web_status, port)

    @staticmethod
    def _web_status(port: int) -> int | None:
        for secure in (False, True):
            if secure:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                connection = http.client.HTTPSConnection(
                    "127.0.0.1", port, timeout=2, context=context
                )
            else:
                connection = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
            try:
                connection.request("GET", "/")
                response = connection.getresponse()
                response.read(16384)
                return response.status
            except (OSError, http.client.HTTPException):
                pass
            finally:
                connection.close()
        return None
