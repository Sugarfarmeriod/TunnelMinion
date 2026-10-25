"""后台脚本的启动、归属核对和环回验证。"""

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
from tunnelminion.repair.contracts import LaunchRecord, PortOwner, SpawnedProcess


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


class BackgroundProcessLauncher:
    """在当前账户下启动脚本，仅清理本次拉起的进程树。"""

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

    def launch(self, record: LaunchRecord, *, log_path: Path) -> SpawnedProcess:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        env = {
            key: value
            for key, value in self._environ.items()
            if not key.startswith("TUNNELMINION_")
        }
        with log_path.open("ab") as output:
            spawn = partial(
                self._popen,
                [record.interpreter, *record.arguments],
                cwd=record.working_directory,
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

    def port_owner(self, port: int, launch: LaunchRecord | None = None) -> PortOwner | None:
        for listener in self._reader.listeners():
            if listener.protocol != "tcp" or listener.port != port:
                continue
            matches_launch = False
            if launch is not None and listener.pid is not None:
                try:
                    process = self._process_factory(listener.pid)
                    matches_launch = tuple(process.cmdline()[1:]) == launch.arguments and (
                        os.path.normcase(os.path.normpath(process.cwd()))
                        == os.path.normcase(os.path.normpath(launch.working_directory))
                    )
                except (psutil.Error, OSError):
                    pass
            return PortOwner(
                pid=listener.pid,
                process_name=listener.process_name,
                matches_launch=matches_launch,
            )
        return None


class SocketLocalVerifier:
    """仅连接本机环回地址，阻塞 IO 在线程里运行。"""

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
