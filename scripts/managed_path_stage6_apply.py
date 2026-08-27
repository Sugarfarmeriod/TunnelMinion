"""在阶段 6 批准资源上执行真实 Provider 与有界 path verify。"""

from __future__ import annotations

import argparse
import asyncio
import base64
import contextlib
import ctypes
import hashlib
import ipaddress
import json
import os
import re
import secrets
import signal
import stat
import subprocess
import sys
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from scripts.managed_path_stage6_identity import (
    _APPROVED_DATA_DIRS,  # pyright: ignore[reportPrivateUsage]
    _NETWORK_ID,  # pyright: ignore[reportPrivateUsage]
    _assert_trusted_data_dir,  # pyright: ignore[reportPrivateUsage]
    _publish_public_identity,  # pyright: ignore[reportPrivateUsage]
    _require_matching_platform,  # pyright: ignore[reportPrivateUsage]
)
from scripts.managed_path_stage6_identity import (
    _CONFIGS as _IDENTITY_CONFIGS,  # pyright: ignore[reportPrivateUsage]
)
from scripts.managed_path_stage6_preview import (
    _CONFIGS,  # pyright: ignore[reportPrivateUsage]
    _assert_safe_existing_database,  # pyright: ignore[reportPrivateUsage]
    _desired_config,  # pyright: ignore[reportPrivateUsage]
    _git_commit,  # pyright: ignore[reportPrivateUsage]
    _load_peer_identity,  # pyright: ignore[reportPrivateUsage]
    _read_regular_file,  # pyright: ignore[reportPrivateUsage]
    _signed_envelope,  # pyright: ignore[reportPrivateUsage]
)

from tunnelminion.agent.managed_path import ManagedPathProbeFactory
from tunnelminion.domain.identifiers import AuthorizationId, NetworkId, NodeId
from tunnelminion.model.secrets import KeyringSecretStore, SecretStore, SecretStoreError
from tunnelminion.network.contracts import (
    DesiredNetworkConfig,
    NetworkAcknowledgement,
    NetworkAction,
    NetworkPlan,
    ProviderReceipt,
    canonical_sha256,
)
from tunnelminion.network.governance import (
    LocalControlAuthority,
    ManagedPathLifecycle,
    NetworkAuthorizationGrant,
    NetworkAuthorizationScope,
    NetworkGovernancePhase,
    NetworkGovernanceRecord,
    NetworkOperationPolicy,
    SQLiteNetworkAuthorizationRepository,
    SQLiteNetworkGovernanceStore,
)
from tunnelminion.network.ledger import SQLiteManagedResourceLedger
from tunnelminion.network.path_controller import (
    DirectPathController,
    DirectPathErrorCode,
    DirectPathEvidence,
    NetworkPathType,
    PathControllerPolicy,
    PathSelection,
)
from tunnelminion.network.path_probe import PathProbePolicy
from tunnelminion.network.provider import NetworkProvider
from tunnelminion.platforms.macos.managed_path import build_macos_managed_path_platform
from tunnelminion.platforms.macos.managed_system import MacOSProviderPaths
from tunnelminion.platforms.macos.system import CommandResult, CommandRunner
from tunnelminion.platforms.windows.managed_path import build_windows_managed_path_platform
from tunnelminion.tools.contracts import ToolCancellationToken

_BARRIER_TIMEOUT_SECONDS = 180
_AUTHORIZATION_TTL_SECONDS = 900
_HASH_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
_MACOS_CONSOLE_PATH = Path("/dev/console")
_MACOS_LOGIN_UID_MINIMUM = 501
_MACOS_STAGE6_ROOT = Path("/private/var/root/Library/Application Support/TunnelMinion/stage6")
_MACOS_STAGE6_TOOL_SOURCES = {
    "wg": Path("/opt/homebrew/bin/wg"),
    "wg-quick": Path("/opt/homebrew/bin/wg-quick"),
    "wireguard-go": Path("/opt/homebrew/bin/wireguard-go"),
}
_MACOS_STAGE6_TOOL_HASHES = {
    "wg": "5b7b2a5c1756e7afbb76047fb3f5b975d0c9b0ff905817283ec09ab2e11b9e57",
    "wg-quick": "1b8caefd878a3ffecfd8959a5d306c459d0cd645879071b5195ba538b2d40c15",
    "wireguard-go": "c62a563ac888d8c6ca9895ee6f7ac5e7297171f20bc7e1c7e0ec4d6d21415337",
}
_MACOS_STAGE6_PUBLIC_FIELDS = frozenset(
    {"public-key", "peers", "endpoints", "allowed-ips", "latest-handshakes"}
)


@dataclass(frozen=True, slots=True)
class _ApprovedTarget:
    host: str
    port: int


class _MacOSLoginKeychainSecretStore:
    """root runner 仅把固定 Keychain 读取降权到当前控制台登录用户。"""

    def __init__(
        self,
        *,
        expected_name: str,
        service_name: str = "TunnelMinion",
        platform_name: str | None = None,
        effective_uid: Callable[[], int] | None = None,
        console_uid: Callable[[], int] | None = None,
        run_process: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
    ) -> None:
        self._expected_name = expected_name
        self._service_name = service_name
        self._platform_name = sys.platform if platform_name is None else platform_name
        self._effective_uid = effective_uid or cast(
            Callable[[], int], getattr(os, "geteuid", lambda: -1)
        )
        self._console_uid = console_uid or (lambda: os.stat(_MACOS_CONSOLE_PATH).st_uid)
        self._run_process = run_process

    def get(self, name: str) -> str | None:
        """通过固定系统 argv 读取一个既有项；错误正文和秘密均不外泄。"""
        if self._platform_name != "darwin" or self._effective_uid() != 0:
            raise SecretStoreError("macOS 登录用户 Keychain 代理上下文无效")
        if name != self._expected_name:
            raise SecretStoreError("macOS 登录用户 Keychain 代理拒绝非批准名称")
        try:
            uid = self._console_uid()
        except OSError:
            uid = None
        if uid is None:
            raise SecretStoreError("无法确认 macOS 控制台登录用户")
        if not _MACOS_LOGIN_UID_MINIMUM <= uid < 2**31:
            raise SecretStoreError("macOS 控制台没有可用的普通登录用户")
        command = (
            "/bin/launchctl",
            "asuser",
            str(uid),
            "/usr/bin/sudo",
            "-u",
            f"#{uid}",
            "-H",
            "/usr/bin/security",
            "find-generic-password",
            "-s",
            self._service_name,
            "-a",
            name,
            "-w",
        )
        try:
            completed: subprocess.CompletedProcess[str] | None = self._run_process(
                command,
                check=False,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="strict",
                timeout=15,
                env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin"},
            )
        except (OSError, subprocess.SubprocessError, UnicodeError):
            completed = None
        if completed is None:
            raise SecretStoreError("无法读取 macOS 登录用户 Keychain")
        if completed.returncode != 0:
            raise SecretStoreError("无法读取 macOS 登录用户 Keychain")
        value = completed.stdout.rstrip("\r\n")
        return value or None

    def set(self, name: str, value: str) -> None:
        del name, value
        raise SecretStoreError("阶段 6 管理员执行禁止创建或覆盖身份")

    def delete(self, name: str) -> None:
        del name
        raise SecretStoreError("阶段 6 管理员执行禁止删除身份")


class _MacOSStage6CommandRunner:
    """仅执行固定 Stage 6 argv，并持有可取消的 root 进程组。"""

    def __init__(
        self,
        desired: DesiredNetworkConfig,
        *,
        paths: MacOSProviderPaths | None = None,
        platform_name: str | None = None,
        effective_uid: Callable[[], int] | None = None,
    ) -> None:
        self._desired = desired
        self._platform_name = sys.platform if platform_name is None else platform_name
        self._effective_uid = effective_uid or cast(
            Callable[[], int], getattr(os, "geteuid", lambda: -1)
        )
        self._paths = paths or _macos_stage6_paths()
        self._tools_root = self._paths.wg.parent
        self._config_root = self._paths.config_root

    async def run(self, command: tuple[str, ...], timeout_seconds: float) -> CommandResult:
        mutation = self._validate_command(command)
        self._verify_tool(Path(command[0]))
        if mutation:
            self._verify_tool(self._tools_root / "wireguard-go")
            self._validate_config(Path(command[2]))
        process = await asyncio.create_subprocess_exec(
            *command,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env={"PATH": f"{self._tools_root}:/usr/bin:/bin:/usr/sbin:/sbin"},
            start_new_session=True,
        )
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout_seconds)
        except TimeoutError:
            await self._terminate_process_group(process)
            if mutation:
                raise RuntimeError(
                    "Stage 6 macOS root 网络命令超时，状态不确定且必须恢复"
                ) from None
            return CommandResult(returncode=124, stdout="", stderr="")
        except asyncio.CancelledError:
            await asyncio.shield(self._terminate_process_group(process))
            raise
        if mutation:
            return CommandResult(returncode=process.returncode or 0, stdout="", stderr="")
        return CommandResult(
            returncode=process.returncode or 0,
            stdout=stdout.decode("utf-8", errors="replace"),
            stderr=stderr.decode("utf-8", errors="replace"),
        )

    def _validate_command(self, command: tuple[str, ...]) -> bool:
        if self._platform_name != "darwin" or self._effective_uid() != 0:
            raise RuntimeError("Stage 6 macOS command runner 上下文无效")
        if any(
            not value or len(value) > 1024 or "\x00" in value or "\n" in value for value in command
        ):
            raise RuntimeError("Stage 6 macOS command runner 拒绝异常 argv")
        wg = str(self._paths.wg)
        wg_quick = str(self._paths.wg_quick)
        if command == (wg, "show", "interfaces"):
            return False
        if (
            len(command) == 4
            and command[:2] == (wg, "show")
            and command[3] in _MACOS_STAGE6_PUBLIC_FIELDS
            and (
                command[2] == self._desired.interface_name
                or re.fullmatch(r"utun[0-9]+", command[2]) is not None
            )
        ):
            return False
        if (
            len(command) == 2
            and command[0] == str(self._paths.ifconfig)
            and (
                command[1] == self._desired.interface_name
                or re.fullmatch(r"utun[0-9]+", command[1]) is not None
            )
        ):
            return False
        if command in {
            (str(self._paths.netstat), "-rn", "-f", "inet"),
            (str(self._paths.netstat), "-rn", "-f", "inet6"),
        }:
            return False
        expected_config = str(
            self._config_root / f"{self._desired.interface_name}.r{self._desired.revision}.conf"
        )
        if command in {
            (wg_quick, "up", expected_config),
            (wg_quick, "down", expected_config),
        }:
            return True
        raise RuntimeError("Stage 6 macOS command runner 拒绝非批准命令")

    def _verify_tool(self, path: Path) -> None:
        _assert_root_owned_path(path, regular_file=True)
        expected = _MACOS_STAGE6_TOOL_HASHES.get(path.name)
        if expected is not None and _sha256_file(path) != expected:
            raise RuntimeError("Stage 6 macOS 固定工具 hash 不匹配")

    def _validate_config(self, path: Path) -> None:
        expected = (
            self._config_root / f"{self._desired.interface_name}.r{self._desired.revision}.conf"
        )
        if path != expected:
            raise RuntimeError("Stage 6 macOS 配置路径不匹配")
        _assert_root_owned_path(path, regular_file=True, exact_mode=0o600)
        try:
            text = path.read_text(encoding="utf-8", errors="strict")
        except (OSError, UnicodeError):
            raise RuntimeError("Stage 6 macOS 配置不可验证") from None
        lines = text.splitlines()
        redacted: list[str] = []
        private_count = 0
        for line in lines:
            if line.startswith("PrivateKey = "):
                private_count += 1
                try:
                    private = base64.b64decode(line.removeprefix("PrivateKey = "), validate=True)
                except ValueError:
                    raise RuntimeError("Stage 6 macOS 配置 grammar 不匹配") from None
                if len(private) != 32:
                    raise RuntimeError("Stage 6 macOS 配置 grammar 不匹配")
                redacted.append("PrivateKey = <redacted>")
            else:
                redacted.append(line)
        if private_count != 1 or tuple(redacted) != _expected_redacted_config(self._desired):
            raise RuntimeError("Stage 6 macOS 配置 grammar 不匹配")

    @staticmethod
    async def _terminate_process_group(process: asyncio.subprocess.Process) -> None:
        if process.returncode is not None:
            return
        with contextlib.suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGTERM)  # pyright: ignore
        try:
            await asyncio.wait_for(process.wait(), timeout=2)
            return
        except TimeoutError:
            pass
        with contextlib.suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGKILL)  # pyright: ignore
        try:
            await asyncio.wait_for(process.wait(), timeout=2)
        except TimeoutError:
            raise RuntimeError("Stage 6 macOS root 子进程组无法确认终止") from None


_TARGETS: dict[str, tuple[_ApprovedTarget, ...]] = {
    "windows": (_ApprovedTarget("192.0.2.2", 8787),),
    "macos": (
        _ApprovedTarget("192.0.2.1", 7899),
        _ApprovedTarget("192.0.2.1", 47990),
    ),
}

_READY_KEYS = frozenset(
    {
        "schema_version",
        "platform",
        "barrier_id_hash",
        "plan_hash",
        "authorization_hash",
        "authorization_expires_at",
        "provider_verified",
        "network_writes_completed",
    }
)
_GO_KEYS = frozenset(
    {
        "schema_version",
        "platform",
        "barrier_id_hash",
        "local_plan_hash",
        "peer_plan_hash",
        "local_authorization_hash",
        "peer_authorization_hash",
        "local_authorization_expires_at",
        "peer_authorization_expires_at",
        "pair_hash",
        "release_after_both_provider_verified",
    }
)
_ATTEMPT_KEYS = frozenset(
    {
        "schema_version",
        "platform",
        "barrier_id_hash",
        "pair_hash",
        "plan_hash",
        "authorization_hash",
        "target_host_hash",
        "target_port",
        "started_at",
    }
)
_RESULT_KEYS = frozenset(
    {
        "schema_version",
        "attempt_hash",
        "succeeded",
        "evidence",
        "finished_at",
    }
)


def _macos_stage6_paths() -> MacOSProviderPaths:
    tools = _MACOS_STAGE6_ROOT / "tools"
    return MacOSProviderPaths(
        wg=tools / "wg",
        wg_quick=tools / "wg-quick",
        ifconfig=Path("/sbin/ifconfig"),
        netstat=Path("/usr/sbin/netstat"),
        config_root=_MACOS_STAGE6_ROOT / "configs",
    )


def _expected_redacted_config(desired: DesiredNetworkConfig) -> tuple[str, ...]:
    lines = ["[Interface]", "PrivateKey = <redacted>", f"Address = {desired.address}"]
    if desired.listen_port is not None:
        lines.append(f"ListenPort = {desired.listen_port}")
    for peer in desired.peers:
        lines.extend(("", "[Peer]", f"PublicKey = {peer.public_key}"))
        lines.append(f"AllowedIPs = {', '.join(peer.allowed_host_routes)}")
        if peer.candidates:
            candidate = peer.candidates[0]
            lines.append(f"Endpoint = {candidate.host}:{candidate.port}")
        if peer.persistent_keepalive_seconds is not None:
            lines.append(f"PersistentKeepalive = {peer.persistent_keepalive_seconds}")
    return tuple(lines)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            while chunk := handle.read(1024 * 1024):
                digest.update(chunk)
    except OSError:
        raise RuntimeError("Stage 6 macOS 固定文件不可读取") from None
    return digest.hexdigest()


def _assert_root_owned_path(
    path: Path,
    *,
    regular_file: bool = False,
    exact_mode: int | None = None,
) -> None:
    try:
        info = os.lstat(path)
    except OSError:
        raise RuntimeError("Stage 6 macOS root-owned 路径不存在") from None
    mode = stat.S_IMODE(info.st_mode)
    if info.st_uid != 0 or stat.S_ISLNK(info.st_mode) or mode & 0o022:
        raise RuntimeError("Stage 6 macOS root-owned 路径身份不可信")
    if regular_file and (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1):
        raise RuntimeError("Stage 6 macOS 固定文件身份不可信")
    if exact_mode is not None and mode != exact_mode:
        raise RuntimeError("Stage 6 macOS 固定文件权限不匹配")


def _ensure_macos_stage6_directory(path: Path) -> None:
    if path != _MACOS_STAGE6_ROOT and _MACOS_STAGE6_ROOT not in path.parents:
        raise RuntimeError("Stage 6 macOS 执行目录越界")
    current = Path("/private/var/root")
    _assert_root_owned_path(current)
    relative = path.relative_to(current)
    for part in relative.parts:
        current /= part
        with contextlib.suppress(FileExistsError):
            current.mkdir(mode=0o700)
        _assert_root_owned_path(current)
        if not current.is_dir():
            raise RuntimeError("Stage 6 macOS 执行路径不是目录")
        os.chmod(current, 0o700)


def _install_macos_stage6_tools() -> dict[str, object]:
    if sys.platform != "darwin" or os.geteuid() != 0:  # pyright: ignore
        raise SystemExit("Stage 6 macOS 固定工具安装必须使用 root")
    tools_root = _MACOS_STAGE6_ROOT / "tools"
    _ensure_macos_stage6_directory(tools_root)
    installed: list[str] = []
    for name, source in _MACOS_STAGE6_TOOL_SOURCES.items():
        target = tools_root / name
        expected_hash = _MACOS_STAGE6_TOOL_HASHES[name]
        if target.exists() or target.is_symlink():
            _assert_root_owned_path(target, regular_file=True, exact_mode=0o500)
            if _sha256_file(target) != expected_hash:
                raise SystemExit("Stage 6 macOS 已安装固定工具 hash 不匹配")
            continue
        _copy_hash_pinned_tool(source, target, expected_hash)
        installed.append(name)
    return {"installed": installed, "root": str(_MACOS_STAGE6_ROOT), "success": True}


def _copy_hash_pinned_tool(source: Path, target: Path, expected_hash: str) -> None:
    try:
        source_descriptor = os.open(source, os.O_RDONLY)
    except OSError:
        raise SystemExit("Stage 6 macOS 工具源不可读取") from None
    temporary = target.parent / f".{target.name}.{secrets.token_hex(16)}.tmp"
    target_descriptor = -1
    try:
        source_info = os.fstat(source_descriptor)
        if (
            not stat.S_ISREG(source_info.st_mode)
            or not 1 <= source_info.st_size <= 64 * 1024 * 1024
        ):
            raise SystemExit("Stage 6 macOS 工具源身份不可信")
        digest = hashlib.sha256()
        while chunk := os.read(source_descriptor, 1024 * 1024):
            digest.update(chunk)
        if digest.hexdigest() != expected_hash:
            raise SystemExit("Stage 6 macOS 工具源 hash 不匹配")
        os.lseek(source_descriptor, 0, os.SEEK_SET)
        target_descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o500,
        )
        while chunk := os.read(source_descriptor, 1024 * 1024):
            view = memoryview(chunk)
            while view:
                written = os.write(target_descriptor, view)
                view = view[written:]
        os.fchmod(target_descriptor, 0o500)  # pyright: ignore
        os.fchown(target_descriptor, 0, 0)  # pyright: ignore
        os.fsync(target_descriptor)
        os.close(target_descriptor)
        target_descriptor = -1
        os.replace(temporary, target)
        _assert_root_owned_path(target, regular_file=True, exact_mode=0o500)
        if _sha256_file(target) != expected_hash:
            raise SystemExit("Stage 6 macOS 固定工具安装后 hash 不匹配")
    finally:
        os.close(source_descriptor)
        if target_descriptor >= 0:
            os.close(target_descriptor)
        if temporary.exists() or temporary.is_symlink():
            temporary.unlink()


def _load_exact_marker(path: Path, keys: frozenset[str]) -> dict[str, object]:
    raw = json.loads(_read_regular_file(path))
    if not isinstance(raw, dict):
        raise RuntimeError("阶段 6.3 barrier marker schema 不匹配")
    payload = cast(dict[str, object], raw)
    if frozenset(payload.keys()) != keys:
        raise RuntimeError("阶段 6.3 barrier marker schema 不匹配")
    return payload


def _validate_ready_marker(payload: dict[str, object], *, platform: str, barrier_hash: str) -> None:
    expires = payload.get("authorization_expires_at")
    try:
        expires_at = datetime.fromisoformat(cast(str, expires))
    except (TypeError, ValueError) as exc:
        raise RuntimeError("阶段 6.3 ready marker 授权时间无效") from exc
    hashes = (
        payload.get("barrier_id_hash"),
        payload.get("plan_hash"),
        payload.get("authorization_hash"),
    )
    if (
        payload.get("schema_version") != "managed-path-stage6-barrier/v2"
        or payload.get("platform") != platform
        or payload.get("barrier_id_hash") != barrier_hash
        or payload.get("provider_verified") is not True
        or payload.get("network_writes_completed") is not True
        or any(
            not isinstance(value, str) or _HASH_PATTERN.fullmatch(value) is None for value in hashes
        )
        or expires_at.tzinfo is None
        or expires_at.utcoffset() != timedelta(0)
        or expires_at <= datetime.now(UTC)
    ):
        raise RuntimeError("阶段 6.3 ready marker 绑定或 TTL 无效")


def _require_utc_timestamp(value: object, *, label: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(cast(str, value))
    except (TypeError, ValueError) as exc:
        raise RuntimeError(f"阶段 6.3 {label} 时间无效") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise RuntimeError(f"阶段 6.3 {label} 必须是 UTC 时间")
    return parsed


def _go_marker(
    platform: str,
    barrier_id: str,
    ready: dict[str, object],
    peer_ready: dict[str, object],
) -> dict[str, object]:
    barrier_hash = canonical_sha256({"barrier_id": barrier_id})
    peer_platform = "macos" if platform == "windows" else "windows"
    _validate_ready_marker(ready, platform=platform, barrier_hash=barrier_hash)
    _validate_ready_marker(peer_ready, platform=peer_platform, barrier_hash=barrier_hash)
    pair = {
        item["platform"]: {
            "plan_hash": item["plan_hash"],
            "authorization_hash": item["authorization_hash"],
            "authorization_expires_at": item["authorization_expires_at"],
        }
        for item in sorted((ready, peer_ready), key=lambda value: cast(str, value["platform"]))
    }
    return {
        "schema_version": "managed-path-stage6-barrier/v2",
        "platform": platform,
        "barrier_id_hash": barrier_hash,
        "local_plan_hash": ready["plan_hash"],
        "peer_plan_hash": peer_ready["plan_hash"],
        "local_authorization_hash": ready["authorization_hash"],
        "peer_authorization_hash": peer_ready["authorization_hash"],
        "local_authorization_expires_at": ready["authorization_expires_at"],
        "peer_authorization_expires_at": peer_ready["authorization_expires_at"],
        "pair_hash": canonical_sha256(pair),
        "release_after_both_provider_verified": True,
    }


def _publish_or_validate(path: Path, payload: dict[str, object]) -> None:
    if path.exists() or path.is_symlink():
        if json.loads(_read_regular_file(path)) != payload:
            raise RuntimeError("阶段 6.3 已有 marker 与当前绑定不一致")
        return
    _publish_public_identity(path, payload)


def _target_attempt(
    *,
    data_dir: Path,
    label: str,
    platform: str,
    barrier_id: str,
    pair_hash: str,
    plan_hash: str,
    authorization_hash: str,
    target: _ApprovedTarget,
    now: datetime,
) -> tuple[dict[str, object], dict[str, object] | None, bool]:
    attempt_path = data_dir / f"stage6-target-{label}-attempt.json"
    result_path = data_dir / f"stage6-target-{label}-result.json"
    attempt: dict[str, object] = {
        "schema_version": "managed-path-stage6-target-attempt/v1",
        "platform": platform,
        "barrier_id_hash": canonical_sha256({"barrier_id": barrier_id}),
        "pair_hash": pair_hash,
        "plan_hash": plan_hash,
        "authorization_hash": authorization_hash,
        "target_host_hash": canonical_sha256({"host": target.host}),
        "target_port": target.port,
        "started_at": now.isoformat(),
    }
    if not attempt_path.exists() and not attempt_path.is_symlink():
        _publish_public_identity(attempt_path, attempt)
        return attempt, None, True
    existing = _load_exact_marker(attempt_path, _ATTEMPT_KEYS)
    started_at = _require_utc_timestamp(existing["started_at"], label="target attempt")
    comparable = dict(existing)
    comparable.pop("started_at")
    expected = dict(attempt)
    expected.pop("started_at")
    if comparable != expected:
        raise RuntimeError("阶段 6.3 target attempt 绑定不一致")
    if not result_path.exists() and not result_path.is_symlink():
        raise RuntimeError("阶段 6.3 target connect 结果不确定，拒绝重试")
    result = _load_exact_marker(result_path, _RESULT_KEYS)
    finished_at = _require_utc_timestamp(result["finished_at"], label="target result")
    if (
        result.get("schema_version") != "managed-path-stage6-target-result/v1"
        or result.get("attempt_hash") != canonical_sha256(existing)
        or not isinstance(result.get("attempt_hash"), str)
        or _HASH_PATTERN.fullmatch(cast(str, result.get("attempt_hash"))) is None
        or not isinstance(result.get("succeeded"), bool)
        or started_at > finished_at
        or finished_at > now
    ):
        raise RuntimeError("阶段 6.3 target result 绑定不一致")
    return existing, result, False


def _finish_target_attempt(
    data_dir: Path,
    label: str,
    attempt: dict[str, object],
    *,
    succeeded: bool,
    evidence: DirectPathEvidence | None,
    now: datetime,
) -> None:
    _publish_public_identity(
        data_dir / f"stage6-target-{label}-result.json",
        {
            "schema_version": "managed-path-stage6-target-result/v1",
            "attempt_hash": canonical_sha256(attempt),
            "succeeded": succeeded,
            "evidence": evidence.model_dump(mode="json") if evidence else None,
            "finished_at": now.isoformat(),
        },
    )


def _marker_hash(path: Path, keys: frozenset[str]) -> str | None:
    if not path.exists() and not path.is_symlink():
        return None
    return canonical_sha256(_load_exact_marker(path, keys))


class _CountingAuthorizationRepository(SQLiteNetworkAuthorizationRepository):
    def __init__(self, path: Path, *, control: LocalControlAuthority) -> None:
        self.list_calls = 0
        super().__init__(path, control=control)

    def list_grants(
        self, network_id: NetworkId, node_id: NodeId
    ) -> tuple[NetworkAuthorizationGrant, ...]:
        self.list_calls += 1
        return super().list_grants(network_id, node_id)


class _CountingProvider:
    def __init__(self, provider: object) -> None:
        self._provider = provider
        self.apply_calls = 0
        self.rollback_calls = 0

    def __getattr__(self, name: str) -> object:
        return getattr(self._provider, name)

    async def apply(
        self,
        plan: NetworkPlan,
        *,
        idempotency_key: str,
        cancellation: ToolCancellationToken,
    ) -> ProviderReceipt:
        self.apply_calls += 1
        provider = cast(NetworkProvider, self._provider)
        return await provider.apply(
            plan,
            idempotency_key=idempotency_key,
            cancellation=cancellation,
        )

    async def rollback(
        self,
        plan: NetworkPlan,
        receipt: ProviderReceipt,
        *,
        cancellation: ToolCancellationToken,
    ) -> ProviderReceipt:
        self.rollback_calls += 1
        provider = cast(NetworkProvider, self._provider)
        return await provider.rollback(plan, receipt, cancellation=cancellation)


class _AcknowledgementRecorder:
    def __init__(self) -> None:
        self.items: list[NetworkAcknowledgement] = []

    async def acknowledge(self, acknowledgement: NetworkAcknowledgement) -> None:
        self.items.append(acknowledgement)


class _ExistingOnlySecretStore:
    """每次读取都核验批准身份，并拒绝所有身份写入。"""

    def __init__(
        self,
        backend: SecretStore,
        *,
        expected_name: str,
        expected_public_key: str,
        expected_public_key_hash: str,
    ) -> None:
        self._backend = backend
        self._expected_name = expected_name
        self._expected_public_key = expected_public_key
        self._expected_public_key_hash = expected_public_key_hash

    def get(self, name: str) -> str | None:
        if name != self._expected_name:
            raise SecretStoreError("阶段 6 身份引用不在批准范围")
        private_text = self._backend.get(name)
        if private_text is None:
            raise SecretStoreError("既有阶段 6 身份不可用，拒绝创建替代身份")
        result = private_text
        try:
            private = X25519PrivateKey.from_private_bytes(
                base64.b64decode(private_text, validate=True)
            )
            public = base64.b64encode(
                private.public_key().public_bytes(
                    serialization.Encoding.Raw,
                    serialization.PublicFormat.Raw,
                )
            ).decode()
        except (ValueError, TypeError) as exc:
            raise SecretStoreError("既有阶段 6 身份格式无效") from exc
        finally:
            private_text = ""
        if (
            public != self._expected_public_key
            or canonical_sha256({"public_key": public}) != self._expected_public_key_hash
        ):
            raise SecretStoreError("既有阶段 6 身份与批准公开身份不一致")
        return result

    def set(self, name: str, value: str) -> None:
        del name, value
        raise SecretStoreError("阶段 6 验收禁止创建或覆盖身份")

    def delete(self, name: str) -> None:
        del name
        raise SecretStoreError("阶段 6 验收禁止删除预置身份")


class _BarrierPathVerifier:
    """Provider verify 后等待双端 barrier，再执行一次声明顺序 target run。"""

    def __init__(
        self,
        *,
        platform: str,
        barrier_id: str,
        data_dir: Path,
        probe_factory: ManagedPathProbeFactory,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self._platform = platform
        self._barrier_id = barrier_id
        self._data_dir = data_dir
        self._probe_factory = probe_factory
        self._clock = clock
        self._authorization_hash: str | None = None
        self._authorization_expires_at: datetime | None = None
        self._pair_hash: str | None = None
        self.probe_runs = 0
        self.target_attempts: list[int] = []

    def bind_authorization(self, grant: NetworkAuthorizationGrant) -> None:
        if self._authorization_hash is not None:
            raise RuntimeError("阶段 6.3 verifier 授权只能绑定一次")
        self._authorization_hash = canonical_sha256(
            {
                "authorization_id": str(grant.authorization_id),
                "expires_at": grant.expires_at.isoformat(),
                "scope_hash": canonical_sha256(grant.scope.model_dump(mode="json")),
            }
        )
        self._authorization_expires_at = grant.expires_at

    async def verify(self, plan: NetworkPlan, *, now: datetime) -> DirectPathEvidence:
        del now
        if self.probe_runs != 0:
            raise RuntimeError("阶段 6.3 每个平台只允许一次 path probe run")
        if self._authorization_hash is None or self._authorization_expires_at is None:
            raise RuntimeError("阶段 6.3 path verifier 缺少授权绑定")
        self.probe_runs = 1
        ready: dict[str, object] = {
            "schema_version": "managed-path-stage6-barrier/v2",
            "platform": self._platform,
            "barrier_id_hash": canonical_sha256({"barrier_id": self._barrier_id}),
            "plan_hash": plan.plan_hash,
            "authorization_hash": self._authorization_hash,
            "authorization_expires_at": self._authorization_expires_at.isoformat(),
            "provider_verified": True,
            "network_writes_completed": True,
        }
        _publish_or_validate(self._data_dir / "stage6-apply-ready.json", ready)
        await self._wait_for_release(plan)
        current = self._fresh_authorized_time()
        desired = plan.desired
        peer = desired.peers[0]
        expected_host_route = peer.allowed_host_routes[0]
        candidate_networks = tuple(
            str(
                ipaddress.ip_network(
                    f"{candidate.host}/{ipaddress.ip_address(candidate.host).max_prefixlen}",
                    strict=True,
                )
            )
            for candidate in peer.candidates
        )
        approved_networks = tuple(
            dict.fromkeys(
                (*candidate_networks, *(f"{target.host}/32" for target in _TARGETS[self._platform]))
            )
        )
        approved_ports = tuple(
            dict.fromkeys(
                (
                    *(candidate.port for candidate in peer.candidates),
                    *(target.port for target in _TARGETS[self._platform]),
                )
            )
        )
        policy = PathProbePolicy(
            approved_networks=approved_networks,
            approved_ports=approved_ports,
            target_timeout_seconds=2.0,
        )
        probe = self._probe_factory(desired, policy)
        primary = _TARGETS[self._platform][0]
        self.target_attempts.append(primary.port)
        if self._pair_hash is None:
            raise RuntimeError("阶段 6.3 target attempt 缺少 barrier/授权绑定")
        primary_attempt, primary_result, primary_created = _target_attempt(
            data_dir=self._data_dir,
            label="primary",
            platform=self._platform,
            barrier_id=self._barrier_id,
            pair_hash=self._pair_hash,
            plan_hash=plan.plan_hash,
            authorization_hash=self._authorization_hash,
            target=primary,
            now=current,
        )
        if primary_created:
            evidence = await probe.probe(
                network_id=desired.network_id,
                node_id=desired.target_node_id,
                plan_hash=plan.plan_hash,
                authorization_revision=desired.revision,
                revision=desired.revision,
                candidates=peer.candidates,
                expected_host_route=expected_host_route,
                target_host=primary.host,
                target_port=primary.port,
                now=current,
            )
            _finish_target_attempt(
                self._data_dir,
                "primary",
                primary_attempt,
                succeeded=evidence.target_probe_succeeded,
                evidence=evidence,
                now=self._clock().astimezone(UTC),
            )
        else:
            if primary_result is None:
                raise RuntimeError("阶段 6.3 primary result 不存在")
            evidence_payload = primary_result.get("evidence")
            if not isinstance(evidence_payload, dict):
                raise RuntimeError("阶段 6.3 primary result 缺少脱敏 evidence")
            evidence = DirectPathEvidence.model_validate(evidence_payload)
            if (
                evidence.plan_hash != plan.plan_hash
                or evidence.target_host_hash != primary_attempt["target_host_hash"]
                or evidence.target_port != primary.port
                or evidence.target_probe_succeeded is not primary_result["succeeded"]
            ):
                raise RuntimeError("阶段 6.3 primary evidence 绑定不一致")
        if (
            evidence.verified
            or self._platform != "macos"
            or evidence.stable_error_code is not DirectPathErrorCode.TARGET_UNREACHABLE
        ):
            return evidence
        fallback = _TARGETS["macos"][1]
        fallback_time = self._fresh_authorized_time()
        self.target_attempts.append(fallback.port)
        fallback_attempt, fallback_result, fallback_created = _target_attempt(
            data_dir=self._data_dir,
            label="fallback",
            platform=self._platform,
            barrier_id=self._barrier_id,
            pair_hash=self._pair_hash,
            plan_hash=plan.plan_hash,
            authorization_hash=self._authorization_hash,
            target=fallback,
            now=fallback_time,
        )
        if fallback_created:
            succeeded = await probe.target(fallback.host, fallback.port, 2.0)
            fallback_evidence = evidence.model_copy(
                update={
                    "target_host_hash": canonical_sha256({"host": fallback.host}),
                    "target_port": fallback.port,
                    "target_probe_at": fallback_time,
                    "target_probe_succeeded": succeeded,
                    "verified": succeeded,
                    "stable_error_code": (
                        None if succeeded else DirectPathErrorCode.TARGET_UNREACHABLE
                    ),
                    "observed_at": fallback_time,
                    "expires_at": fallback_time + timedelta(seconds=evidence.freshness_ttl_seconds),
                }
            )
            _finish_target_attempt(
                self._data_dir,
                "fallback",
                fallback_attempt,
                succeeded=succeeded,
                evidence=fallback_evidence,
                now=self._clock().astimezone(UTC),
            )
        else:
            if fallback_result is None:
                raise RuntimeError("阶段 6.3 fallback result 绑定不一致")
            fallback_payload = fallback_result.get("evidence")
            if not isinstance(fallback_payload, dict):
                raise RuntimeError("阶段 6.3 fallback result 缺少脱敏 evidence")
            fallback_evidence = DirectPathEvidence.model_validate(fallback_payload)
            if (
                fallback_evidence.plan_hash != plan.plan_hash
                or fallback_evidence.target_host_hash != fallback_attempt["target_host_hash"]
                or fallback_evidence.target_port != fallback.port
                or fallback_evidence.target_probe_succeeded is not fallback_result["succeeded"]
            ):
                raise RuntimeError("阶段 6.3 fallback evidence 绑定不一致")
        return fallback_evidence

    def _fresh_authorized_time(self) -> datetime:
        current = self._clock().astimezone(UTC)
        if self._authorization_expires_at is None or current >= self._authorization_expires_at:
            raise RuntimeError("阶段 6.3 授权已过期，拒绝执行 target connect")
        return current

    async def _wait_for_release(self, plan: NetworkPlan) -> None:
        release = self._data_dir / "stage6-apply-go.json"
        deadline = asyncio.get_running_loop().time() + _BARRIER_TIMEOUT_SECONDS
        while asyncio.get_running_loop().time() < deadline:
            if release.exists() or release.is_symlink():
                payload = _load_exact_marker(release, _GO_KEYS)
                peer = _load_exact_marker(
                    self._data_dir / "stage6-apply-peer-ready.json", _READY_KEYS
                )
                expected = _go_marker(
                    self._platform,
                    self._barrier_id,
                    _load_exact_marker(self._data_dir / "stage6-apply-ready.json", _READY_KEYS),
                    peer,
                )
                if payload != expected or payload["local_plan_hash"] != plan.plan_hash:
                    raise RuntimeError("阶段 6.3 barrier release 绑定不一致")
                self._pair_hash = cast(str, payload["pair_hash"])
                return
            await asyncio.sleep(0.25)
        raise TimeoutError("阶段 6.3 等待双端 Provider verify barrier 超时")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--platform", choices=tuple(_CONFIGS), required=True)
    parser.add_argument("--barrier-id", required=True)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--release-barrier", action="store_true")
    mode.add_argument("--recover", action="store_true")
    mode.add_argument("--rollback-create", action="store_true")
    mode.add_argument("--install-macos-execution-materials", action="store_true")
    args = parser.parse_args(argv)
    if len(args.barrier_id) != 32 or any(
        char not in "0123456789abcdef" for char in args.barrier_id
    ):
        raise SystemExit("barrier id 必须是 32 位小写十六进制")
    _require_matching_platform(args.platform)
    if args.install_macos_execution_materials:
        if args.platform != "macos":
            raise SystemExit("Stage 6 macOS 固定工具只允许在 macOS 安装")
        result = _install_macos_stage6_tools()
        print(json.dumps(result, sort_keys=True))
        return 0
    if args.release_barrier:
        _release_barrier(args.platform, args.barrier_id)
        return 0
    result = asyncio.run(
        _run(
            args.platform,
            args.barrier_id,
            now=datetime.now(UTC),
            recover=args.recover,
            rollback_create=args.rollback_create,
        )
    )
    print(json.dumps(result, sort_keys=True))
    return 0 if result.get("success") is True else 2


async def _run(
    platform: str,
    barrier_id: str,
    *,
    now: datetime,
    recover: bool = False,
    rollback_create: bool = False,
) -> dict[str, object]:
    _require_elevated(platform)
    config = _CONFIGS[platform]
    data_dir = _APPROVED_DATA_DIRS[platform]
    _assert_trusted_data_dir(data_dir, data_dir)
    protected = tuple(
        data_dir / name
        for name in (
            "stage6-apply-evidence.json",
            "stage6-apply-ready.json",
            "stage6-apply-go.json",
            "stage6-apply-peer-ready.json",
            "stage6-apply-governance.sqlite3",
            "stage6-apply-governance.sqlite3-wal",
            "stage6-apply-governance.sqlite3-shm",
            "stage6-apply-governance.sqlite3-journal",
            "stage6-target-primary-attempt.json",
            "stage6-target-primary-result.json",
            "stage6-target-fallback-attempt.json",
            "stage6-target-fallback-result.json",
        )
    )
    if (
        not recover
        and not rollback_create
        and any(path.exists() or path.is_symlink() for path in protected)
    ):
        raise SystemExit("阶段 6.3 证据、barrier 或治理状态已存在，拒绝覆盖或复用")
    evidence_path = data_dir / "stage6-apply-evidence.json"
    database = data_dir / "stage6-apply-governance.sqlite3"
    rollback_evidence_path = data_dir / "stage6-rollback-evidence.json"
    if recover and (evidence_path.exists() or evidence_path.is_symlink()):
        raise SystemExit("阶段 6.3 已有最终证据，不得以 recover 重放")
    if recover and (rollback_evidence_path.exists() or rollback_evidence_path.is_symlink()):
        raise SystemExit("阶段 6 已完成 rollback，不得以 recover 重放")
    if recover and not database.is_file():
        raise SystemExit("阶段 6.3 recover 缺少既有治理记录")
    if rollback_create and (
        not database.is_file()
        or rollback_evidence_path.exists()
        or rollback_evidence_path.is_symlink()
    ):
        raise SystemExit("阶段 6 rollback 缺少治理记录或已有证据")
    identity_store = _assert_existing_identity(platform)
    peer_identity = _load_peer_identity(data_dir / config.peer_identity_file, config)
    desired = _desired_config(config, peer_identity, now=now)
    envelope = _signed_envelope(desired, now=now)
    ledger_path = data_dir / "managed-network-ledger.sqlite3"
    provider_journal = (
        data_dir
        / "managed-network"
        / ("windows-operations.sqlite3" if platform == "windows" else "macos-operations.sqlite3")
    )
    _assert_safe_existing_database(ledger_path)
    _assert_safe_existing_database(provider_journal)
    ledger = SQLiteManagedResourceLedger(ledger_path)
    dependencies = (
        build_windows_managed_path_platform(data_dir, ledger, secret_store=identity_store)
        if platform == "windows"
        else build_macos_managed_path_platform(
            data_dir,
            ledger,
            secret_store=identity_store,
            paths=_macos_stage6_paths(),
            command_runner=cast(CommandRunner, _MacOSStage6CommandRunner(desired)),
        )
    )
    if not dependencies.capabilities.provider_apply_available:
        raise SystemExit("当前管理员上下文没有真实 Provider apply capability")
    provider = _CountingProvider(dependencies.provider)
    control = LocalControlAuthority()
    repository = _CountingAuthorizationRepository(database, control=control)
    store = SQLiteNetworkGovernanceStore(database, authorization_repository=repository)
    acknowledgements = _AcknowledgementRecorder()
    verifier = _BarrierPathVerifier(
        platform=platform,
        barrier_id=barrier_id,
        data_dir=data_dir,
        probe_factory=dependencies.probe_factory,
    )
    initial = PathSelection(
        path_type=NetworkPathType.STATIC,
        provider=dependencies.provider_kind,
        revision=1,
        candidate_count=0,
        consecutive_failures=0,
        consecutive_successes=0,
        selected_at=now,
        last_evidence_at=now,
    )
    lifecycle = ManagedPathLifecycle(
        cast(NetworkProvider, provider),
        NetworkOperationPolicy(repository.read_only),
        store,
        acknowledgements,
        path_verifier=verifier,
        path_controller=DirectPathController(PathControllerPolicy(), initial=initial),
        ledger=ledger,
        clock=lambda: datetime.now(UTC),
    )
    if rollback_create:
        existing = store.get(_NETWORK_ID, config.node_id, 1)
        if (
            existing is None
            or existing.plan.action is not NetworkAction.CREATE
            or existing.receipt is None
            or existing.phase
            not in {NetworkGovernancePhase.VERIFIED, NetworkGovernancePhase.PATH_DEGRADED}
        ):
            raise SystemExit("阶段 6 rollback 缺少原 CREATE plan/receipt")
        rolled_record = await lifecycle._rollback(  # pyright: ignore[reportPrivateUsage]
            existing,
            existing.receipt,
            cancellation=ToolCancellationToken(),
        )
        rolled = rolled_record.receipt
        if rolled is None:
            raise RuntimeError("阶段 6 rollback 未返回 Provider receipt")
        identity_name = f"wireguard/{_NETWORK_ID}/{config.node_id}"
        identity_store.get(identity_name)
        success = rolled_record.phase is NetworkGovernancePhase.ROLLED_BACK
        _publish_public_identity(
            rollback_evidence_path,
            {
                "schema_version": "managed-path-stage6-rollback/v1",
                "mode": "rollback_create",
                "platform": platform,
                "commit": _git_commit(),
                "plan_hash": existing.plan.plan_hash,
                "governance_phase": rolled_record.phase.value,
                "receipt_status": rolled.status.value,
                "stable_error_code": rolled_record.stable_error_code,
                "rollback_calls": provider.rollback_calls,
                "provider_apply_calls": provider.apply_calls,
                "precreated_identity_preserved": True,
                "final_ownership": (
                    rolled.observation_after.ownership.value
                    if rolled.observation_after is not None
                    else None
                ),
                "finished_at": datetime.now(UTC).isoformat(),
            },
        )
        return {
            "platform": platform,
            "provider_apply_calls": provider.apply_calls,
            "rollback_calls": provider.rollback_calls,
            "success": success,
        }
    if recover:
        existing = store.get(_NETWORK_ID, config.node_id, 1)
        if existing is None or existing.authorization_id is None:
            raise SystemExit("阶段 6.3 recover 没有精确的已授权治理记录")
        grant = repository.get(existing.authorization_id)
        if grant is None:
            raise SystemExit("阶段 6.3 recover 无法读取原授权")
        verifier.bind_authorization(grant)
        recoverable = store.list_recoverable()
        if len(recoverable) != 1 or recoverable[0] != existing:
            raise SystemExit("阶段 6.3 recoverable 集合不是唯一精确目标，拒绝恢复")
        recovered = await lifecycle.recover()
        matches = tuple(
            item
            for item in recovered
            if item.plan.desired.network_id == _NETWORK_ID
            and item.plan.desired.target_node_id == config.node_id
            and item.plan.desired.revision == 1
            and item.plan.plan_hash == existing.plan.plan_hash
        )
        if len(matches) != 1:
            raise RuntimeError("阶段 6.3 recover 没有返回唯一精确治理记录")
        result = matches[0]
        return _finalize_run(
            platform,
            result,
            provider=provider,
            repository=repository,
            verifier=verifier,
            acknowledgements=acknowledgements,
            observed_at=now,
            evidence_path=evidence_path,
            expected_apply_calls=0,
        )
    pending = await lifecycle.reconcile(envelope, action=NetworkAction.CREATE, ownership=None)
    if pending.phase is not NetworkGovernancePhase.AWAITING_AUTHORIZATION:
        raise RuntimeError("阶段 6.3 初始 lifecycle 没有停在 awaiting authorization")
    approved_at = datetime.now(UTC)
    grant = NetworkAuthorizationGrant(
        authorization_id=AuthorizationId.new(),
        scope=NetworkAuthorizationScope.from_plan(
            pending.plan,
            address_pool="192.0.2.0/30",
            interface_prefix="tmn-stage6-",
        ),
        approved_by="stage6-explicit-user-authorization-20260826",
        approved_at=approved_at,
        expires_at=approved_at + timedelta(seconds=_AUTHORIZATION_TTL_SECONDS),
    )
    repository.approve(grant, capability=control.authorization_capability())
    verifier.bind_authorization(grant)
    result = await lifecycle.reconcile(envelope, action=NetworkAction.CREATE, ownership=None)
    return _finalize_run(
        platform,
        result,
        provider=provider,
        repository=repository,
        verifier=verifier,
        acknowledgements=acknowledgements,
        observed_at=now,
        evidence_path=evidence_path,
        expected_apply_calls=1,
    )


def _finalize_run(
    platform: str,
    result: NetworkGovernanceRecord,
    *,
    provider: _CountingProvider,
    repository: _CountingAuthorizationRepository,
    verifier: _BarrierPathVerifier,
    acknowledgements: _AcknowledgementRecorder,
    observed_at: datetime,
    evidence_path: Path,
    expected_apply_calls: int,
) -> dict[str, object]:
    evidence = _evidence(
        platform,
        result,
        provider=provider,
        repository=repository,
        verifier=verifier,
        acknowledgements=acknowledgements,
        observed_at=observed_at,
        mode="recover" if expected_apply_calls == 0 else "apply",
    )
    _publish_public_identity(evidence_path, evidence)
    success = (
        result.phase is NetworkGovernancePhase.VERIFIED
        and result.acknowledgement_delivered
        and bool(result.path_evidence and result.path_evidence.verified)
        and bool(result.verification and result.verification.succeeded)
        and provider.apply_calls == expected_apply_calls
        and verifier.probe_runs == 1
        and len(acknowledgements.items) >= 1
    )
    return {
        "acknowledgement_delivered": result.acknowledgement_delivered,
        "path_verified": bool(result.path_evidence and result.path_evidence.verified),
        "platform": platform,
        "provider_apply_calls": provider.apply_calls,
        "provider_verified": bool(result.verification and result.verification.succeeded),
        "real_network_writes_performed": (provider.apply_calls > 0 or provider.rollback_calls > 0),
        "success": success,
    }


def _release_barrier(platform: str, barrier_id: str) -> None:
    data_dir = _APPROVED_DATA_DIRS[platform]
    _assert_trusted_data_dir(data_dir, data_dir)
    ready_path = data_dir / "stage6-apply-ready.json"
    peer_ready_path = data_dir / "stage6-apply-peer-ready.json"
    if not ready_path.exists() and not ready_path.is_symlink():
        raise SystemExit("阶段 6.3 本端 ready marker 不存在")
    if not peer_ready_path.exists() and not peer_ready_path.is_symlink():
        raise SystemExit("阶段 6.3 peer-ready marker 不存在")
    try:
        ready = _load_exact_marker(ready_path, _READY_KEYS)
        peer_ready = _load_exact_marker(peer_ready_path, _READY_KEYS)
        release = _go_marker(platform, barrier_id, ready, peer_ready)
    except RuntimeError as exc:
        raise SystemExit("阶段 6.3 本端或对端 ready marker 绑定不一致") from exc
    _publish_or_validate(data_dir / "stage6-apply-go.json", release)


def _require_elevated(platform: str) -> None:
    if platform == "windows":
        windll = getattr(ctypes, "windll", None)
        if windll is None or not bool(windll.shell32.IsUserAnAdmin()):
            raise SystemExit("Windows 阶段 6.3 必须使用已提升管理员令牌")
    effective_uid = cast(Callable[[], int], getattr(os, "geteuid", lambda: -1))
    if platform == "macos" and effective_uid() != 0:
        raise SystemExit("macOS 阶段 6.3 必须使用 GUI 授权的 root 进程")


def _assert_existing_identity(
    platform: str, *, backend: SecretStore | None = None
) -> _ExistingOnlySecretStore:
    config = _IDENTITY_CONFIGS[platform]
    payload = json.loads(_read_regular_file(config.data_dir / "public-identity.json"))
    if (
        payload.get("schema_version") != "managed-path-stage6-public-identity/v1"
        or payload.get("network_id") != str(_NETWORK_ID)
        or payload.get("node_id") != str(config.node_id)
        or payload.get("provider") != config.provider.value
        or payload.get("secret_reference_configured") is not True
        or not isinstance(payload.get("public_key"), str)
        or not isinstance(payload.get("public_key_hash"), str)
    ):
        raise SystemExit("阶段 6 本机公开身份绑定不一致")
    name = f"wireguard/{_NETWORK_ID}/{config.node_id}"
    try:
        selected_backend = backend
        if selected_backend is None:
            selected_backend = (
                _MacOSLoginKeychainSecretStore(expected_name=name)
                if platform == "macos"
                else KeyringSecretStore()
            )
        store = _ExistingOnlySecretStore(
            selected_backend,
            expected_name=name,
            expected_public_key=payload["public_key"],
            expected_public_key_hash=payload["public_key_hash"],
        )
        store.get(name)
    except SecretStoreError as exc:
        raise SystemExit("当前管理员上下文中的阶段 6 身份不可用或不匹配") from exc
    return store


def _evidence(
    platform: str,
    record: NetworkGovernanceRecord,
    *,
    provider: _CountingProvider,
    repository: _CountingAuthorizationRepository,
    verifier: _BarrierPathVerifier,
    acknowledgements: _AcknowledgementRecorder,
    observed_at: datetime,
    mode: str,
) -> dict[str, object]:
    phase = record.phase
    receipt = record.receipt
    verification = record.verification
    path_evidence = record.path_evidence
    selection = record.path_selection
    acknowledgement_delivered = record.acknowledgement_delivered
    return {
        "schema_version": "managed-path-stage6-apply/v1",
        "mode": mode,
        "platform": platform,
        "commit": _git_commit(),
        "entrypoint": "python -m scripts.managed_path_stage6_apply",
        "started_at": observed_at.isoformat(),
        "finished_at": datetime.now(UTC).isoformat(),
        "phase": phase.value,
        "record_stable_error_code": record.stable_error_code,
        "record": {
            "phase": phase.value,
            "stable_error_code": record.stable_error_code,
            "idempotency_key_hash": canonical_sha256({"idempotency_key": record.idempotency_key}),
        },
        "plan_hash": record.plan.plan_hash,
        "observed_fingerprint": record.plan.observed_fingerprint,
        "barrier": {
            "barrier_id_hash": canonical_sha256(
                {"barrier_id": verifier._barrier_id}  # pyright: ignore[reportPrivateUsage]
            ),
            "pair_hash": verifier._pair_hash,  # pyright: ignore[reportPrivateUsage]
            "authorization_hash": verifier._authorization_hash,  # pyright: ignore[reportPrivateUsage]
            "authorization_expires_at": (
                verifier._authorization_expires_at.isoformat()  # pyright: ignore[reportPrivateUsage]
                if verifier._authorization_expires_at  # pyright: ignore[reportPrivateUsage]
                else None
            ),
        },
        "authorization_reads": repository.list_calls,
        "authorization_ttl_seconds": _AUTHORIZATION_TTL_SECONDS,
        "provider_apply_calls": provider.apply_calls,
        "provider_rollback_calls": provider.rollback_calls,
        "recovery_invocations": 1 if mode == "recover" else 0,
        "provider_receipt": {
            "present": receipt is not None,
            "status": receipt.status.value if receipt is not None else None,
            "step_count": len(receipt.steps) if receipt is not None else 0,
        },
        "provider_verification": {
            "present": verification is not None,
            "succeeded": bool(verification and verification.succeeded),
        },
        "path": {
            "probe_runs": verifier.probe_runs,
            "target_attempt_ports": verifier.target_attempts,
            "verified": bool(path_evidence and path_evidence.verified),
            "target_host_hash": path_evidence.target_host_hash if path_evidence else None,
            "target_port": path_evidence.target_port if path_evidence else None,
            "selection": selection.path_type.value if selection else None,
            "selection_provider": selection.provider.value if selection else None,
            "selection_revision": selection.revision if selection else None,
            "selected_candidate_hash": (
                path_evidence.selected_candidate_hash if path_evidence else None
            ),
            "route_identity_hash": (path_evidence.route_identity_hash if path_evidence else None),
            "observed_at": (path_evidence.observed_at.isoformat() if path_evidence else None),
            "expires_at": (path_evidence.expires_at.isoformat() if path_evidence else None),
            "stable_error_code": (
                path_evidence.stable_error_code.value
                if path_evidence and path_evidence.stable_error_code
                else None
            ),
        },
        "target_attempt_markers": {
            label: {
                "attempt_hash": _marker_hash(
                    verifier._data_dir / f"stage6-target-{label}-attempt.json",  # pyright: ignore[reportPrivateUsage]
                    _ATTEMPT_KEYS,
                ),
                "result_hash": _marker_hash(
                    verifier._data_dir / f"stage6-target-{label}-result.json",  # pyright: ignore[reportPrivateUsage]
                    _RESULT_KEYS,
                ),
            }
            for label in ("primary", "fallback")
        },
        "acknowledgement": {
            "delivered": acknowledgement_delivered,
            "count": len(acknowledgements.items),
            "stage": acknowledgements.items[-1].stage.value if acknowledgements.items else None,
            "plan_hash": (acknowledgements.items[-1].plan_hash if acknowledgements.items else None),
            "receipt_hash": (
                acknowledgements.items[-1].receipt_hash if acknowledgements.items else None
            ),
        },
        "real_network_writes_performed": (provider.apply_calls > 0 or provider.rollback_calls > 0),
        "private_material_exported": False,
    }


if __name__ == "__main__":
    raise SystemExit(main())
