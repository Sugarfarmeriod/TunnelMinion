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
_MACOS_WIREGUARD_RUNTIME_ROOT = Path("/var/run/wireguard")
_MACOS_ROUTE = Path("/sbin/route")
_MACOS_PS = Path("/bin/ps")
_MACOS_OTOOL = Path("/usr/bin/otool")
_MACOS_STAGE6_RUNTIME_SCHEMA = "managed-path-stage6-macos-runtime/v1"
_MACOS_STAGE6_TOOL_SOURCES = {
    "wg": Path("/opt/homebrew/bin/wg"),
    "wireguard-go": Path("/opt/homebrew/bin/wireguard-go"),
}
_MACOS_STAGE6_TOOL_HASHES = {
    "wg": "5b7b2a5c1756e7afbb76047fb3f5b975d0c9b0ff905817283ec09ab2e11b9e57",
    "wireguard-go": "c62a563ac888d8c6ca9895ee6f7ac5e7297171f20bc7e1c7e0ec4d6d21415337",
}
_MACOS_STAGE6_LEGACY_WG_QUICK_HASH = (
    "1b8caefd878a3ffecfd8959a5d306c459d0cd645879071b5195ba538b2d40c15"
)
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
    """用两个固定工具直接管理 Stage 6 utun，不执行 `wg-quick`。"""

    def __init__(
        self,
        desired: DesiredNetworkConfig,
        *,
        paths: MacOSProviderPaths | None = None,
        platform_name: str | None = None,
        effective_uid: Callable[[], int] | None = None,
        runtime_root: Path = _MACOS_WIREGUARD_RUNTIME_ROOT,
        route_path: Path = _MACOS_ROUTE,
    ) -> None:
        self._desired = desired
        self._platform_name = sys.platform if platform_name is None else platform_name
        self._effective_uid = effective_uid or cast(
            Callable[[], int], getattr(os, "geteuid", lambda: -1)
        )
        self._paths = paths or _macos_stage6_paths()
        self._tools_root = self._paths.wg.parent
        self._config_root = self._paths.config_root
        self._runtime_root = runtime_root
        self._route_path = route_path
        self._operation_binding: tuple[str, str] | None = None
        self._wireguard_process: asyncio.subprocess.Process | None = None
        self._spawn_known_absent = False
        self._mutation_lock = asyncio.Lock()

    def bind_operation(self, plan_hash: str, creation_nonce: str) -> None:
        """绑定 Provider 已核准的计划与本次创建 nonce，不保存正文。"""
        if (
            _HASH_PATTERN.fullmatch(plan_hash) is None
            or re.fullmatch(r"[0-9a-f]{32}", creation_nonce) is None
        ):
            raise RuntimeError("Stage 6 macOS operation 绑定无效")
        self._operation_binding = (plan_hash, creation_nonce)

    def runtime_resources(self) -> tuple[str, ...]:
        """只返回固定制品的脱敏存在性 token，纳入 Provider 恢复 hash。"""
        name_file, marker_path, wg_config = self._runtime_paths()
        paths = (
            ("name", name_file),
            ("marker", marker_path),
            ("marker-temp", _private_temp_path(marker_path)),
            ("wg-config", wg_config),
            ("wg-config-temp", _private_temp_path(wg_config)),
        )
        return tuple(
            f"stage6:{label}" for label, path in paths if path.exists() or path.is_symlink()
        )

    async def run(self, command: tuple[str, ...], timeout_seconds: float) -> CommandResult:
        mutation = self._validate_command(command)
        self._verify_tool(Path(command[0]))
        if mutation:
            self._verify_tool(self._tools_root / "wireguard-go")
            self._validate_config(Path(command[2]))
            async with self._mutation_lock:
                try:
                    return await self._run_direct_manager(
                        command[1], Path(command[2]), timeout_seconds
                    )
                except (RuntimeError, TimeoutError):
                    return CommandResult(returncode=1, stdout="", stderr="")
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
        manager = str(self._paths.wg_quick)
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
            (manager, "up", expected_config),
            (manager, "down", expected_config),
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

    async def _run_direct_manager(
        self, action: str, config_path: Path, timeout_seconds: float
    ) -> CommandResult:
        if action == "up":
            await asyncio.wait_for(self._direct_up(config_path), timeout=timeout_seconds)
        elif action == "down":
            await asyncio.wait_for(self._direct_down(config_path), timeout=timeout_seconds)
        else:  # pragma: no cover - `_validate_command` 已封闭动作集合
            raise RuntimeError("Stage 6 macOS direct manager 动作无效")
        return CommandResult(returncode=0, stdout="", stderr="")

    def _direct_parameters(self) -> tuple[str, str]:
        approved = _CONFIGS["macos"]
        peers = self._desired.peers
        routes = tuple(route for peer in self._desired.peers for route in peer.allowed_host_routes)
        if (
            self._desired.provider.value != "macos"
            or self._desired.network_id != _NETWORK_ID
            or self._desired.target_node_id != approved.node_id
            or self._desired.revision != 1
            or self._desired.parent_revision != 0
            or self._desired.interface_name != approved.interface_name
            or self._desired.address != approved.address
            or self._desired.listen_port != approved.listen_port
            or self._desired.allowed_route_overlaps != approved.allowed_route_overlaps
            or len(peers) != 1
            or peers[0].node_id != approved.peer_node_id
            or routes != (approved.peer_host_route,)
            or peers[0].persistent_keepalive_seconds != 25
            or len(peers[0].candidates) != 1
            or peers[0].candidates[0].host != approved.peer_endpoint_host
            or peers[0].candidates[0].port != approved.peer_endpoint_port
            or peers[0].candidates[0].source.value != "admin_explicit"
        ):
            raise RuntimeError("Stage 6 macOS direct manager 资源超出批准范围")
        return self._desired.address, routes[0]

    def _runtime_paths(self) -> tuple[Path, Path, Path]:
        stem = f"{self._desired.interface_name}.r{self._desired.revision}"
        return (
            self._runtime_root / f"{stem}.name",
            _MACOS_STAGE6_ROOT / "runtime" / f"{stem}.json",
            self._config_root / f"{stem}.wg.conf",
        )

    async def _direct_up(self, config_path: Path) -> None:
        if self._operation_binding is None:
            raise RuntimeError("Stage 6 macOS direct manager 缺少计划绑定")
        address, host_route = self._direct_parameters()
        _assert_root_owned_path(self._runtime_root)
        if not self._runtime_root.is_dir():
            raise RuntimeError("Stage 6 macOS WireGuard runtime 目录无效")
        name_file, marker_path, wg_config = self._runtime_paths()
        runtime_materials = (
            name_file,
            marker_path,
            _private_temp_path(marker_path),
            wg_config,
            _private_temp_path(wg_config),
        )
        if any(path.exists() or path.is_symlink() for path in runtime_materials):
            raise RuntimeError("Stage 6 macOS direct manager 存在未清理运行材料")
        _ensure_macos_stage6_directory(marker_path.parent)
        plan_hash, creation_nonce = self._operation_binding
        public_key_hash = self._config_public_key_hash(config_path)
        marker = self._runtime_marker_payload(
            phase="preparing",
            plan_hash=plan_hash,
            creation_nonce=creation_nonce,
            public_key_hash=public_key_hash,
        )
        _write_root_private_json(marker_path, marker)
        try:
            self._write_wg_only_config(config_path, wg_config)
            started_at = datetime.now(UTC)
            try:
                process = await asyncio.create_subprocess_exec(
                    str(self._tools_root / "wireguard-go"),
                    "-f",
                    "utun",
                    stdin=asyncio.subprocess.DEVNULL,
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                    env={
                        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
                        "WG_TUN_NAME_FILE": str(name_file),
                    },
                    start_new_session=True,
                )
            except OSError:
                self._spawn_known_absent = True
                raise
            self._wireguard_process = process
            runtime_interface = await self._wait_runtime_name(name_file, process)
            marker = self._runtime_marker_payload(
                phase="spawned",
                plan_hash=plan_hash,
                creation_nonce=creation_nonce,
                public_key_hash=public_key_hash,
                runtime_interface=runtime_interface,
                pid=process.pid,
                started_at=started_at,
            )
            _write_root_private_json(marker_path, marker)
            await self._run_private_command(
                (str(self._paths.wg), "setconf", runtime_interface, str(wg_config))
            )
            marker["phase"] = "configured"
            _write_root_private_json(marker_path, marker)
            await self._run_private_command(
                (
                    str(self._paths.ifconfig),
                    runtime_interface,
                    "inet",
                    address.removesuffix("/32"),
                    address.removesuffix("/32"),
                    "netmask",
                    "255.255.255.255",
                )
            )
            await self._run_private_command((str(self._paths.ifconfig), runtime_interface, "up"))
            marker["phase"] = "addressed"
            _write_root_private_json(marker_path, marker)
            await self._run_private_command(
                (
                    str(self._route_path),
                    "-q",
                    "-n",
                    "add",
                    "-inet",
                    host_route,
                    "-interface",
                    runtime_interface,
                )
            )
            marker["phase"] = "routed"
            _write_root_private_json(marker_path, marker)
        except BaseException:
            try:
                await asyncio.shield(self._direct_down(config_path))
            except BaseException:
                raise RuntimeError(
                    "Stage 6 macOS direct manager apply 状态不确定且必须恢复"
                ) from None
            raise

    def _runtime_marker_payload(
        self,
        *,
        phase: str,
        plan_hash: str,
        creation_nonce: str,
        public_key_hash: str,
        runtime_interface: str | None = None,
        pid: int | None = None,
        started_at: datetime | None = None,
    ) -> dict[str, object]:
        return {
            "schema_version": _MACOS_STAGE6_RUNTIME_SCHEMA,
            "phase": phase,
            "provider": self._desired.provider.value,
            "network_id": str(self._desired.network_id),
            "node_id": str(self._desired.target_node_id),
            "interface_name": self._desired.interface_name,
            "revision": self._desired.revision,
            "runtime_interface": runtime_interface,
            "pid": pid,
            "started_at": started_at.isoformat() if started_at is not None else None,
            "wireguard_go_hash": f"sha256:{_MACOS_STAGE6_TOOL_HASHES['wireguard-go']}",
            "plan_hash": plan_hash,
            "creation_nonce_hash": canonical_sha256({"creation_nonce": creation_nonce}),
            "public_key_hash": public_key_hash,
        }

    async def _direct_down(self, config_path: Path) -> None:
        del config_path
        if self._operation_binding is None:
            raise RuntimeError("Stage 6 macOS direct manager 缺少恢复绑定")
        _, host_route = self._direct_parameters()
        name_file, marker_path, wg_config = self._runtime_paths()
        marker_temp = _private_temp_path(marker_path)
        wg_config_temp = _private_temp_path(wg_config)
        if not marker_path.exists() and not marker_path.is_symlink():
            if (marker_temp.exists() or marker_temp.is_symlink()) and not any(
                path.exists() or path.is_symlink()
                for path in (name_file, wg_config, wg_config_temp)
            ):
                _assert_root_owned_path(marker_temp, regular_file=True, exact_mode=0o600)
                await self._assert_udp_port_absent()
                marker_temp.unlink()
                return
            raise RuntimeError("Stage 6 macOS intent marker 缺失且残留组合不可证明")
        marker = _load_macos_runtime_marker(marker_path)
        plan_hash, creation_nonce = self._operation_binding
        if marker["plan_hash"] != plan_hash or marker["creation_nonce_hash"] != canonical_sha256(
            {"creation_nonce": creation_nonce}
        ):
            raise RuntimeError("Stage 6 macOS runtime marker 操作绑定不匹配")
        marker_pid = cast(int | None, marker["pid"])
        started_at = cast(str | None, marker["started_at"])
        runtime_interface = cast(str | None, marker["runtime_interface"])
        if (
            marker["phase"] == "preparing"
            and self._wireguard_process is None
            and marker_pid is None
            and started_at is None
        ):
            uncertain_private_material = marker_temp.exists() or marker_temp.is_symlink()
            uncertain_spawn_material = (
                name_file.exists()
                or name_file.is_symlink()
                or runtime_interface is not None
                or ((wg_config.exists() or wg_config.is_symlink()) and not self._spawn_known_absent)
            )
            if uncertain_private_material or uncertain_spawn_material:
                raise RuntimeError("Stage 6 macOS pre-spawn 结果无法证明，必须人工恢复")
            route_table = await self._run_private_command(
                (str(self._paths.netstat), "-rn", "-f", "inet")
            )
            if _exact_macos_route_interfaces(route_table or "", host_route):
                raise RuntimeError("Stage 6 macOS pre-spawn 出现不可能的 host route")
            await self._assert_udp_port_absent()
            for path in (wg_config_temp, wg_config, marker_path):
                if path.exists() or path.is_symlink():
                    _assert_root_owned_path(path, regular_file=True)
                    path.unlink()
            return
        if runtime_interface is None:
            runtime_interface = await self._recover_runtime_name(name_file)
        pid = (
            self._wireguard_process.pid
            if marker_pid is None and self._wireguard_process is not None
            else marker_pid
        )
        current_process_owned = (
            pid is not None
            and self._wireguard_process is not None
            and pid == self._wireguard_process.pid
            and self._wireguard_process.returncode is None
        )
        process_owned = current_process_owned or (
            pid is not None
            and started_at is not None
            and await self._same_macos_process(pid, started_at)
        )
        runtime_public_hash = (
            await self._runtime_public_key_hash(runtime_interface, allow_absent=True)
            if runtime_interface is not None
            else None
        )
        if runtime_public_hash is not None and marker["public_key_hash"] != runtime_public_hash:
            raise RuntimeError("Stage 6 macOS runtime 接口所有权不匹配")
        if runtime_public_hash is not None and not process_owned:
            raise RuntimeError("Stage 6 macOS runtime 进程所有权不匹配")
        route_table = await self._run_private_command(
            (str(self._paths.netstat), "-rn", "-f", "inet")
        )
        route_interfaces = _exact_macos_route_interfaces(route_table or "", host_route)
        if route_interfaces:
            if (
                marker["phase"] not in {"addressed", "routed"}
                or not process_owned
                or runtime_public_hash is None
                or marker["public_key_hash"] != runtime_public_hash
            ):
                raise RuntimeError("Stage 6 macOS host route 进程或接口所有权不匹配")
            if route_interfaces != (runtime_interface,):
                raise RuntimeError("Stage 6 macOS host route 所有权不匹配")
            owned_runtime_interface = cast(str, runtime_interface)
            await self._run_private_command(
                (
                    str(self._route_path),
                    "-q",
                    "-n",
                    "delete",
                    "-inet",
                    host_route,
                    "-interface",
                    owned_runtime_interface,
                )
            )
        socket_path = (
            self._runtime_root / f"{runtime_interface}.sock"
            if runtime_interface is not None
            else None
        )
        if socket_path is not None and (socket_path.exists() or socket_path.is_symlink()):
            intent_owned = marker["phase"] == "preparing" and marker_pid is None
            if not process_owned and not intent_owned:
                raise RuntimeError("Stage 6 macOS control socket 进程绑定不匹配")
            _assert_root_owned_socket(socket_path)
            socket_path.unlink()
        elif process_owned and current_process_owned and self._wireguard_process is not None:
            await self._terminate_process_group(self._wireguard_process)
        elif process_owned and pid is not None and started_at is not None:
            await self._terminate_bound_process(pid, started_at)
        if runtime_interface is not None:
            await self._wait_interface_absent(runtime_interface)
        if pid is not None and started_at is not None:
            await self._wait_bound_process_absent(pid, started_at)
        elif self._wireguard_process is not None:
            try:
                await asyncio.wait_for(self._wireguard_process.wait(), timeout=2)
            except TimeoutError:
                raise RuntimeError("Stage 6 macOS runtime 进程未确认退出") from None
        await self._assert_udp_port_absent()
        # intent marker 必须最后删除，确保任一清理中断仍可被下一次 recover 识别。
        for path in (name_file, wg_config_temp, wg_config, marker_temp, marker_path):
            if path.exists() or path.is_symlink():
                _assert_root_owned_path(path, regular_file=True)
                path.unlink()
        self._wireguard_process = None

    async def _recover_runtime_name(self, name_file: Path) -> str | None:
        for _ in range(20):
            if name_file.exists() or name_file.is_symlink():
                _assert_root_owned_path(name_file, regular_file=True)
                try:
                    runtime = name_file.read_text(encoding="ascii", errors="strict").strip()
                except (OSError, UnicodeError):
                    raise RuntimeError("Stage 6 macOS runtime name 不可验证") from None
                if re.fullmatch(r"utun[0-9]+", runtime) is None:
                    raise RuntimeError("Stage 6 macOS runtime name 不匹配")
                return runtime
            await asyncio.sleep(0.05)
        return None

    async def _run_private_command(
        self,
        command: tuple[str, ...],
        *,
        allow_failure: bool = False,
        timeout_seconds: float = 5,
    ) -> str | None:
        executable = Path(command[0])
        if executable == self._paths.wg:
            self._verify_tool(executable)
        else:
            _assert_root_owned_path(executable, regular_file=True)
        process = await asyncio.create_subprocess_exec(
            *command,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
            env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin"},
            start_new_session=True,
        )
        try:
            stdout, _ = await asyncio.wait_for(process.communicate(), timeout=timeout_seconds)
        except TimeoutError:
            await self._terminate_process_group(process)
            raise RuntimeError("Stage 6 macOS 固定网络步骤超时") from None
        except asyncio.CancelledError:
            await asyncio.shield(self._terminate_process_group(process))
            raise
        if process.returncode != 0:
            if allow_failure:
                return None
            raise RuntimeError("Stage 6 macOS 固定网络步骤失败")
        return stdout.decode("utf-8", errors="strict")

    async def _wait_runtime_name(self, name_file: Path, process: asyncio.subprocess.Process) -> str:
        for _ in range(100):
            if process.returncode is not None:
                raise RuntimeError("Stage 6 macOS wireguard-go 启动失败")
            if name_file.exists():
                _assert_root_owned_path(name_file, regular_file=True)
                runtime = name_file.read_text(encoding="ascii", errors="strict").strip()
                if re.fullmatch(r"utun[0-9]+", runtime) is None:
                    raise RuntimeError("Stage 6 macOS runtime 接口名称无效")
                return runtime
            await asyncio.sleep(0.05)
        raise RuntimeError("Stage 6 macOS runtime 接口创建超时")

    async def _wait_interface_absent(self, runtime_interface: str) -> None:
        for _ in range(100):
            result = await self._run_private_command((str(self._paths.wg), "show", "interfaces"))
            if result is not None and runtime_interface not in result.split():
                process = self._wireguard_process
                if process is not None:
                    try:
                        await asyncio.wait_for(process.wait(), timeout=2)
                    except TimeoutError:
                        raise RuntimeError("Stage 6 macOS wireguard-go 未确认退出") from None
                return
            await asyncio.sleep(0.05)
        raise RuntimeError("Stage 6 macOS runtime 接口未确认清理")

    async def _runtime_public_key_hash(
        self, runtime_interface: str, *, allow_absent: bool = False
    ) -> str | None:
        value = await self._run_private_command(
            (str(self._paths.wg), "show", runtime_interface, "public-key"),
            allow_failure=allow_absent,
        )
        if allow_absent and value is None:
            return None
        if value is None or not value.strip():
            raise RuntimeError("Stage 6 macOS runtime 公开身份不可读取")
        return canonical_sha256({"public_key": value.strip()})

    async def _same_macos_process(self, pid: int, started_at: str) -> bool:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            raise RuntimeError("Stage 6 macOS runtime PID 不可验证") from None
        process_path = _macos_process_path(pid)
        try:
            same_executable = process_path is not None and os.path.samefile(
                process_path, self._tools_root / "wireguard-go"
            )
        except OSError:
            same_executable = False
        if not same_executable:
            return False
        started = await self._run_private_command((str(_MACOS_PS), "-p", str(pid), "-o", "lstart="))
        try:
            observed = datetime.strptime((started or "").strip(), "%a %b %d %H:%M:%S %Y")
            observed = observed.astimezone().astimezone(UTC)
            expected = datetime.fromisoformat(started_at).astimezone(UTC)
        except ValueError:
            raise RuntimeError("Stage 6 macOS runtime 启动时间不可验证") from None
        return abs((observed - expected).total_seconds()) <= 5

    async def _terminate_bound_process(self, pid: int, started_at: str) -> None:
        if not await self._same_macos_process(pid, started_at):
            return
        with contextlib.suppress(ProcessLookupError):
            os.killpg(pid, signal.SIGTERM)  # pyright: ignore
        for _ in range(40):
            if not await self._same_macos_process(pid, started_at):
                return
            await asyncio.sleep(0.05)
        if not await self._same_macos_process(pid, started_at):
            return
        with contextlib.suppress(ProcessLookupError):
            os.killpg(pid, 9)  # pyright: ignore
        for _ in range(40):
            if not await self._same_macos_process(pid, started_at):
                return
            await asyncio.sleep(0.05)
        raise RuntimeError("Stage 6 macOS runtime 进程未确认终止")

    async def _wait_bound_process_absent(self, pid: int, started_at: str) -> None:
        for _ in range(100):
            if not await self._same_macos_process(pid, started_at):
                return
            await asyncio.sleep(0.05)
        raise RuntimeError("Stage 6 macOS runtime PID 未确认退出")

    async def _assert_udp_port_absent(self) -> None:
        output = await self._run_private_command((str(self._paths.netstat), "-anv", "-p", "udp"))
        port = self._desired.listen_port
        if port is None:
            raise RuntimeError("Stage 6 macOS UDP 端口绑定缺失")
        if _macos_udp_port_present(output or "", port):
            raise RuntimeError("Stage 6 macOS UDP listener 未确认清理")

    def _config_public_key_hash(self, config_path: Path) -> str:
        private_value = next(
            (
                line.removeprefix("PrivateKey = ")
                for line in config_path.read_text(encoding="utf-8").splitlines()
                if line.startswith("PrivateKey = ")
            ),
            "",
        )
        try:
            private_bytes = base64.b64decode(private_value, validate=True)
            public_bytes = (
                X25519PrivateKey.from_private_bytes(private_bytes)
                .public_key()
                .public_bytes(
                    serialization.Encoding.Raw,
                    serialization.PublicFormat.Raw,
                )
            )
        except (ValueError, TypeError):
            raise RuntimeError("Stage 6 macOS 配置公开身份不可导出") from None
        public_text = base64.b64encode(public_bytes).decode("ascii")
        return canonical_sha256({"public_key": public_text})

    def _write_wg_only_config(self, source: Path, target: Path) -> None:
        lines = source.read_text(encoding="utf-8", errors="strict").splitlines()
        filtered = [line for line in lines if not line.startswith("Address = ")]
        if len(lines) - len(filtered) != 1:
            raise RuntimeError("Stage 6 macOS Address 配置数量无效")
        _write_root_private_bytes(target, ("\n".join(filtered) + "\n").encode("utf-8"))

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
        # 通用 backend 仍把此槽位当 manager；Stage 6 runner 拦截 up/down，
        # 实际只执行下面这个 hash-pinned wireguard-go 和固定系统 argv。
        wg_quick=tools / "wireguard-go",
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


def _exact_macos_route_interfaces(stdout: str, host_route: str) -> tuple[str, ...]:
    """只提取批准 `/32` 的接口列；不把宽路由当成可删除目标。"""
    host = host_route.removesuffix("/32")
    interfaces: list[str] = []
    for line in stdout.splitlines():
        parts = line.split()
        if len(parts) >= 4 and parts[0] in {host, host_route}:
            interfaces.append(parts[-1])
    return tuple(interfaces)


def _macos_udp_port_present(stdout: str, port: int) -> bool:
    suffixes = (f".{port}", f":{port}")
    for line in stdout.splitlines():
        parts = line.split()
        if len(parts) >= 5 and parts[0].startswith("udp") and parts[3].endswith(suffixes):
            return True
    return False


def _macos_process_path(pid: int) -> Path | None:
    """通过 macOS libproc 读取 PID 的真实可执行路径，不执行动态命令。"""
    if sys.platform != "darwin":
        return None
    try:
        libproc = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
        function = libproc.proc_pidpath
        function.argtypes = (ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32)
        function.restype = ctypes.c_int
        buffer = ctypes.create_string_buffer(4096)
        length = function(pid, buffer, len(buffer))
        if length <= 0:
            return None
        return Path(buffer.value.decode("utf-8", errors="strict"))
    except (OSError, UnicodeError, AttributeError):
        return None


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


def _assert_root_owned_socket(path: Path) -> None:
    try:
        info = os.lstat(path)
    except OSError:
        raise RuntimeError("Stage 6 macOS WireGuard control socket 不存在") from None
    if info.st_uid != 0 or stat.S_ISLNK(info.st_mode) or not stat.S_ISSOCK(info.st_mode):
        raise RuntimeError("Stage 6 macOS WireGuard control socket 身份不可信")


def _write_root_private_bytes(path: Path, payload: bytes) -> None:
    """在已验证的 Stage 6 根目录内原子写入 root-only 文件。"""
    if _MACOS_STAGE6_ROOT not in path.parents:
        raise RuntimeError("Stage 6 macOS 私有文件路径越界")
    _assert_root_owned_path(path.parent)
    temporary = _private_temp_path(path)
    descriptor = -1
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            view = view[written:]
        os.fchmod(descriptor, 0o600)  # pyright: ignore
        os.fchown(descriptor, 0, 0)  # pyright: ignore
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.replace(temporary, path)
        _assert_root_owned_path(path, regular_file=True, exact_mode=0o600)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary.exists() or temporary.is_symlink():
            temporary.unlink()


def _private_temp_path(path: Path) -> Path:
    """为单写者原子写固定唯一临时路径，便于 crash recovery 精确回收。"""
    return path.parent / f".{path.name}.tmp"


def _write_root_private_json(path: Path, payload: dict[str, object]) -> None:
    _write_root_private_bytes(
        path,
        (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8"),
    )


def _load_macos_runtime_marker(path: Path) -> dict[str, object]:
    _assert_root_owned_path(path, regular_file=True, exact_mode=0o600)
    try:
        raw = json.loads(path.read_text(encoding="utf-8", errors="strict"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise RuntimeError("Stage 6 macOS runtime marker 不可验证") from None
    if not isinstance(raw, dict):
        raise RuntimeError("Stage 6 macOS runtime marker schema 不匹配")
    payload = cast(dict[str, object], raw)
    expected_keys = {
        "schema_version",
        "phase",
        "provider",
        "network_id",
        "node_id",
        "interface_name",
        "revision",
        "runtime_interface",
        "pid",
        "started_at",
        "wireguard_go_hash",
        "plan_hash",
        "creation_nonce_hash",
        "public_key_hash",
    }
    hashes = (
        payload.get("wireguard_go_hash"),
        payload.get("plan_hash"),
        payload.get("creation_nonce_hash"),
        payload.get("public_key_hash"),
    )
    started_raw = payload.get("started_at")
    if isinstance(started_raw, str):
        try:
            started_at = datetime.fromisoformat(started_raw)
        except ValueError:
            started_at = None
    else:
        started_at = None
    phase = payload.get("phase")
    preparing = phase == "preparing"
    runtime = payload.get("runtime_interface")
    pid = payload.get("pid")
    if (
        set(payload) != expected_keys
        or payload.get("schema_version") != _MACOS_STAGE6_RUNTIME_SCHEMA
        or phase not in {"preparing", "spawned", "configured", "addressed", "routed"}
        or payload.get("provider") != "macos"
        or payload.get("network_id") != str(_NETWORK_ID)
        or payload.get("node_id") != str(_CONFIGS["macos"].node_id)
        or payload.get("interface_name") != _CONFIGS["macos"].interface_name
        or payload.get("revision") != 1
        or (preparing and (runtime is not None or pid is not None or started_raw is not None))
        or (
            not preparing
            and (
                re.fullmatch(r"utun[0-9]+", str(runtime)) is None
                or not isinstance(pid, int)
                or pid <= 0
                or started_at is None
                or started_at.tzinfo is None
                or started_at.utcoffset() != timedelta(0)
            )
        )
        or any(
            not isinstance(value, str) or _HASH_PATTERN.fullmatch(value) is None for value in hashes
        )
        or payload.get("wireguard_go_hash") != f"sha256:{_MACOS_STAGE6_TOOL_HASHES['wireguard-go']}"
    ):
        raise RuntimeError("Stage 6 macOS runtime marker schema 不匹配")
    return payload


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
    legacy = tools_root / "wg-quick"
    removed: list[str] = []
    if legacy.exists() or legacy.is_symlink():
        _assert_root_owned_path(legacy, regular_file=True, exact_mode=0o500)
        if _sha256_file(legacy) != _MACOS_STAGE6_LEGACY_WG_QUICK_HASH:
            raise SystemExit("Stage 6 macOS legacy wg-quick 身份不匹配")
        legacy.unlink()
        removed.append("wg-quick")
    installed: list[str] = []
    for name, source in _MACOS_STAGE6_TOOL_SOURCES.items():
        target = tools_root / name
        expected_hash = _MACOS_STAGE6_TOOL_HASHES[name]
        if target.exists() or target.is_symlink():
            _assert_root_owned_path(target, regular_file=True, exact_mode=0o500)
            if _sha256_file(target) != expected_hash:
                raise SystemExit("Stage 6 macOS 已安装固定工具 hash 不匹配")
            _validate_macos_tool_closure(target)
            continue
        _validate_macos_tool_closure(source)
        _copy_hash_pinned_tool(source, target, expected_hash)
        _validate_macos_tool_closure(target)
        installed.append(name)
    return {
        "installed": installed,
        "removed": removed,
        "root": str(_MACOS_STAGE6_ROOT),
        "success": True,
    }


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


def _validate_macos_tool_closure(
    path: Path,
    *,
    run_process: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> None:
    """拒绝 Mach-O 加载任何非 Apple 绝对系统库或动态 rpath。"""
    _assert_root_owned_path(_MACOS_OTOOL, regular_file=True)
    try:
        completed = run_process(
            (str(_MACOS_OTOOL), "-L", str(path)),
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="strict",
            timeout=10,
            env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin"},
        )
    except (OSError, subprocess.SubprocessError, UnicodeError):
        raise SystemExit("Stage 6 macOS 工具动态库闭包不可验证") from None
    lines = completed.stdout.splitlines()
    dependencies = tuple(
        line.strip().split(" (", maxsplit=1)[0] for line in lines[1:] if line.strip()
    )
    if (
        completed.returncode != 0
        or not lines
        or not dependencies
        or any(
            not dependency.startswith(("/usr/lib/", "/System/Library/"))
            for dependency in dependencies
        )
    ):
        raise SystemExit("Stage 6 macOS 工具动态库闭包超出 Apple 系统范围")


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


class _ProvidedSecretStore:
    """只在当前进程内提供一次固定身份，不允许任何写入。"""

    def __init__(self, *, expected_name: str, value: str) -> None:
        self._expected_name = expected_name
        self._value = value

    def get(self, name: str) -> str | None:
        if name != self._expected_name:
            raise SecretStoreError("阶段 6 stdin 身份引用不在批准范围")
        return self._value

    def set(self, name: str, value: str) -> None:
        del name, value
        raise SecretStoreError("阶段 6 stdin 身份禁止写入")

    def delete(self, name: str) -> None:
        del name
        raise SecretStoreError("阶段 6 stdin 身份禁止删除")


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
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--apply", action="store_true")
    mode.add_argument("--release-barrier", action="store_true")
    mode.add_argument("--recover", action="store_true")
    mode.add_argument("--rollback-create", action="store_true")
    mode.add_argument("--install-macos-execution-materials", action="store_true")
    mode.add_argument("--import-peer-ready", action="store_true")
    parser.add_argument("--identity-stdin", action="store_true")
    args = parser.parse_args(argv)
    if len(args.barrier_id) != 32 or any(
        char not in "0123456789abcdef" for char in args.barrier_id
    ):
        raise SystemExit("barrier id 必须是 32 位小写十六进制")
    _require_matching_platform(args.platform)
    if args.install_macos_execution_materials:
        if args.identity_stdin:
            raise SystemExit("安装固定工具不得接收阶段 6 身份")
        if args.platform != "macos":
            raise SystemExit("Stage 6 macOS 固定工具只允许在 macOS 安装")
        result = _install_macos_stage6_tools()
        print(json.dumps(result, sort_keys=True))
        return 0
    if args.import_peer_ready:
        if args.identity_stdin:
            raise SystemExit("导入 peer-ready 不得接收阶段 6 身份")
        _require_elevated(args.platform)
        result = _import_peer_ready(args.platform, args.barrier_id, sys.stdin.read())
        print(json.dumps(result, sort_keys=True))
        return 0
    if args.release_barrier:
        if args.identity_stdin:
            raise SystemExit("释放 barrier 不得接收阶段 6 身份")
        _require_elevated(args.platform)
        _release_barrier(args.platform, args.barrier_id)
        return 0
    identity_backend = _read_identity_stdin(args.platform) if args.identity_stdin else None
    result = asyncio.run(
        _run(
            args.platform,
            args.barrier_id,
            now=datetime.now(UTC),
            recover=args.recover,
            rollback_create=args.rollback_create,
            identity_backend=identity_backend,
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
    identity_backend: SecretStore | None = None,
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
    identity_store = _assert_existing_identity(platform, backend=identity_backend)
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
        approved_by="stage6-explicit-user-authorization-20260828",
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


def _import_peer_ready(platform: str, barrier_id: str, raw: str) -> dict[str, object]:
    """从操作员前台粘贴导入对端公开 barrier，不接收任何秘密。"""
    if len(raw.encode("utf-8")) > 4096:
        raise SystemExit("阶段 6.3 peer-ready marker 超出固定大小上限")
    try:
        decoded = json.loads(raw)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise SystemExit("阶段 6.3 peer-ready marker 不是有效 JSON") from exc
    if not isinstance(decoded, dict):
        raise SystemExit("阶段 6.3 peer-ready marker schema 不匹配")
    payload = cast(dict[str, object], decoded)
    if frozenset(payload) != _READY_KEYS:
        raise SystemExit("阶段 6.3 peer-ready marker schema 不匹配")
    peer_platform = "macos" if platform == "windows" else "windows"
    barrier_hash = canonical_sha256({"barrier_id": barrier_id})
    try:
        _validate_ready_marker(payload, platform=peer_platform, barrier_hash=barrier_hash)
    except RuntimeError as exc:
        raise SystemExit("阶段 6.3 peer-ready marker 绑定或 TTL 无效") from exc
    data_dir = _APPROVED_DATA_DIRS[platform]
    _assert_trusted_data_dir(data_dir, data_dir)
    _publish_or_validate(data_dir / "stage6-apply-peer-ready.json", payload)
    return {
        "barrier_id_hash": barrier_hash,
        "peer_platform": peer_platform,
        "peer_ready_imported": True,
        "private_material_imported": False,
    }


def _require_elevated(platform: str) -> None:
    if platform == "windows":
        windll = getattr(ctypes, "windll", None)
        if windll is None or not bool(windll.shell32.IsUserAnAdmin()):
            raise SystemExit("Windows 阶段 6.3 必须使用已提升管理员令牌")
    effective_uid = cast(Callable[[], int], getattr(os, "geteuid", lambda: -1))
    if platform == "macos" and effective_uid() != 0:
        raise SystemExit("macOS 阶段 6.3 必须使用已授权的 root 进程")


def _read_identity_stdin(platform: str) -> _ProvidedSecretStore:
    """从匿名 stdin 读取一次固定身份，不回显也不持久化。"""
    name = f"wireguard/{_NETWORK_ID}/{_IDENTITY_CONFIGS[platform].node_id}"
    value = sys.stdin.readline(257).rstrip("\r\n")
    if not value or len(value) > 128 or any(char.isspace() for char in value):
        value = ""
        raise SystemExit("阶段 6 stdin 身份格式无效")
    return _ProvidedSecretStore(expected_name=name, value=value)


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
        raise SystemExit("当前执行上下文中的阶段 6 身份不可用或不匹配") from exc
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
        "entrypoint": f"python -m scripts.managed_path_stage6_apply --{mode}",
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
