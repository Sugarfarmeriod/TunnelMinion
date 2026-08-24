"""为阶段 6 隔离资源生成本机身份，只导出公开身份文件。"""

from __future__ import annotations

import argparse
import ctypes
import json
import os
import secrets
import stat
import sys
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, cast

from tunnelminion.domain.identifiers import NetworkId, NodeId
from tunnelminion.network.contracts import LocalNetworkKeyMaterial, ProviderKind
from tunnelminion.network.ledger import SQLiteManagedResourceLedger
from tunnelminion.platforms.macos.managed_path import build_macos_managed_path_platform
from tunnelminion.platforms.windows.managed_path import build_windows_managed_path_platform

_NETWORK_ID = NetworkId("network_60000000000000000000000000000000")


class _IdentityProvider(Protocol):
    def create_local_identity(
        self,
        network_id: NetworkId,
        node_id: NodeId,
    ) -> LocalNetworkKeyMaterial: ...


class _WindowsShell32(Protocol):
    def IsUserAnAdmin(self) -> int: ...


class _WindowsDlls(Protocol):
    shell32: _WindowsShell32


@dataclass(frozen=True, slots=True)
class _PlatformConfig:
    provider: ProviderKind
    node_id: NodeId
    data_dir: Path


_APPROVED_DATA_DIRS = {
    "windows": Path(r"F:\Project\codex\tunnelminion-stage6-data\windows"),
    "macos": Path("/Volumes/DarkAI/Codex-project/Side project/Tunnelminion-stage6-data/macos"),
}

_CONFIGS = {
    "windows": _PlatformConfig(
        provider=ProviderKind.WINDOWS,
        node_id=NodeId("node_6000000000000000000000000000000a"),
        data_dir=_APPROVED_DATA_DIRS["windows"],
    ),
    "macos": _PlatformConfig(
        provider=ProviderKind.MACOS,
        node_id=NodeId("node_6000000000000000000000000000000b"),
        data_dir=_APPROVED_DATA_DIRS["macos"],
    ),
}


def main(argv: list[str] | None = None) -> int:
    """首次生成隔离身份；既有或中断状态一律拒绝复用。"""
    parser = argparse.ArgumentParser()
    parser.add_argument("--platform", choices=tuple(_CONFIGS), required=True)
    args = parser.parse_args(argv)
    config = _CONFIGS[args.platform]
    _require_matching_platform(args.platform)
    _require_unprivileged(args.platform)
    approved_data_dir = _APPROVED_DATA_DIRS[args.platform]
    _assert_trusted_data_dir(config.data_dir, approved_data_dir)
    config.data_dir.mkdir(parents=True, exist_ok=True)
    _assert_trusted_data_dir(config.data_dir, approved_data_dir)
    intent = config.data_dir / ".identity-creation-in-progress"
    output = config.data_dir / "public-identity.json"
    if intent.exists() or intent.is_symlink() or output.exists() or output.is_symlink():
        raise SystemExit("身份已存在或上次创建未完整结束，拒绝读取或覆盖")
    _write_creation_intent(intent)
    ledger = SQLiteManagedResourceLedger(config.data_dir / "managed-network-ledger.sqlite3")
    dependencies = (
        build_windows_managed_path_platform(config.data_dir, ledger)
        if args.platform == "windows"
        else build_macos_managed_path_platform(config.data_dir, ledger)
    )
    provider = cast(_IdentityProvider, dependencies.provider)
    material = provider.create_local_identity(_NETWORK_ID, config.node_id)
    payload = {
        "schema_version": "managed-path-stage6-public-identity/v1",
        "network_id": str(_NETWORK_ID),
        "node_id": str(config.node_id),
        "provider": config.provider.value,
        "public_key": material.public_key,
        "public_key_hash": material.public_key_hash,
        "secret_reference_configured": True,
    }
    _publish_public_identity(output, payload)
    _assert_trusted_data_dir(config.data_dir, approved_data_dir)
    intent.unlink()
    _fsync_directory(config.data_dir)
    _assert_trusted_data_dir(config.data_dir, approved_data_dir)
    print(
        json.dumps(
            {
                "identity_written": True,
                "platform": args.platform,
                "secret_reference_configured": True,
                "private_material_exported": False,
            },
            sort_keys=True,
        )
    )
    return 0


def _require_matching_platform(platform: str) -> None:
    if platform == "windows" and os.name != "nt":
        raise SystemExit("Windows identity 只能在 Windows 运行")
    if platform == "macos" and sys.platform != "darwin":
        raise SystemExit("macOS identity 只能在 macOS 运行")


def _require_unprivileged(platform: str) -> None:
    """身份创建固定使用普通用户；管理员仅留给后续 Provider apply。"""
    if platform == "windows":
        windows_dlls = cast(_WindowsDlls | None, getattr(ctypes, "windll", None))
        if windows_dlls is None:
            raise SystemExit("无法确认 Windows 管理员令牌状态")
        if bool(windows_dlls.shell32.IsUserAnAdmin()):
            raise SystemExit("Windows 身份创建禁止使用管理员令牌")
    effective_uid = cast(Callable[[], int], getattr(os, "geteuid", lambda: -1))
    if platform == "macos" and effective_uid() == 0:
        raise SystemExit("macOS 身份创建禁止使用 root")


def _assert_trusted_data_dir(data_dir: Path, approved_data_dir: Path) -> None:
    """拒绝获准数据路径任一既有组件上的链接或重解析点。"""
    if not data_dir.is_absolute():
        raise SystemExit("阶段 6 数据目录必须是绝对路径")
    canonical = os.path.normcase(os.path.abspath(data_dir))
    approved = os.path.normcase(os.path.abspath(approved_data_dir))
    if canonical != approved:
        raise SystemExit("阶段 6 数据目录与获准固定路径不一致")
    current = Path(data_dir.anchor)
    for part in data_dir.parts[1:]:
        current /= part
        try:
            info = os.lstat(current)
        except FileNotFoundError:
            continue
        attributes = getattr(info, "st_file_attributes", 0)
        reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
        if stat.S_ISLNK(info.st_mode) or attributes & reparse:
            raise SystemExit("阶段 6 数据目录不得经过链接或重解析点")
        if current != data_dir and not stat.S_ISDIR(info.st_mode):
            raise SystemExit("阶段 6 数据目录父路径不是目录")


def _exclusive_flags() -> int:
    return os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)


def _write_creation_intent(path: Path) -> None:
    descriptor = os.open(path, _exclusive_flags(), 0o600)
    try:
        os.write(descriptor, b"managed-path-stage6-identity/v1\n")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    _fsync_directory(path.parent)


def _publish_public_identity(output: Path, payload: Mapping[str, object]) -> None:
    temporary = output.parent / f".{output.name}.{secrets.token_hex(16)}.tmp"
    descriptor = os.open(temporary, _exclusive_flags(), 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            descriptor = -1
            json.dump(payload, handle, ensure_ascii=False, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.link(temporary, output, follow_symlinks=False)
        temporary.unlink()
        _fsync_directory(output.parent)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary.exists() or temporary.is_symlink():
            temporary.unlink()


def _fsync_directory(path: Path) -> None:
    directory_flag = getattr(os, "O_DIRECTORY", 0)
    if directory_flag == 0:
        return
    descriptor = os.open(path, os.O_RDONLY | directory_flag)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


if __name__ == "__main__":
    raise SystemExit(main())
