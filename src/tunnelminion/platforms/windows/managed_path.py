"""Windows 常规应用的 managed path 平台依赖工厂。"""

from __future__ import annotations

import os
from pathlib import Path

from tunnelminion.agent.managed_path import (
    ManagedPathCapabilityState,
    ManagedPathPlatformDependencies,
)
from tunnelminion.model.secrets import KeyringSecretStore, SecretStore
from tunnelminion.network.contracts import DesiredNetworkConfig, ProviderKind, ProviderMode
from tunnelminion.network.ledger import SQLiteManagedResourceLedger
from tunnelminion.network.path_probe import PathProbePolicy
from tunnelminion.platforms.windows.managed_system import (
    FixedWindowsWireGuardCommands,
    WindowsProviderPaths,
    WindowsWireGuardObserver,
)
from tunnelminion.platforms.windows.network_provider import (
    SQLiteWindowsOperationJournal,
    WindowsNetworkProvider,
)
from tunnelminion.platforms.windows.official_backend import (
    AclRestrictedWindowsConfigStore,
    OfficialWindowsManagedBackend,
)
from tunnelminion.platforms.windows.path_probe import WindowsPathProbe
from tunnelminion.platforms.windows.system import PsutilSystemReader, SubprocessCommandRunner


def build_windows_managed_path_platform(
    data_dir: Path,
    ledger: SQLiteManagedResourceLedger,
    *,
    secret_store: SecretStore | None = None,
) -> ManagedPathPlatformDependencies:
    """创建 Windows Provider、只读观察器和固定能力状态，不执行 Provider 操作。"""
    root = data_dir.resolve()
    tools_root = root / "managed-platform-tools"
    paths = WindowsProviderPaths(
        wireguard_exe=_tool_path(
            tools_root, "wireguard.exe", r"C:\Program Files\WireGuard\wireguard.exe"
        ),
        wg_exe=_tool_path(tools_root, "wg.exe", r"C:\Program Files\WireGuard\wg.exe"),
        sc_exe=_tool_path(tools_root, "sc.exe", r"C:\Windows\System32\sc.exe"),
        route_exe=_tool_path(tools_root, "route.exe", r"C:\Windows\System32\route.exe"),
        config_root=root / "managed-network" / "windows",
    )
    runner = SubprocessCommandRunner()
    commands = FixedWindowsWireGuardCommands(paths, runner)
    preflight = commands.preflight()
    observer = WindowsWireGuardObserver(PsutilSystemReader(), commands)
    materials = AclRestrictedWindowsConfigStore(
        paths.config_root,
        secret_store or KeyringSecretStore(),
        runner,
        _tool_path(tools_root, "icacls.exe", r"C:\Windows\System32\icacls.exe"),
    )
    backend = OfficialWindowsManagedBackend(commands, observer, materials)
    provider = WindowsNetworkProvider(
        backend,
        ledger,
        SQLiteWindowsOperationJournal(root / "managed-network" / "windows-operations.sqlite3"),
    )

    def probe_factory(desired: DesiredNetworkConfig, policy: PathProbePolicy):
        peer = desired.peers[0]
        return WindowsPathProbe(
            observer,
            interface_name=desired.interface_name,
            peer_public_key=peer.public_key,
            policy=policy,
            preflight=preflight,
        )

    capabilities = ManagedPathCapabilityState(
        provider=ProviderKind.WINDOWS,
        mode=preflight.mode,
        platform_supported=preflight.platform_supported,
        provider_apply_available=preflight.mode is ProviderMode.MANAGED,
        path_probe_available=(
            preflight.platform_supported
            and preflight.wg_available
            and preflight.route_tool_available
        ),
        stable_error_code=preflight.error_code,
    )
    return ManagedPathPlatformDependencies(
        provider=provider,
        provider_kind=ProviderKind.WINDOWS,
        capabilities=capabilities,
        probe_factory=probe_factory,
    )


def _tool_path(root: Path, name: str, native_path: str) -> Path:
    return Path(native_path) if os.name == "nt" else root / name


__all__ = ["build_windows_managed_path_platform"]
