"""macOS 常规应用的 managed path 平台依赖工厂。"""

from __future__ import annotations

import sys
from collections.abc import Callable
from pathlib import Path

from tunnelminion.agent.managed_path import (
    ManagedPathCapabilityState,
    ManagedPathPlatformDependencies,
)
from tunnelminion.model.secrets import KeyringSecretStore, SecretStore
from tunnelminion.network.contracts import DesiredNetworkConfig, ProviderKind, ProviderMode
from tunnelminion.network.ledger import SQLiteManagedResourceLedger
from tunnelminion.network.path_probe import PathProbePolicy
from tunnelminion.platforms.macos.managed_system import (
    FixedMacOSWireGuardCommands,
    MacOSProviderPaths,
    MacOSWireGuardObserver,
)
from tunnelminion.platforms.macos.network_provider import (
    MacOSNetworkProvider,
    SQLiteMacOSOperationJournal,
)
from tunnelminion.platforms.macos.official_backend import (
    OfficialMacOSManagedBackend,
    RestrictedMacOSConfigStore,
)
from tunnelminion.platforms.macos.path_probe import MacOSPathProbe
from tunnelminion.platforms.macos.system import SubprocessCommandRunner


def build_macos_managed_path_platform(
    data_dir: Path,
    ledger: SQLiteManagedResourceLedger,
    *,
    secret_store: SecretStore | None = None,
) -> ManagedPathPlatformDependencies:
    """创建 macOS Provider、只读观察器和固定能力状态，不执行 Provider 操作。"""
    root = data_dir.resolve()
    tools_root = root / "managed-platform-tools"
    paths = MacOSProviderPaths(
        wg=_tool_path(
            tools_root,
            "wg",
            "/usr/local/bin/wg",
            "/opt/homebrew/bin/wg",
        ),
        wg_quick=_tool_path(
            tools_root,
            "wg-quick",
            "/usr/local/bin/wg-quick",
            "/opt/homebrew/bin/wg-quick",
        ),
        ifconfig=_tool_path(tools_root, "ifconfig", "/sbin/ifconfig"),
        netstat=_tool_path(tools_root, "netstat", "/usr/sbin/netstat"),
        config_root=root / "managed-network" / "macos",
    )
    runner = SubprocessCommandRunner()
    commands = FixedMacOSWireGuardCommands(paths, runner)
    preflight = commands.preflight()
    observer = MacOSWireGuardObserver(commands)
    materials = RestrictedMacOSConfigStore(
        paths.config_root,
        secret_store or KeyringSecretStore(),
    )
    backend = OfficialMacOSManagedBackend(commands, observer, materials)
    provider = MacOSNetworkProvider(
        backend,
        ledger,
        SQLiteMacOSOperationJournal(root / "managed-network" / "macos-operations.sqlite3"),
    )

    def probe_factory(desired: DesiredNetworkConfig, policy: PathProbePolicy):
        peer = desired.peers[0]
        return MacOSPathProbe(
            observer,
            interface_name=desired.interface_name,
            peer_public_key=peer.public_key,
            policy=policy,
            preflight=preflight,
        )

    capabilities = ManagedPathCapabilityState(
        provider=ProviderKind.MACOS,
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
        provider_kind=ProviderKind.MACOS,
        capabilities=capabilities,
        probe_factory=probe_factory,
    )


def _tool_path(
    root: Path,
    name: str,
    *native_paths: str,
    platform_name: str | None = None,
    path_exists: Callable[[Path], bool] | None = None,
) -> Path:
    platform = sys.platform if platform_name is None else platform_name
    if platform != "darwin":
        return root / name
    exists = Path.exists if path_exists is None else path_exists
    candidates = tuple(Path(value) for value in native_paths)
    return next((path for path in candidates if exists(path)), candidates[0])


__all__ = ["build_macos_managed_path_platform"]
