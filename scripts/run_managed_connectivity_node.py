"""在单个节点预览或应用已签名、已本机批准的受管连接验收配置。"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
from collections.abc import Sequence
from pathlib import Path

from tunnelminion.coordinator.contracts import VerificationKeyView
from tunnelminion.model.secrets import KeyringSecretStore, RestrictedFileSecretStore
from tunnelminion.network.contracts import (
    NetworkAction,
    OwnershipState,
    SignedDesiredConfig,
)
from tunnelminion.network.ledger import SQLiteManagedResourceLedger
from tunnelminion.network.signing import (
    verify_signed_desired_config,
    verify_signed_desired_config_for_removal,
)
from tunnelminion.platforms.macos.managed_system import (
    FixedMacOSWireGuardCommands,
    MacOSProviderPaths,
    MacOSWireGuardObserver,
)
from tunnelminion.platforms.macos.network_provider import (
    MacOSNetworkProvider,
    macos_operation_journal,
)
from tunnelminion.platforms.macos.official_backend import (
    OfficialMacOSManagedBackend,
    RestrictedMacOSConfigStore,
)
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
from tunnelminion.platforms.windows.system import (
    PsutilSystemReader,
    SubprocessCommandRunner,
)


def _provider(platform: str, root: Path):
    runner = SubprocessCommandRunner()
    ledger = SQLiteManagedResourceLedger(root / "ownership.sqlite3")
    if platform == "windows":
        system_root = Path(os.environ["SYSTEMROOT"])
        paths = WindowsProviderPaths(
            wireguard_exe=Path(r"C:\Program Files\WireGuard\wireguard.exe"),
            wg_exe=Path(r"C:\Program Files\WireGuard\wg.exe"),
            sc_exe=system_root / "System32" / "sc.exe",
            route_exe=system_root / "System32" / "route.exe",
            config_root=root / "configs",
        )
        commands = FixedWindowsWireGuardCommands(paths, runner)
        materials = AclRestrictedWindowsConfigStore(
            paths.config_root,
            KeyringSecretStore("TunnelMinion Managed Acceptance"),
            runner,
            system_root / "System32" / "icacls.exe",
        )
        return (
            WindowsNetworkProvider(
                OfficialWindowsManagedBackend(
                    commands,
                    WindowsWireGuardObserver(PsutilSystemReader(), commands),
                    materials,
                ),
                ledger,
                SQLiteWindowsOperationJournal(root / "operations.sqlite3"),
            ),
            ledger,
        )
    paths = MacOSProviderPaths(
        wg=Path("/opt/homebrew/bin/wg"),
        wg_quick=Path("/opt/homebrew/bin/wg-quick"),
        ifconfig=Path("/sbin/ifconfig"),
        netstat=Path("/usr/sbin/netstat"),
        config_root=root / "configs",
    )
    commands = FixedMacOSWireGuardCommands(paths, runner)
    return (
        MacOSNetworkProvider(
            OfficialMacOSManagedBackend(
                commands,
                MacOSWireGuardObserver(commands),
                RestrictedMacOSConfigStore(
                    paths.config_root,
                    RestrictedFileSecretStore(root / "secrets"),
                ),
            ),
            ledger,
            macos_operation_journal(root / "operations.sqlite3"),
        ),
        ledger,
    )


async def execute(
    *,
    command: str,
    platform: str,
    data_directory: Path,
    envelope_path: Path | None,
    verification_key_path: Path | None,
    approve_plan_hash: str | None,
) -> dict[str, object]:
    root = data_directory.resolve()
    if command == "recover":
        raise RuntimeError(
            "真实恢复必须等待常规应用装配唯一 managed path lifecycle，不得直接调用 Provider.recover"
        )
    provider, ledger = _provider(platform, root)
    if envelope_path is None or verification_key_path is None:
        raise ValueError("preview/apply/remove 必须提供签名配置和验证公钥")
    envelope = SignedDesiredConfig.model_validate_json(envelope_path.read_text(encoding="utf-8"))
    key = VerificationKeyView.model_validate_json(verification_key_path.read_text(encoding="utf-8"))
    removing = command in {"remove-preview", "remove"}
    verifier = (
        verify_signed_desired_config_for_removal if removing else verify_signed_desired_config
    )
    desired = verifier(
        envelope,
        (key,),
        (f"sha256:{key.fingerprint}",),
        network_id=envelope.config.network_id,
        target_node_id=envelope.config.target_node_id,
        parent_revision=0,
    )
    observed = await provider.observe(desired.interface_name)
    ownership_entry = ledger.get(desired.network_id, desired.target_node_id) if removing else None
    if removing and ownership_entry is None:
        if observed.ownership is not OwnershipState.ABSENT:
            raise RuntimeError("接口仍存在但本地双重所有权账本缺失，拒绝按名称清理")
        return {
            "platform": platform,
            "phase": "verified",
            "plan_hash": None,
            "receipt_status": "already_absent",
            "writes_performed": False,
        }
    plan = await provider.plan(
        action=NetworkAction.REMOVE if removing else NetworkAction.CREATE,
        desired=desired,
        observed=observed,
        ownership=None if ownership_entry is None else ownership_entry.ownership,
    )
    if command in {"preview", "remove-preview"}:
        return {
            "platform": platform,
            "mode": observed.mode.value,
            "action": plan.action.value,
            "plan_hash": plan.plan_hash,
            "interface": desired.interface_name,
            "address": desired.address,
            "listen_port": desired.listen_port,
            "allowed_route_overlaps": [
                item.model_dump(mode="json") for item in desired.allowed_route_overlaps
            ],
            "writes_performed": False,
        }
    if approve_plan_hash != plan.plan_hash:
        raise PermissionError("本机批准的 plan hash 与实时预览不一致")
    raise RuntimeError(
        "真实 apply/remove 必须等待常规应用装配唯一 managed path lifecycle、"
        "持久授权仓储和真实 path verifier/controller；当前仅允许只读 preview"
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "command",
        choices=("preview", "apply", "remove-preview", "remove", "recover"),
    )
    parser.add_argument("--platform", choices=("windows", "macos"), required=True)
    parser.add_argument("--data-directory", type=Path, required=True)
    parser.add_argument("--envelope", type=Path)
    parser.add_argument("--verification-key", type=Path)
    parser.add_argument("--approve-plan-hash")
    args = parser.parse_args(argv)
    result = asyncio.run(
        execute(
            command=args.command,
            platform=args.platform,
            data_directory=args.data_directory,
            envelope_path=args.envelope,
            verification_key_path=args.verification_key,
            approve_plan_hash=args.approve_plan_hash,
        )
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
