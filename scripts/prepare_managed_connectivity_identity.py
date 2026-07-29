"""在隔离目录准备受管连接公钥身份和空所有权账本，不执行网络写入。"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from collections.abc import Sequence
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from tunnelminion.domain.identifiers import NetworkId, NodeId
from tunnelminion.model.secrets import KeyringSecretStore, RestrictedFileSecretStore
from tunnelminion.network.contracts import LocalNetworkKeyMaterial
from tunnelminion.network.ledger import SQLiteManagedResourceLedger
from tunnelminion.platforms.macos.official_backend import RestrictedMacOSConfigStore
from tunnelminion.platforms.windows.official_backend import AclRestrictedWindowsConfigStore
from tunnelminion.platforms.windows.system import SubprocessCommandRunner


class IdentityPreparationReport(BaseModel):
    """允许跨节点交换的公钥身份准备报告。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = "managed-connectivity-identity-preparation/v1"
    platform: str = Field(pattern=r"^(windows|macos)$")
    network_id: NetworkId
    node_id: NodeId
    public_key: str
    public_key_hash: str
    secret_reference: str = Field(repr=False)
    authorization_plan_sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    data_directory: str
    ownership_ledger: str
    network_writes_performed: bool = False


def _authorization_hash(path: Path) -> str:
    payload = path.read_bytes()
    plan = json.loads(payload)
    if (
        plan.get("status") != "explicit_user_authorization_received"
        or plan.get("required_user_confirmation") != "completed"
    ):
        raise ValueError("授权计划尚未记录用户明确确认")
    return f"sha256:{hashlib.sha256(payload).hexdigest()}"


def prepare_material(
    platform: str,
    root: Path,
    network_id: NetworkId,
    node_id: NodeId,
) -> LocalNetworkKeyMaterial:
    if platform == "macos":
        store = RestrictedMacOSConfigStore(
            root / "configs",
            RestrictedFileSecretStore(root / "secrets"),
        )
        return store.ensure_identity(network_id, node_id)
    if os.name != "nt":
        raise RuntimeError("Windows 身份只能在 Windows 节点准备")
    store = AclRestrictedWindowsConfigStore(
        root / "configs",
        KeyringSecretStore("TunnelMinion Managed Acceptance"),
        SubprocessCommandRunner(),
        Path(os.environ["SYSTEMROOT"]) / "System32" / "icacls.exe",
    )
    return store.ensure_identity(network_id, node_id)


def prepare_identity(
    *,
    platform: str,
    data_directory: Path,
    authorization_plan: Path,
    network_id: NetworkId,
    node_id: NodeId,
) -> IdentityPreparationReport:
    """先验证授权记录，再生成本机密钥并初始化空账本。"""
    root = data_directory.resolve()
    root.mkdir(parents=True, exist_ok=True)
    if platform == "macos":
        os.chmod(root, 0o700)
    plan_hash = _authorization_hash(authorization_plan.resolve())
    material = prepare_material(platform, root, network_id, node_id)
    ledger_path = root / "ownership.sqlite3"
    if SQLiteManagedResourceLedger(ledger_path).list_all():
        raise ValueError("隔离所有权账本不是空账本")
    return IdentityPreparationReport(
        platform=platform,
        network_id=network_id,
        node_id=node_id,
        public_key=material.public_key,
        public_key_hash=material.public_key_hash,
        secret_reference=material.secret_reference,
        authorization_plan_sha256=plan_hash,
        data_directory=str(root),
        ownership_ledger=str(ledger_path),
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--platform", choices=("windows", "macos"), required=True)
    parser.add_argument("--data-directory", type=Path, required=True)
    parser.add_argument("--authorization-plan", type=Path, required=True)
    parser.add_argument("--network-id", type=NetworkId, required=True)
    parser.add_argument("--node-id", type=NodeId, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    report = prepare_identity(
        platform=args.platform,
        data_directory=args.data_directory,
        authorization_plan=args.authorization_plan,
        network_id=args.network_id,
        node_id=args.node_id,
    )
    output = args.output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(report.model_dump_json(indent=2) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {
                "platform": report.platform,
                "network_id": str(report.network_id),
                "node_id": str(report.node_id),
                "public_key_hash": report.public_key_hash,
                "authorization_plan_sha256": report.authorization_plan_sha256,
                "network_writes_performed": False,
                "output": str(output),
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
