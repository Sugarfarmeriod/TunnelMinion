"""在阶段 6 固定资源上运行真实 observe/plan 与双次授权读取，不执行 apply。"""

from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import json
import os
import stat
import subprocess
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import BaseModel, ConfigDict
from scripts.managed_path_stage6_identity import (
    _APPROVED_DATA_DIRS,  # pyright: ignore[reportPrivateUsage]
    _NETWORK_ID,  # pyright: ignore[reportPrivateUsage]
    _assert_trusted_data_dir,  # pyright: ignore[reportPrivateUsage]
    _publish_public_identity,  # pyright: ignore[reportPrivateUsage]
    _require_matching_platform,  # pyright: ignore[reportPrivateUsage]
    _require_unprivileged,  # pyright: ignore[reportPrivateUsage]
)

from tunnelminion.domain.identifiers import AuthorizationId, NetworkId, NodeId
from tunnelminion.network.contracts import (
    ApprovedRouteOverlap,
    CandidateSource,
    DesiredNetworkConfig,
    EndpointCandidate,
    NetworkAction,
    NetworkPlan,
    PeerConfiguration,
    ProviderKind,
    ProviderReceipt,
    SignedDesiredConfig,
    canonical_sha256,
)
from tunnelminion.network.governance import (
    DirectPathEvidence,
    LocalControlAuthority,
    ManagedPathLifecycle,
    NetworkAuthorizationGrant,
    NetworkAuthorizationScope,
    NetworkGovernancePhase,
    NetworkOperationPolicy,
    NetworkPathType,
    PathSelection,
    SQLiteNetworkAuthorizationRepository,
    SQLiteNetworkGovernanceStore,
)
from tunnelminion.network.ledger import SQLiteManagedResourceLedger
from tunnelminion.network.provider import NetworkProvider
from tunnelminion.network.signing import desired_config_payload
from tunnelminion.platforms.macos.managed_path import build_macos_managed_path_platform
from tunnelminion.platforms.windows.managed_path import build_windows_managed_path_platform
from tunnelminion.tools.contracts import ToolCancellationToken


class _PublicIdentity(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str
    network_id: NetworkId
    node_id: NodeId
    provider: ProviderKind
    public_key: str
    public_key_hash: str
    secret_reference_configured: bool


@dataclass(frozen=True, slots=True)
class _PreviewConfig:
    provider: ProviderKind
    node_id: NodeId
    peer_node_id: NodeId
    interface_name: str
    address: str
    listen_port: int
    peer_host_route: str
    peer_endpoint_host: str
    peer_endpoint_port: int
    peer_identity_file: str
    allowed_route_overlaps: tuple[ApprovedRouteOverlap, ...] = ()


_CONFIGS = {
    "windows": _PreviewConfig(
        provider=ProviderKind.WINDOWS,
        node_id=NodeId("node_6000000000000000000000000000000a"),
        peer_node_id=NodeId("node_6000000000000000000000000000000b"),
        interface_name="tmn-stage6-a",
        address="192.0.2.1/32",
        listen_port=51888,
        peer_host_route="192.0.2.2/32",
        peer_endpoint_host="10.77.0.1",
        peer_endpoint_port=51889,
        peer_identity_file="macos-peer-public-identity.json",
        allowed_route_overlaps=(
            ApprovedRouteOverlap(
                route="192.0.0.0/9",
                observation_fingerprint=(
                    "sha256:43938c1ef2e9e749462dc899a7e408f759f575dc472bfe412763f7c9244814bf"
                ),
            ),
        ),
    ),
    "macos": _PreviewConfig(
        provider=ProviderKind.MACOS,
        node_id=NodeId("node_6000000000000000000000000000000b"),
        peer_node_id=NodeId("node_6000000000000000000000000000000a"),
        interface_name="tmn-stage6-b",
        address="192.0.2.2/32",
        listen_port=51889,
        peer_host_route="192.0.2.1/32",
        peer_endpoint_host="10.77.0.2",
        peer_endpoint_port=51888,
        peer_identity_file="windows-peer-public-identity.json",
    ),
}


class _CountingAuthorizationRepository(SQLiteNetworkAuthorizationRepository):
    """第三次授权读取后请求取消，使 lifecycle 完成 recheck 但不调用 apply。"""

    def __init__(
        self,
        path: Path,
        *,
        control: LocalControlAuthority,
        cancellation: ToolCancellationToken,
    ) -> None:
        self.list_calls = 0
        self._cancellation = cancellation
        super().__init__(path, control=control)

    def list_grants(
        self, network_id: NetworkId, node_id: NodeId
    ) -> tuple[NetworkAuthorizationGrant, ...]:
        self.list_calls += 1
        grants = super().list_grants(network_id, node_id)
        if self.list_calls == 3:
            self._cancellation.cancel()
        return grants


class _PreviewOnlyProvider:
    """委托真实 observe/plan，并把任何 apply 尝试变成测试失败。"""

    def __init__(self, provider: object) -> None:
        self._provider = provider
        self.apply_calls = 0

    def __getattr__(self, name: str) -> object:
        return getattr(self._provider, name)

    async def apply(
        self,
        plan: NetworkPlan,
        *,
        idempotency_key: str,
        cancellation: ToolCancellationToken,
    ) -> ProviderReceipt:
        del plan, idempotency_key, cancellation
        self.apply_calls += 1
        raise AssertionError("阶段 6.2 预览禁止调用 Provider.apply")


class _NeverPathVerifier:
    async def verify(self, plan: NetworkPlan, *, now: datetime) -> DirectPathEvidence:
        del plan, now
        raise AssertionError("阶段 6.2 预览禁止 path verify")


class _NeverPathController:
    @property
    def selection(self) -> PathSelection:
        raise AssertionError("阶段 6.2 预览禁止读取 path selection")

    async def reconcile(
        self,
        evidence: DirectPathEvidence,
        *,
        fallback: NetworkPathType = NetworkPathType.STATIC,
    ) -> PathSelection:
        del evidence, fallback
        raise AssertionError("阶段 6.2 预览禁止 path reconcile")


async def _run(platform: str, *, now: datetime) -> dict[str, object]:
    config = _CONFIGS[platform]
    data_dir = _APPROVED_DATA_DIRS[platform]
    _assert_trusted_data_dir(data_dir, data_dir)
    output = data_dir / "stage6-preview-evidence.json"
    database = data_dir / "stage6-preview-governance.sqlite3"
    protected_outputs = (
        output,
        database,
        database.with_name(f"{database.name}-wal"),
        database.with_name(f"{database.name}-shm"),
        database.with_name(f"{database.name}-journal"),
    )
    if any(path.exists() or path.is_symlink() for path in protected_outputs):
        raise SystemExit("阶段 6.2 预览证据或治理状态已存在，拒绝覆盖或复用")
    peer_identity = _load_peer_identity(data_dir / config.peer_identity_file, config)
    desired = _desired_config(config, peer_identity, now=now)
    envelope = _signed_envelope(desired, now=now)
    ledger_path = data_dir / "managed-network-ledger.sqlite3"
    provider_journal = (
        data_dir
        / "managed-network"
        / ("windows-operations.sqlite3" if platform == "windows" else "macos-operations.sqlite3")
    )
    _assert_trusted_data_dir(provider_journal.parent, provider_journal.parent)
    _assert_safe_existing_database(ledger_path)
    _assert_safe_existing_database(provider_journal)
    ledger = SQLiteManagedResourceLedger(ledger_path)
    dependencies = (
        build_windows_managed_path_platform(data_dir, ledger)
        if platform == "windows"
        else build_macos_managed_path_platform(data_dir, ledger)
    )
    preview_provider = _PreviewOnlyProvider(dependencies.provider)
    cancellation = ToolCancellationToken()
    control = LocalControlAuthority()
    repository = _CountingAuthorizationRepository(
        database,
        control=control,
        cancellation=cancellation,
    )
    store = SQLiteNetworkGovernanceStore(database, authorization_repository=repository)
    lifecycle = ManagedPathLifecycle(
        cast(NetworkProvider, preview_provider),
        NetworkOperationPolicy(repository.read_only),
        store,
        None,
        path_verifier=_NeverPathVerifier(),
        path_controller=_NeverPathController(),
        ledger=ledger,
        clock=lambda: now,
    )
    pending = await lifecycle.reconcile(envelope, action=NetworkAction.CREATE, ownership=None)
    if pending.phase is not NetworkGovernancePhase.AWAITING_AUTHORIZATION:
        raise RuntimeError("首次 lifecycle 预览没有停在 awaiting authorization")
    grant = NetworkAuthorizationGrant(
        authorization_id=AuthorizationId.new(),
        scope=NetworkAuthorizationScope.from_plan(
            pending.plan,
            address_pool="192.0.2.0/30",
            interface_prefix="tmn-stage6-",
        ),
        approved_by="stage6-explicit-user-authorization-20260824",
        approved_at=now,
        expires_at=now + timedelta(seconds=900),
    )
    repository.approve(grant, capability=control.authorization_capability())
    rechecked = await lifecycle.reconcile(
        envelope,
        action=NetworkAction.CREATE,
        ownership=None,
        cancellation=cancellation,
    )
    phases = tuple(entry.phase.value for entry in rechecked.journal)
    if (
        repository.list_calls != 3
        or preview_provider.apply_calls != 0
        or NetworkGovernancePhase.RECHECKING.value not in phases
        or rechecked.phase is not NetworkGovernancePhase.CANCELLED
    ):
        raise RuntimeError("阶段 6.2 authorization recheck 未在 apply 前安全停止")
    evidence: dict[str, object] = {
        "schema_version": "managed-path-stage6-preview/v1",
        "platform": platform,
        "commit": _git_commit(),
        "entrypoint": "python -m scripts.managed_path_stage6_preview",
        "observed_at": now.isoformat(),
        "initial_phase": pending.phase.value,
        "recheck_phase": rechecked.phase.value,
        "journal_phases": phases,
        "authorization_reads": repository.list_calls,
        "authorization_ttl_seconds": 900,
        "authorization": {
            "authorization_id": str(grant.authorization_id),
            "approved_by": grant.approved_by,
            "approved_at": grant.approved_at.isoformat(),
            "expires_at": grant.expires_at.isoformat(),
        },
        "authorization_scope": grant.scope.model_dump(mode="json"),
        "plan": {
            "action": pending.plan.action.value,
            "plan_hash": pending.plan.plan_hash,
            "observed_fingerprint": pending.plan.observed_fingerprint,
            "interface_name": desired.interface_name,
            "address": desired.address,
            "listen_port": desired.listen_port,
            "peer_node_id": str(config.peer_node_id),
            "peer_host_routes": [config.peer_host_route],
            "peer_endpoint": {
                "host": config.peer_endpoint_host,
                "port": config.peer_endpoint_port,
            },
            "allowed_route_overlaps": [
                overlap.model_dump(mode="json") for overlap in desired.allowed_route_overlaps
            ],
            "steps": [
                {
                    "index": step.index,
                    "kind": step.kind.value,
                    "target": step.target,
                    "rollback_kind": step.rollback_kind.value if step.rollback_kind else None,
                }
                for step in pending.plan.steps
            ],
        },
        "provider_apply_calls": preview_provider.apply_calls,
        "real_network_writes_performed": False,
        "private_material_exported": False,
    }
    _publish_public_identity(output, evidence)
    _assert_trusted_data_dir(data_dir, data_dir)
    return {
        "authorization_rechecked": True,
        "platform": platform,
        "provider_apply_calls": 0,
        "real_network_writes_performed": False,
    }


def _load_peer_identity(path: Path, config: _PreviewConfig) -> _PublicIdentity:
    identity = _PublicIdentity.model_validate_json(_read_regular_file(path))
    if (
        identity.schema_version != "managed-path-stage6-public-identity/v1"
        or identity.network_id != _NETWORK_ID
        or identity.node_id != config.peer_node_id
        or identity.provider is config.provider
        or not identity.secret_reference_configured
        or identity.public_key_hash != canonical_sha256({"public_key": identity.public_key})
    ):
        raise SystemExit("对端公开身份与阶段 6 固定绑定不一致")
    return identity


def _read_regular_file(path: Path) -> str:
    _assert_regular_nonreparse(path)
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        info = os.fstat(descriptor)
        _assert_regular_stat(info)
        with os.fdopen(descriptor, "r", encoding="utf-8") as handle:
            descriptor = -1
            return handle.read()
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _assert_safe_existing_database(path: Path) -> None:
    candidates = (
        path,
        path.with_name(f"{path.name}-journal"),
        path.with_name(f"{path.name}-wal"),
        path.with_name(f"{path.name}-shm"),
    )
    for candidate in candidates:
        if candidate.exists() or candidate.is_symlink():
            _assert_regular_nonreparse(candidate)


def _assert_regular_nonreparse(path: Path) -> None:
    try:
        info = os.lstat(path)
    except FileNotFoundError as exc:
        raise SystemExit("阶段 6 固定输入文件不存在") from exc
    _assert_regular_stat(info)


def _assert_regular_stat(info: os.stat_result) -> None:
    attributes = getattr(info, "st_file_attributes", 0)
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    if (
        not stat.S_ISREG(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or attributes & reparse
        or getattr(info, "st_nlink", 0) != 1
    ):
        raise SystemExit("阶段 6 固定文件不得是链接、重解析点、多重硬链接或非常规文件")


def _desired_config(
    config: _PreviewConfig,
    peer_identity: _PublicIdentity,
    *,
    now: datetime,
) -> DesiredNetworkConfig:
    return DesiredNetworkConfig(
        network_id=_NETWORK_ID,
        target_node_id=config.node_id,
        provider=config.provider,
        revision=1,
        parent_revision=0,
        interface_name=config.interface_name,
        address=config.address,
        listen_port=config.listen_port,
        allowed_route_overlaps=config.allowed_route_overlaps,
        peers=(
            PeerConfiguration(
                node_id=config.peer_node_id,
                public_key=peer_identity.public_key,
                allowed_host_routes=(config.peer_host_route,),
                candidates=(
                    EndpointCandidate(
                        host=config.peer_endpoint_host,
                        port=config.peer_endpoint_port,
                        source=CandidateSource.ADMIN_EXPLICIT,
                        observed_at=now,
                        expires_at=now + timedelta(minutes=30),
                    ),
                ),
                persistent_keepalive_seconds=25,
            ),
        ),
    )


def _signed_envelope(desired: DesiredNetworkConfig, *, now: datetime) -> SignedDesiredConfig:
    private = Ed25519PrivateKey.generate()
    public_raw = private.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    expires_at = now + timedelta(minutes=30)
    signature = private.sign(desired_config_payload(desired, now, expires_at))
    return SignedDesiredConfig(
        config=desired,
        key_id="stage6-local-preview",
        key_fingerprint=f"sha256:{hashlib.sha256(public_raw).hexdigest()}",
        issued_at=now,
        expires_at=expires_at,
        signature=base64.urlsafe_b64encode(signature).rstrip(b"=").decode(),
    )


def _git_commit() -> str:
    result = subprocess.run(
        ("git", "rev-parse", "HEAD"),
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
    return result.stdout.strip()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--platform", choices=tuple(_CONFIGS), required=True)
    args = parser.parse_args(argv)
    _require_matching_platform(args.platform)
    _require_unprivileged(args.platform)
    result = asyncio.run(_run(args.platform, now=datetime.now(UTC)))
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
