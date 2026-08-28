"""阶段 6.3 真实 apply 入口的无网络安全门禁测试。"""

from __future__ import annotations

import asyncio
import base64
import json
import sqlite3
import stat
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from scripts import managed_path_stage6_apply as subject
from scripts import managed_path_stage6_preview as preview
from tunnelminion.domain.identifiers import AuthorizationId, NetworkId, NodeId
from tunnelminion.model.secrets import SecretStoreError
from tunnelminion.network.contracts import (
    DesiredNetworkConfig,
    EndpointCandidate,
    LocalNetworkKeyMaterial,
    NetworkAction,
    NetworkError,
    NetworkErrorCode,
    NetworkObservation,
    NetworkPlan,
    OwnershipState,
    ProviderKind,
    ProviderMode,
    ProviderReceipt,
    ReceiptStatus,
    StepReceipt,
    VerificationResult,
    canonical_sha256,
)
from tunnelminion.network.fakes import InMemoryNetworkProvider
from tunnelminion.network.governance import (
    NetworkAuthorizationGrant,
    NetworkAuthorizationScope,
)
from tunnelminion.network.path_controller import DirectPathErrorCode, DirectPathEvidence
from tunnelminion.network.path_probe import PathProbePolicy, PlatformPathProbe
from tunnelminion.platforms.macos.official_backend import (
    OfficialMacOSManagedBackend,
    RestrictedMacOSConfigStore,
)
from tunnelminion.platforms.windows.network_provider import (
    SQLiteWindowsOperationJournal,
    WindowsNetworkProvider,
    WindowsOperationJournal,
)
from tunnelminion.platforms.windows.official_backend import (
    AclRestrictedWindowsConfigStore,
    OfficialWindowsManagedBackend,
)

NOW = datetime(2026, 8, 26, 8, 0, tzinfo=UTC)
BARRIER_ID = "a" * 32
ARCHIVE_NOW = datetime(2026, 8, 28, 8, 0, tzinfo=UTC)


def _stage6_test_paths(root: Path) -> subject.MacOSProviderPaths:
    return subject.MacOSProviderPaths(
        wg=root / "tools" / "wg",
        wg_quick=root / "tools" / "wireguard-go",
        ifconfig=root / "system" / "ifconfig",
        netstat=root / "system" / "netstat",
        config_root=root / "configs",
    )


class _Probe:
    def __init__(
        self,
        calls: list[tuple[str, int]],
        *,
        primary_succeeds: bool,
        error: DirectPathErrorCode | None = None,
    ) -> None:
        self._calls = calls
        self._primary_succeeds = primary_succeeds
        self._error = error

    async def probe(
        self,
        *,
        network_id: NetworkId,
        node_id: NodeId,
        plan_hash: str,
        authorization_revision: int,
        revision: int,
        candidates: tuple[EndpointCandidate, ...],
        expected_host_route: str,
        target_host: str,
        target_port: int,
        now: datetime,
        cancel_event: asyncio.Event | None = None,
    ) -> DirectPathEvidence:
        del candidates, cancel_event
        self._calls.append((target_host, target_port))
        verified = (self._primary_succeeds or target_port == 47990) and self._error is None
        return DirectPathEvidence(
            network_id=network_id,
            node_id=node_id,
            plan_hash=plan_hash,
            authorization_revision=authorization_revision,
            provider=ProviderKind.MACOS,
            revision=revision,
            target_host_hash=canonical_sha256({"host": target_host}),
            target_port=target_port,
            route_identity_hash=canonical_sha256({"host_route": expected_host_route}),
            candidate_count=1,
            selected_candidate_hash=f"sha256:{'b' * 64}",
            endpoint_probe_at=now,
            endpoint_probe_succeeded=True,
            last_handshake_at=now,
            handshake_fresh=True,
            host_route_probe_at=now,
            host_route_present=True,
            target_probe_at=now,
            target_probe_succeeded=verified,
            verified=verified,
            stable_error_code=(
                None if verified else self._error or DirectPathErrorCode.TARGET_UNREACHABLE
            ),
            observed_at=now,
            expires_at=now + timedelta(seconds=180),
        )

    async def target(self, host: str, port: int, timeout_seconds: float) -> bool:
        del timeout_seconds
        self._calls.append((host, port))
        return port == 47990


def _plan() -> NetworkPlan:
    config = preview._CONFIGS["macos"]  # pyright: ignore[reportPrivateUsage]
    public_key = "A" * 43 + "="
    identity = preview._PublicIdentity.model_validate(  # pyright: ignore[reportPrivateUsage]
        {
            "schema_version": "managed-path-stage6-public-identity/v1",
            "network_id": "network_60000000000000000000000000000000",
            "node_id": "node_6000000000000000000000000000000a",
            "provider": "windows",
            "public_key": public_key,
            "public_key_hash": canonical_sha256({"public_key": public_key}),
            "secret_reference_configured": True,
        }
    )
    desired = preview._desired_config(  # pyright: ignore[reportPrivateUsage]
        config, identity, now=NOW
    )
    observation = NetworkObservation(
        provider=ProviderKind.MACOS,
        mode=ProviderMode.MANAGED,
        interface_name=desired.interface_name,
        ownership=OwnershipState.ABSENT,
        system_fingerprint=canonical_sha256({"fixture": "stage6-apply"}),
        observed_at=NOW,
    )
    provider = InMemoryNetworkProvider(observation)

    async def build():
        observed = await provider.observe(desired.interface_name)
        return await provider.plan(
            action=NetworkAction.CREATE,
            desired=desired,
            observed=observed,
            ownership=None,
        )

    return asyncio.run(build())


def _grant(plan: NetworkPlan) -> NetworkAuthorizationGrant:
    expires_at = datetime.now(UTC) + timedelta(minutes=15)
    return NetworkAuthorizationGrant(
        authorization_id=AuthorizationId.new(),
        scope=NetworkAuthorizationScope.from_plan(
            plan, address_pool="192.0.2.0/30", interface_prefix="tmn-stage6-"
        ),
        approved_by="test",
        approved_at=NOW,
        expires_at=expires_at,
    )


def _operation_journal(plan: NetworkPlan, *, status: ReceiptStatus) -> WindowsOperationJournal:
    return WindowsOperationJournal(
        plan=plan,
        idempotency_key=f"netop_{'c' * 64}",
        secret_reference="stage6-test-reference",
        creation_nonce="d" * 32,
        baseline_snapshot_hash=f"sha256:{'e' * 64}",
        baseline_runtime_hash=f"sha256:{'f' * 64}",
        steps=tuple(
            StepReceipt(
                index=index,
                kind=step.kind,
                succeeded=True,
                system_receipt_hash=f"sha256:{index:064x}",
            )
            for index, step in enumerate(plan.steps)
        ),
        status=status,
        updated_at=NOW,
    )


class _ExactRollbackProvider:
    async def rollback(
        self,
        plan: NetworkPlan,
        receipt: ProviderReceipt,
        *,
        cancellation: object,
    ) -> ProviderReceipt:
        del cancellation
        assert receipt.plan_hash == plan.plan_hash
        observation = NetworkObservation(
            provider=plan.desired.provider,
            mode=ProviderMode.MANAGED,
            interface_name=plan.desired.interface_name,
            ownership=OwnershipState.ABSENT,
            system_fingerprint=canonical_sha256({"fixture": "rolled-back"}),
            observed_at=NOW,
        )
        return ProviderReceipt(
            idempotency_key=receipt.idempotency_key,
            plan_hash=plan.plan_hash,
            revision=plan.desired.revision,
            provider=plan.desired.provider,
            observation_fingerprint=observation.system_fingerprint,
            status=ReceiptStatus.ROLLED_BACK,
            steps=receipt.steps,
            observation_after=observation,
        )


def test_exact_provider_journal_rollback_survives_missing_governance_body(
    tmp_path: Path,
) -> None:
    plan = _plan()
    journal = _operation_journal(plan, status=ReceiptStatus.APPLIED)
    provider_path = tmp_path / "managed-network" / "macos-operations.sqlite3"
    SQLiteWindowsOperationJournal(provider_path).put(journal)
    provider = subject._CountingProvider(_ExactRollbackProvider())  # pyright: ignore[reportPrivateUsage]

    loaded, rolled = asyncio.run(
        subject._rollback_exact_stage6_provider_run(  # pyright: ignore[reportPrivateUsage]
            "macos",
            provider_path,
            plan.desired,
            provider,
        )
    )

    assert loaded == journal
    assert rolled.status is ReceiptStatus.ROLLED_BACK
    assert provider.apply_calls == 0
    assert provider.rollback_calls == 1


def _orphan_governance_fixture(
    path: Path, journal: WindowsOperationJournal, *, state: str = "active"
) -> None:
    connection = sqlite3.connect(path)
    try:
        connection.execute("CREATE TABLE network_governance(payload TEXT NOT NULL)")
        connection.execute(
            """
            CREATE TABLE network_apply_claims(
                network_id TEXT NOT NULL,
                node_id TEXT NOT NULL,
                revision INTEGER NOT NULL,
                idempotency_key TEXT NOT NULL,
                plan_hash TEXT NOT NULL,
                lease_expires_at TEXT NOT NULL,
                state TEXT NOT NULL
            )
            """
        )
        connection.execute(
            "INSERT INTO network_apply_claims VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                str(journal.plan.desired.network_id),
                str(journal.plan.desired.target_node_id),
                journal.plan.desired.revision,
                journal.idempotency_key,
                journal.plan.plan_hash,
                (NOW - timedelta(minutes=1)).isoformat(),
                state,
            ),
        )
        connection.commit()
    finally:
        connection.close()


def _write_operation_journal(path: Path, journal: WindowsOperationJournal) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path)
    try:
        connection.execute(
            """
            CREATE TABLE windows_network_operations(
                idempotency_key TEXT PRIMARY KEY,
                plan_hash TEXT NOT NULL,
                revision INTEGER NOT NULL,
                status TEXT,
                payload TEXT NOT NULL
            )
            """
        )
        connection.execute(
            "INSERT INTO windows_network_operations VALUES (?, ?, ?, ?, ?)",
            (
                journal.idempotency_key,
                journal.plan.plan_hash,
                journal.plan.desired.revision,
                journal.status.value if journal.status is not None else None,
                journal.model_dump_json(),
            ),
        )
        connection.commit()
    finally:
        connection.close()


def test_provider_verification_dimensions_are_redacted_booleans() -> None:
    plan = _plan()
    observation = NetworkObservation(
        provider=plan.desired.provider,
        mode=ProviderMode.MANAGED,
        interface_name=plan.desired.interface_name,
        ownership=OwnershipState.ABSENT,
        system_fingerprint=canonical_sha256({"fixture": "verify-mismatch"}),
        observed_at=NOW,
    )
    verification = VerificationResult(
        idempotency_key=f"netop_{'a' * 64}",
        plan_hash=plan.plan_hash,
        revision=plan.desired.revision,
        provider=plan.desired.provider,
        observation_fingerprint=observation.system_fingerprint,
        succeeded=False,
        checked_dimensions=("ownership", "address", "host_route"),
        observation=observation,
        error=NetworkError(
            code=NetworkErrorCode.VERIFY_FAILED,
            message="fixture",
            correlation_id=plan.plan_hash,
        ),
    )

    assert subject._provider_verification_dimensions(  # pyright: ignore[reportPrivateUsage]
        plan, verification
    ) == {
        "ownership_matches": False,
        "address_present": False,
        "host_routes_present": False,
    }
    assert subject._provider_verification_dimensions(  # pyright: ignore[reportPrivateUsage]
        plan, None
    ) == {
        "ownership_matches": None,
        "address_present": None,
        "host_routes_present": None,
    }


def _rolled_back_archive_fixture(
    root: Path,
    *,
    phase: str = "rolled_back",
    receipt_status: str = "rolled_back",
    claim_state: str = "released",
    governance_phase: str = "rolled_back",
) -> None:
    root.mkdir(parents=True)
    (root / "public-identity.json").write_text(
        json.dumps({"schema_version": "managed-path-stage6-public-identity/v1"}),
        encoding="utf-8",
    )
    (root / "stage6-apply-evidence.json").write_text(
        json.dumps(
            {
                "schema_version": "managed-path-stage6-apply/v1",
                "platform": "windows",
                "phase": phase,
                "commit": "a" * 40,
                "provider_receipt": {"status": receipt_status},
                "private_material_exported": False,
            }
        ),
        encoding="utf-8",
    )
    database = root / "stage6-apply-governance.sqlite3"
    connection = sqlite3.connect(database)
    try:
        connection.execute("CREATE TABLE network_apply_claims(state TEXT NOT NULL)")
        connection.execute("INSERT INTO network_apply_claims VALUES (?)", (claim_state,))
        connection.execute("CREATE TABLE network_governance(payload TEXT NOT NULL)")
        connection.execute(
            "INSERT INTO network_governance VALUES (?)",
            (json.dumps({"phase": governance_phase}),),
        )
        connection.commit()
    finally:
        connection.close()
    (root / "managed-network-ledger.sqlite3").write_bytes(b"ledger")
    provider = root / "managed-network" / "windows-operations.sqlite3"
    provider.parent.mkdir()
    provider.write_bytes(b"journal")


def test_archive_rolled_back_run_moves_artifacts_and_preserves_public_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "windows"
    _rolled_back_archive_fixture(root)
    monkeypatch.setitem(subject._APPROVED_DATA_DIRS, "windows", root)  # pyright: ignore[reportPrivateUsage]

    result = subject._archive_rolled_back_run(  # pyright: ignore[reportPrivateUsage]
        "windows", resources_absent=lambda _platform, _root: True, now=ARCHIVE_NOW
    )

    archive = Path(cast(str, result["archive"]))
    assert result["success"] is True
    assert (root / "public-identity.json").is_file()
    assert not (root / "stage6-apply-evidence.json").exists()
    assert (archive / "stage6-apply-evidence.json").is_file()
    assert (archive / "stage6-apply-governance.sqlite3").is_file()
    assert (archive / "managed-network-ledger.sqlite3").is_file()
    assert (archive / "managed-network" / "windows-operations.sqlite3").is_file()
    manifest = json.loads((archive / "archive-manifest.json").read_text(encoding="utf-8"))
    assert manifest["private_material_exported"] is False
    assert manifest["identity_preserved"] is True
    assert "public-identity.json" not in manifest["files"]


def test_archive_without_run_is_successful_noop(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "windows"
    root.mkdir()
    identity = root / "public-identity.json"
    identity.write_text("{}", encoding="utf-8")
    ledger = root / "managed-network-ledger.sqlite3"
    ledger.write_bytes(b"identity-infrastructure")
    provider = root / "managed-network" / "windows-operations.sqlite3"
    provider.parent.mkdir()
    provider.write_bytes(b"identity-infrastructure")
    monkeypatch.setitem(subject._APPROVED_DATA_DIRS, "windows", root)  # pyright: ignore[reportPrivateUsage]

    result = subject._archive_rolled_back_run(  # pyright: ignore[reportPrivateUsage]
        "windows", resources_absent=lambda _platform, _root: True, now=ARCHIVE_NOW
    )

    assert result["success"] is True
    assert result["status"] == "no_run"
    assert result["archived_files"] == 0
    assert identity.is_file()
    assert ledger.is_file()
    assert provider.is_file()
    assert not (root / "stage6-run-archives").exists()


def test_archive_without_evidence_rejects_partial_run_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "windows"
    root.mkdir()
    (root / "stage6-apply-ready.json").write_text("{}", encoding="utf-8")
    monkeypatch.setitem(subject._APPROVED_DATA_DIRS, "windows", root)  # pyright: ignore[reportPrivateUsage]

    with pytest.raises(SystemExit, match="存在不完整运行制品"):
        subject._archive_rolled_back_run(  # pyright: ignore[reportPrivateUsage]
            "windows", resources_absent=lambda _platform, _root: True, now=ARCHIVE_NOW
        )


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"phase": "applying"}, "未证明完整回滚"),
        ({"receipt_status": "applied"}, "未证明完整回滚"),
        ({"claim_state": "held"}, "claim 尚未全部 released"),
        ({"governance_phase": "failed"}, "治理记录尚未全部 rolled_back"),
    ],
)
def test_archive_rolled_back_run_rejects_incomplete_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    overrides: dict[str, str],
    message: str,
) -> None:
    root = tmp_path / "windows"
    _rolled_back_archive_fixture(root, **overrides)
    monkeypatch.setitem(subject._APPROVED_DATA_DIRS, "windows", root)  # pyright: ignore[reportPrivateUsage]

    with pytest.raises(SystemExit, match=message):
        subject._archive_rolled_back_run(  # pyright: ignore[reportPrivateUsage]
            "windows", resources_absent=lambda _platform, _root: True, now=ARCHIVE_NOW
        )


def test_archive_rolled_back_run_rejects_present_resources(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "windows"
    _rolled_back_archive_fixture(root)
    monkeypatch.setitem(subject._APPROVED_DATA_DIRS, "windows", root)  # pyright: ignore[reportPrivateUsage]

    with pytest.raises(SystemExit, match="批准接口、地址或 host route 仍存在"):
        subject._archive_rolled_back_run(  # pyright: ignore[reportPrivateUsage]
            "windows", resources_absent=lambda _platform, _root: False, now=ARCHIVE_NOW
        )


def test_orphan_recover_accepts_unique_verified_journal_without_claim(
    tmp_path: Path,
) -> None:
    plan = _plan()
    journal = _operation_journal(plan, status=ReceiptStatus.VERIFIED)
    provider_path = tmp_path / "managed-network" / "windows-operations.sqlite3"
    SQLiteWindowsOperationJournal(provider_path).put(journal)
    database = tmp_path / "stage6-apply-governance.sqlite3"
    connection = sqlite3.connect(database)
    try:
        connection.execute("CREATE TABLE network_governance(payload TEXT NOT NULL)")
        connection.execute(
            """
            CREATE TABLE network_apply_claims(
                network_id TEXT, node_id TEXT, revision INTEGER,
                idempotency_key TEXT, plan_hash TEXT,
                lease_expires_at TEXT, state TEXT
            )
            """
        )
        connection.commit()
    finally:
        connection.close()

    loaded = subject._load_exact_provider_journal(  # pyright: ignore[reportPrivateUsage]
        "windows",
        provider_path,
        allowed_statuses=frozenset({ReceiptStatus.APPLIED, ReceiptStatus.VERIFIED}),
    )
    assert loaded == journal
    assert subject._orphan_claim_states(database) == ()  # pyright: ignore[reportPrivateUsage]


def test_orphan_recover_records_but_does_not_trust_stale_claim(tmp_path: Path) -> None:
    journal = _operation_journal(_plan(), status=ReceiptStatus.VERIFIED)
    database = tmp_path / "stage6-apply-governance.sqlite3"
    _orphan_governance_fixture(database, journal)
    connection = sqlite3.connect(database)
    try:
        connection.execute("UPDATE network_apply_claims SET plan_hash=?", (f"sha256:{'9' * 64}",))
        connection.commit()
    finally:
        connection.close()

    assert subject._orphan_claim_states(database) == (  # pyright: ignore[reportPrivateUsage]
        "active",
    )


def test_orphan_recover_normalizes_terminal_journal_after_resources_are_absent(
    tmp_path: Path,
) -> None:
    journal = _operation_journal(_plan(), status=ReceiptStatus.MANUAL_INTERVENTION)
    provider_path = tmp_path / "managed-network" / "windows-operations.sqlite3"
    _write_operation_journal(provider_path, journal)

    subject._mark_provider_journal_rolled_back(  # pyright: ignore[reportPrivateUsage]
        provider_path, journal
    )

    loaded = subject._load_exact_provider_journal(  # pyright: ignore[reportPrivateUsage]
        "windows",
        provider_path,
        allowed_statuses=frozenset({ReceiptStatus.ROLLED_BACK}),
    )
    assert loaded.status is ReceiptStatus.ROLLED_BACK


def test_archive_accepts_completed_orphan_recover(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "windows"
    root.mkdir(parents=True)
    (root / "public-identity.json").write_text("{}", encoding="utf-8")
    journal = _operation_journal(_plan(), status=ReceiptStatus.ROLLED_BACK)
    database = root / "stage6-apply-governance.sqlite3"
    _orphan_governance_fixture(database, journal)
    provider_path = root / "managed-network" / "windows-operations.sqlite3"
    _write_operation_journal(provider_path, journal)
    (root / "managed-network-ledger.sqlite3").write_bytes(b"ledger")
    (root / "stage6-apply-evidence.json").write_text(
        json.dumps(
            {
                "schema_version": "managed-path-stage6-apply/v1",
                "mode": "orphan_recover",
                "platform": "windows",
                "phase": "rolled_back",
                "commit": "a" * 40,
                "plan_hash": journal.plan.plan_hash,
                "provider_receipt": {"status": "rolled_back"},
                "private_material_exported": False,
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setitem(subject._APPROVED_DATA_DIRS, "windows", root)  # pyright: ignore[reportPrivateUsage]

    result = subject._archive_rolled_back_run(  # pyright: ignore[reportPrivateUsage]
        "windows", resources_absent=lambda _platform, _root: True, now=ARCHIVE_NOW
    )

    assert result["success"] is True
    assert Path(cast(str, result["archive"])).is_dir()


def test_archive_mode_rejects_barrier_and_identity_without_reading_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def allow_elevated(_platform: str) -> None:
        return None

    monkeypatch.setattr(subject, "_require_elevated", allow_elevated)

    with pytest.raises(SystemExit, match="不得接收 barrier"):
        subject.main(
            [
                "--platform",
                "windows",
                "--barrier-id",
                BARRIER_ID,
                "--archive-rolled-back",
            ]
        )
    with pytest.raises(SystemExit, match="不得接收 barrier"):
        subject.main(["--platform", "windows", "--identity-stdin", "--archive-rolled-back"])


def _release(
    data_dir: Path,
    plan: NetworkPlan,
    verifier: subject._BarrierPathVerifier,  # pyright: ignore[reportPrivateUsage]
) -> NetworkAuthorizationGrant:
    grant = _grant(plan)
    verifier.bind_authorization(grant)
    authorization_hash = verifier._authorization_hash  # pyright: ignore[reportPrivateUsage]
    local: dict[str, object] = {
        "schema_version": "managed-path-stage6-barrier/v2",
        "platform": "macos",
        "barrier_id_hash": canonical_sha256({"barrier_id": BARRIER_ID}),
        "plan_hash": plan.plan_hash,
        "authorization_hash": authorization_hash,
        "authorization_expires_at": grant.expires_at.isoformat(),
        "provider_verified": True,
        "network_writes_completed": True,
    }
    peer: dict[str, object] = {
        **local,
        "platform": "windows",
        "plan_hash": f"sha256:{'d' * 64}",
        "authorization_hash": f"sha256:{'e' * 64}",
    }
    (data_dir / "stage6-apply-ready.json").write_text(json.dumps(local), encoding="utf-8")
    (data_dir / "stage6-apply-peer-ready.json").write_text(json.dumps(peer), encoding="utf-8")
    release = subject._go_marker(  # pyright: ignore[reportPrivateUsage]
        "macos", BARRIER_ID, local, peer
    )
    (data_dir / "stage6-apply-go.json").write_text(json.dumps(release), encoding="utf-8")
    return grant


def test_barrier_verifier_uses_fallback_only_after_primary_failure(tmp_path: Path) -> None:
    plan = _plan()
    calls: list[tuple[str, int]] = []

    def factory(desired: DesiredNetworkConfig, policy: PathProbePolicy) -> PlatformPathProbe:
        del desired, policy
        return cast(PlatformPathProbe, _Probe(calls, primary_succeeds=False))

    verifier = subject._BarrierPathVerifier(  # pyright: ignore[reportPrivateUsage]
        platform="macos",
        barrier_id=BARRIER_ID,
        data_dir=tmp_path,
        probe_factory=factory,
        clock=lambda: NOW,
    )
    _release(tmp_path, plan, verifier)
    evidence = asyncio.run(verifier.verify(plan, now=NOW))

    assert evidence.verified
    assert calls == [("192.0.2.1", 7899), ("192.0.2.1", 47990)]
    assert verifier.probe_runs == 1
    assert verifier.target_attempts == [7899, 47990]


def test_barrier_verifier_stops_after_primary_success(tmp_path: Path) -> None:
    plan = _plan()
    calls: list[tuple[str, int]] = []

    def factory(desired: DesiredNetworkConfig, policy: PathProbePolicy) -> PlatformPathProbe:
        del desired, policy
        return cast(PlatformPathProbe, _Probe(calls, primary_succeeds=True))

    verifier = subject._BarrierPathVerifier(  # pyright: ignore[reportPrivateUsage]
        platform="macos",
        barrier_id=BARRIER_ID,
        data_dir=tmp_path,
        probe_factory=factory,
        clock=lambda: NOW,
    )
    _release(tmp_path, plan, verifier)

    assert asyncio.run(verifier.verify(plan, now=NOW)).verified
    assert calls == [("192.0.2.1", 7899)]


def test_targets_match_authorization_and_are_not_discovery_ranges() -> None:
    assert {  # pyright: ignore[reportPrivateUsage]
        "windows": (subject._ApprovedTarget("192.0.2.2", 8787),),  # pyright: ignore[reportPrivateUsage]
        "macos": (
            subject._ApprovedTarget("192.0.2.1", 7899),  # pyright: ignore[reportPrivateUsage]
            subject._ApprovedTarget("192.0.2.1", 47990),  # pyright: ignore[reportPrivateUsage]
        ),
    } == subject._TARGETS  # pyright: ignore[reportPrivateUsage]


def test_release_requires_matching_local_and_peer_ready(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setitem(
        subject._APPROVED_DATA_DIRS,  # pyright: ignore[reportPrivateUsage]
        "windows",
        tmp_path,
    )
    barrier_hash = canonical_sha256({"barrier_id": BARRIER_ID})
    local = {
        "schema_version": "managed-path-stage6-barrier/v2",
        "platform": "windows",
        "barrier_id_hash": barrier_hash,
        "plan_hash": f"sha256:{'c' * 64}",
        "authorization_hash": f"sha256:{'e' * 64}",
        "authorization_expires_at": (datetime.now(UTC) + timedelta(minutes=15)).isoformat(),
        "provider_verified": True,
        "network_writes_completed": True,
    }
    peer = {
        "schema_version": "managed-path-stage6-barrier/v2",
        "platform": "macos",
        "barrier_id_hash": barrier_hash,
        "plan_hash": f"sha256:{'d' * 64}",
        "authorization_hash": f"sha256:{'f' * 64}",
        "authorization_expires_at": (datetime.now(UTC) + timedelta(minutes=15)).isoformat(),
        "provider_verified": True,
        "network_writes_completed": True,
    }
    (tmp_path / "stage6-apply-ready.json").write_text(json.dumps(local), encoding="utf-8")
    with pytest.raises(SystemExit, match="peer-ready"):
        subject._release_barrier("windows", BARRIER_ID)  # pyright: ignore[reportPrivateUsage]
    (tmp_path / "stage6-apply-peer-ready.json").write_text(json.dumps(peer), encoding="utf-8")

    subject._release_barrier("windows", BARRIER_ID)  # pyright: ignore[reportPrivateUsage]

    released = json.loads((tmp_path / "stage6-apply-go.json").read_text(encoding="utf-8"))
    assert released["release_after_both_provider_verified"] is True
    assert released["local_plan_hash"] == local["plan_hash"]
    assert released["peer_plan_hash"] == peer["plan_hash"]
    assert "barrier_id" not in released


def test_authorization_expiry_after_barrier_makes_zero_target_calls(
    tmp_path: Path,
) -> None:
    plan = _plan()
    calls: list[tuple[str, int]] = []
    clock = [NOW]

    def factory(desired: DesiredNetworkConfig, policy: PathProbePolicy) -> PlatformPathProbe:
        del desired, policy
        return cast(PlatformPathProbe, _Probe(calls, primary_succeeds=True))

    verifier = subject._BarrierPathVerifier(  # pyright: ignore[reportPrivateUsage]
        platform="macos",
        barrier_id=BARRIER_ID,
        data_dir=tmp_path,
        probe_factory=factory,
        clock=lambda: clock[0],
    )
    grant = _release(tmp_path, plan, verifier)
    clock[0] = grant.expires_at

    with pytest.raises(RuntimeError, match="授权已过期"):
        asyncio.run(verifier.verify(plan, now=NOW))
    assert calls == []


def test_fallback_rechecks_ttl_and_does_not_connect_after_expiry(tmp_path: Path) -> None:
    plan = _plan()
    calls: list[tuple[str, int]] = []
    clock_values: list[datetime] = []

    def factory(desired: DesiredNetworkConfig, policy: PathProbePolicy) -> PlatformPathProbe:
        del desired, policy
        return cast(PlatformPathProbe, _Probe(calls, primary_succeeds=False))

    verifier = subject._BarrierPathVerifier(  # pyright: ignore[reportPrivateUsage]
        platform="macos",
        barrier_id=BARRIER_ID,
        data_dir=tmp_path,
        probe_factory=factory,
        clock=lambda: clock_values.pop(0),
    )
    grant = _release(tmp_path, plan, verifier)
    clock_values.extend((NOW, NOW, grant.expires_at))

    with pytest.raises(RuntimeError, match="授权已过期"):
        asyncio.run(verifier.verify(plan, now=NOW))
    assert calls == [("192.0.2.1", 7899)]


def test_non_target_unreachable_error_never_uses_fallback(tmp_path: Path) -> None:
    plan = _plan()
    calls: list[tuple[str, int]] = []

    def factory(desired: DesiredNetworkConfig, policy: PathProbePolicy) -> PlatformPathProbe:
        del desired, policy
        return cast(
            PlatformPathProbe,
            _Probe(
                calls,
                primary_succeeds=False,
                error=DirectPathErrorCode.PERMISSION_DENIED,
            ),
        )

    verifier = subject._BarrierPathVerifier(  # pyright: ignore[reportPrivateUsage]
        platform="macos",
        barrier_id=BARRIER_ID,
        data_dir=tmp_path,
        probe_factory=factory,
        clock=lambda: NOW,
    )
    _release(tmp_path, plan, verifier)

    evidence = asyncio.run(verifier.verify(plan, now=NOW))
    assert evidence.stable_error_code is DirectPathErrorCode.PERMISSION_DENIED
    assert calls == [("192.0.2.1", 7899)]


def test_started_target_attempt_without_result_is_never_replayed(tmp_path: Path) -> None:
    plan = _plan()
    calls: list[tuple[str, int]] = []

    def factory(desired: DesiredNetworkConfig, policy: PathProbePolicy) -> PlatformPathProbe:
        del desired, policy
        return cast(PlatformPathProbe, _Probe(calls, primary_succeeds=True))

    verifier = subject._BarrierPathVerifier(  # pyright: ignore[reportPrivateUsage]
        platform="macos",
        barrier_id=BARRIER_ID,
        data_dir=tmp_path,
        probe_factory=factory,
        clock=lambda: NOW,
    )
    grant = _release(tmp_path, plan, verifier)
    go = json.loads((tmp_path / "stage6-apply-go.json").read_text(encoding="utf-8"))
    subject._target_attempt(  # pyright: ignore[reportPrivateUsage]
        data_dir=tmp_path,
        label="primary",
        platform="macos",
        barrier_id=BARRIER_ID,
        pair_hash=go["pair_hash"],
        plan_hash=plan.plan_hash,
        authorization_hash=cast(
            str,
            verifier._authorization_hash,  # pyright: ignore[reportPrivateUsage]
        ),
        target=subject._TARGETS["macos"][0],  # pyright: ignore[reportPrivateUsage]
        now=grant.approved_at,
    )

    with pytest.raises(RuntimeError, match="结果不确定"):
        asyncio.run(verifier.verify(plan, now=NOW))
    assert calls == []


def test_completed_fallback_recovery_keeps_original_stale_time_and_never_reconnects(
    tmp_path: Path,
) -> None:
    plan = _plan()
    initial_calls: list[tuple[str, int]] = []

    def initial_factory(
        desired: DesiredNetworkConfig, policy: PathProbePolicy
    ) -> PlatformPathProbe:
        del desired, policy
        return cast(PlatformPathProbe, _Probe(initial_calls, primary_succeeds=False))

    initial = subject._BarrierPathVerifier(  # pyright: ignore[reportPrivateUsage]
        platform="macos",
        barrier_id=BARRIER_ID,
        data_dir=tmp_path,
        probe_factory=initial_factory,
        clock=lambda: NOW,
    )
    grant = _release(tmp_path, plan, initial)
    original = asyncio.run(initial.verify(plan, now=NOW))
    assert original.verified
    assert initial_calls == [("192.0.2.1", 7899), ("192.0.2.1", 47990)]

    recovery_calls: list[tuple[str, int]] = []

    def recovery_factory(
        desired: DesiredNetworkConfig, policy: PathProbePolicy
    ) -> PlatformPathProbe:
        del desired, policy
        return cast(PlatformPathProbe, _Probe(recovery_calls, primary_succeeds=True))

    stale_now = NOW + timedelta(seconds=181)
    recovery = subject._BarrierPathVerifier(  # pyright: ignore[reportPrivateUsage]
        platform="macos",
        barrier_id=BARRIER_ID,
        data_dir=tmp_path,
        probe_factory=recovery_factory,
        clock=lambda: stale_now,
    )
    recovery.bind_authorization(grant)
    recovered = asyncio.run(recovery.verify(plan, now=stale_now))

    assert recovery_calls == []
    assert recovered.observed_at == original.observed_at
    assert recovered.target_probe_at == original.target_probe_at
    assert recovered.expires_at == original.expires_at
    assert recovered.expires_at <= stale_now


class _VanishingSecretStore:
    def __init__(self, value: str) -> None:
        self._values = [value, None]
        self.set_calls = 0
        self.delete_calls = 0

    def get(self, name: str) -> str | None:
        del name
        return self._values.pop(0)

    def set(self, name: str, value: str) -> None:
        del name, value
        self.set_calls += 1

    def delete(self, name: str) -> None:
        del name
        self.delete_calls += 1


def test_existing_only_identity_disappearance_never_creates_or_deletes(
    tmp_path: Path,
) -> None:
    private = X25519PrivateKey.generate()
    private_text = base64.b64encode(
        private.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
    ).decode()
    public = base64.b64encode(
        private.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
    ).decode()
    backend = _VanishingSecretStore(private_text)
    name = (
        "wireguard/network_60000000000000000000000000000000/node_6000000000000000000000000000000a"
    )
    store = subject._ExistingOnlySecretStore(  # pyright: ignore[reportPrivateUsage]
        backend,
        expected_name=name,
        expected_public_key=public,
        expected_public_key_hash=canonical_sha256({"public_key": public}),
    )
    assert store.get(name) is not None
    materials = RestrictedMacOSConfigStore(tmp_path.resolve(), store)

    with pytest.raises(SecretStoreError, match="拒绝创建替代身份"):
        materials.ensure_identity(
            NetworkId("network_60000000000000000000000000000000"),
            NodeId("node_6000000000000000000000000000000a"),
        )
    assert backend.set_calls == 0
    assert backend.delete_calls == 0
    assert list(tmp_path.iterdir()) == []


def test_go_marker_rejects_wrong_peer_platform_and_extra_fields(tmp_path: Path) -> None:
    expires_at = (datetime.now(UTC) + timedelta(minutes=15)).isoformat()
    base: dict[str, object] = {
        "schema_version": "managed-path-stage6-barrier/v2",
        "platform": "windows",
        "barrier_id_hash": canonical_sha256({"barrier_id": BARRIER_ID}),
        "plan_hash": f"sha256:{'a' * 64}",
        "authorization_hash": f"sha256:{'b' * 64}",
        "authorization_expires_at": expires_at,
        "provider_verified": True,
        "network_writes_completed": True,
    }
    wrong_peer = {**base, "plan_hash": f"sha256:{'c' * 64}"}
    with pytest.raises(RuntimeError, match="绑定"):
        subject._go_marker(  # pyright: ignore[reportPrivateUsage]
            "windows", BARRIER_ID, base, wrong_peer
        )
    marker_path = tmp_path / "marker.json"
    marker_path.write_text(json.dumps({**base, "extra": True}), encoding="utf-8")
    with pytest.raises(RuntimeError, match="schema"):
        subject._load_exact_marker(  # pyright: ignore[reportPrivateUsage]
            marker_path,
            subject._READY_KEYS,  # pyright: ignore[reportPrivateUsage]
        )


def test_main_returns_nonzero_when_acceptance_is_not_successful(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def failed_run(*args: object, **kwargs: object) -> dict[str, object]:
        del args, kwargs
        return {"platform": "windows", "success": False}

    def matching_platform(platform: str) -> None:
        del platform

    monkeypatch.setattr(subject, "_require_matching_platform", matching_platform)
    monkeypatch.setattr(subject, "_run", failed_run)
    assert subject.main(["--platform", "windows", "--barrier-id", BARRIER_ID, "--apply"]) == 2


def test_main_requires_an_explicit_execution_mode() -> None:
    with pytest.raises(SystemExit) as exc_info:
        subject.main(["--platform", "windows", "--barrier-id", BARRIER_ID])

    assert exc_info.value.code == 2


def test_release_barrier_requires_elevated_context(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def matching_platform(platform: str) -> None:
        assert platform == "macos"

    def reject_elevation(platform: str) -> None:
        assert platform == "macos"
        raise SystemExit("elevation required")

    def unexpected_release(platform: str, barrier_id: str) -> None:
        pytest.fail(f"unexpected release: {platform} {barrier_id}")

    monkeypatch.setattr(subject, "_require_matching_platform", matching_platform)
    monkeypatch.setattr(subject, "_require_elevated", reject_elevation)
    monkeypatch.setattr(subject, "_release_barrier", unexpected_release)

    with pytest.raises(SystemExit, match="elevation required"):
        subject.main(
            [
                "--platform",
                "macos",
                "--barrier-id",
                BARRIER_ID,
                "--release-barrier",
            ]
        )


def test_import_peer_ready_writes_only_valid_bound_marker(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setitem(
        subject._APPROVED_DATA_DIRS,  # pyright: ignore[reportPrivateUsage]
        "windows",
        tmp_path,
    )
    barrier_hash = canonical_sha256({"barrier_id": BARRIER_ID})
    peer = {
        "schema_version": "managed-path-stage6-barrier/v2",
        "platform": "macos",
        "barrier_id_hash": barrier_hash,
        "plan_hash": f"sha256:{'a' * 64}",
        "authorization_hash": f"sha256:{'b' * 64}",
        "authorization_expires_at": (datetime.now(UTC) + timedelta(minutes=15)).isoformat(),
        "provider_verified": True,
        "network_writes_completed": True,
    }

    result = subject._import_peer_ready(  # pyright: ignore[reportPrivateUsage]
        "windows", BARRIER_ID, json.dumps(peer)
    )

    assert result == {
        "barrier_id_hash": barrier_hash,
        "peer_platform": "macos",
        "peer_ready_imported": True,
        "private_material_imported": False,
    }
    assert json.loads((tmp_path / "stage6-apply-peer-ready.json").read_text()) == peer


@pytest.mark.parametrize(
    "raw",
    [
        "[]",
        json.dumps({"schema_version": "managed-path-stage6-barrier/v2"}),
        "x" * 4097,
    ],
)
def test_import_peer_ready_rejects_invalid_or_oversized_payload(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    raw: str,
) -> None:
    monkeypatch.setitem(
        subject._APPROVED_DATA_DIRS,  # pyright: ignore[reportPrivateUsage]
        "windows",
        tmp_path,
    )

    with pytest.raises(SystemExit, match="peer-ready marker"):
        subject._import_peer_ready(  # pyright: ignore[reportPrivateUsage]
            "windows", BARRIER_ID, raw
        )

    assert not (tmp_path / "stage6-apply-peer-ready.json").exists()


def test_import_peer_ready_rejects_wrong_platform_or_barrier(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setitem(
        subject._APPROVED_DATA_DIRS,  # pyright: ignore[reportPrivateUsage]
        "windows",
        tmp_path,
    )
    peer = {
        "schema_version": "managed-path-stage6-barrier/v2",
        "platform": "windows",
        "barrier_id_hash": canonical_sha256({"barrier_id": BARRIER_ID}),
        "plan_hash": f"sha256:{'a' * 64}",
        "authorization_hash": f"sha256:{'b' * 64}",
        "authorization_expires_at": (datetime.now(UTC) + timedelta(minutes=15)).isoformat(),
        "provider_verified": True,
        "network_writes_completed": True,
    }

    with pytest.raises(SystemExit, match="绑定或 TTL"):
        subject._import_peer_ready(  # pyright: ignore[reportPrivateUsage]
            "windows", BARRIER_ID, json.dumps(peer)
        )

    assert not (tmp_path / "stage6-apply-peer-ready.json").exists()


def test_ready_marker_rejects_non_hex_hash_naive_expiry_and_replay() -> None:
    barrier_hash = canonical_sha256({"barrier_id": BARRIER_ID})
    base: dict[str, object] = {
        "schema_version": "managed-path-stage6-barrier/v2",
        "platform": "windows",
        "barrier_id_hash": barrier_hash,
        "plan_hash": f"sha256:{'a' * 64}",
        "authorization_hash": f"sha256:{'b' * 64}",
        "authorization_expires_at": (datetime.now(UTC) + timedelta(minutes=15)).isoformat(),
        "provider_verified": True,
        "network_writes_completed": True,
    }
    with pytest.raises(RuntimeError, match="绑定"):
        subject._validate_ready_marker(  # pyright: ignore[reportPrivateUsage]
            {**base, "plan_hash": f"sha256:{'g' * 64}"},
            platform="windows",
            barrier_hash=barrier_hash,
        )
    with pytest.raises(RuntimeError, match="绑定"):
        subject._validate_ready_marker(  # pyright: ignore[reportPrivateUsage]
            {
                **base,
                "authorization_expires_at": (datetime.now() + timedelta(minutes=15)).isoformat(),
            },
            platform="windows",
            barrier_hash=barrier_hash,
        )
    with pytest.raises(RuntimeError, match="绑定"):
        subject._validate_ready_marker(  # pyright: ignore[reportPrivateUsage]
            base,
            platform="windows",
            barrier_hash=canonical_sha256({"barrier_id": "replayed"}),
        )


def test_platform_identity_delegates_remain_available_for_default_factories() -> None:
    material = LocalNetworkKeyMaterial(
        secret_reference="keyring:test",
        public_key="A" * 43 + "=",
        public_key_hash=f"sha256:{'a' * 64}",
    )

    class IdentityFactory:
        def create_identity(
            self, network_id: NetworkId, node_id: NodeId
        ) -> LocalNetworkKeyMaterial:
            del network_id, node_id
            return material

    macos = object.__new__(OfficialMacOSManagedBackend)
    macos._materials = cast(  # pyright: ignore[reportPrivateUsage]
        RestrictedMacOSConfigStore, IdentityFactory()
    )
    windows = object.__new__(OfficialWindowsManagedBackend)
    windows._materials = cast(  # pyright: ignore[reportPrivateUsage]
        AclRestrictedWindowsConfigStore, IdentityFactory()
    )
    provider = object.__new__(WindowsNetworkProvider)
    provider._backend = windows  # pyright: ignore[reportPrivateUsage]

    network_id = NetworkId("network_60000000000000000000000000000000")
    node_id = NodeId("node_6000000000000000000000000000000a")
    assert macos.create_identity(network_id, node_id) is material
    assert windows.create_identity(network_id, node_id) is material
    assert provider.create_local_identity(network_id, node_id) is material


def test_macos_root_reads_only_approved_login_keychain_item_without_secret_in_argv() -> None:
    captured: list[tuple[tuple[str, ...], dict[str, object]]] = []
    private_text = "private-material-only-in-stdout"

    def run_process(command: tuple[str, ...], **kwargs: object) -> subprocess.CompletedProcess[str]:
        captured.append((command, kwargs))
        return subprocess.CompletedProcess(command, 0, f"{private_text}\n", "ignored")

    name = "wireguard/network/node"
    store = subject._MacOSLoginKeychainSecretStore(  # pyright: ignore[reportPrivateUsage]
        expected_name=name,
        platform_name="darwin",
        effective_uid=lambda: 0,
        console_uid=lambda: 501,
        run_process=run_process,
    )

    assert store.get(name) == private_text
    command, kwargs = captured[0]
    assert command == (
        "/bin/launchctl",
        "asuser",
        "501",
        "/usr/bin/sudo",
        "-u",
        "#501",
        "-H",
        "/usr/bin/security",
        "find-generic-password",
        "-s",
        "TunnelMinion",
        "-a",
        name,
        "-w",
    )
    assert private_text not in command
    assert kwargs["timeout"] == 15
    assert kwargs["env"] == {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin"}
    with pytest.raises(SecretStoreError, match="禁止创建"):
        store.set(name, private_text)
    with pytest.raises(SecretStoreError, match="禁止删除"):
        store.delete(name)


@pytest.mark.parametrize(
    ("platform_name", "effective_uid", "console_uid", "requested_name", "message"),
    [
        ("win32", 0, 501, "wireguard/network/node", "上下文无效"),
        ("darwin", 501, 501, "wireguard/network/node", "上下文无效"),
        ("darwin", 0, 501, "wireguard/other/node", "非批准名称"),
        ("darwin", 0, 0, "wireguard/network/node", "普通登录用户"),
        ("darwin", 0, 2**31, "wireguard/network/node", "普通登录用户"),
    ],
)
def test_macos_login_keychain_store_rejects_wrong_boundary(
    platform_name: str,
    effective_uid: int,
    console_uid: int,
    requested_name: str,
    message: str,
) -> None:
    store = subject._MacOSLoginKeychainSecretStore(  # pyright: ignore[reportPrivateUsage]
        expected_name="wireguard/network/node",
        platform_name=platform_name,
        effective_uid=lambda: effective_uid,
        console_uid=lambda: console_uid,
    )
    with pytest.raises(SecretStoreError, match=message):
        store.get(requested_name)


def test_macos_login_keychain_store_redacts_failures() -> None:
    def missing_console() -> int:
        raise OSError("sensitive console detail")

    missing = subject._MacOSLoginKeychainSecretStore(  # pyright: ignore[reportPrivateUsage]
        expected_name="wireguard/network/node",
        platform_name="darwin",
        effective_uid=lambda: 0,
        console_uid=missing_console,
    )
    with pytest.raises(SecretStoreError, match="无法确认") as console_error:
        missing.get("wireguard/network/node")
    assert "sensitive" not in str(console_error.value)

    def failed_process(
        command: tuple[str, ...], **kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        del kwargs
        return subprocess.CompletedProcess(command, 1, "private-output", "sensitive error")

    failed = subject._MacOSLoginKeychainSecretStore(  # pyright: ignore[reportPrivateUsage]
        expected_name="wireguard/network/node",
        platform_name="darwin",
        effective_uid=lambda: 0,
        console_uid=lambda: 501,
        run_process=failed_process,
    )
    with pytest.raises(SecretStoreError, match="无法读取") as process_error:
        failed.get("wireguard/network/node")
    assert "private-output" not in str(process_error.value)
    assert "sensitive error" not in str(process_error.value)

    def timed_out(command: tuple[str, ...], **kwargs: object) -> subprocess.CompletedProcess[str]:
        del kwargs
        raise subprocess.TimeoutExpired(command, 15, output="private-output", stderr="sensitive")

    timeout_store = subject._MacOSLoginKeychainSecretStore(  # pyright: ignore[reportPrivateUsage]
        expected_name="wireguard/network/node",
        platform_name="darwin",
        effective_uid=lambda: 0,
        console_uid=lambda: 501,
        run_process=timed_out,
    )
    with pytest.raises(SecretStoreError, match="无法读取") as timeout_error:
        timeout_store.get("wireguard/network/node")
    assert timeout_error.value.__cause__ is None
    assert timeout_error.value.__context__ is None


def test_macos_stage6_runner_accepts_only_exact_public_and_mutation_argv(
    tmp_path: Path,
) -> None:
    plan = _plan()
    desired = plan.desired
    paths = _stage6_test_paths(tmp_path)
    runner = subject._MacOSStage6CommandRunner(  # pyright: ignore[reportPrivateUsage]
        desired,
        paths=paths,
        platform_name="darwin",
        effective_uid=lambda: 0,
    )
    config = paths.config_root / f"{desired.interface_name}.r{desired.revision}.conf"

    assert not runner._validate_command(  # pyright: ignore[reportPrivateUsage]
        (str(paths.wg), "show", "interfaces")
    )
    assert not runner._validate_command(  # pyright: ignore[reportPrivateUsage]
        (str(paths.wg), "show", "utun17", "latest-handshakes")
    )
    assert not runner._validate_command(  # pyright: ignore[reportPrivateUsage]
        (str(paths.ifconfig), "utun17")
    )
    assert not runner._validate_command(  # pyright: ignore[reportPrivateUsage]
        (str(paths.netstat), "-rn", "-f", "inet")
    )
    assert runner._validate_command(  # pyright: ignore[reportPrivateUsage]
        (str(paths.wg_quick), "up", str(config))
    )

    rejected = (
        (str(paths.wg), "private-key"),
        (str(paths.wg), "showconf", "utun17"),
        (str(paths.wg_quick), "up", "/tmp/other.conf"),
        (str(paths.wg_quick), "down", str(config.with_name("other.conf"))),
        (str(paths.ifconfig), "en0", "down"),
        (str(paths.netstat), "-an"),
        (str(paths.wg), "show", "utun17", "private-key"),
        (str(paths.wg), "show", "utun17\n", "peers"),
    )
    for command in rejected:
        with pytest.raises(RuntimeError, match="拒绝"):
            runner._validate_command(command)  # pyright: ignore[reportPrivateUsage]


def test_macos_stage6_runner_validates_root_config_grammar_without_exposing_key(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    desired = _plan().desired
    paths = _stage6_test_paths(tmp_path)
    runner = subject._MacOSStage6CommandRunner(  # pyright: ignore[reportPrivateUsage]
        desired,
        paths=paths,
        platform_name="darwin",
        effective_uid=lambda: 0,
    )
    config = paths.config_root / f"{desired.interface_name}.r{desired.revision}.conf"
    config.parent.mkdir()
    private_text = "A" * 43 + "="
    expected = subject._expected_redacted_config(desired)  # pyright: ignore[reportPrivateUsage]
    config.write_text(
        "\n".join(
            line.replace("<redacted>", private_text) if line.startswith("PrivateKey") else line
            for line in expected
        )
        + "\n",
        encoding="utf-8",
    )

    def accept_root_path(
        path: Path, *, regular_file: bool = False, exact_mode: int | None = None
    ) -> None:
        del path, regular_file, exact_mode

    monkeypatch.setattr(subject, "_assert_root_owned_path", accept_root_path)

    runner._validate_config(config)  # pyright: ignore[reportPrivateUsage]
    config.write_text(
        config.read_text(encoding="utf-8") + "PostUp = touch /tmp/x\n", encoding="utf-8"
    )
    with pytest.raises(RuntimeError, match="grammar") as hook_error:
        runner._validate_config(config)  # pyright: ignore[reportPrivateUsage]
    assert private_text not in str(hook_error.value)


def test_macos_stage6_direct_manager_uses_only_fixed_narrow_argv(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan = _plan()
    desired = plan.desired
    paths = _stage6_test_paths(tmp_path)
    runtime_root = tmp_path / "wireguard-runtime"
    runtime_root.mkdir()
    runner = subject._MacOSStage6CommandRunner(  # pyright: ignore[reportPrivateUsage]
        desired,
        paths=paths,
        platform_name="darwin",
        effective_uid=lambda: 0,
        runtime_root=runtime_root,
        route_path=tmp_path / "system" / "route",
    )
    runner.bind_operation(plan.plan_hash, "a" * 32)
    config = paths.config_root / f"{desired.interface_name}.r{desired.revision}.conf"
    process = _FakeMacOSProcess(output=(b"", b""))
    commands: list[tuple[str, ...]] = []
    marker_payloads: list[dict[str, object]] = []

    def accept_root_path(
        path: Path, *, regular_file: bool = False, exact_mode: int | None = None
    ) -> None:
        del path, regular_file, exact_mode

    async def process_factory(*args: object, **kwargs: object) -> _FakeMacOSProcess:
        command = tuple(str(value) for value in args)
        assert command == (str(paths.wg_quick), "-f", "utun")
        assert kwargs["env"] == {
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
            "WG_TUN_NAME_FILE": str(
                runtime_root / f"{desired.interface_name}.r{desired.revision}.name"
            ),
        }
        return process

    async def fixed_runtime_name(name_file: Path, started: _FakeMacOSProcess) -> str:
        del name_file
        assert started is process
        return "utun9"

    async def record_command(command: tuple[str, ...], *, allow_failure: bool = False) -> str:
        assert not allow_failure
        commands.append(command)
        return ""

    def ignore_directory(path: Path) -> None:
        del path

    def ignore_json(path: Path, data: dict[str, object]) -> None:
        del path
        marker_payloads.append(dict(data))

    def ignore_config(source: Path, target: Path) -> None:
        del source, target

    def fixed_public_hash(path: Path) -> str:
        del path
        return f"sha256:{'b' * 64}"

    monkeypatch.setattr(subject, "_assert_root_owned_path", accept_root_path)
    monkeypatch.setattr(subject, "_ensure_macos_stage6_directory", ignore_directory)
    monkeypatch.setattr(subject, "_write_root_private_json", ignore_json)
    monkeypatch.setattr(subject.asyncio, "create_subprocess_exec", process_factory)
    monkeypatch.setattr(
        runner,
        "_runtime_paths",
        lambda: (
            runtime_root / "tmn-stage6-b.r1.name",
            tmp_path / "runtime" / "tmn-stage6-b.r1.json",
            paths.config_root / "tmn-stage6-b.r1.wg.conf",
        ),
    )
    monkeypatch.setattr(runner, "_write_wg_only_config", ignore_config)
    monkeypatch.setattr(runner, "_wait_runtime_name", fixed_runtime_name)
    monkeypatch.setattr(runner, "_config_public_key_hash", fixed_public_hash)
    monkeypatch.setattr(runner, "_run_private_command", record_command)

    asyncio.run(runner._direct_up(config))  # pyright: ignore[reportPrivateUsage]

    assert [payload["phase"] for payload in marker_payloads] == [
        "preparing",
        "spawned",
        "configured",
        "addressed",
        "routed",
    ]
    assert marker_payloads[0]["runtime_interface"] is None
    assert marker_payloads[0]["pid"] is None
    assert all("private" not in key and "endpoint" not in key for key in marker_payloads[0])
    assert commands == [
        (str(paths.wg), "setconf", "utun9", str(paths.config_root / "tmn-stage6-b.r1.wg.conf")),
        (
            str(paths.ifconfig),
            "utun9",
            "inet",
            "192.0.2.2",
            "192.0.2.2",
            "netmask",
            "255.255.255.255",
        ),
        (str(paths.ifconfig), "utun9", "up"),
        (
            str(tmp_path / "system" / "route"),
            "-q",
            "-n",
            "add",
            "-inet",
            "192.0.2.1/32",
            "-interface",
            "utun9",
        ),
    ]
    rendered = " ".join(value for command in commands for value in command).lower()
    assert all(
        forbidden not in rendered
        for forbidden in ("bash", "wg-quick", "dns", "default", "firewall", "murus")
    )


@pytest.mark.parametrize("stale_kind", ["marker-temp", "wg-config-temp"])
def test_macos_stage6_direct_up_rejects_preexisting_atomic_temp(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    stale_kind: str,
) -> None:
    plan = _plan()
    paths = _stage6_test_paths(tmp_path)
    runtime_root = tmp_path / "wireguard-runtime"
    runtime_root.mkdir()
    runner = subject._MacOSStage6CommandRunner(  # pyright: ignore[reportPrivateUsage]
        plan.desired,
        paths=paths,
        platform_name="darwin",
        effective_uid=lambda: 0,
        runtime_root=runtime_root,
    )
    runner.bind_operation(plan.plan_hash, "a" * 32)
    name_file = runtime_root / "tmn-stage6-b.r1.name"
    marker_file = tmp_path / "runtime" / "tmn-stage6-b.r1.json"
    wg_config = paths.config_root / "tmn-stage6-b.r1.wg.conf"
    stale_path = subject._private_temp_path(  # pyright: ignore[reportPrivateUsage]
        marker_file if stale_kind == "marker-temp" else wg_config
    )
    stale_path.parent.mkdir(parents=True, exist_ok=True)
    stale_path.write_bytes(b"preexisting")
    monkeypatch.setattr(runner, "_runtime_paths", lambda: (name_file, marker_file, wg_config))

    def accept_root_path(
        path: Path, *, regular_file: bool = False, exact_mode: int | None = None
    ) -> None:
        del path, regular_file, exact_mode

    monkeypatch.setattr(subject, "_assert_root_owned_path", accept_root_path)

    with pytest.raises(RuntimeError, match="存在未清理运行材料"):
        asyncio.run(runner._direct_up(tmp_path / "config.conf"))  # pyright: ignore[reportPrivateUsage]

    assert stale_path.read_bytes() == b"preexisting"
    assert runner.runtime_resources() == (f"stage6:{stale_kind}",)


def test_macos_stage6_direct_manager_deletes_only_owned_route_and_socket(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan = _plan()
    paths = _stage6_test_paths(tmp_path)
    runtime_root = tmp_path / "wireguard-runtime"
    runtime_root.mkdir()
    runner = subject._MacOSStage6CommandRunner(  # pyright: ignore[reportPrivateUsage]
        plan.desired,
        paths=paths,
        platform_name="darwin",
        effective_uid=lambda: 0,
        runtime_root=runtime_root,
        route_path=tmp_path / "system" / "route",
    )
    runner.bind_operation(plan.plan_hash, "a" * 32)
    name_file = runtime_root / "tmn-stage6-b.r1.name"
    marker_file = tmp_path / "runtime" / "tmn-stage6-b.r1.json"
    wg_config = paths.config_root / "tmn-stage6-b.r1.wg.conf"
    for item in (name_file, marker_file, wg_config, runtime_root / "utun9.sock"):
        item.parent.mkdir(parents=True, exist_ok=True)
        item.write_text("fixture", encoding="utf-8")
    deleted_commands: list[tuple[str, ...]] = []

    def accept_root_path(
        path: Path, *, regular_file: bool = False, exact_mode: int | None = None
    ) -> None:
        del path, regular_file, exact_mode

    async def public_hash(_runtime: str, *, allow_absent: bool = False) -> str:
        assert allow_absent
        return f"sha256:{'b' * 64}"

    async def command_result(command: tuple[str, ...], *, allow_failure: bool = False) -> str:
        assert not allow_failure
        if command == (str(paths.netstat), "-rn", "-f", "inet"):
            return "192.0.2.1 link#20 UHS utun9\n"
        deleted_commands.append(command)
        return ""

    async def absent(_runtime: str) -> None:
        return None

    async def process_owned(_pid: int, _started_at: str) -> bool:
        return True

    async def wait_process_absent(_pid: int, _started_at: str) -> None:
        return None

    async def udp_absent() -> None:
        return None

    def accept_socket(path: Path) -> None:
        del path

    def runtime_marker(path: Path) -> dict[str, object]:
        del path
        return {
            "phase": "routed",
            "runtime_interface": "utun9",
            "public_key_hash": f"sha256:{'b' * 64}",
            "pid": 4242,
            "started_at": NOW.isoformat(),
            "plan_hash": plan.plan_hash,
            "creation_nonce_hash": canonical_sha256({"creation_nonce": "a" * 32}),
        }

    monkeypatch.setattr(subject, "_assert_root_owned_path", accept_root_path)
    monkeypatch.setattr(subject, "_assert_root_owned_socket", accept_socket)
    monkeypatch.setattr(
        subject,
        "_load_macos_runtime_marker",
        runtime_marker,
    )
    monkeypatch.setattr(runner, "_runtime_paths", lambda: (name_file, marker_file, wg_config))
    monkeypatch.setattr(runner, "_runtime_public_key_hash", public_hash)
    monkeypatch.setattr(runner, "_same_macos_process", process_owned)
    monkeypatch.setattr(runner, "_run_private_command", command_result)
    monkeypatch.setattr(runner, "_wait_interface_absent", absent)
    monkeypatch.setattr(runner, "_wait_bound_process_absent", wait_process_absent)
    monkeypatch.setattr(runner, "_assert_udp_port_absent", udp_absent)

    asyncio.run(runner._direct_down(wg_config))  # pyright: ignore[reportPrivateUsage]

    assert deleted_commands == [
        (
            str(tmp_path / "system" / "route"),
            "-q",
            "-n",
            "delete",
            "-inet",
            "192.0.2.1/32",
            "-interface",
            "utun9",
        )
    ]
    assert all(not item.exists() for item in (name_file, marker_file, wg_config))
    assert not (runtime_root / "utun9.sock").exists()


@pytest.mark.parametrize(
    ("phase", "process_is_owned", "runtime_public_hash", "route_interface", "error"),
    [
        pytest.param(
            "spawned",
            True,
            f"sha256:{'b' * 64}",
            "utun9",
            "host route 进程或接口所有权不匹配",
            id="phase-not-addressed",
        ),
        pytest.param(
            "routed",
            False,
            f"sha256:{'b' * 64}",
            "utun9",
            "runtime 进程所有权不匹配",
            id="process-not-owned",
        ),
        pytest.param(
            "routed",
            True,
            None,
            "utun9",
            "host route 进程或接口所有权不匹配",
            id="public-key-unavailable",
        ),
        pytest.param(
            "routed",
            True,
            f"sha256:{'c' * 64}",
            "utun9",
            "runtime 接口所有权不匹配",
            id="public-key-mismatch",
        ),
        pytest.param(
            "routed",
            True,
            f"sha256:{'b' * 64}",
            "utun8",
            "host route 所有权不匹配",
            id="route-interface-mismatch",
        ),
    ],
)
def test_macos_stage6_route_recovery_requires_each_ownership_proof(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    phase: str,
    process_is_owned: bool,
    runtime_public_hash: str | None,
    route_interface: str,
    error: str,
) -> None:
    plan = _plan()
    paths = _stage6_test_paths(tmp_path)
    runtime_root = tmp_path / "wireguard-runtime"
    runtime_root.mkdir()
    runner = subject._MacOSStage6CommandRunner(  # pyright: ignore[reportPrivateUsage]
        plan.desired,
        paths=paths,
        platform_name="darwin",
        effective_uid=lambda: 0,
        runtime_root=runtime_root,
        route_path=tmp_path / "system" / "route",
    )
    runner.bind_operation(plan.plan_hash, "a" * 32)
    name_file = runtime_root / "tmn-stage6-b.r1.name"
    marker_file = tmp_path / "runtime" / "tmn-stage6-b.r1.json"
    wg_config = paths.config_root / "tmn-stage6-b.r1.wg.conf"
    for item in (name_file, marker_file, wg_config):
        item.parent.mkdir(parents=True, exist_ok=True)
        item.write_text("fixture", encoding="utf-8")
    commands: list[tuple[str, ...]] = []

    def runtime_marker(path: Path) -> dict[str, object]:
        del path
        return {
            "phase": phase,
            "runtime_interface": "utun9",
            "public_key_hash": f"sha256:{'b' * 64}",
            "pid": 4242,
            "started_at": NOW.isoformat(),
            "plan_hash": plan.plan_hash,
            "creation_nonce_hash": canonical_sha256({"creation_nonce": "a" * 32}),
        }

    async def public_hash(_runtime: str, *, allow_absent: bool = False) -> str | None:
        assert allow_absent
        return runtime_public_hash

    async def process_owned(_pid: int, _started_at: str) -> bool:
        return process_is_owned

    async def command_result(command: tuple[str, ...], *, allow_failure: bool = False) -> str:
        assert not allow_failure
        commands.append(command)
        if command == (str(paths.netstat), "-rn", "-f", "inet"):
            return f"192.0.2.1 link#20 UHS {route_interface}\n"
        return ""

    monkeypatch.setattr(subject, "_load_macos_runtime_marker", runtime_marker)
    monkeypatch.setattr(runner, "_runtime_paths", lambda: (name_file, marker_file, wg_config))
    monkeypatch.setattr(runner, "_runtime_public_key_hash", public_hash)
    monkeypatch.setattr(runner, "_same_macos_process", process_owned)
    monkeypatch.setattr(runner, "_run_private_command", command_result)

    with pytest.raises(RuntimeError, match=error):
        asyncio.run(runner._direct_down(wg_config))  # pyright: ignore[reportPrivateUsage]

    assert all(command[0] != str(tmp_path / "system" / "route") for command in commands)
    assert all(item.exists() for item in (name_file, marker_file, wg_config))


def test_macos_stage6_preparing_recovery_cleans_private_artifacts_without_network(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan = _plan()
    paths = _stage6_test_paths(tmp_path)
    runner = subject._MacOSStage6CommandRunner(  # pyright: ignore[reportPrivateUsage]
        plan.desired,
        paths=paths,
        platform_name="darwin",
        effective_uid=lambda: 0,
        runtime_root=tmp_path / "wireguard-runtime",
    )
    runner.bind_operation(plan.plan_hash, "a" * 32)
    name_file = tmp_path / "wireguard-runtime" / "tmn-stage6-b.r1.name"
    marker_file = tmp_path / "runtime" / "tmn-stage6-b.r1.json"
    wg_config = paths.config_root / "tmn-stage6-b.r1.wg.conf"
    wg_config_temp = subject._private_temp_path(  # pyright: ignore[reportPrivateUsage]
        wg_config
    )
    for item in (marker_file, wg_config, wg_config_temp):
        item.parent.mkdir(parents=True, exist_ok=True)
        item.write_text("fixture", encoding="utf-8")
    monkeypatch.setattr(runner, "_runtime_paths", lambda: (name_file, marker_file, wg_config))
    assert runner.runtime_resources() == (
        "stage6:marker",
        "stage6:wg-config",
        "stage6:wg-config-temp",
    )

    def accept_root_path(
        path: Path, *, regular_file: bool = False, exact_mode: int | None = None
    ) -> None:
        del path, regular_file, exact_mode

    def runtime_marker(path: Path) -> dict[str, object]:
        del path
        return {
            "phase": "preparing",
            "runtime_interface": None,
            "pid": None,
            "started_at": None,
            "plan_hash": plan.plan_hash,
            "creation_nonce_hash": canonical_sha256({"creation_nonce": "a" * 32}),
            "public_key_hash": f"sha256:{'b' * 64}",
        }

    async def no_runtime(_path: Path) -> None:
        return None

    async def route_table(command: tuple[str, ...], **kwargs: object) -> str:
        del kwargs
        assert command == (str(paths.netstat), "-rn", "-f", "inet")
        return ""

    async def udp_absent() -> None:
        return None

    monkeypatch.setattr(subject, "_assert_root_owned_path", accept_root_path)
    monkeypatch.setattr(subject, "_load_macos_runtime_marker", runtime_marker)
    monkeypatch.setattr(runner, "_recover_runtime_name", no_runtime)
    monkeypatch.setattr(runner, "_run_private_command", route_table)
    monkeypatch.setattr(runner, "_assert_udp_port_absent", udp_absent)

    with pytest.raises(RuntimeError, match="结果无法证明"):
        asyncio.run(runner._direct_down(wg_config))  # pyright: ignore[reportPrivateUsage]
    assert runner.runtime_resources() == (
        "stage6:marker",
        "stage6:wg-config",
        "stage6:wg-config-temp",
    )

    runner._spawn_known_absent = True  # pyright: ignore[reportPrivateUsage]
    asyncio.run(runner._direct_down(wg_config))  # pyright: ignore[reportPrivateUsage]

    assert runner.runtime_resources() == ()


def test_macos_stage6_preparing_recovery_cleans_incomplete_config_temp(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan = _plan()
    paths = _stage6_test_paths(tmp_path)
    runner = subject._MacOSStage6CommandRunner(  # pyright: ignore[reportPrivateUsage]
        plan.desired,
        paths=paths,
        platform_name="darwin",
        effective_uid=lambda: 0,
        runtime_root=tmp_path / "wireguard-runtime",
    )
    runner.bind_operation(plan.plan_hash, "a" * 32)
    name_file = tmp_path / "wireguard-runtime" / "tmn-stage6-b.r1.name"
    marker_file = tmp_path / "runtime" / "tmn-stage6-b.r1.json"
    wg_config = paths.config_root / "tmn-stage6-b.r1.wg.conf"
    wg_config_temp = subject._private_temp_path(  # pyright: ignore[reportPrivateUsage]
        wg_config
    )
    for item in (marker_file, wg_config_temp):
        item.parent.mkdir(parents=True, exist_ok=True)
        item.write_text("fixture", encoding="utf-8")
    monkeypatch.setattr(runner, "_runtime_paths", lambda: (name_file, marker_file, wg_config))

    def runtime_marker(path: Path) -> dict[str, object]:
        del path
        return {
            "phase": "preparing",
            "runtime_interface": None,
            "pid": None,
            "started_at": None,
            "plan_hash": plan.plan_hash,
            "creation_nonce_hash": canonical_sha256({"creation_nonce": "a" * 32}),
            "public_key_hash": f"sha256:{'b' * 64}",
        }

    async def route_table(command: tuple[str, ...], **kwargs: object) -> str:
        del kwargs
        assert command == (str(paths.netstat), "-rn", "-f", "inet")
        return ""

    async def udp_absent() -> None:
        return None

    def accept_root_path(
        path: Path, *, regular_file: bool = False, exact_mode: int | None = None
    ) -> None:
        del path, regular_file, exact_mode

    monkeypatch.setattr(subject, "_assert_root_owned_path", accept_root_path)
    monkeypatch.setattr(subject, "_load_macos_runtime_marker", runtime_marker)
    monkeypatch.setattr(runner, "_run_private_command", route_table)
    monkeypatch.setattr(runner, "_assert_udp_port_absent", udp_absent)

    asyncio.run(runner._direct_down(wg_config))  # pyright: ignore[reportPrivateUsage]

    assert runner.runtime_resources() == ()


def test_macos_stage6_recovery_removes_only_uncommitted_marker_temp(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan = _plan()
    paths = _stage6_test_paths(tmp_path)
    runner = subject._MacOSStage6CommandRunner(  # pyright: ignore[reportPrivateUsage]
        plan.desired,
        paths=paths,
        platform_name="darwin",
        effective_uid=lambda: 0,
        runtime_root=tmp_path / "wireguard-runtime",
    )
    runner.bind_operation(plan.plan_hash, "a" * 32)
    name_file = tmp_path / "wireguard-runtime" / "tmn-stage6-b.r1.name"
    marker_file = tmp_path / "runtime" / "tmn-stage6-b.r1.json"
    marker_temp = subject._private_temp_path(  # pyright: ignore[reportPrivateUsage]
        marker_file
    )
    wg_config = paths.config_root / "tmn-stage6-b.r1.wg.conf"
    unrelated_temp = marker_file.parent / f".{marker_file.name}.unrelated.tmp"
    for item in (marker_temp, unrelated_temp):
        item.parent.mkdir(parents=True, exist_ok=True)
        item.write_text("fixture", encoding="utf-8")
    monkeypatch.setattr(runner, "_runtime_paths", lambda: (name_file, marker_file, wg_config))
    assert runner.runtime_resources() == ("stage6:marker-temp",)

    def accept_root_path(
        path: Path, *, regular_file: bool = False, exact_mode: int | None = None
    ) -> None:
        assert path == marker_temp
        assert regular_file is True
        assert exact_mode == 0o600

    async def udp_absent() -> None:
        return None

    monkeypatch.setattr(subject, "_assert_root_owned_path", accept_root_path)
    monkeypatch.setattr(runner, "_assert_udp_port_absent", udp_absent)

    asyncio.run(runner._direct_down(wg_config))  # pyright: ignore[reportPrivateUsage]

    assert not marker_temp.exists()
    assert unrelated_temp.exists()
    assert runner.runtime_resources() == ()


@pytest.mark.parametrize("other_kind", ["name", "wg-config", "wg-config-temp"])
def test_macos_stage6_marker_temp_recovery_rejects_any_other_material(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    other_kind: str,
) -> None:
    plan = _plan()
    paths = _stage6_test_paths(tmp_path)
    runner = subject._MacOSStage6CommandRunner(  # pyright: ignore[reportPrivateUsage]
        plan.desired,
        paths=paths,
        platform_name="darwin",
        effective_uid=lambda: 0,
        runtime_root=tmp_path / "wireguard-runtime",
    )
    runner.bind_operation(plan.plan_hash, "a" * 32)
    name_file = tmp_path / "wireguard-runtime" / "tmn-stage6-b.r1.name"
    marker_file = tmp_path / "runtime" / "tmn-stage6-b.r1.json"
    marker_temp = subject._private_temp_path(  # pyright: ignore[reportPrivateUsage]
        marker_file
    )
    wg_config = paths.config_root / "tmn-stage6-b.r1.wg.conf"
    wg_config_temp = subject._private_temp_path(  # pyright: ignore[reportPrivateUsage]
        wg_config
    )
    other_path = {
        "name": name_file,
        "wg-config": wg_config,
        "wg-config-temp": wg_config_temp,
    }[other_kind]
    for item in (marker_temp, other_path):
        item.parent.mkdir(parents=True, exist_ok=True)
        item.write_text("fixture", encoding="utf-8")
    monkeypatch.setattr(runner, "_runtime_paths", lambda: (name_file, marker_file, wg_config))

    with pytest.raises(RuntimeError, match="残留组合不可证明"):
        asyncio.run(runner._direct_down(wg_config))  # pyright: ignore[reportPrivateUsage]

    assert marker_temp.exists()
    assert other_path.exists()


@pytest.mark.parametrize("unexpected_kind", ["name-and-socket", "route"])
def test_macos_stage6_preparing_without_pid_never_deletes_network_material(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    unexpected_kind: str,
) -> None:
    plan = _plan()
    paths = _stage6_test_paths(tmp_path)
    runtime_root = tmp_path / "wireguard-runtime"
    runtime_root.mkdir()
    runner = subject._MacOSStage6CommandRunner(  # pyright: ignore[reportPrivateUsage]
        plan.desired,
        paths=paths,
        platform_name="darwin",
        effective_uid=lambda: 0,
        runtime_root=runtime_root,
    )
    runner.bind_operation(plan.plan_hash, "a" * 32)
    name_file = runtime_root / "tmn-stage6-b.r1.name"
    marker_file = tmp_path / "runtime" / "tmn-stage6-b.r1.json"
    wg_config = paths.config_root / "tmn-stage6-b.r1.wg.conf"
    marker_file.parent.mkdir(parents=True, exist_ok=True)
    marker_file.write_text("fixture", encoding="utf-8")
    socket_file = runtime_root / "utun9.sock"
    if unexpected_kind == "name-and-socket":
        name_file.write_text("utun9\n", encoding="ascii")
        socket_file.write_text("fixture", encoding="utf-8")
    monkeypatch.setattr(runner, "_runtime_paths", lambda: (name_file, marker_file, wg_config))

    def runtime_marker(path: Path) -> dict[str, object]:
        del path
        return {
            "phase": "preparing",
            "runtime_interface": None,
            "pid": None,
            "started_at": None,
            "plan_hash": plan.plan_hash,
            "creation_nonce_hash": canonical_sha256({"creation_nonce": "a" * 32}),
            "public_key_hash": f"sha256:{'b' * 64}",
        }

    commands: list[tuple[str, ...]] = []

    async def route_table(command: tuple[str, ...], **kwargs: object) -> str:
        del kwargs
        commands.append(command)
        return "192.0.2.1/32 192.0.2.1 UGSc utun9\n" if unexpected_kind == "route" else ""

    monkeypatch.setattr(subject, "_load_macos_runtime_marker", runtime_marker)
    monkeypatch.setattr(runner, "_run_private_command", route_table)

    with pytest.raises(RuntimeError, match="pre-spawn"):
        asyncio.run(runner._direct_down(wg_config))  # pyright: ignore[reportPrivateUsage]

    assert all("delete" not in command for command in commands)
    assert marker_file.exists()
    if unexpected_kind == "name-and-socket":
        assert name_file.exists()
        assert socket_file.exists()


@pytest.mark.parametrize(
    "updates",
    [
        {"revision": 2},
        {"parent_revision": 1},
        {"listen_port": 51890},
        {"interface_name": "tmn-stage6-other"},
    ],
)
def test_macos_stage6_direct_manager_rejects_resource_drift(
    tmp_path: Path, updates: dict[str, object]
) -> None:
    desired = _plan().desired.model_copy(update=updates)
    runner = subject._MacOSStage6CommandRunner(  # pyright: ignore[reportPrivateUsage]
        desired,
        paths=_stage6_test_paths(tmp_path),
        platform_name="darwin",
        effective_uid=lambda: 0,
    )

    with pytest.raises(RuntimeError, match="超出批准范围"):
        runner._direct_parameters()  # pyright: ignore[reportPrivateUsage]


def test_macos_stage6_direct_manager_rejects_peer_and_endpoint_drift(tmp_path: Path) -> None:
    plan = _plan()
    peer = plan.desired.peers[0]
    candidate = peer.candidates[0]
    variants = (
        peer.model_copy(update={"persistent_keepalive_seconds": 26}),
        peer.model_copy(update={"candidates": (candidate.model_copy(update={"port": 51890}),)}),
        peer.model_copy(update={"allowed_host_routes": ("192.0.2.3/32",)}),
    )
    for changed_peer in variants:
        runner = subject._MacOSStage6CommandRunner(  # pyright: ignore[reportPrivateUsage]
            plan.desired.model_copy(update={"peers": (changed_peer,)}),
            paths=_stage6_test_paths(tmp_path),
            platform_name="darwin",
            effective_uid=lambda: 0,
        )
        with pytest.raises(RuntimeError, match="超出批准范围"):
            runner._direct_parameters()  # pyright: ignore[reportPrivateUsage]


def test_macos_stage6_recovery_rejects_wrong_plan_or_nonce_binding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    plan = _plan()
    runner = subject._MacOSStage6CommandRunner(  # pyright: ignore[reportPrivateUsage]
        plan.desired,
        paths=_stage6_test_paths(tmp_path),
        platform_name="darwin",
        effective_uid=lambda: 0,
    )
    runner.bind_operation(plan.plan_hash, "a" * 32)
    name_file = tmp_path / "wireguard-runtime" / "tmn-stage6-b.r1.name"
    marker_file = tmp_path / "runtime" / "tmn-stage6-b.r1.json"
    wg_config = tmp_path / "config" / "tmn-stage6-b.r1.wg.conf"
    marker_file.parent.mkdir(parents=True, exist_ok=True)
    marker_file.write_text("fixture", encoding="utf-8")
    monkeypatch.setattr(runner, "_runtime_paths", lambda: (name_file, marker_file, wg_config))

    def wrong_marker(path: Path) -> dict[str, object]:
        del path
        return {
            "plan_hash": f"sha256:{'f' * 64}",
            "creation_nonce_hash": canonical_sha256({"creation_nonce": "a" * 32}),
        }

    monkeypatch.setattr(subject, "_load_macos_runtime_marker", wrong_marker)
    with pytest.raises(RuntimeError, match="绑定不匹配"):
        asyncio.run(
            runner._direct_down(tmp_path / "config.conf")  # pyright: ignore[reportPrivateUsage]
        )


class _FakeMacOSProcess:
    def __init__(self, *, output: tuple[bytes, bytes] | None = None) -> None:
        self.pid = 4242
        self.returncode: int | None = None
        self.output = output
        self.started = asyncio.Event()

    async def communicate(self) -> tuple[bytes, bytes]:
        self.started.set()
        if self.output is not None:
            return self.output
        await asyncio.Event().wait()
        raise AssertionError("unreachable")

    async def wait(self) -> int:
        self.returncode = -15
        return self.returncode


def test_macos_private_mutation_timeout_and_cancel_reap_before_return(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = subject._MacOSStage6CommandRunner(  # pyright: ignore[reportPrivateUsage]
        _plan().desired,
        paths=_stage6_test_paths(tmp_path),
        platform_name="darwin",
        effective_uid=lambda: 0,
    )
    command = (str(runner._paths.ifconfig), "utun9", "up")  # pyright: ignore[reportPrivateUsage]

    def accept_root_path(
        path: Path, *, regular_file: bool = False, exact_mode: int | None = None
    ) -> None:
        del path, regular_file, exact_mode

    monkeypatch.setattr(subject, "_assert_root_owned_path", accept_root_path)
    killed: list[tuple[int, int]] = []

    def kill_group(pid: int, sig: int) -> None:
        killed.append((pid, sig))

    monkeypatch.setattr(subject.os, "killpg", kill_group, raising=False)
    timeout_process = _FakeMacOSProcess()

    async def timeout_factory(*args: object, **kwargs: object) -> _FakeMacOSProcess:
        del args, kwargs
        return timeout_process

    monkeypatch.setattr(subject.asyncio, "create_subprocess_exec", timeout_factory)
    with pytest.raises(RuntimeError, match="步骤超时"):
        asyncio.run(runner._run_private_command(command, timeout_seconds=0.001))  # pyright: ignore[reportPrivateUsage]
    assert timeout_process.returncode == -15
    assert killed == [(4242, subject.signal.SIGTERM)]

    killed.clear()
    cancelled_process = _FakeMacOSProcess()

    async def cancel_factory(*args: object, **kwargs: object) -> _FakeMacOSProcess:
        del args, kwargs
        return cancelled_process

    monkeypatch.setattr(subject.asyncio, "create_subprocess_exec", cancel_factory)

    async def cancel_run() -> None:
        task = asyncio.create_task(runner._run_private_command(command))  # pyright: ignore[reportPrivateUsage]
        await cancelled_process.started.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(cancel_run())
    assert cancelled_process.returncode == -15
    assert killed == [(4242, subject.signal.SIGTERM)]


def test_macos_udp_listener_parser_uses_only_local_address_column() -> None:
    parser = subject._macos_udp_port_present  # pyright: ignore[reportPrivateUsage]
    assert parser("udp4 0 0 *.51889 *.* 0 0\n", 51889)
    assert parser("udp6 0 0 [::1]:51889 *.* 0 0\n", 51889)
    assert not parser("udp4 0 0 *.60000 10.0.0.1.51889 0 0\n", 51889)


def test_macos_stage6_runner_read_timeout_and_cancel_reap_process_group(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    desired = _plan().desired
    commands = _stage6_test_paths(tmp_path)
    runner = subject._MacOSStage6CommandRunner(  # pyright: ignore[reportPrivateUsage]
        desired,
        paths=commands,
        platform_name="darwin",
        effective_uid=lambda: 0,
    )
    command = (str(commands.wg), "show", "interfaces")

    def accept_command(value: tuple[str, ...]) -> bool:
        del value
        return False

    def accept_path(value: Path) -> None:
        del value

    monkeypatch.setattr(runner, "_validate_command", accept_command)
    monkeypatch.setattr(runner, "_verify_tool", accept_path)
    killed: list[tuple[int, int]] = []

    def kill_group(pid: int, sig: int) -> None:
        killed.append((pid, sig))

    monkeypatch.setattr(subject.os, "killpg", kill_group, raising=False)

    timeout_process = _FakeMacOSProcess()

    async def timeout_factory(*args: object, **kwargs: object) -> _FakeMacOSProcess:
        del args, kwargs
        return timeout_process

    monkeypatch.setattr(subject.asyncio, "create_subprocess_exec", timeout_factory)
    result = asyncio.run(runner.run(command, 0.001))
    assert result.returncode == 124
    assert timeout_process.returncode == -15
    assert killed == [(4242, subject.signal.SIGTERM)]

    killed.clear()
    cancelled_process = _FakeMacOSProcess()

    async def cancel_factory(*args: object, **kwargs: object) -> _FakeMacOSProcess:
        del args, kwargs
        return cancelled_process

    monkeypatch.setattr(subject.asyncio, "create_subprocess_exec", cancel_factory)

    async def cancel_run() -> None:
        task = asyncio.create_task(runner.run(command, 30))
        await cancelled_process.started.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(cancel_run())
    assert cancelled_process.returncode == -15
    assert killed == [(4242, subject.signal.SIGTERM)]


def test_hash_pinned_tool_copy_is_atomic_and_rejects_mismatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source"
    target = tmp_path / "target"
    source.write_bytes(b"fixed-tool")
    digest = subject.hashlib.sha256(b"fixed-tool").hexdigest()

    def ignore_chmod(fd: int, mode: int) -> None:
        del fd, mode

    def ignore_chown(fd: int, uid: int, gid: int) -> None:
        del fd, uid, gid

    def accept_root_path(
        path: Path, *, regular_file: bool = False, exact_mode: int | None = None
    ) -> None:
        del path, regular_file, exact_mode

    monkeypatch.setattr(subject.os, "fchmod", ignore_chmod, raising=False)
    monkeypatch.setattr(subject.os, "fchown", ignore_chown, raising=False)
    monkeypatch.setattr(subject, "_assert_root_owned_path", accept_root_path)

    subject._copy_hash_pinned_tool(source, target, digest)  # pyright: ignore[reportPrivateUsage]
    assert target.read_bytes() == b"fixed-tool"
    assert not tuple(tmp_path.glob(".*.tmp"))

    rejected = tmp_path / "rejected"
    with pytest.raises(SystemExit, match="hash"):
        subject._copy_hash_pinned_tool(  # pyright: ignore[reportPrivateUsage]
            source, rejected, "0" * 64
        )
    assert not rejected.exists()


def test_macos_runtime_marker_accepts_only_bound_phase_shapes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan = _plan()
    runner = subject._MacOSStage6CommandRunner(  # pyright: ignore[reportPrivateUsage]
        plan.desired,
        paths=_stage6_test_paths(tmp_path),
        platform_name="darwin",
        effective_uid=lambda: 0,
    )
    marker = tmp_path / "runtime.json"

    def accept_root_path(
        path: Path, *, regular_file: bool = False, exact_mode: int | None = None
    ) -> None:
        del path, regular_file, exact_mode

    monkeypatch.setattr(subject, "_assert_root_owned_path", accept_root_path)
    preparing = runner._runtime_marker_payload(  # pyright: ignore[reportPrivateUsage]
        phase="preparing",
        plan_hash=plan.plan_hash,
        creation_nonce="a" * 32,
        public_key_hash=f"sha256:{'b' * 64}",
    )
    marker.write_text(json.dumps(preparing), encoding="utf-8")
    assert subject._load_macos_runtime_marker(marker)["phase"] == "preparing"  # pyright: ignore[reportPrivateUsage]

    spawned = runner._runtime_marker_payload(  # pyright: ignore[reportPrivateUsage]
        phase="spawned",
        plan_hash=plan.plan_hash,
        creation_nonce="a" * 32,
        public_key_hash=f"sha256:{'b' * 64}",
        runtime_interface="utun9",
        pid=4242,
        started_at=NOW,
    )
    marker.write_text(json.dumps(spawned), encoding="utf-8")
    assert subject._load_macos_runtime_marker(marker)["pid"] == 4242  # pyright: ignore[reportPrivateUsage]

    marker.write_text(json.dumps({**spawned, "phase": "unknown"}), encoding="utf-8")
    with pytest.raises(RuntimeError, match="schema"):
        subject._load_macos_runtime_marker(marker)  # pyright: ignore[reportPrivateUsage]


def test_macos_tool_closure_accepts_only_apple_absolute_dependencies(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tool = tmp_path / "wg"
    tool.write_bytes(b"fixture")

    def accept_system_file(path: Path) -> None:
        del path

    monkeypatch.setattr(subject, "_assert_root_owned_system_file", accept_system_file)

    def apple_only(command: tuple[str, ...], **kwargs: object) -> subprocess.CompletedProcess[str]:
        del kwargs
        return subprocess.CompletedProcess(
            command,
            0,
            f"{tool}:\n\t/usr/lib/libSystem.B.dylib (compatibility version 1.0.0)\n",
            "",
        )

    subject._validate_macos_tool_closure(  # pyright: ignore[reportPrivateUsage]
        tool, run_process=apple_only
    )

    def homebrew_dependency(
        command: tuple[str, ...], **kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        del kwargs
        return subprocess.CompletedProcess(
            command,
            0,
            f"{tool}:\n\t/opt/homebrew/lib/libunsafe.dylib (compatibility version 1.0.0)\n",
            "",
        )

    with pytest.raises(SystemExit, match="Apple"):
        subject._validate_macos_tool_closure(  # pyright: ignore[reportPrivateUsage]
            tool, run_process=homebrew_dependency
        )


def test_macos_system_tool_accepts_apfs_multiple_hard_links(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    metadata = type(
        "Metadata",
        (),
        {
            "st_uid": 0,
            "st_mode": stat.S_IFREG | 0o755,
            "st_nlink": 78,
        },
    )()

    def fixed_metadata(path: Path) -> object:
        del path
        return metadata

    monkeypatch.setattr(subject.os, "lstat", fixed_metadata)

    subject._assert_root_owned_system_file(  # pyright: ignore[reportPrivateUsage]
        Path("/usr/bin/otool")
    )
