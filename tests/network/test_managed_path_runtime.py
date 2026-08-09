"""受管路径阶段一状态、持久 owner 与零 Provider 写入测试。"""

from __future__ import annotations

import asyncio
import base64
import json
import os
import sqlite3
import stat
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, cast

import pytest
from pydantic import ValidationError
from tests.network.factories import NETWORK_ID, NODE_A, NOW, desired, observation

from tunnelminion.domain.identifiers import AuthorizationId, NetworkId, NodeId
from tunnelminion.network.contracts import (
    NetworkAction,
    NetworkPlan,
    ProviderKind,
    SignedDesiredConfig,
    canonical_sha256,
)
from tunnelminion.network.governance import NetworkAuthorizationGrant, NetworkAuthorizationScope
from tunnelminion.network.managed_path_runtime import (
    MANAGED_PATH_CHECKPOINT_RELATIVE_PATH,
    FileManagedPathCheckpointRepository,
    ManagedPathCheckpoint,
    ManagedPathCheckpointError,
    ManagedPathCheckpointSink,
    ManagedPathEvidenceErrorCode,
    ManagedPathEvidenceState,
    ManagedPathOperationCode,
    ManagedPathPhaseOneErrorCode,
    ManagedPathPhaseOneLifecycle,
    ManagedPathPublicationCancelled,
    ManagedPathSelectionState,
    ManagedPathSinkDeliveryState,
    NetworkAuthorizationMatch,
    PathAuthorizationState,
    PathEvidenceFreshness,
    PathEvidenceSource,
    ReadOnlyNetworkAuthorizationMatcher,
)
from tunnelminion.network.path_controller import NetworkPathType


def run(awaitable: Any) -> Any:
    return asyncio.run(awaitable)


class ProviderSpy:
    """任何 Provider 边界被触达都会留下证据并立即失败。"""

    def __init__(self) -> None:
        self.calls: list[str] = []

    def __getattr__(self, name: str) -> Any:
        if name in {
            "apply",
            "ensure_local_identity",
            "observe",
            "plan",
            "recover",
            "rollback",
            "verify",
        }:
            self.calls.append(name)
            raise AssertionError(f"阶段一不得调用 Provider {name}")
        raise AttributeError(name)


def _build_plan() -> NetworkPlan:
    from tunnelminion.network.fakes import InMemoryNetworkProvider

    provider = InMemoryNetworkProvider(observation())
    return run(
        provider.plan(
            action=NetworkAction.CREATE,
            desired=desired(),
            observed=observation(),
            ownership=None,
        )
    )


TEST_PLAN = _build_plan()


def envelope(value: NetworkPlan) -> SignedDesiredConfig:
    return SignedDesiredConfig(
        config=value.desired,
        key_id="test-key",
        key_fingerprint=canonical_sha256({"key": "test"}),
        issued_at=NOW - timedelta(minutes=1),
        expires_at=NOW + timedelta(minutes=5),
        signature="s" * 80,
    )


def grant(
    value: NetworkPlan = TEST_PLAN,
    *,
    approved_at: datetime = NOW - timedelta(minutes=1),
    expires_at: datetime = NOW + timedelta(minutes=5),
    revoked_at: datetime | None = None,
) -> NetworkAuthorizationGrant:
    return NetworkAuthorizationGrant(
        authorization_id=AuthorizationId.new(),
        scope=NetworkAuthorizationScope.from_plan(value, address_pool="10.203.0.0/24"),
        approved_by="local-owner",
        approved_at=approved_at,
        expires_at=expires_at,
        revoked_at=revoked_at,
    )


def checkpoint(**updates: object) -> ManagedPathCheckpoint:
    values: dict[str, object] = {
        "network_id": NETWORK_ID,
        "node_id": NODE_A,
        "revision": 1,
        "provider": TEST_PLAN.desired.provider,
        "pending_plan_hash": TEST_PLAN.plan_hash,
        "observed_fingerprint": TEST_PLAN.observed_fingerprint,
        "authorization_state": PathAuthorizationState.AWAITING_AUTHORIZATION,
        "stable_error_code": ManagedPathPhaseOneErrorCode.LOCAL_L3_APPROVAL_REQUIRED,
        "updated_at": NOW,
    }
    values.update(updates)
    return ManagedPathCheckpoint.model_validate(values)


def evidence(
    value: ManagedPathCheckpoint,
    *,
    refreshed_at: datetime = NOW,
    expires_at: datetime = NOW + timedelta(seconds=180),
    **updates: object,
) -> ManagedPathEvidenceState:
    values: dict[str, object] = {
        "source": PathEvidenceSource.FAKE,
        "freshness": PathEvidenceFreshness.FRESH,
        "network_id": value.network_id,
        "node_id": value.node_id,
        "revision": value.revision,
        "provider": value.provider,
        "plan_hash": value.pending_plan_hash,
        "observed_fingerprint": value.observed_fingerprint,
        "authorization_id": value.authorization_id,
        "endpoint_probe_at": refreshed_at,
        "endpoint_probe_succeeded": True,
        "last_handshake_at": refreshed_at,
        "handshake_fresh": True,
        "host_route_present": True,
        "target_probe_at": refreshed_at,
        "target_probe_succeeded": True,
        "refreshed_at": refreshed_at,
        "expires_at": expires_at,
    }
    values.update(updates)
    return ManagedPathEvidenceState.model_validate(values)


class MemoryAuthorizationReader:
    def __init__(self, grants: tuple[NetworkAuthorizationGrant, ...] = ()) -> None:
        self.grants = grants
        self.reads: list[tuple[object, object]] = []

    def list_grants(
        self,
        network_id: object,
        node_id: object,
    ) -> tuple[NetworkAuthorizationGrant, ...]:
        self.reads.append((network_id, node_id))
        return self.grants


class FakeReadOnlyRefresher:
    def __init__(
        self,
        candidate: ManagedPathEvidenceState | None = None,
        *,
        gate: asyncio.Event | None = None,
    ) -> None:
        self.candidate = candidate
        self.calls = 0
        self.gate = gate

    async def refresh(self, checkpoint: ManagedPathCheckpoint) -> ManagedPathEvidenceState:
        self.calls += 1
        if self.gate is not None:
            await self.gate.wait()
        return self.candidate or evidence(checkpoint)


class MemoryCheckpointSink:
    def __init__(self, *, fail: bool = False, cancel: bool = False) -> None:
        self.fail = fail
        self.cancel = cancel
        self.items: list[ManagedPathCheckpoint] = []
        self.idempotency_keys: list[str] = []
        self.completed_keys: set[str] = set()

    async def publish(
        self,
        checkpoint: ManagedPathCheckpoint,
        *,
        idempotency_key: str,
    ) -> None:
        self.idempotency_keys.append(idempotency_key)
        if idempotency_key in self.completed_keys:
            return
        self.items.append(checkpoint)
        if self.cancel:
            raise asyncio.CancelledError
        if self.fail:
            raise RuntimeError("正文不得进入稳定结果")
        self.completed_keys.add(idempotency_key)


def repository(
    tmp_path: Path, *, writer_name: str = "phase-one-writer"
) -> FileManagedPathCheckpointRepository:
    return FileManagedPathCheckpointRepository(tmp_path, writer_name=writer_name)


def lifecycle(
    tmp_path: Path,
    *,
    grants: tuple[NetworkAuthorizationGrant, ...] = (),
    refresher: FakeReadOnlyRefresher | None = None,
    sinks: tuple[ManagedPathCheckpointSink, ...] = (),
    clock: datetime = NOW,
) -> tuple[
    ManagedPathPhaseOneLifecycle,
    ProviderSpy,
    MemoryAuthorizationReader,
    FileManagedPathCheckpointRepository,
]:
    provider = ProviderSpy()
    reader = MemoryAuthorizationReader(grants)
    checkpoints = repository(tmp_path)
    return (
        ManagedPathPhaseOneLifecycle(
            provider,  # type: ignore[arg-type]
            ReadOnlyNetworkAuthorizationMatcher(reader),
            checkpoints,
            refresher or FakeReadOnlyRefresher(),
            clock=lambda: clock,
            sinks=sinks,
        ),
        provider,
        reader,
        checkpoints,
    )


def test_state_schema_uses_fixed_codes_and_strict_utc() -> None:
    value = checkpoint()
    assert value.schema_version == 1
    assert ManagedPathEvidenceState().freshness is PathEvidenceFreshness.UNKNOWN
    with pytest.raises(ValidationError):
        ManagedPathEvidenceState.model_validate({"stable_error_code": "198.51.100.8"})
    with pytest.raises(ValidationError):
        ManagedPathCheckpoint.model_validate({**value.model_dump(), "endpoint": "198.51.100.8"})
    with pytest.raises(ValidationError, match="timezone-aware UTC"):
        checkpoint(updated_at=NOW.replace(tzinfo=None))
    with pytest.raises(ValidationError, match="timezone-aware UTC"):
        checkpoint(updated_at=NOW.astimezone(timezone(timedelta(hours=8))))
    with pytest.raises(ValidationError, match="timezone-aware UTC"):
        ManagedPathSelectionState(
            path_type=NetworkPathType.STATIC, selected_at=NOW.replace(tzinfo=None)
        )
    with pytest.raises(ValidationError, match="授权状态"):
        checkpoint(authorization_state="authorized")
    with pytest.raises(ValidationError, match="direct selection"):
        checkpoint(
            selection=ManagedPathSelectionState(path_type=NetworkPathType.DIRECT, selected_at=NOW)
        )


@pytest.mark.parametrize(
    "payload",
    [
        {"source": "fake", "freshness": "unknown"},
        {"source": "none", "freshness": "unknown", "refreshed_at": NOW},
        {"source": "none", "freshness": "fresh"},
        {"source": "fake", "freshness": "fresh"},
        {"endpoint_probe_at": NOW.replace(tzinfo=None)},
    ],
)
def test_evidence_rejects_incomplete_or_naive_state(payload: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        ManagedPathEvidenceState.model_validate(payload)


def test_observed_evidence_requires_refresh_window() -> None:
    value = checkpoint()
    payload = evidence(value).model_dump()
    payload["refreshed_at"] = None
    payload["expires_at"] = None
    with pytest.raises(ValidationError, match="刷新窗口"):
        ManagedPathEvidenceState.model_validate(payload)


def test_evidence_accepts_fixed_error_and_rejects_ttl_boundaries() -> None:
    value = checkpoint()
    valid = evidence(value, stable_error_code=ManagedPathEvidenceErrorCode.ENDPOINT_UNREACHABLE)
    assert valid.stable_error_code is ManagedPathEvidenceErrorCode.ENDPOINT_UNREACHABLE
    with pytest.raises(ValidationError, match="晚于"):
        evidence(value, expires_at=NOW)
    with pytest.raises(ValidationError, match="TTL"):
        evidence(value, expires_at=NOW + timedelta(seconds=181))
    with pytest.raises(ValidationError, match="timezone-aware UTC"):
        evidence(value, refreshed_at=NOW.replace(tzinfo=None))


@pytest.mark.parametrize(
    ("field", "wrong_value"),
    [
        ("network_id", NetworkId.new()),
        ("node_id", NodeId.new()),
        ("revision", 2),
        ("provider", ProviderKind.MACOS),
        ("plan_hash", canonical_sha256({"wrong": "plan"})),
        ("observed_fingerprint", canonical_sha256({"wrong": "observation"})),
        ("authorization_id", AuthorizationId.new()),
    ],
)
def test_parent_checkpoint_rejects_every_nested_evidence_binding_mismatch(
    field: str,
    wrong_value: object,
) -> None:
    parent = checkpoint()
    nested = evidence(parent).model_copy(update={field: wrong_value})
    with pytest.raises(ValidationError, match="绑定不一致"):
        checkpoint(
            evidence=nested,
            selection=ManagedPathSelectionState(
                path_type=NetworkPathType.STATIC,
                selected_at=NOW,
            ),
        )


def test_save_load_and_read_status_revalidate_nested_evidence_binding(tmp_path: Path) -> None:
    repo = repository(tmp_path.resolve())
    parent = checkpoint()
    invalid = parent.model_copy(
        update={
            "evidence": evidence(parent).model_copy(
                update={"plan_hash": canonical_sha256({"wrong": "plan"})}
            )
        }
    )
    with pytest.raises(ManagedPathCheckpointError, match="校验失败"):
        repo.save(invalid)
    repo.path.write_text(
        json.dumps(invalid.model_dump(mode="json")),
        encoding="utf-8",
    )
    with pytest.raises(ManagedPathCheckpointError, match="校验失败"):
        repo.load()
    runtime = ManagedPathPhaseOneLifecycle(
        ProviderSpy(),  # type: ignore[arg-type]
        ReadOnlyNetworkAuthorizationMatcher(MemoryAuthorizationReader()),
        repo,
        FakeReadOnlyRefresher(),
        clock=lambda: NOW,
    )
    with pytest.raises(ManagedPathCheckpointError, match="校验失败"):
        runtime.read_status()


def test_grant_times_require_aware_utc_and_boundary_is_exclusive() -> None:
    with pytest.raises(ValidationError, match="timezone-aware UTC"):
        grant(approved_at=(NOW - timedelta(minutes=1)).replace(tzinfo=None))
    with pytest.raises(ValidationError, match="timezone-aware UTC"):
        grant(expires_at=(NOW + timedelta(minutes=5)).astimezone(timezone(timedelta(hours=8))))
    active = grant(expires_at=NOW)
    assert not active.is_active(at=NOW)


def test_repository_binds_root_and_uses_non_reusable_lifecycle_lease(tmp_path: Path) -> None:
    root = tmp_path.resolve()
    repo = repository(root, writer_name="writer-a")
    assert repo.path == root / MANAGED_PATH_CHECKPOINT_RELATIVE_PATH
    assert repo.load() is None
    with pytest.raises(PermissionError, match="lease"):
        repository(root, writer_name="writer-a")
    with pytest.raises(PermissionError, match="lease"):
        repository(root, writer_name="writer-b")
    repo.close()
    replacement = repository(root, writer_name="writer-a")
    replacement.save(checkpoint())
    assert replacement.load() == checkpoint()
    replacement.close()
    replacement.close()
    with pytest.raises(ManagedPathCheckpointError, match="已关闭"):
        replacement.load()
    with pytest.raises(ManagedPathCheckpointError, match="绝对路径"):
        FileManagedPathCheckpointRepository(Path("relative"), writer_name="writer-a")
    with pytest.raises(ManagedPathCheckpointError, match="固定相对路径"):
        FileManagedPathCheckpointRepository(
            root, writer_name="writer-a", relative_path=Path("../escape")
        )
    with pytest.raises(ManagedPathCheckpointError, match="writer name"):
        FileManagedPathCheckpointRepository(root, writer_name="INVALID WRITER")
    missing = root / "missing"
    with pytest.raises(ManagedPathCheckpointError, match="allowed_root"):
        repository(missing)
    plain_file = root / "plain-file"
    plain_file.write_text("x", encoding="utf-8")
    with pytest.raises(ManagedPathCheckpointError, match="allowed_root"):
        repository(plain_file)


def test_repository_owner_is_enforced_in_another_process(tmp_path: Path) -> None:
    root = tmp_path.resolve()
    owner = repository(root, writer_name="writer-a")
    claim = json.loads((owner.path.parent / ".writer-owner.json").read_text(encoding="utf-8"))
    assert claim["writer_name"] == "writer-a"
    assert claim["process_id"] == os.getpid()
    assert len(claim["lease_nonce"]) == 64
    assert len(claim["process_start_nonce"]) == 64
    script = (
        "import json,sys; from pathlib import Path; "
        "from tunnelminion.network.managed_path_runtime "
        "import FileManagedPathCheckpointRepository; "
        "\ntry:\n "
        f" FileManagedPathCheckpointRepository(Path({str(root)!r}), writer_name='writer-a')\n"
        "except PermissionError:\n print(json.dumps({'error':'lease-held'})); sys.exit(17)\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", script],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 17
    assert json.loads(result.stdout) == {"error": "lease-held"}


def test_crashed_process_owner_claim_remains_fail_closed(tmp_path: Path) -> None:
    root = tmp_path.resolve()
    script = (
        "from pathlib import Path; "
        "from tunnelminion.network.managed_path_runtime "
        "import FileManagedPathCheckpointRepository; "
        f"FileManagedPathCheckpointRepository(Path({str(root)!r}), writer_name='writer-a')"
    )
    result = subprocess.run(
        [sys.executable, "-c", script],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    with pytest.raises(PermissionError, match="lease"):
        repository(root, writer_name="writer-a")


def test_repository_lock_covers_owner_validation_and_save(tmp_path: Path) -> None:
    repo = repository(tmp_path.resolve(), writer_name="writer-a")
    lock_path = repo.path.parent / ".writer-lock.sqlite3"
    repo.load()
    connection = sqlite3.connect(lock_path, timeout=0, isolation_level=None)
    connection.execute("BEGIN EXCLUSIVE")
    try:
        with pytest.raises(ManagedPathCheckpointError, match="正忙"):
            repo.save(checkpoint())
    finally:
        connection.rollback()
        connection.close()
    repo.save(checkpoint(revision=2))
    assert repo.load() == checkpoint(revision=2)


def test_repository_random_temp_cleanup_and_previous_state_survives(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = repository(tmp_path.resolve())
    original = checkpoint()
    repo.save(original)

    def fail_replace(_source: object, _target: object) -> None:
        raise OSError("crash")

    monkeypatch.setattr("tunnelminion.network.managed_path_runtime.os.replace", fail_replace)
    with pytest.raises(OSError, match="crash"):
        repo.save(checkpoint(revision=2))
    assert repo.load() == original
    assert not tuple(repo.path.parent.glob("*.tmp"))


def _create_symlink_or_skip(link: Path, target: Path, *, directory: bool = False) -> None:
    try:
        link.symlink_to(target, target_is_directory=directory)
    except OSError as exc:
        pytest.skip(f"当前平台不允许创建反例符号链接: {exc.winerror or exc.errno}")


def test_repository_rejects_real_parent_reparse_point(tmp_path: Path) -> None:
    root = tmp_path.resolve()
    outside = root / "outside"
    outside.mkdir()
    parent_link_root = root / "parent-link-root"
    parent_link_root.mkdir()
    _create_symlink_or_skip(parent_link_root / "managed-path", outside, directory=True)
    with pytest.raises(ManagedPathCheckpointError, match="父级"):
        repository(parent_link_root)


def test_repository_rejects_real_target_reparse_point(tmp_path: Path) -> None:
    root = tmp_path.resolve()
    state_dir = root / "managed-path"
    state_dir.mkdir()
    outside = root / "outside.json"
    outside.write_text("sentinel", encoding="utf-8")
    _create_symlink_or_skip(state_dir / "checkpoint.json", outside)
    with pytest.raises(ManagedPathCheckpointError, match="reparse"):
        repository(root)
    assert outside.read_text(encoding="utf-8") == "sentinel"


def test_exclusive_open_rejects_real_temp_reparse_without_touching_target(tmp_path: Path) -> None:
    root = tmp_path.resolve()
    repo = repository(root)
    outside = root / "outside.json"
    outside.write_text("sentinel", encoding="utf-8")
    malicious_temp = repo.path.parent / ".checkpoint.json.attacker.tmp"
    _create_symlink_or_skip(malicious_temp, outside)
    with pytest.raises((FileExistsError, ManagedPathCheckpointError)):
        repo._open_exclusive_regular(  # pyright: ignore[reportPrivateUsage]
            malicious_temp
        )
    assert outside.read_text(encoding="utf-8") == "sentinel"
    assert malicious_temp.is_symlink()


def test_exclusive_open_rejects_real_directory_reparse_point(tmp_path: Path) -> None:
    root = tmp_path.resolve()
    repo = repository(root)
    outside = root / "outside"
    outside.mkdir()
    malicious_temp = repo.path.parent / ".checkpoint.json.attacker-dir.tmp"
    _create_symlink_or_skip(malicious_temp, outside, directory=True)
    with pytest.raises((FileExistsError, IsADirectoryError, ManagedPathCheckpointError)):
        repo._open_exclusive_regular(  # pyright: ignore[reportPrivateUsage]
            malicious_temp
        )


def test_save_revalidates_random_temp_identity_before_replace(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path.resolve()
    repo = repository(root)
    original = repo._require_regular_identity  # pyright: ignore[reportPrivateUsage]
    calls = 0

    def reject_changed_identity(path: Path, expected: os.stat_result) -> None:
        nonlocal calls
        calls += 1
        if path.suffix == ".tmp":
            raise ManagedPathCheckpointError("临时文件身份或 reparse 状态已变化")
        original(path, expected)

    monkeypatch.setattr(repo, "_require_regular_identity", reject_changed_identity)
    with pytest.raises(ManagedPathCheckpointError, match="身份"):
        repo.save(checkpoint())
    assert repo.load() is None


def test_repository_rejects_non_regular_paths_and_changed_owner(tmp_path: Path) -> None:
    root = tmp_path.resolve()
    state_dir = root / "managed-path"
    state_dir.mkdir()
    (state_dir / "checkpoint.json").mkdir()
    with pytest.raises(ManagedPathCheckpointError, match="普通文件"):
        repository(root)
    os.rmdir(state_dir / "checkpoint.json")
    repo = repository(root)
    (state_dir / ".writer-owner.json").write_text('{"writer_name":"other"}', encoding="utf-8")
    with pytest.raises(PermissionError, match="lease"):
        repo.load()


def test_repository_defensive_path_resolution_checks(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    alias_root = tmp_path.resolve() / "alias-root"
    alias_root.mkdir()
    original_resolve = Path.resolve

    def alias_resolve(path: Path, strict: bool = False) -> Path:
        if path == alias_root:
            return alias_root.parent
        return original_resolve(path, strict=strict)

    monkeypatch.setattr(Path, "resolve", alias_resolve)
    with pytest.raises(ManagedPathCheckpointError, match="路径别名"):
        repository(alias_root)

    monkeypatch.undo()
    escaped_root = tmp_path.resolve() / "escaped-root"
    escaped_root.mkdir()

    def escaped_resolve(path: Path, strict: bool = False) -> Path:
        if path == escaped_root / "managed-path":
            return escaped_root.parent / "outside" / "managed-path"
        return original_resolve(path, strict=strict)

    monkeypatch.setattr(Path, "resolve", escaped_resolve)
    with pytest.raises(ManagedPathCheckpointError, match="逃逸"):
        repository(escaped_root)


def test_repository_defensive_stat_and_handle_checks(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path.resolve()
    missing = root / "missing"
    with pytest.raises(ManagedPathCheckpointError, match="父级无法读取"):
        FileManagedPathCheckpointRepository._require_directory(  # pyright: ignore[reportPrivateUsage]
            missing
        )
    plain = root / "plain"
    plain.write_text("x", encoding="utf-8")
    with pytest.raises(ManagedPathCheckpointError, match="父级"):
        FileManagedPathCheckpointRepository._require_directory(  # pyright: ignore[reportPrivateUsage]
            plain
        )

    original_stat = Path.stat

    def denied_stat(path: Path, *, follow_symlinks: bool = True) -> os.stat_result:
        del path, follow_symlinks
        raise PermissionError("denied")

    monkeypatch.setattr(Path, "stat", denied_stat)
    with pytest.raises(ManagedPathCheckpointError, match="路径无法读取"):
        FileManagedPathCheckpointRepository._require_safe_optional_file(  # pyright: ignore[reportPrivateUsage]
            plain
        )
    monkeypatch.setattr(Path, "stat", original_stat)

    class ReparseMetadata:
        st_mode = stat.S_IFREG
        st_file_attributes = 0x400

    def reparse_stat(path: Path, *, follow_symlinks: bool = True) -> os.stat_result:
        del path, follow_symlinks
        return cast(os.stat_result, ReparseMetadata())

    monkeypatch.setattr(Path, "stat", reparse_stat)
    with pytest.raises(ManagedPathCheckpointError, match="reparse"):
        FileManagedPathCheckpointRepository._require_safe_optional_file(  # pyright: ignore[reportPrivateUsage]
            plain
        )
    monkeypatch.setattr(Path, "stat", original_stat)

    descriptor = os.open(plain, os.O_RDONLY)
    try:

        def different_files(_left: os.stat_result, _right: os.stat_result) -> bool:
            return False

        monkeypatch.setattr(
            "tunnelminion.network.managed_path_runtime.os.path.samestat",
            different_files,
        )
        with pytest.raises(ManagedPathCheckpointError, match="句柄指向"):
            FileManagedPathCheckpointRepository._validate_open_regular(  # pyright: ignore[reportPrivateUsage]
                descriptor,
                plain,
            )
    finally:
        os.close(descriptor)

    other = root / "other"
    other.write_text("y", encoding="utf-8")
    with pytest.raises(ManagedPathCheckpointError, match="身份"):
        FileManagedPathCheckpointRepository._require_regular_identity(  # pyright: ignore[reportPrivateUsage]
            plain,
            other.stat(),
        )


def test_repository_closes_exclusive_handle_when_validation_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path.resolve() / "exclusive"

    def reject_handle(
        _cls: type[FileManagedPathCheckpointRepository],
        _descriptor: int,
        _path: Path,
    ) -> os.stat_result:
        raise ManagedPathCheckpointError("安全文件句柄无法验证")

    monkeypatch.setattr(
        FileManagedPathCheckpointRepository,
        "_validate_open_regular",
        classmethod(reject_handle),
    )
    with pytest.raises(ManagedPathCheckpointError, match="句柄无法验证"):
        FileManagedPathCheckpointRepository._open_exclusive_regular(  # pyright: ignore[reportPrivateUsage]
            path
        )
    path.unlink()


def test_repository_wraps_open_handle_stat_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path.resolve() / "plain"
    path.write_text("x", encoding="utf-8")
    descriptor = os.open(path, os.O_RDONLY)

    def denied_stat(value: Path, *, follow_symlinks: bool = True) -> os.stat_result:
        del value, follow_symlinks
        raise PermissionError("denied")

    monkeypatch.setattr(Path, "stat", denied_stat)
    try:
        with pytest.raises(ManagedPathCheckpointError, match="句柄无法验证"):
            FileManagedPathCheckpointRepository._validate_open_regular(  # pyright: ignore[reportPrivateUsage]
                descriptor,
                path,
            )
    finally:
        os.close(descriptor)


def test_repository_closes_temp_descriptor_if_stream_creation_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = repository(tmp_path.resolve())

    def fail_fdopen(*_args: object, **_kwargs: object) -> Any:
        raise OSError("fdopen failed")

    monkeypatch.setattr("tunnelminion.network.managed_path_runtime.os.fdopen", fail_fdopen)
    with pytest.raises(OSError, match="fdopen failed"):
        repo.save(checkpoint())


def test_directory_fsync_success_path_is_platform_independent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, int]] = []

    def open_directory(_path: os.PathLike[str] | str, _flags: int) -> int:
        return 91

    def fsync_directory(descriptor: int) -> None:
        calls.append(("fsync", descriptor))

    def close_directory(descriptor: int) -> None:
        calls.append(("close", descriptor))

    monkeypatch.setattr("tunnelminion.network.managed_path_runtime.os.open", open_directory)
    monkeypatch.setattr("tunnelminion.network.managed_path_runtime.os.fsync", fsync_directory)
    monkeypatch.setattr("tunnelminion.network.managed_path_runtime.os.close", close_directory)
    FileManagedPathCheckpointRepository._fsync_directory(  # pyright: ignore[reportPrivateUsage]
        tmp_path.resolve()
    )
    assert calls == [("fsync", 91), ("close", 91)]


def test_repository_rejects_corrupt_owner_claim_at_open_and_load(tmp_path: Path) -> None:
    first_root = tmp_path.resolve() / "first"
    first_root.mkdir()
    first_state = first_root / "managed-path"
    first_state.mkdir()
    (first_state / ".writer-owner.json").write_text("{", encoding="utf-8")
    with pytest.raises(PermissionError, match="lease"):
        repository(first_root)

    second_root = tmp_path.resolve() / "second"
    second_root.mkdir()
    repo = repository(second_root)
    repo._owner_path.write_text("{", encoding="utf-8")  # pyright: ignore[reportPrivateUsage]
    with pytest.raises(ManagedPathCheckpointError, match="owner claim"):
        repo.load()


@pytest.mark.parametrize(
    ("content", "message"),
    [
        ("not-json", "无法读取"),
        ("[]", "结构无效"),
        ('{"network_id":"legacy"}', "缺少 schema"),
        ('{"schema_version":99}', "schema 不受支持"),
        ('{"schema_version":1}', "校验失败"),
    ],
)
def test_repository_corruption_fails_closed_and_can_recover(
    tmp_path: Path,
    content: str,
    message: str,
) -> None:
    repo = repository(tmp_path.resolve())
    repo.path.write_text(content, encoding="utf-8")
    with pytest.raises(ManagedPathCheckpointError, match=message):
        repo.load()
    repo.save(checkpoint())
    assert repo.load() == checkpoint()


def test_repository_legacy_state_never_infers_path(tmp_path: Path) -> None:
    repo = repository(tmp_path.resolve())
    repo.path.write_text('{"phase":"idle","applied_revision":1}', encoding="utf-8")
    assert repo.load() is None


@pytest.mark.parametrize(
    "key",
    [
        "private_key",
        "PrIvAtE-Key",
        "\uff30\uff32\uff29\uff36\uff21\uff34\uff25\uff3f\uff2b\uff25\uff39",
        "%70%72%69%76%61%74%65%5f%6b%65%79",
        "nestedToken",
    ],
)
def test_secret_scan_rejects_key_case_encoding_and_boundaries(tmp_path: Path, key: str) -> None:
    repo = repository(tmp_path.resolve())
    payload = checkpoint().model_dump(mode="json")
    payload["selection"] = {"nested": {key: "never-echo-this-secret"}}
    repo.path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ManagedPathCheckpointError) as error:
        repo.assert_no_secret_material()
    assert "never-echo-this-secret" not in str(error.value)


@pytest.mark.parametrize(
    "secret",
    [
        "Bearer never-echo-this-secret",
        "refresh_credential=never-echo-this-secret",
        base64.b64encode(b"preshared_key=never-echo-this-secret").decode(),
        "%70%73%6b=never-echo-this-secret",
    ],
)
def test_secret_scan_rejects_encoded_nested_values_without_echo(
    tmp_path: Path, secret: str
) -> None:
    repo = repository(tmp_path.resolve())
    payload = checkpoint().model_dump(mode="json")
    payload["selection"] = {"path_type": "static", "selected_at": secret}
    repo.path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ManagedPathCheckpointError) as error:
        repo.assert_no_secret_material()
    assert "never-echo-this-secret" not in str(error.value)


def test_secret_scan_rejects_invalid_json_and_non_object(tmp_path: Path) -> None:
    repo = repository(tmp_path.resolve())
    repo.assert_no_secret_material()
    for content in ("{", "[]"):
        repo.path.write_text(content, encoding="utf-8")
        with pytest.raises(ManagedPathCheckpointError):
            repo.assert_no_secret_material()


def test_secret_scan_accepts_valid_state_and_rejects_schema_and_nested_list(tmp_path: Path) -> None:
    repo = repository(tmp_path.resolve())
    repo.save(checkpoint())
    repo.assert_no_secret_material()
    payload = checkpoint().model_dump(mode="json")
    payload["selection"] = [{"stable_error_code": "Bearer never-echo-this-secret"}]
    repo.path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ManagedPathCheckpointError, match="禁止正文"):
        repo.assert_no_secret_material()
    payload["selection"] = {"path_type": "static", "selected_at": "x" * 4097}
    repo.path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ManagedPathCheckpointError, match="校验失败"):
        repo.assert_no_secret_material()


def test_authorization_matcher_is_exact_and_fail_closed() -> None:
    active = grant()
    cases = (
        ((), ManagedPathPhaseOneErrorCode.LOCAL_L3_APPROVAL_REQUIRED),
        (
            (active.model_copy(update={"revoked_at": NOW}),),
            ManagedPathPhaseOneErrorCode.LOCAL_L3_APPROVAL_REVOKED,
        ),
        (
            (grant(approved_at=NOW + timedelta(minutes=1), expires_at=NOW + timedelta(minutes=2)),),
            ManagedPathPhaseOneErrorCode.LOCAL_L3_APPROVAL_NOT_YET_VALID,
        ),
        (
            (grant(approved_at=NOW - timedelta(minutes=2), expires_at=NOW),),
            ManagedPathPhaseOneErrorCode.LOCAL_L3_APPROVAL_EXPIRED,
        ),
        (
            (
                active.model_copy(
                    update={
                        "scope": active.scope.model_copy(
                            update={"plan_hash": canonical_sha256({"other": "plan"})}
                        )
                    }
                ),
            ),
            ManagedPathPhaseOneErrorCode.LOCAL_L3_SCOPE_MISMATCH,
        ),
    )
    for grants, expected in cases:
        result = ReadOnlyNetworkAuthorizationMatcher(MemoryAuthorizationReader(grants)).evaluate(
            TEST_PLAN, at=NOW
        )
        assert result.state is PathAuthorizationState.AWAITING_AUTHORIZATION
        assert result.code is expected
    matched = ReadOnlyNetworkAuthorizationMatcher(MemoryAuthorizationReader((active,))).evaluate(
        TEST_PLAN, at=NOW
    )
    assert matched.authorization_id == active.authorization_id
    with pytest.raises(ValueError, match="timezone-aware UTC"):
        ReadOnlyNetworkAuthorizationMatcher(MemoryAuthorizationReader()).evaluate(
            TEST_PLAN, at=NOW.replace(tzinfo=None)
        )
    with pytest.raises(ValidationError, match="授权匹配"):
        NetworkAuthorizationMatch(
            state=PathAuthorizationState.AUTHORIZED,
            code=ManagedPathPhaseOneErrorCode.PROVIDER_EXECUTION_DISABLED,
        )


@pytest.mark.anyio
async def test_pending_without_authorization_persists_and_never_touches_provider(
    tmp_path: Path,
) -> None:
    good_sink = MemoryCheckpointSink()
    bad_sink = MemoryCheckpointSink(fail=True)
    runtime, provider, reader, repo = lifecycle(tmp_path.resolve(), sinks=(good_sink, bad_sink))
    result = await runtime.stage_pending(envelope(TEST_PLAN), TEST_PLAN, at=NOW)
    assert result.code is ManagedPathOperationCode.PERSISTED_WITH_SINK_FAILURES
    assert result.persisted
    assert result.checkpoint is not None
    assert result.checkpoint.authorization_state is PathAuthorizationState.AWAITING_AUTHORIZATION
    assert result.sink_failures[0].sink_index == 1
    assert repo.load() == result.checkpoint
    assert good_sink.items == [result.checkpoint]
    assert reader.reads == [(NETWORK_ID, NODE_A)]
    assert provider.calls == []


@pytest.mark.anyio
async def test_sink_cancellation_reports_persisted_delivery_states_and_idempotent_retry(
    tmp_path: Path,
) -> None:
    succeeded = MemoryCheckpointSink()
    cancelled = MemoryCheckpointSink(cancel=True)
    trailing = MemoryCheckpointSink()
    runtime, provider, _, repo = lifecycle(
        tmp_path.resolve(),
        sinks=(succeeded, cancelled, trailing),
    )
    with pytest.raises(ManagedPathPublicationCancelled) as captured:
        await runtime.stage_pending(envelope(TEST_PLAN), TEST_PLAN, at=NOW)
    result = captured.value.result
    assert result.persisted
    assert result.publication_id is not None
    assert [delivery.state for delivery in result.sink_deliveries] == [
        ManagedPathSinkDeliveryState.SUCCEEDED,
        ManagedPathSinkDeliveryState.UNKNOWN,
        ManagedPathSinkDeliveryState.NOT_ATTEMPTED,
    ]
    assert repo.load() == result.checkpoint
    assert "正文" not in str(captured.value)
    assert provider.calls == []

    cancelled.cancel = False
    retried = await runtime.stage_pending(envelope(TEST_PLAN), TEST_PLAN, at=NOW)
    assert retried.publication_id == result.publication_id
    assert succeeded.items == [result.checkpoint]
    assert succeeded.idempotency_keys == [result.publication_id, result.publication_id]
    assert trailing.items == [result.checkpoint]
    assert provider.calls == []


@pytest.mark.anyio
async def test_task_cancellation_preserves_persisted_publication_result(tmp_path: Path) -> None:
    started = asyncio.Event()
    release = asyncio.Event()

    class BlockingSink:
        async def publish(
            self,
            checkpoint: ManagedPathCheckpoint,
            *,
            idempotency_key: str,
        ) -> None:
            del checkpoint, idempotency_key
            started.set()
            await release.wait()

    runtime, _, _, repo = lifecycle(tmp_path.resolve(), sinks=(BlockingSink(),))
    task = asyncio.create_task(runtime.stage_pending(envelope(TEST_PLAN), TEST_PLAN, at=NOW))
    await started.wait()
    task.cancel()
    with pytest.raises(ManagedPathPublicationCancelled) as captured:
        await task
    result = captured.value.result
    assert result.persisted
    assert result.sink_deliveries[0].state is ManagedPathSinkDeliveryState.UNKNOWN
    assert repo.load() == result.checkpoint


@pytest.mark.anyio
async def test_sink_system_exit_is_not_blindly_caught(tmp_path: Path) -> None:
    class TerminatingSink:
        async def publish(
            self,
            checkpoint: ManagedPathCheckpoint,
            *,
            idempotency_key: str,
        ) -> None:
            del checkpoint, idempotency_key
            raise SystemExit(7)

    runtime, _, _, repo = lifecycle(tmp_path.resolve(), sinks=(TerminatingSink(),))
    with pytest.raises(SystemExit) as captured:
        await runtime.stage_pending(envelope(TEST_PLAN), TEST_PLAN, at=NOW)
    assert captured.value.code == 7
    assert repo.load() is not None


@pytest.mark.anyio
async def test_authorized_pending_still_never_touches_provider(tmp_path: Path) -> None:
    runtime, provider, _, _ = lifecycle(tmp_path.resolve(), grants=(grant(),))
    result = await runtime.stage_pending(envelope(TEST_PLAN), TEST_PLAN, at=NOW)
    assert result.code is ManagedPathOperationCode.PERSISTED
    assert result.checkpoint is not None
    assert result.checkpoint.authorization_state is PathAuthorizationState.AUTHORIZED
    assert provider.calls == []
    wrong = envelope(TEST_PLAN).model_copy(update={"config": desired(revision=2)})
    with pytest.raises(ValueError, match="不一致"):
        await runtime.stage_pending(wrong, TEST_PLAN, at=NOW)
    assert provider.calls == []


@pytest.mark.anyio
async def test_read_status_has_no_authorization_refresh_or_provider_side_effect(
    tmp_path: Path,
) -> None:
    refresher = FakeReadOnlyRefresher()
    runtime, provider, reader, _ = lifecycle(tmp_path.resolve(), refresher=refresher)
    staged = await runtime.stage_pending(envelope(TEST_PLAN), TEST_PLAN, at=NOW)
    reads = len(reader.reads)
    assert runtime.read_status() == staged.checkpoint
    assert len(reader.reads) == reads
    assert refresher.calls == 0
    assert provider.calls == []


@pytest.mark.anyio
async def test_refresh_is_coalesced_validated_but_never_committed(tmp_path: Path) -> None:
    gate = asyncio.Event()
    refresher = FakeReadOnlyRefresher(gate=gate)
    runtime, provider, reader, repo = lifecycle(tmp_path.resolve(), refresher=refresher)
    empty = await runtime.refresh()
    assert empty.code is ManagedPathOperationCode.NO_CHECKPOINT
    staged = await runtime.stage_pending(envelope(TEST_PLAN), TEST_PLAN, at=NOW)
    reads = len(reader.reads)
    first = asyncio.create_task(runtime.refresh())
    second = asyncio.create_task(runtime.refresh())
    while refresher.calls == 0:
        await asyncio.sleep(0)
    gate.set()
    first_result, second_result = await asyncio.gather(first, second)
    assert first_result == second_result
    assert first_result.code is ManagedPathOperationCode.REFRESH_NOT_COMMITTED
    assert not first_result.evidence_accepted
    assert repo.load() == staged.checkpoint
    assert len(reader.reads) == reads
    assert provider.calls == []


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("candidate_update", "clock", "expected"),
    [
        (
            {"plan_hash": canonical_sha256({"wrong": True})},
            NOW,
            ManagedPathOperationCode.REFRESH_REJECTED_BINDING,
        ),
        (
            {
                "refreshed_at": NOW - timedelta(seconds=1),
                "expires_at": NOW + timedelta(seconds=179),
            },
            NOW,
            ManagedPathOperationCode.REFRESH_REJECTED_TIME,
        ),
        (
            {
                "refreshed_at": NOW + timedelta(seconds=1),
                "expires_at": NOW + timedelta(seconds=181),
            },
            NOW,
            ManagedPathOperationCode.REFRESH_REJECTED_TIME,
        ),
        (
            {
                "refreshed_at": NOW - timedelta(seconds=2),
                "expires_at": NOW - timedelta(seconds=1),
            },
            NOW,
            ManagedPathOperationCode.REFRESH_REJECTED_TIME,
        ),
    ],
)
async def test_refresh_rejects_binding_old_future_and_expired_evidence(
    tmp_path: Path,
    candidate_update: dict[str, object],
    clock: datetime,
    expected: ManagedPathOperationCode,
) -> None:
    base = checkpoint()
    candidate_values = evidence(base).model_dump()
    candidate_values.update(candidate_update)
    candidate = ManagedPathEvidenceState.model_validate(candidate_values)
    refresher = FakeReadOnlyRefresher(candidate)
    runtime, provider, _, repo = lifecycle(tmp_path.resolve(), refresher=refresher, clock=clock)
    await runtime.stage_pending(envelope(TEST_PLAN), TEST_PLAN, at=NOW)
    before = repo.load()
    result = await runtime.refresh()
    assert result.code is expected
    assert repo.load() == before
    assert provider.calls == []


@pytest.mark.anyio
async def test_refresh_rejects_regression_against_existing_evidence(tmp_path: Path) -> None:
    current = checkpoint(
        evidence=evidence(checkpoint(), refreshed_at=NOW, expires_at=NOW + timedelta(seconds=180))
    )
    older = evidence(
        current, refreshed_at=NOW - timedelta(seconds=1), expires_at=NOW + timedelta(seconds=179)
    )
    runtime, provider, _, repo = lifecycle(
        tmp_path.resolve(), refresher=FakeReadOnlyRefresher(older), clock=NOW
    )
    repo.save(current)
    result = await runtime.refresh()
    assert result.code is ManagedPathOperationCode.REFRESH_REJECTED_TIME
    assert repo.load() == current
    assert provider.calls == []


@pytest.mark.anyio
async def test_refresh_rejects_same_observation_time_ttl_extension_replay(tmp_path: Path) -> None:
    base = checkpoint()
    current = checkpoint(
        evidence=evidence(
            base,
            refreshed_at=NOW - timedelta(seconds=30),
            expires_at=NOW + timedelta(seconds=120),
        )
    )
    replay = evidence(
        current,
        refreshed_at=NOW - timedelta(seconds=30),
        expires_at=NOW + timedelta(seconds=150),
    )
    runtime, provider, _, repo = lifecycle(
        tmp_path.resolve(),
        refresher=FakeReadOnlyRefresher(replay),
        clock=NOW,
    )
    repo.save(current)
    result = await runtime.refresh()
    assert result.code is ManagedPathOperationCode.REFRESH_REJECTED_TIME
    assert repo.load() == current
    assert provider.calls == []


@pytest.mark.anyio
async def test_refresh_defensively_rejects_constructed_candidate_without_window(
    tmp_path: Path,
) -> None:
    value = checkpoint()
    candidate = evidence(value).model_copy(update={"refreshed_at": None, "expires_at": None})
    runtime, provider, _, repo = lifecycle(
        tmp_path.resolve(),
        refresher=FakeReadOnlyRefresher(candidate),
    )
    repo.save(value)
    result = await runtime.refresh()
    assert result.code is ManagedPathOperationCode.REFRESH_REJECTED_TIME
    assert repo.load() == value
    assert provider.calls == []


def test_refresh_clock_must_be_utc(tmp_path: Path) -> None:
    runtime, _, _, repo = lifecycle(tmp_path.resolve(), clock=NOW.replace(tzinfo=None))
    repo.save(checkpoint())
    with pytest.raises(ValueError, match="timezone-aware UTC"):
        run(runtime.refresh())
