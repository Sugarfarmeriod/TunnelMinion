"""受管路径阶段一状态、持久 owner 与零 Provider 写入测试。"""

from __future__ import annotations

import asyncio
import base64
import errno
import json
import os
import subprocess
import sys
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Never

import pytest
from pydantic import ValidationError
from tests.network.factories import NETWORK_ID, NODE_A, NOW, desired, observation

from tunnelminion.domain.identifiers import AuthorizationId, NetworkId, NodeId
from tunnelminion.network import managed_path_runtime as runtime_module
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
    with pytest.raises(ValidationError, match="publication identity"):
        checkpoint(sink_delivery_states=(ManagedPathSinkDeliveryState.NOT_ATTEMPTED,))


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
    repo.load()
    with (
        repo._trusted.lock(repo._lock_name),  # pyright: ignore[reportPrivateUsage]
        pytest.raises(ManagedPathCheckpointError, match="正忙"),
    ):
        repo.save(checkpoint())
    repo.save(checkpoint(revision=2))
    assert repo.load() == checkpoint(revision=2)


def test_repository_random_temp_cleanup_and_previous_state_survives(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = repository(tmp_path.resolve())
    original = checkpoint()
    repo.save(original)

    def fail_replace(_descriptor: int, _source: str, _target: str) -> None:
        raise OSError("crash")

    monkeypatch.setattr(repo._trusted, "replace_open_file", fail_replace)  # pyright: ignore[reportPrivateUsage]
    with pytest.raises(OSError, match="crash"):
        repo.save(checkpoint(revision=2))
    assert repo.load() == original
    assert not tuple(repo.path.parent.glob("*.tmp"))


def _create_symlink_or_skip(link: Path, target: Path, *, directory: bool = False) -> None:
    try:
        link.symlink_to(target, target_is_directory=directory)
    except OSError as exc:
        error_code = getattr(exc, "winerror", None) or exc.errno
        pytest.skip(f"当前平台不允许创建反例符号链接: {error_code}")


def test_repository_rejects_real_parent_reparse_point(tmp_path: Path) -> None:
    root = tmp_path.resolve()
    outside = root / "outside"
    outside.mkdir()
    parent_link_root = root / "parent-link-root"
    parent_link_root.mkdir()
    _create_symlink_or_skip(parent_link_root / "managed-path", outside, directory=True)
    with pytest.raises(ManagedPathCheckpointError, match="可信.*目录"):
        repository(parent_link_root)


def test_repository_rejects_real_target_reparse_point(tmp_path: Path) -> None:
    root = tmp_path.resolve()
    state_dir = root / "managed-path"
    state_dir.mkdir()
    outside = root / "outside.json"
    outside.write_text("sentinel", encoding="utf-8")
    _create_symlink_or_skip(state_dir / "checkpoint.json", outside)
    with pytest.raises(ManagedPathCheckpointError, match="可信文件"):
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
        repo._trusted.open_file(  # pyright: ignore[reportPrivateUsage]
            malicious_temp.name,
            create=True,
            writable=True,
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
        repo._trusted.open_file(  # pyright: ignore[reportPrivateUsage]
            malicious_temp.name,
            create=True,
            writable=True,
        )


def test_save_binds_replace_to_trusted_directory_during_directory_swap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path.resolve()
    repo = repository(root)
    state_dir = repo.path.parent
    moved = root / "trusted-managed-path"
    outside = root / "outside"
    outside.mkdir()
    sentinel = outside / "checkpoint.json"
    sentinel.write_text("sentinel", encoding="utf-8")
    swapped = False

    def swap_directory(boundary: str) -> None:
        nonlocal swapped
        if boundary != "before_checkpoint_replace":
            return
        try:
            state_dir.rename(moved)
        except OSError:
            return
        state_dir.symlink_to(outside, target_is_directory=True)
        swapped = True

    monkeypatch.setattr(repo, "_on_io_boundary", swap_directory)
    if os.name == "nt":
        repo.save(checkpoint())
        assert not swapped
        assert repo.load() == checkpoint()
    else:
        with pytest.raises(ManagedPathCheckpointError, match="公开身份已变化"):
            repo.save(checkpoint())
        assert swapped
    assert sentinel.read_text(encoding="utf-8") == "sentinel"


@pytest.mark.parametrize(
    "boundary",
    [
        "before_writer_lock",
        "before_lease_read",
        "before_checkpoint_read",
        "before_secret_scan_read",
    ],
)
def test_read_lease_lock_and_secret_scan_fail_closed_on_directory_swap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    boundary: str,
) -> None:
    root = tmp_path.resolve()
    repo = repository(root)
    repo.save(checkpoint())
    state_dir = repo.path.parent
    moved = root / "trusted-managed-path"
    outside = root / "outside"
    outside.mkdir()
    sentinel = outside / "checkpoint.json"
    sentinel.write_text("sentinel", encoding="utf-8")
    swapped = False

    def swap_directory(current: str) -> None:
        nonlocal swapped
        if current != boundary or swapped:
            return
        try:
            state_dir.rename(moved)
        except OSError:
            return
        state_dir.symlink_to(outside, target_is_directory=True)
        swapped = True

    monkeypatch.setattr(repo, "_on_io_boundary", swap_directory)
    operation = (
        repo.assert_no_secret_material if boundary == "before_secret_scan_read" else repo.load
    )
    if os.name == "nt":
        operation()
        assert not swapped
    else:
        with pytest.raises(ManagedPathCheckpointError, match="公开身份已变化"):
            operation()
        assert swapped
    assert sentinel.read_text(encoding="utf-8") == "sentinel"


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


def test_repository_defensive_stat_and_handle_checks(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    del monkeypatch
    repo = repository(tmp_path.resolve())
    with pytest.raises(ManagedPathCheckpointError, match="单层文件名"):
        repo._trusted.open_file("../escape")  # pyright: ignore[reportPrivateUsage]
    repo._trusted.close()  # pyright: ignore[reportPrivateUsage]
    with pytest.raises(ManagedPathCheckpointError, match="可信目录句柄已关闭"):
        repo.load()


def test_repository_closes_exclusive_handle_when_validation_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = repository(tmp_path.resolve())

    def no_progress(_descriptor: int, _payload: object) -> int:
        return 0

    monkeypatch.setattr("tunnelminion.network.managed_path_runtime.os.write", no_progress)
    with pytest.raises(ManagedPathCheckpointError, match="未取得进展"):
        repo.save(checkpoint())
    assert not tuple(repo.path.parent.glob("*.tmp"))


def test_repository_directory_fsync_open_failure_is_fail_safe(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = repository(tmp_path.resolve())

    def denied_fsync(_descriptor: int) -> None:
        raise PermissionError("denied")

    monkeypatch.setattr("tunnelminion.network.managed_path_runtime.os.fsync", denied_fsync)
    with pytest.raises(ManagedPathCheckpointError, match="文件无法持久化"):
        repo.save(checkpoint())
    assert not tuple(repo.path.parent.glob("*.tmp"))


def test_repository_wraps_open_handle_stat_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = repository(tmp_path.resolve())
    original = repo._trusted.replace_open_file  # pyright: ignore[reportPrivateUsage]

    def fail_after_replace(descriptor: int, source: str, target: str) -> None:
        original(descriptor, source, target)
        raise ManagedPathCheckpointError("checkpoint 目录元数据无法持久化")

    monkeypatch.setattr(repo._trusted, "replace_open_file", fail_after_replace)  # pyright: ignore[reportPrivateUsage]
    with pytest.raises(ManagedPathCheckpointError, match="元数据无法持久化"):
        repo.save(checkpoint())
    assert repo.load() == checkpoint()


def test_repository_closes_temp_descriptor_if_stream_creation_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = repository(tmp_path.resolve())

    def fail_write(_descriptor: int, _payload: object) -> int:
        raise OSError("write failed")

    monkeypatch.setattr("tunnelminion.network.managed_path_runtime.os.write", fail_write)
    with pytest.raises(OSError, match="write failed"):
        repo.save(checkpoint())


def test_directory_fsync_success_path_is_platform_independent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    del monkeypatch
    repo = repository(tmp_path.resolve())
    repo.save(checkpoint())
    assert repo.load() == checkpoint()


def test_owner_claim_metadata_failure_cleans_partial_claim(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    trusted_type = runtime_module.__dict__["_TrustedDirectory"]
    original_sync = trusted_type.sync_metadata
    sync_count = 0

    def fail_claim_sync(instance: Any, descriptor: int | None = None) -> None:
        nonlocal sync_count
        sync_count += 1
        if sync_count == 2:
            raise ManagedPathCheckpointError("owner claim 元数据无法持久化")
        original_sync(instance, descriptor)

    monkeypatch.setattr(trusted_type, "sync_metadata", fail_claim_sync)
    root = tmp_path.resolve()
    with pytest.raises(ManagedPathCheckpointError, match="owner claim 元数据无法持久化"):
        repository(root)
    assert not (root / "managed-path" / ".writer-owner.json").exists()


def test_uninitialized_repository_has_no_trusted_directory() -> None:
    repository_type = FileManagedPathCheckpointRepository
    uninitialized = object.__new__(repository_type)
    uninitialized.__dict__["_directory"] = None
    trusted_property = repository_type.__dict__["_trusted"]
    with pytest.raises(ManagedPathCheckpointError, match="尚未初始化"):
        trusted_property.__get__(uninitialized, repository_type)


def test_posix_trusted_directory_handle_operations_are_relative(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    trusted_type = runtime_module.__dict__["_TrustedDirectory"]
    trusted = object.__new__(trusted_type)
    trusted.path = tmp_path.resolve()
    trusted._windows = None
    trusted._descriptor = 91
    trusted._closed = False
    trusted._identity = trusted.path.stat()
    directory_metadata = trusted.path.stat()
    regular_metadata = Path(__file__).stat()
    calls: list[tuple[object, ...]] = []

    def fake_fstat(descriptor: int) -> os.stat_result:
        return directory_metadata if descriptor in {91, 93} else regular_metadata

    def fake_open(
        name: os.PathLike[str] | str,
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        calls.append(("open", str(name), flags, mode, dir_fd))
        if str(name) == "missing":
            raise FileNotFoundError(str(name))
        if str(name) == "child":
            return 93
        return 92

    def fake_mkdir(
        name: os.PathLike[str] | str,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> None:
        calls.append(("mkdir", str(name), mode, dir_fd))

    def fake_close(descriptor: int) -> None:
        calls.append(("close", descriptor))

    def fake_replace(
        source: os.PathLike[str] | str,
        target: os.PathLike[str] | str,
        *,
        src_dir_fd: int | None = None,
        dst_dir_fd: int | None = None,
    ) -> None:
        calls.append(("replace", str(source), str(target), src_dir_fd, dst_dir_fd))

    def fake_unlink(name: os.PathLike[str] | str, *, dir_fd: int | None = None) -> None:
        calls.append(("unlink", str(name), dir_fd))

    def fake_fsync(descriptor: int) -> None:
        calls.append(("fsync", descriptor))

    def fake_read(_descriptor: int, _size: int) -> bytes:
        return b""

    def fake_flock(descriptor: int, operation: int) -> None:
        calls.append(("flock", descriptor, operation))

    def fake_import_module(_name: str) -> SimpleNamespace:
        return fake_fcntl

    def fake_child_constructor(path: Path, *, descriptor: int) -> Any:
        child = object.__new__(trusted_type)
        child.path = path
        child._windows = None
        child._descriptor = descriptor
        child._closed = False
        child._identity = directory_metadata
        child.validate()
        return child

    monkeypatch.setattr(runtime_module.os, "fstat", fake_fstat)
    monkeypatch.setattr(runtime_module.os, "open", fake_open)
    monkeypatch.setattr(runtime_module.os, "mkdir", fake_mkdir)
    monkeypatch.setattr(runtime_module.os, "close", fake_close)
    monkeypatch.setattr(runtime_module.os, "replace", fake_replace)
    monkeypatch.setattr(runtime_module.os, "unlink", fake_unlink)
    monkeypatch.setattr(runtime_module.os, "fsync", fake_fsync)
    monkeypatch.setattr(runtime_module.os, "read", fake_read)
    fake_fcntl = SimpleNamespace(
        LOCK_EX=1,
        LOCK_NB=2,
        LOCK_UN=4,
        flock=fake_flock,
    )
    monkeypatch.setattr(runtime_module.importlib, "import_module", fake_import_module)

    trusted.validate()
    trusted.require_public_identity()
    assert trusted._open_directory(tmp_path) == 92
    with monkeypatch.context() as platform_patch:
        platform_patch.setitem(runtime_module.__dict__, "_TrustedDirectory", fake_child_constructor)
        child = trusted.open_child_directory("child")
    child.close()

    def reject_link_open(
        name: os.PathLike[str] | str,
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        if str(name) in {"broken", "linked"}:
            raise OSError(errno.ELOOP, "link rejected")
        return fake_open(name, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(runtime_module.os, "open", reject_link_open)
    with pytest.raises(ManagedPathCheckpointError, match="非符号链接目录"):
        trusted.open_child_directory("broken")
    with pytest.raises(ManagedPathCheckpointError, match="非符号链接普通文件"):
        trusted.open_file("linked")
    monkeypatch.setattr(runtime_module.os, "open", fake_open)
    descriptor = trusted.open_file("value", create=True, writable=True)
    assert descriptor == 92
    assert trusted.read_bytes("value") == b""
    assert not trusted.exists("missing")
    with pytest.raises(FileNotFoundError):
        trusted.unlink("missing")
    trusted.replace_open_file(92, "source", "target")
    trusted.unlink("value")
    with trusted.lock("value"):
        calls.append(("locked",))
    successful_flock = fake_fcntl.flock

    def busy_flock(descriptor: int, operation: int) -> None:
        if operation == 3:
            raise OSError("busy")
        successful_flock(descriptor, operation)

    fake_fcntl.flock = busy_flock
    with pytest.raises(ManagedPathCheckpointError, match="writer 正忙"), trusted.lock("value"):
        pass
    trusted.sync_metadata()
    trusted.close()
    assert any(call[0] == "replace" for call in calls)
    assert any(call[0] == "unlink" for call in calls)
    assert ("flock", 92, 3) in calls
    assert ("flock", 92, 4) in calls


def test_posix_trusted_directory_fail_closed_branches(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    trusted_type = runtime_module.__dict__["_TrustedDirectory"]
    trusted = object.__new__(trusted_type)
    trusted.path = tmp_path.resolve()
    trusted._windows = None
    trusted._descriptor = 91
    trusted._closed = False
    trusted._identity = trusted.path.stat()
    directory_metadata = trusted.path.stat()
    regular_metadata = Path(__file__).stat()

    def return_regular(_descriptor: int) -> os.stat_result:
        return regular_metadata

    def return_directory(_descriptor: int) -> os.stat_result:
        return directory_metadata

    def deny_path(*_args: object, **_kwargs: object) -> Never:
        raise PermissionError("denied")

    def deny_sync(_descriptor: int) -> Never:
        raise PermissionError("denied")

    def fake_open(
        _name: os.PathLike[str] | str,
        _flags: int,
        _mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        del dir_fd
        return 92

    def fake_close(_descriptor: int) -> None:
        return None

    monkeypatch.setattr(runtime_module.os, "fstat", return_regular)
    with pytest.raises(ManagedPathCheckpointError, match="不再指向目录"):
        trusted.validate()
    monkeypatch.setattr(
        runtime_module.os,
        "fstat",
        return_directory,
    )
    monkeypatch.setattr(runtime_module.os, "open", fake_open)
    monkeypatch.setattr(runtime_module.os, "close", fake_close)
    with pytest.raises(ManagedPathCheckpointError, match="普通文件"):
        trusted.open_file("directory")

    monkeypatch.setattr(Path, "stat", deny_path)
    with pytest.raises(ManagedPathCheckpointError, match="公开身份已变化"):
        trusted.require_public_identity()
    monkeypatch.undo()
    monkeypatch.setattr(runtime_module.os, "fstat", return_directory)

    trusted._identity = None
    with pytest.raises(ManagedPathCheckpointError, match="公开身份已变化"):
        trusted.require_public_identity()
    trusted._identity = directory_metadata
    monkeypatch.setattr(
        runtime_module.os,
        "fsync",
        deny_sync,
    )
    with pytest.raises(ManagedPathCheckpointError, match="目录元数据无法持久化"):
        trusted.sync_metadata()


def test_windows_handle_api_error_paths_are_stable(monkeypatch: pytest.MonkeyPatch) -> None:
    api_type = runtime_module.__dict__["_WindowsTrustedDirectoryApi"]
    api = object.__new__(api_type)

    def close_success(_handle: int) -> int:
        return 1

    def close_failure(_handle: int) -> int:
        return 0

    def get_info_failure(
        _handle: int,
        _kind: int,
        _pointer: Any,
        _size: int,
    ) -> int:
        return 0

    def get_info_reparse(
        _handle: int,
        _kind: int,
        pointer: Any,
        _size: int,
    ) -> int:
        pointer._obj.file_attributes = 0x400
        return 1

    def get_info_directory(
        _handle: int,
        _kind: int,
        pointer: Any,
        _size: int,
    ) -> int:
        pointer._obj.file_attributes = 0x10
        return 1

    def create_invalid(*_args: object) -> int:
        return api._INVALID_HANDLE_VALUE

    def create_handle(*_args: object) -> int:
        return 1

    def set_info_failure(*_args: object) -> int:
        return 0

    def lock_success(*_args: object) -> int:
        return 1

    def lock_failure(*_args: object) -> int:
        return 0

    def unlock_failure(*_args: object) -> int:
        return 0

    def fd_handle(_descriptor: int) -> int:
        return 1

    api._close_handle = close_success
    api._get_info = get_info_failure
    monkeypatch.setitem(runtime_module.ctypes.__dict__, "get_last_error", lambda: 999)
    with pytest.raises(OSError):
        api._attributes(1)

    for error, error_type in (
        (80, FileExistsError),
        (2, FileNotFoundError),
        (5, PermissionError),
        (32, ManagedPathCheckpointError),
    ):
        monkeypatch.setitem(
            runtime_module.ctypes.__dict__,
            "get_last_error",
            lambda current=error: current,
        )
        with pytest.raises(error_type):
            api._raise_last_error("stable")
    monkeypatch.setitem(runtime_module.ctypes.__dict__, "get_last_error", lambda: 999)

    api._create_file = create_invalid
    with pytest.raises(OSError):
        api.open_directory(Path("state"))
    with pytest.raises(OSError):
        api.open_file(Path("checkpoint"), create=False, writable=False, deletable=False)

    api._create_file = create_handle
    api._get_info = get_info_reparse
    with pytest.raises(ManagedPathCheckpointError, match="reparse"):
        api.open_directory(Path("state"))
    with pytest.raises(ManagedPathCheckpointError, match="普通文件"):
        api.open_file(Path("checkpoint"), create=False, writable=False, deletable=False)

    api._get_info = get_info_reparse
    with pytest.raises(ManagedPathCheckpointError, match="reparse"):
        api.require_directory(1)
    with pytest.raises(ManagedPathCheckpointError, match="普通文件"):
        api.require_regular(1)

    api.fd_handle = fd_handle
    api._set_info = set_info_failure
    with pytest.raises(OSError):
        api.replace(1, Path("target"))
    with pytest.raises(OSError):
        api.unlink(1)
    api._lock_file = lock_failure
    api._unlock_file = unlock_failure
    with pytest.raises(OSError), api.lock(1):
        pass
    api._lock_file = lock_success
    api._unlock_file = unlock_failure
    with pytest.raises(OSError), api.lock(1):
        pass
    api._close_handle = close_failure
    with pytest.raises(OSError):
        api.close_handle(1)

    trusted_type = runtime_module.__dict__["_TrustedDirectory"]
    trusted = object.__new__(trusted_type)
    trusted.path = Path("state")
    trusted._windows = api
    trusted._descriptor = 1
    trusted._closed = False
    trusted._identity = None
    api._get_info = get_info_directory
    with pytest.raises(ManagedPathCheckpointError, match="缺少可信文件句柄"):
        trusted.sync_metadata()


def test_windows_trusted_handle_success_paths_are_platform_independent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    api_type = runtime_module.__dict__["_WindowsTrustedDirectoryApi"]
    trusted_type = runtime_module.__dict__["_TrustedDirectory"]
    api = object.__new__(api_type)
    calls: list[tuple[object, ...]] = []

    def create_file(path: str, *args: object) -> int:
        calls.append(("create", path, *args))
        return 41 if Path(path).name in {"state", "child"} else 43

    def get_info(handle: int, _kind: int, pointer: Any, _size: int) -> int:
        pointer._obj.file_attributes = 0x10 if handle in {41, 42} else 0
        return 1

    def set_info(handle: int, kind: int, *_args: object) -> int:
        calls.append(("set_info", handle, kind))
        return 1

    def close_handle(handle: int) -> int:
        calls.append(("close_handle", handle))
        return 1

    def lock_file(*_args: object) -> int:
        calls.append(("lock",))
        return 1

    def unlock_file(*_args: object) -> int:
        calls.append(("unlock",))
        return 1

    def open_osfhandle(handle: int, flags: int) -> int:
        calls.append(("open_osfhandle", handle, flags))
        return handle + 100

    def get_osfhandle(descriptor: int) -> int:
        return descriptor - 100

    fake_msvcrt = SimpleNamespace(
        open_osfhandle=open_osfhandle,
        get_osfhandle=get_osfhandle,
    )

    def import_module(name: str) -> SimpleNamespace:
        assert name == "msvcrt"
        return fake_msvcrt

    def fake_mkdir(
        path: os.PathLike[str] | str,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> None:
        calls.append(("mkdir", str(path), mode, dir_fd))

    def fake_close(descriptor: int) -> None:
        calls.append(("close_fd", descriptor))

    def fake_fsync(descriptor: int) -> None:
        calls.append(("fsync", descriptor))

    def fake_read(_descriptor: int, _size: int) -> bytes:
        return b""

    def child_constructor(path: Path, *, descriptor: int) -> Any:
        child = object.__new__(trusted_type)
        child.path = path
        child._windows = api
        child._descriptor = descriptor
        child._closed = False
        child._identity = None
        child.validate()
        return child

    class FakeKernelFunction:
        def __init__(self, callback: Callable[..., int]) -> None:
            self._callback = callback
            self.restype: object | None = None

        def __call__(self, *args: object) -> int:
            return self._callback(*args)

    kernel32 = SimpleNamespace(
        CreateFileW=FakeKernelFunction(create_file),
        GetFileInformationByHandleEx=FakeKernelFunction(get_info),
        SetFileInformationByHandle=FakeKernelFunction(set_info),
        CloseHandle=FakeKernelFunction(close_handle),
        LockFileEx=FakeKernelFunction(lock_file),
        UnlockFileEx=FakeKernelFunction(unlock_file),
    )

    def load_kernel32(_name: str, *, use_last_error: bool) -> SimpleNamespace:
        assert use_last_error
        return kernel32

    with monkeypatch.context() as ctypes_patch:
        ctypes_patch.setitem(runtime_module.ctypes.__dict__, "WinDLL", load_kernel32)
        initialized = api_type()
    assert initialized._create_file is kernel32.CreateFileW

    api._create_file = create_file
    api._get_info = get_info
    api._set_info = set_info
    api._close_handle = close_handle
    api._lock_file = lock_file
    api._unlock_file = unlock_file
    monkeypatch.setattr(runtime_module.importlib, "import_module", import_module)
    monkeypatch.setattr(runtime_module.os, "mkdir", fake_mkdir)
    monkeypatch.setattr(runtime_module.os, "close", fake_close)
    monkeypatch.setattr(runtime_module.os, "fsync", fake_fsync)
    monkeypatch.setattr(runtime_module.os, "read", fake_read)

    directory_handle = api.open_directory(Path("state"))
    assert directory_handle == 41
    file_descriptor = api.open_file(
        Path("checkpoint"),
        create=True,
        writable=True,
        deletable=True,
    )
    assert file_descriptor == 143
    assert api.fd_handle(file_descriptor) == 43
    api.replace(file_descriptor, Path("target"))
    api.unlink(file_descriptor)
    with api.lock(file_descriptor):
        calls.append(("locked",))
    api.close_handle(directory_handle)

    trusted = object.__new__(trusted_type)
    trusted.path = tmp_path / "state"
    trusted._windows = api
    trusted._descriptor = 41
    trusted._closed = False
    trusted._identity = None
    trusted.validate()
    trusted.require_public_identity()
    assert trusted._open_directory(trusted.path) == 41
    with monkeypatch.context() as constructor_patch:
        constructor_patch.setitem(runtime_module.__dict__, "_TrustedDirectory", child_constructor)
        child = trusted.open_child_directory("child")
    child.close()

    original_open_directory = api.open_directory

    def deny_directory(_path: Path) -> Never:
        raise OSError("denied")

    api.open_directory = deny_directory
    with pytest.raises(ManagedPathCheckpointError, match="非 reparse 目录"):
        trusted.open_child_directory("blocked")
    api.open_directory = original_open_directory

    original_open_file = api.open_file

    def deny_open(*_args: object, **_kwargs: object) -> Never:
        raise PermissionError("denied")

    api.open_file = deny_open
    with pytest.raises(ManagedPathCheckpointError, match="非 reparse 普通文件"):
        trusted.open_file("denied")
    api.open_file = original_open_file

    assert trusted.open_file("value", writable=True) == 143
    assert trusted.read_bytes("value") == b""
    trusted.replace_open_file(143, "temporary", "checkpoint")
    trusted.unlink("value")
    with trusted.lock("value"):
        calls.append(("trusted_locked",))
    trusted.sync_metadata(143)
    trusted.close()
    assert ("locked",) in calls
    assert ("trusted_locked",) in calls
    assert any(call[0] == "set_info" for call in calls)


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
    (repo.path.parent / ".writer-owner.json").write_text("{", encoding="utf-8")
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
        "Be" + "arer never-echo-this-secret",
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
    payload["selection"] = [{"stable_error_code": "Be" + "arer never-echo-this-secret"}]
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
    assert len(good_sink.items) == 1
    assert good_sink.items[0].publication_id == result.checkpoint.publication_id
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
    retried = await runtime.stage_pending(
        envelope(TEST_PLAN),
        TEST_PLAN,
        at=NOW + timedelta(seconds=17),
    )
    assert retried.publication_id == result.publication_id
    assert len(succeeded.items) == 1
    assert succeeded.idempotency_keys == [result.publication_id]
    assert cancelled.idempotency_keys == [result.publication_id, result.publication_id]
    assert len(trailing.items) == 1
    assert trailing.idempotency_keys == [result.publication_id]
    assert retried.checkpoint is not None
    assert retried.checkpoint.updated_at == NOW + timedelta(seconds=17)
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
