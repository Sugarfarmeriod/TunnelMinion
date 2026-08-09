"""受管路径阶段一状态、持久 owner 与零 Provider 写入测试。"""

from __future__ import annotations

import asyncio
import base64
import json
import os
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError
from tests.network.factories import NETWORK_ID, NODE_A, NOW, desired, observation

from tunnelminion.domain.identifiers import AuthorizationId
from tunnelminion.network.contracts import (
    NetworkAction,
    NetworkPlan,
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
    ManagedPathSelectionState,
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
    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail
        self.items: list[ManagedPathCheckpoint] = []

    async def publish(self, checkpoint: ManagedPathCheckpoint) -> None:
        self.items.append(checkpoint)
        if self.fail:
            raise RuntimeError("正文不得进入稳定结果")


def repository(
    tmp_path: Path, *, writer_id: str = "phase-one-writer"
) -> FileManagedPathCheckpointRepository:
    return FileManagedPathCheckpointRepository(tmp_path, writer_id=writer_id)


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


def test_grant_times_require_aware_utc_and_boundary_is_exclusive() -> None:
    with pytest.raises(ValidationError, match="timezone-aware UTC"):
        grant(approved_at=(NOW - timedelta(minutes=1)).replace(tzinfo=None))
    with pytest.raises(ValidationError, match="timezone-aware UTC"):
        grant(expires_at=(NOW + timedelta(minutes=5)).astimezone(timezone(timedelta(hours=8))))
    active = grant(expires_at=NOW)
    assert not active.is_active(at=NOW)


def test_repository_binds_root_fixed_path_and_persistent_owner(tmp_path: Path) -> None:
    root = tmp_path.resolve()
    repo = repository(root, writer_id="writer-a")
    assert repo.path == root / MANAGED_PATH_CHECKPOINT_RELATIVE_PATH
    assert repo.load() is None
    same_owner = repository(root, writer_id="writer-a")
    same_owner.save(checkpoint())
    assert repo.load() == checkpoint()
    with pytest.raises(PermissionError, match="其他 writer"):
        repository(root, writer_id="writer-b")
    with pytest.raises(ManagedPathCheckpointError, match="绝对路径"):
        FileManagedPathCheckpointRepository(Path("relative"), writer_id="writer-a")
    with pytest.raises(ManagedPathCheckpointError, match="固定相对路径"):
        FileManagedPathCheckpointRepository(
            root, writer_id="writer-a", relative_path=Path("../escape")
        )
    with pytest.raises(ManagedPathCheckpointError, match="identity"):
        FileManagedPathCheckpointRepository(root, writer_id="INVALID WRITER")
    missing = root / "missing"
    with pytest.raises(ManagedPathCheckpointError, match="allowed_root"):
        repository(missing)
    plain_file = root / "plain-file"
    plain_file.write_text("x", encoding="utf-8")
    with pytest.raises(ManagedPathCheckpointError, match="allowed_root"):
        repository(plain_file)


def test_repository_rejects_simulated_parent_and_target_symlink(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path.resolve()
    target = root / MANAGED_PATH_CHECKPOINT_RELATIVE_PATH
    original = Path.is_symlink

    def target_is_symlink(path: Path) -> bool:
        return path == target or original(path)

    monkeypatch.setattr(
        Path,
        "is_symlink",
        target_is_symlink,
    )
    with pytest.raises(ManagedPathCheckpointError, match="符号链接"):
        repository(root)

    def parent_is_symlink(path: Path) -> bool:
        return path == target.parent or original(path)

    monkeypatch.setattr(
        Path,
        "is_symlink",
        parent_is_symlink,
    )
    with pytest.raises(ManagedPathCheckpointError, match="父级"):
        repository(root)


def test_repository_owner_is_enforced_in_another_process(tmp_path: Path) -> None:
    root = tmp_path.resolve()
    repository(root, writer_id="writer-a")
    script = (
        "from pathlib import Path; "
        "from tunnelminion.network.managed_path_runtime "
        "import FileManagedPathCheckpointRepository; "
        f"FileManagedPathCheckpointRepository(Path({str(root)!r}), writer_id='writer-b')"
    )
    result = subprocess.run(
        [sys.executable, "-c", script],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
    assert "其他 writer" in result.stderr


def test_repository_lock_blocks_second_instance_and_recovers(tmp_path: Path) -> None:
    first = repository(tmp_path.resolve(), writer_id="writer-a")
    second = repository(tmp_path.resolve(), writer_id="writer-a")
    with (
        first._writer_lock(),  # pyright: ignore[reportPrivateUsage]
        pytest.raises(
            ManagedPathCheckpointError,
            match="正忙",
        ),
    ):
        second.save(checkpoint())
    second.save(checkpoint(revision=2))
    assert first.load() == checkpoint(revision=2)


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


def test_repository_temp_creation_is_exclusive_and_nofollow(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = repository(tmp_path.resolve())
    original_open = os.open
    observed_flags: list[int] = []

    def guarded_open(path: os.PathLike[str] | str, flags: int, mode: int = 0o777) -> int:
        if str(path).endswith(".tmp"):
            observed_flags.append(flags)
            assert flags & os.O_EXCL
            nofollow = getattr(os, "O_NOFOLLOW", 0)
            if nofollow:
                assert flags & nofollow
            raise FileExistsError("预置临时链接不得被跟随")
        return original_open(path, flags, mode)

    monkeypatch.setattr("tunnelminion.network.managed_path_runtime.os.open", guarded_open)
    with pytest.raises(FileExistsError, match="不得被跟随"):
        repo.save(checkpoint())
    assert observed_flags
    assert repo.load() is None


def test_repository_rejects_target_parent_and_temp_symlinks(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path.resolve()
    state_dir = root / "managed-path"
    state_dir.mkdir()
    outside = root / "outside"
    outside.mkdir()
    parent_link_root = root / "parent-link-root"
    parent_link_root.mkdir()
    try:
        (parent_link_root / "managed-path").symlink_to(outside, target_is_directory=True)
        with pytest.raises(ManagedPathCheckpointError, match="父级"):
            repository(parent_link_root)
    except OSError:
        pytest.skip("当前平台不允许创建测试符号链接")

    target = state_dir / "checkpoint.json"
    target.symlink_to(root / "outside.json")
    with pytest.raises(ManagedPathCheckpointError, match="符号链接"):
        repository(root)
    target.unlink()
    repo = repository(root)

    class FixedUuid:
        hex = "fixed"

    monkeypatch.setattr("tunnelminion.network.managed_path_runtime.uuid4", lambda: FixedUuid())
    (state_dir / ".checkpoint.json.fixed.tmp").symlink_to(root / "outside.json")
    with pytest.raises(FileExistsError):
        repo.save(checkpoint())


def test_repository_rejects_non_regular_paths_and_changed_owner(tmp_path: Path) -> None:
    root = tmp_path.resolve()
    state_dir = root / "managed-path"
    state_dir.mkdir()
    (state_dir / "checkpoint.json").mkdir()
    with pytest.raises(ManagedPathCheckpointError, match="普通文件"):
        repository(root)
    os.rmdir(state_dir / "checkpoint.json")
    repo = repository(root)
    (state_dir / ".writer-owner.json").write_text('{"writer_id":"other"}', encoding="utf-8")
    with pytest.raises(PermissionError, match="identity"):
        repo.load()


def test_repository_rejects_corrupt_owner_claim_at_open_and_load(tmp_path: Path) -> None:
    first_root = tmp_path.resolve() / "first"
    first_root.mkdir()
    first_state = first_root / "managed-path"
    first_state.mkdir()
    (first_state / ".writer-owner.json").write_text("{", encoding="utf-8")
    with pytest.raises(ManagedPathCheckpointError, match="owner claim"):
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
