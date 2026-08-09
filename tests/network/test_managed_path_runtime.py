"""受管路径阶段一状态、授权只读端口与零 Provider 写入测试。"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timedelta
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
from tunnelminion.network.fakes import InMemoryNetworkProvider
from tunnelminion.network.governance import (
    NetworkAuthorizationGrant,
    NetworkAuthorizationScope,
)
from tunnelminion.network.managed_path_runtime import (
    FileManagedPathCheckpointRepository,
    ManagedPathCheckpoint,
    ManagedPathCheckpointError,
    ManagedPathCheckpointSink,
    ManagedPathEvidenceState,
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


def _build_plan() -> NetworkPlan:
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


def plan() -> tuple[InMemoryNetworkProvider, NetworkPlan]:
    return InMemoryNetworkProvider(observation()), TEST_PLAN


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
    value: NetworkPlan,
    *,
    approved_at: datetime = NOW - timedelta(minutes=1),
    expires_at: datetime = NOW + timedelta(minutes=5),
    revoked_at: datetime | None = None,
) -> NetworkAuthorizationGrant:
    return NetworkAuthorizationGrant(
        authorization_id=AuthorizationId.new(),
        scope=NetworkAuthorizationScope.from_plan(
            value,
            address_pool="10.203.0.0/24",
        ),
        approved_by="local-owner",
        approved_at=approved_at,
        expires_at=expires_at,
        revoked_at=revoked_at,
    )


def checkpoint(**updates: object) -> ManagedPathCheckpoint:
    _, value = plan()
    values: dict[str, object] = {
        "network_id": NETWORK_ID,
        "node_id": NODE_A,
        "revision": 1,
        "provider": value.desired.provider,
        "pending_plan_hash": value.plan_hash,
        "observed_fingerprint": value.observed_fingerprint,
        "authorization_state": PathAuthorizationState.AWAITING_AUTHORIZATION,
        "stable_error_code": ManagedPathPhaseOneErrorCode.LOCAL_L3_APPROVAL_REQUIRED,
        "updated_at": NOW,
    }
    values.update(updates)
    return ManagedPathCheckpoint.model_validate(values)


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
    def __init__(self, *, gate: asyncio.Event | None = None) -> None:
        self.calls = 0
        self.gate = gate

    async def refresh(self, checkpoint: ManagedPathCheckpoint) -> ManagedPathEvidenceState:
        del checkpoint
        self.calls += 1
        if self.gate is not None:
            await self.gate.wait()
        return ManagedPathEvidenceState(
            source=PathEvidenceSource.FAKE,
            freshness=PathEvidenceFreshness.FRESH,
            endpoint_probe_at=NOW,
            endpoint_probe_succeeded=True,
            last_handshake_at=NOW,
            handshake_fresh=True,
            host_route_present=True,
            target_probe_at=NOW,
            target_probe_succeeded=True,
            refreshed_at=NOW,
            expires_at=NOW + timedelta(minutes=3),
        )


class MemoryCheckpointSink:
    def __init__(self) -> None:
        self.items: list[ManagedPathCheckpoint] = []

    async def publish(self, checkpoint: ManagedPathCheckpoint) -> None:
        self.items.append(checkpoint)


def lifecycle(
    tmp_path: Path,
    *,
    grants: tuple[NetworkAuthorizationGrant, ...] = (),
    refresher: FakeReadOnlyRefresher | None = None,
    sinks: tuple[ManagedPathCheckpointSink, ...] = (),
) -> tuple[
    ManagedPathPhaseOneLifecycle,
    InMemoryNetworkProvider,
    NetworkPlan,
    MemoryAuthorizationReader,
    FileManagedPathCheckpointRepository,
]:
    provider, value = plan()
    reader = MemoryAuthorizationReader(grants)
    writer = object()
    repository = FileManagedPathCheckpointRepository(
        tmp_path / "managed-path.json",
        writer_token=writer,
    )
    return (
        ManagedPathPhaseOneLifecycle(
            provider,
            ReadOnlyNetworkAuthorizationMatcher(reader),
            repository,
            refresher or FakeReadOnlyRefresher(),
            writer_token=writer,
            sinks=sinks,
        ),
        provider,
        value,
        reader,
        repository,
    )


def test_state_schema_is_versioned_redacted_and_consistent() -> None:
    unknown = ManagedPathEvidenceState()
    assert unknown.model_dump(mode="json") == {
        "source": "none",
        "freshness": "unknown",
        "endpoint_probe_at": None,
        "endpoint_probe_succeeded": None,
        "last_handshake_at": None,
        "handshake_fresh": None,
        "host_route_present": None,
        "target_probe_at": None,
        "target_probe_succeeded": None,
        "refreshed_at": None,
        "expires_at": None,
        "stable_error_code": None,
    }
    value = checkpoint()
    assert value.schema_version == 1
    assert "endpoint" not in value.model_dump(mode="json")
    assert "routes" not in value.model_dump(mode="json")

    with pytest.raises(ValidationError, match="授权状态"):
        checkpoint(authorization_state="authorized")
    with pytest.raises(ValidationError, match="更新时间"):
        checkpoint(updated_at=NOW.replace(tzinfo=None))
    with pytest.raises(ValidationError, match="direct selection"):
        checkpoint(
            selection=ManagedPathSelectionState(
                path_type=NetworkPathType.DIRECT,
                selected_at=NOW,
            )
        )
    with pytest.raises(ValidationError):
        ManagedPathCheckpoint.model_validate({**value.model_dump(), "endpoint": "192.0.2.1"})


@pytest.mark.parametrize(
    "payload",
    [
        {"source": "fake", "freshness": "unknown"},
        {"source": "none", "freshness": "unknown", "refreshed_at": NOW},
        {"source": "none", "freshness": "fresh"},
        {"source": "fake", "freshness": "fresh"},
        {
            "source": "fake",
            "freshness": "fresh",
            "refreshed_at": NOW,
            "expires_at": NOW - timedelta(seconds=1),
        },
        {"endpoint_probe_at": NOW.replace(tzinfo=None)},
    ],
)
def test_evidence_schema_rejects_false_freshness(payload: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        ManagedPathEvidenceState.model_validate(payload)


def test_checkpoint_repository_is_atomic_single_writer_and_legacy_safe(tmp_path: Path) -> None:
    path = tmp_path / "managed-path.json"
    writer = object()
    repository = FileManagedPathCheckpointRepository(path, writer_token=writer)
    assert repository.load() is None
    repository.assert_no_secret_material()

    value = checkpoint()
    with pytest.raises(PermissionError, match="单一 writer"):
        repository.save(value, writer_token=object())
    repository.save(value, writer_token=writer)
    assert repository.load() == value
    repository.assert_no_secret_material()
    assert not (tmp_path / ".managed-path.json.tmp").exists()

    path.write_text('{"phase":"idle","applied_revision":1}', encoding="utf-8")
    assert repository.load() is None


@pytest.mark.parametrize(
    ("content", "message"),
    [
        ("not-json", "无法读取"),
        ("[]", "结构无效"),
        ('{"network_id":"legacy"}', "缺少 schema"),
        ('{"schema_version":99}', "schema 不受支持"),
        ('{"schema_version":1,"private_key":"hidden"}', "禁止字段"),
        ('{"phase":"idle","private_key":"hidden"}', "禁止字段"),
        ('{"schema_version":1}', "校验失败"),
    ],
)
def test_checkpoint_load_fails_closed(tmp_path: Path, content: str, message: str) -> None:
    path = tmp_path / "managed-path.json"
    path.write_text(content, encoding="utf-8")
    repository = FileManagedPathCheckpointRepository(path, writer_token=object())
    with pytest.raises(ManagedPathCheckpointError, match=message):
        repository.load()


@pytest.mark.parametrize(
    "payload",
    [
        ["invalid"],
        {"schema_version": 1, "token": "hidden"},
        {"schema_version": 1, "stable_error_code": "Bearer hidden"},
        {"schema_version": 1},
    ],
)
def test_checkpoint_secret_scan_fails_closed(tmp_path: Path, payload: object) -> None:
    path = tmp_path / "managed-path.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    repository = FileManagedPathCheckpointRepository(path, writer_token=object())
    with pytest.raises(ManagedPathCheckpointError):
        repository.assert_no_secret_material()


def test_checkpoint_secret_scan_rejects_invalid_json(tmp_path: Path) -> None:
    path = tmp_path / "managed-path.json"
    path.write_text("{", encoding="utf-8")
    repository = FileManagedPathCheckpointRepository(path, writer_token=object())
    with pytest.raises(ManagedPathCheckpointError, match="无法扫描"):
        repository.assert_no_secret_material()


def test_authorization_matcher_distinguishes_all_fail_closed_results() -> None:
    _, value = plan()
    active = grant(value)
    cases = (
        ((), ManagedPathPhaseOneErrorCode.LOCAL_L3_APPROVAL_REQUIRED),
        (
            (active.model_copy(update={"revoked_at": NOW}),),
            ManagedPathPhaseOneErrorCode.LOCAL_L3_APPROVAL_REVOKED,
        ),
        (
            (
                grant(
                    value,
                    approved_at=NOW + timedelta(minutes=1),
                    expires_at=NOW + timedelta(minutes=2),
                ),
            ),
            ManagedPathPhaseOneErrorCode.LOCAL_L3_APPROVAL_NOT_YET_VALID,
        ),
        (
            (
                grant(
                    value,
                    approved_at=NOW - timedelta(minutes=2),
                    expires_at=NOW,
                ),
            ),
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
            value, at=NOW
        )
        assert result.state is PathAuthorizationState.AWAITING_AUTHORIZATION
        assert result.code is expected
        assert result.authorization_id is None

    matched = ReadOnlyNetworkAuthorizationMatcher(MemoryAuthorizationReader((active,))).evaluate(
        value, at=NOW
    )
    assert matched.state is PathAuthorizationState.AUTHORIZED
    assert matched.authorization_id == active.authorization_id
    assert matched.code is ManagedPathPhaseOneErrorCode.PROVIDER_EXECUTION_DISABLED
    with pytest.raises(ValueError, match="时区"):
        ReadOnlyNetworkAuthorizationMatcher(MemoryAuthorizationReader()).evaluate(
            value,
            at=NOW.replace(tzinfo=None),
        )
    with pytest.raises(ValidationError, match="授权匹配"):
        NetworkAuthorizationMatch(
            state=PathAuthorizationState.AUTHORIZED,
            code=ManagedPathPhaseOneErrorCode.PROVIDER_EXECUTION_DISABLED,
        )


@pytest.mark.anyio
async def test_phase_one_without_authorization_only_persists_pending(tmp_path: Path) -> None:
    first_sink = MemoryCheckpointSink()
    second_sink = MemoryCheckpointSink()
    runtime, provider, value, reader, repository = lifecycle(
        tmp_path,
        sinks=(first_sink, second_sink),
    )
    result = await runtime.stage_pending(envelope(value), value, at=NOW)
    assert result.authorization_state is PathAuthorizationState.AWAITING_AUTHORIZATION
    assert result.stable_error_code is ManagedPathPhaseOneErrorCode.LOCAL_L3_APPROVAL_REQUIRED
    assert result.selection is None
    assert result.evidence.freshness is PathEvidenceFreshness.UNKNOWN
    assert provider.apply_calls == 0
    assert reader.reads == [(NETWORK_ID, NODE_A)]
    assert repository.load() == result
    assert first_sink.items == [result]
    assert second_sink.items == [result]


@pytest.mark.anyio
async def test_phase_one_never_executes_provider_even_with_authorization(tmp_path: Path) -> None:
    provider, value = plan()
    approved = grant(value)
    reader = MemoryAuthorizationReader((approved,))
    writer = object()
    repository = FileManagedPathCheckpointRepository(
        tmp_path / "managed-path.json", writer_token=writer
    )
    runtime = ManagedPathPhaseOneLifecycle(
        provider,
        ReadOnlyNetworkAuthorizationMatcher(reader),
        repository,
        FakeReadOnlyRefresher(),
        writer_token=writer,
    )
    result = await runtime.stage_pending(envelope(value), value, at=NOW)
    assert result.authorization_state is PathAuthorizationState.AUTHORIZED
    assert result.authorization_id == approved.authorization_id
    assert result.stable_error_code is ManagedPathPhaseOneErrorCode.PROVIDER_EXECUTION_DISABLED
    assert provider.apply_calls == 0

    wrong = envelope(value).model_copy(update={"config": desired(revision=2)})
    with pytest.raises(ValueError, match="不一致"):
        await runtime.stage_pending(wrong, value, at=NOW)
    assert provider.apply_calls == 0


@pytest.mark.anyio
async def test_status_consumers_cannot_create_authorization(tmp_path: Path) -> None:
    runtime, provider, value, reader, _ = lifecycle(tmp_path)
    staged = await runtime.stage_pending(envelope(value), value, at=NOW)
    reads_before = len(reader.reads)
    for _consumer in (
        "startup",
        "model",
        "conversation",
        "memory",
        "service-observation",
        "coordinator",
        "web-view",
    ):
        assert runtime.read_status() == staged
    assert len(reader.reads) == reads_before
    assert reader.grants == ()
    assert provider.apply_calls == 0


@pytest.mark.anyio
async def test_concurrent_refresh_is_coalesced_and_never_replays_apply(tmp_path: Path) -> None:
    gate = asyncio.Event()
    refresher = FakeReadOnlyRefresher(gate=gate)
    runtime, provider, value, reader, repository = lifecycle(
        tmp_path,
        refresher=refresher,
    )
    assert await runtime.refresh() is None
    await runtime.stage_pending(envelope(value), value, at=NOW)
    authorization_reads = len(reader.reads)

    first = asyncio.create_task(runtime.refresh())
    second = asyncio.create_task(runtime.refresh())
    for _ in range(3):
        if refresher.calls:
            break
        await asyncio.sleep(0)
    assert refresher.calls == 1
    gate.set()
    first_result, second_result = await asyncio.gather(first, second)
    assert first_result == second_result
    assert first_result is not None
    assert first_result.evidence.source is PathEvidenceSource.FAKE
    assert repository.load() == first_result
    assert len(reader.reads) == authorization_reads
    assert provider.apply_calls == 0
