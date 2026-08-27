"""阶段 5 managed path 共用工厂、能力降级与同步接缝测试。"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

import pytest
from fastapi import FastAPI
from tests.agent.test_network_sync import (
    FakeNetworkSyncTransport,
    signed,
)
from tests.agent.test_network_sync import (
    build as build_sync,
)
from tests.network.factories import observation
from tests.network.test_managed_path_lifecycle import path_evidence

from tunnelminion.agent.coordinator import CoordinatorTransport
from tunnelminion.agent.managed_application import (
    ManagedNodeApplication,
    build_managed_node_application,
    managed_application_lifespan,
)
from tunnelminion.agent.managed_network_runtime import ManagedNetworkSyncLoop
from tunnelminion.agent.managed_node import (
    FileManagedNodeConfigRepository,
    ManagedNodeState,
    ManagedNodeStatus,
    managed_node_status,
)
from tunnelminion.agent.managed_path import (
    ManagedPathApplication,
    ManagedPathCapabilityState,
    ManagedPathPlatformDependencies,
    ManagedPathProbeFactory,
    PlatformManagedPathVerifier,
    _CredentialedPathStatusSink,  # pyright: ignore[reportPrivateUsage]
    _stable_error_code,  # pyright: ignore[reportPrivateUsage]
    _utc,  # pyright: ignore[reportPrivateUsage]
    build_managed_path_application,
)
from tunnelminion.agent.managed_runtime import ManagedNodeRuntime
from tunnelminion.agent.network_sync import ManagedNetworkSyncTransport
from tunnelminion.agent.service_observation import CollectionAdapter
from tunnelminion.domain.identifiers import NetworkId, NodeId
from tunnelminion.network.contracts import (
    DesiredNetworkConfig,
    NetworkAction,
    ProviderKind,
    ProviderMode,
    canonical_sha256,
)
from tunnelminion.network.fakes import InMemoryNetworkProvider
from tunnelminion.network.governance import NetworkGovernanceRecord, NetworkPathStatus
from tunnelminion.network.ledger import SQLiteManagedResourceLedger
from tunnelminion.network.path_controller import (
    DirectPathErrorCode,
    DirectPathEvidence,
    NetworkPathType,
)
from tunnelminion.network.path_probe import PathProbePolicy, PlatformPathProbe
from tunnelminion.network.path_status import (
    ManagedPathAuthorizationState,
    ManagedPathFreshness,
    ManagedPathStatus,
)
from tunnelminion.network.provider import NetworkProvider
from tunnelminion.platforms.macos.managed_path import (
    _tool_path as macos_tool_path,  # pyright: ignore[reportPrivateUsage]
)
from tunnelminion.platforms.macos.managed_path import build_macos_managed_path_platform
from tunnelminion.platforms.macos.managed_system import MacOSProviderPaths
from tunnelminion.platforms.macos.system import CommandResult
from tunnelminion.platforms.windows.managed_path import build_windows_managed_path_platform
from tunnelminion.tools.registry import ToolRegistry

NOW = datetime(2026, 7, 26, 12, 0, tzinfo=UTC)


def _platform(
    provider: InMemoryNetworkProvider,
    *,
    apply_available: bool = True,
) -> ManagedPathPlatformDependencies:
    capabilities = ManagedPathCapabilityState(
        provider=ProviderKind.WINDOWS,
        mode=ProviderMode.MANAGED if apply_available else ProviderMode.OBSERVE_ONLY,
        platform_supported=apply_available,
        provider_apply_available=apply_available,
        path_probe_available=apply_available,
        stable_error_code=None if apply_available else "platform_unsupported",
    )
    return ManagedPathPlatformDependencies(
        provider=cast(NetworkProvider, provider),
        provider_kind=ProviderKind.WINDOWS,
        capabilities=capabilities,
        probe_factory=_empty_probe_factory,
    )


def _empty_probe_factory(
    desired: DesiredNetworkConfig,
    policy: PathProbePolicy,
) -> PlatformPathProbe:
    del desired, policy
    return cast(PlatformPathProbe, object())


def test_common_factory_keeps_awaiting_authorization_before_provider_apply(
    tmp_path: Path,
) -> None:
    envelope, _ = signed()
    provider = InMemoryNetworkProvider(observation())
    application = build_managed_path_application(
        tmp_path,
        envelope.config.network_id,
        envelope.config.target_node_id,
        lambda data_dir, ledger: _platform(provider),
        revision_source=lambda: 0,
        pending_source=lambda: envelope,
        clock=lambda: NOW,
    )

    record = asyncio.run(application.reconcile_pending(envelope))

    assert record is not None
    assert cast(NetworkGovernanceRecord, record).phase.value == "awaiting_authorization"
    assert provider.apply_calls == 0
    status = application.current_managed_path_status()
    assert status.authorization_state is ManagedPathAuthorizationState.AWAITING_AUTHORIZATION
    assert application.resource_payload()["configured"] is True
    assert application.resource_payload()["authorization_state"] == "awaiting_authorization"
    assert application.path_selection() is None
    assert application.path_evidence() is None
    assert application.path_authorization() == "awaiting_authorization"
    application.assert_no_secret_material()
    application.close()
    application.close()


def test_common_factory_skips_provider_when_platform_capability_is_degraded(
    tmp_path: Path,
) -> None:
    envelope, _ = signed()
    provider = InMemoryNetworkProvider(observation())
    application = build_managed_path_application(
        tmp_path,
        envelope.config.network_id,
        envelope.config.target_node_id,
        lambda data_dir, ledger: _platform(provider, apply_available=False),
        revision_source=lambda: 0,
        pending_source=lambda: envelope,
        clock=lambda: NOW,
    )

    assert asyncio.run(application.reconcile_pending(envelope)) is None
    assert provider.observe_calls == 0
    assert provider.apply_calls == 0
    payload = application.resource_payload()
    assert payload["configured"] is True
    assert payload["stable_error_code"] == "platform_unsupported"
    application.close()


def test_common_factory_close_releases_windows_sqlite_handle(tmp_path: Path) -> None:
    envelope, _ = signed()
    provider = InMemoryNetworkProvider(observation())
    application = build_managed_path_application(
        tmp_path,
        envelope.config.network_id,
        envelope.config.target_node_id,
        lambda data_dir, ledger: _platform(provider),
        revision_source=lambda: 0,
        pending_source=lambda: None,
        clock=lambda: NOW,
    )

    governance_database = tmp_path / "governance.sqlite3"
    ledger_database = tmp_path / "managed-network-ledger.sqlite3"
    assert governance_database.exists()
    assert ledger_database.exists()
    application.close()
    application.close()
    governance_database.unlink()
    ledger_database.unlink()
    assert not governance_database.exists()
    assert not ledger_database.exists()


@pytest.mark.parametrize("failure", ("none", "start", "stop"))
def test_real_lifespan_releases_both_sqlite_databases_without_gc(
    tmp_path: Path,
    failure: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """正常、启动失败和停止失败均只关闭一次并释放两个数据库。"""
    envelope, _ = signed()
    provider = InMemoryNetworkProvider(observation())
    managed_path = build_managed_path_application(
        tmp_path,
        envelope.config.network_id,
        envelope.config.target_node_id,
        lambda data_dir, ledger: _platform(provider),
        revision_source=lambda: 0,
        pending_source=lambda: envelope,
        clock=lambda: NOW,
    )

    class Runtime:
        def __init__(self) -> None:
            self.calls: list[str] = []

        async def start(self) -> None:
            self.calls.append("start")
            if failure == "start":
                raise RuntimeError("start sentinel")

        async def stop(self) -> None:
            self.calls.append("stop")
            if failure == "stop":
                raise RuntimeError("stop sentinel")

    runtime = Runtime()
    close_calls = 0
    original_close = ManagedNodeApplication.close

    def record_close(application: ManagedNodeApplication) -> None:
        nonlocal close_calls
        close_calls += 1
        original_close(application)

    monkeypatch.setattr(ManagedNodeApplication, "close", record_close)
    owner = ManagedNodeApplication(
        config=None,
        enrollment=managed_node_status(None),
        runtime=cast(ManagedNodeRuntime, runtime),
        managed_path=managed_path,
    )

    async def scenario() -> None:
        if failure == "start":
            with pytest.raises(RuntimeError, match="start sentinel"):
                async with managed_application_lifespan(owner)(FastAPI()):
                    raise AssertionError("failed start must not enter lifespan")
        elif failure == "stop":
            with pytest.raises(RuntimeError, match="stop sentinel"):
                async with managed_application_lifespan(owner)(FastAPI()):
                    pass
        else:
            async with managed_application_lifespan(owner)(FastAPI()):
                pass

    asyncio.run(scenario())
    assert close_calls == 1
    assert runtime.calls == (["start"] if failure == "start" else ["start", "stop"])

    for database in (
        tmp_path / "governance.sqlite3",
        tmp_path / "managed-network-ledger.sqlite3",
    ):
        database.unlink()
        assert not database.exists()


def test_common_factory_managed_node_payload_projects_ttl_with_injected_clock(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    envelope, _ = signed()
    provider = InMemoryNetworkProvider(observation())
    now = [NOW + timedelta(seconds=181)]
    application = build_managed_path_application(
        tmp_path,
        envelope.config.network_id,
        envelope.config.target_node_id,
        lambda data_dir, ledger: _platform(provider),
        revision_source=lambda: 0,
        pending_source=lambda: envelope,
        clock=lambda: now[0],
    )
    evidence = path_evidence()
    status = ManagedPathStatus(
        network_id=evidence.network_id,
        node_id=evidence.node_id,
        revision=evidence.revision,
        plan_hash=evidence.plan_hash,
        authorization_revision=evidence.authorization_revision,
        provider=evidence.provider,
        authorization_state=ManagedPathAuthorizationState.UNKNOWN,
        path_type=NetworkPathType.STATIC,
        evidence=evidence,
        source="fake",
        freshness=ManagedPathFreshness.FRESH,
        candidate_count=evidence.candidate_count,
        observed_at=evidence.observed_at,
        refreshed_at=evidence.observed_at,
        expires_at=evidence.expires_at,
        journal_sequence=0,
        updated_at=NOW,
    )

    def get_path_status(*_args: object) -> ManagedPathStatus:
        return status

    monkeypatch.setattr(application.lifecycle, "get_path_status", get_path_status)

    payload = application.resource_payload()

    assert payload["freshness"] == "stale"
    assert payload["stable_error_code"] == "path_evidence_stale"
    assert payload["authorization_state"] == "unknown"
    application.close()


def test_managed_path_rejects_identity_provider_and_reports_stable_errors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    envelope, _ = signed()
    provider = InMemoryNetworkProvider(observation())
    application = build_managed_path_application(
        tmp_path,
        envelope.config.network_id,
        envelope.config.target_node_id,
        lambda data_dir, ledger: _platform(provider),
        revision_source=lambda: 0,
        pending_source=lambda: envelope,
        clock=lambda: NOW,
    )
    wrong_network = envelope.model_copy(
        update={"config": envelope.config.model_copy(update={"network_id": NetworkId.new()})}
    )
    wrong_provider = envelope.model_copy(
        update={"config": envelope.config.model_copy(update={"provider": ProviderKind.MACOS})}
    )

    assert asyncio.run(application.reconcile_pending(wrong_network)) is None
    assert asyncio.run(application.reconcile_pending(wrong_provider)) is None

    class CodedFailure(RuntimeError):
        code = "coded_failure"

    failures: list[Exception] = [RuntimeError("fallback"), CodedFailure("coded")]

    async def fail_reconcile(*args: object, **kwargs: object) -> None:
        raise failures.pop(0)

    monkeypatch.setattr(application.lifecycle, "reconcile", fail_reconcile)
    assert asyncio.run(application.reconcile_pending(envelope)) is None
    assert application.resource_payload()["stable_error_code"] == "managed_path_reconcile_failed"
    assert asyncio.run(application.reconcile_pending(envelope)) is None
    assert application.resource_payload()["stable_error_code"] == "coded_failure"

    def fail_status(*args: object, **kwargs: object) -> None:
        raise RuntimeError("status unavailable")

    monkeypatch.setattr(application.lifecycle, "get_path_status", fail_status)
    assert (
        application.current_managed_path_status().stable_error_code
        == "managed_path_status_unavailable"
    )
    application.close()


def test_status_sink_redacts_both_path_status_shapes() -> None:
    network_id = NetworkId.new()
    node_id = NodeId.new()
    plan_hash = f"sha256:{'a' * 64}"

    class Reporter:
        def __init__(self) -> None:
            self.statuses: list[NetworkPathStatus] = []

        async def report_path_status(self, status: NetworkPathStatus) -> None:
            self.statuses.append(status)

    evidence = DirectPathEvidence(
        network_id=network_id,
        node_id=node_id,
        plan_hash=plan_hash,
        authorization_revision=1,
        provider=ProviderKind.WINDOWS,
        revision=1,
        target_host_hash=f"sha256:{'b' * 64}",
        target_port=51820,
        route_identity_hash=f"sha256:{'c' * 64}",
        candidate_count=0,
        verified=False,
        stable_error_code=DirectPathErrorCode.ENDPOINT_UNREACHABLE,
        source="fake",
        observed_at=NOW,
        expires_at=NOW + timedelta(seconds=180),
        last_handshake_at=NOW,
    )

    def managed_status(
        current_evidence: DirectPathEvidence | None,
        *,
        source: str = "none",
        freshness: ManagedPathFreshness = ManagedPathFreshness.UNVERIFIED,
    ) -> ManagedPathStatus:
        return ManagedPathStatus(
            network_id=network_id,
            node_id=node_id,
            revision=1,
            plan_hash=plan_hash,
            authorization_revision=1,
            provider=ProviderKind.WINDOWS,
            authorization_state=ManagedPathAuthorizationState.UNKNOWN,
            path_type=NetworkPathType.STATIC,
            evidence=current_evidence,
            source=source,
            freshness=freshness,
            candidate_count=0,
            observed_at=current_evidence.observed_at if current_evidence is not None else None,
            refreshed_at=current_evidence.observed_at if current_evidence is not None else None,
            expires_at=current_evidence.expires_at if current_evidence is not None else None,
            journal_sequence=0,
            updated_at=NOW,
        )

    async def scenario() -> Reporter:
        reporter = Reporter()
        await _CredentialedPathStatusSink(object()).publish(
            NetworkPathStatus(
                network_id=network_id,
                node_id=node_id,
                revision=1,
                path_type="static",
                candidate_count=0,
            ),
            idempotency_key="ignored",
        )
        sink = _CredentialedPathStatusSink(reporter)
        await sink.publish(
            NetworkPathStatus(
                network_id=network_id,
                node_id=node_id,
                revision=1,
                path_type="static",
                candidate_count=0,
            ),
            idempotency_key="network",
        )
        await sink.publish(managed_status(None), idempotency_key="none")
        await sink.publish(
            managed_status(evidence, source="fake", freshness=ManagedPathFreshness.UNVERIFIED),
            idempotency_key="evidence",
        )
        no_handshake = evidence.model_copy(update={"last_handshake_at": None})
        await sink.publish(
            managed_status(no_handshake, source="fake", freshness=ManagedPathFreshness.UNVERIFIED),
            idempotency_key="no-handshake",
        )
        return reporter

    reporter = asyncio.run(scenario())
    assert len(reporter.statuses) == 4


def test_managed_path_validation_helpers_reject_unsafe_clock() -> None:
    class Coded(RuntimeError):
        code = "stable"

    assert _stable_error_code(Coded(), "fallback") == "stable"
    assert _stable_error_code(RuntimeError(), "fallback") == "fallback"
    with pytest.raises(ValueError, match="时钟"):
        _utc(datetime(2026, 7, 26, 12, 0))


def test_managed_application_attaches_one_shared_lifecycle_to_three_domains(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from tests.agent.test_managed_application import config as managed_config

    node_id = NodeId.new()
    config = managed_config(node_id)
    FileManagedNodeConfigRepository(tmp_path / "managed-node.json").save(config)
    ready = ManagedNodeStatus(
        configured=True,
        enabled=True,
        state=ManagedNodeState.READY,
        schema_version=config.schema_version,
        network_id=config.network_id,
        node_id=config.node_id,
        platform=config.platform,
        credential_configured=True,
    )

    def fake_managed_node_status(*args: object, **kwargs: object) -> ManagedNodeStatus:
        del args, kwargs
        return ready

    monkeypatch.setattr(
        "tunnelminion.agent.managed_application.managed_node_status",
        fake_managed_node_status,
    )
    provider = InMemoryNetworkProvider(observation())
    adapter = cast(CollectionAdapter, object())
    application = build_managed_node_application(
        tmp_path,
        node_id,
        config.platform,
        ToolRegistry(),
        adapter,
        adapter,
        adapter,
        coordinator_transport=cast(CoordinatorTransport, object()),
        network_transport=cast(ManagedNetworkSyncTransport, object()),
        managed_path_platform_factory=lambda data_dir, ledger: _platform(provider),
    )

    assert application.managed_path is not None
    assert application.network is not None
    assert application.network.managed_path is application.managed_path
    assert len(application.runtime.status.loops) == 3  # type: ignore[union-attr]
    application.network.attach_managed_path(application.managed_path)
    with pytest.raises(ValueError, match="多个 managed path"):
        application.network.attach_managed_path(cast(ManagedPathApplication, object()))
    application.close()


def test_platform_factories_share_capability_shape_without_running_commands(
    tmp_path: Path,
) -> None:
    envelope, _ = signed()
    policy = PathProbePolicy(
        approved_networks=("10.203.0.2/32",),
        approved_ports=(18889,),
    )
    values = (
        (build_windows_managed_path_platform, ProviderKind.WINDOWS),
        (build_macos_managed_path_platform, ProviderKind.MACOS),
    )
    for index, (factory, provider_kind) in enumerate(values):
        root = tmp_path / str(index)
        ledger = SQLiteManagedResourceLedger(root / "ledger.sqlite3")
        dependencies = factory(root, ledger)
        assert dependencies.provider_kind is provider_kind
        assert dependencies.capabilities.provider is provider_kind
        assert dependencies.capabilities.mode is ProviderMode.OBSERVE_ONLY
        assert dependencies.capabilities.provider_apply_available is False
        probe = dependencies.probe_factory(envelope.config, policy)
        assert isinstance(probe, PlatformPathProbe)


def test_macos_tool_path_supports_apple_silicon_homebrew(tmp_path: Path) -> None:
    apple_silicon = Path("/opt/homebrew/bin/wg")

    selected = macos_tool_path(
        tmp_path,
        "wg",
        "/usr/local/bin/wg",
        str(apple_silicon),
        platform_name="darwin",
        path_exists=lambda path: path == apple_silicon,
    )

    assert selected == apple_silicon


def test_macos_factory_accepts_fixed_stage_runner_and_paths(tmp_path: Path) -> None:
    class FixedRunner:
        async def run(self, command: tuple[str, ...], timeout_seconds: float) -> CommandResult:
            del command, timeout_seconds
            return CommandResult(returncode=0, stdout="", stderr="")

    paths = MacOSProviderPaths(
        wg=tmp_path / "tools" / "wg",
        wg_quick=tmp_path / "tools" / "wg-quick",
        ifconfig=tmp_path / "system" / "ifconfig",
        netstat=tmp_path / "system" / "netstat",
        config_root=tmp_path / "configs",
    )
    ledger = SQLiteManagedResourceLedger(tmp_path / "ledger.sqlite3")

    dependencies = build_macos_managed_path_platform(
        tmp_path,
        ledger,
        paths=paths,
        command_runner=FixedRunner(),
    )

    assert dependencies.provider_kind is ProviderKind.MACOS
    assert dependencies.capabilities.mode is ProviderMode.OBSERVE_ONLY


class _RecordingProbe:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    async def probe(self, **kwargs: object) -> DirectPathEvidence:
        self.calls.append(kwargs)
        values = kwargs
        return DirectPathEvidence(
            network_id=cast(NetworkId, values["network_id"]),
            node_id=cast(NodeId, values["node_id"]),
            plan_hash=cast(str, values["plan_hash"]),
            authorization_revision=cast(int, values["revision"]),
            provider=ProviderKind.WINDOWS,
            revision=cast(int, values["revision"]),
            target_host_hash=canonical_sha256({"host": values["target_host"]}),
            target_port=cast(int, values["target_port"]),
            route_identity_hash=canonical_sha256({"host_route": values["expected_host_route"]}),
            candidate_count=len(cast(tuple[object, ...], values["candidates"])),
            verified=False,
            stable_error_code=DirectPathErrorCode.ENDPOINT_UNREACHABLE,
            source="fake",
            observed_at=cast(datetime, values["now"]),
            expires_at=cast(datetime, values["now"]) + timedelta(seconds=180),
        )


def test_shared_verifier_uses_structured_candidates_and_safe_route_fallback() -> None:
    envelope, _ = signed()
    provider = InMemoryNetworkProvider(observation())
    plan = asyncio.run(
        provider.plan(
            action=NetworkAction.CREATE,
            desired=envelope.config,
            observed=observation(),
            ownership=None,
        )
    )
    probe = _RecordingProbe()

    def probe_factory(
        _desired: DesiredNetworkConfig,
        _policy: PathProbePolicy,
    ) -> PlatformPathProbe:
        return cast(PlatformPathProbe, probe)

    verifier = PlatformManagedPathVerifier(cast(ManagedPathProbeFactory, probe_factory))

    first = asyncio.run(verifier.verify(plan, now=NOW))
    assert probe.calls[0]["target_host"] == "203.0.113.10"
    assert probe.calls[0]["target_port"] == 18889
    assert first.candidate_count == 1

    no_candidates = envelope.model_copy(
        update={
            "config": envelope.config.model_copy(
                update={"peers": (envelope.config.peers[0].model_copy(update={"candidates": ()}),)}
            )
        }
    )
    no_candidate_plan = asyncio.run(
        provider.plan(
            action=NetworkAction.CREATE,
            desired=no_candidates.config,
            observed=observation(),
            ownership=None,
        )
    )
    asyncio.run(verifier.verify(no_candidate_plan, now=NOW))
    assert probe.calls[1]["target_port"] == 51820
    assert probe.calls[1]["candidates"] == ()


def test_network_loop_consumes_pending_at_managed_path_safe_point(tmp_path: Path) -> None:
    class RecordingManagedPath:
        def __init__(self) -> None:
            self.envelopes: list[object] = []
            self.checkpoints = 0

        async def reconcile_pending(self, envelope: object) -> None:
            self.envelopes.append(envelope)

        def assert_no_secret_material(self) -> None:
            self.checkpoints += 1

    async def scenario() -> None:
        envelope, key = signed()
        transport = FakeNetworkSyncTransport(key, (envelope,))
        synchronizer, store, _ = build_sync(tmp_path, transport, sync_interval=0.01)
        managed_path = RecordingManagedPath()
        loop = ManagedNetworkSyncLoop(
            synchronizer,
            store,
            managed_path=cast(ManagedPathApplication, managed_path),
        )
        stop = asyncio.Event()
        task = asyncio.create_task(loop.run(stop))
        for _ in range(200):
            if managed_path.envelopes:
                break
            await asyncio.sleep(0.001)
        stop.set()
        await task
        await loop.checkpoint()
        assert managed_path.envelopes == [envelope]
        assert managed_path.checkpoints == 1

    asyncio.run(scenario())
