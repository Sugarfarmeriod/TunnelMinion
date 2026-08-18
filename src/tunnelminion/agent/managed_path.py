"""Windows/macOS 常规应用共享的 managed path 依赖与状态组装。"""

from __future__ import annotations

import ipaddress
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol, cast

from pydantic import BaseModel, ConfigDict, Field, JsonValue

from tunnelminion.domain.identifiers import NetworkId, NodeId
from tunnelminion.network.contracts import (
    DesiredNetworkConfig,
    NetworkAction,
    NetworkPlan,
    ProviderKind,
    ProviderMode,
    SignedDesiredConfig,
)
from tunnelminion.network.governance import (
    LocalControlAuthority,
    ManagedPathLifecycle,
    ManagedPathStatusSink,
    NetworkAcknowledgementSink,
    NetworkOperationPolicy,
    NetworkPathStatus,
    NetworkPathStatusSink,
    SQLiteNetworkAuthorizationRepository,
    SQLiteNetworkGovernanceStore,
)
from tunnelminion.network.ledger import SQLiteManagedResourceLedger
from tunnelminion.network.path_controller import (
    DirectPathController,
    DirectPathEvidence,
    NetworkPathType,
    PathControllerPolicy,
    PathSelection,
)
from tunnelminion.network.path_probe import PathProbePolicy, PlatformPathProbe
from tunnelminion.network.path_status import (
    ManagedPathAuthorizationState,
    ManagedPathFreshness,
    ManagedPathStatus,
    redacted_managed_path_status_payload,
)
from tunnelminion.network.provider import NetworkProvider


class ManagedPathCapabilityState(BaseModel):
    """平台 Provider/probe 能力的固定脱敏摘要。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    provider: ProviderKind
    mode: ProviderMode
    platform_supported: bool
    provider_apply_available: bool
    path_probe_available: bool
    stable_error_code: str | None = Field(default=None, min_length=1, max_length=128)


class ManagedPathProbeFactory(Protocol):
    """按签名 desired 配置创建只读 PathProbe。"""

    def __call__(
        self,
        desired: DesiredNetworkConfig,
        policy: PathProbePolicy,
    ) -> PlatformPathProbe: ...  # pragma: no cover - Protocol 无运行时实现


@dataclass(frozen=True, slots=True)
class ManagedPathPlatformDependencies:
    """平台层唯一可注入的 Provider、probe 和能力状态。"""

    provider: NetworkProvider
    provider_kind: ProviderKind
    capabilities: ManagedPathCapabilityState
    probe_factory: ManagedPathProbeFactory


class ManagedPathPlatformFactory(Protocol):
    """常规应用共享的跨平台依赖工厂边界。"""

    def __call__(
        self,
        data_dir: Path,
        ledger: SQLiteManagedResourceLedger,
    ) -> ManagedPathPlatformDependencies: ...  # pragma: no cover - Protocol 无运行时实现


class _PathStatusReporter(Protocol):
    """已有 Coordinator sink 的路径摘要方法。"""

    async def report_path_status(self, status: NetworkPathStatus) -> None: ...


class PlatformManagedPathVerifier:
    """由 desired 结构化候选驱动平台只读探测，不持有 Provider 写权限。"""

    def __init__(
        self,
        probe_factory: ManagedPathProbeFactory,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        del clock
        self._probe_factory = probe_factory

    async def verify(self, plan: NetworkPlan, *, now: datetime) -> DirectPathEvidence:
        """验证首个结构化 peer 的 host route 与固定目标。"""
        desired = plan.desired
        peer = desired.peers[0]
        expected_host_route = peer.allowed_host_routes[0]
        route = ipaddress.ip_network(expected_host_route, strict=True)
        candidates = peer.candidates
        approved_networks = tuple(
            dict.fromkeys(
                str(
                    ipaddress.ip_network(
                        f"{candidate.host}/{ipaddress.ip_address(candidate.host).max_prefixlen}",
                        strict=True,
                    )
                )
                for candidate in candidates
            )
        ) or (str(route),)
        approved_ports = tuple(dict.fromkeys(candidate.port for candidate in candidates)) or (
            51820,
        )
        policy = PathProbePolicy(
            approved_networks=approved_networks,
            approved_ports=approved_ports,
        )
        candidate = candidates[0] if candidates else None
        target_host = candidate.host if candidate is not None else str(route.network_address)
        target_port = candidate.port if candidate is not None else 51820
        probe = self._probe_factory(desired, policy)
        return await probe.probe(
            network_id=desired.network_id,
            node_id=desired.target_node_id,
            plan_hash=plan.plan_hash,
            authorization_revision=desired.revision,
            revision=desired.revision,
            candidates=candidates,
            expected_host_route=expected_host_route,
            target_host=target_host,
            target_port=target_port,
            now=now,
        )


class _CredentialedPathStatusSink:
    """把生命周期的两个 status sink 收敛到已有 Coordinator 传输。"""

    def __init__(self, reporter: object) -> None:
        self._reporter = reporter

    async def publish(
        self,
        status: NetworkPathStatus | ManagedPathStatus,
        *,
        idempotency_key: str,
    ) -> None:
        del idempotency_key
        report = getattr(self._reporter, "report_path_status", None)
        if not callable(report):
            return
        if isinstance(status, ManagedPathStatus):
            status = NetworkPathStatus(
                network_id=status.network_id,
                node_id=status.node_id,
                revision=status.revision,
                path_type=status.path_type.value,
                candidate_count=status.candidate_count,
                last_handshake_at=(
                    status.evidence.last_handshake_at if status.evidence is not None else None
                ),
                last_probe_at=status.observed_at,
                stable_error_code=status.stable_error_code,
            )
        await cast(_PathStatusReporter, self._reporter).report_path_status(status)


@dataclass(slots=True)
class ManagedPathApplication:
    """常规本地应用持有的唯一 managed path lifecycle。"""

    network_id: NetworkId
    node_id: NodeId
    dependencies: ManagedPathPlatformDependencies
    ledger: SQLiteManagedResourceLedger
    lifecycle: ManagedPathLifecycle
    governance_store: SQLiteNetworkGovernanceStore
    authorization_repository: SQLiteNetworkAuthorizationRepository
    revision_source: Callable[[], int]
    pending_source: Callable[[], SignedDesiredConfig | None]
    clock: Callable[[], datetime]
    _pending: SignedDesiredConfig | None = None
    _last_error_code: str | None = None
    _closed: bool = False

    @property
    def capabilities(self) -> ManagedPathCapabilityState:
        """返回平台能力的脱敏只读视图。"""
        return self.dependencies.capabilities

    @property
    def provider_kind(self) -> ProviderKind:
        """返回生命周期绑定的 Provider 类型。"""
        return self.dependencies.provider_kind

    async def reconcile_pending(self, envelope: SignedDesiredConfig) -> object | None:
        """消费同步器 pending；无 managed 能力或授权时不执行 Provider 写入。"""
        self._pending = envelope
        desired = envelope.config
        if desired.network_id != self.network_id or desired.target_node_id != self.node_id:
            self._last_error_code = "identity_mismatch"
            return None
        if desired.provider is not self.dependencies.provider_kind:
            self._last_error_code = "provider_mismatch"
            return None
        if not self.capabilities.provider_apply_available:
            self._last_error_code = self.capabilities.stable_error_code or "provider_unavailable"
            return None
        entry = self.ledger.get(self.network_id, self.node_id)
        action = NetworkAction.UPDATE if entry is not None else NetworkAction.CREATE
        ownership = entry.ownership if entry is not None else None
        try:
            record = await self.lifecycle.reconcile(
                envelope,
                action=action,
                ownership=ownership,
            )
        except Exception as exc:
            self._last_error_code = _stable_error_code(exc, "managed_path_reconcile_failed")
            return None
        self._last_error_code = record.stable_error_code
        return record

    def current_managed_path_status(self) -> ManagedPathStatus:
        """读取持久化 lifecycle 状态；尚无计划时返回显式 unverified 投影。"""
        revision = self._current_revision()
        try:
            status = self.lifecycle.get_path_status(self.network_id, self.node_id, revision)
        except Exception as exc:
            self._last_error_code = _stable_error_code(exc, "managed_path_status_unavailable")
            status = None
        if status is not None:
            return status
        return ManagedPathStatus(
            network_id=self.network_id,
            node_id=self.node_id,
            revision=revision,
            plan_hash=f"sha256:{'0' * 64}",
            authorization_revision=revision,
            provider=self.provider_kind,
            authorization_state=(
                ManagedPathAuthorizationState.AWAITING_AUTHORIZATION
                if self._pending_config() is not None
                else ManagedPathAuthorizationState.UNKNOWN
            ),
            path_type=NetworkPathType.STATIC,
            source="none",
            freshness=ManagedPathFreshness.UNVERIFIED,
            candidate_count=0,
            stable_error_code=self._last_error_code,
            journal_sequence=0,
            updated_at=_utc(datetime.now(UTC)),
        )

    def resource_payload(self) -> dict[str, JsonValue]:
        """生成资源 API 可直接消费的持久化、脱敏状态。"""
        status = self.current_managed_path_status().at(
            _utc(self.clock()),
            stale_error_code="path_evidence_stale",
        )
        capabilities = cast(dict[str, JsonValue], self.capabilities.model_dump(mode="json"))
        payload = cast(
            dict[str, JsonValue],
            redacted_managed_path_status_payload(status),
        )
        payload["configured"] = True
        payload["capabilities"] = capabilities
        return payload

    def path_selection(self) -> PathSelection | None:
        """兼容旧资源路由的只读选择回调。"""
        status = self.current_managed_path_status()
        return status.selection

    def path_evidence(self) -> DirectPathEvidence | None:
        """兼容旧资源路由的只读 evidence 回调。"""
        status = self.current_managed_path_status()
        return status.evidence

    def path_authorization(self) -> str:
        """返回严格受控的公开授权状态。"""
        status = self.current_managed_path_status()
        return status.authorization_state.value

    def assert_no_secret_material(self) -> None:
        """对 managed path 账本执行非秘密断言。"""
        self.ledger.assert_no_secret_material()

    def close(self) -> None:
        """关闭 lifecycle 持有的本地 SQLite 句柄。"""
        if self._closed:
            return
        self._closed = True
        self.governance_store.close()
        self.authorization_repository.close()

    def __del__(self) -> None:
        """在未进入 FastAPI lifespan 的组装验收中释放 SQLite 句柄。"""
        with suppress(Exception):
            self.close()

    def _pending_config(self) -> SignedDesiredConfig | None:
        return self._pending or self.pending_source()

    def _current_revision(self) -> int:
        pending = self._pending_config()
        if pending is not None:
            return pending.config.revision
        return max(1, self.revision_source())


def build_managed_path_application(
    data_dir: Path,
    network_id: NetworkId,
    node_id: NodeId,
    platform_factory: ManagedPathPlatformFactory,
    *,
    revision_source: Callable[[], int],
    pending_source: Callable[[], SignedDesiredConfig | None],
    acknowledgements: NetworkAcknowledgementSink | None = None,
    commit_last_known_good: Callable[[SignedDesiredConfig], object] | None = None,
    clock: Callable[[], datetime] | None = None,
) -> ManagedPathApplication:
    """用同一生命周期语义装配 Windows/macOS 常规应用。"""
    current_clock = clock or (lambda: datetime.now(UTC))
    ledger = SQLiteManagedResourceLedger(data_dir / "managed-network-ledger.sqlite3")
    dependencies = platform_factory(data_dir, ledger)
    authorization_repository = SQLiteNetworkAuthorizationRepository(
        data_dir / "governance.sqlite3",
        control=LocalControlAuthority(),
    )
    governance_store = SQLiteNetworkGovernanceStore(
        data_dir / "governance.sqlite3",
        authorization_repository=authorization_repository,
    )
    initial = PathSelection(
        path_type=NetworkPathType.STATIC,
        provider=dependencies.provider_kind,
        revision=1,
        candidate_count=0,
        consecutive_failures=0,
        consecutive_successes=0,
        selected_at=_utc(current_clock()),
        last_evidence_at=_utc(current_clock()),
    )
    reporter = (
        _CredentialedPathStatusSink(acknowledgements)
        if acknowledgements is not None
        and callable(getattr(acknowledgements, "report_path_status", None))
        else None
    )
    lifecycle = ManagedPathLifecycle(
        dependencies.provider,
        NetworkOperationPolicy(),
        governance_store,
        acknowledgements,
        path_verifier=PlatformManagedPathVerifier(
            dependencies.probe_factory,
            clock=current_clock,
        ),
        path_controller=DirectPathController(
            PathControllerPolicy(),
            initial=initial,
        ),
        path_status_sink=cast(NetworkPathStatusSink | None, reporter),
        managed_path_status_sink=cast(ManagedPathStatusSink | None, reporter),
        ledger=ledger,
        clock=current_clock,
        commit_last_known_good=commit_last_known_good,
    )
    return ManagedPathApplication(
        network_id=network_id,
        node_id=node_id,
        dependencies=dependencies,
        ledger=ledger,
        lifecycle=lifecycle,
        governance_store=governance_store,
        authorization_repository=authorization_repository,
        revision_source=revision_source,
        pending_source=pending_source,
        clock=current_clock,
    )


def _stable_error_code(error: Exception, fallback: str) -> str:
    code = getattr(error, "code", None)
    return code if isinstance(code, str) and code else fallback


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("managed path 时钟必须包含时区")
    return value.astimezone(UTC)


__all__ = [
    "ManagedPathApplication",
    "ManagedPathCapabilityState",
    "ManagedPathPlatformDependencies",
    "ManagedPathPlatformFactory",
    "ManagedPathProbeFactory",
    "PlatformManagedPathVerifier",
    "build_managed_path_application",
]
