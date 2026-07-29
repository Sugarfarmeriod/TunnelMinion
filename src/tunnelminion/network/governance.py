"""受管网络专用的 L3 本机授权、执行、回滚与恢复工作流。"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import sqlite3
from collections.abc import Callable
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Protocol, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from tunnelminion.domain.identifiers import AuthorizationId, NetworkId, NodeId, ResourceId
from tunnelminion.network.contracts import (
    AcknowledgementStage,
    ApprovedRouteOverlap,
    ManagedResourceOwnership,
    NetworkAcknowledgement,
    NetworkAction,
    NetworkErrorCode,
    NetworkPlan,
    ProviderKind,
    ProviderReceipt,
    ReceiptStatus,
    RelayRole,
    SignedDesiredConfig,
    VerificationResult,
    canonical_sha256,
)
from tunnelminion.network.provider import NetworkProvider
from tunnelminion.tools.contracts import ToolCancellationToken

_SECRET_FRAGMENTS = (
    "private_key",
    "preshared_key",
    "authorization:",
    "bearer ",
)


class NetworkGovernancePhase(StrEnum):
    """本机 L3 网络操作的持久化阶段。"""

    AWAITING_AUTHORIZATION = "awaiting_authorization"
    AUTHORIZED = "authorized"
    APPLYING = "applying"
    VERIFYING = "verifying"
    VERIFIED = "verified"
    ROLLED_BACK = "rolled_back"
    OWNERSHIP_CONFLICT = "ownership_conflict"
    MANUAL_INTERVENTION = "manual_intervention"
    CANCELLED = "cancelled"


class NetworkPolicyAction(StrEnum):
    """L3 网络策略的确定性决定。"""

    EXECUTE = "execute"
    AWAIT_AUTHORIZATION = "await_authorization"
    REFUSE = "refuse"


class NetworkAuthorizationScope(BaseModel):
    """绑定完整变化面的不可变 L3 网络授权范围。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    network_id: NetworkId
    node_id: NodeId
    provider: ProviderKind
    action: NetworkAction
    ownership_resource_id: ResourceId | None = None
    ownership_fingerprint: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    interface_prefix: str = Field(pattern=r"^tmn-[a-z0-9-]{0,32}$")
    address_pool: str
    allowed_host_routes: frozenset[str] = Field(max_length=256)
    allowed_route_overlaps: frozenset[ApprovedRouteOverlap] = Field(max_length=32)
    peer_node_ids: tuple[NodeId, ...] = Field(min_length=1, max_length=32)
    maximum_peers: int = Field(ge=1, le=32)
    allowed_relay_roles: frozenset[RelayRole] = Field(min_length=1)
    revision: int = Field(ge=1)
    parent_revision: int = Field(ge=0)
    plan_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_scope(self) -> Self:
        ipaddress.ip_network(self.address_pool, strict=True)
        normalized = frozenset(
            str(ipaddress.ip_network(route, strict=True)) for route in self.allowed_host_routes
        )
        if normalized != self.allowed_host_routes:
            raise ValueError("授权 host route 必须使用规范形式")
        if self.maximum_peers < len(self.peer_node_ids):
            raise ValueError("peer 上限不得小于已批准 peer 数量")
        if len({str(node_id) for node_id in self.peer_node_ids}) != len(self.peer_node_ids):
            raise ValueError("授权 peer 节点不得重复")
        return self

    @classmethod
    def from_plan(
        cls,
        plan: NetworkPlan,
        *,
        address_pool: str,
        interface_prefix: str = "tmn-",
    ) -> Self:
        """从本机预览后的确定性计划生成精确授权范围。"""
        routes = frozenset(
            route for peer in plan.desired.peers for route in peer.allowed_host_routes
        )
        relays = frozenset(
            {plan.desired.relay_policy, *(peer.relay_role for peer in plan.desired.peers)}
        )
        ownership = plan.ownership
        ownership_fingerprint = canonical_sha256(
            ownership.model_dump(mode="json") if ownership is not None else {"state": "absent"}
        )
        return cls(
            network_id=plan.desired.network_id,
            node_id=plan.desired.target_node_id,
            provider=plan.desired.provider,
            action=plan.action,
            ownership_resource_id=ownership.resource_id if ownership is not None else None,
            ownership_fingerprint=ownership_fingerprint,
            interface_prefix=interface_prefix,
            address_pool=address_pool,
            allowed_host_routes=routes,
            allowed_route_overlaps=frozenset(plan.desired.allowed_route_overlaps),
            peer_node_ids=tuple(peer.node_id for peer in plan.desired.peers),
            maximum_peers=len(plan.desired.peers),
            allowed_relay_roles=relays,
            revision=plan.desired.revision,
            parent_revision=plan.desired.parent_revision,
            plan_hash=plan.plan_hash,
        )

    def matches(self, plan: NetworkPlan) -> bool:
        """逐维度比较，签名配置或模型文字不能扩大授权。"""
        desired = plan.desired
        address = ipaddress.ip_interface(desired.address).ip
        pool = ipaddress.ip_network(self.address_pool, strict=True)
        routes = frozenset(route for peer in desired.peers for route in peer.allowed_host_routes)
        relays = frozenset({desired.relay_policy, *(peer.relay_role for peer in desired.peers)})
        ownership = plan.ownership
        ownership_fingerprint = canonical_sha256(
            ownership.model_dump(mode="json") if ownership is not None else {"state": "absent"}
        )
        return (
            desired.network_id == self.network_id
            and desired.target_node_id == self.node_id
            and desired.provider is self.provider
            and plan.action is self.action
            and (ownership.resource_id if ownership is not None else None)
            == self.ownership_resource_id
            and ownership_fingerprint == self.ownership_fingerprint
            and desired.interface_name.startswith(self.interface_prefix)
            and address in pool
            and routes <= self.allowed_host_routes
            and frozenset(desired.allowed_route_overlaps) <= self.allowed_route_overlaps
            and {str(peer.node_id) for peer in desired.peers}
            <= {str(node_id) for node_id in self.peer_node_ids}
            and len(desired.peers) <= self.maximum_peers
            and relays <= self.allowed_relay_roles
            and desired.revision == self.revision
            and desired.parent_revision == self.parent_revision
            and plan.plan_hash == self.plan_hash
        )


class NetworkAuthorizationGrant(BaseModel):
    """只能由本机控制面创建和撤销的 L3 授权。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    authorization_id: AuthorizationId
    scope: NetworkAuthorizationScope
    approved_by: str = Field(min_length=1, max_length=256)
    approved_at: datetime
    expires_at: datetime
    revoked_at: datetime | None = None

    @model_validator(mode="after")
    def validate_times(self) -> Self:
        if self.expires_at <= self.approved_at:
            raise ValueError("授权过期时间必须晚于批准时间")
        if self.revoked_at is not None and self.revoked_at < self.approved_at:
            raise ValueError("撤销时间不得早于批准时间")
        return self

    def is_active(self, *, at: datetime) -> bool:
        return self.revoked_at is None and self.approved_at <= at < self.expires_at


class NetworkPolicyDecision(BaseModel):
    """供资源页和审计展示的脱敏策略结果。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    action: NetworkPolicyAction
    code: str = Field(min_length=1, max_length=128)
    authorization_id: AuthorizationId | None = None


class NetworkOperationPolicy:
    """独立于模型、prompt 和普通 Tool Gateway 的 L3 授权表。"""

    def __init__(self) -> None:
        self._grants: dict[str, NetworkAuthorizationGrant] = {}

    def approve(
        self,
        grant: NetworkAuthorizationGrant,
        *,
        local_control: bool,
    ) -> NetworkAuthorizationGrant:
        if not local_control:
            raise PermissionError("L3 网络授权只能由目标节点本地控制面创建")
        self._grants[str(grant.authorization_id)] = grant
        return grant

    def revoke(
        self,
        authorization_id: AuthorizationId,
        *,
        revoked_at: datetime,
        local_control: bool,
    ) -> NetworkAuthorizationGrant:
        if not local_control:
            raise PermissionError("L3 网络授权只能由目标节点本地控制面撤销")
        grant = self._grants[str(authorization_id)]
        revoked = grant.model_copy(update={"revoked_at": revoked_at})
        NetworkAuthorizationGrant.model_validate(revoked.model_dump())
        self._grants[str(authorization_id)] = revoked
        return revoked

    def evaluate(self, plan: NetworkPlan, *, at: datetime) -> NetworkPolicyDecision:
        matching = next(
            (
                grant
                for grant in self._grants.values()
                if grant.is_active(at=at) and grant.scope.matches(plan)
            ),
            None,
        )
        if matching is None:
            return NetworkPolicyDecision(
                action=NetworkPolicyAction.AWAIT_AUTHORIZATION,
                code="local_l3_approval_required",
            )
        return NetworkPolicyDecision(
            action=NetworkPolicyAction.EXECUTE,
            code="local_l3_scope_matched",
            authorization_id=matching.authorization_id,
        )


class NetworkGovernanceRecord(BaseModel):
    """崩溃后可恢复且不含秘密的网络治理记录。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    envelope: SignedDesiredConfig
    plan: NetworkPlan
    phase: NetworkGovernancePhase
    authorization_id: AuthorizationId | None = None
    idempotency_key: str = Field(pattern=r"^netop_[0-9a-f]{64}$")
    receipt: ProviderReceipt | None = None
    verification: VerificationResult | None = None
    updated_at: datetime


class SQLiteNetworkGovernanceStore:
    """持久化 L3 阶段、逐步回执和独立验证结果。"""

    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self._connection = sqlite3.connect(path)
        self._connection.execute(
            """
            CREATE TABLE IF NOT EXISTS network_governance (
                network_id TEXT NOT NULL,
                node_id TEXT NOT NULL,
                revision INTEGER NOT NULL,
                payload TEXT NOT NULL,
                PRIMARY KEY (network_id, node_id, revision)
            )
            """
        )

    def put(self, record: NetworkGovernanceRecord) -> None:
        desired = record.plan.desired
        payload = record.model_dump_json()
        self._reject_secrets(payload)
        with self._connection:
            self._connection.execute(
                """
                INSERT INTO network_governance(network_id, node_id, revision, payload)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(network_id, node_id, revision)
                DO UPDATE SET payload = excluded.payload
                """,
                (str(desired.network_id), str(desired.target_node_id), desired.revision, payload),
            )

    def get(
        self,
        network_id: NetworkId,
        node_id: NodeId,
        revision: int,
    ) -> NetworkGovernanceRecord | None:
        row = self._connection.execute(
            """
            SELECT payload FROM network_governance
            WHERE network_id = ? AND node_id = ? AND revision = ?
            """,
            (str(network_id), str(node_id), revision),
        ).fetchone()
        if row is None:
            return None
        self._reject_secrets(row[0])
        return NetworkGovernanceRecord.model_validate_json(row[0])

    def list_recoverable(self) -> tuple[NetworkGovernanceRecord, ...]:
        rows = self._connection.execute(
            """
            SELECT payload FROM network_governance
            WHERE json_extract(payload, '$.phase') IN ('applying', 'verifying')
            ORDER BY revision
            """
        ).fetchall()
        records = tuple(NetworkGovernanceRecord.model_validate_json(row[0]) for row in rows)
        for row in rows:
            self._reject_secrets(row[0])
        return records

    def assert_no_secret_material(self) -> None:
        rows = self._connection.execute("SELECT payload FROM network_governance").fetchall()
        for row in rows:
            self._reject_secrets(row[0])

    @staticmethod
    def _reject_secrets(payload: str) -> None:
        lowered = payload.lower()
        if any(fragment in lowered for fragment in _SECRET_FRAGMENTS):
            raise ValueError("网络治理存储检测到禁止的秘密字段")


class NetworkAcknowledgementSink(Protocol):
    """发送脱敏配置阶段确认的控制面边界。"""

    async def acknowledge(
        self, acknowledgement: NetworkAcknowledgement
    ) -> None: ...  # pragma: no cover - Protocol 无运行时实现


class NetworkPathStatus(BaseModel):
    """允许同步给 Coordinator 的有限路径摘要。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    network_id: NetworkId
    node_id: NodeId
    revision: int = Field(ge=1)
    path_type: str = Field(pattern=r"^(pending|direct|relayed|static|offline)$")
    candidate_count: int = Field(ge=0, le=8)
    relay_identity_hash: str | None = Field(default=None, pattern=r"^sha256:[0-9a-f]{64}$")
    last_handshake_at: datetime | None = None
    last_probe_at: datetime | None = None
    stable_error_code: str | None = Field(default=None, min_length=1, max_length=128)


class ManagedNetworkGovernanceWorkflow:
    """串行执行已验签 pending config，不接收模型生成的授权。"""

    def __init__(
        self,
        provider: NetworkProvider,
        policy: NetworkOperationPolicy,
        store: SQLiteNetworkGovernanceStore,
        acknowledgements: NetworkAcknowledgementSink,
        *,
        clock: Callable[[], datetime] | None = None,
        commit_last_known_good: Callable[[SignedDesiredConfig], object] | None = None,
    ) -> None:
        self._provider = provider
        self._policy = policy
        self._store = store
        self._acknowledgements = acknowledgements
        self._clock = clock or (lambda: datetime.now(UTC))
        self._commit_last_known_good = commit_last_known_good
        self._lock = asyncio.Lock()

    async def reconcile(
        self,
        envelope: SignedDesiredConfig,
        *,
        action: NetworkAction,
        ownership: ManagedResourceOwnership | None,
        cancellation: ToolCancellationToken | None = None,
    ) -> NetworkGovernanceRecord:
        """预览、授权、apply、独立 verify，并在失败时逆序回滚。"""
        if self._lock.locked():
            raise RuntimeError("受管网络 apply 已在运行")
        token = cancellation or ToolCancellationToken()
        async with self._lock:
            desired = envelope.config
            existing = self._store.get(
                desired.network_id,
                desired.target_node_id,
                desired.revision,
            )
            if existing is not None and existing.phase is NetworkGovernancePhase.VERIFIED:
                await self._ack(existing, AcknowledgementStage.VERIFIED)
                return existing
            if existing is not None and existing.phase in {
                NetworkGovernancePhase.APPLYING,
                NetworkGovernancePhase.VERIFYING,
            }:
                plan = existing.plan
            else:
                observed = await self._provider.observe(desired.interface_name)
                plan = await self._provider.plan(
                    action=action,
                    desired=desired,
                    observed=observed,
                    ownership=ownership,
                )
            decision = self._policy.evaluate(plan, at=self._now())
            key = self._idempotency_key(plan)
            if decision.action is not NetworkPolicyAction.EXECUTE:
                record = NetworkGovernanceRecord(
                    envelope=envelope,
                    plan=plan,
                    phase=NetworkGovernancePhase.AWAITING_AUTHORIZATION,
                    idempotency_key=key,
                    updated_at=self._now(),
                )
                self._store.put(record)
                await self._ack(record, AcknowledgementStage.AWAITING_AUTHORIZATION)
                return record
            record = NetworkGovernanceRecord(
                envelope=envelope,
                plan=plan,
                phase=NetworkGovernancePhase.APPLYING,
                authorization_id=decision.authorization_id,
                idempotency_key=existing.idempotency_key if existing is not None else key,
                receipt=existing.receipt if existing is not None else None,
                updated_at=self._now(),
            )
            self._store.put(record)
            await self._ack(record, AcknowledgementStage.APPLYING)
            if token.cancelled:
                cancelled = record.model_copy(
                    update={"phase": NetworkGovernancePhase.CANCELLED, "updated_at": self._now()}
                )
                self._store.put(cancelled)
                return cancelled
            receipt = await self._provider.apply(
                plan,
                idempotency_key=record.idempotency_key,
                cancellation=token,
            )
            applied = record.model_copy(update={"receipt": receipt, "updated_at": self._now()})
            self._store.put(applied)
            if receipt.status is not ReceiptStatus.APPLIED:
                return await self._rollback(applied, receipt)
            await self._ack(applied, AcknowledgementStage.APPLIED)
            verifying = applied.model_copy(
                update={
                    "phase": NetworkGovernancePhase.VERIFYING,
                    "updated_at": self._now(),
                }
            )
            self._store.put(verifying)
            verification = await self._provider.verify(plan)
            if not verification.succeeded:
                failed = verifying.model_copy(
                    update={"verification": verification, "updated_at": self._now()}
                )
                self._store.put(failed)
                return await self._rollback(failed, receipt)
            verified = verifying.model_copy(
                update={
                    "phase": NetworkGovernancePhase.VERIFIED,
                    "verification": verification,
                    "updated_at": self._now(),
                }
            )
            self._store.put(verified)
            if self._commit_last_known_good is not None:
                self._commit_last_known_good(envelope)
            await self._ack(verified, AcknowledgementStage.VERIFIED)
            return verified

    async def emergency_stop(
        self,
        envelope: SignedDesiredConfig,
        ownership: ManagedResourceOwnership,
        *,
        local_control: bool,
    ) -> NetworkGovernanceRecord:
        """控制面和模型离线时，只停止实时指纹匹配的受管资源。"""
        if not local_control:
            raise PermissionError("紧急停止只能由节点本地控制面确认")
        observed = await self._provider.observe(envelope.config.interface_name)
        if (
            observed.stable_interface_id != ownership.stable_interface_id
            or observed.public_key_hash != ownership.public_key_hash
            or observed.system_fingerprint != ownership.system_fingerprint
        ):
            raise RuntimeError("实时资源与本地所有权账本不匹配")
        plan = await self._provider.plan(
            action=NetworkAction.STOP,
            desired=envelope.config,
            observed=observed,
            ownership=ownership,
        )
        now = self._now()
        record = NetworkGovernanceRecord(
            envelope=envelope,
            plan=plan,
            phase=NetworkGovernancePhase.APPLYING,
            idempotency_key=self._idempotency_key(plan),
            updated_at=now,
        )
        self._store.put(record)
        receipt = await self._provider.apply(
            plan,
            idempotency_key=record.idempotency_key,
            cancellation=ToolCancellationToken(),
        )
        verification = await self._provider.verify(plan)
        phase = (
            NetworkGovernancePhase.VERIFIED
            if receipt.status is ReceiptStatus.APPLIED and verification.succeeded
            else NetworkGovernancePhase.MANUAL_INTERVENTION
        )
        completed = record.model_copy(
            update={
                "phase": phase,
                "receipt": receipt,
                "verification": verification,
                "updated_at": self._now(),
            }
        )
        self._store.put(completed)
        return completed

    async def recover_without_model(self) -> tuple[ProviderReceipt, ...]:
        """不依赖模型或 Coordinator，恢复 Provider 未完成回执。"""
        recovered = await self._provider.recover(cancellation=ToolCancellationToken())
        for record in self._store.list_recoverable():
            matching = next(
                (item for item in recovered if item.plan_hash == record.plan.plan_hash),
                None,
            )
            if matching is None:
                continue
            phase = (
                NetworkGovernancePhase.ROLLED_BACK
                if matching.status is ReceiptStatus.ROLLED_BACK
                else NetworkGovernancePhase.MANUAL_INTERVENTION
            )
            self._store.put(
                record.model_copy(
                    update={"phase": phase, "receipt": matching, "updated_at": self._now()}
                )
            )
        return recovered

    async def _rollback(
        self,
        record: NetworkGovernanceRecord,
        receipt: ProviderReceipt,
    ) -> NetworkGovernanceRecord:
        rolled = await self._provider.rollback(
            record.plan,
            receipt,
            cancellation=ToolCancellationToken(),
        )
        if rolled.status is ReceiptStatus.ROLLED_BACK:
            phase = NetworkGovernancePhase.ROLLED_BACK
            stage = AcknowledgementStage.ROLLED_BACK
        elif rolled.error is not None and rolled.error.code is NetworkErrorCode.OWNERSHIP_CONFLICT:
            phase = NetworkGovernancePhase.OWNERSHIP_CONFLICT
            stage = AcknowledgementStage.OWNERSHIP_CONFLICT
        else:
            phase = NetworkGovernancePhase.MANUAL_INTERVENTION
            stage = AcknowledgementStage.MANUAL_INTERVENTION
        completed = record.model_copy(
            update={"phase": phase, "receipt": rolled, "updated_at": self._now()}
        )
        self._store.put(completed)
        await self._ack(completed, stage)
        return completed

    async def _ack(
        self,
        record: NetworkGovernanceRecord,
        stage: AcknowledgementStage,
    ) -> None:
        receipt_hash = (
            canonical_sha256(record.receipt.model_dump(mode="json"))
            if record.receipt is not None
            else None
        )
        try:
            await self._acknowledgements.acknowledge(
                NetworkAcknowledgement(
                    network_id=record.plan.desired.network_id,
                    node_id=record.plan.desired.target_node_id,
                    revision=record.plan.desired.revision,
                    stage=stage,
                    plan_hash=record.plan.plan_hash,
                    receipt_hash=receipt_hash,
                    acknowledged_at=self._now(),
                )
            )
        except (ConnectionError, TimeoutError):
            # 控制面确认可稍后重放，不能反向决定本机 Provider 的正确性。
            return

    @staticmethod
    def _idempotency_key(plan: NetworkPlan) -> str:
        digest = canonical_sha256(
            {
                "network_id": str(plan.desired.network_id),
                "node_id": str(plan.desired.target_node_id),
                "revision": plan.desired.revision,
                "plan_hash": plan.plan_hash,
            }
        ).removeprefix("sha256:")
        return f"netop_{digest}"

    def _now(self) -> datetime:
        now = self._clock()
        if now.tzinfo is None:
            raise ValueError("治理时钟必须包含时区")
        return now.astimezone(UTC)


def redacted_path_status_payload(status: NetworkPathStatus) -> dict[str, object]:
    """输出固定字段，防止 endpoint、物理接口和完整 route 混入同步。"""
    payload = status.model_dump(mode="json")
    encoded = json.dumps(payload, sort_keys=True)
    if any(fragment in encoded.lower() for fragment in _SECRET_FRAGMENTS):
        raise ValueError("路径状态包含秘密")
    return payload
