"""受管网络专用的 L3 本机授权、执行、回滚与恢复工作流。"""

from __future__ import annotations

import asyncio
import errno
import ipaddress
import json
import re
import secrets
import sqlite3
from collections.abc import Awaitable, Callable, Generator, Mapping
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import NoReturn, Protocol, Self, cast

from pydantic import BaseModel, ConfigDict, Field, model_validator

from tunnelminion.domain.identifiers import AuthorizationId, NetworkId, NodeId, ResourceId
from tunnelminion.network.contracts import (
    AcknowledgementStage,
    ApprovedRouteOverlap,
    ManagedResourceOwnership,
    NetworkAcknowledgement,
    NetworkAction,
    NetworkError,
    NetworkErrorCode,
    NetworkPlan,
    OwnershipState,
    ProviderKind,
    ProviderReceipt,
    ReceiptStatus,
    RelayRole,
    SignedDesiredConfig,
    VerificationResult,
    canonical_sha256,
    network_operation_idempotency_key,
)
from tunnelminion.network.path_controller import (
    DirectPathEvidence,
    NetworkPathType,
    PathSelection,
)
from tunnelminion.network.path_status import (
    MANAGED_PATH_REFRESH_MIN_INTERVAL,
    ManagedPathAuthorizationState,
    ManagedPathFreshness,
    ManagedPathStatus,
    restore_managed_path_status_payload,
    source_category,
)
from tunnelminion.network.path_status import (
    redacted_managed_path_status_payload as _redacted_managed_path_status_payload,
)
from tunnelminion.network.provider import NetworkProvider
from tunnelminion.tools.contracts import ToolCancellationToken

_SECRET_FRAGMENTS = (
    "private_key",
    "preshared_key",
    "authorization:",
    "bearer ",
)
_GRANT_SECRET_KEY_FRAGMENTS = (
    "accesstoken",
    "assertion",
    "credential",
    "password",
    "privatekey",
    "presharedkey",
    "refresh",
    "secret",
    "signature",
    "token",
)


async def _reraise(error: BaseException) -> NoReturn:
    """保留已持久化的异常语义并把控制权交回调用方。"""
    await asyncio.sleep(0)
    raise error


class NetworkGovernancePhase(StrEnum):
    """本机 L3 网络操作的持久化阶段。"""

    OBSERVING = "observing"
    PLANNING = "planning"
    RECHECKING = "rechecking"
    AWAITING_AUTHORIZATION = "awaiting_authorization"
    AUTHORIZED = "authorized"
    APPLYING = "applying"
    APPLIED = "applied"
    VERIFYING = "verifying"
    PROVIDER_VERIFIED = "provider_verified"
    PATH_VERIFYING = "path_verifying"
    PATH_RECONCILING = "path_reconciling"
    PATH_DEGRADED = "path_degraded"
    ROLLING_BACK = "rolling_back"
    ACKNOWLEDGING = "acknowledging"
    VERIFIED = "verified"
    ROLLED_BACK = "rolled_back"
    OWNERSHIP_CONFLICT = "ownership_conflict"
    MANUAL_INTERVENTION = "manual_intervention"
    CANCELLED = "cancelled"
    RECOVERING = "recovering"
    RECOVERY_REQUIRED = "recovery_required"


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
    listen_port: int | None = Field(default=None, ge=1, le=65535)
    peer_node_ids: tuple[NodeId, ...] = Field(min_length=1, max_length=32)
    maximum_peers: int = Field(ge=1, le=32)
    allowed_relay_roles: frozenset[RelayRole] = Field(min_length=1)
    revision: int = Field(ge=1)
    parent_revision: int = Field(ge=0)
    plan_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    observed_fingerprint: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")

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
            listen_port=plan.desired.listen_port,
            peer_node_ids=tuple(peer.node_id for peer in plan.desired.peers),
            maximum_peers=len(plan.desired.peers),
            allowed_relay_roles=relays,
            revision=plan.desired.revision,
            parent_revision=plan.desired.parent_revision,
            plan_hash=plan.plan_hash,
            observed_fingerprint=plan.observed_fingerprint,
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
            and desired.listen_port == self.listen_port
            and {str(peer.node_id) for peer in desired.peers}
            <= {str(node_id) for node_id in self.peer_node_ids}
            and len(desired.peers) <= self.maximum_peers
            and relays <= self.allowed_relay_roles
            and desired.revision == self.revision
            and desired.parent_revision == self.parent_revision
            and plan.plan_hash == self.plan_hash
            and plan.observed_fingerprint == self.observed_fingerprint
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
        for value in (self.approved_at, self.expires_at, self.revoked_at):
            if value is not None and (value.tzinfo is None or value.utcoffset() != timedelta(0)):
                raise ValueError("授权时间必须使用 timezone-aware UTC")
        if self.expires_at <= self.approved_at:
            raise ValueError("授权过期时间必须晚于批准时间")
        if self.revoked_at is not None and self.revoked_at < self.approved_at:
            raise ValueError("撤销时间不得早于批准时间")
        return self

    def is_active(self, *, at: datetime) -> bool:
        return self.revoked_at is None and self.approved_at <= at < self.expires_at


class NetworkAuthorizationStorageError(ValueError):
    """授权仓储无法证明记录可信时使用的稳定 fail-closed 错误。"""

    code = "local_l3_authorization_storage_unavailable"


class NetworkAuthorizationConflictError(NetworkAuthorizationStorageError):
    """稳定授权 ID 已经绑定另一份不可覆盖的授权范围。"""

    code = "local_l3_authorization_conflict"


class _LocalControlRoot:
    """只有本地控制面能持有的私有权限根。"""


class LocalControlCapability:
    """用于 approve/revoke 的本地控制凭证，不允许伪造成布尔值。"""

    __slots__ = ("__root",)

    def __init__(self, root: _LocalControlRoot) -> None:
        self.__root = root

    def belongs_to(self, root: _LocalControlRoot) -> bool:
        return self.__root is root


class KillSwitchCapability:
    """独立 emergency stop 的本地控制凭证，不允许提升普通权限。"""

    __slots__ = ("__root",)

    def __init__(self, root: _LocalControlRoot) -> None:
        self.__root = root

    def belongs_to(self, root: _LocalControlRoot) -> bool:
        return self.__root is root


class LocalControlAuthority:
    """只在本地控制面创建的 capability 发放器。"""

    def __init__(self) -> None:
        self.__root = _LocalControlRoot()

    def authorization_capability(self) -> LocalControlCapability:
        return LocalControlCapability(self.__root)

    def kill_switch_capability(self) -> KillSwitchCapability:
        return KillSwitchCapability(self.__root)

    def accepts_authorization(self, capability: object) -> bool:
        return isinstance(capability, LocalControlCapability) and capability.belongs_to(self.__root)

    def accepts_kill_switch(self, capability: object) -> bool:
        return isinstance(capability, KillSwitchCapability) and capability.belongs_to(self.__root)


class NetworkAuthorizationReadPort(Protocol):
    """供 policy/lifecycle 使用的只读授权端口。"""

    def list_grants(
        self,
        network_id: NetworkId,
        node_id: NodeId,
    ) -> tuple[NetworkAuthorizationGrant, ...]: ...

    def accepts_kill_switch(self, capability: object) -> bool: ...


class SQLiteNetworkAuthorizationReadPort:
    """不暴露 approve/revoke 的 SQLite 只读视图。"""

    def __init__(self, repository: SQLiteNetworkAuthorizationRepository) -> None:
        self._repository = repository

    def list_grants(
        self,
        network_id: NetworkId,
        node_id: NodeId,
    ) -> tuple[NetworkAuthorizationGrant, ...]:
        return self._repository.list_grants(network_id, node_id)

    def accepts_kill_switch(self, capability: object) -> bool:
        return self._repository.accepts_kill_switch(capability)


class SQLiteNetworkAuthorizationRepository:
    """现有网络治理 SQLite 中唯一权威的 L3 授权仓储。"""

    _TABLE = "network_authorization_grants"
    _CLAIM_TABLE = "network_apply_claims"
    _COLUMNS = frozenset({"authorization_id", "network_id", "node_id", "payload"})

    def __init__(
        self,
        path: Path | str | None = None,
        *,
        connection: sqlite3.Connection | None = None,
        control: LocalControlAuthority,
    ) -> None:
        if (path is None) == (connection is None):
            raise ValueError("授权仓储必须提供数据库路径或现有连接")
        self._owns_connection = connection is None
        if connection is None:
            assert path is not None
            if str(path) != ":memory:":
                Path(path).parent.mkdir(parents=True, exist_ok=True)
            self._connection = sqlite3.connect(path, timeout=5)
        else:
            self._connection = connection
        self._control = control
        self._migrate()

    def accepts_kill_switch(self, capability: object) -> bool:
        return self._control.accepts_kill_switch(capability)

    @property
    def read_only(self) -> NetworkAuthorizationReadPort:
        """返回只读端口，避免消费者拿到写方法。"""
        return SQLiteNetworkAuthorizationReadPort(self)

    def approve(
        self,
        grant: NetworkAuthorizationGrant,
        *,
        capability: LocalControlCapability,
    ) -> NetworkAuthorizationGrant:
        """由本机控制面原子保存一次不可覆盖的授权。"""
        if not self._control.accepts_authorization(capability):
            raise PermissionError("L3 网络授权只能由目标节点本地控制面创建")
        payload = self._safe_payload(grant)
        authorization_id = str(grant.authorization_id)
        try:
            with self._transaction():
                rows = self._connection.execute(
                    f"SELECT authorization_id, network_id, node_id, payload FROM {self._TABLE} "
                    "WHERE authorization_id = ?",
                    (authorization_id,),
                ).fetchall()
                if rows:
                    if len(rows) != 1:
                        raise NetworkAuthorizationConflictError("授权 ID 存在冲突记录")
                    existing = self._decode_row(rows[0])
                    if existing != grant:
                        raise NetworkAuthorizationConflictError("授权 ID 已绑定不同授权范围")
                    return existing
                self._connection.execute(
                    f"INSERT INTO {self._TABLE}(authorization_id, network_id, node_id, payload) "
                    "VALUES (?, ?, ?, ?)",
                    (
                        authorization_id,
                        str(grant.scope.network_id),
                        str(grant.scope.node_id),
                        payload,
                    ),
                )
                return grant
        except NetworkAuthorizationStorageError:
            raise

    def revoke(
        self,
        authorization_id: AuthorizationId,
        *,
        revoked_at: datetime,
        capability: LocalControlCapability,
    ) -> NetworkAuthorizationGrant:
        """由本机控制面原子撤销；撤销后的 ID 永不恢复或换绑。"""
        if not self._control.accepts_authorization(capability):
            raise PermissionError("L3 网络授权只能由目标节点本地控制面撤销")
        if revoked_at.tzinfo is None or revoked_at.utcoffset() != timedelta(0):
            raise ValueError("撤销时间必须使用 timezone-aware UTC")
        key = str(authorization_id)
        try:
            with self._transaction():
                rows = self._connection.execute(
                    f"SELECT authorization_id, network_id, node_id, payload FROM {self._TABLE} "
                    "WHERE authorization_id = ?",
                    (key,),
                ).fetchall()
                if len(rows) == 0:
                    raise NetworkAuthorizationStorageError("未找到本机 L3 授权")
                if len(rows) != 1:
                    raise NetworkAuthorizationConflictError("授权 ID 存在冲突记录")
                existing = self._decode_row(rows[0])
                if existing.revoked_at is not None:
                    if existing.revoked_at == revoked_at:
                        return existing
                    raise NetworkAuthorizationConflictError("已撤销授权不可重新写入")
                if revoked_at < existing.approved_at:
                    raise ValueError("撤销时间不得早于批准时间")
                active_claim = self._connection.execute(
                    f"SELECT 1 FROM {self._CLAIM_TABLE} "
                    "WHERE authorization_id=? AND state='active' LIMIT 1",
                    (key,),
                ).fetchone()
                if active_claim is not None:
                    raise NetworkApplyClaimConflictError(
                        "活动 apply claim 必须先完成或进入恢复状态，不能并发撤销授权"
                    )
                revoked = NetworkAuthorizationGrant.model_validate(
                    {**existing.model_dump(mode="python"), "revoked_at": revoked_at}
                )
                payload = self._safe_payload(revoked)
                cursor = self._connection.execute(
                    f"UPDATE {self._TABLE} SET payload = ? "
                    "WHERE authorization_id = ? AND payload = ?",
                    (payload, key, existing.model_dump_json()),
                )
                if cursor.rowcount != 1:
                    raise NetworkAuthorizationConflictError("授权撤销发生并发冲突")
                return revoked
        except NetworkAuthorizationStorageError:
            raise

    def claim_apply(
        self,
        plan: NetworkPlan,
        *,
        authorization_id: AuthorizationId,
        idempotency_key: str,
        now: datetime,
        lease_seconds: int = 30,
        lease_token: str | None = None,
    ) -> NetworkApplyClaim:
        """在同一 SQLite CAS 域内申请写 lease，过期 lease 只能进入不确定态。"""
        current = self._require_utc(now)
        if lease_seconds < 1:
            raise ValueError("apply claim lease 必须为正数")
        token = lease_token or secrets.token_hex(32)
        owner_hash = canonical_sha256({"lease_token": token})
        expires = current + timedelta(seconds=lease_seconds)
        key = str(authorization_id)
        network_id = str(plan.desired.network_id)
        node_id = str(plan.desired.target_node_id)
        try:
            with self._transaction():
                grant_rows = self._connection.execute(
                    f"SELECT authorization_id, network_id, node_id, payload FROM {self._TABLE} "
                    "WHERE authorization_id = ?",
                    (key,),
                ).fetchall()
                if len(grant_rows) != 1:
                    raise NetworkApplyClaimConflictError("apply claim 缺少唯一授权记录")
                grant = self._decode_row(grant_rows[0])
                if (
                    str(grant.scope.network_id) != network_id
                    or str(grant.scope.node_id) != node_id
                    or not grant.is_active(at=current)
                    or not grant.scope.matches(plan)
                ):
                    raise NetworkApplyClaimConflictError("apply claim 授权已撤销或 scope 不匹配")
                authorization_version = canonical_sha256(grant.model_dump(mode="json"))
                existing = self._connection.execute(
                    f"SELECT authorization_id, authorization_version, idempotency_key, plan_hash, "
                    f"lease_owner_hash, lease_expires_at, state, fencing_token "
                    f"FROM {self._CLAIM_TABLE} "
                    "WHERE network_id=? AND node_id=? AND revision=?",
                    (network_id, node_id, plan.desired.revision),
                ).fetchone()
                fencing_token = 1
                if existing is not None:
                    existing_expires = self._parse_utc(str(existing[5]))
                    state = str(existing[6])
                    same_identity = (
                        str(existing[0]) == key
                        and str(existing[1]) == authorization_version
                        and str(existing[2]) == idempotency_key
                        and str(existing[3]) == plan.plan_hash
                    )
                    fencing_token = int(existing[7]) + 1
                    if state == "active":
                        if existing_expires <= current:
                            self._connection.execute(
                                f"UPDATE {self._CLAIM_TABLE} SET state='uncertain' "
                                "WHERE network_id=? AND node_id=? AND revision=? "
                                "AND state='active' AND lease_expires_at=?",
                                (
                                    network_id,
                                    node_id,
                                    plan.desired.revision,
                                    str(existing[5]),
                                ),
                            )
                            raise NetworkApplyClaimConflictError(
                                "apply claim lease 已过期，写结果必须先恢复"
                            )
                        raise NetworkApplyClaimConflictError(
                            "同一 network/node/revision 已有活跃 apply claim"
                        )
                    if state != "released" or not same_identity:
                        raise NetworkApplyClaimConflictError(
                            "apply claim 已进入不可重放状态或绑定发生冲突"
                        )
                    cursor = self._connection.execute(
                        f"UPDATE {self._CLAIM_TABLE} SET lease_owner_hash=?, "
                        "lease_expires_at=?, state='active', fencing_token=? "
                        "WHERE network_id=? AND node_id=? AND revision=? "
                        "AND state='released' AND fencing_token=?",
                        (
                            owner_hash,
                            expires.isoformat(),
                            fencing_token,
                            network_id,
                            node_id,
                            plan.desired.revision,
                            fencing_token - 1,
                        ),
                    )
                    if cursor.rowcount != 1:
                        raise NetworkApplyClaimConflictError("apply claim CAS 更新失败")
                else:
                    self._connection.execute(
                        f"""INSERT INTO {self._CLAIM_TABLE}(
                            network_id, node_id, revision, authorization_id,
                            authorization_version, idempotency_key, plan_hash,
                            lease_owner_hash, lease_expires_at, state, fencing_token
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?)""",
                        (
                            network_id,
                            node_id,
                            plan.desired.revision,
                            key,
                            authorization_version,
                            idempotency_key,
                            plan.plan_hash,
                            owner_hash,
                            expires.isoformat(),
                            fencing_token,
                        ),
                    )
        except NetworkAuthorizationStorageError:
            raise
        return NetworkApplyClaim(
            network_id=plan.desired.network_id,
            node_id=plan.desired.target_node_id,
            revision=plan.desired.revision,
            authorization_id=authorization_id,
            authorization_version=authorization_version,
            idempotency_key=idempotency_key,
            plan_hash=plan.plan_hash,
            lease_token=token,
            lease_expires_at=expires,
            fencing_token=fencing_token,
        )

    def assert_apply_claim(self, claim: NetworkApplyClaim, *, now: datetime) -> None:
        """在 Provider.apply 前再次以 CAS 验证未撤销授权和 lease 版本。"""
        current = self._require_utc(now)
        owner_hash = canonical_sha256({"lease_token": claim.lease_token})
        try:
            with self._transaction():
                row = self._connection.execute(
                    f"SELECT authorization_id, authorization_version, idempotency_key, plan_hash, "
                    f"lease_owner_hash, lease_expires_at, state, fencing_token "
                    f"FROM {self._CLAIM_TABLE} "
                    "WHERE network_id=? AND node_id=? AND revision=?",
                    (str(claim.network_id), str(claim.node_id), claim.revision),
                ).fetchone()
                if row is None or str(row[4]) != owner_hash:
                    raise NetworkApplyClaimConflictError("apply claim 不存在或 owner 已变化")
                if str(row[6]) != "active" or int(row[7]) != claim.fencing_token:
                    raise NetworkApplyClaimConflictError("apply claim fencing 状态已变化")
                if self._parse_utc(str(row[5])) <= current:
                    raise NetworkApplyClaimConflictError("apply claim lease 已过期")
                if (
                    str(row[0]) != str(claim.authorization_id)
                    or str(row[1]) != claim.authorization_version
                    or str(row[2]) != claim.idempotency_key
                    or str(row[3]) != claim.plan_hash
                ):
                    raise NetworkApplyClaimConflictError("apply claim 绑定字段发生冲突")
                grant_rows = self._connection.execute(
                    f"SELECT authorization_id, network_id, node_id, payload FROM {self._TABLE} "
                    "WHERE authorization_id=?",
                    (str(claim.authorization_id),),
                ).fetchall()
                if len(grant_rows) != 1:
                    raise NetworkApplyClaimConflictError("apply claim 授权记录丢失")
                grant = self._decode_row(grant_rows[0])
                if not grant.is_active(at=current):
                    raise NetworkApplyClaimConflictError("apply claim 授权已撤销")
                if canonical_sha256(grant.model_dump(mode="json")) != claim.authorization_version:
                    raise NetworkApplyClaimConflictError("apply claim 授权版本已变化")
        except NetworkAuthorizationStorageError:
            raise

    def renew_apply_claim(
        self,
        claim: NetworkApplyClaim,
        *,
        now: datetime,
        lease_seconds: int = 30,
    ) -> NetworkApplyClaim:
        """在 Provider 长写期间续租；暂停或过期会被 fencing，而不是静默续写。"""
        current = self._require_utc(now)
        if lease_seconds < 1:
            raise ValueError("apply claim lease 必须为正数")
        owner_hash = canonical_sha256({"lease_token": claim.lease_token})
        expires = current + timedelta(seconds=lease_seconds)
        try:
            with self._transaction():
                row = self._connection.execute(
                    f"SELECT authorization_id, authorization_version, idempotency_key, plan_hash, "
                    f"lease_owner_hash, lease_expires_at, state, fencing_token "
                    f"FROM {self._CLAIM_TABLE} WHERE network_id=? AND node_id=? AND revision=?",
                    (str(claim.network_id), str(claim.node_id), claim.revision),
                ).fetchone()
                if row is None or str(row[4]) != owner_hash:
                    raise NetworkApplyClaimConflictError("apply claim 不存在或 owner 已变化")
                if str(row[6]) != "active" or int(row[7]) != claim.fencing_token:
                    raise NetworkApplyClaimConflictError("apply claim fencing 状态已变化")
                if (
                    str(row[0]) != str(claim.authorization_id)
                    or str(row[1]) != claim.authorization_version
                    or str(row[2]) != claim.idempotency_key
                    or str(row[3]) != claim.plan_hash
                ):
                    self._connection.execute(
                        f"UPDATE {self._CLAIM_TABLE} SET state='uncertain' "
                        "WHERE network_id=? AND node_id=? AND revision=? "
                        "AND state='active' AND fencing_token=?",
                        (
                            str(claim.network_id),
                            str(claim.node_id),
                            claim.revision,
                            claim.fencing_token,
                        ),
                    )
                    raise NetworkApplyClaimConflictError("apply claim 绑定字段发生冲突")
                if self._parse_utc(str(row[5])) <= current:
                    self._connection.execute(
                        f"UPDATE {self._CLAIM_TABLE} SET state='uncertain' "
                        "WHERE network_id=? AND node_id=? AND revision=? "
                        "AND state='active' AND fencing_token=?",
                        (
                            str(claim.network_id),
                            str(claim.node_id),
                            claim.revision,
                            claim.fencing_token,
                        ),
                    )
                    raise NetworkApplyClaimConflictError("apply claim lease 已过期")
                grant_rows = self._connection.execute(
                    f"SELECT authorization_id, network_id, node_id, payload FROM {self._TABLE} "
                    "WHERE authorization_id=?",
                    (str(claim.authorization_id),),
                ).fetchall()
                if len(grant_rows) != 1:
                    self._connection.execute(
                        f"UPDATE {self._CLAIM_TABLE} SET state='uncertain' "
                        "WHERE network_id=? AND node_id=? AND revision=? "
                        "AND state='active' AND fencing_token=?",
                        (
                            str(claim.network_id),
                            str(claim.node_id),
                            claim.revision,
                            claim.fencing_token,
                        ),
                    )
                    raise NetworkApplyClaimConflictError("apply claim 授权记录丢失")
                grant = self._decode_row(grant_rows[0])
                if not grant.is_active(at=current):
                    self._connection.execute(
                        f"UPDATE {self._CLAIM_TABLE} SET state='uncertain' "
                        "WHERE network_id=? AND node_id=? AND revision=? "
                        "AND state='active' AND fencing_token=?",
                        (
                            str(claim.network_id),
                            str(claim.node_id),
                            claim.revision,
                            claim.fencing_token,
                        ),
                    )
                    raise NetworkApplyClaimConflictError("apply claim 授权已撤销或过期")
                if canonical_sha256(grant.model_dump(mode="json")) != claim.authorization_version:
                    self._connection.execute(
                        f"UPDATE {self._CLAIM_TABLE} SET state='uncertain' "
                        "WHERE network_id=? AND node_id=? AND revision=? "
                        "AND state='active' AND fencing_token=?",
                        (
                            str(claim.network_id),
                            str(claim.node_id),
                            claim.revision,
                            claim.fencing_token,
                        ),
                    )
                    raise NetworkApplyClaimConflictError("apply claim 授权版本已变化")
                cursor = self._connection.execute(
                    f"UPDATE {self._CLAIM_TABLE} SET lease_expires_at=? "
                    "WHERE network_id=? AND node_id=? AND revision=? "
                    "AND lease_owner_hash=? AND state='active' AND fencing_token=?",
                    (
                        expires.isoformat(),
                        str(claim.network_id),
                        str(claim.node_id),
                        claim.revision,
                        owner_hash,
                        claim.fencing_token,
                    ),
                )
                if cursor.rowcount != 1:
                    raise NetworkApplyClaimConflictError("apply claim 续租 CAS 失败")
        except NetworkAuthorizationStorageError:
            raise
        return NetworkApplyClaim(
            network_id=claim.network_id,
            node_id=claim.node_id,
            revision=claim.revision,
            authorization_id=claim.authorization_id,
            authorization_version=claim.authorization_version,
            idempotency_key=claim.idempotency_key,
            plan_hash=claim.plan_hash,
            lease_token=claim.lease_token,
            lease_expires_at=expires,
            fencing_token=claim.fencing_token,
        )

    def release_apply_claim(self, claim: NetworkApplyClaim) -> None:
        owner_hash = canonical_sha256({"lease_token": claim.lease_token})
        try:
            with self._transaction():
                self._connection.execute(
                    f"UPDATE {self._CLAIM_TABLE} SET state='released' "
                    "WHERE network_id=? AND node_id=? AND revision=? "
                    "AND lease_owner_hash=? AND idempotency_key=? AND plan_hash=? "
                    "AND state='active' AND fencing_token=?",
                    (
                        str(claim.network_id),
                        str(claim.node_id),
                        claim.revision,
                        owner_hash,
                        claim.idempotency_key,
                        claim.plan_hash,
                        claim.fencing_token,
                    ),
                )
        except NetworkAuthorizationStorageError:
            raise

    def fence_apply_claim(self, claim: NetworkApplyClaim) -> None:
        """把未知写结果的 claim 封存为不确定态，禁止任何重放。"""
        owner_hash = canonical_sha256({"lease_token": claim.lease_token})
        try:
            with self._transaction():
                self._connection.execute(
                    f"UPDATE {self._CLAIM_TABLE} SET state='uncertain' "
                    "WHERE network_id=? AND node_id=? AND revision=? "
                    "AND lease_owner_hash=? AND idempotency_key=? AND plan_hash=? "
                    "AND state='active' AND fencing_token=?",
                    (
                        str(claim.network_id),
                        str(claim.node_id),
                        claim.revision,
                        owner_hash,
                        claim.idempotency_key,
                        claim.plan_hash,
                        claim.fencing_token,
                    ),
                )
        except NetworkAuthorizationStorageError:
            raise

    def reap_expired_claims(self, *, now: datetime) -> int:
        current = self._require_utc(now)
        try:
            with self._transaction():
                cursor = self._connection.execute(
                    f"UPDATE {self._CLAIM_TABLE} SET state='uncertain' "
                    "WHERE lease_expires_at <= ? AND state='active'",
                    (current.isoformat(),),
                )
                return int(cursor.rowcount)
        except NetworkAuthorizationStorageError:
            raise

    def resolve_apply_claim(
        self,
        *,
        network_id: NetworkId,
        node_id: NodeId,
        revision: int,
        idempotency_key: str,
        plan_hash: str,
    ) -> None:
        """仅在恢复查询已确定结果后封存 claim，永不把不确定写结果变成可重放。"""
        try:
            with self._transaction():
                self._connection.execute(
                    f"UPDATE {self._CLAIM_TABLE} SET state='resolved' "
                    "WHERE network_id=? AND node_id=? AND revision=? "
                    "AND idempotency_key=? AND plan_hash=? "
                    "AND state='uncertain'",
                    (
                        str(network_id),
                        str(node_id),
                        revision,
                        idempotency_key,
                        plan_hash,
                    ),
                )
        except NetworkAuthorizationStorageError:
            raise

    def has_active_apply_claim(
        self,
        *,
        network_id: NetworkId,
        node_id: NodeId,
        revision: int,
        now: datetime,
    ) -> bool:
        current = self._require_utc(now)
        try:
            row = self._connection.execute(
                f"SELECT state, lease_expires_at FROM {self._CLAIM_TABLE} "
                "WHERE network_id=? AND node_id=? AND revision=?",
                (str(network_id), str(node_id), revision),
            ).fetchone()
        except sqlite3.Error as exc:
            raise NetworkAuthorizationStorageError("apply claim 状态读取失败") from exc
        return (
            row is not None and str(row[0]) == "active" and self._parse_utc(str(row[1])) > current
        )

    @staticmethod
    def _require_utc(value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() != timedelta(0):
            raise ValueError("apply claim 时间必须使用 timezone-aware UTC")
        return value.astimezone(UTC)

    @staticmethod
    def _parse_utc(value: str) -> datetime:
        return SQLiteNetworkAuthorizationRepository._require_utc(datetime.fromisoformat(value))

    def list_grants(
        self,
        network_id: NetworkId,
        node_id: NodeId,
    ) -> tuple[NetworkAuthorizationGrant, ...]:
        """读取并验证整个授权表，再返回目标 network/node 的记录。"""
        return tuple(
            grant
            for grant in self._read_all()
            if grant.scope.network_id == network_id and grant.scope.node_id == node_id
        )

    def get(self, authorization_id: AuthorizationId) -> NetworkAuthorizationGrant | None:
        """读取单个授权；表中任一冲突记录都会使读取 fail closed。"""
        return next(
            (grant for grant in self._read_all() if grant.authorization_id == authorization_id),
            None,
        )

    def assert_no_secret_material(self) -> None:
        """扫描并验证整个授权表，禁止秘密或无法解析的 payload。"""
        self._read_all()

    def close(self) -> None:
        if self._owns_connection:
            self._connection.close()

    def _migrate(self) -> None:
        try:
            with self._connection:
                self._connection.execute(
                    f"""
                    CREATE TABLE IF NOT EXISTS {self._TABLE} (
                        authorization_id TEXT NOT NULL PRIMARY KEY,
                        network_id TEXT NOT NULL,
                        node_id TEXT NOT NULL,
                        payload TEXT NOT NULL
                    )
                    """
                )
                self._connection.execute(
                    f"CREATE INDEX IF NOT EXISTS idx_{self._TABLE}_scope "
                    f"ON {self._TABLE}(network_id, node_id)"
                )
                self._connection.execute(
                    f"""
                    CREATE TABLE IF NOT EXISTS {self._CLAIM_TABLE} (
                        network_id TEXT NOT NULL,
                        node_id TEXT NOT NULL,
                        revision INTEGER NOT NULL,
                        authorization_id TEXT NOT NULL,
                        authorization_version TEXT NOT NULL,
                        idempotency_key TEXT NOT NULL,
                        plan_hash TEXT NOT NULL,
                        lease_owner_hash TEXT NOT NULL,
                        lease_expires_at TEXT NOT NULL,
                        state TEXT NOT NULL DEFAULT 'active',
                        fencing_token INTEGER NOT NULL DEFAULT 1,
                        PRIMARY KEY (network_id, node_id, revision),
                        UNIQUE (idempotency_key)
                    )
                    """
                )
                claim_columns = {
                    str(row[1])
                    for row in self._connection.execute(
                        f"PRAGMA table_info({self._CLAIM_TABLE})"
                    ).fetchall()
                    if len(row) > 1
                }
                if "state" not in claim_columns:
                    self._connection.execute(
                        f"ALTER TABLE {self._CLAIM_TABLE} ADD COLUMN "
                        "state TEXT NOT NULL DEFAULT 'active'"
                    )
                if "fencing_token" not in claim_columns:
                    self._connection.execute(
                        f"ALTER TABLE {self._CLAIM_TABLE} ADD COLUMN "
                        "fencing_token INTEGER NOT NULL DEFAULT 1"
                    )
            self._validate_schema()
        except NetworkAuthorizationStorageError:
            raise
        except sqlite3.Error as exc:
            raise NetworkAuthorizationStorageError("授权表迁移失败") from exc

    def _validate_schema(self) -> None:
        try:
            rows = self._connection.execute(f"PRAGMA table_info({self._TABLE})").fetchall()
        except sqlite3.Error as exc:
            raise NetworkAuthorizationStorageError("授权表结构读取失败") from exc
        metadata = {
            str(row[1]): (str(row[2]).upper(), int(row[3]), int(row[5]))
            for row in rows
            if len(row) >= 6
        }
        if frozenset(metadata) != self._COLUMNS:
            raise NetworkAuthorizationStorageError("授权表结构不可验证")
        for name, (declared_type, not_null, primary_key) in metadata.items():
            expected_primary_key = 1 if name == "authorization_id" else 0
            if declared_type != "TEXT" or not_null != 1 or primary_key != expected_primary_key:
                raise NetworkAuthorizationStorageError("授权表结构不可验证")

    def _read_all(self) -> tuple[NetworkAuthorizationGrant, ...]:
        self._validate_schema()
        try:
            rows = self._connection.execute(
                f"SELECT authorization_id, network_id, node_id, payload "
                f"FROM {self._TABLE} ORDER BY authorization_id"
            ).fetchall()
        except sqlite3.Error as exc:
            raise NetworkAuthorizationStorageError("授权记录读取失败") from exc
        seen: set[str] = set()
        grants: list[NetworkAuthorizationGrant] = []
        for row in rows:
            grant = self._decode_row(row)
            key = str(grant.authorization_id)
            if key in seen:
                raise NetworkAuthorizationConflictError("授权表存在重复授权 ID")
            seen.add(key)
            grants.append(grant)
        return tuple(grants)

    @staticmethod
    def _safe_payload(grant: NetworkAuthorizationGrant) -> str:
        payload = grant.model_dump_json()
        SQLiteNetworkAuthorizationRepository._reject_secret_payload(payload)
        return payload

    @staticmethod
    def _reject_secret_payload(payload: str) -> None:
        try:
            decoded_raw: object = json.loads(payload)
        except (TypeError, ValueError) as exc:
            raise NetworkAuthorizationStorageError("授权 payload 不是合法 JSON") from exc
        if not isinstance(decoded_raw, dict):
            raise NetworkAuthorizationStorageError("授权 payload 格式不可验证")
        decoded = cast(dict[str, object], decoded_raw)
        lowered = payload.casefold()
        if any(fragment in lowered for fragment in _SECRET_FRAGMENTS):
            raise NetworkAuthorizationStorageError("授权存储检测到禁止的秘密字段")

        def walk(value: object) -> None:
            if isinstance(value, dict):
                for key, item in cast(dict[object, object], value).items():
                    compact = re.sub(r"[^a-z0-9]", "", str(key).casefold())
                    if any(fragment in compact for fragment in _GRANT_SECRET_KEY_FRAGMENTS):
                        raise NetworkAuthorizationStorageError("授权存储检测到禁止的秘密字段")
                    walk(item)
            elif isinstance(value, list):
                for item in cast(list[object], value):
                    walk(item)

        walk(decoded)

    @classmethod
    def _decode_row(cls, row: tuple[object, ...]) -> NetworkAuthorizationGrant:
        if len(row) != 4 or not all(isinstance(value, str) for value in row):
            raise NetworkAuthorizationStorageError("授权记录格式不可验证")
        authorization_id, network_id, node_id, payload = row
        assert isinstance(authorization_id, str)
        assert isinstance(network_id, str)
        assert isinstance(node_id, str)
        assert isinstance(payload, str)
        cls._reject_secret_payload(payload)
        try:
            grant = NetworkAuthorizationGrant.model_validate_json(payload)
            if (
                str(grant.authorization_id) != authorization_id
                or str(grant.scope.network_id) != network_id
                or str(grant.scope.node_id) != node_id
            ):
                raise NetworkAuthorizationConflictError("授权索引与 payload 不一致")
            return grant
        except NetworkAuthorizationStorageError:
            raise
        except Exception as exc:
            raise NetworkAuthorizationStorageError("授权记录 payload 不可验证") from exc

    @contextmanager
    def _transaction(self) -> Generator[None, None, None]:
        try:
            self._connection.execute("BEGIN IMMEDIATE")
            yield
            self._connection.commit()
        except NetworkAuthorizationStorageError:
            self._rollback()
            raise
        except sqlite3.Error as exc:
            self._rollback()
            raise NetworkAuthorizationStorageError("授权事务失败") from exc
        except Exception:
            self._rollback()
            raise

    def _rollback(self) -> None:
        with suppress(sqlite3.Error):
            self._connection.rollback()


class NetworkPolicyDecision(BaseModel):
    """供资源页和审计展示的脱敏策略结果。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    action: NetworkPolicyAction
    code: str = Field(min_length=1, max_length=128)
    authorization_id: AuthorizationId | None = None


class NetworkOperationPolicy:
    """独立于模型、prompt 和普通 Tool Gateway 的 L3 授权表。"""

    def __init__(
        self,
        repository: NetworkAuthorizationReadPort | None = None,
    ) -> None:
        self._repository = repository

    def bind(self, repository: NetworkAuthorizationReadPort) -> None:
        """将策略门面绑定到治理 store 的唯一授权仓储。"""
        if self._repository is not None and self._repository is not repository:
            current_owner = getattr(self._repository, "_repository", None)
            incoming_owner = getattr(repository, "_repository", None)
            if current_owner is None or current_owner is not incoming_owner:
                raise ValueError("网络策略不得绑定多个授权仓储")
            return
        self._repository = repository

    def read_port(self) -> NetworkAuthorizationReadPort:
        return self._require_repository()

    def approve(
        self,
        grant: NetworkAuthorizationGrant,
        *,
        capability: LocalControlCapability,
    ) -> NetworkAuthorizationGrant:
        """生产 policy 保持只读；写入必须经过本地控制面 authority。"""
        del grant, capability
        raise PermissionError("生产网络 policy 不持有授权写入 capability")

    def revoke(
        self,
        authorization_id: AuthorizationId,
        *,
        revoked_at: datetime,
        capability: LocalControlCapability,
    ) -> NetworkAuthorizationGrant:
        """生产 policy 保持只读；撤销必须经过本地控制面 authority。"""
        del authorization_id, revoked_at, capability
        raise PermissionError("生产网络 policy 不持有授权写入 capability")

    def _require_repository(self) -> NetworkAuthorizationReadPort:
        if self._repository is None:
            raise NetworkAuthorizationStorageError("网络策略尚未绑定授权仓储")
        return self._repository

    def accepts_kill_switch(self, capability: object) -> bool:
        return self._require_repository().accepts_kill_switch(capability)

    def evaluate(self, plan: NetworkPlan, *, at: datetime) -> NetworkPolicyDecision:
        # 与阶段一 lifecycle 共用同一个只读精确 matcher，避免两套授权语义。
        from tunnelminion.network.managed_path_runtime import (
            ReadOnlyNetworkAuthorizationMatcher,
        )

        match = ReadOnlyNetworkAuthorizationMatcher(self.read_port()).evaluate(plan, at=at)
        if match.authorization_id is None:
            return NetworkPolicyDecision(
                action=NetworkPolicyAction.AWAIT_AUTHORIZATION,
                code=match.code.value,
            )
        return NetworkPolicyDecision(
            action=NetworkPolicyAction.EXECUTE,
            code="local_l3_scope_matched",
            authorization_id=match.authorization_id,
        )


class NetworkApplyClaimConflictError(NetworkAuthorizationStorageError):
    """同一 network/node/revision 的写 claim 发生 CAS 冲突。"""

    code = "network_apply_claim_conflict"


@dataclass(frozen=True, slots=True)
class NetworkApplyClaim:
    """绑定 fencing token 的 SQLite 有效写 lease，持有者只保存 token。"""

    network_id: NetworkId
    node_id: NodeId
    revision: int
    authorization_id: AuthorizationId
    authorization_version: str
    idempotency_key: str
    plan_hash: str
    lease_token: str
    lease_expires_at: datetime
    fencing_token: int


class NetworkProviderJournal(Protocol):
    """受控 Provider journal 的只读恢复操作与计划接口。"""

    def load_operation(
        self,
        *,
        idempotency_key: str,
        plan_hash: str,
    ) -> tuple[SignedDesiredConfig, NetworkPlan] | None: ...


class NetworkKillSwitchProvider(Protocol):
    """紧急停止的独立 Provider 写入边界，不复用普通 apply。"""

    async def emergency_stop(
        self,
        plan: NetworkPlan,
        *,
        idempotency_key: str,
        cancellation: ToolCancellationToken,
    ) -> ProviderReceipt: ...


class NetworkJournalEntry(BaseModel):
    """一次已落盘的生命周期边界；不保存计划正文或秘密。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    sequence: int = Field(ge=0)
    previous_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    entry_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    phase: NetworkGovernancePhase
    idempotency_key: str = Field(pattern=r"^netop_[0-9a-f]{64}$")
    plan_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    occurred_at: datetime
    receipt_hash: str | None = Field(default=None, pattern=r"^sha256:[0-9a-f]{64}$")
    verification_hash: str | None = Field(default=None, pattern=r"^sha256:[0-9a-f]{64}$")
    path_evidence_hash: str | None = Field(default=None, pattern=r"^sha256:[0-9a-f]{64}$")
    stable_error_code: str | None = Field(default=None, min_length=1, max_length=128)

    @model_validator(mode="after")
    def validate_time(self) -> Self:
        if self.occurred_at.tzinfo is None or self.occurred_at.utcoffset() != timedelta(0):
            raise ValueError("生命周期 journal 时间必须使用 timezone-aware UTC")
        expected = canonical_sha256(
            {
                "sequence": self.sequence,
                "previous_hash": self.previous_hash,
                "phase": self.phase.value,
                "idempotency_key": self.idempotency_key,
                "plan_hash": self.plan_hash,
                "occurred_at": self.occurred_at.isoformat(),
                "receipt_hash": self.receipt_hash,
                "verification_hash": self.verification_hash,
                "path_evidence_hash": self.path_evidence_hash,
                "stable_error_code": self.stable_error_code,
            }
        )
        if self.entry_hash != expected:
            raise ValueError("生命周期 journal entry hash 校验失败")
        return self


LifecycleJournalEntry = NetworkJournalEntry


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
    stable_error_code: str | None = Field(default=None, min_length=1, max_length=128)
    path_evidence: DirectPathEvidence | None = None
    path_selection: PathSelection | None = None
    last_known_good_revision: int | None = Field(default=None, ge=1)
    last_refresh_attempt_at: datetime | None = None
    acknowledgement_delivered: bool = False
    path_status_delivered: bool = False
    managed_path_status_delivered: bool = False
    managed_path_status_delivery_hash: str | None = Field(
        default=None,
        pattern=r"^sha256:[0-9a-f]{64}$",
    )
    journal_start_sequence: int = Field(default=0, ge=0)
    journal_previous_hash: str = Field(
        default="sha256:" + "0" * 64,
        pattern=r"^sha256:[0-9a-f]{64}$",
    )
    journal: tuple[NetworkJournalEntry, ...] = Field(default=(), max_length=128)

    @model_validator(mode="after")
    def validate_lifecycle_bindings(self) -> Self:
        if self.updated_at.tzinfo is None or self.updated_at.utcoffset() != timedelta(0):
            raise ValueError("治理记录时间必须使用 timezone-aware UTC")
        if self.last_refresh_attempt_at is not None:
            if (
                self.last_refresh_attempt_at.tzinfo is None
                or self.last_refresh_attempt_at.utcoffset() != timedelta(0)
            ):
                raise ValueError("refresh attempt 时间必须使用 timezone-aware UTC")
            if self.last_refresh_attempt_at > self.updated_at:
                raise ValueError("refresh attempt 不得来自 updated_at 之后")
        previous = self.journal_start_sequence - 1
        previous_hash = self.journal_previous_hash
        for entry in self.journal:
            if entry.sequence != previous + 1:
                raise ValueError("生命周期 journal 序号必须连续")
            if entry.previous_hash != previous_hash:
                raise ValueError("生命周期 journal hash chain 不连续")
            if (
                entry.idempotency_key != self.idempotency_key
                or entry.plan_hash != self.plan.plan_hash
            ):
                raise ValueError("生命周期 journal 必须绑定同一计划")
            previous = entry.sequence
            previous_hash = entry.entry_hash
        if self.receipt is not None:
            if (
                self.receipt.idempotency_key != self.idempotency_key
                or self.receipt.plan_hash != self.plan.plan_hash
                or self.receipt.revision != self.plan.desired.revision
                or self.receipt.provider is not self.plan.desired.provider
            ):
                raise ValueError("Provider receipt binding conflict")
            if self.receipt.observation_after is not None and (
                self.receipt.observation_after.provider is not self.plan.desired.provider
                or self.receipt.observation_after.interface_name != self.plan.desired.interface_name
            ):
                raise ValueError("Provider receipt observation binding conflict")
            if (
                self.receipt.observation_after is None
                and self.receipt.observation_fingerprint != self.plan.observed_fingerprint
            ):
                raise ValueError("Provider receipt observation fingerprint conflict")
        if self.verification is not None:
            if (
                self.verification.idempotency_key != self.idempotency_key
                or self.verification.plan_hash != self.plan.plan_hash
                or self.verification.revision != self.plan.desired.revision
                or self.verification.provider is not self.plan.desired.provider
            ):
                raise ValueError("Provider verification binding conflict")
            if (
                self.verification.observation.provider is not self.plan.desired.provider
                or self.verification.observation.interface_name != self.plan.desired.interface_name
            ):
                raise ValueError("Provider verification observation binding conflict")
        if self.path_evidence is not None:
            if (
                self.path_evidence.network_id != self.plan.desired.network_id
                or self.path_evidence.node_id != self.plan.desired.target_node_id
                or self.path_evidence.plan_hash != self.plan.plan_hash
                or self.path_evidence.authorization_revision != self.plan.desired.revision
            ):
                raise ValueError("path evidence binding conflict")
            if self.path_evidence.provider is not self.plan.desired.provider:
                raise ValueError("路径证据 Provider 必须绑定计划")
            if self.path_evidence.observed_at > self.updated_at:
                raise ValueError("路径证据不得来自未来时间")
        if (
            self.path_selection is not None
            and self.path_selection.revision < self.plan.desired.revision
        ):
            raise ValueError("路径选择 revision 不得早于计划")
        if (
            self.path_selection is not None
            and self.path_selection.path_type is NetworkPathType.DIRECT
        ):
            selection = self.path_selection
            evidence = self.path_evidence
            if evidence is None or (
                selection.network_id != self.plan.desired.network_id
                or selection.node_id != self.plan.desired.target_node_id
                or selection.plan_hash != self.plan.plan_hash
                or selection.authorization_revision != self.plan.desired.revision
                or selection.provider is not self.plan.desired.provider
                or selection.revision != self.plan.desired.revision
                or selection.target_host_hash != evidence.target_host_hash
                or selection.target_port != evidence.target_port
                or selection.route_identity_hash != evidence.route_identity_hash
                or selection.expires_at != evidence.expires_at
            ):
                raise ValueError("direct path selection binding conflict")
        return self


class SQLiteNetworkGovernanceStore:
    """持久化 L3 阶段、逐步回执和独立验证结果。"""

    def __init__(
        self,
        path: Path,
        *,
        authorization_repository: SQLiteNetworkAuthorizationRepository,
    ) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        self._connection = sqlite3.connect(
            path,
            timeout=5,
            check_same_thread=False,
            isolation_level=None,
        )
        self._connection.execute("PRAGMA journal_mode=WAL")
        self._connection.execute("PRAGMA synchronous=NORMAL")
        self._connection.execute("PRAGMA foreign_keys=ON")
        self._connection.execute(
            """
            CREATE TABLE IF NOT EXISTS network_governance (
                network_id TEXT NOT NULL,
                node_id TEXT NOT NULL,
                revision INTEGER NOT NULL,
                payload TEXT NOT NULL,
                identity_hash TEXT NOT NULL DEFAULT '',
                plan_hash TEXT NOT NULL DEFAULT '',
                idempotency_key TEXT NOT NULL DEFAULT '',
                journal_sequence INTEGER NOT NULL DEFAULT -1,
                journal_hash TEXT NOT NULL DEFAULT '',
                PRIMARY KEY (network_id, node_id, revision)
            )
            """
        )
        self._ensure_governance_columns()
        self._connection.execute(
            """
            CREATE TABLE IF NOT EXISTS network_path_status (
                network_id TEXT NOT NULL,
                node_id TEXT NOT NULL,
                revision INTEGER NOT NULL,
                payload TEXT NOT NULL,
                status_hash TEXT NOT NULL,
                journal_sequence INTEGER NOT NULL,
                PRIMARY KEY (network_id, node_id, revision)
            )
            """
        )
        self._records: dict[tuple[str, str, int], NetworkGovernanceRecord] = {}
        self._provider_journal: NetworkProviderJournal | None = None
        self._authorization_repository = authorization_repository

    def close(self) -> None:
        """关闭本地 SQLite 连接，供常规应用 lifespan 安全停止时调用。"""
        self._connection.close()

    def _ensure_governance_columns(self) -> None:
        rows = self._connection.execute("PRAGMA table_info(network_governance)").fetchall()
        columns = {str(row[1]) for row in rows if len(row) > 1}
        additions = {
            "identity_hash": "TEXT NOT NULL DEFAULT ''",
            "plan_hash": "TEXT NOT NULL DEFAULT ''",
            "idempotency_key": "TEXT NOT NULL DEFAULT ''",
            "journal_sequence": "INTEGER NOT NULL DEFAULT -1",
            "journal_hash": "TEXT NOT NULL DEFAULT ''",
        }
        for name, declaration in additions.items():
            if name not in columns:
                self._connection.execute(
                    f"ALTER TABLE network_governance ADD COLUMN {name} {declaration}"
                )

    def bind_provider_journal(self, provider: object) -> None:
        if not hasattr(provider, "load_operation"):
            self._provider_journal = None
            return
        self._provider_journal = cast(NetworkProviderJournal, provider)

    def claim_apply(
        self,
        plan: NetworkPlan,
        *,
        authorization_id: AuthorizationId,
        idempotency_key: str,
        now: datetime,
        lease_seconds: int = 30,
    ) -> NetworkApplyClaim:
        return self._authorization_repository.claim_apply(
            plan,
            authorization_id=authorization_id,
            idempotency_key=idempotency_key,
            now=now,
            lease_seconds=lease_seconds,
        )

    def assert_apply_claim(self, claim: NetworkApplyClaim, *, now: datetime) -> None:
        self._authorization_repository.assert_apply_claim(claim, now=now)

    def renew_apply_claim(
        self,
        claim: NetworkApplyClaim,
        *,
        now: datetime,
        lease_seconds: int = 30,
    ) -> NetworkApplyClaim:
        return self._authorization_repository.renew_apply_claim(
            claim,
            now=now,
            lease_seconds=lease_seconds,
        )

    def release_apply_claim(self, claim: NetworkApplyClaim) -> None:
        self._authorization_repository.release_apply_claim(claim)

    def fence_apply_claim(self, claim: NetworkApplyClaim) -> None:
        self._authorization_repository.fence_apply_claim(claim)

    def reap_expired_claims(self, *, now: datetime) -> int:
        return self._authorization_repository.reap_expired_claims(now=now)

    def resolve_apply_claim(
        self,
        *,
        network_id: NetworkId,
        node_id: NodeId,
        revision: int,
        idempotency_key: str,
        plan_hash: str,
    ) -> None:
        self._authorization_repository.resolve_apply_claim(
            network_id=network_id,
            node_id=node_id,
            revision=revision,
            idempotency_key=idempotency_key,
            plan_hash=plan_hash,
        )

    def has_active_apply_claim(
        self,
        *,
        network_id: NetworkId,
        node_id: NodeId,
        revision: int,
        now: datetime,
    ) -> bool:
        return self._authorization_repository.has_active_apply_claim(
            network_id=network_id,
            node_id=node_id,
            revision=revision,
            now=now,
        )

    @property
    def authorization_read_port(self) -> NetworkAuthorizationReadPort:
        """返回只读授权端口；本地控制 capability 不会从治理 store 泄露。"""
        return self._authorization_repository.read_only

    def list_grants(
        self,
        network_id: NetworkId,
        node_id: NodeId,
    ) -> tuple[NetworkAuthorizationGrant, ...]:
        """兼容只读 matcher 的查询入口，不暴露授权写方法。"""
        return self._authorization_repository.list_grants(network_id, node_id)

    def put(self, record: NetworkGovernanceRecord) -> None:
        prepared = self._prepare_record(record)
        with self._transaction():
            self._put_record_in_transaction(prepared)
        self._records[prepared[3]] = prepared[0]

    def put_journal_step(
        self,
        record: NetworkGovernanceRecord,
        status: ManagedPathStatus,
    ) -> None:
        """在同一 SQLite 事务中提交治理 journal 与 path status。"""
        prepared_record = self._prepare_record(record)
        prepared_status = self._prepare_path_status(status)
        self._validate_journal_step_binding(prepared_record[0], prepared_status[0])
        with self._transaction():
            self._put_record_in_transaction(prepared_record)
            self._put_path_status_in_transaction(prepared_status)
        self._records[prepared_record[3]] = prepared_record[0]

    def get(
        self,
        network_id: NetworkId,
        node_id: NodeId,
        revision: int,
    ) -> NetworkGovernanceRecord | None:
        key = (str(network_id), str(node_id), revision)
        cached = self._records.get(key)
        if cached is not None:
            return cached
        row = self._connection.execute(
            """
            SELECT payload, identity_hash, plan_hash, idempotency_key,
                   journal_sequence, journal_hash
            FROM network_governance
            WHERE network_id = ? AND node_id = ? AND revision = ?
            """,
            (str(network_id), str(node_id), revision),
        ).fetchone()
        if row is None:
            return None
        self._reject_secrets(row[0])
        restored = self._restore_payload(
            row[0],
            stored_identity_hash=row[1],
            stored_plan_hash=row[2],
            stored_idempotency_key=row[3],
            stored_journal_sequence=row[4],
            stored_journal_hash=row[5],
        )
        if restored is not None:
            self._records[key] = restored
        return restored

    def list_recoverable(self) -> tuple[NetworkGovernanceRecord, ...]:
        rows = self._connection.execute(
            """
            SELECT network_id, node_id, revision, payload FROM network_governance
            WHERE json_extract(payload, '$.phase') IN (
                'observing', 'planning', 'authorized', 'rechecking',
                'applying', 'applied', 'verifying', 'provider_verified',
                'path_verifying', 'path_reconciling', 'rolling_back',
                'acknowledging', 'recovering'
            )
            ORDER BY network_id, node_id, revision
            """
        ).fetchall()
        records: list[NetworkGovernanceRecord] = []
        for network_id, node_id, revision, payload in rows:
            self._reject_secrets(payload)
            restored = self.get(NetworkId(str(network_id)), NodeId(str(node_id)), int(revision))
            if restored is not None:
                records.append(restored)
        return tuple(records)

    def put_path_status(self, status: ManagedPathStatus) -> None:
        """以 journal sequence CAS 保存严格脱敏的 path status。"""
        prepared = self._prepare_path_status(status)
        with self._transaction():
            self._put_path_status_in_transaction(prepared)

    def _prepare_record(
        self,
        record: NetworkGovernanceRecord,
    ) -> tuple[NetworkGovernanceRecord, str, str, tuple[str, str, int], int, str]:
        validated = NetworkGovernanceRecord.model_validate_json(record.model_dump_json())
        desired = validated.plan.desired
        payload = self._safe_payload(validated)
        self._reject_secrets(payload)
        identity_hash = self._identity_hash(validated)
        tail_sequence = validated.journal[-1].sequence if validated.journal else -1
        tail_hash = (
            validated.journal[-1].entry_hash
            if validated.journal
            else validated.journal_previous_hash
        )
        key = (str(desired.network_id), str(desired.target_node_id), desired.revision)
        return validated, payload, identity_hash, key, tail_sequence, tail_hash

    def _put_record_in_transaction(
        self,
        prepared: tuple[NetworkGovernanceRecord, str, str, tuple[str, str, int], int, str],
    ) -> None:
        validated, payload, identity_hash, key, tail_sequence, tail_hash = prepared
        current = self._connection.execute(
            "SELECT payload, identity_hash, journal_hash FROM network_governance "
            "WHERE network_id=? AND node_id=? AND revision=?",
            key,
        ).fetchone()
        if current is None:
            self._connection.execute(
                """INSERT INTO network_governance(
                    network_id, node_id, revision, payload, identity_hash,
                    plan_hash, idempotency_key, journal_sequence, journal_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    *key,
                    payload,
                    identity_hash,
                    validated.plan.plan_hash,
                    validated.idempotency_key,
                    tail_sequence,
                    tail_hash,
                ),
            )
            return
        current_payload, current_identity, current_tail_hash = current
        if str(current_identity) != identity_hash:
            raise NetworkAuthorizationConflictError(
                "同一 revision 的 envelope/plan/action/ownership 发生冲突"
            )
        if str(current_payload) == payload:
            return
        incoming_previous_hash = (
            validated.journal[-1].previous_hash
            if validated.journal
            else validated.journal_previous_hash
        )
        if str(current_tail_hash) != incoming_previous_hash:
            raise NetworkAuthorizationConflictError("治理 journal CAS 版本发生冲突")
        cursor = self._connection.execute(
            """UPDATE network_governance SET payload=?, identity_hash=?, plan_hash=?,
                idempotency_key=?, journal_sequence=?, journal_hash=?
                WHERE network_id=? AND node_id=? AND revision=?
                AND identity_hash=? AND journal_hash=?""",
            (
                payload,
                identity_hash,
                validated.plan.plan_hash,
                validated.idempotency_key,
                tail_sequence,
                tail_hash,
                *key,
                identity_hash,
                str(current_tail_hash),
            ),
        )
        if cursor.rowcount != 1:
            raise NetworkAuthorizationConflictError("治理 journal CAS 更新失败")

    def _prepare_path_status(
        self,
        status: ManagedPathStatus,
    ) -> tuple[ManagedPathStatus, str, tuple[str, str, int], str]:
        validated = ManagedPathStatus.model_validate_json(status.model_dump_json())
        payload = validated.model_dump_json()
        self._reject_secrets(payload)
        key = (str(validated.network_id), str(validated.node_id), validated.revision)
        status_hash = canonical_sha256(validated.model_dump(mode="json"))
        return validated, payload, key, status_hash

    def _put_path_status_in_transaction(
        self,
        prepared: tuple[ManagedPathStatus, str, tuple[str, str, int], str],
    ) -> None:
        validated, payload, key, status_hash = prepared
        current = self._connection.execute(
            "SELECT status_hash, journal_sequence FROM network_path_status "
            "WHERE network_id=? AND node_id=? AND revision=?",
            key,
        ).fetchone()
        if current is None:
            self._connection.execute(
                "INSERT INTO network_path_status("
                "network_id, node_id, revision, payload, status_hash, journal_sequence) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (*key, payload, status_hash, validated.journal_sequence),
            )
            return
        current_hash, current_sequence = str(current[0]), int(current[1])
        if current_hash == status_hash and current_sequence == validated.journal_sequence:
            return
        if validated.journal_sequence <= current_sequence:
            raise NetworkAuthorizationConflictError("path status journal sequence 冲突或倒退")
        cursor = self._connection.execute(
            "UPDATE network_path_status SET payload=?, status_hash=?, "
            "journal_sequence=? WHERE network_id=? AND node_id=? AND revision=? "
            "AND status_hash=? AND journal_sequence=?",
            (
                payload,
                status_hash,
                validated.journal_sequence,
                *key,
                current_hash,
                current_sequence,
            ),
        )
        if cursor.rowcount != 1:
            raise NetworkAuthorizationConflictError("path status CAS 更新失败")

    @staticmethod
    def _validate_journal_step_binding(
        record: NetworkGovernanceRecord,
        status: ManagedPathStatus,
    ) -> None:
        desired = record.plan.desired
        expected_sequence = record.journal[-1].sequence if record.journal else 0
        if (
            status.network_id != desired.network_id
            or status.node_id != desired.target_node_id
            or status.revision != desired.revision
            or status.plan_hash != record.plan.plan_hash
            or status.provider is not desired.provider
            or status.journal_sequence != expected_sequence
        ):
            raise NetworkAuthorizationConflictError("治理 journal 与 path status 绑定冲突")

    def get_path_status(
        self,
        network_id: NetworkId,
        node_id: NodeId,
        revision: int,
    ) -> ManagedPathStatus | None:
        """读取并重新验证脱敏 path status；旧/损坏 schema 一律拒绝。"""
        try:
            row = self._connection.execute(
                "SELECT payload, status_hash, journal_sequence FROM network_path_status "
                "WHERE network_id=? AND node_id=? AND revision=?",
                (str(network_id), str(node_id), revision),
            ).fetchone()
        except sqlite3.Error as exc:
            raise ManagedPathLifecycleError("path status schema 不受支持") from exc
        if row is None:
            return None
        payload, stored_hash, stored_sequence = str(row[0]), str(row[1]), int(row[2])
        self._reject_secrets(payload)
        try:
            raw_payload_raw: object = json.loads(payload)
            if not isinstance(raw_payload_raw, dict):
                raise ValueError("path status payload 必须是 object")
            raw_payload = cast(dict[str, object], raw_payload_raw)
            status, schema_version = restore_managed_path_status_payload(payload)
        except Exception as exc:
            raise ManagedPathLifecycleError("path status schema 无法安全恢复") from exc
        if (
            status.network_id != network_id
            or status.node_id != node_id
            or status.revision != revision
            or status.journal_sequence != stored_sequence
            or canonical_sha256(raw_payload) != stored_hash
        ):
            raise ManagedPathLifecycleError("path status identity 或 hash 校验失败")
        if schema_version == 1:
            migrated_payload = status.model_dump_json()
            migrated_hash = canonical_sha256(status.model_dump(mode="json"))
            try:
                with self._transaction():
                    cursor = self._connection.execute(
                        "UPDATE network_path_status SET payload=?, status_hash=? "
                        "WHERE network_id=? AND node_id=? AND revision=? "
                        "AND status_hash=? AND journal_sequence=?",
                        (
                            migrated_payload,
                            migrated_hash,
                            str(network_id),
                            str(node_id),
                            revision,
                            stored_hash,
                            stored_sequence,
                        ),
                    )
                    if cursor.rowcount != 1:
                        raise ManagedPathLifecycleError("path status v1 迁移 CAS 冲突")
            except ManagedPathLifecycleError:
                raise
            except sqlite3.Error as exc:
                raise ManagedPathLifecycleError("path status v1 迁移失败") from exc
        return status

    def assert_no_secret_material(self) -> None:
        rows = self._connection.execute("SELECT payload FROM network_governance").fetchall()
        for row in rows:
            self._reject_secrets(row[0])
        rows = self._connection.execute("SELECT payload FROM network_path_status").fetchall()
        for row in rows:
            self._reject_secrets(row[0])

    @staticmethod
    def _reject_secrets(payload: str) -> None:
        lowered = payload.lower()
        if any(fragment in lowered for fragment in _SECRET_FRAGMENTS):
            raise ValueError("网络治理存储检测到禁止的秘密字段")

        forbidden_keys = (
            '"signature"',
            '"endpoint"',
            '"allowed_host_routes"',
            '"peers"',
            '"peer"',
            '"desired_config"',
        )
        if any(key in lowered for key in forbidden_keys):
            raise ValueError("治理 SQLite 不得保存完整配置或 endpoint/route/peer 正文")

    def _safe_payload(self, record: NetworkGovernanceRecord) -> str:
        desired = record.plan.desired
        payload: dict[str, object] = {
            "schema": 2,
            "network_id": str(desired.network_id),
            "node_id": str(desired.target_node_id),
            "revision": desired.revision,
            "phase": record.phase.value,
            "authorization_id": (
                str(record.authorization_id) if record.authorization_id is not None else None
            ),
            "idempotency_key": record.idempotency_key,
            "plan_hash": record.plan.plan_hash,
            "action": record.plan.action.value,
            "provider": desired.provider.value,
            "observed_fingerprint": record.plan.observed_fingerprint,
            "envelope_hash": canonical_sha256(record.envelope.model_dump(mode="json")),
            "ownership_hash": (
                canonical_sha256(record.plan.ownership.model_dump(mode="json"))
                if record.plan.ownership is not None
                else None
            ),
            "interface_hash": canonical_sha256({"interface": desired.interface_name}),
            "address_hash": canonical_sha256({"address": desired.address}),
            "topology_count": len(desired.peers),
            "listen_port": desired.listen_port,
            "updated_at": record.updated_at.isoformat(),
            "stable_error_code": record.stable_error_code,
            "receipt": self._receipt_summary(record.receipt),
            "verification": self._verification_summary(record.verification),
            "path_evidence": self._path_evidence_summary(record.path_evidence),
            "path_selection": self._path_selection_summary(record.path_selection),
            "last_known_good_revision": record.last_known_good_revision,
            "last_refresh_attempt_at": (
                record.last_refresh_attempt_at.isoformat()
                if record.last_refresh_attempt_at is not None
                else None
            ),
            "acknowledgement_delivered": record.acknowledgement_delivered,
            "path_status_delivered": record.path_status_delivered,
            "managed_path_status_delivered": record.managed_path_status_delivered,
            "managed_path_status_delivery_hash": record.managed_path_status_delivery_hash,
            "journal_start_sequence": record.journal_start_sequence,
            "journal_previous_hash": record.journal_previous_hash,
            "journal": [entry.model_dump(mode="json") for entry in record.journal],
        }
        return json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":"))

    @staticmethod
    def _identity_hash(record: NetworkGovernanceRecord) -> str:
        return canonical_sha256(
            {
                "network_id": str(record.plan.desired.network_id),
                "node_id": str(record.plan.desired.target_node_id),
                "revision": record.plan.desired.revision,
                "plan_hash": record.plan.plan_hash,
                "idempotency_key": record.idempotency_key,
                "action": record.plan.action.value,
                "provider": record.plan.desired.provider.value,
                "ownership_hash": (
                    canonical_sha256(record.plan.ownership.model_dump(mode="json"))
                    if record.plan.ownership is not None
                    else None
                ),
                "envelope_hash": canonical_sha256(record.envelope.model_dump(mode="json")),
            }
        )

    @staticmethod
    def _receipt_summary(receipt: ProviderReceipt | None) -> dict[str, object] | None:
        if receipt is None:
            return None
        return {
            "idempotency_key": receipt.idempotency_key,
            "plan_hash": receipt.plan_hash,
            "revision": receipt.revision,
            "provider": receipt.provider.value,
            "observation_fingerprint": receipt.observation_fingerprint,
            "status": receipt.status.value,
            "step_hashes": [step.system_receipt_hash for step in receipt.steps],
            "error_code": receipt.error.code.value if receipt.error is not None else None,
        }

    @staticmethod
    def _verification_summary(verification: VerificationResult | None) -> dict[str, object] | None:
        if verification is None:
            return None
        return {
            "idempotency_key": verification.idempotency_key,
            "plan_hash": verification.plan_hash,
            "revision": verification.revision,
            "provider": verification.provider.value,
            "observation_fingerprint": verification.observation_fingerprint,
            "succeeded": verification.succeeded,
            "error_code": verification.error.code.value if verification.error is not None else None,
        }

    @staticmethod
    def _path_evidence_summary(evidence: DirectPathEvidence | None) -> dict[str, object] | None:
        if evidence is None:
            return None
        return {
            "network_id": str(evidence.network_id),
            "node_id": str(evidence.node_id),
            "plan_hash": evidence.plan_hash,
            "authorization_revision": evidence.authorization_revision,
            "provider": evidence.provider.value,
            "revision": evidence.revision,
            "target_host_hash": evidence.target_host_hash,
            "target_port": evidence.target_port,
            "path_identity_hash": evidence.route_identity_hash,
            "candidate_count": evidence.candidate_count,
            "verified": evidence.verified,
            "observed_at": evidence.observed_at.isoformat(),
            "expires_at": evidence.expires_at.isoformat(),
            "stable_error_code": (
                evidence.stable_error_code.value if evidence.stable_error_code else None
            ),
        }

    @staticmethod
    def _path_selection_summary(selection: PathSelection | None) -> dict[str, object] | None:
        if selection is None:
            return None
        return {
            "network_id": str(selection.network_id) if selection.network_id else None,
            "node_id": str(selection.node_id) if selection.node_id else None,
            "plan_hash": selection.plan_hash,
            "authorization_revision": selection.authorization_revision,
            "provider": selection.provider.value,
            "revision": selection.revision,
            "path_type": selection.path_type.value,
            "target_host_hash": selection.target_host_hash,
            "target_port": selection.target_port,
            "path_identity_hash": selection.route_identity_hash,
            "expires_at": selection.expires_at.isoformat() if selection.expires_at else None,
            "stable_error_code": (
                selection.stable_error_code.value if selection.stable_error_code else None
            ),
        }

    def _restore_payload(
        self,
        payload: str,
        *,
        stored_identity_hash: object,
        stored_plan_hash: object,
        stored_idempotency_key: object,
        stored_journal_sequence: object,
        stored_journal_hash: object,
    ) -> NetworkGovernanceRecord | None:
        parsed_raw: object = json.loads(payload)
        if not isinstance(parsed_raw, dict):
            raise ManagedPathLifecycleError("治理 SQLite payload schema 不可安全恢复")
        parsed = cast(dict[str, object], parsed_raw)
        if parsed.get("schema") != 2:
            raise ManagedPathLifecycleError("治理 SQLite payload schema 不可安全恢复")
        if self._provider_journal is None:
            return None
        operation = self._provider_journal.load_operation(
            idempotency_key=str(parsed["idempotency_key"]),
            plan_hash=str(parsed["plan_hash"]),
        )
        if operation is None:
            return None
        envelope, plan = operation
        if (
            plan.plan_hash != parsed["plan_hash"]
            or str(plan.desired.network_id) != parsed["network_id"]
            or str(plan.desired.target_node_id) != parsed["node_id"]
            or plan.desired.revision != parsed["revision"]
            or canonical_sha256(envelope.model_dump(mode="json")) != parsed["envelope_hash"]
        ):
            raise ManagedPathLifecycleError("Provider journal 与治理 record 绑定不一致")
        journal_items = cast(list[object], parsed["journal"])
        journal = tuple(NetworkJournalEntry.model_validate(item) for item in journal_items)
        authorization_value = parsed.get("authorization_id")
        restored = NetworkGovernanceRecord(
            envelope=envelope,
            plan=plan,
            phase=NetworkGovernancePhase(str(parsed["phase"])),
            authorization_id=(
                AuthorizationId(str(authorization_value))
                if authorization_value is not None
                else None
            ),
            idempotency_key=str(parsed["idempotency_key"]),
            updated_at=datetime.fromisoformat(str(parsed["updated_at"])),
            stable_error_code=cast(str | None, parsed.get("stable_error_code")),
            last_known_good_revision=cast(int | None, parsed.get("last_known_good_revision")),
            last_refresh_attempt_at=cast(
                datetime | None,
                parsed.get("last_refresh_attempt_at"),
            ),
            acknowledgement_delivered=bool(parsed.get("acknowledgement_delivered", False)),
            path_status_delivered=bool(parsed.get("path_status_delivered", False)),
            managed_path_status_delivered=bool(parsed.get("managed_path_status_delivered", False)),
            managed_path_status_delivery_hash=cast(
                str | None,
                parsed.get("managed_path_status_delivery_hash"),
            ),
            journal_start_sequence=int(cast(int, parsed.get("journal_start_sequence", 0))),
            journal_previous_hash=str(parsed["journal_previous_hash"]),
            journal=journal,
        )
        if not isinstance(stored_identity_hash, str) or not stored_identity_hash:
            raise ManagedPathLifecycleError("治理 record identity 元数据缺失")
        if not isinstance(stored_plan_hash, str) or stored_plan_hash != plan.plan_hash:
            raise ManagedPathLifecycleError("治理 record plan hash 元数据冲突")
        if not isinstance(stored_idempotency_key, str) or stored_idempotency_key != str(
            parsed["idempotency_key"]
        ):
            raise ManagedPathLifecycleError("治理 record 幂等键元数据冲突")
        if not isinstance(stored_journal_sequence, int) or not isinstance(stored_journal_hash, str):
            raise ManagedPathLifecycleError("治理 record journal 元数据格式不可验证")
        tail_sequence = restored.journal[-1].sequence if restored.journal else -1
        tail_hash = (
            restored.journal[-1].entry_hash if restored.journal else restored.journal_previous_hash
        )
        if stored_journal_sequence != tail_sequence or stored_journal_hash != tail_hash:
            raise ManagedPathLifecycleError("治理 record journal 元数据冲突")
        if self._identity_hash(restored) != stored_identity_hash:
            raise ManagedPathLifecycleError("治理 record identity hash 校验失败")
        if not restored.journal or restored.journal[-1].phase is not restored.phase:
            raise ManagedPathLifecycleError("治理 record phase 与 journal 尾部冲突")
        return restored

    @contextmanager
    def _transaction(self) -> Generator[None, None, None]:
        try:
            self._connection.execute("BEGIN IMMEDIATE")
            yield
            self._connection.commit()
        except Exception:
            with suppress(sqlite3.Error):
                self._connection.rollback()
            raise


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


class NetworkPathVerificationSource(Protocol):
    """只接收结构化计划并返回脱敏 path evidence 的读取边界。"""

    async def verify(self, plan: NetworkPlan, *, now: datetime) -> DirectPathEvidence: ...


class NetworkPathController(Protocol):
    """只消费 path evidence 的控制器边界，不持有 Provider 写权限。"""

    @property
    def selection(self) -> PathSelection: ...

    async def reconcile(
        self,
        evidence: DirectPathEvidence,
        *,
        fallback: NetworkPathType = NetworkPathType.STATIC,
    ) -> PathSelection: ...


class NetworkPathStatusSink(Protocol):
    """按固定幂等键接收脱敏 path status 的发布边界。"""

    async def publish(self, status: NetworkPathStatus, *, idempotency_key: str) -> None: ...


class ManagedPathStatusSink(Protocol):
    """接收完整但脱敏的 selection/evidence/freshness 状态投影。"""

    async def publish(
        self,
        status: ManagedPathStatus,
        *,
        idempotency_key: str,
    ) -> None: ...


class NetworkOwnershipLedger(Protocol):
    """崩溃恢复使用的只读所有权账本端口。"""

    def get(
        self,
        network_id: NetworkId,
        node_id: NodeId,
    ) -> object | None: ...


class LifecycleCrashBoundary(StrEnum):
    """fake 验收可注入的崩溃边界。"""

    PLAN = "plan"
    APPLY = "apply"
    VERIFY = "verify"
    ACK = "ack"


class LifecycleInjectedCrash(RuntimeError):
    """只用于隔离 fake 验收，不代表平台进程错误。"""


class ManagedPathLifecycleError(RuntimeError):
    """生命周期无法安全持久化或恢复时的稳定边界错误。"""


class ManagedNetworkGovernanceWorkflow:
    """旧入口的委托适配器；普通生命周期唯一由 ManagedPathLifecycle 执行。"""

    def __init__(
        self,
        provider: NetworkProvider,
        policy: NetworkOperationPolicy,
        store: SQLiteNetworkGovernanceStore,
        acknowledgements: NetworkAcknowledgementSink | None,
        *,
        path_verifier: NetworkPathVerificationSource,
        path_controller: NetworkPathController,
        path_status_sink: NetworkPathStatusSink | None = None,
        managed_path_status_sink: ManagedPathStatusSink | None = None,
        ledger: NetworkOwnershipLedger | None = None,
        clock: Callable[[], datetime] | None = None,
        commit_last_known_good: Callable[[SignedDesiredConfig], object] | None = None,
        crash_after: LifecycleCrashBoundary | None = None,
        apply_lease_seconds: int = 30,
    ) -> None:
        self._lifecycle = ManagedPathLifecycle(
            provider,
            policy,
            store,
            acknowledgements,
            path_verifier=path_verifier,
            path_controller=path_controller,
            path_status_sink=path_status_sink,
            managed_path_status_sink=managed_path_status_sink,
            ledger=ledger,
            clock=clock,
            commit_last_known_good=commit_last_known_good,
            crash_after=crash_after,
            apply_lease_seconds=apply_lease_seconds,
        )

    async def reconcile(
        self,
        envelope: SignedDesiredConfig,
        *,
        action: NetworkAction,
        ownership: ManagedResourceOwnership | None,
        cancellation: ToolCancellationToken | None = None,
    ) -> NetworkGovernanceRecord:
        """委托唯一生命周期实现，避免维护第二套 apply/verify 状态机。"""
        return await self._lifecycle.reconcile(
            envelope,
            action=action,
            ownership=ownership,
            cancellation=cancellation,
        )

    async def recover(self) -> tuple[NetworkGovernanceRecord, ...]:
        """委托唯一恢复实现。"""
        return await self._lifecycle.recover()

    async def recover_without_model(self) -> tuple[ProviderReceipt, ...]:
        """保留旧返回形状，但恢复动作仍完全委托给唯一 lifecycle。"""
        records = await self._lifecycle.recover()
        return tuple(record.receipt for record in records if record.receipt is not None)

    def get_path_status(
        self,
        network_id: NetworkId,
        node_id: NodeId,
        revision: int,
    ) -> ManagedPathStatus | None:
        """委托唯一 lifecycle 的只读状态投影。"""
        return self._lifecycle.get_path_status(network_id, node_id, revision)

    async def refresh_path(
        self,
        network_id: NetworkId,
        node_id: NodeId,
        revision: int,
        *,
        cancellation: ToolCancellationToken | None = None,
    ) -> ManagedPathStatus | None:
        """委托唯一 lifecycle 的只读刷新。"""
        return await self._lifecycle.refresh_path(
            network_id,
            node_id,
            revision,
            cancellation=cancellation,
        )

    async def emergency_stop(
        self,
        envelope: SignedDesiredConfig,
        ownership: ManagedResourceOwnership,
        *,
        capability: KillSwitchCapability,
    ) -> NetworkGovernanceRecord:
        """委托独立、可审计的本地 kill-switch 入口。"""
        return await self._lifecycle.emergency_stop(
            envelope,
            ownership,
            capability=capability,
        )


_LIFECYCLE_UNSET = object()


def _validated_record_update(
    record: NetworkGovernanceRecord,
    updates: Mapping[str, object],
) -> NetworkGovernanceRecord:
    """通过完整模型校验生成生命周期记录，禁止绕过绑定校验的浅复制。"""
    payload = record.model_dump(mode="python")
    payload.update(updates)
    return NetworkGovernanceRecord.model_validate(payload)


class ManagedPathLifecycle:
    """串联授权、Provider 与 path controller 的单写者 fake/平台通用生命周期。"""

    def __init__(
        self,
        provider: NetworkProvider,
        policy: NetworkOperationPolicy,
        store: SQLiteNetworkGovernanceStore,
        acknowledgements: NetworkAcknowledgementSink | None,
        *,
        path_verifier: NetworkPathVerificationSource,
        path_controller: NetworkPathController,
        path_status_sink: NetworkPathStatusSink | None = None,
        managed_path_status_sink: ManagedPathStatusSink | None = None,
        ledger: NetworkOwnershipLedger | None = None,
        clock: Callable[[], datetime] | None = None,
        commit_last_known_good: Callable[[SignedDesiredConfig], object] | None = None,
        crash_after: LifecycleCrashBoundary | None = None,
        apply_lease_seconds: int = 30,
    ) -> None:
        if apply_lease_seconds < 1:
            raise ValueError("apply claim lease 必须为正数")
        self._provider = provider
        self._policy = policy
        self._store = store
        self._acknowledgements = acknowledgements
        self._path_verifier = path_verifier
        self._path_controller = path_controller
        self._path_status_sink = path_status_sink
        self._managed_path_status_sink = managed_path_status_sink
        self._ledger = ledger
        self._clock = clock or (lambda: datetime.now(UTC))
        self._commit_last_known_good = commit_last_known_good
        self._crash_after = crash_after
        self._apply_lease_seconds = apply_lease_seconds
        self._lock = asyncio.Lock()
        self._path_refresh_tasks: dict[
            tuple[str, str, int], asyncio.Task[ManagedPathStatus | None]
        ] = {}
        self._path_refresh_tasks_lock = asyncio.Lock()
        self._local_claims: dict[tuple[str, str, int], NetworkApplyClaim] = {}
        policy.bind(store.authorization_read_port)
        store.bind_provider_journal(provider)

    async def reconcile(
        self,
        envelope: SignedDesiredConfig,
        *,
        action: NetworkAction,
        ownership: ManagedResourceOwnership | None,
        cancellation: ToolCancellationToken | None = None,
    ) -> NetworkGovernanceRecord:
        """执行一次受控生命周期；所有 Provider 写入都经过 apply 前二次授权读取。"""
        if self._lock.locked():
            raise RuntimeError("受管 path lifecycle 已在运行")
        token = cancellation or ToolCancellationToken()
        async with self._lock:
            desired = envelope.config
            existing = self._store.get(
                desired.network_id,
                desired.target_node_id,
                desired.revision,
            )
            if existing is not None and (
                existing.envelope != envelope
                or existing.plan.action is not action
                or existing.plan.ownership != ownership
            ):
                raise NetworkAuthorizationConflictError(
                    "同一 revision 的 envelope/plan/action/ownership 发生冲突"
                )
            if existing is not None:
                existing = self._restore_persisted_path_state(existing)
            if existing is not None and existing.phase in {
                NetworkGovernancePhase.VERIFIED,
                NetworkGovernancePhase.PATH_DEGRADED,
            }:
                if self._needs_path_retry(existing):
                    self._check_cancelled(token)
                    return (
                        existing
                        if self._path_refresh_rate_limited(existing)
                        else await self._verify_path(existing)
                    )
                return await self._retry_sinks(existing)
            if existing is not None and existing.phase in {
                NetworkGovernancePhase.RECOVERY_REQUIRED,
                NetworkGovernancePhase.MANUAL_INTERVENTION,
                NetworkGovernancePhase.OWNERSHIP_CONFLICT,
            }:
                return existing
            if (
                existing is not None
                and self._store.has_active_apply_claim(
                    network_id=desired.network_id,
                    node_id=desired.target_node_id,
                    revision=desired.revision,
                    now=self._now(),
                )
                and self._record_claim_key(existing) not in self._local_claims
            ):
                return existing
            if (
                existing is not None
                and existing.phase is NetworkGovernancePhase.AWAITING_AUTHORIZATION
            ):
                decision = self._evaluate_authorization(existing.plan)
                if decision is None:
                    return await self._authorization_wait(
                        existing,
                        code="local_l3_authorization_storage_unavailable",
                    )
                if decision.action is not NetworkPolicyAction.EXECUTE:
                    return await self._authorization_wait(existing, code=decision.code)
                record = self._journal(
                    existing,
                    NetworkGovernancePhase.AUTHORIZED,
                    authorization_id=decision.authorization_id,
                    acknowledgement_delivered=False,
                    path_status_delivered=False,
                    stable_error_code=None,
                )
                self._maybe_crash(LifecycleCrashBoundary.PLAN)
                if token.cancelled:
                    return self._journal(
                        record,
                        NetworkGovernancePhase.CANCELLED,
                        stable_error_code=NetworkErrorCode.CANCELLED.value,
                    )
                self._check_cancelled(token)
                record = self._journal(record, NetworkGovernancePhase.RECHECKING)
                rechecked = self._evaluate_authorization(record.plan)
                if rechecked is None:
                    return await self._authorization_wait(
                        record,
                        code="local_l3_authorization_storage_unavailable",
                    )
                if (
                    rechecked.action is not NetworkPolicyAction.EXECUTE
                    or rechecked.authorization_id != record.authorization_id
                ):
                    return await self._authorization_wait(record, code=rechecked.code)
                return await self._apply_and_verify(record, token)
            if existing is not None and existing.phase in {
                NetworkGovernancePhase.OBSERVING,
                NetworkGovernancePhase.PLANNING,
                NetworkGovernancePhase.AUTHORIZED,
                NetworkGovernancePhase.RECHECKING,
                NetworkGovernancePhase.APPLYING,
                NetworkGovernancePhase.APPLIED,
                NetworkGovernancePhase.VERIFYING,
                NetworkGovernancePhase.PROVIDER_VERIFIED,
                NetworkGovernancePhase.PATH_VERIFYING,
                NetworkGovernancePhase.PATH_RECONCILING,
                NetworkGovernancePhase.ROLLING_BACK,
                NetworkGovernancePhase.ACKNOWLEDGING,
                NetworkGovernancePhase.RECOVERING,
            }:
                return await self._recover_record(existing, token)

            self._check_cancelled(token)
            observed = await self._provider.observe(desired.interface_name)
            plan = await self._provider.plan(
                action=action,
                desired=desired,
                observed=observed,
                ownership=ownership,
            )
            remember_operation = getattr(self._provider, "remember_operation", None)
            if callable(remember_operation):
                remember_operation(
                    envelope,
                    plan,
                    idempotency_key=self._idempotency_key(plan),
                )
            record = NetworkGovernanceRecord(
                envelope=envelope,
                plan=plan,
                phase=NetworkGovernancePhase.OBSERVING,
                idempotency_key=self._idempotency_key(plan),
                updated_at=self._now(),
            )
            record = self._journal(record, NetworkGovernancePhase.OBSERVING)
            record = self._journal(record, NetworkGovernancePhase.PLANNING)
            self._maybe_crash(LifecycleCrashBoundary.PLAN)

            decision = self._evaluate_authorization(plan)
            if decision is None:
                return await self._authorization_wait(
                    record,
                    code="local_l3_authorization_storage_unavailable",
                )
            if decision.action is not NetworkPolicyAction.EXECUTE:
                return await self._authorization_wait(record, code=decision.code)
            record = self._journal(
                record,
                NetworkGovernancePhase.AUTHORIZED,
                authorization_id=decision.authorization_id,
                acknowledgement_delivered=False,
                path_status_delivered=False,
                stable_error_code=None,
            )
            self._check_cancelled(token)
            record = self._journal(record, NetworkGovernancePhase.RECHECKING)
            rechecked = self._evaluate_authorization(plan)
            if rechecked is None:
                return await self._authorization_wait(
                    record,
                    code="local_l3_authorization_storage_unavailable",
                )
            if (
                rechecked.action is not NetworkPolicyAction.EXECUTE
                or rechecked.authorization_id != record.authorization_id
            ):
                return await self._authorization_wait(record, code=rechecked.code)
            return await self._apply_and_verify(record, token)

    def get_path_status(
        self,
        network_id: NetworkId,
        node_id: NodeId,
        revision: int,
    ) -> ManagedPathStatus | None:
        """只读投影当前 path freshness；不触发授权、plan、Provider 或 probe。"""
        record = self._store.get(network_id, node_id, revision)
        persisted = self._store.get_path_status(network_id, node_id, revision)
        if persisted is not None:
            if record is not None and (
                persisted.plan_hash != record.plan.plan_hash
                or persisted.provider is not record.plan.desired.provider
                or persisted.journal_sequence
                != (record.journal[-1].sequence if record.journal else 0)
            ):
                raise ManagedPathLifecycleError("path status 与治理 record 绑定冲突")
            return persisted.at(self._now())
        if record is None:
            return None
        return self._status_from_record(record).at(self._now())

    async def refresh_path(
        self,
        network_id: NetworkId,
        node_id: NodeId,
        revision: int,
        *,
        cancellation: ToolCancellationToken | None = None,
    ) -> ManagedPathStatus | None:
        """合并同一 path 的只读刷新；永不调用 Provider plan/apply。"""
        key = (str(network_id), str(node_id), revision)
        async with self._path_refresh_tasks_lock:
            task = self._path_refresh_tasks.get(key)
            if task is None or task.done():
                token = cancellation or ToolCancellationToken()
                task = asyncio.create_task(
                    self._refresh_path_once(network_id, node_id, revision, token)
                )
                self._path_refresh_tasks[key] = task

                def discard(completed: asyncio.Task[ManagedPathStatus | None]) -> None:
                    if self._path_refresh_tasks.get(key) is completed:
                        self._path_refresh_tasks.pop(key, None)

                task.add_done_callback(discard)
        return await asyncio.shield(task)

    async def _refresh_path_once(
        self,
        network_id: NetworkId,
        node_id: NodeId,
        revision: int,
        cancellation: ToolCancellationToken,
    ) -> ManagedPathStatus | None:
        async with self._lock:
            self._check_cancelled(cancellation)
            record = self._store.get(network_id, node_id, revision)
            persisted = self._store.get_path_status(network_id, node_id, revision)
            if record is None:
                return persisted.at(self._now()) if persisted is not None else None
            record = self._restore_persisted_path_state(record)
            current = self._status_from_record(record).at(self._now())
            if record.phase not in {
                NetworkGovernancePhase.VERIFIED,
                NetworkGovernancePhase.PATH_DEGRADED,
            }:
                return current
            if record.verification is not None and not record.verification.succeeded:
                return current
            now = self._now()
            if self._path_refresh_rate_limited(record, now=now):
                values = current.model_dump(mode="python")
                values["stable_error_code"] = "path_refresh_rate_limited"
                return ManagedPathStatus.model_validate(values)
            self._check_cancelled(cancellation)
            record = self._journal(
                record,
                record.phase,
                last_refresh_attempt_at=now,
            )
            refreshed = await self._verify_path(record)
            self._check_cancelled(cancellation)
            return self._status_from_record(refreshed).at(self._now())

    async def recover(
        self,
        cancellation: ToolCancellationToken | None = None,
    ) -> tuple[NetworkGovernanceRecord, ...]:
        """先读取授权、journal、账本和实时状态，再选择验证或回滚；绝不调用 apply。"""
        if self._lock.locked():
            raise RuntimeError("受管 path lifecycle 已在运行")
        token = cancellation or ToolCancellationToken()
        async with self._lock:
            recoverable = self._store.list_recoverable()
            results: list[NetworkGovernanceRecord] = []
            for record in recoverable:
                results.append(await self._recover_record(record, token))
            return tuple(results)

    async def emergency_stop(
        self,
        envelope: SignedDesiredConfig,
        ownership: ManagedResourceOwnership,
        *,
        capability: KillSwitchCapability,
    ) -> NetworkGovernanceRecord:
        """执行独立可审计 kill-switch；它不复用普通 Provider.apply。"""
        if not self._policy.accepts_kill_switch(capability):
            raise PermissionError("紧急停止只能由节点本地控制面确认")
        if self._lock.locked():
            raise RuntimeError("受管 path lifecycle 已在运行")
        async with self._lock:
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
            remember_operation = getattr(self._provider, "remember_operation", None)
            idempotency_key = self._idempotency_key(plan)
            if callable(remember_operation):
                remember_operation(envelope, plan, idempotency_key=idempotency_key)
            record = self._journal(
                NetworkGovernanceRecord(
                    envelope=envelope,
                    plan=plan,
                    phase=NetworkGovernancePhase.APPLYING,
                    idempotency_key=idempotency_key,
                    updated_at=self._now(),
                ),
                NetworkGovernancePhase.APPLYING,
            )
            emergency_stop = getattr(self._provider, "emergency_stop", None)
            if not callable(emergency_stop):
                return await self._deliver_sinks(
                    self._journal(
                        record,
                        NetworkGovernancePhase.MANUAL_INTERVENTION,
                        stable_error_code=NetworkErrorCode.UNSUPPORTED.value,
                    ),
                    final_phase=NetworkGovernancePhase.MANUAL_INTERVENTION,
                    acknowledgement_stage=AcknowledgementStage.MANUAL_INTERVENTION,
                )
            try:
                receipt = await cast(Callable[..., Awaitable[ProviderReceipt]], emergency_stop)(
                    plan,
                    idempotency_key=record.idempotency_key,
                    cancellation=ToolCancellationToken(),
                )
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                return await self._deliver_sinks(
                    self._journal(
                        record,
                        NetworkGovernancePhase.MANUAL_INTERVENTION,
                        stable_error_code=self._provider_error_code(exc).value,
                    ),
                    final_phase=NetworkGovernancePhase.MANUAL_INTERVENTION,
                    acknowledgement_stage=AcknowledgementStage.MANUAL_INTERVENTION,
                )
            if not self._receipt_matches_record(record, receipt):
                return await self._deliver_sinks(
                    self._journal(
                        record,
                        NetworkGovernancePhase.RECOVERY_REQUIRED,
                        stable_error_code=NetworkErrorCode.JOURNAL_CONFLICT.value,
                    ),
                    final_phase=NetworkGovernancePhase.RECOVERY_REQUIRED,
                    acknowledgement_stage=AcknowledgementStage.MANUAL_INTERVENTION,
                )
            record = self._journal(
                record,
                NetworkGovernancePhase.APPLIED,
                receipt=receipt,
                stable_error_code=(receipt.error.code.value if receipt.error else None),
            )
            if receipt.status is not ReceiptStatus.APPLIED:
                return await self._deliver_sinks(
                    self._journal(
                        record,
                        NetworkGovernancePhase.MANUAL_INTERVENTION,
                        stable_error_code=(
                            receipt.error.code.value
                            if receipt.error is not None
                            else NetworkErrorCode.RECOVERY_REQUIRED.value
                        ),
                    ),
                    final_phase=NetworkGovernancePhase.MANUAL_INTERVENTION,
                    acknowledgement_stage=AcknowledgementStage.MANUAL_INTERVENTION,
                )
            record = self._journal(record, NetworkGovernancePhase.VERIFYING)
            try:
                verification = await self._provider.verify(plan)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                return await self._deliver_sinks(
                    self._journal(
                        record,
                        NetworkGovernancePhase.RECOVERY_REQUIRED,
                        stable_error_code=self._provider_error_code(exc).value,
                    ),
                    final_phase=NetworkGovernancePhase.RECOVERY_REQUIRED,
                    acknowledgement_stage=AcknowledgementStage.MANUAL_INTERVENTION,
                )
            if not self._verification_matches_record(record, verification):
                return await self._deliver_sinks(
                    self._journal(
                        record,
                        NetworkGovernancePhase.RECOVERY_REQUIRED,
                        stable_error_code=NetworkErrorCode.JOURNAL_CONFLICT.value,
                    ),
                    final_phase=NetworkGovernancePhase.RECOVERY_REQUIRED,
                    acknowledgement_stage=AcknowledgementStage.MANUAL_INTERVENTION,
                )
            if not verification.succeeded:
                return await self._deliver_sinks(
                    self._journal(
                        record,
                        NetworkGovernancePhase.MANUAL_INTERVENTION,
                        verification=verification,
                        stable_error_code=(
                            verification.error.code.value
                            if verification.error is not None
                            else NetworkErrorCode.VERIFY_FAILED.value
                        ),
                    ),
                    final_phase=NetworkGovernancePhase.MANUAL_INTERVENTION,
                    acknowledgement_stage=AcknowledgementStage.MANUAL_INTERVENTION,
                )
            return await self._deliver_sinks(
                self._journal(
                    record,
                    NetworkGovernancePhase.VERIFIED,
                    verification=verification,
                    stable_error_code=None,
                ),
                final_phase=NetworkGovernancePhase.VERIFIED,
                acknowledgement_stage=AcknowledgementStage.VERIFIED,
            )

    async def _apply_and_verify(
        self,
        record: NetworkGovernanceRecord,
        cancellation: ToolCancellationToken,
    ) -> NetworkGovernanceRecord:
        record = self._journal(record, NetworkGovernancePhase.APPLYING)
        if cancellation.cancelled:
            return self._journal(
                record,
                NetworkGovernancePhase.CANCELLED,
                stable_error_code=NetworkErrorCode.CANCELLED.value,
            )
        if record.authorization_id is None:
            return self._journal(
                record,
                NetworkGovernancePhase.RECOVERY_REQUIRED,
                stable_error_code=NetworkErrorCode.AUTHORIZATION_REQUIRED.value,
            )
        try:
            claim = self._store.claim_apply(
                record.plan,
                authorization_id=record.authorization_id,
                idempotency_key=record.idempotency_key,
                now=self._now(),
                lease_seconds=self._apply_lease_seconds,
            )
            self._store.assert_apply_claim(claim, now=self._now())
        except NetworkApplyClaimConflictError:
            return self._journal(
                record,
                NetworkGovernancePhase.RECOVERY_REQUIRED,
                stable_error_code=NetworkErrorCode.CLAIM_CONFLICT.value,
            )
        claim_key = self._record_claim_key(record)
        self._local_claims[claim_key] = claim
        stop_renewal = asyncio.Event()
        claim_invalid = asyncio.Event()
        renewal = asyncio.create_task(self._renew_claim(claim, stop_renewal, claim_invalid))
        completed: NetworkGovernanceRecord | None = None
        try:
            receipt = await self._provider.apply(
                record.plan,
                idempotency_key=record.idempotency_key,
                cancellation=cancellation,
            )
        except asyncio.CancelledError as exc:
            self._journal(
                record,
                NetworkGovernancePhase.APPLYING,
                stable_error_code=NetworkErrorCode.RECOVERY_REQUIRED.value,
            )
            self._store.fence_apply_claim(claim)
            stop_renewal.set()
            await self._finish_claim_renewal(renewal)
            await _reraise(exc)
        except Exception as exc:
            self._journal(
                record,
                NetworkGovernancePhase.APPLYING,
                stable_error_code=self._provider_error_code(exc).value,
            )
            self._store.fence_apply_claim(claim)
            stop_renewal.set()
            await self._finish_claim_renewal(renewal)
            await _reraise(exc)
        try:
            self._maybe_crash(LifecycleCrashBoundary.APPLY)
            if not self._receipt_matches_record(record, receipt):
                completed = self._journal(
                    record,
                    NetworkGovernancePhase.RECOVERY_REQUIRED,
                    stable_error_code=NetworkErrorCode.JOURNAL_CONFLICT.value,
                )
                return completed
            record = self._journal(
                record,
                NetworkGovernancePhase.APPLIED,
                receipt=receipt,
                stable_error_code=(receipt.error.code.value if receipt.error else None),
            )
            if claim_invalid.is_set():
                completed = self._journal(
                    record,
                    NetworkGovernancePhase.RECOVERY_REQUIRED,
                    stable_error_code=NetworkErrorCode.CLAIM_CONFLICT.value,
                )
                return completed
            try:
                self._store.assert_apply_claim(claim, now=self._now())
            except NetworkApplyClaimConflictError:
                completed = self._journal(
                    record,
                    NetworkGovernancePhase.RECOVERY_REQUIRED,
                    stable_error_code=NetworkErrorCode.CLAIM_CONFLICT.value,
                )
                return completed
            if receipt.status is not ReceiptStatus.APPLIED:
                completed = await self._rollback(record, receipt, cancellation=cancellation)
                return completed

            record = self._journal(record, NetworkGovernancePhase.VERIFYING)
            try:
                verification = await self._provider.verify(record.plan)
            except asyncio.CancelledError as exc:
                await _reraise(exc)
            except Exception as exc:
                completed = self._journal(
                    record,
                    NetworkGovernancePhase.RECOVERY_REQUIRED,
                    stable_error_code=self._provider_error_code(exc).value,
                )
                return completed
            if not self._verification_matches_record(record, verification):
                completed = self._journal(
                    record,
                    NetworkGovernancePhase.RECOVERY_REQUIRED,
                    stable_error_code=NetworkErrorCode.JOURNAL_CONFLICT.value,
                )
                return completed
            record = self._journal(
                record,
                NetworkGovernancePhase.PROVIDER_VERIFIED,
                verification=verification,
                stable_error_code=(verification.error.code.value if verification.error else None),
            )
            self._maybe_crash(LifecycleCrashBoundary.VERIFY)
            if claim_invalid.is_set():
                completed = self._journal(
                    record,
                    NetworkGovernancePhase.RECOVERY_REQUIRED,
                    stable_error_code=NetworkErrorCode.CLAIM_CONFLICT.value,
                )
                return completed
            try:
                self._store.assert_apply_claim(claim, now=self._now())
            except NetworkApplyClaimConflictError:
                completed = self._journal(
                    record,
                    NetworkGovernancePhase.RECOVERY_REQUIRED,
                    stable_error_code=NetworkErrorCode.CLAIM_CONFLICT.value,
                )
                return completed
            if not verification.succeeded:
                completed = await self._rollback(record, receipt, cancellation=cancellation)
                return completed
            completed = await self._verify_path(
                record,
                claim=claim,
                claim_invalid=claim_invalid,
            )
            return completed
        except LifecycleInjectedCrash:
            self._store.reap_expired_claims(
                now=self._now() + timedelta(seconds=self._apply_lease_seconds)
            )
            raise
        finally:
            stop_renewal.set()
            await self._finish_claim_renewal(renewal)
            if completed is not None:
                if completed.phase in {
                    NetworkGovernancePhase.VERIFIED,
                    NetworkGovernancePhase.PATH_DEGRADED,
                    NetworkGovernancePhase.ROLLED_BACK,
                }:
                    self._store.release_apply_claim(claim)
                    self._local_claims.pop(claim_key, None)
                else:
                    self._store.fence_apply_claim(claim)

    async def _renew_claim(
        self,
        claim: NetworkApplyClaim,
        stop: asyncio.Event,
        claim_invalid: asyncio.Event,
    ) -> None:
        interval = max(0.1, min(self._apply_lease_seconds / 3, 5.0))
        while not stop.is_set():
            try:
                await asyncio.wait_for(stop.wait(), timeout=interval)
            except TimeoutError:
                try:
                    claim = self._store.renew_apply_claim(
                        claim,
                        now=self._now(),
                        lease_seconds=self._apply_lease_seconds,
                    )
                except NetworkApplyClaimConflictError:
                    claim_invalid.set()
                    return
                except Exception:
                    claim_invalid.set()
                    return

    @staticmethod
    async def _finish_claim_renewal(task: asyncio.Task[None]) -> None:
        if not task.done():
            task.cancel()
        with suppress(asyncio.CancelledError):
            await task

    async def _verify_path(
        self,
        record: NetworkGovernanceRecord,
        *,
        claim: NetworkApplyClaim | None = None,
        claim_invalid: asyncio.Event | None = None,
    ) -> NetworkGovernanceRecord:
        record = self._journal(record, NetworkGovernancePhase.PATH_VERIFYING)
        try:
            evidence = await self._path_verifier.verify(record.plan, now=self._now())
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            degraded = self._degrade_path(record, self._path_error_code(exc).value)
            return await degraded
        now = self._now()
        if (
            evidence.network_id != record.plan.desired.network_id
            or evidence.node_id != record.plan.desired.target_node_id
            or evidence.plan_hash != record.plan.plan_hash
            or evidence.authorization_revision != record.plan.desired.revision
            or evidence.revision != record.plan.desired.revision
            or evidence.provider is not record.plan.desired.provider
            or evidence.observed_at > now
            or evidence.expires_at <= now
        ):
            return await self._degrade_path(record, "path_evidence_binding_mismatch")
        record = self._journal(
            record,
            NetworkGovernancePhase.PATH_RECONCILING,
            path_evidence=evidence,
            path_selection=None,
            stable_error_code=(
                evidence.stable_error_code.value if evidence.stable_error_code else None
            ),
        )
        try:
            selection = await self._path_controller.reconcile(
                evidence,
                fallback=NetworkPathType.STATIC,
            )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            return await self._degrade_path(record, self._path_error_code(exc).value)
        if evidence.verified and (
            selection.path_type
            not in {
                NetworkPathType.DIRECT,
                NetworkPathType.STATIC,
            }
            or selection.network_id != record.plan.desired.network_id
            or selection.node_id != record.plan.desired.target_node_id
            or selection.plan_hash != record.plan.plan_hash
            or selection.authorization_revision != record.plan.desired.revision
            or selection.provider is not record.plan.desired.provider
            or selection.revision != record.plan.desired.revision
            or selection.target_host_hash != evidence.target_host_hash
            or selection.target_port != evidence.target_port
            or selection.route_identity_hash != evidence.route_identity_hash
            or selection.expires_at != evidence.expires_at
            or selection.last_evidence_at > now
            or selection.expires_at is None
            or selection.expires_at <= now
        ):
            return await self._degrade_path(record, "path_selection_binding_mismatch")
        if not evidence.verified:
            return await self._degrade_path(
                record,
                evidence.stable_error_code.value
                if evidence.stable_error_code is not None
                else "path_verify_failed",
                selection=selection,
            )
        if claim is not None and claim_invalid is not None:
            if claim_invalid.is_set():
                return self._journal(
                    record,
                    NetworkGovernancePhase.RECOVERY_REQUIRED,
                    stable_error_code=NetworkErrorCode.CLAIM_CONFLICT.value,
                )
            try:
                self._store.assert_apply_claim(claim, now=self._now())
            except NetworkApplyClaimConflictError:
                return self._journal(
                    record,
                    NetworkGovernancePhase.RECOVERY_REQUIRED,
                    stable_error_code=NetworkErrorCode.CLAIM_CONFLICT.value,
                )
        committed = True
        stable_error: str | None = None
        if self._commit_last_known_good is not None:
            try:
                self._commit_last_known_good(record.envelope)
            except Exception:
                committed = False
                stable_error = "last_known_good_checkpoint_failed"
        record = self._journal(
            record,
            NetworkGovernancePhase.ACKNOWLEDGING,
            path_evidence=evidence,
            path_selection=selection,
            last_known_good_revision=(record.plan.desired.revision if committed else None),
            stable_error_code=stable_error,
        )
        return await self._deliver_sinks(
            record,
            final_phase=NetworkGovernancePhase.VERIFIED,
            acknowledgement_stage=AcknowledgementStage.VERIFIED,
        )

    @staticmethod
    def _needs_path_retry(record: NetworkGovernanceRecord) -> bool:
        """在 Provider 已验证后继续推进 controller 的 direct hysteresis。"""
        return (
            record.verification is not None
            and record.verification.succeeded
            and record.path_evidence is not None
            and record.path_evidence.verified
            and record.path_selection is not None
            and record.path_selection.path_type is not NetworkPathType.DIRECT
        )

    def _path_refresh_rate_limited(
        self,
        record: NetworkGovernanceRecord,
        *,
        now: datetime | None = None,
    ) -> bool:
        """所有 path 恢复入口共享持久化刷新尝试预算。"""
        attempt = record.last_refresh_attempt_at
        return attempt is not None and (
            (self._now() if now is None else now) - attempt < MANAGED_PATH_REFRESH_MIN_INTERVAL
        )

    async def _degrade_path(
        self,
        record: NetworkGovernanceRecord,
        stable_error_code: str,
        *,
        selection: PathSelection | None = None,
    ) -> NetworkGovernanceRecord:
        chosen = selection
        if chosen is None:
            try:
                current = self._path_controller.selection
            except Exception:
                current = None
            if current is not None and current.revision >= record.plan.desired.revision:
                chosen = current
        record = self._journal(
            record,
            NetworkGovernancePhase.PATH_DEGRADED,
            path_selection=chosen,
            stable_error_code=stable_error_code,
        )
        return await self._deliver_sinks(
            record,
            final_phase=NetworkGovernancePhase.PATH_DEGRADED,
            acknowledgement_stage=AcknowledgementStage.APPLIED,
        )

    @staticmethod
    def _provider_error_code(error: Exception) -> NetworkErrorCode:
        if isinstance(error, PermissionError):
            return NetworkErrorCode.PERMISSION_DENIED
        if isinstance(error, TimeoutError):
            return NetworkErrorCode.TIMEOUT
        if isinstance(error, NotImplementedError):
            return NetworkErrorCode.UNSUPPORTED
        if isinstance(error, OSError) and error.errno in {
            errno.ENOSYS,
            errno.ENOTSUP,
            errno.EOPNOTSUPP,
        }:
            return NetworkErrorCode.UNSUPPORTED
        if isinstance(error, ConnectionError):
            return NetworkErrorCode.PROVIDER_UNAVAILABLE
        return NetworkErrorCode.PROVIDER_UNAVAILABLE

    @staticmethod
    def _path_error_code(error: Exception) -> NetworkErrorCode:
        if isinstance(error, PermissionError):
            return NetworkErrorCode.PERMISSION_DENIED
        if isinstance(error, TimeoutError):
            return NetworkErrorCode.TIMEOUT
        if isinstance(error, NotImplementedError):
            return NetworkErrorCode.UNSUPPORTED
        if isinstance(error, OSError) and error.errno in {
            errno.ENOSYS,
            errno.ENOTSUP,
            errno.EOPNOTSUPP,
        }:
            return NetworkErrorCode.UNSUPPORTED
        return NetworkErrorCode.PATH_UNAVAILABLE

    async def _rollback(
        self,
        record: NetworkGovernanceRecord,
        receipt: ProviderReceipt,
        *,
        cancellation: ToolCancellationToken,
    ) -> NetworkGovernanceRecord:
        record = self._journal(record, NetworkGovernancePhase.ROLLING_BACK)
        try:
            rolled = await self._provider.rollback(
                record.plan,
                receipt,
                cancellation=cancellation,
            )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            return await self._ack_only(
                self._journal(
                    record,
                    NetworkGovernancePhase.MANUAL_INTERVENTION,
                    stable_error_code=self._provider_error_code(exc).value,
                ),
                stage=AcknowledgementStage.MANUAL_INTERVENTION,
            )
        if not self._receipt_matches_record(record, rolled):
            return self._journal(
                record,
                NetworkGovernancePhase.RECOVERY_REQUIRED,
                stable_error_code=NetworkErrorCode.JOURNAL_CONFLICT.value,
            )
        phase = NetworkGovernancePhase.MANUAL_INTERVENTION
        stage = AcknowledgementStage.MANUAL_INTERVENTION
        if rolled.status is ReceiptStatus.ROLLED_BACK:
            phase = NetworkGovernancePhase.ROLLED_BACK
            stage = AcknowledgementStage.ROLLED_BACK
        elif rolled.error is not None and rolled.error.code is NetworkErrorCode.OWNERSHIP_CONFLICT:
            phase = NetworkGovernancePhase.OWNERSHIP_CONFLICT
            stage = AcknowledgementStage.OWNERSHIP_CONFLICT
        record = self._journal(
            record,
            phase,
            receipt=rolled,
            stable_error_code=(rolled.error.code.value if rolled.error else None),
        )
        return await self._ack_only(record, stage=stage)

    async def _recover_record(
        self,
        original: NetworkGovernanceRecord,
        cancellation: ToolCancellationToken,
    ) -> NetworkGovernanceRecord:
        if self._path_refresh_rate_limited(original):
            return original
        claim_key = self._record_claim_key(original)
        if (
            self._store.has_active_apply_claim(
                network_id=original.plan.desired.network_id,
                node_id=original.plan.desired.target_node_id,
                revision=original.plan.desired.revision,
                now=self._now(),
            )
            and claim_key not in self._local_claims
        ):
            return original
        local_claim = self._local_claims.get(claim_key)
        if local_claim is not None:
            self._store.fence_apply_claim(local_claim)
        self._store.resolve_apply_claim(
            network_id=original.plan.desired.network_id,
            node_id=original.plan.desired.target_node_id,
            revision=original.plan.desired.revision,
            idempotency_key=original.idempotency_key,
            plan_hash=original.plan.plan_hash,
        )
        self._local_claims.pop(claim_key, None)
        record = self._journal(original, NetworkGovernancePhase.RECOVERING)
        decision = self._evaluate_authorization(record.plan)
        if decision is None or (
            decision.action is not NetworkPolicyAction.EXECUTE
            or decision.authorization_id != record.authorization_id
        ):
            return self._journal(
                record,
                NetworkGovernancePhase.RECOVERY_REQUIRED,
                stable_error_code=(
                    "local_l3_authorization_storage_unavailable"
                    if decision is None
                    else decision.code
                ),
            )
        ledger_matches = self._ledger_matches(record.plan)
        if record.plan.action is NetworkAction.CREATE and not ledger_matches:
            return await self._ack_only(
                self._journal(
                    record,
                    NetworkGovernancePhase.MANUAL_INTERVENTION,
                    stable_error_code=NetworkErrorCode.OWNERSHIP_CONFLICT.value,
                ),
                stage=AcknowledgementStage.MANUAL_INTERVENTION,
            )
        try:
            observed = await self._provider.observe(record.plan.desired.interface_name)
        except Exception as exc:
            return self._journal(
                record,
                NetworkGovernancePhase.RECOVERY_REQUIRED,
                stable_error_code=self._provider_error_code(exc).value,
            )
        if not ledger_matches or observed.ownership in {
            OwnershipState.OBSERVED_USER,
            OwnershipState.OWNERSHIP_CONFLICT,
            OwnershipState.OWNERSHIP_UNKNOWN,
        }:
            return await self._ack_only(
                self._journal(
                    record,
                    NetworkGovernancePhase.OWNERSHIP_CONFLICT,
                    stable_error_code=NetworkErrorCode.OWNERSHIP_CONFLICT.value,
                ),
                stage=AcknowledgementStage.OWNERSHIP_CONFLICT,
            )
        if (
            record.plan.action is NetworkAction.CREATE
            and observed.ownership is OwnershipState.ABSENT
        ):
            return await self._ack_only(
                self._journal(
                    record,
                    NetworkGovernancePhase.MANUAL_INTERVENTION,
                    stable_error_code=NetworkErrorCode.OWNERSHIP_CONFLICT.value,
                ),
                stage=AcknowledgementStage.MANUAL_INTERVENTION,
            )

        if original.phase is NetworkGovernancePhase.ACKNOWLEDGING:
            final = (
                NetworkGovernancePhase.VERIFIED
                if original.path_evidence is not None and original.path_evidence.verified
                else NetworkGovernancePhase.PATH_DEGRADED
            )
            stage = (
                AcknowledgementStage.VERIFIED
                if final is NetworkGovernancePhase.VERIFIED
                else AcknowledgementStage.APPLIED
            )
            return await self._deliver_sinks(
                record,
                final_phase=final,
                acknowledgement_stage=stage,
            )

        receipt = record.receipt
        refresh_recovery = (
            original.phase
            in {
                NetworkGovernancePhase.PATH_VERIFYING,
                NetworkGovernancePhase.PATH_RECONCILING,
            }
            and original.last_refresh_attempt_at is not None
        )
        if receipt is None:
            if (
                original.phase
                in {
                    NetworkGovernancePhase.OBSERVING,
                    NetworkGovernancePhase.PLANNING,
                    NetworkGovernancePhase.AUTHORIZED,
                    NetworkGovernancePhase.RECHECKING,
                }
                or refresh_recovery
            ):
                try:
                    verification = await self._provider.verify(record.plan)
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    return self._journal(
                        record,
                        NetworkGovernancePhase.RECOVERY_REQUIRED,
                        stable_error_code=self._provider_error_code(exc).value,
                    )
                if not self._verification_matches_record(record, verification):
                    return self._journal(
                        record,
                        NetworkGovernancePhase.RECOVERY_REQUIRED,
                        stable_error_code=NetworkErrorCode.JOURNAL_CONFLICT.value,
                    )
                if refresh_recovery and verification.succeeded:
                    record = self._journal(
                        record,
                        NetworkGovernancePhase.PROVIDER_VERIFIED,
                        verification=verification,
                        stable_error_code=(
                            verification.error.code.value if verification.error else None
                        ),
                    )
                    return await self._verify_path(record)
                return self._journal(
                    record,
                    NetworkGovernancePhase.RECOVERY_REQUIRED,
                    verification=verification,
                    stable_error_code=(
                        verification.error.code.value
                        if verification.error is not None
                        else NetworkErrorCode.RECOVERY_REQUIRED.value
                    ),
                )
            try:
                recovered = await self._provider.recover(cancellation=cancellation)
            except Exception as exc:
                return self._journal(
                    record,
                    NetworkGovernancePhase.RECOVERY_REQUIRED,
                    stable_error_code=self._provider_error_code(exc).value,
                )
            receipt = next(
                (item for item in recovered if self._receipt_matches_record(record, item)),
                None,
            )
            if receipt is None:
                return self._journal(
                    record,
                    NetworkGovernancePhase.RECOVERY_REQUIRED,
                    stable_error_code=NetworkErrorCode.RECOVERY_REQUIRED.value,
                )
            record = self._journal(
                record,
                NetworkGovernancePhase.APPLIED,
                receipt=receipt,
                stable_error_code=(receipt.error.code.value if receipt.error else None),
            )
        if receipt.status is not ReceiptStatus.APPLIED:
            terminal_phase = NetworkGovernancePhase.MANUAL_INTERVENTION
            terminal_stage = AcknowledgementStage.MANUAL_INTERVENTION
            if receipt.status is ReceiptStatus.ROLLED_BACK:
                terminal_phase = NetworkGovernancePhase.ROLLED_BACK
                terminal_stage = AcknowledgementStage.ROLLED_BACK
            elif receipt.status is ReceiptStatus.CANCELLED:
                terminal_phase = NetworkGovernancePhase.CANCELLED
            return await self._ack_only(
                self._journal(
                    record,
                    terminal_phase,
                    stable_error_code=(receipt.error.code.value if receipt.error else None),
                ),
                stage=terminal_stage,
            )
        try:
            verification = await self._provider.verify(record.plan)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            return self._journal(
                record,
                NetworkGovernancePhase.RECOVERY_REQUIRED,
                stable_error_code=self._provider_error_code(exc).value,
            )
        if not self._verification_matches_record(record, verification):
            return self._journal(
                record,
                NetworkGovernancePhase.RECOVERY_REQUIRED,
                stable_error_code=NetworkErrorCode.JOURNAL_CONFLICT.value,
            )
        record = self._journal(
            record,
            NetworkGovernancePhase.PROVIDER_VERIFIED,
            verification=verification,
            stable_error_code=(verification.error.code.value if verification.error else None),
        )
        if not verification.succeeded:
            return await self._rollback(record, receipt, cancellation=cancellation)
        return await self._verify_path(record)

    async def _authorization_wait(
        self,
        record: NetworkGovernanceRecord,
        *,
        code: str,
    ) -> NetworkGovernanceRecord:
        record = self._journal(
            record,
            NetworkGovernancePhase.AWAITING_AUTHORIZATION,
            authorization_id=None,
            stable_error_code=code,
        )
        return await self._ack_only(
            record,
            stage=AcknowledgementStage.AWAITING_AUTHORIZATION,
        )

    async def _ack_only(
        self,
        record: NetworkGovernanceRecord,
        *,
        stage: AcknowledgementStage,
    ) -> NetworkGovernanceRecord:
        if record.acknowledgement_delivered:
            return record
        if self._acknowledgements is None:
            return self._journal(
                record,
                record.phase,
                acknowledgement_delivered=True,
                stable_error_code=(
                    None if record.stable_error_code == "ack_sink_failed" else _LIFECYCLE_UNSET
                ),
            )
        try:
            await self._acknowledgements.acknowledge(self._acknowledgement(record, stage))
        except Exception:
            return self._journal(record, record.phase, stable_error_code="ack_sink_failed")
        return self._journal(
            record,
            record.phase,
            acknowledgement_delivered=True,
            stable_error_code=(
                None if record.stable_error_code == "ack_sink_failed" else _LIFECYCLE_UNSET
            ),
        )

    async def _deliver_sinks(
        self,
        record: NetworkGovernanceRecord,
        *,
        final_phase: NetworkGovernancePhase,
        acknowledgement_stage: AcknowledgementStage,
    ) -> NetworkGovernanceRecord:
        acknowledgement_was_pending = not record.acknowledgement_delivered
        record = await self._ack_only(record, stage=acknowledgement_stage)
        if not record.acknowledgement_delivered:
            return self._journal(record, final_phase)
        if acknowledgement_was_pending:
            self._maybe_crash(LifecycleCrashBoundary.ACK)
        if self._path_status_sink is None and not record.path_status_delivered:
            record = self._journal(
                record,
                final_phase,
                path_status_delivered=True,
            )
        elif self._path_status_sink is not None and not record.path_status_delivered:
            try:
                await self._path_status_sink.publish(
                    self._path_status(record),
                    idempotency_key=record.idempotency_key,
                )
            except Exception:
                record = self._journal(record, final_phase, stable_error_code="path_sink_failed")
            else:
                record = self._journal(
                    record,
                    final_phase,
                    path_status_delivered=True,
                    stable_error_code=(
                        None if record.stable_error_code == "path_sink_failed" else _LIFECYCLE_UNSET
                    ),
                )
        if self._managed_path_status_sink is not None and self._managed_path_status_pending(record):
            status = self._managed_path_status_for_delivery(record)
            delivery_hash = self._managed_path_status_delivery_hash(status)
            try:
                await self._managed_path_status_sink.publish(
                    status,
                    idempotency_key=record.idempotency_key,
                )
            except Exception:
                record = self._journal(
                    record,
                    final_phase,
                    stable_error_code="managed_path_status_sink_failed",
                )
            else:
                record = self._journal(
                    record,
                    final_phase,
                    managed_path_status_delivered=True,
                    managed_path_status_delivery_hash=delivery_hash,
                    stable_error_code=(
                        None
                        if record.stable_error_code == "managed_path_status_sink_failed"
                        else _LIFECYCLE_UNSET
                    ),
                )
        if record.phase is not final_phase:
            return self._journal(record, final_phase)
        return record

    async def _retry_sinks(self, record: NetworkGovernanceRecord) -> NetworkGovernanceRecord:
        if (
            record.acknowledgement_delivered
            and record.path_status_delivered
            and (
                self._managed_path_status_sink is None
                or not self._managed_path_status_pending(record)
            )
        ):
            return record
        pending = self._journal(record, NetworkGovernancePhase.ACKNOWLEDGING)
        stage = (
            AcknowledgementStage.VERIFIED
            if record.phase is NetworkGovernancePhase.VERIFIED
            else AcknowledgementStage.APPLIED
        )
        return await self._deliver_sinks(
            pending,
            final_phase=record.phase,
            acknowledgement_stage=stage,
        )

    def _evaluate_authorization(self, plan: NetworkPlan) -> NetworkPolicyDecision | None:
        try:
            return self._policy.evaluate(plan, at=self._now())
        except NetworkAuthorizationStorageError:
            return None

    @staticmethod
    def _receipt_matches_record(
        record: NetworkGovernanceRecord,
        receipt: ProviderReceipt,
    ) -> bool:
        if (
            receipt.idempotency_key != record.idempotency_key
            or receipt.plan_hash != record.plan.plan_hash
            or receipt.revision != record.plan.desired.revision
            or receipt.provider is not record.plan.desired.provider
        ):
            return False
        observation = receipt.observation_after
        if observation is None:
            return receipt.observation_fingerprint == record.plan.observed_fingerprint
        return (
            observation.provider is record.plan.desired.provider
            and observation.interface_name == record.plan.desired.interface_name
            and observation.system_fingerprint == receipt.observation_fingerprint
        )

    @staticmethod
    def _verification_matches_record(
        record: NetworkGovernanceRecord,
        verification: VerificationResult,
    ) -> bool:
        observation = verification.observation
        return (
            verification.idempotency_key == record.idempotency_key
            and verification.plan_hash == record.plan.plan_hash
            and verification.revision == record.plan.desired.revision
            and verification.provider is record.plan.desired.provider
            and observation.provider is record.plan.desired.provider
            and observation.interface_name == record.plan.desired.interface_name
            and observation.system_fingerprint == verification.observation_fingerprint
        )

    def _ledger_matches(self, plan: NetworkPlan) -> bool:
        if self._ledger is None:
            return plan.action is not NetworkAction.CREATE
        entry = self._ledger.get(plan.desired.network_id, plan.desired.target_node_id)
        ownership = getattr(entry, "ownership", None)
        if not isinstance(ownership, ManagedResourceOwnership):
            return False
        if (
            ownership.network_id != plan.desired.network_id
            or ownership.node_id != plan.desired.target_node_id
            or ownership.provider is not plan.desired.provider
            or ownership.interface_name != plan.desired.interface_name
            or ownership.desired_config_hash
            != canonical_sha256(plan.desired.model_dump(mode="json"))
        ):
            return False
        if plan.action is NetworkAction.CREATE:
            return True
        return plan.ownership is not None and ownership == plan.ownership

    def _restore_persisted_path_state(
        self,
        record: NetworkGovernanceRecord,
    ) -> NetworkGovernanceRecord:
        """恢复 controller 游标和治理记录中的脱敏 path 摘要。"""
        status = self._store.get_path_status(
            record.plan.desired.network_id,
            record.plan.desired.target_node_id,
            record.plan.desired.revision,
        )
        if status is None:
            return record
        tail_sequence = record.journal[-1].sequence if record.journal else 0
        if status.journal_sequence != tail_sequence:
            raise ManagedPathLifecycleError("path status journal 与治理 record 不一致")
        if (
            status.plan_hash != record.plan.plan_hash
            or status.provider is not record.plan.desired.provider
        ):
            raise ManagedPathLifecycleError("path status 与治理计划绑定冲突")
        if status.selection is not None:
            restore = getattr(self._path_controller, "restore", None)
            if callable(restore):
                try:
                    restore(status.selection)
                except Exception as exc:
                    raise ManagedPathLifecycleError("path controller checkpoint 恢复失败") from exc
        updates: dict[str, object] = {}
        if record.path_evidence is None and status.evidence is not None:
            updates["path_evidence"] = status.evidence
        if record.path_selection is None and status.selection is not None:
            updates["path_selection"] = status.selection
        if not updates:
            return record
        return _validated_record_update(record, updates)

    def _status_from_record(self, record: NetworkGovernanceRecord) -> ManagedPathStatus:
        """把治理 record 投影为可持久化、不可重放的 path status。"""
        evidence = record.path_evidence
        selection = record.path_selection
        if record.authorization_id is not None:
            authorization_state = ManagedPathAuthorizationState.AUTHORIZED
            authorization_id = record.authorization_id
        elif record.phase is NetworkGovernancePhase.AWAITING_AUTHORIZATION:
            authorization_state = ManagedPathAuthorizationState.AWAITING_AUTHORIZATION
            authorization_id = None
        else:
            authorization_state = ManagedPathAuthorizationState.UNKNOWN
            authorization_id = None
        stable_error = record.stable_error_code
        if (
            evidence is not None
            and not evidence.verified
            and evidence.stable_error_code is not None
        ):
            stable_error = evidence.stable_error_code.value
        if evidence is not None and evidence.verified and evidence.expires_at <= record.updated_at:
            stable_error = stable_error or "path_evidence_stale"
        freshness = ManagedPathFreshness.UNVERIFIED
        if evidence is not None and evidence.verified:
            freshness = (
                ManagedPathFreshness.FRESH
                if evidence.expires_at > record.updated_at
                else ManagedPathFreshness.STALE
            )
        return ManagedPathStatus(
            network_id=record.plan.desired.network_id,
            node_id=record.plan.desired.target_node_id,
            revision=record.plan.desired.revision,
            plan_hash=record.plan.plan_hash,
            authorization_revision=record.plan.desired.revision,
            provider=record.plan.desired.provider,
            authorization_state=authorization_state,
            authorization_id=authorization_id,
            path_type=(selection.path_type if selection is not None else NetworkPathType.STATIC),
            selection=selection,
            evidence=evidence,
            source=(source_category(evidence.source) if evidence is not None else "none"),
            freshness=freshness,
            candidate_count=(evidence.candidate_count if evidence is not None else 0),
            last_known_good_revision=(
                record.last_known_good_revision
                if record.last_known_good_revision is not None
                else (selection.last_known_good_revision if selection is not None else None)
            ),
            observed_at=(evidence.observed_at if evidence is not None else None),
            refreshed_at=(evidence.observed_at if evidence is not None else None),
            expires_at=(evidence.expires_at if evidence is not None else None),
            last_refresh_attempt_at=record.last_refresh_attempt_at,
            stable_error_code=stable_error,
            journal_sequence=(record.journal[-1].sequence if record.journal else 0),
            updated_at=record.updated_at,
        )

    def _journal(
        self,
        record: NetworkGovernanceRecord,
        phase: NetworkGovernancePhase,
        *,
        authorization_id: AuthorizationId | None | object = _LIFECYCLE_UNSET,
        receipt: ProviderReceipt | None | object = _LIFECYCLE_UNSET,
        verification: VerificationResult | None | object = _LIFECYCLE_UNSET,
        path_evidence: DirectPathEvidence | None | object = _LIFECYCLE_UNSET,
        path_selection: PathSelection | None | object = _LIFECYCLE_UNSET,
        last_known_good_revision: int | None | object = _LIFECYCLE_UNSET,
        last_refresh_attempt_at: datetime | None | object = _LIFECYCLE_UNSET,
        acknowledgement_delivered: bool | object = _LIFECYCLE_UNSET,
        path_status_delivered: bool | object = _LIFECYCLE_UNSET,
        managed_path_status_delivered: bool | object = _LIFECYCLE_UNSET,
        managed_path_status_delivery_hash: str | None | object = _LIFECYCLE_UNSET,
        stable_error_code: str | None | object = _LIFECYCLE_UNSET,
    ) -> NetworkGovernanceRecord:
        updates: dict[str, object] = {
            "phase": phase,
            "updated_at": self._now(),
        }
        for name, value in (
            ("authorization_id", authorization_id),
            ("receipt", receipt),
            ("verification", verification),
            ("path_evidence", path_evidence),
            ("path_selection", path_selection),
            ("last_known_good_revision", last_known_good_revision),
            ("last_refresh_attempt_at", last_refresh_attempt_at),
            ("acknowledgement_delivered", acknowledgement_delivered),
            ("path_status_delivered", path_status_delivered),
            ("managed_path_status_delivered", managed_path_status_delivered),
            ("managed_path_status_delivery_hash", managed_path_status_delivery_hash),
            ("stable_error_code", stable_error_code),
        ):
            if value is not _LIFECYCLE_UNSET:
                updates[name] = value
        candidate = _validated_record_update(record, updates)
        journal = list(record.journal)
        journal_start_sequence = record.journal_start_sequence
        journal_previous_hash = record.journal_previous_hash
        if len(journal) >= 128:
            drop_count = len(journal) - 127
            dropped = journal[drop_count - 1]
            journal = journal[drop_count:]
            journal_start_sequence = dropped.sequence + 1
            journal_previous_hash = dropped.entry_hash
        sequence = journal_start_sequence + len(journal)
        previous_hash = journal[-1].entry_hash if journal else journal_previous_hash
        entry_fields = {
            "sequence": sequence,
            "previous_hash": previous_hash,
            "phase": phase.value,
            "idempotency_key": candidate.idempotency_key,
            "plan_hash": candidate.plan.plan_hash,
            "occurred_at": candidate.updated_at.isoformat(),
            "receipt_hash": (
                canonical_sha256(candidate.receipt.model_dump(mode="json"))
                if candidate.receipt is not None
                else None
            ),
            "verification_hash": (
                canonical_sha256(candidate.verification.model_dump(mode="json"))
                if candidate.verification is not None
                else None
            ),
            "path_evidence_hash": (
                canonical_sha256(candidate.path_evidence.model_dump(mode="json"))
                if candidate.path_evidence is not None
                else None
            ),
            "stable_error_code": candidate.stable_error_code,
        }
        entry = NetworkJournalEntry(
            sequence=sequence,
            previous_hash=previous_hash,
            entry_hash=canonical_sha256(entry_fields),
            phase=phase,
            idempotency_key=candidate.idempotency_key,
            plan_hash=candidate.plan.plan_hash,
            occurred_at=candidate.updated_at,
            receipt_hash=cast(str | None, entry_fields["receipt_hash"]),
            verification_hash=cast(str | None, entry_fields["verification_hash"]),
            path_evidence_hash=cast(str | None, entry_fields["path_evidence_hash"]),
            stable_error_code=candidate.stable_error_code,
        )
        result = _validated_record_update(
            candidate,
            {
                "journal_start_sequence": journal_start_sequence,
                "journal_previous_hash": journal_previous_hash,
                "journal": (*journal, entry),
            },
        )
        try:
            self._store.put_journal_step(result, self._status_from_record(result))
        except Exception as exc:
            raise ManagedPathLifecycleError("治理 lifecycle journal 持久化失败") from exc
        return result

    def _acknowledgement(
        self,
        record: NetworkGovernanceRecord,
        stage: AcknowledgementStage,
    ) -> NetworkAcknowledgement:
        receipt_hash = (
            canonical_sha256(record.receipt.model_dump(mode="json"))
            if record.receipt is not None
            else None
        )
        error = None
        if record.stable_error_code is not None and stage is not AcknowledgementStage.VERIFIED:
            error = NetworkError(
                code=(
                    NetworkErrorCode.RECOVERY_REQUIRED
                    if record.phase is NetworkGovernancePhase.RECOVERY_REQUIRED
                    else NetworkErrorCode.VERIFY_FAILED
                ),
                message="managed path lifecycle 未达到独立验证完成条件",
                correlation_id=record.plan.plan_hash,
            )
        return NetworkAcknowledgement(
            network_id=record.plan.desired.network_id,
            node_id=record.plan.desired.target_node_id,
            revision=record.plan.desired.revision,
            stage=stage,
            plan_hash=record.plan.plan_hash,
            receipt_hash=receipt_hash,
            idempotency_key=record.idempotency_key,
            error=error,
            acknowledged_at=self._now(),
        )

    def _path_status(self, record: NetworkGovernanceRecord) -> NetworkPathStatus:
        evidence = record.path_evidence
        selection = record.path_selection
        return NetworkPathStatus(
            network_id=record.plan.desired.network_id,
            node_id=record.plan.desired.target_node_id,
            revision=record.plan.desired.revision,
            path_type=(selection.path_type.value if selection is not None else "static"),
            candidate_count=(evidence.candidate_count if evidence is not None else 0),
            last_handshake_at=(evidence.last_handshake_at if evidence is not None else None),
            last_probe_at=(evidence.observed_at if evidence is not None else None),
            stable_error_code=record.stable_error_code,
        )

    def _managed_path_status(self, record: NetworkGovernanceRecord) -> ManagedPathStatus:
        """构造给新 status sink 的严格脱敏投影。"""
        return self._status_from_record(record).at(self._now())

    def _managed_path_status_for_delivery(
        self,
        record: NetworkGovernanceRecord,
    ) -> ManagedPathStatus:
        """构造递送快照；只清除 managed sink 自己留下的失败码。"""
        if record.stable_error_code == "managed_path_status_sink_failed":
            record = _validated_record_update(record, {"stable_error_code": None})
        return self._managed_path_status(record)

    @staticmethod
    def _managed_path_status_delivery_hash(status: ManagedPathStatus) -> str:
        """以公开语义字段形成递送 CAS，排除内部 journal/更新时间。"""
        payload = status.model_dump(mode="json")
        payload.pop("journal_sequence", None)
        payload.pop("updated_at", None)
        return canonical_sha256(payload)

    def _managed_path_status_pending(self, record: NetworkGovernanceRecord) -> bool:
        if self._managed_path_status_sink is None:
            return False
        status = self._managed_path_status_for_delivery(record)
        expected = self._managed_path_status_delivery_hash(status)
        return (
            not record.managed_path_status_delivered
            or record.managed_path_status_delivery_hash != expected
        )

    def _maybe_crash(self, boundary: LifecycleCrashBoundary) -> None:
        if self._crash_after is boundary:
            self._crash_after = None
            raise LifecycleInjectedCrash(f"fake lifecycle crash after {boundary.value}")

    @staticmethod
    def _check_cancelled(cancellation: ToolCancellationToken) -> None:
        if cancellation.cancelled:
            raise asyncio.CancelledError

    @staticmethod
    def _idempotency_key(plan: NetworkPlan) -> str:
        return network_operation_idempotency_key(plan)

    @staticmethod
    def _record_claim_key(record: NetworkGovernanceRecord) -> tuple[str, str, int]:
        return (
            str(record.plan.desired.network_id),
            str(record.plan.desired.target_node_id),
            record.plan.desired.revision,
        )

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


def redacted_managed_path_status_payload(status: ManagedPathStatus) -> dict[str, object]:
    """导出新 status schema 的固定脱敏字段。"""
    return _redacted_managed_path_status_payload(status)
