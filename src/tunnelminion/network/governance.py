"""受管网络专用的 L3 本机授权、执行、回滚与恢复工作流。"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import re
import sqlite3
from collections.abc import Callable, Generator
from contextlib import contextmanager, suppress
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Protocol, Self, cast

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
)
from tunnelminion.network.path_controller import (
    DirectPathEvidence,
    NetworkPathType,
    PathSelection,
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


class NetworkAuthorizationReadPort(Protocol):
    """供 policy/lifecycle 使用的只读授权端口。"""

    def list_grants(
        self,
        network_id: NetworkId,
        node_id: NodeId,
    ) -> tuple[NetworkAuthorizationGrant, ...]: ...


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


class SQLiteNetworkAuthorizationRepository:
    """现有网络治理 SQLite 中唯一权威的 L3 授权仓储。"""

    _TABLE = "network_authorization_grants"
    _COLUMNS = frozenset({"authorization_id", "network_id", "node_id", "payload"})

    def __init__(
        self,
        path: Path | str | None = None,
        *,
        connection: sqlite3.Connection | None = None,
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
        self._migrate()

    @property
    def read_only(self) -> NetworkAuthorizationReadPort:
        """返回只读端口，避免消费者拿到写方法。"""
        return SQLiteNetworkAuthorizationReadPort(self)

    def approve(
        self,
        grant: NetworkAuthorizationGrant,
        *,
        local_control: bool,
    ) -> NetworkAuthorizationGrant:
        """由本机控制面原子保存一次不可覆盖的授权。"""
        if not local_control:
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
        local_control: bool,
    ) -> NetworkAuthorizationGrant:
        """由本机控制面原子撤销；撤销后的 ID 永不恢复或换绑。"""
        if not local_control:
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
                revoked = existing.model_copy(update={"revoked_at": revoked_at})
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
        repository: SQLiteNetworkAuthorizationRepository | None = None,
    ) -> None:
        self._repository = repository

    def bind(self, repository: SQLiteNetworkAuthorizationRepository) -> None:
        """将策略门面绑定到治理 store 的唯一授权仓储。"""
        if self._repository is not None and self._repository is not repository:
            raise ValueError("网络策略不得绑定多个授权仓储")
        self._repository = repository

    def read_port(self) -> NetworkAuthorizationReadPort:
        return self._require_repository().read_only

    def _require_repository(self) -> SQLiteNetworkAuthorizationRepository:
        if self._repository is None:
            raise NetworkAuthorizationStorageError("网络策略尚未绑定授权仓储")
        return self._repository

    def approve(
        self,
        grant: NetworkAuthorizationGrant,
        *,
        local_control: bool,
    ) -> NetworkAuthorizationGrant:
        return self._require_repository().approve(grant, local_control=local_control)

    def revoke(
        self,
        authorization_id: AuthorizationId,
        *,
        revoked_at: datetime,
        local_control: bool,
    ) -> NetworkAuthorizationGrant:
        return self._require_repository().revoke(
            authorization_id,
            revoked_at=revoked_at,
            local_control=local_control,
        )

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


class NetworkJournalEntry(BaseModel):
    """一次已落盘的生命周期边界；不保存计划正文或秘密。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    sequence: int = Field(ge=0)
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
    acknowledgement_delivered: bool = False
    path_status_delivered: bool = False
    journal: tuple[NetworkJournalEntry, ...] = Field(default=(), max_length=128)

    @model_validator(mode="after")
    def validate_lifecycle_bindings(self) -> Self:
        if self.updated_at.tzinfo is None or self.updated_at.utcoffset() != timedelta(0):
            raise ValueError("治理记录时间必须使用 timezone-aware UTC")
        previous = -1
        for entry in self.journal:
            if entry.sequence != previous + 1:
                raise ValueError("生命周期 journal 序号必须连续")
            if (
                entry.idempotency_key != self.idempotency_key
                or entry.plan_hash != self.plan.plan_hash
            ):
                raise ValueError("生命周期 journal 必须绑定同一计划")
            previous = entry.sequence
        if self.path_evidence is not None:
            if self.path_evidence.revision != self.plan.desired.revision:
                raise ValueError("路径证据 revision 必须绑定计划")
            if self.path_evidence.provider is not self.plan.desired.provider:
                raise ValueError("路径证据 Provider 必须绑定计划")
        if (
            self.path_selection is not None
            and self.path_selection.revision < self.plan.desired.revision
        ):
            raise ValueError("路径选择 revision 不得早于计划")
        return self


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
        self._authorization_repository = SQLiteNetworkAuthorizationRepository(
            connection=self._connection
        )

    @property
    def authorization_repository(self) -> SQLiteNetworkAuthorizationRepository:
        """同一本治理数据库中的唯一 L3 授权仓储。"""
        return self._authorization_repository

    def list_grants(
        self,
        network_id: NetworkId,
        node_id: NodeId,
    ) -> tuple[NetworkAuthorizationGrant, ...]:
        """兼容只读 matcher 的查询入口，不暴露授权写方法。"""
        return self._authorization_repository.list_grants(network_id, node_id)

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
            WHERE json_extract(payload, '$.phase') IN (
                'observing', 'planning', 'authorized', 'rechecking',
                'applying', 'applied', 'verifying', 'provider_verified',
                'path_verifying', 'path_reconciling', 'rolling_back',
                'acknowledging', 'recovering'
            )
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
        policy.bind(store.authorization_repository)

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


_LIFECYCLE_UNSET = object()


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
        ledger: NetworkOwnershipLedger | None = None,
        clock: Callable[[], datetime] | None = None,
        commit_last_known_good: Callable[[SignedDesiredConfig], object] | None = None,
        crash_after: LifecycleCrashBoundary | None = None,
    ) -> None:
        self._provider = provider
        self._policy = policy
        self._store = store
        self._acknowledgements = acknowledgements
        self._path_verifier = path_verifier
        self._path_controller = path_controller
        self._path_status_sink = path_status_sink
        self._ledger = ledger
        self._clock = clock or (lambda: datetime.now(UTC))
        self._commit_last_known_good = commit_last_known_good
        self._crash_after = crash_after
        self._lock = asyncio.Lock()
        policy.bind(store.authorization_repository)

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
            if existing is not None and existing.phase in {
                NetworkGovernancePhase.VERIFIED,
                NetworkGovernancePhase.PATH_DEGRADED,
            }:
                return await self._retry_sinks(existing)
            if existing is not None and existing.phase is NetworkGovernancePhase.RECOVERY_REQUIRED:
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
        try:
            receipt = await self._provider.apply(
                record.plan,
                idempotency_key=record.idempotency_key,
                cancellation=cancellation,
            )
        except asyncio.CancelledError:
            self._journal(
                record,
                NetworkGovernancePhase.APPLYING,
                stable_error_code=NetworkErrorCode.RECOVERY_REQUIRED.value,
            )
            raise
        except TimeoutError:
            self._journal(
                record,
                NetworkGovernancePhase.APPLYING,
                stable_error_code=NetworkErrorCode.RECOVERY_REQUIRED.value,
            )
            raise
        self._maybe_crash(LifecycleCrashBoundary.APPLY)
        record = self._journal(
            record,
            NetworkGovernancePhase.APPLIED,
            receipt=receipt,
            stable_error_code=(receipt.error.code.value if receipt.error else None),
        )
        if receipt.status is not ReceiptStatus.APPLIED:
            return await self._rollback(record, receipt, cancellation=cancellation)

        record = self._journal(record, NetworkGovernancePhase.VERIFYING)
        verification = await self._provider.verify(record.plan)
        record = self._journal(
            record,
            NetworkGovernancePhase.PROVIDER_VERIFIED,
            verification=verification,
            stable_error_code=(verification.error.code.value if verification.error else None),
        )
        self._maybe_crash(LifecycleCrashBoundary.VERIFY)
        if not verification.succeeded:
            return await self._rollback(record, receipt, cancellation=cancellation)
        return await self._verify_path(record)

    async def _verify_path(self, record: NetworkGovernanceRecord) -> NetworkGovernanceRecord:
        record = self._journal(record, NetworkGovernancePhase.PATH_VERIFYING)
        try:
            evidence = await self._path_verifier.verify(record.plan, now=self._now())
        except asyncio.CancelledError:
            raise
        except Exception:
            degraded = self._degrade_path(record, "path_probe_failed")
            return await degraded
        if (
            evidence.revision != record.plan.desired.revision
            or evidence.provider is not record.plan.desired.provider
        ):
            return await self._degrade_path(record, "path_evidence_binding_mismatch")
        record = self._journal(
            record,
            NetworkGovernancePhase.PATH_RECONCILING,
            path_evidence=evidence,
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
        except Exception:
            return await self._degrade_path(record, "path_controller_failed")
        if not evidence.verified:
            return await self._degrade_path(
                record,
                evidence.stable_error_code.value
                if evidence.stable_error_code is not None
                else "path_verify_failed",
                selection=selection,
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
        try:
            observed = await self._provider.observe(record.plan.desired.interface_name)
        except Exception:
            return self._journal(
                record,
                NetworkGovernancePhase.RECOVERY_REQUIRED,
                stable_error_code=NetworkErrorCode.RECOVERY_REQUIRED.value,
            )
        if not self._ledger_matches(record.plan) or observed.ownership in {
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
        if receipt is None:
            if original.phase in {
                NetworkGovernancePhase.OBSERVING,
                NetworkGovernancePhase.PLANNING,
                NetworkGovernancePhase.AUTHORIZED,
                NetworkGovernancePhase.RECHECKING,
            }:
                verification = await self._provider.verify(record.plan)
                return self._journal(
                    record,
                    NetworkGovernancePhase.RECOVERY_REQUIRED,
                    verification=verification,
                    stable_error_code=NetworkErrorCode.RECOVERY_REQUIRED.value,
                )
            try:
                recovered = await self._provider.recover(cancellation=cancellation)
            except Exception:
                return self._journal(
                    record,
                    NetworkGovernancePhase.RECOVERY_REQUIRED,
                    stable_error_code=NetworkErrorCode.RECOVERY_REQUIRED.value,
                )
            receipt = next(
                (item for item in recovered if item.plan_hash == record.plan.plan_hash),
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
        verification = await self._provider.verify(record.plan)
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
            )
        try:
            await self._acknowledgements.acknowledge(self._acknowledgement(record, stage))
        except Exception:
            return self._journal(record, record.phase, stable_error_code="ack_sink_failed")
        return self._journal(
            record,
            record.phase,
            acknowledgement_delivered=True,
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
        if self._path_status_sink is None:
            return self._journal(
                record,
                final_phase,
                path_status_delivered=True,
            )
        if not record.path_status_delivered:
            try:
                await self._path_status_sink.publish(
                    self._path_status(record),
                    idempotency_key=record.idempotency_key,
                )
            except Exception:
                return self._journal(record, final_phase, stable_error_code="path_sink_failed")
            record = self._journal(
                record,
                final_phase,
                path_status_delivered=True,
            )
        return record

    async def _retry_sinks(self, record: NetworkGovernanceRecord) -> NetworkGovernanceRecord:
        if record.acknowledgement_delivered and record.path_status_delivered:
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

    def _ledger_matches(self, plan: NetworkPlan) -> bool:
        if self._ledger is None:
            return True
        entry = self._ledger.get(plan.desired.network_id, plan.desired.target_node_id)
        if plan.action is NetworkAction.CREATE:
            return True
        ownership = getattr(entry, "ownership", None)
        return ownership is not None and ownership == plan.ownership

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
        acknowledgement_delivered: bool | object = _LIFECYCLE_UNSET,
        path_status_delivered: bool | object = _LIFECYCLE_UNSET,
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
            ("acknowledgement_delivered", acknowledgement_delivered),
            ("path_status_delivered", path_status_delivered),
            ("stable_error_code", stable_error_code),
        ):
            if value is not _LIFECYCLE_UNSET:
                updates[name] = value
        candidate = record.model_copy(update=updates)
        entry = NetworkJournalEntry(
            sequence=len(record.journal),
            phase=phase,
            idempotency_key=candidate.idempotency_key,
            plan_hash=candidate.plan.plan_hash,
            occurred_at=candidate.updated_at,
            receipt_hash=(
                canonical_sha256(candidate.receipt.model_dump(mode="json"))
                if candidate.receipt is not None
                else None
            ),
            verification_hash=(
                canonical_sha256(candidate.verification.model_dump(mode="json"))
                if candidate.verification is not None
                else None
            ),
            path_evidence_hash=(
                canonical_sha256(candidate.path_evidence.model_dump(mode="json"))
                if candidate.path_evidence is not None
                else None
            ),
            stable_error_code=candidate.stable_error_code,
        )
        result = candidate.model_copy(update={"journal": (*record.journal, entry)})
        try:
            self._store.put(result)
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
