"""Coordinator 受管网络地址、元数据、签名配置与 revision saga 控制面。"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import sqlite3
from collections import defaultdict, deque
from collections.abc import Callable, Collection, Sequence
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from time import monotonic
from typing import cast

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from pydantic import BaseModel, ConfigDict, Field, model_validator

from tunnelminion.coordinator.contracts import (
    CoordinatorAuditAction,
    CoordinatorErrorCode,
    VerificationKeyView,
)
from tunnelminion.coordinator.identity import SigningKeyService
from tunnelminion.coordinator.registry import (
    RegistryError,
    SQLiteCoordinatorStore,
    insert_audit_for_transaction,
    next_revision_for_transaction,
)
from tunnelminion.domain.identifiers import NetworkId, NodeId
from tunnelminion.network.contracts import (
    MAX_ENDPOINT_CANDIDATES,
    AcknowledgementStage,
    AddressLease,
    CandidateSource,
    DesiredNetworkConfig,
    EndpointCandidate,
    KeyLifecycle,
    LeaseStatus,
    NetworkAcknowledgement,
    RelayRole,
    SignedDesiredConfig,
)

MAX_POOL_ADDRESSES = 65_536
MAX_RESERVED_ADDRESSES = 256
MAX_CANDIDATE_BYTES = 1_024
MAX_CANDIDATE_TTL_SECONDS = 3_600
DEFAULT_CONFIG_TTL_SECONDS = 600
DESIRED_CONFIG_DOMAIN = b"TunnelMinion desired config v1\x00"


class SagaStatus(StrEnum):
    """共同配置修订的 Coordinator 收敛状态。"""

    PENDING = "pending"
    ACTIVE = "active"
    ROLLING_BACK = "rolling_back"
    ROLLED_BACK = "rolled_back"
    MANUAL_INTERVENTION = "manual_intervention"


class ManagedNetworkRequest(BaseModel):
    """环回管理员创建受管 network 的严格请求。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    network_id: NetworkId


class AddressPoolRequest(BaseModel):
    """环回管理员配置的有界私有地址池。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    pool: str
    reserved_addresses: tuple[str, ...] = Field(default=(), max_length=MAX_RESERVED_ADDRESSES)

    @model_validator(mode="after")
    def validate_pool(self) -> AddressPoolRequest:
        network = ipaddress.ip_network(self.pool, strict=True)
        if not network.is_private or network.num_addresses > MAX_POOL_ADDRESSES:
            raise ValueError("地址池必须是有界私有网段")
        reserved = tuple(ipaddress.ip_address(value) for value in self.reserved_addresses)
        if len(set(reserved)) != len(reserved):
            raise ValueError("保留地址不得重复")
        if any(address not in network for address in reserved):
            raise ValueError("保留地址必须属于地址池")
        return self


class AddressPoolView(BaseModel):
    """不含秘密的 network 地址池视图。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    network_id: NetworkId
    pool: str
    reserved_addresses: tuple[str, ...]
    created_at: datetime
    revoked_at: datetime | None = None


class NetworkPublicKeyView(BaseModel):
    """节点 WireGuard 公钥生命周期视图。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    network_id: NetworkId
    node_id: NodeId
    public_key: str = Field(pattern=r"^[A-Za-z0-9+/]{43}=$")
    status: KeyLifecycle
    revision: int = Field(ge=1)
    created_at: datetime
    activated_at: datetime | None = None
    retired_at: datetime | None = None


class NetworkPublicKeyRequest(BaseModel):
    """Agent 只可提交公钥，额外秘密或完整配置字段会被拒绝。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    public_key: str = Field(pattern=r"^[A-Za-z0-9+/]{43}=$")


class EndpointCandidateReport(BaseModel):
    """认证节点替换其候选集合的有界请求。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    candidates: tuple[EndpointCandidate, ...] = Field(
        default=(), max_length=MAX_ENDPOINT_CANDIDATES
    )


class RelayRoleRequest(BaseModel):
    """环回管理员显式设置 relay 角色和能力验证结果。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    role: RelayRole
    capability_verified: bool = False

    @model_validator(mode="after")
    def validate_role(self) -> RelayRoleRequest:
        if self.role is RelayRole.ACTIVE and not self.capability_verified:
            raise ValueError("active relay 必须先通过能力验证")
        return self


class RelayRoleView(BaseModel):
    """节点 relay 角色的脱敏视图。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    network_id: NetworkId
    node_id: NodeId
    role: RelayRole
    capability_verified: bool
    revision: int = Field(ge=1)
    updated_at: datetime


class SagaView(BaseModel):
    """共同 revision、逐节点阶段和回滚指令摘要。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    network_id: NetworkId
    revision: int = Field(ge=1)
    parent_revision: int = Field(ge=0)
    status: SagaStatus
    required_node_ids: tuple[NodeId, ...] = Field(min_length=1)
    acknowledgements: tuple[NetworkAcknowledgement, ...]
    rollback_node_ids: tuple[NodeId, ...]
    created_at: datetime
    updated_at: datetime


class DesiredConfigVerificationError(ValueError):
    """签名配置离线验证失败，不回显配置或签名正文。"""


class ManagedNetworkControlService:
    """使用短事务维护受管网络最小公共控制面。"""

    def __init__(
        self,
        store: SQLiteCoordinatorStore,
        signing_keys: SigningKeyService,
        *,
        clock: Callable[[], datetime] | None = None,
        monotonic_clock: Callable[[], float] = monotonic,
        candidate_updates_per_minute: int = 30,
    ) -> None:
        if candidate_updates_per_minute < 1:
            raise ValueError("候选更新速率必须大于零")
        self.store = store
        self._signing_keys = signing_keys
        self._clock = clock or (lambda: datetime.now(UTC))
        self._monotonic = monotonic_clock
        self._candidate_limit = candidate_updates_per_minute
        self._candidate_attempts: defaultdict[str, deque[float]] = defaultdict(deque)

    def create_network(self, network_id: NetworkId) -> NetworkId:
        """幂等创建 network，并只在首次创建时写入脱敏审计。"""
        now = self._now()
        with self.store.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                "SELECT 1 FROM networks WHERE network_id=?", (str(network_id),)
            ).fetchone()
            if existing is not None:
                connection.commit()
                return network_id
            connection.execute(
                "INSERT INTO networks(network_id, created_at) VALUES (?, ?)",
                (str(network_id), now.isoformat()),
            )
            connection.execute(
                "INSERT INTO revisions(network_id, value) VALUES (?, 0)",
                (str(network_id),),
            )
            insert_audit_for_transaction(
                connection,
                network_id,
                None,
                0,
                CoordinatorAuditAction.NETWORK_CREATED,
                now,
                item_count=1,
            )
            connection.commit()
        return network_id

    def configure_address_pool(
        self, network_id: NetworkId, request: AddressPoolRequest
    ) -> AddressPoolView:
        """拒绝重叠后幂等保存地址池；已有租约时不得静默改保留集合。"""
        now = self._now()
        pool = ipaddress.ip_network(request.pool, strict=True)
        normalized_pool = str(pool)
        reserved = tuple(
            sorted(str(ipaddress.ip_address(item)) for item in request.reserved_addresses)
        )
        reserved_json = _json_dump(reserved)
        with self.store.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            _require_network(connection, network_id)
            current = connection.execute(
                """SELECT * FROM network_address_pools
                WHERE network_id=? AND pool=?""",
                (str(network_id), normalized_pool),
            ).fetchone()
            if current is not None and current["revoked_at"] is None:
                if cast(str, current["reserved_json"]) != reserved_json:
                    connection.rollback()
                    raise RegistryError(
                        CoordinatorErrorCode.CONFLICT,
                        "已启用地址池的保留集合不能静默改变",
                    )
                connection.commit()
                return _pool_from_row(current)
            for row in connection.execute(
                "SELECT network_id, pool FROM network_address_pools WHERE revoked_at IS NULL"
            ).fetchall():
                if pool.overlaps(ipaddress.ip_network(cast(str, row["pool"]), strict=True)):
                    connection.rollback()
                    raise RegistryError(
                        CoordinatorErrorCode.CONFLICT,
                        "地址池与现有受管地址池重叠",
                    )
            connection.execute(
                """INSERT INTO network_address_pools(
                    network_id, pool, reserved_json, created_at, revoked_at
                ) VALUES (?, ?, ?, ?, NULL)
                ON CONFLICT(network_id, pool) DO UPDATE SET
                    reserved_json=excluded.reserved_json,
                    created_at=excluded.created_at,
                    revoked_at=NULL""",
                (str(network_id), normalized_pool, reserved_json, now.isoformat()),
            )
            revision = next_revision_for_transaction(connection, network_id)
            insert_audit_for_transaction(
                connection,
                network_id,
                None,
                revision,
                CoordinatorAuditAction.ADDRESS_POOL_CONFIGURED,
                now,
                item_count=1,
            )
            row = cast(
                sqlite3.Row,
                connection.execute(
                    """SELECT * FROM network_address_pools
                    WHERE network_id=? AND pool=?""",
                    (str(network_id), normalized_pool),
                ).fetchone(),
            )
            connection.commit()
        return _pool_from_row(row)

    def list_address_pools(self, network_id: NetworkId) -> tuple[AddressPoolView, ...]:
        """返回 network 的全部地址池生命周期记录。"""
        with self.store.connect() as connection:
            _require_network(connection, network_id)
            rows = connection.execute(
                """SELECT * FROM network_address_pools
                WHERE network_id=? ORDER BY pool""",
                (str(network_id),),
            ).fetchall()
        return tuple(_pool_from_row(row) for row in rows)

    def allocate_address(
        self, network_id: NetworkId, node_id: NodeId, *, pool: str
    ) -> AddressLease:
        """在 IMMEDIATE 事务中稳定分配首个可用 host address。"""
        now = self._now()
        normalized_pool = str(ipaddress.ip_network(pool, strict=True))
        with self.store.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            _require_node(connection, network_id, node_id)
            pool_row = connection.execute(
                """SELECT * FROM network_address_pools
                WHERE network_id=? AND pool=? AND revoked_at IS NULL""",
                (str(network_id), normalized_pool),
            ).fetchone()
            if pool_row is None:
                connection.rollback()
                raise RegistryError(CoordinatorErrorCode.FORBIDDEN, "地址池不可用于分配")
            existing = connection.execute(
                """SELECT * FROM network_address_leases
                WHERE network_id=? AND node_id=?""",
                (str(network_id), str(node_id)),
            ).fetchone()
            if existing is not None and existing["status"] != LeaseStatus.RELEASED.value:
                connection.commit()
                return _lease_from_row(existing)
            reserved = set(json.loads(cast(str, pool_row["reserved_json"])))
            occupied = {
                cast(str, row["address"]).split("/", maxsplit=1)[0]
                for row in connection.execute(
                    """SELECT address FROM network_address_leases
                    WHERE network_id=? AND status!=?""",
                    (str(network_id), LeaseStatus.RELEASED.value),
                ).fetchall()
            }
            previous = cast(str | None, existing["address"]) if existing is not None else None
            candidate = _choose_address(normalized_pool, reserved, occupied, previous)
            if candidate is None:
                connection.rollback()
                raise RegistryError(CoordinatorErrorCode.CONFLICT, "地址池没有可用地址")
            revision = next_revision_for_transaction(connection, network_id)
            connection.execute(
                """INSERT INTO network_address_leases(
                    network_id, node_id, address, pool, status, revision,
                    created_at, released_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, NULL)
                ON CONFLICT(network_id, node_id) DO UPDATE SET
                    address=excluded.address,
                    pool=excluded.pool,
                    status=excluded.status,
                    revision=excluded.revision,
                    released_at=NULL""",
                (
                    str(network_id),
                    str(node_id),
                    candidate,
                    normalized_pool,
                    LeaseStatus.RESERVED.value,
                    revision,
                    now.isoformat(),
                ),
            )
            _audit_lease(connection, network_id, node_id, revision, now)
            row = cast(
                sqlite3.Row,
                connection.execute(
                    """SELECT * FROM network_address_leases
                    WHERE network_id=? AND node_id=?""",
                    (str(network_id), str(node_id)),
                ).fetchone(),
            )
            connection.commit()
        return _lease_from_row(row)

    def set_lease_status(
        self,
        network_id: NetworkId,
        node_id: NodeId,
        status: LeaseStatus,
    ) -> AddressLease:
        """激活、释放或恢复原地址；恢复冲突时拒绝重新编号。"""
        now = self._now()
        with self.store.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            _require_node(connection, network_id, node_id)
            row = connection.execute(
                """SELECT * FROM network_address_leases
                WHERE network_id=? AND node_id=?""",
                (str(network_id), str(node_id)),
            ).fetchone()
            if row is None:
                connection.rollback()
                raise RegistryError(CoordinatorErrorCode.CONFLICT, "地址租约不存在")
            current = LeaseStatus(cast(str, row["status"]))
            if current is status:
                connection.commit()
                return _lease_from_row(row)
            if current is LeaseStatus.RELEASED and status is LeaseStatus.ACTIVE:
                collision = connection.execute(
                    """SELECT 1 FROM network_address_leases
                    WHERE network_id=? AND address=? AND node_id!=? AND status!=?""",
                    (
                        str(network_id),
                        cast(str, row["address"]),
                        str(node_id),
                        LeaseStatus.RELEASED.value,
                    ),
                ).fetchone()
                if collision is not None:
                    connection.rollback()
                    raise RegistryError(
                        CoordinatorErrorCode.CONFLICT,
                        "原稳定地址已被占用，不能静默重新编号",
                    )
            if not (
                (
                    current is LeaseStatus.RESERVED
                    and status in {LeaseStatus.ACTIVE, LeaseStatus.RELEASED}
                )
                or (current is LeaseStatus.ACTIVE and status is LeaseStatus.RELEASED)
                or (current is LeaseStatus.RELEASED and status is LeaseStatus.ACTIVE)
            ):
                connection.rollback()
                raise RegistryError(CoordinatorErrorCode.OUT_OF_ORDER, "地址租约状态迁移无效")
            revision = next_revision_for_transaction(connection, network_id)
            connection.execute(
                """UPDATE network_address_leases
                SET status=?, revision=?, released_at=?
                WHERE network_id=? AND node_id=?""",
                (
                    status.value,
                    revision,
                    now.isoformat() if status is LeaseStatus.RELEASED else None,
                    str(network_id),
                    str(node_id),
                ),
            )
            _audit_lease(connection, network_id, node_id, revision, now)
            updated = cast(
                sqlite3.Row,
                connection.execute(
                    """SELECT * FROM network_address_leases
                    WHERE network_id=? AND node_id=?""",
                    (str(network_id), str(node_id)),
                ).fetchone(),
            )
            connection.commit()
        return _lease_from_row(updated)

    def register_public_key(
        self,
        network_id: NetworkId,
        node_id: NodeId,
        request: NetworkPublicKeyRequest,
    ) -> NetworkPublicKeyView:
        """把新公钥注册为 pending，不覆盖当前 active key。"""
        now = self._now()
        with self.store.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            _require_node(connection, network_id, node_id)
            row = connection.execute(
                """SELECT * FROM network_public_keys
                WHERE network_id=? AND node_id=? AND public_key=?""",
                (str(network_id), str(node_id), request.public_key),
            ).fetchone()
            if row is not None:
                connection.commit()
                return _key_from_row(row)
            revision = next_revision_for_transaction(connection, network_id)
            connection.execute(
                """INSERT INTO network_public_keys(
                    network_id, node_id, public_key, status, revision,
                    created_at, activated_at, retired_at
                ) VALUES (?, ?, ?, ?, ?, ?, NULL, NULL)""",
                (
                    str(network_id),
                    str(node_id),
                    request.public_key,
                    KeyLifecycle.PENDING.value,
                    revision,
                    now.isoformat(),
                ),
            )
            _audit_key(connection, network_id, node_id, revision, now)
            saved = cast(
                sqlite3.Row,
                connection.execute(
                    """SELECT * FROM network_public_keys
                    WHERE network_id=? AND node_id=? AND public_key=?""",
                    (str(network_id), str(node_id), request.public_key),
                ).fetchone(),
            )
            connection.commit()
        return _key_from_row(saved)

    def activate_public_key(
        self, network_id: NetworkId, node_id: NodeId, public_key: str
    ) -> NetworkPublicKeyView:
        """原子激活 pending key，并把旧 active key 标记 retired。"""
        request = NetworkPublicKeyRequest(public_key=public_key)
        now = self._now()
        with self.store.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            _require_node(connection, network_id, node_id)
            row = connection.execute(
                """SELECT * FROM network_public_keys
                WHERE network_id=? AND node_id=? AND public_key=?""",
                (str(network_id), str(node_id), request.public_key),
            ).fetchone()
            if row is None:
                connection.rollback()
                raise RegistryError(CoordinatorErrorCode.CONFLICT, "pending 公钥不存在")
            if row["status"] == KeyLifecycle.ACTIVE.value:
                connection.commit()
                return _key_from_row(row)
            if row["status"] != KeyLifecycle.PENDING.value:
                connection.rollback()
                raise RegistryError(CoordinatorErrorCode.OUT_OF_ORDER, "retired 公钥不能重新激活")
            revision = next_revision_for_transaction(connection, network_id)
            connection.execute(
                """UPDATE network_public_keys
                SET status=?, revision=?, retired_at=?
                WHERE network_id=? AND node_id=? AND status=?""",
                (
                    KeyLifecycle.RETIRED.value,
                    revision,
                    now.isoformat(),
                    str(network_id),
                    str(node_id),
                    KeyLifecycle.ACTIVE.value,
                ),
            )
            connection.execute(
                """UPDATE network_public_keys
                SET status=?, revision=?, activated_at=?, retired_at=NULL
                WHERE network_id=? AND node_id=? AND public_key=?""",
                (
                    KeyLifecycle.ACTIVE.value,
                    revision,
                    now.isoformat(),
                    str(network_id),
                    str(node_id),
                    request.public_key,
                ),
            )
            _audit_key(connection, network_id, node_id, revision, now)
            updated = cast(
                sqlite3.Row,
                connection.execute(
                    """SELECT * FROM network_public_keys
                    WHERE network_id=? AND node_id=? AND public_key=?""",
                    (str(network_id), str(node_id), request.public_key),
                ).fetchone(),
            )
            connection.commit()
        return _key_from_row(updated)

    def list_public_keys(
        self, network_id: NetworkId, node_id: NodeId
    ) -> tuple[NetworkPublicKeyView, ...]:
        """按创建时间返回一个节点的公钥生命周期。"""
        with self.store.connect() as connection:
            _require_node(connection, network_id, node_id)
            rows = connection.execute(
                """SELECT * FROM network_public_keys
                WHERE network_id=? AND node_id=? ORDER BY created_at, public_key""",
                (str(network_id), str(node_id)),
            ).fetchall()
        return tuple(_key_from_row(row) for row in rows)

    def replace_candidates(
        self,
        network_id: NetworkId,
        node_id: NodeId,
        report: EndpointCandidateReport,
    ) -> tuple[EndpointCandidate, ...]:
        """有预算地替换认证节点候选；只保存可解释来源和 TTL。"""
        self._check_candidate_rate(network_id, node_id)
        now = self._now()
        encoded = report.model_dump_json().encode()
        if len(encoded) > MAX_CANDIDATE_BYTES:
            raise RegistryError(CoordinatorErrorCode.SNAPSHOT_TOO_LARGE, "候选集合超出字节预算")
        identities = {(item.host, item.port, item.source.value) for item in report.candidates}
        if len(identities) != len(report.candidates):
            raise RegistryError(CoordinatorErrorCode.CONFLICT, "候选 endpoint 不得重复")
        for item in report.candidates:
            if item.expires_at <= now:
                raise RegistryError(CoordinatorErrorCode.OUT_OF_ORDER, "候选 endpoint 已过期")
            if item.expires_at - now > timedelta(seconds=MAX_CANDIDATE_TTL_SECONDS):
                raise RegistryError(CoordinatorErrorCode.FORBIDDEN, "候选 endpoint TTL 超出预算")
        with self.store.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            _require_node(connection, network_id, node_id)
            connection.execute(
                """DELETE FROM network_endpoint_candidates
                WHERE network_id=? AND node_id=?""",
                (str(network_id), str(node_id)),
            )
            connection.executemany(
                """INSERT INTO network_endpoint_candidates(
                    network_id, node_id, host, port, source,
                    observed_at, expires_at, received_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                tuple(
                    (
                        str(network_id),
                        str(node_id),
                        item.host,
                        item.port,
                        item.source.value,
                        item.observed_at.isoformat(),
                        item.expires_at.isoformat(),
                        now.isoformat(),
                    )
                    for item in report.candidates
                ),
            )
            revision = next_revision_for_transaction(connection, network_id)
            insert_audit_for_transaction(
                connection,
                network_id,
                node_id,
                revision,
                CoordinatorAuditAction.ENDPOINT_CANDIDATES_REPLACED,
                now,
                item_count=len(report.candidates),
            )
            connection.commit()
        return report.candidates

    def fresh_candidates(
        self, network_id: NetworkId, node_id: NodeId
    ) -> tuple[EndpointCandidate, ...]:
        """只返回尚未过期的候选，不把候选宣称为已验证路径。"""
        now = self._now()
        with self.store.connect() as connection:
            _require_node(connection, network_id, node_id)
            rows = connection.execute(
                """SELECT * FROM network_endpoint_candidates
                WHERE network_id=? AND node_id=? AND expires_at>?
                ORDER BY source, host, port""",
                (str(network_id), str(node_id), now.isoformat()),
            ).fetchall()
        return tuple(_candidate_from_row(row) for row in rows)

    def set_relay_role(
        self,
        network_id: NetworkId,
        node_id: NodeId,
        request: RelayRoleRequest,
    ) -> RelayRoleView:
        """仅保存管理员显式角色；active 必须带已验证能力。"""
        now = self._now()
        with self.store.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            _require_node(connection, network_id, node_id)
            existing = connection.execute(
                """SELECT * FROM network_relay_roles
                WHERE network_id=? AND node_id=?""",
                (str(network_id), str(node_id)),
            ).fetchone()
            if (
                existing is not None
                and existing["role"] == request.role.value
                and bool(existing["capability_verified"]) is request.capability_verified
            ):
                connection.commit()
                return _relay_from_row(existing)
            revision = next_revision_for_transaction(connection, network_id)
            connection.execute(
                """INSERT INTO network_relay_roles(
                    network_id, node_id, role, capability_verified, revision, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(network_id, node_id) DO UPDATE SET
                    role=excluded.role,
                    capability_verified=excluded.capability_verified,
                    revision=excluded.revision,
                    updated_at=excluded.updated_at""",
                (
                    str(network_id),
                    str(node_id),
                    request.role.value,
                    int(request.capability_verified),
                    revision,
                    now.isoformat(),
                ),
            )
            insert_audit_for_transaction(
                connection,
                network_id,
                node_id,
                revision,
                CoordinatorAuditAction.RELAY_ROLE_CHANGED,
                now,
                item_count=1,
            )
            row = cast(
                sqlite3.Row,
                connection.execute(
                    """SELECT * FROM network_relay_roles
                    WHERE network_id=? AND node_id=?""",
                    (str(network_id), str(node_id)),
                ).fetchone(),
            )
            connection.commit()
        return _relay_from_row(row)

    def next_revision(self, network_id: NetworkId) -> int:
        """返回当前观察到的下一全局 revision；发布时仍由事务校验。"""
        with self.store.connect() as connection:
            row = connection.execute(
                "SELECT value FROM revisions WHERE network_id=?", (str(network_id),)
            ).fetchone()
        if row is None:
            raise RegistryError(CoordinatorErrorCode.FORBIDDEN, "network 不存在")
        return cast(int, row["value"]) + 1

    def publish_desired_configs(
        self,
        configs: Sequence[DesiredNetworkConfig],
        *,
        ttl_seconds: int = DEFAULT_CONFIG_TTL_SECONDS,
    ) -> tuple[SignedDesiredConfig, ...]:
        """事务发布共同 revision，并对每个目标生成域分离 Ed25519 envelope。"""
        if not configs:
            raise ValueError("至少需要一个目标配置")
        if not 30 <= ttl_seconds <= 3_600:
            raise ValueError("签名配置 TTL 必须在 30 到 3600 秒之间")
        first = configs[0]
        if any(
            item.network_id != first.network_id
            or item.revision != first.revision
            or item.parent_revision != first.parent_revision
            for item in configs
        ):
            raise RegistryError(CoordinatorErrorCode.CONFLICT, "配置批次必须共享 network/revision")
        target_ids = tuple(item.target_node_id for item in configs)
        if len({str(item) for item in target_ids}) != len(target_ids):
            raise RegistryError(CoordinatorErrorCode.CONFLICT, "配置目标节点不得重复")
        now = self._now()
        expires_at = now + timedelta(seconds=ttl_seconds)
        metadata, private_key = self._signing_keys.active_signer()
        fingerprint = f"sha256:{metadata.fingerprint}"
        envelopes = tuple(
            _sign_config(
                item,
                key_id=metadata.key_id,
                fingerprint=fingerprint,
                issued_at=now,
                expires_at=expires_at,
                private_key=private_key,
            )
            for item in configs
        )
        with self.store.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            _require_network(connection, first.network_id)
            existing = connection.execute(
                """SELECT envelope_json FROM network_desired_configs
                WHERE network_id=? AND revision=? ORDER BY node_id""",
                (str(first.network_id), first.revision),
            ).fetchall()
            if existing:
                restored = tuple(
                    SignedDesiredConfig.model_validate_json(cast(str, row["envelope_json"]))
                    for row in existing
                )
                restored_by_node = {str(item.config.target_node_id): item for item in restored}
                if {node_id: item.config for node_id, item in restored_by_node.items()} != {
                    str(item.target_node_id): item for item in configs
                }:
                    connection.rollback()
                    raise RegistryError(
                        CoordinatorErrorCode.CONFLICT,
                        "revision 已绑定到不同配置",
                    )
                connection.commit()
                return tuple(restored_by_node[str(item.target_node_id)] for item in configs)
            for node_id in target_ids:
                _require_node(connection, first.network_id, node_id)
            revision = next_revision_for_transaction(connection, first.network_id)
            if revision != first.revision:
                connection.rollback()
                raise RegistryError(
                    CoordinatorErrorCode.OUT_OF_ORDER,
                    "配置 revision 不是当前事务的下一 revision",
                )
            connection.execute(
                """INSERT INTO network_sagas(
                    network_id, revision, parent_revision, status,
                    required_nodes_json, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    str(first.network_id),
                    revision,
                    first.parent_revision,
                    SagaStatus.PENDING.value,
                    _json_dump(tuple(sorted(str(item) for item in target_ids))),
                    now.isoformat(),
                    now.isoformat(),
                ),
            )
            connection.executemany(
                """INSERT INTO network_desired_configs(
                    network_id, node_id, revision, parent_revision,
                    key_id, key_fingerprint, envelope_json, status, expires_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                tuple(
                    (
                        str(item.config.network_id),
                        str(item.config.target_node_id),
                        item.config.revision,
                        item.config.parent_revision,
                        item.key_id,
                        item.key_fingerprint,
                        item.model_dump_json(),
                        SagaStatus.PENDING.value,
                        item.expires_at.isoformat(),
                    )
                    for item in envelopes
                ),
            )
            insert_audit_for_transaction(
                connection,
                first.network_id,
                None,
                revision,
                CoordinatorAuditAction.DESIRED_CONFIG_PUBLISHED,
                now,
                item_count=len(envelopes),
            )
            connection.commit()
        return envelopes

    def acknowledge(self, acknowledgement: NetworkAcknowledgement) -> SagaView:
        """幂等收敛逐节点阶段；失败触发回滚，全部 verified 后才 active。"""
        now = self._now()
        with self.store.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            saga = connection.execute(
                """SELECT * FROM network_sagas
                WHERE network_id=? AND revision=?""",
                (str(acknowledgement.network_id), acknowledgement.revision),
            ).fetchone()
            if saga is None:
                connection.rollback()
                raise RegistryError(CoordinatorErrorCode.CONFLICT, "配置 saga 不存在")
            required = tuple(
                NodeId(item) for item in json.loads(cast(str, saga["required_nodes_json"]))
            )
            if acknowledgement.node_id not in required:
                connection.rollback()
                raise RegistryError(CoordinatorErrorCode.FORBIDDEN, "节点不属于该配置 saga")
            existing = connection.execute(
                """SELECT * FROM network_acknowledgements
                WHERE network_id=? AND node_id=? AND revision=?""",
                (
                    str(acknowledgement.network_id),
                    str(acknowledgement.node_id),
                    acknowledgement.revision,
                ),
            ).fetchone()
            if existing is not None:
                previous = _ack_from_row(existing)
                if previous == acknowledgement:
                    connection.commit()
                    return self.get_saga(acknowledgement.network_id, acknowledgement.revision)
                if _stage_rank(acknowledgement.stage) <= _stage_rank(previous.stage):
                    connection.rollback()
                    raise RegistryError(
                        CoordinatorErrorCode.OUT_OF_ORDER,
                        "acknowledgement 阶段乱序或内容冲突",
                    )
            connection.execute(
                """INSERT INTO network_acknowledgements(
                    network_id, node_id, revision, stage, plan_hash,
                    receipt_hash, error_code, error_json, acknowledged_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(network_id, node_id, revision) DO UPDATE SET
                    stage=excluded.stage,
                    plan_hash=excluded.plan_hash,
                    receipt_hash=excluded.receipt_hash,
                    error_code=excluded.error_code,
                    error_json=excluded.error_json,
                    acknowledged_at=excluded.acknowledged_at""",
                (
                    str(acknowledgement.network_id),
                    str(acknowledgement.node_id),
                    acknowledgement.revision,
                    acknowledgement.stage.value,
                    acknowledgement.plan_hash,
                    acknowledgement.receipt_hash,
                    acknowledgement.error.code.value if acknowledgement.error else None,
                    (
                        acknowledgement.error.model_dump_json()
                        if acknowledgement.error is not None
                        else None
                    ),
                    acknowledgement.acknowledged_at.isoformat(),
                ),
            )
            acknowledgements = tuple(
                _ack_from_row(row)
                for row in connection.execute(
                    """SELECT * FROM network_acknowledgements
                    WHERE network_id=? AND revision=? ORDER BY node_id""",
                    (str(acknowledgement.network_id), acknowledgement.revision),
                ).fetchall()
            )
            status = _saga_status(required, acknowledgements)
            connection.execute(
                """UPDATE network_sagas SET status=?, updated_at=?
                WHERE network_id=? AND revision=?""",
                (
                    status.value,
                    now.isoformat(),
                    str(acknowledgement.network_id),
                    acknowledgement.revision,
                ),
            )
            connection.execute(
                """UPDATE network_desired_configs SET status=?
                WHERE network_id=? AND revision=?""",
                (
                    status.value,
                    str(acknowledgement.network_id),
                    acknowledgement.revision,
                ),
            )
            insert_audit_for_transaction(
                connection,
                acknowledgement.network_id,
                acknowledgement.node_id,
                acknowledgement.revision,
                CoordinatorAuditAction.NETWORK_ACKNOWLEDGED,
                now,
                item_count=1,
            )
            connection.commit()
        return self.get_saga(acknowledgement.network_id, acknowledgement.revision)

    def get_saga(self, network_id: NetworkId, revision: int) -> SagaView:
        """读取 saga 与仍需回滚的已应用节点。"""
        with self.store.connect() as connection:
            row = connection.execute(
                """SELECT * FROM network_sagas
                WHERE network_id=? AND revision=?""",
                (str(network_id), revision),
            ).fetchone()
            if row is None:
                raise RegistryError(CoordinatorErrorCode.CONFLICT, "配置 saga 不存在")
            acknowledgements = tuple(
                _ack_from_row(item)
                for item in connection.execute(
                    """SELECT * FROM network_acknowledgements
                    WHERE network_id=? AND revision=? ORDER BY node_id""",
                    (str(network_id), revision),
                ).fetchall()
            )
        required = tuple(NodeId(item) for item in json.loads(cast(str, row["required_nodes_json"])))
        by_node = {str(item.node_id): item for item in acknowledgements}
        rollback = (
            tuple(
                node_id
                for node_id in required
                if str(node_id) in by_node
                and by_node[str(node_id)].stage
                in {AcknowledgementStage.APPLIED, AcknowledgementStage.VERIFIED}
            )
            if SagaStatus(cast(str, row["status"])) is SagaStatus.ROLLING_BACK
            else ()
        )
        return SagaView(
            network_id=network_id,
            revision=revision,
            parent_revision=cast(int, row["parent_revision"]),
            status=SagaStatus(cast(str, row["status"])),
            required_node_ids=required,
            acknowledgements=acknowledgements,
            rollback_node_ids=rollback,
            created_at=datetime.fromisoformat(cast(str, row["created_at"])),
            updated_at=datetime.fromisoformat(cast(str, row["updated_at"])),
        )

    def _check_candidate_rate(self, network_id: NetworkId, node_id: NodeId) -> None:
        key = f"{network_id}:{node_id}"
        now = self._monotonic()
        attempts = self._candidate_attempts[key]
        while attempts and now - attempts[0] >= 60:
            attempts.popleft()
        if len(attempts) >= self._candidate_limit:
            raise RegistryError(CoordinatorErrorCode.RATE_LIMITED, "候选更新速率超出预算")
        attempts.append(now)

    def _now(self) -> datetime:
        value = self._clock()
        return value.astimezone(UTC) if value.tzinfo is not None else value.replace(tzinfo=UTC)


def verify_signed_desired_config(
    envelope: SignedDesiredConfig,
    verification_keys: Collection[VerificationKeyView],
    pinned_fingerprints: Collection[str],
    *,
    network_id: NetworkId,
    target_node_id: NodeId,
    parent_revision: int,
    now: datetime | None = None,
) -> DesiredNetworkConfig:
    """使用固定指纹、域分离 payload 和目标/父修订绑定离线验签。"""
    current = now or datetime.now(UTC)
    if current.tzinfo is None:
        current = current.replace(tzinfo=UTC)
    config = envelope.config
    if envelope.expires_at <= current or envelope.issued_at > current + timedelta(seconds=5):
        raise DesiredConfigVerificationError("签名配置不在有效时间窗口")
    if (
        config.network_id != network_id
        or config.target_node_id != target_node_id
        or config.parent_revision != parent_revision
    ):
        raise DesiredConfigVerificationError("签名配置目标或父 revision 不匹配")
    key = next((item for item in verification_keys if item.key_id == envelope.key_id), None)
    if key is None:
        raise DesiredConfigVerificationError("签名配置使用未知 key")
    if key.activates_at > current or (key.retires_at is not None and key.retires_at <= current):
        raise DesiredConfigVerificationError("签名 key 不在验证窗口")
    expected_fingerprint = f"sha256:{key.fingerprint}"
    if envelope.key_fingerprint != expected_fingerprint or envelope.key_fingerprint not in set(
        pinned_fingerprints
    ):
        raise DesiredConfigVerificationError("签名 key 指纹未固定")
    try:
        public_raw = _b64url_decode(key.public_key)
        if f"sha256:{hashlib.sha256(public_raw).hexdigest()}" != expected_fingerprint:
            raise DesiredConfigVerificationError("签名公钥与指纹不一致")
        Ed25519PublicKey.from_public_bytes(public_raw).verify(
            _b64url_decode(envelope.signature),
            _desired_payload(config, envelope.issued_at, envelope.expires_at),
        )
    except (InvalidSignature, ValueError, TypeError) as exc:
        if isinstance(exc, DesiredConfigVerificationError):
            raise
        raise DesiredConfigVerificationError("签名配置验签失败") from exc
    return config


def _sign_config(
    config: DesiredNetworkConfig,
    *,
    key_id: str,
    fingerprint: str,
    issued_at: datetime,
    expires_at: datetime,
    private_key: Ed25519PrivateKey,
) -> SignedDesiredConfig:
    signature = private_key.sign(_desired_payload(config, issued_at, expires_at))
    return SignedDesiredConfig(
        config=config,
        key_id=key_id,
        key_fingerprint=fingerprint,
        issued_at=issued_at,
        expires_at=expires_at,
        signature=_b64url(signature),
    )


def _desired_payload(
    config: DesiredNetworkConfig, issued_at: datetime, expires_at: datetime
) -> bytes:
    body = {
        "config": config.model_dump(mode="json"),
        "issued_at": issued_at.isoformat(),
        "expires_at": expires_at.isoformat(),
    }
    return DESIRED_CONFIG_DOMAIN + _json_dump(body).encode()


def _choose_address(
    pool: str,
    reserved: set[str],
    occupied: set[str],
    previous: str | None,
) -> str | None:
    network = ipaddress.ip_network(pool, strict=True)
    if previous is not None:
        previous_ip = ipaddress.ip_interface(previous).ip
        if previous_ip in network and str(previous_ip) not in reserved | occupied:
            return f"{previous_ip}/{previous_ip.max_prefixlen}"
    for address in network.hosts():
        if str(address) not in reserved | occupied:
            return f"{address}/{address.max_prefixlen}"
    return None


def _require_network(connection: sqlite3.Connection, network_id: NetworkId) -> None:
    if (
        connection.execute(
            "SELECT 1 FROM networks WHERE network_id=?", (str(network_id),)
        ).fetchone()
        is None
    ):
        raise RegistryError(CoordinatorErrorCode.FORBIDDEN, "network 不存在")


def _require_node(connection: sqlite3.Connection, network_id: NetworkId, node_id: NodeId) -> None:
    if (
        connection.execute(
            "SELECT 1 FROM nodes WHERE network_id=? AND node_id=?",
            (str(network_id), str(node_id)),
        ).fetchone()
        is None
    ):
        raise RegistryError(CoordinatorErrorCode.FORBIDDEN, "节点不属于该 network")


def _pool_from_row(row: sqlite3.Row) -> AddressPoolView:
    return AddressPoolView(
        network_id=NetworkId(cast(str, row["network_id"])),
        pool=cast(str, row["pool"]),
        reserved_addresses=tuple(json.loads(cast(str, row["reserved_json"]))),
        created_at=datetime.fromisoformat(cast(str, row["created_at"])),
        revoked_at=(
            datetime.fromisoformat(cast(str, row["revoked_at"]))
            if row["revoked_at"] is not None
            else None
        ),
    )


def _lease_from_row(row: sqlite3.Row) -> AddressLease:
    return AddressLease(
        network_id=NetworkId(cast(str, row["network_id"])),
        node_id=NodeId(cast(str, row["node_id"])),
        address=cast(str, row["address"]),
        pool=cast(str, row["pool"]),
        revision=cast(int, row["revision"]),
        status=LeaseStatus(cast(str, row["status"])),
    )


def _key_from_row(row: sqlite3.Row) -> NetworkPublicKeyView:
    return NetworkPublicKeyView(
        network_id=NetworkId(cast(str, row["network_id"])),
        node_id=NodeId(cast(str, row["node_id"])),
        public_key=cast(str, row["public_key"]),
        status=KeyLifecycle(cast(str, row["status"])),
        revision=cast(int, row["revision"]),
        created_at=datetime.fromisoformat(cast(str, row["created_at"])),
        activated_at=(
            datetime.fromisoformat(cast(str, row["activated_at"]))
            if row["activated_at"] is not None
            else None
        ),
        retired_at=(
            datetime.fromisoformat(cast(str, row["retired_at"]))
            if row["retired_at"] is not None
            else None
        ),
    )


def _candidate_from_row(row: sqlite3.Row) -> EndpointCandidate:
    return EndpointCandidate(
        host=cast(str, row["host"]),
        port=cast(int, row["port"]),
        source=CandidateSource(cast(str, row["source"])),
        observed_at=datetime.fromisoformat(cast(str, row["observed_at"])),
        expires_at=datetime.fromisoformat(cast(str, row["expires_at"])),
    )


def _relay_from_row(row: sqlite3.Row) -> RelayRoleView:
    return RelayRoleView(
        network_id=NetworkId(cast(str, row["network_id"])),
        node_id=NodeId(cast(str, row["node_id"])),
        role=RelayRole(cast(str, row["role"])),
        capability_verified=bool(row["capability_verified"]),
        revision=cast(int, row["revision"]),
        updated_at=datetime.fromisoformat(cast(str, row["updated_at"])),
    )


def _ack_from_row(row: sqlite3.Row) -> NetworkAcknowledgement:
    from tunnelminion.network.contracts import NetworkError

    return NetworkAcknowledgement(
        network_id=NetworkId(cast(str, row["network_id"])),
        node_id=NodeId(cast(str, row["node_id"])),
        revision=cast(int, row["revision"]),
        stage=AcknowledgementStage(cast(str, row["stage"])),
        plan_hash=cast(str | None, row["plan_hash"]),
        receipt_hash=cast(str | None, row["receipt_hash"]),
        error=(
            NetworkError.model_validate_json(cast(str, row["error_json"]))
            if row["error_json"] is not None
            else None
        ),
        acknowledged_at=datetime.fromisoformat(cast(str, row["acknowledged_at"])),
    )


def _saga_status(
    required: tuple[NodeId, ...],
    acknowledgements: tuple[NetworkAcknowledgement, ...],
) -> SagaStatus:
    by_node = {str(item.node_id): item for item in acknowledgements}
    failure_stages = {
        AcknowledgementStage.OWNERSHIP_CONFLICT,
        AcknowledgementStage.MANUAL_INTERVENTION,
    }
    if any(item.stage in failure_stages for item in acknowledgements):
        if any(
            item.stage in {AcknowledgementStage.APPLIED, AcknowledgementStage.VERIFIED}
            for item in acknowledgements
        ):
            return SagaStatus.ROLLING_BACK
        return SagaStatus.MANUAL_INTERVENTION
    if by_node and all(
        by_node.get(str(node_id)) is not None
        and by_node[str(node_id)].stage is AcknowledgementStage.ROLLED_BACK
        for node_id in required
    ):
        return SagaStatus.ROLLED_BACK
    if all(
        by_node.get(str(node_id)) is not None
        and by_node[str(node_id)].stage is AcknowledgementStage.VERIFIED
        for node_id in required
    ):
        return SagaStatus.ACTIVE
    return SagaStatus.PENDING


def _stage_rank(stage: AcknowledgementStage) -> int:
    ranks = {
        AcknowledgementStage.PENDING: 0,
        AcknowledgementStage.AWAITING_AUTHORIZATION: 1,
        AcknowledgementStage.APPLYING: 2,
        AcknowledgementStage.APPLIED: 3,
        AcknowledgementStage.VERIFIED: 4,
        AcknowledgementStage.OWNERSHIP_CONFLICT: 5,
        AcknowledgementStage.MANUAL_INTERVENTION: 5,
        AcknowledgementStage.ROLLED_BACK: 6,
    }
    return ranks[stage]


def _audit_lease(
    connection: sqlite3.Connection,
    network_id: NetworkId,
    node_id: NodeId,
    revision: int,
    now: datetime,
) -> None:
    insert_audit_for_transaction(
        connection,
        network_id,
        node_id,
        revision,
        CoordinatorAuditAction.ADDRESS_LEASE_CHANGED,
        now,
        item_count=1,
    )


def _audit_key(
    connection: sqlite3.Connection,
    network_id: NetworkId,
    node_id: NodeId,
    revision: int,
    now: datetime,
) -> None:
    insert_audit_for_transaction(
        connection,
        network_id,
        node_id,
        revision,
        CoordinatorAuditAction.NETWORK_KEY_CHANGED,
        now,
        item_count=1,
    )


def _json_dump(value: object) -> str:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def _b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
