"""Coordinator SQLite 节点注册、一次性 enrollment 与 refresh 生命周期。"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import sqlite3
from collections import defaultdict, deque
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from time import monotonic
from typing import cast

from tunnelminion.coordinator.contracts import (
    COORDINATOR_PROTOCOL,
    CoordinatorAuditAction,
    CoordinatorAuditRecord,
    CoordinatorAuditResult,
    CoordinatorErrorCode,
    EnrollmentTokenCreated,
    EnrollmentTokenRequest,
    HeartbeatRequest,
    HeartbeatResponse,
    NodeIdentity,
    NodeRegistrationRequest,
    NodeRegistrationResponse,
    NodeStatus,
    RefreshAuthentication,
    RegisteredNodeView,
    SigningKeyMetadata,
)
from tunnelminion.domain.identifiers import (
    CoordinatorAuditId,
    EnrollmentTokenId,
    NetworkId,
    NodeId,
    RefreshCredentialId,
)

SCHEMA_VERSION = 4
ENROLLMENT_PREFIX = "tmne_"
REFRESH_PREFIX = "tmnr_"


@dataclass(frozen=True)
class HeartbeatPolicy:
    """服务器接收时间驱动的节点新鲜度阈值。"""

    stale_after_seconds: int = 30
    offline_after_seconds: int = 90

    def __post_init__(self) -> None:
        if self.stale_after_seconds < 1:
            raise ValueError("stale 阈值必须大于零")
        if self.offline_after_seconds <= self.stale_after_seconds:
            raise ValueError("offline 阈值必须大于 stale 阈值")


class RegistryError(RuntimeError):
    """不包含凭据或跨 network 存在性的稳定注册错误。"""

    def __init__(self, code: CoordinatorErrorCode, message: str) -> None:
        super().__init__(message)
        self.code = code


class SQLiteCoordinatorStore:
    """Coordinator 控制面专用 SQLite 数据库。"""

    def __init__(self, path: Path) -> None:
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS schema_metadata (
                    version INTEGER NOT NULL
                );
                INSERT INTO schema_metadata(version)
                SELECT 1 WHERE NOT EXISTS (SELECT 1 FROM schema_metadata);
                CREATE TABLE IF NOT EXISTS networks (
                    network_id TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS enrollment_tokens (
                    token_id TEXT PRIMARY KEY,
                    network_id TEXT NOT NULL,
                    salt BLOB NOT NULL,
                    digest BLOB NOT NULL,
                    expires_at TEXT NOT NULL,
                    max_uses INTEGER NOT NULL,
                    used_count INTEGER NOT NULL DEFAULT 0,
                    revoked_at TEXT,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(network_id) REFERENCES networks(network_id)
                );
                CREATE INDEX IF NOT EXISTS enrollment_network
                    ON enrollment_tokens(network_id);
                CREATE TABLE IF NOT EXISTS nodes (
                    node_id TEXT PRIMARY KEY,
                    network_id TEXT NOT NULL,
                    device_identity_hash TEXT NOT NULL,
                    identity_json TEXT NOT NULL,
                    status TEXT NOT NULL,
                    server_revision INTEGER NOT NULL,
                    created_at TEXT NOT NULL,
                    revoked_at TEXT,
                    last_received_at TEXT,
                    last_agent_sent_at TEXT,
                    UNIQUE(network_id, device_identity_hash),
                    FOREIGN KEY(network_id) REFERENCES networks(network_id)
                );
                CREATE TABLE IF NOT EXISTS refresh_credentials (
                    credential_id TEXT PRIMARY KEY,
                    node_id TEXT NOT NULL,
                    salt BLOB NOT NULL,
                    digest BLOB NOT NULL,
                    created_at TEXT NOT NULL,
                    revoked_at TEXT,
                    FOREIGN KEY(node_id) REFERENCES nodes(node_id)
                );
                CREATE INDEX IF NOT EXISTS refresh_node
                    ON refresh_credentials(node_id, revoked_at);
                CREATE TABLE IF NOT EXISTS signing_keys (
                    key_id TEXT PRIMARY KEY,
                    private_key_reference TEXT NOT NULL,
                    public_key TEXT NOT NULL,
                    fingerprint TEXT NOT NULL UNIQUE,
                    activates_at TEXT NOT NULL,
                    retires_at TEXT,
                    destroyed_at TEXT
                );
                CREATE TABLE IF NOT EXISTS revocations (
                    revocation_id TEXT PRIMARY KEY,
                    network_id TEXT NOT NULL,
                    node_id TEXT NOT NULL,
                    server_revision INTEGER NOT NULL,
                    reason TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(node_id) REFERENCES nodes(node_id)
                );
                CREATE TABLE IF NOT EXISTS revisions (
                    network_id TEXT PRIMARY KEY,
                    value INTEGER NOT NULL,
                    FOREIGN KEY(network_id) REFERENCES networks(network_id)
                );
                CREATE TABLE IF NOT EXISTS coordinator_audit (
                    audit_id TEXT PRIMARY KEY,
                    network_id TEXT NOT NULL,
                    node_id TEXT,
                    server_revision INTEGER NOT NULL,
                    action TEXT NOT NULL,
                    result TEXT NOT NULL,
                    error_code TEXT,
                    item_count INTEGER NOT NULL,
                    occurred_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS registration_idempotency (
                    idempotency_key TEXT PRIMARY KEY,
                    request_fingerprint TEXT NOT NULL,
                    node_id TEXT NOT NULL,
                    FOREIGN KEY(node_id) REFERENCES nodes(node_id)
                );
                CREATE TABLE IF NOT EXISTS snapshot_heads (
                    node_id TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    snapshot_id TEXT NOT NULL,
                    sequence INTEGER NOT NULL,
                    server_revision INTEGER NOT NULL,
                    received_at TEXT NOT NULL,
                    PRIMARY KEY(node_id, kind),
                    FOREIGN KEY(node_id) REFERENCES nodes(node_id)
                );
                CREATE TABLE IF NOT EXISTS snapshot_receipts (
                    idempotency_key TEXT PRIMARY KEY,
                    request_fingerprint TEXT NOT NULL,
                    network_id TEXT NOT NULL,
                    node_id TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    snapshot_id TEXT NOT NULL,
                    sequence INTEGER NOT NULL,
                    server_revision INTEGER NOT NULL,
                    received_at TEXT NOT NULL,
                    FOREIGN KEY(node_id) REFERENCES nodes(node_id)
                );
                CREATE TABLE IF NOT EXISTS capability_directory (
                    network_id TEXT NOT NULL,
                    node_id TEXT NOT NULL,
                    name TEXT NOT NULL,
                    version_major INTEGER NOT NULL,
                    version_minor INTEGER NOT NULL,
                    platform TEXT NOT NULL,
                    risk_level TEXT NOT NULL,
                    availability TEXT NOT NULL,
                    schema_hash TEXT NOT NULL,
                    snapshot_id TEXT NOT NULL,
                    received_at TEXT NOT NULL,
                    PRIMARY KEY(network_id, node_id, name),
                    FOREIGN KEY(node_id) REFERENCES nodes(node_id)
                );
                CREATE TABLE IF NOT EXISTS service_directory (
                    network_id TEXT NOT NULL,
                    node_id TEXT NOT NULL,
                    service_id TEXT NOT NULL,
                    protocol TEXT NOT NULL,
                    host TEXT NOT NULL,
                    port INTEGER NOT NULL,
                    accessibility TEXT NOT NULL,
                    source TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    observed_at TEXT NOT NULL,
                    lifecycle TEXT NOT NULL,
                    snapshot_id TEXT NOT NULL,
                    received_at TEXT NOT NULL,
                    PRIMARY KEY(network_id, node_id, service_id),
                    FOREIGN KEY(node_id) REFERENCES nodes(node_id)
                );
                CREATE INDEX IF NOT EXISTS capability_lookup
                    ON capability_directory(network_id, name, version_major, version_minor);
                CREATE INDEX IF NOT EXISTS service_lookup
                    ON service_directory(network_id, protocol, port, accessibility, lifecycle);
                CREATE TABLE IF NOT EXISTS network_address_pools (
                    network_id TEXT NOT NULL,
                    pool TEXT NOT NULL,
                    reserved_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    revoked_at TEXT,
                    PRIMARY KEY(network_id, pool),
                    FOREIGN KEY(network_id) REFERENCES networks(network_id)
                );
                CREATE TABLE IF NOT EXISTS network_address_leases (
                    network_id TEXT NOT NULL,
                    node_id TEXT NOT NULL,
                    address TEXT NOT NULL,
                    pool TEXT NOT NULL,
                    status TEXT NOT NULL,
                    revision INTEGER NOT NULL,
                    created_at TEXT NOT NULL,
                    released_at TEXT,
                    PRIMARY KEY(network_id, node_id),
                    FOREIGN KEY(network_id, pool)
                        REFERENCES network_address_pools(network_id, pool),
                    FOREIGN KEY(node_id) REFERENCES nodes(node_id)
                );
                CREATE TABLE IF NOT EXISTS network_public_keys (
                    network_id TEXT NOT NULL,
                    node_id TEXT NOT NULL,
                    public_key TEXT NOT NULL,
                    status TEXT NOT NULL,
                    revision INTEGER NOT NULL,
                    created_at TEXT NOT NULL,
                    activated_at TEXT,
                    retired_at TEXT,
                    PRIMARY KEY(network_id, node_id, public_key),
                    UNIQUE(network_id, public_key),
                    FOREIGN KEY(node_id) REFERENCES nodes(node_id)
                );
                CREATE TABLE IF NOT EXISTS network_endpoint_candidates (
                    network_id TEXT NOT NULL,
                    node_id TEXT NOT NULL,
                    host TEXT NOT NULL,
                    port INTEGER NOT NULL,
                    source TEXT NOT NULL,
                    observed_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    received_at TEXT NOT NULL,
                    PRIMARY KEY(network_id, node_id, host, port, source),
                    FOREIGN KEY(node_id) REFERENCES nodes(node_id)
                );
                CREATE TABLE IF NOT EXISTS network_relay_roles (
                    network_id TEXT NOT NULL,
                    node_id TEXT NOT NULL,
                    role TEXT NOT NULL,
                    capability_verified INTEGER NOT NULL,
                    revision INTEGER NOT NULL,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY(network_id, node_id),
                    FOREIGN KEY(node_id) REFERENCES nodes(node_id)
                );
                CREATE TABLE IF NOT EXISTS network_sagas (
                    network_id TEXT NOT NULL,
                    revision INTEGER NOT NULL,
                    parent_revision INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    required_nodes_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY(network_id, revision),
                    FOREIGN KEY(network_id) REFERENCES networks(network_id)
                );
                CREATE TABLE IF NOT EXISTS network_desired_configs (
                    network_id TEXT NOT NULL,
                    node_id TEXT NOT NULL,
                    revision INTEGER NOT NULL,
                    parent_revision INTEGER NOT NULL,
                    key_id TEXT NOT NULL,
                    key_fingerprint TEXT NOT NULL,
                    envelope_json TEXT NOT NULL,
                    status TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    PRIMARY KEY(network_id, node_id, revision),
                    FOREIGN KEY(node_id) REFERENCES nodes(node_id)
                );
                CREATE TABLE IF NOT EXISTS network_acknowledgements (
                    network_id TEXT NOT NULL,
                    node_id TEXT NOT NULL,
                    revision INTEGER NOT NULL,
                    stage TEXT NOT NULL,
                    plan_hash TEXT,
                    receipt_hash TEXT,
                    error_code TEXT,
                    error_json TEXT,
                    acknowledged_at TEXT NOT NULL,
                    PRIMARY KEY(network_id, node_id, revision),
                    FOREIGN KEY(network_id, revision)
                        REFERENCES network_sagas(network_id, revision),
                    FOREIGN KEY(node_id) REFERENCES nodes(node_id)
                );
                CREATE INDEX IF NOT EXISTS network_candidate_expiry
                    ON network_endpoint_candidates(network_id, node_id, expires_at);
                CREATE UNIQUE INDEX IF NOT EXISTS network_active_lease_address
                    ON network_address_leases(network_id, address)
                    WHERE status != 'released';
                CREATE INDEX IF NOT EXISTS network_config_lookup
                    ON network_desired_configs(network_id, node_id, revision);
                """
            )
            row = cast(
                sqlite3.Row,
                connection.execute("SELECT version FROM schema_metadata").fetchone(),
            )
            version = cast(int, row["version"])
            if version == 1:
                columns = {
                    cast(str, column["name"])
                    for column in connection.execute("PRAGMA table_info(nodes)").fetchall()
                }
                if "last_received_at" not in columns:
                    connection.execute("ALTER TABLE nodes ADD COLUMN last_received_at TEXT")
                if "last_agent_sent_at" not in columns:
                    connection.execute("ALTER TABLE nodes ADD COLUMN last_agent_sent_at TEXT")
                connection.execute("UPDATE schema_metadata SET version=2")
                version = 2
            if version == 2:
                connection.execute("UPDATE schema_metadata SET version=3")
                version = 3
            if version == 3:
                connection.execute("UPDATE schema_metadata SET version=4")
                version = 4
            if version != SCHEMA_VERSION:
                raise RuntimeError("Coordinator SQLite schema 版本不兼容")

    def connect(self) -> sqlite3.Connection:
        """返回启用 WAL、外键和显式事务的短连接。"""
        connection = sqlite3.connect(self.path, timeout=5, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA foreign_keys=ON")
        return connection

    def schema_version(self) -> int:
        with self.connect() as connection:
            row = connection.execute("SELECT version FROM schema_metadata").fetchone()
        if row is None:
            raise RuntimeError("Coordinator schema metadata 缺失")
        return cast(int, row["version"])

    def table_names(self) -> frozenset[str]:
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        return frozenset(cast(str, row["name"]) for row in rows)

    def put_signing_key(self, metadata: SigningKeyMetadata) -> None:
        """保存签名密钥元数据和秘密后端引用，不接收私钥正文。"""
        with self.connect() as connection:
            connection.execute(
                """INSERT INTO signing_keys(
                    key_id, private_key_reference, public_key, fingerprint,
                    activates_at, retires_at, destroyed_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(key_id) DO UPDATE SET
                    private_key_reference=excluded.private_key_reference,
                    public_key=excluded.public_key,
                    fingerprint=excluded.fingerprint,
                    activates_at=excluded.activates_at,
                    retires_at=excluded.retires_at,
                    destroyed_at=excluded.destroyed_at""",
                (
                    metadata.key_id,
                    metadata.private_key_reference,
                    metadata.public_key,
                    metadata.fingerprint,
                    metadata.activates_at.isoformat(),
                    metadata.retires_at.isoformat() if metadata.retires_at is not None else None,
                    (
                        metadata.destroyed_at.isoformat()
                        if metadata.destroyed_at is not None
                        else None
                    ),
                ),
            )

    def list_signing_keys(self) -> tuple[SigningKeyMetadata, ...]:
        """按激活时间返回签名密钥元数据。"""
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM signing_keys ORDER BY activates_at, key_id"
            ).fetchall()
        return tuple(
            SigningKeyMetadata(
                key_id=cast(str, row["key_id"]),
                private_key_reference=cast(str, row["private_key_reference"]),
                public_key=cast(str, row["public_key"]),
                fingerprint=cast(str, row["fingerprint"]),
                activates_at=datetime.fromisoformat(cast(str, row["activates_at"])),
                retires_at=(
                    datetime.fromisoformat(cast(str, row["retires_at"]))
                    if row["retires_at"] is not None
                    else None
                ),
                destroyed_at=(
                    datetime.fromisoformat(cast(str, row["destroyed_at"]))
                    if row["destroyed_at"] is not None
                    else None
                ),
            )
            for row in rows
        )


class CoordinatorRegistryService:
    """以短事务维护 network、节点、enrollment、refresh、修订和脱敏审计。"""

    def __init__(
        self,
        store: SQLiteCoordinatorStore,
        *,
        clock: Callable[[], datetime] | None = None,
        monotonic_clock: Callable[[], float] = monotonic,
        refresh_attempts_per_minute: int = 30,
    ) -> None:
        if refresh_attempts_per_minute < 1:
            raise ValueError("refresh 每分钟尝试次数必须大于零")
        self.store = store
        self._clock = clock or (lambda: datetime.now(UTC))
        self._monotonic = monotonic_clock
        self._refresh_limit = refresh_attempts_per_minute
        self._refresh_attempts: defaultdict[str, deque[float]] = defaultdict(deque)

    def create_network(self, network_id: NetworkId) -> None:
        """幂等创建单所有者私有 network 与初始修订。"""
        now = self._now()
        with self.store.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "INSERT OR IGNORE INTO networks(network_id, created_at) VALUES (?, ?)",
                (str(network_id), now.isoformat()),
            )
            connection.execute(
                "INSERT OR IGNORE INTO revisions(network_id, value) VALUES (?, 0)",
                (str(network_id),),
            )
            connection.commit()

    def create_enrollment_token(self, request: EnrollmentTokenRequest) -> EnrollmentTokenCreated:
        """创建只返回一次完整值、数据库只保存哈希的 enrollment token。"""
        now = self._now()
        expires_at = now + timedelta(seconds=request.expires_in_seconds)
        token_id = EnrollmentTokenId.new()
        token = f"{ENROLLMENT_PREFIX}{secrets.token_urlsafe(32)}"
        salt, digest = _hash_secret(token)
        with self.store.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            if not _network_exists(connection, request.network_id):
                connection.rollback()
                raise RegistryError(CoordinatorErrorCode.FORBIDDEN, "network 不可用于 enrollment")
            connection.execute(
                """INSERT INTO enrollment_tokens(
                    token_id, network_id, salt, digest, expires_at, max_uses,
                    used_count, revoked_at, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, 0, NULL, ?)""",
                (
                    str(token_id),
                    str(request.network_id),
                    salt,
                    digest,
                    expires_at.isoformat(),
                    request.max_uses,
                    now.isoformat(),
                ),
            )
            connection.commit()
        return EnrollmentTokenCreated(
            token_id=token_id,
            network_id=request.network_id,
            token=token,
            expires_at=expires_at,
            max_uses=request.max_uses,
        )

    def revoke_enrollment_token(self, token_id: EnrollmentTokenId) -> None:
        """撤销 enrollment token；不存在时不泄露更多状态。"""
        with self.store.connect() as connection:
            result = connection.execute(
                """UPDATE enrollment_tokens SET revoked_at=?
                WHERE token_id=? AND revoked_at IS NULL""",
                (self._now().isoformat(), str(token_id)),
            )
        if result.rowcount != 1:
            raise RegistryError(CoordinatorErrorCode.UNAUTHENTICATED, "enrollment token 无效")

    def register(self, request: NodeRegistrationRequest) -> NodeRegistrationResponse:
        """原子消费 enrollment token 并创建或幂等恢复稳定节点。"""
        if not request.identity.protocol.is_compatible_with(COORDINATOR_PROTOCOL):
            raise RegistryError(CoordinatorErrorCode.VERSION_INCOMPATIBLE, "协议主版本不兼容")
        now = self._now()
        fingerprint = _registration_fingerprint(request)
        with self.store.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            prior = connection.execute(
                """SELECT request_fingerprint, node_id FROM registration_idempotency
                WHERE idempotency_key=?""",
                (request.idempotency_key,),
            ).fetchone()
            if prior is not None:
                response = self._resume_registration(
                    connection,
                    request,
                    prior,
                    fingerprint,
                    now,
                )
                connection.commit()
                return response

            token_row = _find_enrollment(connection, request)
            if token_row is None or not _enrollment_available(token_row, now):
                connection.rollback()
                raise RegistryError(CoordinatorErrorCode.UNAUTHENTICATED, "enrollment token 无效")
            occupied = connection.execute(
                """SELECT node_id FROM nodes
                WHERE node_id=? OR (network_id=? AND device_identity_hash=?)""",
                (
                    str(request.identity.node_id),
                    str(request.identity.network_id),
                    request.device_identity_hash,
                ),
            ).fetchone()
            if occupied is not None:
                connection.rollback()
                raise RegistryError(CoordinatorErrorCode.CONFLICT, "节点身份已被占用或撤销")

            connection.execute(
                "UPDATE enrollment_tokens SET used_count=used_count+1 WHERE token_id=?",
                (cast(str, token_row["token_id"]),),
            )
            revision = _next_revision(connection, request.identity.network_id)
            connection.execute(
                """INSERT INTO nodes(
                    node_id, network_id, device_identity_hash, identity_json,
                    status, server_revision, created_at, revoked_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, NULL)""",
                (
                    str(request.identity.node_id),
                    str(request.identity.network_id),
                    request.device_identity_hash,
                    request.identity.model_dump_json(),
                    NodeStatus.OFFLINE.value,
                    revision,
                    now.isoformat(),
                ),
            )
            credential_id, refresh = _replace_refresh(connection, request.identity.node_id, now)
            connection.execute(
                """INSERT INTO registration_idempotency(
                    idempotency_key, request_fingerprint, node_id
                ) VALUES (?, ?, ?)""",
                (request.idempotency_key, fingerprint, str(request.identity.node_id)),
            )
            _insert_audit(
                connection,
                request.identity.network_id,
                request.identity.node_id,
                revision,
                CoordinatorAuditAction.NODE_REGISTERED,
                now,
            )
            connection.commit()
        return NodeRegistrationResponse(
            identity=request.identity,
            credential_id=credential_id,
            refresh_credential=refresh,
            server_revision=revision,
            issued_at=now,
        )

    def authenticate_refresh(self, authentication: RefreshAuthentication) -> RegisteredNodeView:
        """验证逐节点 refresh 凭据并返回不含秘密的节点视图。"""
        self._consume_refresh_attempt(authentication.node_id)
        with self.store.connect() as connection:
            row = _authenticated_node(connection, authentication)
        if row is None:
            raise RegistryError(CoordinatorErrorCode.UNAUTHENTICATED, "节点凭据无效")
        return _node_view(row)

    def rotate_refresh(self, authentication: RefreshAuthentication) -> NodeRegistrationResponse:
        """认证后原子轮换 refresh，新值返回一次且旧值立即失效。"""
        self._consume_refresh_attempt(authentication.node_id)
        now = self._now()
        with self.store.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = _authenticated_node(connection, authentication)
            if row is None:
                connection.rollback()
                raise RegistryError(CoordinatorErrorCode.UNAUTHENTICATED, "节点凭据无效")
            identity = NodeIdentity.model_validate_json(cast(str, row["identity_json"]))
            credential_id, refresh = _replace_refresh(connection, identity.node_id, now)
            revision = cast(int, row["server_revision"])
            _insert_audit(
                connection,
                identity.network_id,
                identity.node_id,
                revision,
                CoordinatorAuditAction.CREDENTIAL_ROTATED,
                now,
            )
            connection.commit()
        return NodeRegistrationResponse(
            identity=identity,
            credential_id=credential_id,
            refresh_credential=refresh,
            server_revision=revision,
            issued_at=now,
        )

    def admin_rotate_refresh(
        self,
        network_id: NetworkId,
        node_id: NodeId,
    ) -> NodeRegistrationResponse:
        """管理员无需旧凭据即可轮换非撤销节点的 refresh。"""
        now = self._now()
        with self.store.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM nodes WHERE network_id=? AND node_id=? AND status<>?",
                (str(network_id), str(node_id), NodeStatus.REVOKED.value),
            ).fetchone()
            if row is None:
                connection.rollback()
                raise RegistryError(CoordinatorErrorCode.FORBIDDEN, "节点不可轮换凭据")
            identity = NodeIdentity.model_validate_json(cast(str, row["identity_json"]))
            credential_id, refresh = _replace_refresh(connection, node_id, now)
            revision = cast(int, row["server_revision"])
            _insert_audit(
                connection,
                network_id,
                node_id,
                revision,
                CoordinatorAuditAction.CREDENTIAL_ROTATED,
                now,
            )
            connection.commit()
        return NodeRegistrationResponse(
            identity=identity,
            credential_id=credential_id,
            refresh_credential=refresh,
            server_revision=revision,
            issued_at=now,
        )

    def heartbeat(
        self,
        authentication: RefreshAuthentication,
        heartbeat: HeartbeatRequest,
    ) -> HeartbeatResponse:
        """认证心跳，并只用服务器接收时间更新在线状态。"""
        self._consume_refresh_attempt(authentication.node_id)
        now = self._now()
        with self.store.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = _authenticated_node(connection, authentication)
            if row is None:
                connection.rollback()
                raise RegistryError(CoordinatorErrorCode.UNAUTHENTICATED, "节点凭据无效")
            if (
                heartbeat.network_id != authentication.network_id
                or heartbeat.node_id != authentication.node_id
            ):
                connection.rollback()
                raise RegistryError(CoordinatorErrorCode.FORBIDDEN, "心跳身份绑定不匹配")
            current_status = NodeStatus(cast(str, row["status"]))
            if not heartbeat.protocol.is_compatible_with(COORDINATOR_PROTOCOL):
                self._change_status(
                    connection,
                    authentication.network_id,
                    authentication.node_id,
                    current_status,
                    NodeStatus.INCOMPATIBLE,
                    now,
                )
                connection.commit()
                raise RegistryError(
                    CoordinatorErrorCode.VERSION_INCOMPATIBLE,
                    "心跳协议主版本不兼容",
                )
            revision = self._change_status(
                connection,
                authentication.network_id,
                authentication.node_id,
                current_status,
                NodeStatus.ONLINE,
                now,
            )
            connection.execute(
                """UPDATE nodes
                SET last_received_at=?, last_agent_sent_at=?
                WHERE network_id=? AND node_id=?""",
                (
                    now.isoformat(),
                    heartbeat.sent_at.astimezone(UTC).isoformat(),
                    str(authentication.network_id),
                    str(authentication.node_id),
                ),
            )
            _insert_audit(
                connection,
                authentication.network_id,
                authentication.node_id,
                revision,
                CoordinatorAuditAction.HEARTBEAT_ACCEPTED,
                now,
            )
            connection.commit()
        return HeartbeatResponse(
            received_at=now,
            node_status=NodeStatus.ONLINE,
            server_revision=revision,
        )

    def refresh_node_states(
        self,
        network_id: NetworkId,
        *,
        policy: HeartbeatPolicy | None = None,
    ) -> tuple[RegisteredNodeView, ...]:
        """按服务器最后接收时间推进 online/stale/offline 状态。"""
        actual_policy = policy or HeartbeatPolicy()
        now = self._now()
        with self.store.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            rows = connection.execute(
                "SELECT * FROM nodes WHERE network_id=? ORDER BY created_at, node_id",
                (str(network_id),),
            ).fetchall()
            for row in rows:
                current = NodeStatus(cast(str, row["status"]))
                if current in {NodeStatus.REVOKED, NodeStatus.INCOMPATIBLE}:
                    continue
                received_raw = cast(str | None, row["last_received_at"])
                if received_raw is None:
                    target = NodeStatus.OFFLINE
                else:
                    age = (now - datetime.fromisoformat(received_raw)).total_seconds()
                    if age >= actual_policy.offline_after_seconds:
                        target = NodeStatus.OFFLINE
                    elif age >= actual_policy.stale_after_seconds:
                        target = NodeStatus.STALE
                    else:
                        target = NodeStatus.ONLINE
                self._change_status(
                    connection,
                    network_id,
                    NodeId(cast(str, row["node_id"])),
                    current,
                    target,
                    now,
                )
            connection.commit()
        return self.list_nodes(network_id)

    def revoke_node(self, network_id: NetworkId, node_id: NodeId, *, reason: str) -> None:
        """撤销节点和全部 refresh，并生成 network 修订与脱敏审计。"""
        now = self._now()
        with self.store.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT status FROM nodes WHERE network_id=? AND node_id=?",
                (str(network_id), str(node_id)),
            ).fetchone()
            if row is None or row["status"] == NodeStatus.REVOKED.value:
                connection.rollback()
                raise RegistryError(CoordinatorErrorCode.FORBIDDEN, "节点不可撤销")
            revision = _next_revision(connection, network_id)
            connection.execute(
                """UPDATE nodes SET status=?, server_revision=?, revoked_at=?
                WHERE network_id=? AND node_id=?""",
                (
                    NodeStatus.REVOKED.value,
                    revision,
                    now.isoformat(),
                    str(network_id),
                    str(node_id),
                ),
            )
            connection.execute(
                """UPDATE refresh_credentials SET revoked_at=?
                WHERE node_id=? AND revoked_at IS NULL""",
                (now.isoformat(), str(node_id)),
            )
            connection.execute(
                """INSERT INTO revocations(
                    revocation_id, network_id, node_id, server_revision, reason, created_at
                ) VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    f"revoke_{secrets.token_hex(16)}",
                    str(network_id),
                    str(node_id),
                    revision,
                    reason[:200],
                    now.isoformat(),
                ),
            )
            _insert_audit(
                connection,
                network_id,
                node_id,
                revision,
                CoordinatorAuditAction.NODE_REVOKED,
                now,
            )
            connection.commit()

    def restore_node(
        self,
        network_id: NetworkId,
        node_id: NodeId,
    ) -> NodeRegistrationResponse:
        """显式恢复已撤销节点，并签发全新的 refresh 凭据。"""
        now = self._now()
        with self.store.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM nodes WHERE network_id=? AND node_id=? AND status=?",
                (str(network_id), str(node_id), NodeStatus.REVOKED.value),
            ).fetchone()
            if row is None:
                connection.rollback()
                raise RegistryError(CoordinatorErrorCode.FORBIDDEN, "节点不可恢复")
            revision = _next_revision(connection, network_id)
            connection.execute(
                """UPDATE nodes
                SET status=?, server_revision=?, revoked_at=NULL,
                    last_received_at=NULL, last_agent_sent_at=NULL
                WHERE network_id=? AND node_id=?""",
                (
                    NodeStatus.OFFLINE.value,
                    revision,
                    str(network_id),
                    str(node_id),
                ),
            )
            credential_id, refresh = _replace_refresh(connection, node_id, now)
            identity = NodeIdentity.model_validate_json(cast(str, row["identity_json"]))
            _insert_audit(
                connection,
                network_id,
                node_id,
                revision,
                CoordinatorAuditAction.NODE_RESTORED,
                now,
            )
            connection.commit()
        return NodeRegistrationResponse(
            identity=identity,
            credential_id=credential_id,
            refresh_credential=refresh,
            server_revision=revision,
            issued_at=now,
        )

    def list_nodes(self, network_id: NetworkId) -> tuple[RegisteredNodeView, ...]:
        """按 network 隔离返回不含凭据的节点。"""
        with self.store.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM nodes WHERE network_id=? ORDER BY created_at, node_id",
                (str(network_id),),
            ).fetchall()
        return tuple(_node_view(row) for row in rows)

    def audit_records(self, network_id: NetworkId) -> tuple[CoordinatorAuditRecord, ...]:
        """返回允许字段审计；数据库从未保存完整凭据。"""
        with self.store.connect() as connection:
            rows = connection.execute(
                """SELECT * FROM coordinator_audit
                WHERE network_id=? ORDER BY rowid""",
                (str(network_id),),
            ).fetchall()
        return tuple(
            CoordinatorAuditRecord(
                audit_id=CoordinatorAuditId(cast(str, row["audit_id"])),
                network_id=NetworkId(cast(str, row["network_id"])),
                node_id=(NodeId(cast(str, row["node_id"])) if row["node_id"] is not None else None),
                server_revision=cast(int, row["server_revision"]),
                action=CoordinatorAuditAction(cast(str, row["action"])),
                result=CoordinatorAuditResult(cast(str, row["result"])),
                error_code=(
                    CoordinatorErrorCode(cast(str, row["error_code"]))
                    if row["error_code"] is not None
                    else None
                ),
                item_count=cast(int, row["item_count"]),
                occurred_at=datetime.fromisoformat(cast(str, row["occurred_at"])),
            )
            for row in rows
        )

    def _resume_registration(
        self,
        connection: sqlite3.Connection,
        request: NodeRegistrationRequest,
        prior: sqlite3.Row,
        fingerprint: str,
        now: datetime,
    ) -> NodeRegistrationResponse:
        if prior["request_fingerprint"] != fingerprint:
            connection.rollback()
            raise RegistryError(CoordinatorErrorCode.CONFLICT, "幂等键已用于其他注册请求")
        row = connection.execute(
            "SELECT * FROM nodes WHERE node_id=?",
            (cast(str, prior["node_id"]),),
        ).fetchone()
        if row is None or row["status"] == NodeStatus.REVOKED.value:
            connection.rollback()
            raise RegistryError(CoordinatorErrorCode.FORBIDDEN, "节点不可恢复")
        identity = NodeIdentity.model_validate_json(cast(str, row["identity_json"]))
        credential_id, refresh = _replace_refresh(connection, identity.node_id, now)
        _insert_audit(
            connection,
            identity.network_id,
            identity.node_id,
            cast(int, row["server_revision"]),
            CoordinatorAuditAction.CREDENTIAL_ROTATED,
            now,
        )
        return NodeRegistrationResponse(
            identity=identity,
            credential_id=credential_id,
            refresh_credential=refresh,
            server_revision=cast(int, row["server_revision"]),
            issued_at=now,
        )

    def _consume_refresh_attempt(self, node_id: NodeId) -> None:
        now = self._monotonic()
        attempts = self._refresh_attempts[str(node_id)]
        while attempts and now - attempts[0] >= 60:
            attempts.popleft()
        if len(attempts) >= self._refresh_limit:
            raise RegistryError(CoordinatorErrorCode.RATE_LIMITED, "refresh 请求过于频繁")
        attempts.append(now)

    @staticmethod
    def _change_status(
        connection: sqlite3.Connection,
        network_id: NetworkId,
        node_id: NodeId,
        current: NodeStatus,
        target: NodeStatus,
        now: datetime,
    ) -> int:
        if current is target:
            row = connection.execute(
                "SELECT server_revision FROM nodes WHERE network_id=? AND node_id=?",
                (str(network_id), str(node_id)),
            ).fetchone()
            if row is None:
                raise RuntimeError("节点状态记录缺失")
            return cast(int, row["server_revision"])
        revision = _next_revision(connection, network_id)
        connection.execute(
            """UPDATE nodes SET status=?, server_revision=?
            WHERE network_id=? AND node_id=?""",
            (target.value, revision, str(network_id), str(node_id)),
        )
        _insert_audit(
            connection,
            network_id,
            node_id,
            revision,
            CoordinatorAuditAction.NODE_STATUS_CHANGED,
            now,
        )
        return revision

    def _now(self) -> datetime:
        value = self._clock()
        if value.tzinfo is None:
            raise ValueError("Coordinator 时钟必须包含时区")
        return value.astimezone(UTC)


def _hash_secret(value: str, salt: bytes | None = None) -> tuple[bytes, bytes]:
    actual_salt = salt or secrets.token_bytes(32)
    return actual_salt, hashlib.sha256(actual_salt + value.encode()).digest()


def _matches_secret(value: str, salt: bytes, expected: bytes) -> bool:
    return hmac.compare_digest(_hash_secret(value, salt)[1], expected)


def _network_exists(connection: sqlite3.Connection, network_id: NetworkId) -> bool:
    return (
        connection.execute(
            "SELECT 1 FROM networks WHERE network_id=?",
            (str(network_id),),
        ).fetchone()
        is not None
    )


def _registration_fingerprint(request: NodeRegistrationRequest) -> str:
    payload = {
        "identity": request.identity.model_dump(mode="json"),
        "device_identity_hash": request.device_identity_hash,
        "enrollment_token_hash": hashlib.sha256(request.enrollment_token.encode()).hexdigest(),
    }
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _find_enrollment(
    connection: sqlite3.Connection,
    request: NodeRegistrationRequest,
) -> sqlite3.Row | None:
    rows = connection.execute(
        "SELECT * FROM enrollment_tokens WHERE network_id=?",
        (str(request.identity.network_id),),
    ).fetchall()
    for row in rows:
        if _matches_secret(
            request.enrollment_token,
            cast(bytes, row["salt"]),
            cast(bytes, row["digest"]),
        ):
            return row
    return None


def _enrollment_available(row: sqlite3.Row, now: datetime) -> bool:
    return (
        row["revoked_at"] is None
        and cast(int, row["used_count"]) < cast(int, row["max_uses"])
        and datetime.fromisoformat(cast(str, row["expires_at"])) > now
    )


def _replace_refresh(
    connection: sqlite3.Connection,
    node_id: NodeId,
    now: datetime,
) -> tuple[RefreshCredentialId, str]:
    connection.execute(
        "UPDATE refresh_credentials SET revoked_at=? WHERE node_id=? AND revoked_at IS NULL",
        (now.isoformat(), str(node_id)),
    )
    credential_id = RefreshCredentialId.new()
    value = f"{REFRESH_PREFIX}{secrets.token_urlsafe(32)}"
    salt, digest = _hash_secret(value)
    connection.execute(
        """INSERT INTO refresh_credentials(
            credential_id, node_id, salt, digest, created_at, revoked_at
        ) VALUES (?, ?, ?, ?, ?, NULL)""",
        (
            str(credential_id),
            str(node_id),
            salt,
            digest,
            now.isoformat(),
        ),
    )
    return credential_id, value


def _authenticated_node(
    connection: sqlite3.Connection,
    authentication: RefreshAuthentication,
) -> sqlite3.Row | None:
    if not authentication.protocol.is_compatible_with(COORDINATOR_PROTOCOL):
        return None
    rows = connection.execute(
        """SELECT n.*, c.salt, c.digest FROM nodes n
        JOIN refresh_credentials c ON c.node_id=n.node_id
        WHERE n.network_id=? AND n.node_id=? AND n.status<>? AND c.revoked_at IS NULL""",
        (
            str(authentication.network_id),
            str(authentication.node_id),
            NodeStatus.REVOKED.value,
        ),
    ).fetchall()
    for row in rows:
        if _matches_secret(
            authentication.refresh_credential,
            cast(bytes, row["salt"]),
            cast(bytes, row["digest"]),
        ):
            return row
    return None


def _next_revision(connection: sqlite3.Connection, network_id: NetworkId) -> int:
    connection.execute(
        "UPDATE revisions SET value=value+1 WHERE network_id=?",
        (str(network_id),),
    )
    row = connection.execute(
        "SELECT value FROM revisions WHERE network_id=?",
        (str(network_id),),
    ).fetchone()
    if row is None:
        raise RuntimeError("network 修订记录缺失")
    return cast(int, row["value"])


def _insert_audit(
    connection: sqlite3.Connection,
    network_id: NetworkId,
    node_id: NodeId | None,
    revision: int,
    action: CoordinatorAuditAction,
    now: datetime,
    *,
    item_count: int = 0,
) -> None:
    connection.execute(
        """INSERT INTO coordinator_audit(
            audit_id, network_id, node_id, server_revision, action,
            result, error_code, item_count, occurred_at
        ) VALUES (?, ?, ?, ?, ?, ?, NULL, ?, ?)""",
        (
            str(CoordinatorAuditId.new()),
            str(network_id),
            str(node_id) if node_id is not None else None,
            revision,
            action.value,
            CoordinatorAuditResult.SUCCEEDED.value,
            item_count,
            now.isoformat(),
        ),
    )


def _node_view(row: sqlite3.Row) -> RegisteredNodeView:
    return RegisteredNodeView(
        identity=NodeIdentity.model_validate_json(cast(str, row["identity_json"])),
        device_identity_hash=cast(str, row["device_identity_hash"]),
        status=NodeStatus(cast(str, row["status"])),
        server_revision=cast(int, row["server_revision"]),
        created_at=datetime.fromisoformat(cast(str, row["created_at"])),
        revoked_at=(
            datetime.fromisoformat(cast(str, row["revoked_at"]))
            if row["revoked_at"] is not None
            else None
        ),
        last_received_at=(
            datetime.fromisoformat(cast(str, row["last_received_at"]))
            if row["last_received_at"] is not None
            else None
        ),
        last_agent_sent_at=(
            datetime.fromisoformat(cast(str, row["last_agent_sent_at"]))
            if row["last_agent_sent_at"] is not None
            else None
        ),
    )


def authenticated_node_for_transaction(
    connection: sqlite3.Connection,
    authentication: RefreshAuthentication,
) -> sqlite3.Row | None:
    """供同一 SQLite 事务中的目录写入再次确认 refresh 身份。"""
    return _authenticated_node(connection, authentication)


def next_revision_for_transaction(
    connection: sqlite3.Connection,
    network_id: NetworkId,
) -> int:
    """在调用方已开启的事务中生成单调 network revision。"""
    return _next_revision(connection, network_id)


def insert_audit_for_transaction(
    connection: sqlite3.Connection,
    network_id: NetworkId,
    node_id: NodeId | None,
    revision: int,
    action: CoordinatorAuditAction,
    now: datetime,
    *,
    item_count: int = 0,
) -> None:
    """在调用方事务内写入不含秘密的 Coordinator 审计。"""
    _insert_audit(
        connection,
        network_id,
        node_id,
        revision,
        action,
        now,
        item_count=item_count,
    )
