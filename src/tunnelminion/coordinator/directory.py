"""Coordinator 能力/服务完整快照收敛与有界目录查询。"""

from __future__ import annotations

import base64
import hashlib
import json
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import cast

from tunnelminion.coordinator.contracts import (
    COORDINATOR_PROTOCOL,
    CapabilitySnapshot,
    CoordinatorAuditAction,
    CoordinatorErrorCode,
    DirectoryFreshness,
    DirectoryNodeSummary,
    DirectoryPage,
    DirectoryQuery,
    NodeIdentity,
    NodeStatus,
    RefreshAuthentication,
    ServiceLifecycle,
    ServiceSnapshot,
    SnapshotKind,
    SnapshotReceipt,
)
from tunnelminion.coordinator.registry import (
    CoordinatorRegistryService,
    RegistryError,
    SQLiteCoordinatorStore,
    authenticated_node_for_transaction,
    insert_audit_for_transaction,
    next_revision_for_transaction,
)
from tunnelminion.domain.identifiers import NetworkId, NodeId


@dataclass(frozen=True)
class DirectoryPolicy:
    """目录资源预算与服务器时间 TTL。"""

    max_snapshot_bytes: int = 262_144
    snapshot_ttl_seconds: int = 120

    def __post_init__(self) -> None:
        if self.max_snapshot_bytes < 1024:
            raise ValueError("快照字节预算不能小于 1024")
        if self.snapshot_ttl_seconds < 1:
            raise ValueError("目录 TTL 必须大于零")


class CoordinatorDirectoryService:
    """以 SQLite 短事务原子替换逐节点目录并提供稳定分页。"""

    def __init__(
        self,
        store: SQLiteCoordinatorStore,
        registry: CoordinatorRegistryService,
        *,
        policy: DirectoryPolicy | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if registry.store.path != store.path:
            raise ValueError("目录与注册服务必须共享同一 SQLite 数据库")
        self._store = store
        self._registry = registry
        self._policy = policy or DirectoryPolicy()
        self._clock = clock or (lambda: datetime.now(UTC))

    def replace_capabilities(
        self,
        authentication: RefreshAuthentication,
        snapshot: CapabilitySnapshot,
    ) -> SnapshotReceipt:
        """认证并原子替换节点的完整能力集合。"""
        return self._replace(authentication, snapshot)

    def replace_services(
        self,
        authentication: RefreshAuthentication,
        snapshot: ServiceSnapshot,
    ) -> SnapshotReceipt:
        """认证并原子收敛节点的完整服务集合。"""
        return self._replace(authentication, snapshot)

    def query(
        self,
        authentication: RefreshAuthentication,
        query: DirectoryQuery,
    ) -> DirectoryPage:
        """按认证 network 返回过滤、有界且 revision 一致的节点页。"""
        self._registry.authenticate_refresh(authentication)
        if query.network_id != authentication.network_id:
            raise RegistryError(CoordinatorErrorCode.FORBIDDEN, "目录 network 绑定不匹配")
        now = self._now()
        filter_hash = _query_fingerprint(query)
        after_node = ""
        cursor_revision: int | None = None
        if query.cursor is not None:
            cursor_revision, after_node = _decode_cursor(
                query.cursor,
                authentication.network_id,
                filter_hash,
            )

        with self._store.connect() as connection:
            connection.execute("BEGIN")
            revision = _current_revision(connection, authentication.network_id)
            if cursor_revision is not None and cursor_revision != revision:
                connection.commit()
                return DirectoryPage(
                    server_revision=revision,
                    generated_at=now,
                    nodes=(),
                    full_sync_required=True,
                )
            rows = _query_node_rows(
                connection,
                query,
                after_node=after_node,
                snapshot_cutoff=now - timedelta(seconds=self._policy.snapshot_ttl_seconds),
            )
            summaries = tuple(_node_summary(row, query, now, self._policy) for row in rows)
            selected = summaries[: query.page_size]
            has_more = len(summaries) > query.page_size
            next_cursor = (
                _encode_cursor(
                    authentication.network_id,
                    revision,
                    selected[-1].identity.node_id,
                    filter_hash,
                )
                if has_more and selected
                else None
            )
            connection.commit()
        return DirectoryPage(
            server_revision=revision,
            generated_at=now,
            nodes=selected,
            next_cursor=next_cursor,
        )

    def _replace(
        self,
        authentication: RefreshAuthentication,
        snapshot: CapabilitySnapshot | ServiceSnapshot,
    ) -> SnapshotReceipt:
        self._registry.authenticate_refresh(authentication)
        _validate_snapshot_binding(authentication, snapshot)
        serialized = snapshot.model_dump_json()
        if len(serialized.encode()) > self._policy.max_snapshot_bytes:
            raise RegistryError(
                CoordinatorErrorCode.SNAPSHOT_TOO_LARGE,
                "完整快照超过服务器字节预算",
            )
        now = self._now()
        fingerprint = hashlib.sha256(serialized.encode()).hexdigest()
        with self._store.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            if authenticated_node_for_transaction(connection, authentication) is None:
                connection.rollback()
                raise RegistryError(CoordinatorErrorCode.UNAUTHENTICATED, "节点凭据无效")
            prior = connection.execute(
                "SELECT * FROM snapshot_receipts WHERE idempotency_key=?",
                (snapshot.idempotency_key,),
            ).fetchone()
            if prior is not None:
                if (
                    prior["request_fingerprint"] != fingerprint
                    or prior["network_id"] != str(authentication.network_id)
                    or prior["node_id"] != str(authentication.node_id)
                ):
                    connection.rollback()
                    raise RegistryError(
                        CoordinatorErrorCode.CONFLICT,
                        "快照幂等键已用于其他请求",
                    )
                connection.commit()
                return _receipt(prior, duplicate=True)

            head = connection.execute(
                "SELECT * FROM snapshot_heads WHERE node_id=? AND kind=?",
                (str(authentication.node_id), snapshot.kind.value),
            ).fetchone()
            if head is not None and snapshot.sequence <= cast(int, head["sequence"]):
                connection.rollback()
                raise RegistryError(
                    CoordinatorErrorCode.OUT_OF_ORDER,
                    "完整快照序号不是严格递增",
                )
            revision = next_revision_for_transaction(
                connection,
                authentication.network_id,
            )
            connection.execute(
                "UPDATE nodes SET server_revision=? WHERE network_id=? AND node_id=?",
                (
                    revision,
                    str(authentication.network_id),
                    str(authentication.node_id),
                ),
            )
            if snapshot.kind is SnapshotKind.CAPABILITY:
                assert isinstance(snapshot, CapabilitySnapshot)
                _replace_capability_rows(connection, snapshot, now)
                action = CoordinatorAuditAction.CAPABILITIES_REPLACED
                item_count = len(snapshot.capabilities)
            else:
                assert isinstance(snapshot, ServiceSnapshot)
                _replace_service_rows(connection, snapshot, now)
                action = CoordinatorAuditAction.SERVICES_REPLACED
                item_count = len(snapshot.services)
            connection.execute(
                """INSERT INTO snapshot_heads(
                    node_id, kind, snapshot_id, sequence, server_revision, received_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(node_id, kind) DO UPDATE SET
                    snapshot_id=excluded.snapshot_id,
                    sequence=excluded.sequence,
                    server_revision=excluded.server_revision,
                    received_at=excluded.received_at""",
                (
                    str(authentication.node_id),
                    snapshot.kind.value,
                    str(snapshot.snapshot_id),
                    snapshot.sequence,
                    revision,
                    now.isoformat(),
                ),
            )
            connection.execute(
                """INSERT INTO snapshot_receipts(
                    idempotency_key, request_fingerprint, network_id, node_id,
                    kind, snapshot_id, sequence, server_revision, received_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    snapshot.idempotency_key,
                    fingerprint,
                    str(authentication.network_id),
                    str(authentication.node_id),
                    snapshot.kind.value,
                    str(snapshot.snapshot_id),
                    snapshot.sequence,
                    revision,
                    now.isoformat(),
                ),
            )
            insert_audit_for_transaction(
                connection,
                authentication.network_id,
                authentication.node_id,
                revision,
                action,
                now,
                item_count=item_count,
            )
            connection.commit()
        return SnapshotReceipt(
            snapshot_id=snapshot.snapshot_id,
            sequence=snapshot.sequence,
            server_revision=revision,
            received_at=now,
        )

    def _now(self) -> datetime:
        value = self._clock()
        if value.tzinfo is None:
            raise ValueError("Coordinator 目录时钟必须包含时区")
        return value.astimezone(UTC)


def _replace_capability_rows(
    connection: sqlite3.Connection,
    snapshot: CapabilitySnapshot,
    now: datetime,
) -> None:
    connection.execute(
        "DELETE FROM capability_directory WHERE network_id=? AND node_id=?",
        (str(snapshot.network_id), str(snapshot.node_id)),
    )
    connection.executemany(
        """INSERT INTO capability_directory(
            network_id, node_id, name, version_major, version_minor, platform,
            risk_level, availability, schema_hash, snapshot_id, received_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            (
                str(snapshot.network_id),
                str(snapshot.node_id),
                capability.name,
                capability.version.major,
                capability.version.minor,
                capability.platform.value,
                capability.risk_level.value,
                capability.availability.value,
                capability.schema_hash,
                str(snapshot.snapshot_id),
                now.isoformat(),
            )
            for capability in snapshot.capabilities
        ),
    )


def _replace_service_rows(
    connection: sqlite3.Connection,
    snapshot: ServiceSnapshot,
    now: datetime,
) -> None:
    connection.execute(
        """UPDATE service_directory
        SET lifecycle=?, snapshot_id=?, received_at=?
        WHERE network_id=? AND node_id=? AND lifecycle=?""",
        (
            ServiceLifecycle.STOPPED.value,
            str(snapshot.snapshot_id),
            now.isoformat(),
            str(snapshot.network_id),
            str(snapshot.node_id),
            ServiceLifecycle.ACTIVE.value,
        ),
    )
    connection.executemany(
        """INSERT INTO service_directory(
            network_id, node_id, service_id, protocol, host, port, accessibility,
            source, confidence, observed_at, lifecycle, snapshot_id, received_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(network_id, node_id, service_id) DO UPDATE SET
            protocol=excluded.protocol,
            host=excluded.host,
            port=excluded.port,
            accessibility=excluded.accessibility,
            source=excluded.source,
            confidence=excluded.confidence,
            observed_at=excluded.observed_at,
            lifecycle=excluded.lifecycle,
            snapshot_id=excluded.snapshot_id,
            received_at=excluded.received_at""",
        (
            (
                str(snapshot.network_id),
                str(snapshot.node_id),
                str(service.service_id),
                service.protocol.value,
                service.host,
                service.port,
                service.accessibility.value,
                service.source,
                service.confidence,
                service.observed_at.isoformat(),
                service.lifecycle.value,
                str(snapshot.snapshot_id),
                now.isoformat(),
            )
            for service in snapshot.services
        ),
    )


def _validate_snapshot_binding(
    authentication: RefreshAuthentication,
    snapshot: CapabilitySnapshot | ServiceSnapshot,
) -> None:
    if (
        snapshot.network_id != authentication.network_id
        or snapshot.node_id != authentication.node_id
    ):
        raise RegistryError(CoordinatorErrorCode.FORBIDDEN, "快照身份绑定不匹配")
    if not snapshot.protocol.is_compatible_with(COORDINATOR_PROTOCOL):
        raise RegistryError(
            CoordinatorErrorCode.VERSION_INCOMPATIBLE,
            "快照协议主版本不兼容",
        )


def _receipt(row: sqlite3.Row, *, duplicate: bool) -> SnapshotReceipt:
    from tunnelminion.domain.identifiers import SnapshotId

    return SnapshotReceipt(
        snapshot_id=SnapshotId(cast(str, row["snapshot_id"])),
        sequence=cast(int, row["sequence"]),
        server_revision=cast(int, row["server_revision"]),
        duplicate=duplicate,
        received_at=datetime.fromisoformat(cast(str, row["received_at"])),
    )


def _current_revision(connection: sqlite3.Connection, network_id: NetworkId) -> int:
    row = connection.execute(
        "SELECT value FROM revisions WHERE network_id=?",
        (str(network_id),),
    ).fetchone()
    if row is None:
        raise RegistryError(CoordinatorErrorCode.FORBIDDEN, "network 不可用于目录")
    return cast(int, row["value"])


def _query_node_rows(
    connection: sqlite3.Connection,
    query: DirectoryQuery,
    *,
    after_node: str,
    snapshot_cutoff: datetime,
) -> tuple[sqlite3.Row, ...]:
    clauses = ["n.network_id=?", "n.node_id>?"]
    parameters: list[object] = [str(query.network_id), after_node]
    if query.node_id is not None:
        clauses.append("n.node_id=?")
        parameters.append(str(query.node_id))
    if query.node_status is not None:
        clauses.append("n.status=?")
        parameters.append(query.node_status.value)
    if query.platform is not None:
        clauses.append("json_extract(n.identity_json, '$.platform')=?")
        parameters.append(query.platform.value)
    if query.freshness is DirectoryFreshness.REVOKED:
        clauses.append("n.status=?")
        parameters.append(NodeStatus.REVOKED.value)
    elif query.freshness is DirectoryFreshness.OFFLINE:
        clauses.append("n.status IN (?, ?)")
        parameters.extend([NodeStatus.OFFLINE.value, NodeStatus.INCOMPATIBLE.value])
    elif query.freshness is DirectoryFreshness.STALE:
        clauses.append(
            """(n.status=? OR (
                n.status=? AND (
                    (SELECT MAX(received_at) FROM snapshot_heads h
                     WHERE h.node_id=n.node_id) IS NULL
                    OR (SELECT MAX(received_at) FROM snapshot_heads h
                        WHERE h.node_id=n.node_id)<=?
                )
            ))"""
        )
        parameters.extend(
            [NodeStatus.STALE.value, NodeStatus.ONLINE.value, snapshot_cutoff.isoformat()]
        )
    elif query.freshness is DirectoryFreshness.FRESH:
        clauses.append(
            """n.status=? AND
            (SELECT MAX(received_at) FROM snapshot_heads h
             WHERE h.node_id=n.node_id)>=?"""
        )
        parameters.extend([NodeStatus.ONLINE.value, snapshot_cutoff.isoformat()])
    capability_filters: list[str] = []
    if query.tool_name is not None:
        capability_filters.append("c.name=?")
        parameters.append(query.tool_name)
    if query.tool_version is not None:
        capability_filters.extend(["c.version_major=?", "c.version_minor>=?"])
        parameters.extend([query.tool_version.major, query.tool_version.minor])
    if capability_filters:
        clauses.append(
            "EXISTS (SELECT 1 FROM capability_directory c "
            "WHERE c.network_id=n.network_id AND c.node_id=n.node_id AND "
            + " AND ".join(capability_filters)
            + ")"
        )
    service_filters = ["s.lifecycle=?"]
    service_parameters: list[object] = [ServiceLifecycle.ACTIVE.value]
    if query.service_protocol is not None:
        service_filters.append("s.protocol=?")
        service_parameters.append(query.service_protocol.value)
    if query.service_port is not None:
        service_filters.append("s.port=?")
        service_parameters.append(query.service_port)
    if query.service_accessibility is not None:
        service_filters.append("s.accessibility=?")
        service_parameters.append(query.service_accessibility.value)
    if len(service_filters) > 1:
        if query.freshness is DirectoryFreshness.FRESH:
            service_filters.append("s.received_at>=?")
            service_parameters.append(snapshot_cutoff.isoformat())
        clauses.append(
            "EXISTS (SELECT 1 FROM service_directory s "
            "WHERE s.network_id=n.network_id AND s.node_id=n.node_id AND "
            + " AND ".join(service_filters)
            + ")"
        )
        parameters.extend(service_parameters)
    rows = connection.execute(
        f"""SELECT n.*,
            (SELECT COUNT(*) FROM capability_directory c
             WHERE c.network_id=n.network_id AND c.node_id=n.node_id) AS capability_count,
            (SELECT COUNT(*) FROM service_directory s
             WHERE s.network_id=n.network_id AND s.node_id=n.node_id
             AND s.lifecycle=?) AS service_count,
            (SELECT MAX(received_at) FROM snapshot_heads h
             WHERE h.node_id=n.node_id) AS latest_snapshot_at
        FROM nodes n
        WHERE {" AND ".join(clauses)}
        ORDER BY n.node_id
        LIMIT ?""",
        [ServiceLifecycle.ACTIVE.value, *parameters, query.page_size + 1],
    ).fetchall()
    return tuple(rows)


def _node_summary(
    row: sqlite3.Row,
    query: DirectoryQuery,
    now: datetime,
    policy: DirectoryPolicy,
) -> DirectoryNodeSummary:
    status = NodeStatus(cast(str, row["status"]))
    snapshot_at = (
        datetime.fromisoformat(cast(str, row["latest_snapshot_at"]))
        if row["latest_snapshot_at"] is not None
        else None
    )
    freshness = _freshness(status, snapshot_at, now, policy)
    return DirectoryNodeSummary(
        identity=NodeIdentity.model_validate_json(cast(str, row["identity_json"])),
        status=status,
        freshness=freshness,
        last_received_at=(
            datetime.fromisoformat(cast(str, row["last_received_at"]))
            if row["last_received_at"] is not None
            else None
        ),
        capability_count=cast(int, row["capability_count"]),
        service_count=cast(int, row["service_count"]),
        server_revision=cast(int, row["server_revision"]),
    )


def _freshness(
    status: NodeStatus,
    snapshot_at: datetime | None,
    now: datetime,
    policy: DirectoryPolicy,
) -> DirectoryFreshness:
    if status is NodeStatus.REVOKED:
        return DirectoryFreshness.REVOKED
    if status in {NodeStatus.OFFLINE, NodeStatus.INCOMPATIBLE}:
        return DirectoryFreshness.OFFLINE
    if status is NodeStatus.STALE:
        return DirectoryFreshness.STALE
    if snapshot_at is None or now - snapshot_at >= timedelta(seconds=policy.snapshot_ttl_seconds):
        return DirectoryFreshness.STALE
    return DirectoryFreshness.FRESH


def _query_fingerprint(query: DirectoryQuery) -> str:
    payload = query.model_dump(mode="json", exclude={"cursor", "page_size"})
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _encode_cursor(
    network_id: NetworkId,
    revision: int,
    after_node: NodeId,
    filter_hash: str,
) -> str:
    payload = json.dumps(
        {
            "network_id": str(network_id),
            "revision": revision,
            "after_node": str(after_node),
            "filter_hash": filter_hash,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return base64.urlsafe_b64encode(payload).rstrip(b"=").decode()


def _decode_cursor(
    cursor: str,
    network_id: NetworkId,
    filter_hash: str,
) -> tuple[int, str]:
    try:
        decoded = json.loads(base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4)))
        if not isinstance(decoded, dict):
            raise ValueError("cursor 结构无效")
        payload = cast(dict[str, object], decoded)
        if (
            payload.get("network_id") != str(network_id)
            or payload.get("filter_hash") != filter_hash
            or not isinstance(payload.get("revision"), int)
            or not isinstance(payload.get("after_node"), str)
        ):
            raise ValueError("cursor 绑定无效")
        return cast(int, payload["revision"]), cast(str, payload["after_node"])
    except (ValueError, TypeError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RegistryError(CoordinatorErrorCode.INVALID_CURSOR, "目录游标无效") from exc
