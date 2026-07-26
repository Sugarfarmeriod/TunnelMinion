"""受管网络本地所有权账本；只保存秘密引用，不保存秘密正文。"""

from __future__ import annotations

import json
import re
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import cast

from pydantic import BaseModel, ConfigDict, Field, model_validator

from tunnelminion.domain.identifiers import NetworkId, NodeId
from tunnelminion.network.contracts import ManagedResourceOwnership

_SECRET_REFERENCE = re.compile(r"^[a-z][a-z0-9+.-]{1,31}:[^\s]{1,180}$")
_FORBIDDEN_SECRET_FIELDS = frozenset(
    {
        "private_key",
        "private-key",
        "preshared_key",
        "preshared-key",
        "wireguard_private_key",
    }
)


class ManagedResourceLedgerEntry(BaseModel):
    """本机受管资源的双重所有权证据和秘密后端引用。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    ownership: ManagedResourceOwnership
    secret_reference: str = Field(pattern=_SECRET_REFERENCE.pattern, repr=False)
    created_at: datetime
    updated_at: datetime

    @model_validator(mode="after")
    def validate_timestamps(self) -> ManagedResourceLedgerEntry:
        if self.updated_at < self.created_at:
            raise ValueError("账本更新时间不得早于创建时间")
        lowered = self.secret_reference.lower()
        if any(fragment in lowered for fragment in _FORBIDDEN_SECRET_FIELDS):
            raise ValueError("秘密引用名称不得伪装成秘密正文字段")
        return self


class ManagedResourcePublicExport(BaseModel):
    """诊断和导出可使用的脱敏所有权摘要。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    ownership: ManagedResourceOwnership
    secret_reference_configured: bool
    created_at: datetime
    updated_at: datetime


class SQLiteManagedResourceLedger:
    """以 network/node 为稳定键保存本机受管资源。"""

    def __init__(self, path: Path) -> None:
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS managed_network_resources (
                    network_id TEXT NOT NULL,
                    node_id TEXT NOT NULL,
                    provider TEXT NOT NULL,
                    interface_name TEXT NOT NULL,
                    resource_id TEXT NOT NULL UNIQUE,
                    revision INTEGER NOT NULL,
                    payload TEXT NOT NULL,
                    PRIMARY KEY(network_id, node_id)
                );
                CREATE INDEX IF NOT EXISTS managed_network_resource_interface
                    ON managed_network_resources(provider, interface_name);
                """
            )

    def put(self, entry: ManagedResourceLedgerEntry) -> None:
        """幂等保存同一资源；资源 ID 变化必须先显式删除旧账本。"""
        ownership = entry.ownership
        with self._connect() as connection:
            current = connection.execute(
                """SELECT resource_id FROM managed_network_resources
                WHERE network_id=? AND node_id=?""",
                (str(ownership.network_id), str(ownership.node_id)),
            ).fetchone()
            if current is not None and cast(str, current["resource_id"]) != str(
                ownership.resource_id
            ):
                raise ValueError("同一 network/node 已绑定另一受管资源")
            connection.execute(
                """INSERT INTO managed_network_resources(
                    network_id, node_id, provider, interface_name,
                    resource_id, revision, payload
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(network_id, node_id) DO UPDATE SET
                    provider=excluded.provider,
                    interface_name=excluded.interface_name,
                    resource_id=excluded.resource_id,
                    revision=excluded.revision,
                    payload=excluded.payload""",
                (
                    str(ownership.network_id),
                    str(ownership.node_id),
                    ownership.provider.value,
                    ownership.interface_name,
                    str(ownership.resource_id),
                    ownership.parent_revision,
                    entry.model_dump_json(),
                ),
            )

    def get(self, network_id: NetworkId, node_id: NodeId) -> ManagedResourceLedgerEntry | None:
        """读取精确 network/node 的账本记录。"""
        with self._connect() as connection:
            row = connection.execute(
                """SELECT payload FROM managed_network_resources
                WHERE network_id=? AND node_id=?""",
                (str(network_id), str(node_id)),
            ).fetchone()
        if row is None:
            return None
        return ManagedResourceLedgerEntry.model_validate_json(cast(str, row["payload"]))

    def list_all(self) -> tuple[ManagedResourceLedgerEntry, ...]:
        """按稳定身份返回全部受管资源，不读取秘密后端。"""
        with self._connect() as connection:
            rows = connection.execute(
                """SELECT payload FROM managed_network_resources
                ORDER BY network_id, node_id"""
            ).fetchall()
        return tuple(
            ManagedResourceLedgerEntry.model_validate_json(cast(str, row["payload"]))
            for row in rows
        )

    def delete(
        self,
        network_id: NetworkId,
        node_id: NodeId,
        *,
        expected_system_fingerprint: str,
    ) -> bool:
        """仅在调用方提供的实时系统指纹与账本一致时删除记录。"""
        entry = self.get(network_id, node_id)
        if entry is None:
            return False
        if entry.ownership.system_fingerprint != expected_system_fingerprint:
            raise ValueError("实时系统指纹与本地所有权账本不一致")
        with self._connect() as connection:
            cursor = connection.execute(
                """DELETE FROM managed_network_resources
                WHERE network_id=? AND node_id=?""",
                (str(network_id), str(node_id)),
            )
        return cursor.rowcount == 1

    def export_public(self) -> tuple[ManagedResourcePublicExport, ...]:
        """导出时删除秘密引用名称，仅表达引用是否存在。"""
        return tuple(
            ManagedResourcePublicExport(
                ownership=entry.ownership,
                secret_reference_configured=True,
                created_at=entry.created_at,
                updated_at=entry.updated_at,
            )
            for entry in self.list_all()
        )

    def assert_no_secret_material(self) -> None:
        """检查普通 SQLite payload 没有常见秘密字段或 WireGuard 私钥形态。"""
        with self._connect() as connection:
            rows = connection.execute("SELECT payload FROM managed_network_resources").fetchall()
        for row in rows:
            payload = cast(str, row["payload"])
            lowered = payload.lower()
            if any(f'"{name}"' in lowered for name in _FORBIDDEN_SECRET_FIELDS):
                raise ValueError("本地所有权账本包含禁止的秘密字段")
            parsed = json.loads(payload)
            if not isinstance(parsed, dict) or "secret_reference" not in parsed:
                raise ValueError("本地所有权账本结构无效")

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=5)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA foreign_keys=ON")
        return connection
