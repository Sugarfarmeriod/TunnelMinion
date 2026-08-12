"""受管路径的严格状态投影与新鲜度判定。"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from tunnelminion.domain.identifiers import AuthorizationId, NetworkId, NodeId
from tunnelminion.network.contracts import ProviderKind
from tunnelminion.network.path_controller import (
    DirectPathEvidence,
    NetworkPathType,
    PathSelection,
)

MANAGED_PATH_STATUS_SCHEMA_VERSION = 1
MANAGED_PATH_REFRESH_MIN_INTERVAL = timedelta(seconds=30)
_HASH_PATTERN = r"^sha256:[0-9a-f]{64}$"
_ALLOWED_SOURCES = frozenset(
    {
        "none",
        "fake",
        "platform_read_only",
        "structured-candidate",
    }
)


def source_category(source: str) -> str:
    """把 probe 的内部来源压缩为固定公开类别。"""
    if source in {"fake", "fixture"}:
        return "fake"
    if source == "structured-candidate":
        return source
    if source.startswith("platform"):
        return "platform_read_only"
    raise ValueError("path evidence source 不在固定公开类别中")


class ManagedPathAuthorizationState(StrEnum):
    """公开状态中的本机 L3 授权结论。"""

    UNKNOWN = "unknown"
    AWAITING_AUTHORIZATION = "awaiting_authorization"
    AUTHORIZED = "authorized"


class ManagedPathFreshness(StrEnum):
    """当前 path evidence 是否仍可代表实时事实。"""

    UNVERIFIED = "unverified"
    FRESH = "fresh"
    STALE = "stale"


class ManagedPathStatus(BaseModel):
    """只包含 hash、时间和受控摘要的可恢复路径状态。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal[1] = MANAGED_PATH_STATUS_SCHEMA_VERSION
    network_id: NetworkId
    node_id: NodeId
    revision: int = Field(ge=1)
    plan_hash: str = Field(pattern=_HASH_PATTERN)
    authorization_revision: int = Field(ge=1)
    provider: ProviderKind
    authorization_state: ManagedPathAuthorizationState
    authorization_id: AuthorizationId | None = None
    path_type: NetworkPathType
    selection: PathSelection | None = None
    evidence: DirectPathEvidence | None = None
    source: str = Field(min_length=1, max_length=64)
    freshness: ManagedPathFreshness
    candidate_count: int = Field(ge=0, le=8)
    last_known_good_revision: int | None = Field(default=None, ge=1)
    observed_at: datetime | None = None
    refreshed_at: datetime | None = None
    expires_at: datetime | None = None
    stable_error_code: str | None = Field(default=None, min_length=1, max_length=128)
    journal_sequence: int = Field(ge=0)
    updated_at: datetime

    @model_validator(mode="after")
    def validate_binding(self) -> Self:
        for value in (
            self.observed_at,
            self.refreshed_at,
            self.expires_at,
            self.updated_at,
        ):
            if value is not None and (value.tzinfo is None or value.utcoffset() != timedelta(0)):
                raise ValueError("managed path status 时间必须使用 timezone-aware UTC")
        if self.authorization_state is ManagedPathAuthorizationState.AUTHORIZED:
            if self.authorization_id is None:
                raise ValueError("authorized status 必须绑定 authorization id")
        elif self.authorization_id is not None:
            raise ValueError("未授权 status 不得携带 authorization id")
        if self.authorization_revision != self.revision:
            raise ValueError("status authorization revision 必须精确绑定 revision")
        if self.source not in _ALLOWED_SOURCES:
            raise ValueError("status source 不在固定来源类别中")
        if self.evidence is None:
            if self.source != "none":
                raise ValueError("没有 evidence 时 source 必须为 none")
            if any(
                value is not None
                for value in (self.observed_at, self.refreshed_at, self.expires_at)
            ):
                raise ValueError("没有 evidence 时不得声明 evidence 时间")
        else:
            if (
                self.evidence.network_id != self.network_id
                or self.evidence.node_id != self.node_id
                or self.evidence.plan_hash != self.plan_hash
                or self.evidence.authorization_revision != self.authorization_revision
                or self.evidence.provider is not self.provider
                or self.evidence.revision != self.revision
            ):
                raise ValueError("status evidence 绑定冲突")
            if self.source != source_category(self.evidence.source):
                raise ValueError("status source 与 evidence source 不一致")
            if (
                self.observed_at != self.evidence.observed_at
                or self.refreshed_at != self.evidence.observed_at
                or self.expires_at != self.evidence.expires_at
            ):
                raise ValueError("status evidence 时间摘要不一致")
            if self.candidate_count != self.evidence.candidate_count:
                raise ValueError("status candidate count 与 evidence 不一致")
        if self.selection is not None:
            if self.selection.revision != self.revision:
                raise ValueError("status selection revision 绑定冲突")
            if (
                self.selection.network_id is not None
                and self.selection.network_id != self.network_id
            ):
                raise ValueError("status selection network 绑定冲突")
            if self.selection.node_id is not None and self.selection.node_id != self.node_id:
                raise ValueError("status selection node 绑定冲突")
            if self.selection.plan_hash is not None and self.selection.plan_hash != self.plan_hash:
                raise ValueError("status selection plan 绑定冲突")
            if self.selection.authorization_revision is not None and (
                self.selection.authorization_revision != self.authorization_revision
            ):
                raise ValueError("status selection authorization 绑定冲突")
            if self.selection.provider is not self.provider:
                raise ValueError("status selection provider 绑定冲突")
        if (
            self.evidence is not None
            and self.selection is not None
            and self.selection.path_type is NetworkPathType.DIRECT
        ):
            if not self.evidence.verified:
                raise ValueError("direct selection 不得绑定失败 evidence")
            if (
                self.selection.target_host_hash != self.evidence.target_host_hash
                or self.selection.target_port != self.evidence.target_port
                or self.selection.route_identity_hash != self.evidence.route_identity_hash
                or self.selection.expires_at != self.evidence.expires_at
            ):
                raise ValueError("status direct selection 与 evidence 绑定冲突")
        if self.freshness is ManagedPathFreshness.FRESH and (
            self.evidence is None or not self.evidence.verified
        ):
            raise ValueError("fresh status 必须绑定成功的 path evidence")
        return self

    @property
    def currently_usable(self) -> bool:
        """只有新鲜状态才可被消费者当作当前路径事实。"""

        return (
            self.freshness is ManagedPathFreshness.FRESH
            and self.path_type is not NetworkPathType.OFFLINE
        )

    def at(self, now: datetime) -> Self:
        """按当前时钟投影 stale；不改变持久化 evidence 的 expires_at。"""
        if now.tzinfo is None or now.utcoffset() != timedelta(0):
            raise ValueError("managed path status 时钟必须使用 timezone-aware UTC")
        current = now.astimezone(UTC)
        freshness = ManagedPathFreshness.UNVERIFIED
        stable_error = self.stable_error_code
        if self.evidence is not None and self.evidence.verified:
            if self.evidence.expires_at > current:
                freshness = ManagedPathFreshness.FRESH
            else:
                freshness = ManagedPathFreshness.STALE
                if stable_error is None:
                    stable_error = "path_evidence_stale"
        elif self.evidence is not None:
            assert self.evidence.stable_error_code is not None
            if stable_error is None:
                stable_error = self.evidence.stable_error_code.value
        values = self.model_dump(mode="python")
        values.update({"freshness": freshness, "stable_error_code": stable_error})
        return type(self).model_validate(values)


def redacted_managed_path_status_payload(status: ManagedPathStatus) -> dict[str, object]:
    """导出固定 status 字段，并拒绝完整 endpoint、route 或秘密正文。"""
    payload = status.model_dump(mode="json")
    encoded = json.dumps(payload, sort_keys=True).lower()
    forbidden = (
        '"endpoint"',
        '"allowed_host_routes"',
        '"desired_config"',
        '"peers"',
        '"private_key"',
        '"preshared_key"',
        '"refresh_credential"',
        '"signature"',
    )
    if any(fragment in encoded for fragment in forbidden):
        raise ValueError("managed path status 包含禁止正文")
    return payload
