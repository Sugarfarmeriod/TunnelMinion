"""受管路径阶段一的脱敏状态、只读授权端口与零写入生命周期。"""

from __future__ import annotations

import asyncio
import json
import os
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Literal, Protocol, Self, cast

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from tunnelminion.domain.identifiers import AuthorizationId, NetworkId, NodeId
from tunnelminion.network.contracts import NetworkPlan, ProviderKind, SignedDesiredConfig
from tunnelminion.network.governance import NetworkAuthorizationGrant
from tunnelminion.network.path_controller import NetworkPathType
from tunnelminion.network.provider import NetworkProvider

MANAGED_PATH_CHECKPOINT_SCHEMA_VERSION = 1

_HASH_PATTERN = r"^sha256:[0-9a-f]{64}$"
_FORBIDDEN_KEYS = frozenset(
    {
        "access_token",
        "allowed_host_routes",
        "authorization_header",
        "desired_config",
        "endpoint",
        "peers",
        "preshared_key",
        "private_key",
        "refresh_credential",
        "routes",
        "signature",
        "token",
    }
)
_FORBIDDEN_VALUE_FRAGMENTS = ("bearer ", "-----begin private key-----")
_LEGACY_SYNC_KEYS = frozenset({"applied_revision", "last_known_good", "pending_config", "phase"})


class PathAuthorizationState(StrEnum):
    """脱敏的本机 L3 授权状态。"""

    AWAITING_AUTHORIZATION = "awaiting_authorization"
    AUTHORIZED = "authorized"


class PathEvidenceFreshness(StrEnum):
    """路径证据是否可代表当前事实。"""

    UNKNOWN = "unknown"
    FRESH = "fresh"
    STALE = "stale"


class PathEvidenceSource(StrEnum):
    """证据来源类别；不包含 endpoint 或命令正文。"""

    NONE = "none"
    FAKE = "fake"
    PLATFORM_READ_ONLY = "platform_read_only"


class ManagedPathPhaseOneErrorCode(StrEnum):
    """阶段一可公开的稳定错误码。"""

    LOCAL_L3_APPROVAL_REQUIRED = "local_l3_approval_required"
    LOCAL_L3_APPROVAL_EXPIRED = "local_l3_approval_expired"
    LOCAL_L3_APPROVAL_NOT_YET_VALID = "local_l3_approval_not_yet_valid"
    LOCAL_L3_APPROVAL_REVOKED = "local_l3_approval_revoked"
    LOCAL_L3_SCOPE_MISMATCH = "local_l3_scope_mismatch"
    PROVIDER_EXECUTION_DISABLED = "provider_execution_disabled_phase_one"


class ManagedPathSelectionState(BaseModel):
    """不含地址与路由的路径选择摘要。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    path_type: NetworkPathType
    selected_at: datetime
    last_known_good_revision: int | None = Field(default=None, ge=1)


class ManagedPathEvidenceState(BaseModel):
    """四维路径事实的脱敏时间与结果。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    source: PathEvidenceSource = PathEvidenceSource.NONE
    freshness: PathEvidenceFreshness = PathEvidenceFreshness.UNKNOWN
    endpoint_probe_at: datetime | None = None
    endpoint_probe_succeeded: bool | None = None
    last_handshake_at: datetime | None = None
    handshake_fresh: bool | None = None
    host_route_present: bool | None = None
    target_probe_at: datetime | None = None
    target_probe_succeeded: bool | None = None
    refreshed_at: datetime | None = None
    expires_at: datetime | None = None
    stable_error_code: str | None = Field(default=None, min_length=1, max_length=128)

    @model_validator(mode="after")
    def validate_freshness(self) -> Self:
        timestamps = (
            self.endpoint_probe_at,
            self.last_handshake_at,
            self.target_probe_at,
            self.refreshed_at,
            self.expires_at,
        )
        if any(value is not None and value.tzinfo is None for value in timestamps):
            raise ValueError("路径证据时间必须包含时区")
        if self.freshness is PathEvidenceFreshness.UNKNOWN:
            if self.source is not PathEvidenceSource.NONE:
                raise ValueError("未知证据不得声明来源")
            if self.refreshed_at is not None or self.expires_at is not None:
                raise ValueError("未知证据不得声明刷新窗口")
            return self
        if self.source is PathEvidenceSource.NONE:
            raise ValueError("已观测证据必须声明来源")
        if self.refreshed_at is None or self.expires_at is None:
            raise ValueError("已观测证据必须声明刷新窗口")
        if self.expires_at < self.refreshed_at:
            raise ValueError("证据过期时间不得早于刷新时间")
        return self


class ManagedPathCheckpoint(BaseModel):
    """单 network/node 的版本化、脱敏阶段一 checkpoint。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal[1] = MANAGED_PATH_CHECKPOINT_SCHEMA_VERSION
    network_id: NetworkId
    node_id: NodeId
    revision: int = Field(ge=1)
    provider: ProviderKind
    pending_plan_hash: str = Field(pattern=_HASH_PATTERN)
    observed_fingerprint: str = Field(pattern=_HASH_PATTERN)
    authorization_state: PathAuthorizationState
    authorization_id: AuthorizationId | None = None
    selection: ManagedPathSelectionState | None = None
    evidence: ManagedPathEvidenceState = Field(default_factory=ManagedPathEvidenceState)
    stable_error_code: ManagedPathPhaseOneErrorCode
    updated_at: datetime

    @model_validator(mode="after")
    def validate_authorization(self) -> Self:
        if self.updated_at.tzinfo is None:
            raise ValueError("checkpoint 更新时间必须包含时区")
        authorized = self.authorization_state is PathAuthorizationState.AUTHORIZED
        if authorized != (self.authorization_id is not None):
            raise ValueError("授权状态与授权 ID 不一致")
        if (
            self.selection is not None
            and self.selection.path_type is NetworkPathType.DIRECT
            and self.evidence.freshness is not PathEvidenceFreshness.FRESH
        ):
            raise ValueError("direct selection 必须具有新鲜证据")
        return self


class ManagedPathCheckpointError(RuntimeError):
    """checkpoint 缺失以外的稳定 fail-closed 错误。"""


class FileManagedPathCheckpointRepository:
    """使用进程内 writer token 和原子替换保存单写者 checkpoint。"""

    def __init__(self, path: Path, *, writer_token: object) -> None:
        self.path = path
        self._writer_token = writer_token

    def load(self) -> ManagedPathCheckpoint | None:
        """兼容识别旧同步状态，但绝不从中推断 path selection。"""
        if not self.path.exists():
            return None
        try:
            raw = self.path.read_text(encoding="utf-8")
            payload = json.loads(raw)
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise ManagedPathCheckpointError("managed path checkpoint 无法读取") from exc
        if not isinstance(payload, dict):
            raise ManagedPathCheckpointError("managed path checkpoint 结构无效")
        values = cast(dict[str, object], payload)
        self._reject_secret_material(values)
        if "schema_version" not in values:
            if _LEGACY_SYNC_KEYS.intersection(values):
                return None
            raise ManagedPathCheckpointError("managed path checkpoint 缺少 schema version")
        if values["schema_version"] != MANAGED_PATH_CHECKPOINT_SCHEMA_VERSION:
            raise ManagedPathCheckpointError("managed path checkpoint schema 不受支持")
        try:
            return ManagedPathCheckpoint.model_validate(values)
        except ValidationError as exc:
            raise ManagedPathCheckpointError("managed path checkpoint 校验失败") from exc

    def save(self, checkpoint: ManagedPathCheckpoint, *, writer_token: object) -> None:
        """仅允许绑定 writer 原子保存，失败不覆盖上一个有效文件。"""
        if writer_token is not self._writer_token:
            raise PermissionError("managed path checkpoint 只允许单一 writer")
        payload = checkpoint.model_dump(mode="json")
        self._reject_secret_material(payload)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_name(f".{self.path.name}.tmp")
        try:
            with temporary.open("w", encoding="utf-8", newline="\n") as stream:
                json.dump(
                    payload,
                    stream,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
            temporary.replace(self.path)
        finally:
            temporary.unlink(missing_ok=True)

    def assert_no_secret_material(self) -> None:
        """扫描 checkpoint 的 key/value，并重新执行严格 schema 校验。"""
        if not self.path.exists():
            return
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise ManagedPathCheckpointError("managed path checkpoint 无法扫描") from exc
        self._reject_secret_material(payload)
        if not isinstance(payload, dict):
            raise ManagedPathCheckpointError("managed path checkpoint 结构无效")
        try:
            ManagedPathCheckpoint.model_validate(payload)
        except ValidationError as exc:
            raise ManagedPathCheckpointError("managed path checkpoint 校验失败") from exc

    @classmethod
    def _reject_secret_material(cls, payload: object) -> None:
        if isinstance(payload, dict):
            values = cast(dict[object, object], payload)
            for raw_key, value in values.items():
                key = str(raw_key).lower().replace("-", "_")
                if key in _FORBIDDEN_KEYS:
                    raise ManagedPathCheckpointError("managed path checkpoint 包含禁止字段")
                cls._reject_secret_material(value)
            return
        if isinstance(payload, list):
            values = cast(list[object], payload)
            for value in values:
                cls._reject_secret_material(value)
            return
        if isinstance(payload, str) and any(
            fragment in payload.lower() for fragment in _FORBIDDEN_VALUE_FRAGMENTS
        ):
            raise ManagedPathCheckpointError("managed path checkpoint 包含秘密正文")


class NetworkAuthorizationReader(Protocol):
    """既有本机持久 L3 授权的只读查询端口。"""

    def list_grants(
        self,
        network_id: NetworkId,
        node_id: NodeId,
    ) -> tuple[NetworkAuthorizationGrant, ...]: ...


class NetworkAuthorizationMatch(BaseModel):
    """精确匹配后的脱敏结果。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    state: PathAuthorizationState
    code: ManagedPathPhaseOneErrorCode
    authorization_id: AuthorizationId | None = None

    @model_validator(mode="after")
    def validate_result(self) -> Self:
        authorized = self.state is PathAuthorizationState.AUTHORIZED
        if authorized != (self.authorization_id is not None):
            raise ValueError("授权匹配状态与授权 ID 不一致")
        return self


class ReadOnlyNetworkAuthorizationMatcher:
    """只读取 grant，并复用既有 scope.matches 逐维度精确匹配。"""

    def __init__(self, reader: NetworkAuthorizationReader) -> None:
        self._reader = reader

    def evaluate(self, plan: NetworkPlan, *, at: datetime) -> NetworkAuthorizationMatch:
        current = self.aware(at)
        desired = plan.desired
        grants = self._reader.list_grants(desired.network_id, desired.target_node_id)
        matching_scope = tuple(grant for grant in grants if grant.scope.matches(plan))
        active = next((grant for grant in matching_scope if grant.is_active(at=current)), None)
        if active is not None:
            return NetworkAuthorizationMatch(
                state=PathAuthorizationState.AUTHORIZED,
                code=ManagedPathPhaseOneErrorCode.PROVIDER_EXECUTION_DISABLED,
                authorization_id=active.authorization_id,
            )
        if any(grant.revoked_at is not None for grant in matching_scope):
            code = ManagedPathPhaseOneErrorCode.LOCAL_L3_APPROVAL_REVOKED
        elif any(grant.approved_at > current for grant in matching_scope):
            code = ManagedPathPhaseOneErrorCode.LOCAL_L3_APPROVAL_NOT_YET_VALID
        elif matching_scope:
            code = ManagedPathPhaseOneErrorCode.LOCAL_L3_APPROVAL_EXPIRED
        elif grants:
            code = ManagedPathPhaseOneErrorCode.LOCAL_L3_SCOPE_MISMATCH
        else:
            code = ManagedPathPhaseOneErrorCode.LOCAL_L3_APPROVAL_REQUIRED
        return NetworkAuthorizationMatch(
            state=PathAuthorizationState.AWAITING_AUTHORIZATION,
            code=code,
        )

    @staticmethod
    def aware(value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("授权匹配时钟必须包含时区")
        return value.astimezone(UTC)


class ReadOnlyPathRefresher(Protocol):
    """阶段一仅允许 fake/只读实现的刷新边界。"""

    async def refresh(self, checkpoint: ManagedPathCheckpoint) -> ManagedPathEvidenceState: ...


class ManagedPathCheckpointSink(Protocol):
    """只接收脱敏 checkpoint 的阶段一状态发布边界。"""

    async def publish(self, checkpoint: ManagedPathCheckpoint) -> None: ...


class ManagedPathPhaseOneLifecycle:
    """只保存 pending/授权状态并刷新只读证据，绝不调用 Provider。"""

    def __init__(
        self,
        provider: NetworkProvider,
        authorizations: ReadOnlyNetworkAuthorizationMatcher,
        checkpoints: FileManagedPathCheckpointRepository,
        refresher: ReadOnlyPathRefresher,
        *,
        writer_token: object,
        sinks: tuple[ManagedPathCheckpointSink, ...] = (),
    ) -> None:
        self._provider = provider
        self._authorizations = authorizations
        self._checkpoints = checkpoints
        self._refresher = refresher
        self._writer_token = writer_token
        self._sinks = sinks
        self._lock = asyncio.Lock()
        self._refresh_task: asyncio.Task[ManagedPathCheckpoint | None] | None = None

    async def stage_pending(
        self,
        envelope: SignedDesiredConfig,
        plan: NetworkPlan,
        *,
        at: datetime,
    ) -> ManagedPathCheckpoint:
        """记录脱敏 pending；阶段一即使已授权也不执行 Provider。"""
        if plan.desired != envelope.config:
            raise ValueError("pending plan 与 signed desired config 不一致")
        async with self._lock:
            match = self._authorizations.evaluate(plan, at=at)
            checkpoint = ManagedPathCheckpoint(
                network_id=plan.desired.network_id,
                node_id=plan.desired.target_node_id,
                revision=plan.desired.revision,
                provider=plan.desired.provider,
                pending_plan_hash=plan.plan_hash,
                observed_fingerprint=plan.observed_fingerprint,
                authorization_state=match.state,
                authorization_id=match.authorization_id,
                stable_error_code=match.code,
                updated_at=ReadOnlyNetworkAuthorizationMatcher.aware(at),
            )
            self._checkpoints.save(checkpoint, writer_token=self._writer_token)
            await self._publish(checkpoint)
            return checkpoint

    async def refresh(self) -> ManagedPathCheckpoint | None:
        """合并并发只读刷新；不重新评估授权，也不调用 Provider。"""
        task = self._refresh_task
        if task is None or task.done():
            task = asyncio.create_task(self._refresh_once())
            self._refresh_task = task
        return await asyncio.shield(task)

    async def _refresh_once(self) -> ManagedPathCheckpoint | None:
        async with self._lock:
            checkpoint = self._checkpoints.load()
            if checkpoint is None:
                return None
            evidence = await self._refresher.refresh(checkpoint)
            refreshed = checkpoint.model_copy(update={"evidence": evidence})
            self._checkpoints.save(refreshed, writer_token=self._writer_token)
            await self._publish(refreshed)
            return refreshed

    async def _publish(self, checkpoint: ManagedPathCheckpoint) -> None:
        for sink in self._sinks:
            await sink.publish(checkpoint)

    def read_status(self) -> ManagedPathCheckpoint | None:
        """供启动、模型、页面等消费者读取；不接触授权 writer。"""
        return self._checkpoints.load()
