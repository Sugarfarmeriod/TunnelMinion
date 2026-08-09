"""受管路径阶段一的脱敏状态、只读授权端口与零写入生命周期。"""

from __future__ import annotations

import asyncio
import base64
import binascii
import json
import os
import re
import stat
import unicodedata
from collections.abc import Callable, Generator
from contextlib import contextmanager, suppress
from datetime import datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import IO, Literal, Protocol, Self, cast
from urllib.parse import unquote
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from tunnelminion.domain.identifiers import AuthorizationId, NetworkId, NodeId
from tunnelminion.network.contracts import NetworkPlan, ProviderKind, SignedDesiredConfig
from tunnelminion.network.governance import NetworkAuthorizationGrant
from tunnelminion.network.path_controller import NetworkPathType
from tunnelminion.network.provider import NetworkProvider

MANAGED_PATH_CHECKPOINT_SCHEMA_VERSION = 1
MANAGED_PATH_CHECKPOINT_RELATIVE_PATH = Path("managed-path/checkpoint.json")
MANAGED_PATH_MAX_EVIDENCE_TTL = timedelta(seconds=180)

_HASH_PATTERN = r"^sha256:[0-9a-f]{64}$"
_WRITER_ID_PATTERN = r"^[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?$"
_LEGACY_SYNC_KEYS = frozenset({"applied_revision", "last_known_good", "pending_config", "phase"})
_FORBIDDEN_KEY_FRAGMENTS = frozenset(
    {
        "accesstoken",
        "allowedhostroutes",
        "authorizationheader",
        "bearer",
        "desiredconfig",
        "endpoint",
        "peers",
        "presharedkey",
        "privatekey",
        "psk",
        "refreshcredential",
        "routes",
        "signature",
        "token",
    }
)
_FORBIDDEN_VALUE_FRAGMENTS = frozenset(
    {
        "accesstoken",
        "authorizationheader",
        "bearer",
        "desiredconfig",
        "presharedkey",
        "privatekey",
        "psk",
        "refreshcredential",
        "signature",
    }
)
_ALLOWED_PUBLIC_KEYS = frozenset(
    {
        "applied_revision",
        "authorization_id",
        "authorization_state",
        "endpoint_probe_at",
        "endpoint_probe_succeeded",
        "evidence",
        "expires_at",
        "freshness",
        "handshake_fresh",
        "host_route_present",
        "last_handshake_at",
        "last_known_good",
        "last_known_good_revision",
        "network_id",
        "node_id",
        "observed_fingerprint",
        "path_type",
        "pending_config",
        "pending_plan_hash",
        "phase",
        "plan_hash",
        "provider",
        "refreshed_at",
        "revision",
        "schema_version",
        "selected_at",
        "selection",
        "source",
        "stable_error_code",
        "target_probe_at",
        "target_probe_succeeded",
        "updated_at",
    }
)


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


class ManagedPathEvidenceErrorCode(StrEnum):
    """路径证据唯一允许公开的固定错误码。"""

    NO_APPROVED_CANDIDATE = "no_approved_candidate"
    ENDPOINT_UNREACHABLE = "endpoint_unreachable"
    HANDSHAKE_STALE = "handshake_stale"
    HOST_ROUTE_MISSING = "host_route_missing"
    TARGET_UNREACHABLE = "target_unreachable"
    PERMISSION_DENIED = "permission_denied"
    UNSUPPORTED = "unsupported"


class ManagedPathPhaseOneErrorCode(StrEnum):
    """阶段一可公开的稳定错误码。"""

    LOCAL_L3_APPROVAL_REQUIRED = "local_l3_approval_required"
    LOCAL_L3_APPROVAL_EXPIRED = "local_l3_approval_expired"
    LOCAL_L3_APPROVAL_NOT_YET_VALID = "local_l3_approval_not_yet_valid"
    LOCAL_L3_APPROVAL_REVOKED = "local_l3_approval_revoked"
    LOCAL_L3_SCOPE_MISMATCH = "local_l3_scope_mismatch"
    PROVIDER_EXECUTION_DISABLED = "provider_execution_disabled_phase_one"


class ManagedPathOperationCode(StrEnum):
    """阶段一操作的稳定、不可携带正文的结果码。"""

    PERSISTED = "persisted"
    PERSISTED_WITH_SINK_FAILURES = "persisted_with_sink_failures"
    NO_CHECKPOINT = "no_checkpoint"
    REFRESH_NOT_COMMITTED = "refresh_not_committed_phase_one"
    REFRESH_REJECTED_BINDING = "refresh_rejected_binding"
    REFRESH_REJECTED_TIME = "refresh_rejected_time"


class ManagedPathSinkErrorCode(StrEnum):
    """状态发布失败的固定聚合码。"""

    PUBLISH_FAILED = "publish_failed"


def _require_utc(value: datetime, *, label: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise ValueError(f"{label}必须使用 timezone-aware UTC")
    return value


class ManagedPathSelectionState(BaseModel):
    """不含地址与路由的路径选择摘要。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    path_type: NetworkPathType
    selected_at: datetime
    last_known_good_revision: int | None = Field(default=None, ge=1)

    @model_validator(mode="after")
    def validate_time(self) -> Self:
        _require_utc(self.selected_at, label="selection 时间")
        return self


class ManagedPathEvidenceState(BaseModel):
    """四维路径事实的脱敏时间、绑定与固定结果码。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    source: PathEvidenceSource = PathEvidenceSource.NONE
    freshness: PathEvidenceFreshness = PathEvidenceFreshness.UNKNOWN
    network_id: NetworkId | None = None
    node_id: NodeId | None = None
    revision: int | None = Field(default=None, ge=1)
    provider: ProviderKind | None = None
    plan_hash: str | None = Field(default=None, pattern=_HASH_PATTERN)
    observed_fingerprint: str | None = Field(default=None, pattern=_HASH_PATTERN)
    authorization_id: AuthorizationId | None = None
    endpoint_probe_at: datetime | None = None
    endpoint_probe_succeeded: bool | None = None
    last_handshake_at: datetime | None = None
    handshake_fresh: bool | None = None
    host_route_present: bool | None = None
    target_probe_at: datetime | None = None
    target_probe_succeeded: bool | None = None
    refreshed_at: datetime | None = None
    expires_at: datetime | None = None
    stable_error_code: ManagedPathEvidenceErrorCode | None = None

    @model_validator(mode="after")
    def validate_freshness(self) -> Self:
        timestamps = (
            self.endpoint_probe_at,
            self.last_handshake_at,
            self.target_probe_at,
            self.refreshed_at,
            self.expires_at,
        )
        for value in timestamps:
            if value is not None:
                _require_utc(value, label="路径证据时间")
        bindings = (
            self.network_id,
            self.node_id,
            self.revision,
            self.provider,
            self.plan_hash,
            self.observed_fingerprint,
        )
        if self.freshness is PathEvidenceFreshness.UNKNOWN:
            if self.source is not PathEvidenceSource.NONE or any(
                value is not None for value in bindings
            ):
                raise ValueError("未知证据不得声明来源或运行时绑定")
            if self.refreshed_at is not None or self.expires_at is not None:
                raise ValueError("未知证据不得声明刷新窗口")
            return self
        if self.source is PathEvidenceSource.NONE or any(value is None for value in bindings):
            raise ValueError("已观测证据必须声明来源与完整运行时绑定")
        if self.refreshed_at is None or self.expires_at is None:
            raise ValueError("已观测证据必须声明刷新窗口")
        if self.expires_at <= self.refreshed_at:
            raise ValueError("证据过期时间必须晚于刷新时间")
        if self.expires_at - self.refreshed_at > MANAGED_PATH_MAX_EVIDENCE_TTL:
            raise ValueError("证据 TTL 超出固定上限")
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
        _require_utc(self.updated_at, label="checkpoint 更新时间")
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


class ManagedPathSinkFailure(BaseModel):
    """不包含异常正文的 sink 失败聚合。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    sink_index: int = Field(ge=0)
    code: ManagedPathSinkErrorCode = ManagedPathSinkErrorCode.PUBLISH_FAILED


class ManagedPathOperationResult(BaseModel):
    """区分本地持久成功与远端发布失败，避免调用方盲目重试。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    code: ManagedPathOperationCode
    persisted: bool
    evidence_accepted: bool = False
    checkpoint: ManagedPathCheckpoint | None = None
    sink_failures: tuple[ManagedPathSinkFailure, ...] = ()


class ManagedPathCheckpointError(RuntimeError):
    """checkpoint 缺失以外的稳定 fail-closed 错误。"""


class FileManagedPathCheckpointRepository:
    """在明确根目录内以持久 owner 和进程锁原子保存 checkpoint。"""

    def __init__(
        self,
        allowed_root: Path,
        *,
        writer_id: str,
        relative_path: Path = MANAGED_PATH_CHECKPOINT_RELATIVE_PATH,
    ) -> None:
        if not allowed_root.is_absolute():
            raise ManagedPathCheckpointError("allowed_root 必须是绝对路径")
        if relative_path != MANAGED_PATH_CHECKPOINT_RELATIVE_PATH:
            raise ManagedPathCheckpointError("checkpoint 必须使用固定相对路径")
        if not writer_id or not re.fullmatch(_WRITER_ID_PATTERN, writer_id):
            raise ManagedPathCheckpointError("writer identity 格式无效")
        self.allowed_root = allowed_root
        self.writer_id = writer_id
        self.path = allowed_root / relative_path
        self._owner_path = self.path.parent / ".writer-owner.json"
        self._lock_path = self.path.parent / ".writer.lock"
        self._prepare_root()
        self._claim_writer()

    def _prepare_root(self) -> None:
        if self.allowed_root.is_symlink() or not self.allowed_root.is_dir():
            raise ManagedPathCheckpointError("allowed_root 必须是非符号链接目录")
        resolved_root = self.allowed_root.resolve(strict=True)
        if resolved_root != self.allowed_root:  # pragma: no cover - 根目录符号链接前置已拒绝
            raise ManagedPathCheckpointError("allowed_root 不得包含路径别名或逃逸")
        parent = self.path.parent
        if parent.exists():
            self._require_directory(parent)
        else:
            parent.mkdir(mode=0o700)
            self._require_directory(parent)
        if parent.resolve(strict=True).parent != resolved_root:  # pragma: no cover - 固定相对路径
            raise ManagedPathCheckpointError("checkpoint 路径逃逸 allowed_root")
        self._require_safe_optional_file(self.path)
        self._require_safe_optional_file(self._owner_path)
        self._require_safe_optional_file(self._lock_path)

    @staticmethod
    def _require_directory(path: Path) -> None:
        if path.is_symlink() or not path.is_dir():
            raise ManagedPathCheckpointError("checkpoint 父级必须是非符号链接目录")

    @staticmethod
    def _require_safe_optional_file(path: Path) -> None:
        if path.is_symlink():
            raise ManagedPathCheckpointError("checkpoint 文件不得是符号链接")
        if path.exists() and not stat.S_ISREG(path.stat(follow_symlinks=False).st_mode):
            raise ManagedPathCheckpointError("checkpoint 路径必须是普通文件")

    @staticmethod
    def _exclusive_flags() -> int:
        return os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)

    def _claim_writer(self) -> None:
        payload = json.dumps({"writer_id": self.writer_id}, separators=(",", ":")) + "\n"
        try:
            descriptor = os.open(self._owner_path, self._exclusive_flags(), 0o600)
        except FileExistsError:
            self._require_safe_optional_file(self._owner_path)
            try:
                existing = json.loads(self._owner_path.read_text(encoding="utf-8"))
            except (OSError, UnicodeError, json.JSONDecodeError) as exc:
                raise ManagedPathCheckpointError("writer owner claim 无法读取") from exc
            if existing != {"writer_id": self.writer_id}:
                raise PermissionError("managed path checkpoint 已由其他 writer 持有") from None
            return
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        self._fsync_directory(self.path.parent)

    def load(self) -> ManagedPathCheckpoint | None:
        """兼容识别旧同步状态，但绝不从中推断 path selection。"""
        self._validate_paths()
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

    def save(self, checkpoint: ManagedPathCheckpoint) -> None:
        """持久 owner 在跨进程互斥锁内执行安全原子替换。"""
        payload = checkpoint.model_dump(mode="json")
        self._reject_secret_material(payload)
        encoded = (
            json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
        ).encode("utf-8")
        with self._writer_lock():
            self._validate_paths()
            temporary = self.path.parent / f".{self.path.name}.{uuid4().hex}.tmp"
            descriptor: int | None = None
            try:
                descriptor = os.open(temporary, self._exclusive_flags(), 0o600)
                with os.fdopen(descriptor, "wb") as stream:
                    descriptor = None
                    stream.write(encoded)
                    stream.flush()
                    os.fsync(stream.fileno())
                self._validate_paths()
                os.replace(temporary, self.path)
                self._fsync_directory(self.path.parent)
            finally:
                if descriptor is not None:  # pragma: no cover - 仅 os.fdopen 自身失败时成立
                    os.close(descriptor)
                with suppress(OSError):
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

    def _validate_paths(self) -> None:
        self._require_directory(self.path.parent)
        for path in (self.path, self._owner_path, self._lock_path):
            self._require_safe_optional_file(path)
        try:
            owner = json.loads(self._owner_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise ManagedPathCheckpointError("writer owner claim 无法读取") from exc
        if owner != {"writer_id": self.writer_id}:
            raise PermissionError("managed path checkpoint writer identity 已变化")

    @contextmanager
    def _writer_lock(self) -> Generator[None, None, None]:
        self._require_safe_optional_file(self._lock_path)
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(self._lock_path, flags, 0o600)
        stream = os.fdopen(descriptor, "r+b", buffering=0)
        try:
            if self._lock_path.stat(follow_symlinks=False).st_size == 0:
                stream.write(b"0")
                stream.flush()
                os.fsync(stream.fileno())
            stream.seek(0)
            self._acquire_os_lock(stream)
            try:
                yield
            finally:
                self._release_os_lock(stream)
        finally:
            stream.close()

    @staticmethod
    def _acquire_os_lock(stream: IO[bytes]) -> None:
        try:
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
            else:  # pragma: no cover - 由非 Windows 门禁执行
                import fcntl

                fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            raise ManagedPathCheckpointError("checkpoint writer 正忙") from exc

    @staticmethod
    def _release_os_lock(stream: IO[bytes]) -> None:
        stream.seek(0)
        if os.name == "nt":
            import msvcrt

            msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
        else:  # pragma: no cover - 由非 Windows 门禁执行
            import fcntl

            fcntl.flock(stream.fileno(), fcntl.LOCK_UN)

    @staticmethod
    def _fsync_directory(path: Path) -> None:
        if os.name != "nt":  # pragma: no cover - 由非 Windows 门禁执行
            descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)

    @classmethod
    def _reject_secret_material(cls, payload: object) -> None:
        if isinstance(payload, dict):
            values = cast(dict[object, object], payload)
            for raw_key, value in values.items():
                if not isinstance(raw_key, str) or (
                    raw_key not in _ALLOWED_PUBLIC_KEYS
                    and cls._contains_forbidden_fragment(
                        raw_key,
                        fragments=_FORBIDDEN_KEY_FRAGMENTS,
                    )
                ):
                    raise ManagedPathCheckpointError("managed path checkpoint 包含禁止字段")
                cls._reject_secret_material(value)
            return
        if isinstance(payload, list):
            for value in cast(list[object], payload):
                cls._reject_secret_material(value)
            return
        if isinstance(payload, str) and cls._contains_forbidden_fragment(
            payload,
            fragments=_FORBIDDEN_VALUE_FRAGMENTS,
        ):
            raise ManagedPathCheckpointError("managed path checkpoint 包含禁止正文")

    @classmethod
    def _contains_forbidden_fragment(
        cls,
        value: str,
        *,
        fragments: frozenset[str],
    ) -> bool:
        variants = {value}
        decoded = value
        for _ in range(2):
            decoded = unquote(decoded)
            variants.add(decoded)
        compact = "".join(value.split())
        if len(compact) <= 4096:
            try:
                decoded_bytes = base64.b64decode(compact, validate=True)
                variants.add(decoded_bytes.decode("utf-8"))
            except (ValueError, UnicodeError, binascii.Error):
                pass
        for variant in variants:
            normalized = unicodedata.normalize("NFKC", variant).casefold()
            canonical = "".join(character for character in normalized if character.isalnum())
            if any(fragment in canonical for fragment in fragments):
                return True
        return False


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
        current = _require_utc(at, label="授权匹配时钟")
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


class ReadOnlyPathRefresher(Protocol):
    """阶段一仅允许 fake/只读实现的刷新边界。"""

    async def refresh(self, checkpoint: ManagedPathCheckpoint) -> ManagedPathEvidenceState: ...


class ManagedPathCheckpointSink(Protocol):
    """只接收脱敏 checkpoint 的阶段一状态发布边界。"""

    async def publish(self, checkpoint: ManagedPathCheckpoint) -> None: ...


class ManagedPathPhaseOneLifecycle:
    """只保存 pending 并验证刷新候选；阶段一绝不提交 evidence 或调用 Provider。"""

    def __init__(
        self,
        provider: NetworkProvider,
        authorizations: ReadOnlyNetworkAuthorizationMatcher,
        checkpoints: FileManagedPathCheckpointRepository,
        refresher: ReadOnlyPathRefresher,
        *,
        clock: Callable[[], datetime],
        sinks: tuple[ManagedPathCheckpointSink, ...] = (),
    ) -> None:
        self._provider = provider
        self._authorizations = authorizations
        self._checkpoints = checkpoints
        self._refresher = refresher
        self._clock = clock
        self._sinks = sinks
        self._lock = asyncio.Lock()
        self._refresh_task: asyncio.Task[ManagedPathOperationResult] | None = None

    async def stage_pending(
        self,
        envelope: SignedDesiredConfig,
        plan: NetworkPlan,
        *,
        at: datetime,
    ) -> ManagedPathOperationResult:
        """记录脱敏 pending；已落盘后 sink 失败只作为聚合状态返回。"""
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
                updated_at=_require_utc(at, label="pending 时间"),
            )
            self._checkpoints.save(checkpoint)
            failures = await self._publish(checkpoint)
            code = (
                ManagedPathOperationCode.PERSISTED_WITH_SINK_FAILURES
                if failures
                else ManagedPathOperationCode.PERSISTED
            )
            return ManagedPathOperationResult(
                code=code,
                persisted=True,
                checkpoint=checkpoint,
                sink_failures=failures,
            )

    async def refresh(self) -> ManagedPathOperationResult:
        """合并并发只读刷新；阶段一验证候选但不改变已持久 evidence。"""
        task = self._refresh_task
        if task is None or task.done():
            task = asyncio.create_task(self._refresh_once())
            self._refresh_task = task
        return await asyncio.shield(task)

    async def _refresh_once(self) -> ManagedPathOperationResult:
        async with self._lock:
            checkpoint = self._checkpoints.load()
            if checkpoint is None:
                return ManagedPathOperationResult(
                    code=ManagedPathOperationCode.NO_CHECKPOINT,
                    persisted=False,
                )
            candidate = await self._refresher.refresh(checkpoint)
            code = self._validate_refresh_candidate(checkpoint, candidate)
            return ManagedPathOperationResult(
                code=code,
                persisted=True,
                evidence_accepted=False,
                checkpoint=checkpoint,
            )

    def _validate_refresh_candidate(
        self,
        checkpoint: ManagedPathCheckpoint,
        candidate: ManagedPathEvidenceState,
    ) -> ManagedPathOperationCode:
        bindings = (
            candidate.network_id == checkpoint.network_id,
            candidate.node_id == checkpoint.node_id,
            candidate.revision == checkpoint.revision,
            candidate.provider is checkpoint.provider,
            candidate.plan_hash == checkpoint.pending_plan_hash,
            candidate.observed_fingerprint == checkpoint.observed_fingerprint,
            candidate.authorization_id == checkpoint.authorization_id,
        )
        if not all(bindings):
            return ManagedPathOperationCode.REFRESH_REJECTED_BINDING
        now = _require_utc(self._clock(), label="刷新时钟")
        refreshed_at = candidate.refreshed_at
        expires_at = candidate.expires_at
        if refreshed_at is None or expires_at is None:  # pragma: no cover - schema 已先行保证
            return ManagedPathOperationCode.REFRESH_REJECTED_TIME
        existing_refreshed_at = checkpoint.evidence.refreshed_at
        if (
            refreshed_at < checkpoint.updated_at
            or refreshed_at > now
            or expires_at <= now
            or expires_at - refreshed_at > MANAGED_PATH_MAX_EVIDENCE_TTL
            or (existing_refreshed_at is not None and refreshed_at < existing_refreshed_at)
        ):
            return ManagedPathOperationCode.REFRESH_REJECTED_TIME
        return ManagedPathOperationCode.REFRESH_NOT_COMMITTED

    async def _publish(
        self,
        checkpoint: ManagedPathCheckpoint,
    ) -> tuple[ManagedPathSinkFailure, ...]:
        failures: list[ManagedPathSinkFailure] = []
        for index, sink in enumerate(self._sinks):
            try:
                await sink.publish(checkpoint)
            except Exception:
                failures.append(ManagedPathSinkFailure(sink_index=index))
        return tuple(failures)

    def read_status(self) -> ManagedPathCheckpoint | None:
        """只读状态投影；不接触授权 writer、refresher 或 Provider。"""
        return self._checkpoints.load()
