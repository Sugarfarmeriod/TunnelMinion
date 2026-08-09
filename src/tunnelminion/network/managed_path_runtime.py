"""受管路径阶段一的脱敏状态、只读授权端口与零写入生命周期。"""

from __future__ import annotations

import asyncio
import base64
import binascii
import ctypes
import importlib
import json
import os
import re
import secrets
import stat
import unicodedata
from collections.abc import Callable, Generator
from contextlib import contextmanager, suppress
from datetime import datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Any, Literal, Protocol, Self, cast
from urllib.parse import unquote

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from tunnelminion.domain.identifiers import AuthorizationId, NetworkId, NodeId
from tunnelminion.network.contracts import (
    NetworkPlan,
    ProviderKind,
    SignedDesiredConfig,
    canonical_sha256,
)
from tunnelminion.network.governance import NetworkAuthorizationGrant
from tunnelminion.network.path_controller import NetworkPathType
from tunnelminion.network.provider import NetworkProvider

MANAGED_PATH_CHECKPOINT_SCHEMA_VERSION = 1
MANAGED_PATH_CHECKPOINT_RELATIVE_PATH = Path("managed-path/checkpoint.json")
MANAGED_PATH_MAX_EVIDENCE_TTL = timedelta(seconds=180)

_HASH_PATTERN = r"^sha256:[0-9a-f]{64}$"
_WRITER_ID_PATTERN = r"^[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?$"
_PROCESS_START_NONCE = secrets.token_hex(32)
_REPARSE_POINT_ATTRIBUTE = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
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
        "publication_id",
        "refreshed_at",
        "revision",
        "schema_version",
        "selected_at",
        "selection",
        "source",
        "stable_error_code",
        "sink_delivery_states",
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


class ManagedPathSinkDeliveryState(StrEnum):
    """单个 sink 对固定 checkpoint identity 的发布结论。"""

    SUCCEEDED = "succeeded"
    FAILED = "failed"
    UNKNOWN = "unknown"
    NOT_ATTEMPTED = "not_attempted"


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
            if (
                self.source is not PathEvidenceSource.NONE
                or any(value is not None for value in bindings)
                or self.authorization_id is not None
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
    publication_id: str | None = Field(default=None, pattern=_HASH_PATTERN)
    sink_delivery_states: tuple[ManagedPathSinkDeliveryState, ...] = ()

    @model_validator(mode="after")
    def validate_authorization(self) -> Self:
        _require_utc(self.updated_at, label="checkpoint 更新时间")
        authorized = self.authorization_state is PathAuthorizationState.AUTHORIZED
        if authorized != (self.authorization_id is not None):
            raise ValueError("授权状态与授权 ID 不一致")
        if self.sink_delivery_states and self.publication_id is None:
            raise ValueError("sink 发布状态必须绑定 publication identity")
        if (
            self.selection is not None
            and self.selection.path_type is NetworkPathType.DIRECT
            and self.evidence.freshness is not PathEvidenceFreshness.FRESH
        ):
            raise ValueError("direct selection 必须具有新鲜证据")
        if self.evidence.source is not PathEvidenceSource.NONE:
            evidence_bindings = (
                self.evidence.network_id == self.network_id,
                self.evidence.node_id == self.node_id,
                self.evidence.revision == self.revision,
                self.evidence.provider is self.provider,
                self.evidence.plan_hash == self.pending_plan_hash,
                self.evidence.observed_fingerprint == self.observed_fingerprint,
                self.evidence.authorization_id == self.authorization_id,
            )
            if not all(evidence_bindings):
                raise ValueError("嵌套 evidence 与父 checkpoint 绑定不一致")
        return self


class ManagedPathSinkFailure(BaseModel):
    """不包含异常正文的 sink 失败聚合。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    sink_index: int = Field(ge=0)
    code: ManagedPathSinkErrorCode = ManagedPathSinkErrorCode.PUBLISH_FAILED


class ManagedPathSinkDelivery(BaseModel):
    """按 checkpoint identity 记录的脱敏 sink 发布状态。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    sink_index: int = Field(ge=0)
    state: ManagedPathSinkDeliveryState


class ManagedPathOperationResult(BaseModel):
    """区分本地持久成功与远端发布失败，避免调用方盲目重试。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    code: ManagedPathOperationCode
    persisted: bool
    evidence_accepted: bool = False
    checkpoint: ManagedPathCheckpoint | None = None
    publication_id: str | None = Field(default=None, pattern=_HASH_PATTERN)
    sink_deliveries: tuple[ManagedPathSinkDelivery, ...] = ()

    @property
    def sink_failures(self) -> tuple[ManagedPathSinkFailure, ...]:
        return tuple(
            ManagedPathSinkFailure(sink_index=delivery.sink_index)
            for delivery in self.sink_deliveries
            if delivery.state is ManagedPathSinkDeliveryState.FAILED
        )


class ManagedPathPublicationCancelled(asyncio.CancelledError):
    """发布取消，但 checkpoint 已落盘；结果不包含底层异常正文。"""

    def __init__(self, result: ManagedPathOperationResult) -> None:
        super().__init__("managed path publication cancelled after persistence")
        self.result = result


class ManagedPathCheckpointError(RuntimeError):
    """checkpoint 缺失以外的稳定 fail-closed 错误。"""


class _WindowsTrustedDirectoryApi:
    """用目录 handle 约束 Windows 子项 I/O，且拒绝 reparse point。"""

    _GENERIC_READ = 0x80000000
    _GENERIC_WRITE = 0x40000000
    _DELETE = 0x00010000
    _FILE_LIST_DIRECTORY = 0x00000001
    _FILE_TRAVERSE = 0x00000020
    _FILE_READ_ATTRIBUTES = 0x00000080
    _FILE_SHARE_READ = 0x00000001
    _FILE_SHARE_WRITE = 0x00000002
    _CREATE_NEW = 1
    _OPEN_EXISTING = 3
    _FILE_ATTRIBUTE_NORMAL = 0x00000080
    _FILE_FLAG_WRITE_THROUGH = 0x80000000
    _FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
    _FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
    _FILE_ATTRIBUTE_DIRECTORY = 0x00000010
    _FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
    _FILE_ATTRIBUTE_TAG_INFO = 9
    _FILE_RENAME_INFO = 3
    _FILE_DISPOSITION_INFO = 4
    _LOCKFILE_FAIL_IMMEDIATELY = 0x00000001
    _LOCKFILE_EXCLUSIVE_LOCK = 0x00000002
    _INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

    class _FileAttributeTagInfo(ctypes.Structure):
        _fields_ = (("file_attributes", ctypes.c_uint32), ("reparse_tag", ctypes.c_uint32))

    class _Overlapped(ctypes.Structure):
        _fields_ = (
            ("internal", ctypes.c_void_p),
            ("internal_high", ctypes.c_void_p),
            ("offset", ctypes.c_uint32),
            ("offset_high", ctypes.c_uint32),
            ("event", ctypes.c_void_p),
        )

    class _FileDispositionInfo(ctypes.Structure):
        _fields_ = (("delete_file", ctypes.c_int),)

    class _FileRenameInfoHeader(ctypes.Structure):
        _fields_ = (
            ("replace_if_exists", ctypes.c_uint32),
            ("root_directory", ctypes.c_void_p),
            ("file_name_length", ctypes.c_uint32),
        )

    def __init__(self) -> None:
        win_dll = cast(Callable[..., Any], ctypes.__dict__["WinDLL"])
        kernel32 = win_dll("kernel32", use_last_error=True)
        self._create_file = kernel32.CreateFileW
        self._create_file.restype = ctypes.c_void_p
        self._get_info = kernel32.GetFileInformationByHandleEx
        self._get_info.restype = ctypes.c_int
        self._set_info = kernel32.SetFileInformationByHandle
        self._set_info.restype = ctypes.c_int
        self._close_handle = kernel32.CloseHandle
        self._close_handle.restype = ctypes.c_int
        self._lock_file = kernel32.LockFileEx
        self._lock_file.restype = ctypes.c_int
        self._unlock_file = kernel32.UnlockFileEx
        self._unlock_file.restype = ctypes.c_int

    @staticmethod
    def _raise_last_error(label: str) -> None:
        get_last_error = cast(Callable[[], int], ctypes.__dict__["get_last_error"])
        error = get_last_error()
        if error in {80, 183}:
            raise FileExistsError(error, label)
        if error in {2, 3}:
            raise FileNotFoundError(error, label)
        if error == 5:
            raise PermissionError(error, label)
        if error in {32, 33}:
            raise ManagedPathCheckpointError(label)
        raise OSError(error, label)

    def open_directory(self, path: Path) -> int:
        handle = cast(
            int,
            self._create_file(
                str(path),
                self._FILE_LIST_DIRECTORY | self._FILE_TRAVERSE | self._FILE_READ_ATTRIBUTES,
                self._FILE_SHARE_READ | self._FILE_SHARE_WRITE,
                None,
                self._OPEN_EXISTING,
                self._FILE_FLAG_BACKUP_SEMANTICS | self._FILE_FLAG_OPEN_REPARSE_POINT,
                None,
            ),
        )
        if handle == self._INVALID_HANDLE_VALUE:
            self._raise_last_error("可信目录无法打开")
        try:
            self.require_directory(handle)
        except BaseException:
            self.close_handle(handle)
            raise
        return handle

    def open_file(
        self,
        path: Path,
        *,
        create: bool,
        writable: bool,
        deletable: bool,
    ) -> int:
        access = self._GENERIC_READ | self._FILE_READ_ATTRIBUTES
        if writable:
            access |= self._GENERIC_WRITE
        if deletable:
            access |= self._DELETE
        handle = cast(
            int,
            self._create_file(
                str(path),
                access,
                self._FILE_SHARE_READ | self._FILE_SHARE_WRITE,
                None,
                self._CREATE_NEW if create else self._OPEN_EXISTING,
                self._FILE_ATTRIBUTE_NORMAL
                | self._FILE_FLAG_OPEN_REPARSE_POINT
                | (self._FILE_FLAG_WRITE_THROUGH if writable else 0),
                None,
            ),
        )
        if handle == self._INVALID_HANDLE_VALUE:
            self._raise_last_error("可信文件无法打开")
        try:
            self.require_regular(handle)
            return self._handle_to_fd(handle)
        except BaseException:
            self.close_handle(handle)
            raise

    @staticmethod
    def _handle_to_fd(handle: int) -> int:
        runtime = importlib.import_module("msvcrt")
        open_osfhandle = cast(Callable[[int, int], int], runtime.__dict__["open_osfhandle"])
        binary_flag = cast(int, os.__dict__.get("O_BINARY", 0))
        return open_osfhandle(handle, binary_flag | os.O_RDWR)

    @staticmethod
    def fd_handle(descriptor: int) -> int:
        runtime = importlib.import_module("msvcrt")
        get_osfhandle = cast(Callable[[int], int], runtime.__dict__["get_osfhandle"])
        return get_osfhandle(descriptor)

    def _attributes(self, handle: int) -> int:
        value = self._FileAttributeTagInfo()
        if not self._get_info(
            handle,
            self._FILE_ATTRIBUTE_TAG_INFO,
            ctypes.byref(value),
            ctypes.sizeof(value),
        ):
            self._raise_last_error("可信句柄元数据无法读取")
        return value.file_attributes

    def require_directory(self, handle: int) -> None:
        attributes = self._attributes(handle)
        if not attributes & self._FILE_ATTRIBUTE_DIRECTORY or attributes & (
            self._FILE_ATTRIBUTE_REPARSE_POINT
        ):
            raise ManagedPathCheckpointError("可信目录不得是 reparse point")

    def require_regular(self, handle: int) -> None:
        attributes = self._attributes(handle)
        if attributes & (self._FILE_ATTRIBUTE_DIRECTORY | self._FILE_ATTRIBUTE_REPARSE_POINT):
            raise ManagedPathCheckpointError("可信文件必须是非 reparse 普通文件")

    def replace(self, descriptor: int, target_path: Path) -> None:
        encoded_name = str(target_path).encode("utf-16-le")
        name_offset = self._FileRenameInfoHeader.file_name_length.offset + ctypes.sizeof(
            ctypes.c_uint32
        )
        buffer = ctypes.create_string_buffer(name_offset + len(encoded_name) + 2)
        header = self._FileRenameInfoHeader.from_buffer(buffer)
        header.replace_if_exists = 1
        header.root_directory = None
        header.file_name_length = len(encoded_name)
        ctypes.memmove(ctypes.addressof(buffer) + name_offset, encoded_name, len(encoded_name))
        if not self._set_info(
            self.fd_handle(descriptor),
            self._FILE_RENAME_INFO,
            buffer,
            len(buffer),
        ):
            self._raise_last_error("checkpoint 原子替换失败")

    def unlink(self, descriptor: int) -> None:
        value = self._FileDispositionInfo(delete_file=1)
        if not self._set_info(
            self.fd_handle(descriptor),
            self._FILE_DISPOSITION_INFO,
            ctypes.byref(value),
            ctypes.sizeof(value),
        ):
            self._raise_last_error("可信文件删除失败")

    @contextmanager
    def lock(self, descriptor: int) -> Generator[None, None, None]:
        overlapped = self._Overlapped()
        handle = self.fd_handle(descriptor)
        if not self._lock_file(
            handle,
            self._LOCKFILE_FAIL_IMMEDIATELY | self._LOCKFILE_EXCLUSIVE_LOCK,
            0,
            1,
            0,
            ctypes.byref(overlapped),
        ):
            self._raise_last_error("checkpoint writer 正忙")
        try:
            yield
        finally:
            if not self._unlock_file(handle, 0, 1, 0, ctypes.byref(overlapped)):
                self._raise_last_error("checkpoint writer 锁无法释放")

    def close_handle(self, handle: int) -> None:
        if not self._close_handle(handle):
            self._raise_last_error("可信目录句柄无法关闭")


class _TrustedDirectory:
    """绑定已验证目录对象；后续子项 I/O 不再重新解析可替换父路径。"""

    def __init__(self, path: Path, *, descriptor: int | None = None) -> None:
        self.path = path
        self._windows = cast(
            _WindowsTrustedDirectoryApi | None,
            _WindowsTrustedDirectoryApi() if os.name == "nt" else None,
        )
        self._descriptor = descriptor if descriptor is not None else self._open_directory(path)
        self._closed = False
        self._identity = os.fstat(self._descriptor) if self._windows is None else None
        self.validate()

    def _open_directory(self, path: Path) -> int:
        if self._windows is not None:
            return self._windows.open_directory(path)
        return os.open(
            path,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
        )

    def validate(self) -> None:
        if self._closed:
            raise ManagedPathCheckpointError("可信目录句柄已关闭")
        if self._windows is not None:
            self._windows.require_directory(self._descriptor)
            return
        metadata = os.fstat(self._descriptor)
        if not stat.S_ISDIR(metadata.st_mode):
            raise ManagedPathCheckpointError("可信目录句柄不再指向目录")

    def require_public_identity(self) -> None:
        """公开路径被替换时停止；后续 I/O 仍仅使用已绑定目录句柄。"""
        self.validate()
        if self._windows is not None:
            return
        try:
            visible = self.path.stat(follow_symlinks=False)
        except OSError as exc:
            raise ManagedPathCheckpointError("checkpoint 目录公开身份已变化") from exc
        if (
            self._identity is None
            or not stat.S_ISDIR(visible.st_mode)
            or stat.S_ISLNK(visible.st_mode)
            or not os.path.samestat(self._identity, visible)
        ):
            raise ManagedPathCheckpointError("checkpoint 目录公开身份已变化")

    def open_child_directory(self, name: str) -> _TrustedDirectory:
        self._require_name(name)
        try:
            if self._windows is not None:
                os.mkdir(self.path / name, mode=0o700)
            else:
                os.mkdir(name, mode=0o700, dir_fd=self._descriptor)
        except FileExistsError:
            pass
        if self._windows is not None:
            descriptor = self._windows.open_directory(self.path / name)
        else:
            descriptor = os.open(
                name,
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=self._descriptor,
            )
        return _TrustedDirectory(self.path / name, descriptor=descriptor)

    def open_file(
        self,
        name: str,
        *,
        create: bool = False,
        writable: bool = False,
        deletable: bool = False,
    ) -> int:
        self._require_name(name)
        self.validate()
        if self._windows is not None:
            try:
                return self._windows.open_file(
                    self.path / name,
                    create=create,
                    writable=writable,
                    deletable=deletable,
                )
            except PermissionError as exc:
                raise ManagedPathCheckpointError("可信文件必须是非 reparse 普通文件") from exc
        flags = os.O_RDONLY
        if writable:
            flags = os.O_RDWR
        if create:
            flags |= os.O_CREAT | os.O_EXCL
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(name, flags, 0o600, dir_fd=self._descriptor)
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode):
                raise ManagedPathCheckpointError("可信文件必须是普通文件")
        except BaseException:
            os.close(descriptor)
            raise
        return descriptor

    def read_bytes(self, name: str) -> bytes:
        descriptor = self.open_file(name)
        try:
            chunks: list[bytes] = []
            while chunk := os.read(descriptor, 65536):
                chunks.append(chunk)
            return b"".join(chunks)
        finally:
            os.close(descriptor)

    def exists(self, name: str) -> bool:
        try:
            descriptor = self.open_file(name)
        except FileNotFoundError:
            return False
        else:
            os.close(descriptor)
            return True

    def replace_open_file(self, descriptor: int, source_name: str, target_name: str) -> None:
        self._require_name(source_name)
        self._require_name(target_name)
        self.validate()
        if self._windows is not None:
            self._windows.replace(descriptor, self.path / target_name)
            self.sync_metadata(descriptor)
            return
        os.replace(
            source_name,
            target_name,
            src_dir_fd=self._descriptor,
            dst_dir_fd=self._descriptor,
        )
        self.sync_metadata()

    def unlink(self, name: str, *, missing_ok: bool = False) -> None:
        try:
            descriptor = self.open_file(name, writable=True, deletable=True)
        except FileNotFoundError:
            if missing_ok:
                return
            raise
        try:
            if self._windows is not None:
                self._windows.unlink(descriptor)
                self.sync_metadata(descriptor)
            else:
                os.unlink(name, dir_fd=self._descriptor)
        finally:
            os.close(descriptor)
        if self._windows is None:
            self.sync_metadata()

    @contextmanager
    def lock(self, name: str) -> Generator[None, None, None]:
        descriptor = self.open_file(name, writable=True)
        try:
            if self._windows is not None:
                with self._windows.lock(descriptor):
                    yield
            else:
                fcntl = cast(Any, importlib.import_module("fcntl"))

                try:
                    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except OSError as exc:
                    raise ManagedPathCheckpointError("checkpoint writer 正忙") from exc
                try:
                    yield
                finally:
                    fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)

    def sync_metadata(self, descriptor: int | None = None) -> None:
        self.validate()
        if self._windows is not None:
            if descriptor is None:
                raise ManagedPathCheckpointError("Windows 元数据同步缺少可信文件句柄")
            self.sync_file(descriptor)
            return
        try:
            os.fsync(self._descriptor)
        except OSError as exc:
            raise ManagedPathCheckpointError("checkpoint 目录元数据无法持久化") from exc

    @staticmethod
    def sync_file(descriptor: int) -> None:
        try:
            os.fsync(descriptor)
        except OSError as exc:
            raise ManagedPathCheckpointError("checkpoint 文件无法持久化") from exc

    def close(self) -> None:
        if self._closed:
            return
        if self._windows is not None:
            self._windows.close_handle(self._descriptor)
        else:
            os.close(self._descriptor)
        self._closed = True

    @staticmethod
    def _require_name(name: str) -> None:
        if not name or name in {".", ".."} or Path(name).name != name:
            raise ManagedPathCheckpointError("可信目录只接受固定单层文件名")


class FileManagedPathCheckpointRepository:
    """在明确根目录内以不可复用 lease 和跨进程锁原子保存 checkpoint。"""

    def __init__(
        self,
        allowed_root: Path,
        *,
        writer_name: str,
        relative_path: Path = MANAGED_PATH_CHECKPOINT_RELATIVE_PATH,
    ) -> None:
        if not allowed_root.is_absolute():
            raise ManagedPathCheckpointError("allowed_root 必须是绝对路径")
        if relative_path != MANAGED_PATH_CHECKPOINT_RELATIVE_PATH:
            raise ManagedPathCheckpointError("checkpoint 必须使用固定相对路径")
        if not writer_name or not re.fullmatch(_WRITER_ID_PATTERN, writer_name):
            raise ManagedPathCheckpointError("writer name 格式无效")
        self.allowed_root = allowed_root
        self.writer_name = writer_name
        self.path = allowed_root / relative_path
        self._checkpoint_name = self.path.name
        self._owner_name = ".writer-owner.json"
        self._lock_name = ".writer-lock"
        self._lease_nonce = secrets.token_hex(32)
        self._owner_claim = {
            "schema_version": 1,
            "writer_name": writer_name,
            "lease_nonce": self._lease_nonce,
            "process_id": os.getpid(),
            "process_start_nonce": _PROCESS_START_NONCE,
        }
        self._closed = False
        self._root_directory: _TrustedDirectory | None = None
        self._directory: _TrustedDirectory | None = None
        try:
            self._prepare_root()
            self._ensure_lock_file()
            self._claim_writer()
        except BaseException:
            self._close_directory_handles()
            raise

    def _prepare_root(self) -> None:
        if self._is_reparse_path(self.allowed_root) or not self.allowed_root.is_dir():
            raise ManagedPathCheckpointError("allowed_root 必须是非符号链接目录")
        resolved_root = self.allowed_root.resolve(strict=True)
        if resolved_root != self.allowed_root:
            raise ManagedPathCheckpointError("allowed_root 不得包含路径别名或逃逸")
        self._root_directory = _TrustedDirectory(resolved_root)
        self._directory = self._root_directory.open_child_directory(self.path.parent.name)
        self._directory.exists(self._checkpoint_name)
        self._directory.exists(self._owner_name)

    @staticmethod
    def _is_reparse_stat(metadata: os.stat_result) -> bool:
        attributes = cast(int, getattr(metadata, "st_file_attributes", 0))
        return stat.S_ISLNK(metadata.st_mode) or bool(attributes & _REPARSE_POINT_ATTRIBUTE)

    @classmethod
    def _is_reparse_path(cls, path: Path) -> bool:
        try:
            return cls._is_reparse_stat(path.stat(follow_symlinks=False))
        except OSError:
            return False

    def _claim_writer(self) -> None:
        payload = json.dumps(self._owner_claim, separators=(",", ":")) + "\n"
        with self._writer_lock(validate_lease=False):
            try:
                descriptor = self._trusted.open_file(
                    self._owner_name,
                    create=True,
                    writable=True,
                    deletable=True,
                )
            except FileExistsError as exc:
                raise PermissionError("managed path checkpoint lifecycle lease 已被持有") from exc
            try:
                self._write_all(descriptor, payload.encode("utf-8"))
                self._trusted.sync_file(descriptor)
                self._trusted.sync_metadata(descriptor)
            except BaseException:
                os.close(descriptor)
                descriptor = -1
                with suppress(OSError, ManagedPathCheckpointError):
                    self._trusted.unlink(self._owner_name, missing_ok=True)
                raise
            finally:
                if descriptor >= 0:
                    os.close(descriptor)

    def load(self) -> ManagedPathCheckpoint | None:
        """兼容识别旧同步状态，但绝不从中推断 path selection。"""
        with self._writer_lock():
            try:
                self._on_io_boundary("before_checkpoint_read")
                self._trusted.require_public_identity()
                payload = self._read_json(self._checkpoint_name)
            except FileNotFoundError:
                return None
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
        try:
            validated = ManagedPathCheckpoint.model_validate(payload)
        except ValidationError as exc:
            raise ManagedPathCheckpointError("managed path checkpoint 校验失败") from exc
        encoded = (
            json.dumps(
                validated.model_dump(mode="json"),
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("utf-8")
        with self._writer_lock():
            temporary = f".{self._checkpoint_name}.{secrets.token_hex(16)}.tmp"
            descriptor = self._trusted.open_file(
                temporary,
                create=True,
                writable=True,
                deletable=True,
            )
            replaced = False
            try:
                self._write_all(descriptor, encoded)
                self._trusted.sync_file(descriptor)
                self._on_io_boundary("before_checkpoint_replace")
                self._trusted.require_public_identity()
                self._trusted.replace_open_file(
                    descriptor,
                    temporary,
                    self._checkpoint_name,
                )
                replaced = True
            finally:
                os.close(descriptor)
                if not replaced:
                    with suppress(OSError, ManagedPathCheckpointError):
                        self._trusted.unlink(temporary, missing_ok=True)

    def close(self) -> None:
        """显式释放当前 lease；崩溃遗留 claim 在阶段一保持 fail closed。"""
        if self._closed:
            return
        with self._writer_lock():
            self._trusted.unlink(self._owner_name)
            self._closed = True
        self._close_directory_handles()

    def assert_no_secret_material(self) -> None:
        """扫描 checkpoint 的 key/value，并重新执行严格 schema 校验。"""
        with self._writer_lock():
            try:
                self._on_io_boundary("before_secret_scan_read")
                self._trusted.require_public_identity()
                payload = self._read_json(self._checkpoint_name)
            except FileNotFoundError:
                return
            except (OSError, UnicodeError, json.JSONDecodeError) as exc:
                raise ManagedPathCheckpointError("managed path checkpoint 无法扫描") from exc
        self._reject_secret_material(payload)
        if not isinstance(payload, dict):
            raise ManagedPathCheckpointError("managed path checkpoint 结构无效")
        try:
            ManagedPathCheckpoint.model_validate(payload)
        except ValidationError as exc:
            raise ManagedPathCheckpointError("managed path checkpoint 校验失败") from exc

    def _validate_lease(self) -> None:
        try:
            self._on_io_boundary("before_lease_read")
            self._trusted.require_public_identity()
            owner = self._read_json(self._owner_name)
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise ManagedPathCheckpointError("writer owner claim 无法读取") from exc
        if owner != self._owner_claim:
            raise PermissionError("managed path checkpoint lifecycle lease 已变化")

    @contextmanager
    def _writer_lock(self, *, validate_lease: bool = True) -> Generator[None, None, None]:
        if self._closed:
            raise ManagedPathCheckpointError("managed path checkpoint lifecycle lease 已关闭")
        self._trusted.validate()
        self._on_io_boundary("before_writer_lock")
        self._trusted.require_public_identity()
        with self._trusted.lock(self._lock_name):
            self._trusted.validate()
            if validate_lease:
                self._validate_lease()
            yield

    def _ensure_lock_file(self) -> None:
        try:
            descriptor = self._trusted.open_file(
                self._lock_name,
                create=True,
                writable=True,
                deletable=False,
            )
        except FileExistsError:
            descriptor = self._trusted.open_file(self._lock_name, writable=True)
            os.close(descriptor)
            return
        try:
            self._write_all(descriptor, b"\0")
            self._trusted.sync_file(descriptor)
            self._trusted.sync_metadata(descriptor)
        finally:
            os.close(descriptor)

    @property
    def _trusted(self) -> _TrustedDirectory:
        if self._directory is None:
            raise ManagedPathCheckpointError("可信 checkpoint 目录尚未初始化")
        return self._directory

    @staticmethod
    def _write_all(descriptor: int, payload: bytes) -> None:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise ManagedPathCheckpointError("checkpoint 写入未取得进展")
            view = view[written:]

    def _read_json(self, name: str) -> object:
        return json.loads(self._trusted.read_bytes(name).decode("utf-8"))

    def _on_io_boundary(self, boundary: str) -> None:
        """确定性 race 注入边界；生产实现不执行回调。"""
        del boundary

    def _close_directory_handles(self) -> None:
        directory = getattr(self, "_directory", None)
        if directory is not None:
            with suppress(OSError, ManagedPathCheckpointError):
                directory.close()
            self._directory = None
        root_directory = getattr(self, "_root_directory", None)
        if root_directory is not None:
            with suppress(OSError, ManagedPathCheckpointError):
                root_directory.close()
            self._root_directory = None

    def __del__(self) -> None:
        self._close_directory_handles()

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

    async def publish(
        self,
        checkpoint: ManagedPathCheckpoint,
        *,
        idempotency_key: str,
    ) -> None: ...


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
            publication_id = canonical_sha256(
                {
                    "schema_version": MANAGED_PATH_CHECKPOINT_SCHEMA_VERSION,
                    "network_id": str(plan.desired.network_id),
                    "node_id": str(plan.desired.target_node_id),
                    "revision": plan.desired.revision,
                    "provider": plan.desired.provider,
                    "pending_plan_hash": plan.plan_hash,
                    "observed_fingerprint": plan.observed_fingerprint,
                    "authorization_state": match.state,
                    "authorization_id": match.authorization_id,
                    "stable_error_code": match.code,
                }
            )
            existing = self._checkpoints.load()
            delivery_states = (
                existing.sink_delivery_states
                if existing is not None and existing.publication_id == publication_id
                else ()
            )
            delivery_states = tuple(
                delivery_states[index]
                if index < len(delivery_states)
                else ManagedPathSinkDeliveryState.NOT_ATTEMPTED
                for index in range(len(self._sinks))
            )
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
                publication_id=publication_id,
                sink_delivery_states=delivery_states,
            )
            self._checkpoints.save(checkpoint)
            checkpoint, deliveries = await self._publish(
                checkpoint,
                publication_id=publication_id,
            )
            code = (
                ManagedPathOperationCode.PERSISTED_WITH_SINK_FAILURES
                if any(
                    delivery.state is ManagedPathSinkDeliveryState.FAILED for delivery in deliveries
                )
                else ManagedPathOperationCode.PERSISTED
            )
            return ManagedPathOperationResult(
                code=code,
                persisted=True,
                checkpoint=checkpoint,
                publication_id=publication_id,
                sink_deliveries=deliveries,
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
        if refreshed_at is None or expires_at is None:
            return ManagedPathOperationCode.REFRESH_REJECTED_TIME
        existing_refreshed_at = checkpoint.evidence.refreshed_at
        if (
            refreshed_at < checkpoint.updated_at
            or refreshed_at > now
            or expires_at <= now
            or expires_at - refreshed_at > MANAGED_PATH_MAX_EVIDENCE_TTL
            or (existing_refreshed_at is not None and refreshed_at <= existing_refreshed_at)
        ):
            return ManagedPathOperationCode.REFRESH_REJECTED_TIME
        return ManagedPathOperationCode.REFRESH_NOT_COMMITTED

    async def _publish(
        self,
        checkpoint: ManagedPathCheckpoint,
        *,
        publication_id: str,
    ) -> tuple[ManagedPathCheckpoint, tuple[ManagedPathSinkDelivery, ...]]:
        states = list(checkpoint.sink_delivery_states)
        for index, sink in enumerate(self._sinks):
            if states[index] in {
                ManagedPathSinkDeliveryState.SUCCEEDED,
                ManagedPathSinkDeliveryState.FAILED,
            }:
                continue
            try:
                await sink.publish(checkpoint, idempotency_key=publication_id)
            except asyncio.CancelledError:
                states[index] = ManagedPathSinkDeliveryState.UNKNOWN
                checkpoint = checkpoint.model_copy(update={"sink_delivery_states": tuple(states)})
                self._checkpoints.save(checkpoint)
                deliveries = self._deliveries(states)
                raise ManagedPathPublicationCancelled(
                    ManagedPathOperationResult(
                        code=ManagedPathOperationCode.PERSISTED_WITH_SINK_FAILURES,
                        persisted=True,
                        checkpoint=checkpoint,
                        publication_id=publication_id,
                        sink_deliveries=deliveries,
                    )
                ) from None
            except Exception:
                states[index] = ManagedPathSinkDeliveryState.FAILED
            else:
                states[index] = ManagedPathSinkDeliveryState.SUCCEEDED
            checkpoint = checkpoint.model_copy(update={"sink_delivery_states": tuple(states)})
            self._checkpoints.save(checkpoint)
        return checkpoint, self._deliveries(states)

    @staticmethod
    def _deliveries(
        states: list[ManagedPathSinkDeliveryState],
    ) -> tuple[ManagedPathSinkDelivery, ...]:
        return tuple(
            ManagedPathSinkDelivery(sink_index=index, state=state)
            for index, state in enumerate(states)
        )

    def read_status(self) -> ManagedPathCheckpoint | None:
        """只读状态投影；不接触授权 writer、refresher 或 Provider。"""
        return self._checkpoints.load()
