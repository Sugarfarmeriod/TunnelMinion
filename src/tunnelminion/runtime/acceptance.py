"""独立 A/B peer 验收结果与有界、无秘密 HTTP 探针。"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Iterable, Mapping
from enum import StrEnum
from time import perf_counter
from typing import cast
from urllib.parse import urlsplit, urlunsplit

import httpx
from pydantic import BaseModel, ConfigDict, Field, model_validator

ACCEPTANCE_PATH = "/v1/capabilities"
DEFAULT_PEER_TIMEOUT_SECONDS = 3.0
DEFAULT_MAX_RESPONSE_BYTES = 64 * 1024
MAX_PEER_TIMEOUT_SECONDS = 30.0
MAX_RESPONSE_BYTES = 1024 * 1024
_HEX_64 = "^[0-9a-f]{64}$"
_SENSITIVE_BODY_MARKERS = (
    "authorization:",
    "bearer ",
    "private key",
    "private_key",
    "-----begin",
    "tmn_",
)


class PackageEntrypointSummary(BaseModel):
    """只绑定运行包和入口摘要，不保存程序路径或命令正文。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    package_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{0,159}$")
    application_version: str = Field(min_length=1, max_length=80)
    platform: str = Field(min_length=1, max_length=32)
    architecture: str = Field(min_length=1, max_length=32)
    manifest_sha256: str = Field(pattern=_HEX_64)
    entrypoint_sha256: str = Field(pattern=_HEX_64)
    entrypoint_args_sha256: str = Field(pattern=_HEX_64)

    @classmethod
    def from_manifest(
        cls,
        manifest: Mapping[str, object],
        *,
        manifest_bytes: bytes | None = None,
    ) -> PackageEntrypointSummary:
        """从已验证或待验证的清单提取稳定摘要，不带出入口路径。"""
        return package_entrypoint_summary(manifest, manifest_bytes=manifest_bytes)


class PeerAcceptanceState(StrEnum):
    """A/B peer 的独立端到端分类。"""

    UNVERIFIED = "peer_unverified"
    REACHABLE = "peer_reachable"
    UNREACHABLE = "peer_unreachable"


class PeerAcceptanceResult(BaseModel):
    """不持久化到本地生命周期状态的脱敏 A/B 验收结果。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    status: PeerAcceptanceState
    accepted: bool
    package: PackageEntrypointSummary | None = None
    http_status: int | None = Field(default=None, ge=100, le=599)
    response_size_bytes: int | None = Field(default=None, ge=0)
    latency_ms: int = Field(ge=0)
    error_code: str | None = Field(default=None, min_length=1, max_length=80)
    endpoint_sha256: str | None = Field(default=None, pattern=_HEX_64)
    authorization_header_sent: bool = False
    response_body_discarded: bool = True

    @model_validator(mode="after")
    def validate_acceptance_evidence(self) -> PeerAcceptanceResult:
        """只有无 Authorization 的 401 才能成为 accepted 证据。"""
        if self.accepted and (
            self.status is not PeerAcceptanceState.REACHABLE
            or self.http_status != 401
            or self.authorization_header_sent
            or self.package is None
        ):
            raise ValueError("peer accepted 证据必须是无 Authorization 的 401")
        if self.status is PeerAcceptanceState.REACHABLE and self.http_status != 401:
            raise ValueError("peer_reachable 必须绑定 HTTP 401")
        if self.authorization_header_sent:
            raise ValueError("A/B 验收不得发送 Authorization header")
        return self


def is_production_candidate_accepted(
    local_running: bool,
    peer: PeerAcceptanceResult,
) -> bool:
    """只有本地 running 与独立无 token 401 同时成立才接受候选。"""
    return local_running and peer.accepted


def package_entrypoint_summary(
    manifest: Mapping[str, object],
    *,
    manifest_bytes: bytes | None = None,
) -> PackageEntrypointSummary:
    """提取 package/entrypoint 摘要，拒绝越界入口和不完整清单。"""
    candidate = _mapping(manifest.get("candidate"), "candidate")
    package_id = _text(candidate.get("id"), "candidate.id", maximum=160)
    application_version = _text(
        candidate.get("application_version"),
        "candidate.application_version",
        maximum=80,
    )
    platform = _text(candidate.get("platform"), "candidate.platform", maximum=32)
    architecture = _text(candidate.get("architecture"), "candidate.architecture", maximum=32)
    entrypoint = _text(manifest.get("entrypoint"), "entrypoint", maximum=512)
    _validate_relative_entrypoint(entrypoint)

    raw_files = manifest.get("files")
    if not isinstance(raw_files, list):
        raise ValueError("files 必须是数组")
    entrypoint_hash: str | None = None
    for raw_file in cast(list[object], raw_files):
        file_record = _mapping(raw_file, "files.item")
        path = _text(file_record.get("path"), "files.item.path", maximum=512)
        file_hash = _text(file_record.get("sha256"), "files.item.sha256", maximum=64)
        if not _is_hex_64(file_hash):
            raise ValueError("files.item.sha256 无效")
        if path == entrypoint:
            entrypoint_hash = file_hash
    if entrypoint_hash is None:
        raise ValueError("entrypoint 未被 files 覆盖")

    raw_args = manifest.get("entrypoint_args")
    if not isinstance(raw_args, list):
        raise ValueError("entrypoint_args 无效")
    entrypoint_args_values = cast(list[object], raw_args)
    if len(entrypoint_args_values) > 8:
        raise ValueError("entrypoint_args 无效")
    entrypoint_args: list[str] = []
    for raw_arg in entrypoint_args_values:
        entrypoint_args.append(_text(raw_arg, "entrypoint_args.item", maximum=160))
    manifest_hash = hashlib.sha256(
        manifest_bytes if manifest_bytes is not None else _canonical_json(manifest).encode("utf-8")
    ).hexdigest()
    args_hash = hashlib.sha256(_canonical_json(entrypoint_args).encode("utf-8")).hexdigest()
    return PackageEntrypointSummary(
        package_id=package_id,
        application_version=application_version,
        platform=platform,
        architecture=architecture,
        manifest_sha256=manifest_hash,
        entrypoint_sha256=entrypoint_hash,
        entrypoint_args_sha256=args_hash,
    )


class PeerAcceptanceProbe:
    """向批准 peer 发出无 token、有界 GET，不读写本地生命周期状态。"""

    def __init__(
        self,
        *,
        timeout_seconds: float = DEFAULT_PEER_TIMEOUT_SECONDS,
        max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
        transport: httpx.BaseTransport | None = None,
        monotonic: Callable[[], float] = perf_counter,
    ) -> None:
        if not 0 < timeout_seconds <= MAX_PEER_TIMEOUT_SECONDS:
            raise ValueError("peer timeout 必须在 0 到 30 秒之间")
        if not 1 <= max_response_bytes <= MAX_RESPONSE_BYTES:
            raise ValueError("peer response 上限无效")
        self._timeout_seconds = timeout_seconds
        self._max_response_bytes = max_response_bytes
        self._transport = transport
        self._monotonic = monotonic

    def probe(
        self,
        endpoint: str,
        package: PackageEntrypointSummary | None,
    ) -> PeerAcceptanceResult:
        """返回 peer 结果；任何网络/正文失败均不改变本地状态。"""
        started = self._monotonic()
        if package is None:
            return self._result(
                started,
                PeerAcceptanceState.UNVERIFIED,
                package=None,
                error_code="package_entrypoint_unverified",
            )
        try:
            target = _acceptance_url(endpoint)
        except ValueError:
            return self._result(
                started,
                PeerAcceptanceState.UNVERIFIED,
                package=package,
                error_code="peer_endpoint_invalid",
            )
        endpoint_hash = hashlib.sha256(target.encode("utf-8")).hexdigest()
        try:
            with (
                httpx.Client(
                    transport=self._transport,
                    trust_env=False,
                    follow_redirects=False,
                    timeout=self._timeout_seconds,
                ) as client,
                client.stream(
                    "GET",
                    target,
                    headers={"accept": "application/json"},
                ) as response,
            ):
                response_size, body_error = _consume_response(
                    response.iter_bytes(), self._max_response_bytes
                )
                if body_error is not None:
                    return self._result(
                        started,
                        PeerAcceptanceState.UNREACHABLE,
                        package=package,
                        http_status=response.status_code,
                        response_size_bytes=response_size,
                        error_code=body_error,
                        endpoint_sha256=endpoint_hash,
                    )
                if response.status_code == 401:
                    return self._result(
                        started,
                        PeerAcceptanceState.REACHABLE,
                        package=package,
                        http_status=401,
                        response_size_bytes=response_size,
                        endpoint_sha256=endpoint_hash,
                        accepted=True,
                    )
                return self._result(
                    started,
                    PeerAcceptanceState.UNREACHABLE,
                    package=package,
                    http_status=response.status_code,
                    response_size_bytes=response_size,
                    error_code="peer_http_unexpected_status",
                    endpoint_sha256=endpoint_hash,
                )
        except httpx.TimeoutException:
            return self._result(
                started,
                PeerAcceptanceState.UNREACHABLE,
                package=package,
                error_code="peer_timeout",
                endpoint_sha256=endpoint_hash,
            )
        except httpx.HTTPError:
            return self._result(
                started,
                PeerAcceptanceState.UNREACHABLE,
                package=package,
                error_code="peer_unreachable",
                endpoint_sha256=endpoint_hash,
            )
        except (OSError, RuntimeError):
            return self._result(
                started,
                PeerAcceptanceState.UNREACHABLE,
                package=package,
                error_code="peer_probe_failed",
                endpoint_sha256=endpoint_hash,
            )
        except Exception:
            # 第三方 transport/响应迭代器的异常正文不属于稳定验收输出。
            return self._result(
                started,
                PeerAcceptanceState.UNREACHABLE,
                package=package,
                error_code="peer_probe_failed",
                endpoint_sha256=endpoint_hash,
            )

    def _result(
        self,
        started: float,
        status: PeerAcceptanceState,
        *,
        package: PackageEntrypointSummary | None,
        http_status: int | None = None,
        response_size_bytes: int | None = None,
        error_code: str | None = None,
        endpoint_sha256: str | None = None,
        accepted: bool = False,
    ) -> PeerAcceptanceResult:
        return PeerAcceptanceResult(
            status=status,
            accepted=accepted,
            package=package,
            http_status=http_status,
            response_size_bytes=response_size_bytes,
            latency_ms=max(0, round((self._monotonic() - started) * 1000)),
            error_code=error_code,
            endpoint_sha256=endpoint_sha256,
        )


def _consume_response(
    chunks: Iterable[bytes],
    max_response_bytes: int,
) -> tuple[int, str | None]:
    """只计数并扫描极小尾部，绝不保存 peer 正文。"""
    size = 0
    tail = ""
    marker_length = max(len(marker) for marker in _SENSITIVE_BODY_MARKERS)
    for chunk in chunks:
        size += len(chunk)
        if size > max_response_bytes:
            return max_response_bytes + 1, "peer_response_too_large"
        window = tail + chunk.decode("utf-8", errors="replace").lower()
        if any(marker in window for marker in _SENSITIVE_BODY_MARKERS):
            return size, "peer_response_body_rejected"
        tail = window[-marker_length:]
    return size, None


def _acceptance_url(endpoint: str) -> str:
    """把无凭据的 host/port endpoint 固定到只读 capabilities 路径。"""
    if not endpoint or len(endpoint) > 512:
        raise ValueError("peer endpoint 无效")
    parsed = urlsplit(endpoint)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("peer endpoint scheme 无效")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("peer endpoint 不得携带凭据")
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise ValueError("peer endpoint 只能是 host/port")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("peer endpoint port 无效") from exc
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("peer endpoint port 无效")
    return urlunsplit((parsed.scheme, parsed.netloc, ACCEPTANCE_PATH, "", ""))


def _mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{label} 必须是对象")
    return cast(Mapping[str, object], value)


def _text(value: object, label: str, *, maximum: int) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise ValueError(f"{label} 无效")
    return value


def _is_hex_64(value: str) -> bool:
    return len(value) == 64 and all(char in "0123456789abcdef" for char in value)


def _validate_relative_entrypoint(value: str) -> None:
    if (
        value.startswith(("/", "\\"))
        or ":" in value
        or "\\" in value
        or any(part == ".." for part in value.split("/"))
    ):
        raise ValueError("entrypoint 路径无效")


def _canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
