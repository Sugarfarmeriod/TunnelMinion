"""Agent 的 Coordinator enrollment、元数据渲染、同步、缓存与安全降级。"""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
import secrets
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Protocol, cast
from urllib.parse import urlparse

import httpx
from pydantic import BaseModel, ConfigDict, Field, JsonValue, field_validator

from tunnelminion.coordinator.client_credentials import AgentRefreshCredentialStore
from tunnelminion.coordinator.contracts import (
    AccessAssertionRequest,
    AccessAssertionResponse,
    CapabilityAvailability,
    CapabilitySnapshot,
    CapabilitySummary,
    DirectoryNodeSummary,
    DirectoryPage,
    DirectoryQuery,
    HeartbeatRequest,
    HeartbeatResponse,
    NodeIdentity,
    NodeRegistrationRequest,
    NodeRegistrationResponse,
    RefreshAuthentication,
    ServiceSnapshot,
    ServiceSummary,
    SnapshotReceipt,
    VerificationKeySet,
)
from tunnelminion.domain.identifiers import NetworkId, NodeId, SnapshotId
from tunnelminion.domain.tools import Platform, ToolDefinition


class CoordinatorClientError(RuntimeError):
    """不回显认证材料或远端响应正文的稳定客户端错误。"""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class CoordinatorClientConfig(BaseModel):
    """不含 refresh 凭据的 Agent Coordinator 配置。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    endpoint: str
    network_id: NetworkId
    node_id: NodeId
    pinned_fingerprints: frozenset[str] = Field(min_length=1)
    request_timeout_seconds: float = Field(default=5, gt=0, le=30)
    sync_interval_seconds: float = Field(default=15, gt=0, le=300)
    base_backoff_seconds: float = Field(default=1, gt=0, le=30)
    max_backoff_seconds: float = Field(default=60, gt=0, le=600)
    max_capabilities: int = Field(default=256, ge=1, le=256)
    max_services: int = Field(default=1024, ge=1, le=1024)
    max_snapshot_bytes: int = Field(default=262_144, ge=1024, le=1_000_000)
    cache_ttl_seconds: int = Field(default=120, ge=1, le=3600)

    @field_validator("endpoint")
    @classmethod
    def validate_endpoint(cls, value: str) -> str:
        parsed = urlparse(value)
        if parsed.scheme not in {"http", "https"} or parsed.hostname is None:
            raise ValueError("Coordinator endpoint 必须是 HTTP(S) URL")
        address = ipaddress.ip_address(parsed.hostname)
        if (
            not address.is_private
            or address.is_loopback
            or address.is_unspecified
            or address.is_multicast
        ):
            raise ValueError("Coordinator endpoint 必须使用明确的 WireGuard 私网地址")
        return value.rstrip("/")

    @field_validator("pinned_fingerprints")
    @classmethod
    def validate_fingerprints(cls, value: frozenset[str]) -> frozenset[str]:
        if any(
            len(item) != 64 or any(character not in "0123456789abcdef" for character in item)
            for item in value
        ):
            raise ValueError("Coordinator 验证公钥指纹必须是 64 位小写 SHA-256")
        return value


class CoordinatorTransport(Protocol):
    """同步器依赖的可替换控制面传输。"""

    async def register(self, request: NodeRegistrationRequest) -> NodeRegistrationResponse: ...

    async def verification_keys(self) -> VerificationKeySet: ...

    async def heartbeat(
        self,
        authentication: RefreshAuthentication,
        request: HeartbeatRequest,
    ) -> HeartbeatResponse: ...

    async def replace_capabilities(
        self,
        authentication: RefreshAuthentication,
        snapshot: CapabilitySnapshot,
    ) -> SnapshotReceipt: ...

    async def replace_services(
        self,
        authentication: RefreshAuthentication,
        snapshot: ServiceSnapshot,
    ) -> SnapshotReceipt: ...

    async def query(
        self,
        authentication: RefreshAuthentication,
        query: DirectoryQuery,
    ) -> DirectoryPage: ...


class HttpCoordinatorTransport:
    """使用版本化 Agent API 的有界 HTTP 传输。"""

    def __init__(
        self,
        config: CoordinatorClientConfig,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._config = config
        self._transport = transport

    async def register(self, request: NodeRegistrationRequest) -> NodeRegistrationResponse:
        return NodeRegistrationResponse.model_validate(
            await self._request(
                "POST",
                "/api/v1/agent/registrations",
                request.model_dump(mode="json"),
            )
        )

    async def verification_keys(self) -> VerificationKeySet:
        return VerificationKeySet.model_validate(
            await self._request("GET", "/api/v1/agent/verification-keys")
        )

    async def issue_assertion(
        self,
        request: AccessAssertionRequest,
    ) -> AccessAssertionResponse:
        """为一次目标直连获取短期、指定 audience 的签名身份。"""
        return AccessAssertionResponse.model_validate(
            await self._request(
                "POST",
                "/api/v1/agent/assertions",
                request.model_dump(mode="json"),
            )
        )

    async def heartbeat(
        self,
        authentication: RefreshAuthentication,
        request: HeartbeatRequest,
    ) -> HeartbeatResponse:
        return HeartbeatResponse.model_validate(
            await self._request(
                "POST",
                "/api/v1/agent/heartbeat",
                {
                    "authentication": authentication.model_dump(mode="json"),
                    "heartbeat": request.model_dump(mode="json"),
                },
            )
        )

    async def replace_capabilities(
        self,
        authentication: RefreshAuthentication,
        snapshot: CapabilitySnapshot,
    ) -> SnapshotReceipt:
        return SnapshotReceipt.model_validate(
            await self._request(
                "PUT",
                "/api/v1/agent/snapshots/capabilities",
                {
                    "authentication": authentication.model_dump(mode="json"),
                    "snapshot": snapshot.model_dump(mode="json"),
                },
            )
        )

    async def replace_services(
        self,
        authentication: RefreshAuthentication,
        snapshot: ServiceSnapshot,
    ) -> SnapshotReceipt:
        return SnapshotReceipt.model_validate(
            await self._request(
                "PUT",
                "/api/v1/agent/snapshots/services",
                {
                    "authentication": authentication.model_dump(mode="json"),
                    "snapshot": snapshot.model_dump(mode="json"),
                },
            )
        )

    async def query(
        self,
        authentication: RefreshAuthentication,
        query: DirectoryQuery,
    ) -> DirectoryPage:
        return DirectoryPage.model_validate(
            await self._request(
                "POST",
                "/api/v1/agent/directory/query",
                {
                    "authentication": authentication.model_dump(mode="json"),
                    "query": query.model_dump(mode="json"),
                },
            )
        )

    async def _request(
        self,
        method: str,
        path: str,
        payload: Mapping[str, object] | None = None,
    ) -> object:
        try:
            async with httpx.AsyncClient(
                base_url=self._config.endpoint,
                timeout=self._config.request_timeout_seconds,
                transport=self._transport,
            ) as client:
                response = await client.request(method, path, json=payload)
        except httpx.TimeoutException as exc:
            raise CoordinatorClientError("timeout", "Coordinator 请求超时") from exc
        except httpx.RequestError as exc:
            raise CoordinatorClientError("offline", "Coordinator 不可达") from exc
        if not response.is_success:
            try:
                detail = cast(dict[str, object], response.json()).get("detail")
                code = (
                    cast(dict[str, object], detail).get("code")
                    if isinstance(detail, dict)
                    else None
                )
            except (ValueError, TypeError):
                code = None
            raise CoordinatorClientError(
                code if isinstance(code, str) else f"http_{response.status_code}",
                "Coordinator 拒绝请求",
            )
        try:
            return response.json()
        except ValueError as exc:
            raise CoordinatorClientError("invalid_response", "Coordinator 响应格式无效") from exc


class CoordinatorEnrollmentClient:
    """用一次性 token 注册稳定身份，并把 refresh 只写入秘密存储。"""

    def __init__(
        self,
        config: CoordinatorClientConfig,
        transport: CoordinatorTransport,
        credentials: AgentRefreshCredentialStore,
    ) -> None:
        self._config = config
        self._transport = transport
        self._credentials = credentials

    async def enroll(
        self,
        identity: NodeIdentity,
        *,
        device_identity_hash: str,
        enrollment_token: str,
    ) -> NodeRegistrationResponse:
        if (
            identity.network_id != self._config.network_id
            or identity.node_id != self._config.node_id
        ):
            raise CoordinatorClientError("forbidden", "enrollment 身份与本地配置不匹配")
        keys = await self._transport.verification_keys()
        if not any(key.fingerprint in self._config.pinned_fingerprints for key in keys.keys):
            raise CoordinatorClientError("fingerprint_mismatch", "Coordinator 公钥指纹未确认")
        idempotency_digest = hashlib.sha256(
            (identity.model_dump_json() + device_identity_hash + enrollment_token).encode()
        ).hexdigest()
        response = await self._transport.register(
            NodeRegistrationRequest(
                identity=identity,
                device_identity_hash=device_identity_hash,
                enrollment_token=enrollment_token,
                idempotency_key=f"regkey_{idempotency_digest}",
            )
        )
        self._credentials.save(response)
        return response


class SyncPhase(StrEnum):
    IDLE = "idle"
    SYNCING = "syncing"
    BACKOFF = "backoff"
    STOPPED = "stopped"


class CoordinatorSyncStatus(BaseModel):
    """资源面板可读取的脱敏同步状态。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    phase: SyncPhase = SyncPhase.IDLE
    last_success_at: datetime | None = None
    server_revision: int = Field(default=0, ge=0)
    last_error_code: str | None = None
    consecutive_failures: int = Field(default=0, ge=0)
    next_backoff_seconds: float = Field(default=0, ge=0)
    capability_count: int = Field(default=0, ge=0, le=256)
    service_count: int = Field(default=0, ge=0, le=1024)


class CoordinatorAuthorizationView(BaseModel):
    """Gateway 可读取但不可修改的 Coordinator 授权缓存。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    network_id: NetworkId
    generated_at: datetime
    expires_at: datetime
    nodes: tuple[DirectoryNodeSummary, ...] = Field(max_length=200)
    verification_keys: VerificationKeySet

    def is_fresh(self, now: datetime) -> bool:
        return now < self.expires_at


class CoordinatorCache:
    """进程内有界目录与验证 key 缓存；失败时保留但不会升级为实时证据。"""

    def __init__(self) -> None:
        self._view: CoordinatorAuthorizationView | None = None

    def replace(self, view: CoordinatorAuthorizationView) -> None:
        self._view = view

    def read(self) -> CoordinatorAuthorizationView | None:
        return self._view


class CoordinatorCheckpoint(BaseModel):
    """不含秘密的同步序号与服务器修订。"""

    model_config = ConfigDict(extra="forbid")

    capability_sequence: int = Field(default=0, ge=0)
    service_sequence: int = Field(default=0, ge=0)
    server_revision: int = Field(default=0, ge=0)
    pending_capability: CapabilitySnapshot | None = None
    pending_service: ServiceSnapshot | None = None


class CoordinatorCheckpointStore:
    """原子保存可重启恢复的非秘密同步 checkpoint。"""

    def __init__(self, path: Path) -> None:
        self._path = path

    def load(self) -> CoordinatorCheckpoint:
        if not self._path.exists():
            return CoordinatorCheckpoint()
        return CoordinatorCheckpoint.model_validate_json(self._path.read_text(encoding="utf-8"))

    def save(self, checkpoint: CoordinatorCheckpoint) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self._path.with_suffix(".tmp")
        temporary.write_text(checkpoint.model_dump_json(), encoding="utf-8")
        temporary.replace(self._path)


class AgentCoordinatorSynchronizer:
    """单并发、可停止且不阻塞本地数据面的 Coordinator 同步器。"""

    def __init__(
        self,
        config: CoordinatorClientConfig,
        transport: CoordinatorTransport,
        credentials: AgentRefreshCredentialStore,
        checkpoint_store: CoordinatorCheckpointStore,
        cache: CoordinatorCache,
        *,
        clock: Callable[[], datetime] | None = None,
        jitter: Callable[[], float] | None = None,
    ) -> None:
        self._config = config
        self._transport = transport
        self._credentials = credentials
        self._checkpoint_store = checkpoint_store
        self._checkpoint = checkpoint_store.load()
        self._cache = cache
        self._clock = clock or (lambda: datetime.now(UTC))
        self._jitter = jitter or (lambda: 0.5 + secrets.randbelow(1001) / 1000)
        self._status = CoordinatorSyncStatus(server_revision=self._checkpoint.server_revision)
        self._stop = asyncio.Event()
        self._lock = asyncio.Lock()

    @property
    def status(self) -> CoordinatorSyncStatus:
        return self._status

    async def sync_once(
        self,
        capabilities: Sequence[CapabilitySummary],
        services: Sequence[ServiceSummary],
    ) -> CoordinatorSyncStatus:
        if self._lock.locked():
            raise CoordinatorClientError("concurrency_limited", "同步轮次已在运行")
        async with self._lock:
            self._status = self._status.model_copy(update={"phase": SyncPhase.SYNCING})
            try:
                self._validate_budget(capabilities, services)
                authentication = self._authentication()
                now = self._now()
                async with asyncio.timeout(self._config.request_timeout_seconds):
                    heartbeat = await self._transport.heartbeat(
                        authentication,
                        HeartbeatRequest(
                            network_id=self._config.network_id,
                            node_id=self._config.node_id,
                            sent_at=now,
                            last_server_revision=self._checkpoint.server_revision,
                        ),
                    )
                    capability_snapshot = self._checkpoint.pending_capability
                    if capability_snapshot is None:
                        capability_snapshot = CapabilitySnapshot(
                            network_id=self._config.network_id,
                            node_id=self._config.node_id,
                            snapshot_id=SnapshotId.new(),
                            sequence=self._checkpoint.capability_sequence + 1,
                            idempotency_key=f"snapkey_{secrets.token_hex(32)}",
                            generated_at=now,
                            capabilities=tuple(capabilities),
                        )
                        self._checkpoint = self._checkpoint.model_copy(
                            update={"pending_capability": capability_snapshot}
                        )
                        self._checkpoint_store.save(self._checkpoint)
                    capability_receipt = await self._transport.replace_capabilities(
                        authentication,
                        capability_snapshot,
                    )
                    self._checkpoint = self._checkpoint.model_copy(
                        update={
                            "capability_sequence": capability_snapshot.sequence,
                            "server_revision": capability_receipt.server_revision,
                            "pending_capability": None,
                        }
                    )
                    self._checkpoint_store.save(self._checkpoint)
                    service_snapshot = self._checkpoint.pending_service
                    if service_snapshot is None:
                        service_snapshot = ServiceSnapshot(
                            network_id=self._config.network_id,
                            node_id=self._config.node_id,
                            snapshot_id=SnapshotId.new(),
                            sequence=self._checkpoint.service_sequence + 1,
                            idempotency_key=f"snapkey_{secrets.token_hex(32)}",
                            generated_at=now,
                            services=tuple(services),
                        )
                        self._checkpoint = self._checkpoint.model_copy(
                            update={"pending_service": service_snapshot}
                        )
                        self._checkpoint_store.save(self._checkpoint)
                    service_receipt = await self._transport.replace_services(
                        authentication,
                        service_snapshot,
                    )
                    self._checkpoint = self._checkpoint.model_copy(
                        update={
                            "service_sequence": service_snapshot.sequence,
                            "server_revision": service_receipt.server_revision,
                            "pending_service": None,
                        }
                    )
                    self._checkpoint_store.save(self._checkpoint)
                    page = await self._transport.query(
                        authentication,
                        DirectoryQuery(
                            network_id=self._config.network_id,
                            after_revision=self._checkpoint.server_revision,
                        ),
                    )
                    if page.full_sync_required:
                        page = await self._transport.query(
                            authentication,
                            DirectoryQuery(network_id=self._config.network_id),
                        )
                    keys = await self._transport.verification_keys()
                revision = max(
                    heartbeat.server_revision,
                    capability_receipt.server_revision,
                    service_receipt.server_revision,
                    page.server_revision,
                )
                self._checkpoint = CoordinatorCheckpoint(
                    capability_sequence=self._checkpoint.capability_sequence,
                    service_sequence=self._checkpoint.service_sequence,
                    server_revision=revision,
                )
                self._checkpoint_store.save(self._checkpoint)
                self._cache.replace(
                    CoordinatorAuthorizationView(
                        network_id=self._config.network_id,
                        generated_at=now,
                        expires_at=now + timedelta(seconds=self._config.cache_ttl_seconds),
                        nodes=page.nodes,
                        verification_keys=keys,
                    )
                )
                self._status = CoordinatorSyncStatus(
                    phase=SyncPhase.IDLE,
                    last_success_at=now,
                    server_revision=revision,
                    capability_count=len(capabilities),
                    service_count=len(services),
                )
            except (CoordinatorClientError, TimeoutError) as exc:
                code = exc.code if isinstance(exc, CoordinatorClientError) else "timeout"
                failures = self._status.consecutive_failures + 1
                delay = min(
                    self._config.max_backoff_seconds,
                    self._config.base_backoff_seconds * (2 ** (failures - 1)) * self._jitter(),
                )
                self._status = self._status.model_copy(
                    update={
                        "phase": SyncPhase.BACKOFF,
                        "last_error_code": code,
                        "consecutive_failures": failures,
                        "next_backoff_seconds": delay,
                    }
                )
            return self._status

    async def run(
        self,
        capability_provider: Callable[[], Sequence[CapabilitySummary]],
        service_provider: Callable[[], Sequence[ServiceSummary]],
    ) -> None:
        self._stop.clear()
        while not self._stop.is_set():
            status = await self.sync_once(capability_provider(), service_provider())
            delay = (
                status.next_backoff_seconds
                if status.phase is SyncPhase.BACKOFF
                else self._config.sync_interval_seconds
            )
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=delay)
            except TimeoutError:
                continue
        self._status = self._status.model_copy(update={"phase": SyncPhase.STOPPED})

    def stop(self) -> None:
        self._stop.set()

    def _authentication(self) -> RefreshAuthentication:
        refresh = self._credentials.load(
            self._config.network_id,
            self._config.node_id,
        )
        if refresh is None:
            raise CoordinatorClientError("unauthenticated", "本机没有 Coordinator refresh 凭据")
        return RefreshAuthentication(
            network_id=self._config.network_id,
            node_id=self._config.node_id,
            refresh_credential=refresh,
        )

    def _validate_budget(
        self,
        capabilities: Sequence[CapabilitySummary],
        services: Sequence[ServiceSummary],
    ) -> None:
        if (
            len(capabilities) > self._config.max_capabilities
            or len(services) > self._config.max_services
        ):
            raise CoordinatorClientError("snapshot_too_large", "完整快照数量超过预算")
        encoded = json.dumps(
            {
                "capabilities": [capability.model_dump(mode="json") for capability in capabilities],
                "services": [service.model_dump(mode="json") for service in services],
            },
            separators=(",", ":"),
        ).encode()
        if len(encoded) > self._config.max_snapshot_bytes:
            raise CoordinatorClientError("snapshot_too_large", "完整快照字节数超过预算")

    def _now(self) -> datetime:
        value = self._clock()
        if value.tzinfo is None:
            raise ValueError("Agent Coordinator 时钟必须包含时区")
        return value.astimezone(UTC)


def render_capabilities(
    definitions: Sequence[ToolDefinition],
    platform: Platform,
) -> tuple[CapabilitySummary, ...]:
    """只渲染允许进入目录的工具摘要，并从 schema hash 排除示例与默认正文。"""
    summaries: list[CapabilitySummary] = []
    for definition in definitions:
        if platform not in definition.platforms:
            continue
        structural_schema = _strip_schema_content(
            {
                "input": definition.input_schema,
                "output": definition.output_schema,
            }
        )
        schema_hash = hashlib.sha256(
            json.dumps(structural_schema, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        summaries.append(
            CapabilitySummary(
                name=definition.name,
                version=definition.version,
                platform=platform,
                risk_level=definition.risk_level,
                availability=CapabilityAvailability.AVAILABLE,
                schema_hash=schema_hash,
            )
        )
    return tuple(summaries)


def render_service_observations(
    observations: Sequence[Mapping[str, JsonValue]],
) -> tuple[ServiceSummary, ...]:
    """从任意本地观察只挑选协议允许字段，忽略环境、命令行和正文。"""
    allowed = {
        "service_id",
        "protocol",
        "host",
        "port",
        "accessibility",
        "source",
        "confidence",
        "observed_at",
        "lifecycle",
    }
    return tuple(
        ServiceSummary.model_validate(
            {key: value for key, value in observation.items() if key in allowed}
        )
        for observation in observations
    )


def _strip_schema_content(value: JsonValue) -> JsonValue:
    if isinstance(value, dict):
        excluded = {"example", "examples", "default", "description", "title", "const"}
        return {
            key: _strip_schema_content(item) for key, item in value.items() if key not in excluded
        }
    if isinstance(value, list):
        return [_strip_schema_content(item) for item in value]
    return value
