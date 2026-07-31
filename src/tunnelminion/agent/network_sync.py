"""不依赖模型的受管网络配置拉取、验签、缓存与退避。"""

from __future__ import annotations

import asyncio
import json
import secrets
import sqlite3
from collections.abc import Callable, Mapping
from contextlib import closing
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Protocol, cast

import httpx
from pydantic import BaseModel, ConfigDict, Field, model_validator

from tunnelminion.agent.coordinator import CoordinatorClientConfig, CoordinatorClientError
from tunnelminion.coordinator.client_credentials import AgentRefreshCredentialStore
from tunnelminion.coordinator.contracts import RefreshAuthentication, VerificationKeyView
from tunnelminion.domain.identifiers import NetworkId, NodeId
from tunnelminion.network.contracts import (
    AcknowledgementStage,
    NetworkAcknowledgement,
    SignedDesiredConfig,
)
from tunnelminion.network.governance import NetworkPathStatus, redacted_path_status_payload
from tunnelminion.network.signing import (
    DesiredConfigVerificationError,
    verify_signed_desired_config,
)
from tunnelminion.tools.contracts import ToolCancellationToken


class ManagedNetworkSyncPhase(StrEnum):
    """单节点受管配置同步状态。"""

    IDLE = "idle"
    FETCHING = "fetching"
    PENDING = "pending"
    BACKOFF = "backoff"
    STALE = "stale"
    STOPPED = "stopped"


class ManagedNetworkSyncError(RuntimeError):
    """不回显凭据、签名或配置正文的稳定同步错误。"""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class ManagedNetworkSyncConfig(BaseModel):
    """单节点同步预算与固定签名指纹。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    network_id: NetworkId
    node_id: NodeId
    pinned_fingerprints: frozenset[str] = Field(min_length=1, max_length=8)
    request_timeout_seconds: float = Field(default=10, gt=0, le=60)
    sync_interval_seconds: float = Field(default=30, gt=0, le=3600)
    base_backoff_seconds: float = Field(default=1, gt=0, le=60)
    max_backoff_seconds: float = Field(default=60, gt=0, le=3600)
    max_configs: int = Field(default=32, ge=1, le=128)
    max_config_bytes: int = Field(default=262_144, ge=256, le=1_048_576)

    @model_validator(mode="after")
    def validate_backoff(self) -> ManagedNetworkSyncConfig:
        if self.max_backoff_seconds < self.base_backoff_seconds:
            raise ValueError("最大退避不得小于基础退避")
        if any(
            not value.startswith("sha256:") or len(value) != 71
            for value in self.pinned_fingerprints
        ):
            raise ValueError("Coordinator key 指纹格式无效")
        return self


class ManagedNetworkSyncCheckpoint(BaseModel):
    """SQLite 中不含凭据和私钥的同步恢复点。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    network_id: NetworkId
    node_id: NodeId
    phase: ManagedNetworkSyncPhase = ManagedNetworkSyncPhase.IDLE
    applied_revision: int = Field(default=0, ge=0)
    pending_config: SignedDesiredConfig | None = None
    last_known_good: SignedDesiredConfig | None = None
    consecutive_failures: int = Field(default=0, ge=0)
    next_backoff_seconds: float = Field(default=0, ge=0)
    last_error_code: str | None = Field(default=None, min_length=1, max_length=128)
    full_sync_count: int = Field(default=0, ge=0)
    updated_at: datetime

    @model_validator(mode="after")
    def validate_configs(self) -> ManagedNetworkSyncCheckpoint:
        for envelope in (self.pending_config, self.last_known_good):
            if envelope is not None and (
                envelope.config.network_id != self.network_id
                or envelope.config.target_node_id != self.node_id
            ):
                raise ValueError("同步配置必须属于 checkpoint network/node")
        if (
            self.last_known_good is not None
            and self.last_known_good.config.revision != self.applied_revision
        ):
            raise ValueError("last-known-good revision 必须等于 applied revision")
        if self.pending_config is not None and (
            self.pending_config.config.parent_revision != self.applied_revision
        ):
            raise ValueError("pending config 必须直接继承 applied revision")
        return self


class ManagedNetworkSyncStatus(BaseModel):
    """资源页可读取的脱敏同步状态。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    phase: ManagedNetworkSyncPhase
    applied_revision: int = Field(ge=0)
    pending_revision: int | None = Field(default=None, ge=1)
    last_success_at: datetime | None = None
    last_error_code: str | None = None
    consecutive_failures: int = Field(ge=0)
    next_backoff_seconds: float = Field(ge=0)
    control_plane_stale: bool = False
    full_sync_count: int = Field(ge=0)


class ManagedNetworkSyncTransport(Protocol):
    """已认证 Coordinator 网络配置传输边界。"""

    async def verification_keys(self) -> tuple[VerificationKeyView, ...]:
        """返回受固定指纹约束的验证公钥。"""
        ...  # pragma: no cover - Protocol 无运行时实现

    async def pull_desired_configs(
        self,
        authentication: RefreshAuthentication,
        *,
        after_revision: int,
        full_sync: bool,
    ) -> tuple[SignedDesiredConfig, ...]:
        """拉取增量或有界 full sync 配置。"""
        ...  # pragma: no cover - Protocol 无运行时实现

    async def acknowledge(
        self,
        authentication: RefreshAuthentication,
        acknowledgement: NetworkAcknowledgement,
    ) -> None:
        """发送逐节点配置阶段确认。"""
        ...  # pragma: no cover - Protocol 无运行时实现

    async def report_path_status(
        self,
        authentication: RefreshAuthentication,
        payload: dict[str, object],
    ) -> None:
        """发送固定字段的脱敏路径摘要。"""
        ...  # pragma: no cover - Protocol 无运行时实现


class HttpManagedNetworkSyncTransport:
    """使用 Coordinator Agent API 传输签名配置、确认和路径摘要。"""

    def __init__(
        self,
        config: CoordinatorClientConfig,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._config = config
        self._transport = transport

    async def verification_keys(self) -> tuple[VerificationKeyView, ...]:
        from tunnelminion.coordinator.contracts import VerificationKeySet

        return VerificationKeySet.model_validate(
            await self._request("GET", "/api/v1/agent/verification-keys")
        ).keys

    async def pull_desired_configs(
        self,
        authentication: RefreshAuthentication,
        *,
        after_revision: int,
        full_sync: bool,
    ) -> tuple[SignedDesiredConfig, ...]:
        value = await self._request(
            "POST",
            "/api/v1/agent/network/desired-configs/query",
            {
                "authentication": authentication.model_dump(mode="json"),
                "after_revision": after_revision,
                "full_sync": full_sync,
            },
        )
        if not isinstance(value, list):
            raise CoordinatorClientError("invalid_response", "Coordinator 响应格式无效")
        values = cast(list[object], value)
        return tuple(SignedDesiredConfig.model_validate(item) for item in values)

    async def acknowledge(
        self,
        authentication: RefreshAuthentication,
        acknowledgement: NetworkAcknowledgement,
    ) -> None:
        await self._request(
            "POST",
            "/api/v1/agent/network/acknowledgements",
            {
                "authentication": authentication.model_dump(mode="json"),
                "acknowledgement": acknowledgement.model_dump(mode="json"),
            },
        )

    async def report_path_status(
        self,
        authentication: RefreshAuthentication,
        payload: dict[str, object],
    ) -> None:
        await self._request(
            "POST",
            "/api/v1/agent/network/path-status",
            {
                "authentication": authentication.model_dump(mode="json"),
                "status": payload,
            },
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


class CredentialedNetworkAcknowledgementSink:
    """使用逐节点 refresh 凭据发送治理确认和路径摘要。"""

    def __init__(
        self,
        config: ManagedNetworkSyncConfig,
        transport: ManagedNetworkSyncTransport,
        credentials: AgentRefreshCredentialStore,
    ) -> None:
        self._config = config
        self._transport = transport
        self._credentials = credentials

    async def acknowledge(self, acknowledgement: NetworkAcknowledgement) -> None:
        if (
            acknowledgement.network_id != self._config.network_id
            or acknowledgement.node_id != self._config.node_id
        ):
            raise ValueError("acknowledgement 不属于本机同步范围")
        await self._transport.acknowledge(self._authentication(), acknowledgement)

    async def report_path_status(self, status: NetworkPathStatus) -> None:
        if status.network_id != self._config.network_id or status.node_id != self._config.node_id:
            raise ValueError("路径状态不属于本机同步范围")
        await self._transport.report_path_status(
            self._authentication(),
            redacted_path_status_payload(status),
        )

    def _authentication(self) -> RefreshAuthentication:
        refresh = self._credentials.load(self._config.network_id, self._config.node_id)
        if refresh is None:
            raise ManagedNetworkSyncError("unauthenticated", "本机没有 Coordinator refresh 凭据")
        return RefreshAuthentication(
            network_id=self._config.network_id,
            node_id=self._config.node_id,
            refresh_credential=refresh,
        )


class SQLiteManagedNetworkSyncStore:
    """以 network/node 为键持久化 pending 与 last-known-good。"""

    def __init__(self, path: Path) -> None:
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        with closing(self._connect()) as connection, connection:
            connection.execute(
                """CREATE TABLE IF NOT EXISTS managed_network_sync (
                    network_id TEXT NOT NULL,
                    node_id TEXT NOT NULL,
                    phase TEXT NOT NULL,
                    applied_revision INTEGER NOT NULL,
                    payload TEXT NOT NULL,
                    PRIMARY KEY(network_id, node_id)
                )"""
            )

    def load(
        self, network_id: NetworkId, node_id: NodeId, *, now: datetime
    ) -> ManagedNetworkSyncCheckpoint:
        with closing(self._connect()) as connection, connection:
            row = connection.execute(
                """SELECT payload FROM managed_network_sync
                WHERE network_id=? AND node_id=?""",
                (str(network_id), str(node_id)),
            ).fetchone()
        if row is None:
            return ManagedNetworkSyncCheckpoint(
                network_id=network_id,
                node_id=node_id,
                updated_at=now,
            )
        return ManagedNetworkSyncCheckpoint.model_validate_json(cast(str, row["payload"]))

    def save(self, checkpoint: ManagedNetworkSyncCheckpoint) -> None:
        with closing(self._connect()) as connection, connection:
            connection.execute(
                """INSERT INTO managed_network_sync(
                    network_id, node_id, phase, applied_revision, payload
                ) VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(network_id, node_id) DO UPDATE SET
                    phase=excluded.phase,
                    applied_revision=excluded.applied_revision,
                    payload=excluded.payload""",
                (
                    str(checkpoint.network_id),
                    str(checkpoint.node_id),
                    checkpoint.phase.value,
                    checkpoint.applied_revision,
                    checkpoint.model_dump_json(),
                ),
            )

    def assert_no_secret_material(self) -> None:
        with closing(self._connect()) as connection, connection:
            rows = connection.execute("SELECT payload FROM managed_network_sync").fetchall()
        forbidden = ("private_key", "preshared", "refresh_credential", "authorization")
        if any(
            fragment in cast(str, row["payload"]).lower() for row in rows for fragment in forbidden
        ):
            raise ValueError("网络同步 checkpoint 包含禁止秘密字段")

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=5)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=WAL")
        return connection


class ManagedNetworkSynchronizer:
    """单并发拉取下一签名修订并保存 pending，不直接调用 Provider。"""

    def __init__(
        self,
        config: ManagedNetworkSyncConfig,
        transport: ManagedNetworkSyncTransport,
        credentials: AgentRefreshCredentialStore,
        store: SQLiteManagedNetworkSyncStore,
        *,
        clock: Callable[[], datetime] | None = None,
        jitter: Callable[[], float] | None = None,
    ) -> None:
        self._config = config
        self._transport = transport
        self._credentials = credentials
        self._store = store
        self._clock = clock or (lambda: datetime.now(UTC))
        self._jitter = jitter or (lambda: 0.5 + secrets.randbelow(1001) / 1000)
        now = self._now()
        self._checkpoint = store.load(config.network_id, config.node_id, now=now)
        self._status = self._status_from_checkpoint()
        self._lock = asyncio.Lock()
        self._stop = asyncio.Event()

    @property
    def checkpoint(self) -> ManagedNetworkSyncCheckpoint:
        return self._checkpoint

    @property
    def config(self) -> ManagedNetworkSyncConfig:
        return self._config

    @property
    def status(self) -> ManagedNetworkSyncStatus:
        return self._status

    async def sync_once(
        self,
        *,
        cancellation: ToolCancellationToken | None = None,
    ) -> ManagedNetworkSyncStatus:
        """拉取并验签一个直接继承当前 applied revision 的配置。"""
        if self._lock.locked():
            raise ManagedNetworkSyncError("concurrency_limited", "受管网络同步已在运行")
        token = cancellation or ToolCancellationToken()
        async with self._lock:
            now = self._now()
            self._set_phase(ManagedNetworkSyncPhase.FETCHING, now)
            try:
                self._check_cancelled(token)
                authentication = self._authentication()
                async with asyncio.timeout(self._config.request_timeout_seconds):
                    keys = await self._transport.verification_keys()
                    configs = await self._transport.pull_desired_configs(
                        authentication,
                        after_revision=self._checkpoint.applied_revision,
                        full_sync=False,
                    )
                    self._check_cancelled(token)
                    selected, used_full_sync = await self._select_next(
                        authentication,
                        configs,
                    )
                    if selected is None:
                        self._mark_idle(now, used_full_sync=used_full_sync)
                        return self._status
                    self._validate_budget((selected,))
                    verify_signed_desired_config(
                        selected,
                        keys,
                        self._config.pinned_fingerprints,
                        network_id=self._config.network_id,
                        target_node_id=self._config.node_id,
                        parent_revision=self._checkpoint.applied_revision,
                        now=now,
                    )
                    self._check_cancelled(token)
                    checkpoint = self._checkpoint.model_copy(
                        update={
                            "phase": ManagedNetworkSyncPhase.PENDING,
                            "pending_config": selected,
                            "consecutive_failures": 0,
                            "next_backoff_seconds": 0,
                            "last_error_code": None,
                            "full_sync_count": self._checkpoint.full_sync_count
                            + int(used_full_sync),
                            "updated_at": now,
                        }
                    )
                    self._save(checkpoint)
                    await self._transport.acknowledge(
                        authentication,
                        NetworkAcknowledgement(
                            network_id=self._config.network_id,
                            node_id=self._config.node_id,
                            revision=selected.config.revision,
                            stage=AcknowledgementStage.PENDING,
                            acknowledged_at=now,
                        ),
                    )
                    self._status = self._status_from_checkpoint(last_success_at=now)
            except (
                CoordinatorClientError,
                ManagedNetworkSyncError,
                DesiredConfigVerificationError,
                TimeoutError,
            ) as exc:
                code = (
                    exc.code
                    if isinstance(exc, (CoordinatorClientError, ManagedNetworkSyncError))
                    else "invalid_signed_config"
                    if isinstance(exc, DesiredConfigVerificationError)
                    else "timeout"
                )
                self._mark_failure(code, now)
            return self._status

    def mark_verified(self, envelope: SignedDesiredConfig) -> ManagedNetworkSyncCheckpoint:
        """仅由 Provider 独立验证成功后的治理工作流提交 last-known-good。"""
        pending = self._checkpoint.pending_config
        if pending is None or pending != envelope:
            raise ManagedNetworkSyncError("pending_mismatch", "验证结果不属于当前 pending config")
        now = self._now()
        checkpoint = self._checkpoint.model_copy(
            update={
                "phase": ManagedNetworkSyncPhase.IDLE,
                "applied_revision": envelope.config.revision,
                "pending_config": None,
                "last_known_good": envelope,
                "consecutive_failures": 0,
                "next_backoff_seconds": 0,
                "last_error_code": None,
                "updated_at": now,
            }
        )
        self._save(checkpoint)
        self._status = self._status_from_checkpoint(last_success_at=now)
        return checkpoint

    async def run(
        self,
        *,
        cancellation: ToolCancellationToken | None = None,
    ) -> None:
        """按成功周期或失败退避运行，不阻塞本地数据面。"""
        self._stop.clear()
        while not self._stop.is_set():
            status = await self.sync_once(cancellation=cancellation)
            delay = (
                status.next_backoff_seconds
                if status.phase in {ManagedNetworkSyncPhase.BACKOFF, ManagedNetworkSyncPhase.STALE}
                else self._config.sync_interval_seconds
            )
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=delay)
            except TimeoutError:
                continue
        self._set_phase(ManagedNetworkSyncPhase.STOPPED, self._now())

    def stop(self) -> None:
        self._stop.set()

    async def _select_next(
        self,
        authentication: RefreshAuthentication,
        configs: tuple[SignedDesiredConfig, ...],
    ) -> tuple[SignedDesiredConfig | None, bool]:
        self._validate_budget(configs)
        ordered = tuple(sorted(configs, key=lambda item: item.config.revision))
        if not ordered:
            return None, False
        expected_parent = self._checkpoint.applied_revision
        matching = tuple(item for item in ordered if item.config.parent_revision == expected_parent)
        if matching:
            return matching[0], False
        full = await self._transport.pull_desired_configs(
            authentication,
            after_revision=0,
            full_sync=True,
        )
        self._validate_budget(full)
        full_ordered = tuple(sorted(full, key=lambda item: item.config.revision))
        recovered = tuple(
            item for item in full_ordered if item.config.parent_revision == expected_parent
        )
        if not recovered:
            raise ManagedNetworkSyncError(
                "full_sync_required",
                "full sync 中没有直接继承本地 applied revision 的配置",
            )
        return recovered[0], True

    def _authentication(self) -> RefreshAuthentication:
        refresh = self._credentials.load(self._config.network_id, self._config.node_id)
        if refresh is None:
            raise ManagedNetworkSyncError("unauthenticated", "本机没有 Coordinator refresh 凭据")
        return RefreshAuthentication(
            network_id=self._config.network_id,
            node_id=self._config.node_id,
            refresh_credential=refresh,
        )

    def _validate_budget(self, configs: tuple[SignedDesiredConfig, ...]) -> None:
        if len(configs) > self._config.max_configs:
            raise ManagedNetworkSyncError("config_too_large", "配置数量超过同步预算")
        encoded = json.dumps(
            [item.model_dump(mode="json") for item in configs],
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        if len(encoded) > self._config.max_config_bytes:
            raise ManagedNetworkSyncError("config_too_large", "配置字节数超过同步预算")

    @staticmethod
    def _check_cancelled(cancellation: ToolCancellationToken) -> None:
        if cancellation.cancelled:
            raise ManagedNetworkSyncError("cancelled", "同步在安全检查点取消")

    def _mark_idle(self, now: datetime, *, used_full_sync: bool) -> None:
        checkpoint = self._checkpoint.model_copy(
            update={
                "phase": ManagedNetworkSyncPhase.IDLE,
                "consecutive_failures": 0,
                "next_backoff_seconds": 0,
                "last_error_code": None,
                "full_sync_count": self._checkpoint.full_sync_count + int(used_full_sync),
                "updated_at": now,
            }
        )
        self._save(checkpoint)
        self._status = self._status_from_checkpoint(last_success_at=now)

    def _mark_failure(self, code: str, now: datetime) -> None:
        failures = self._checkpoint.consecutive_failures + 1
        delay = min(
            self._config.max_backoff_seconds,
            self._config.base_backoff_seconds * (2 ** (failures - 1)) * self._jitter(),
        )
        phase = (
            ManagedNetworkSyncPhase.STALE
            if self._checkpoint.last_known_good is not None
            else ManagedNetworkSyncPhase.BACKOFF
        )
        checkpoint = self._checkpoint.model_copy(
            update={
                "phase": phase,
                "consecutive_failures": failures,
                "next_backoff_seconds": delay,
                "last_error_code": code,
                "updated_at": now,
            }
        )
        self._save(checkpoint)
        self._status = self._status_from_checkpoint()

    def _set_phase(self, phase: ManagedNetworkSyncPhase, now: datetime) -> None:
        self._save(self._checkpoint.model_copy(update={"phase": phase, "updated_at": now}))
        self._status = self._status_from_checkpoint()

    def _save(self, checkpoint: ManagedNetworkSyncCheckpoint) -> None:
        self._checkpoint = checkpoint
        self._store.save(checkpoint)

    def _status_from_checkpoint(
        self, *, last_success_at: datetime | None = None
    ) -> ManagedNetworkSyncStatus:
        pending = self._checkpoint.pending_config
        return ManagedNetworkSyncStatus(
            phase=self._checkpoint.phase,
            applied_revision=self._checkpoint.applied_revision,
            pending_revision=pending.config.revision if pending is not None else None,
            last_success_at=last_success_at,
            last_error_code=self._checkpoint.last_error_code,
            consecutive_failures=self._checkpoint.consecutive_failures,
            next_backoff_seconds=self._checkpoint.next_backoff_seconds,
            control_plane_stale=self._checkpoint.phase is ManagedNetworkSyncPhase.STALE,
            full_sync_count=self._checkpoint.full_sync_count,
        )

    def _now(self) -> datetime:
        value = self._clock()
        if value.tzinfo is None:
            raise ValueError("受管网络同步时钟必须包含时区")
        return value.astimezone(UTC)
