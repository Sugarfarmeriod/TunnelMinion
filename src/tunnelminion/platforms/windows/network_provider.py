"""Windows 受管 WireGuard Provider 的计划、回执、验证、回滚与恢复。"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import secrets
import sqlite3
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol, cast

from pydantic import BaseModel, ConfigDict, Field

from tunnelminion.domain.identifiers import ResourceId
from tunnelminion.network.contracts import (
    DesiredNetworkConfig,
    ManagedResourceOwnership,
    NetworkAction,
    NetworkError,
    NetworkErrorCode,
    NetworkObservation,
    NetworkPlan,
    NetworkPlanStep,
    OwnershipState,
    PlanStepKind,
    ProviderKind,
    ProviderMode,
    ProviderReceipt,
    ReceiptStatus,
    StepReceipt,
    VerificationResult,
    canonical_sha256,
    compute_plan_hash,
)
from tunnelminion.network.ledger import (
    ManagedResourceLedgerEntry,
    SQLiteManagedResourceLedger,
)
from tunnelminion.platforms.windows.managed_system import (
    WindowsProviderPreflight,
    WindowsTunnelSnapshot,
)
from tunnelminion.tools.contracts import ToolCancellationToken

_MANAGED_PREFIX = "tmn-"
_FORBIDDEN_SECRET_FRAGMENTS = (
    '"private_key"',
    '"preshared_key"',
    "-----begin private key-----",
)


class WindowsBackendError(RuntimeError):
    """固定 Windows 后端返回的稳定、无秘密错误。"""

    def __init__(
        self,
        code: NetworkErrorCode,
        message: str,
        *,
        retryable: bool = False,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.retryable = retryable


class WindowsManagedBackend(Protocol):
    """平台命令和秘密材料的最小固定边界。"""

    def preflight(self) -> WindowsProviderPreflight: ...  # pragma: no cover - Protocol 无运行时实现

    async def observe(
        self, interface_name: str
    ) -> WindowsTunnelSnapshot: ...  # pragma: no cover - Protocol 无运行时实现

    def ensure_secret(
        self,
        desired: DesiredNetworkConfig,
    ) -> tuple[str, str]:
        """返回秘密引用和公钥哈希，不返回私钥正文。"""
        ...  # pragma: no cover - Protocol 无运行时实现

    async def validate_no_conflicts(self, desired: DesiredNetworkConfig) -> None:
        """扫描其他接口地址和路由；只以稳定错误暴露冲突。"""
        ...  # pragma: no cover - Protocol 无运行时实现

    async def execute_step(
        self,
        plan: NetworkPlan,
        step: NetworkPlanStep,
        *,
        secret_reference: str,
        creation_nonce: str,
        idempotency_key: str,
    ) -> str:
        """执行固定步骤并返回系统回执哈希。"""
        ...  # pragma: no cover - Protocol 无运行时实现

    async def rollback_step(
        self,
        plan: NetworkPlan,
        step: NetworkPlanStep,
        *,
        secret_reference: str,
        creation_nonce: str,
        idempotency_key: str,
    ) -> str:
        """执行固定反向步骤并返回系统回执哈希。"""
        ...  # pragma: no cover - Protocol 无运行时实现


class WindowsOperationJournal(BaseModel):
    """崩溃恢复使用的逐步回执，不保存秘密正文。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    plan: NetworkPlan
    idempotency_key: str = Field(pattern=r"^netop_[0-9a-f]{64}$")
    secret_reference: str = Field(min_length=3, max_length=224, repr=False)
    creation_nonce: str = Field(pattern=r"^[0-9a-f]{32}$")
    steps: tuple[StepReceipt, ...] = ()
    status: ReceiptStatus | None = None
    updated_at: datetime


class SQLiteWindowsOperationJournal:
    """按幂等键持久化 Windows 非原子步骤进度。"""

    def __init__(self, path: Path) -> None:
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS windows_network_operations (
                    idempotency_key TEXT PRIMARY KEY,
                    plan_hash TEXT NOT NULL,
                    revision INTEGER NOT NULL,
                    status TEXT,
                    payload TEXT NOT NULL
                )
                """
            )

    def put(self, journal: WindowsOperationJournal) -> None:
        payload = journal.model_dump_json()
        self._reject_secrets(payload)
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO windows_network_operations(
                    idempotency_key, plan_hash, revision, status, payload
                ) VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(idempotency_key) DO UPDATE SET
                    plan_hash=excluded.plan_hash,
                    revision=excluded.revision,
                    status=excluded.status,
                    payload=excluded.payload
                """,
                (
                    journal.idempotency_key,
                    journal.plan.plan_hash,
                    journal.plan.desired.revision,
                    journal.status.value if journal.status is not None else None,
                    payload,
                ),
            )

    def get(self, idempotency_key: str) -> WindowsOperationJournal | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT payload FROM windows_network_operations WHERE idempotency_key=?",
                (idempotency_key,),
            ).fetchone()
        if row is None:
            return None
        payload = cast(str, row["payload"])
        self._reject_secrets(payload)
        return WindowsOperationJournal.model_validate_json(payload)

    def list_recoverable(self) -> tuple[WindowsOperationJournal, ...]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT payload FROM windows_network_operations
                WHERE status IS NULL OR status IN ('applied', 'failed', 'cancelled')
                ORDER BY revision, idempotency_key
                """
            ).fetchall()
        return tuple(
            WindowsOperationJournal.model_validate_json(cast(str, row["payload"])) for row in rows
        )

    def find_by_plan_hash(self, plan_hash: str) -> WindowsOperationJournal | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT payload FROM windows_network_operations
                WHERE plan_hash=?
                ORDER BY revision DESC LIMIT 1
                """,
                (plan_hash,),
            ).fetchone()
        if row is None:
            return None
        return WindowsOperationJournal.model_validate_json(cast(str, row["payload"]))

    def assert_no_secret_material(self) -> None:
        with self._connect() as connection:
            rows = connection.execute("SELECT payload FROM windows_network_operations").fetchall()
        for row in rows:
            self._reject_secrets(cast(str, row["payload"]))

    @staticmethod
    def _reject_secrets(payload: str) -> None:
        lowered = payload.lower()
        if any(fragment in lowered for fragment in _FORBIDDEN_SECRET_FRAGMENTS):
            raise ValueError("Windows 操作日志包含禁止秘密字段")
        parsed = json.loads(payload)
        if not isinstance(parsed, dict) or "secret_reference" not in parsed:
            raise ValueError("Windows 操作日志结构无效")

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=5)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=WAL")
        return connection


class WindowsNetworkProvider:
    """只管理本地账本可证明自有的独立 `tmn-` 接口。"""

    def __init__(
        self,
        backend: WindowsManagedBackend,
        ledger: SQLiteManagedResourceLedger,
        journals: SQLiteWindowsOperationJournal,
        *,
        clock: Callable[[], datetime] | None = None,
        provider_kind: ProviderKind = ProviderKind.WINDOWS,
        protected_interfaces: frozenset[str] = frozenset({"HomeMac"}),
        platform_label: str = "Windows",
    ) -> None:
        self._backend = backend
        self._ledger = ledger
        self._journals = journals
        self._clock = clock or (lambda: datetime.now(UTC))
        self._lock = asyncio.Lock()
        self._provider_kind = provider_kind
        self._protected_interfaces = protected_interfaces
        self._platform_label = platform_label

    async def observe(self, interface_name: str) -> NetworkObservation:
        snapshot = await self._backend.observe(interface_name)
        entry = self._ledger_entry_for_interface(interface_name)
        ownership = self._classify_ownership(snapshot, entry)
        preflight = self._backend.preflight()
        return NetworkObservation(
            provider=self._provider_kind,
            mode=preflight.mode,
            interface_name=interface_name,
            stable_interface_id=snapshot.stable_interface_id,
            addresses=snapshot.addresses,
            host_routes=snapshot.host_routes,
            public_key_hash=snapshot.public_key_hash,
            ownership=ownership,
            system_fingerprint=snapshot.system_fingerprint,
            observed_at=self._now(),
        )

    async def plan(
        self,
        *,
        action: NetworkAction,
        desired: DesiredNetworkConfig,
        observed: NetworkObservation,
        ownership: ManagedResourceOwnership | None,
    ) -> NetworkPlan:
        if desired.provider is not self._provider_kind:
            raise ValueError(
                f"{self._platform_label.lower()} Provider 不接受其他平台 desired config"
            )
        if (
            desired.interface_name in self._protected_interfaces
            or not desired.interface_name.startswith(_MANAGED_PREFIX)
        ):
            raise ValueError(f"{self._platform_label} Provider 不管理用户接口或非受管前缀")
        if desired.interface_name != observed.interface_name:
            raise ValueError("desired config 与实时接口名称不一致")
        if action is NetworkAction.CREATE:
            if observed.ownership is not OwnershipState.ABSENT or ownership is not None:
                raise ValueError("创建只允许实时不存在且无账本的独立接口")
            await self._backend.validate_no_conflicts(desired)
            self._validate_no_conflicts(desired, observed)
        else:
            self._require_owned(observed, ownership)
        steps = self._steps(action, desired.interface_name)
        return NetworkPlan(
            action=action,
            desired=desired,
            observed_fingerprint=observed.system_fingerprint,
            ownership=ownership,
            steps=steps,
            plan_hash=compute_plan_hash(
                action=action,
                desired=desired,
                observed_fingerprint=observed.system_fingerprint,
                ownership=ownership,
                steps=steps,
            ),
        )

    async def apply(
        self,
        plan: NetworkPlan,
        *,
        idempotency_key: str,
        cancellation: ToolCancellationToken,
    ) -> ProviderReceipt:
        if self._lock.locked():
            return self._error_receipt(
                plan,
                idempotency_key,
                ReceiptStatus.FAILED,
                NetworkErrorCode.APPLY_FAILED,
                "Windows Provider 已有受管操作在运行",
                retryable=True,
            )
        async with self._lock:
            existing = self._journals.get(idempotency_key)
            if existing is not None:
                if existing.plan.plan_hash != plan.plan_hash:
                    return self._error_receipt(
                        plan,
                        idempotency_key,
                        ReceiptStatus.FAILED,
                        NetworkErrorCode.INVALID_CONFIG,
                        "幂等键已绑定另一计划",
                    )
                if existing.status is ReceiptStatus.APPLIED:
                    return await self._receipt_from_journal(existing)
            preflight = self._backend.preflight()
            if preflight.mode is not ProviderMode.MANAGED:
                return self._error_receipt(
                    plan,
                    idempotency_key,
                    ReceiptStatus.FAILED,
                    NetworkErrorCode.PERMISSION_DENIED
                    if preflight.error_code == "permission_denied"
                    else NetworkErrorCode.PROVIDER_UNAVAILABLE,
                    "Windows managed 前置条件不满足",
                )
            live = await self.observe(plan.desired.interface_name)
            if existing is None:
                if live.system_fingerprint != plan.observed_fingerprint:
                    return self._error_receipt(
                        plan,
                        idempotency_key,
                        ReceiptStatus.FAILED,
                        NetworkErrorCode.OWNERSHIP_CONFLICT,
                        "执行前实时系统指纹已变化",
                    )
                ledger_entry = self._ledger.get(
                    plan.desired.network_id,
                    plan.desired.target_node_id,
                )
                secret_reference = (
                    ledger_entry.secret_reference
                    if ledger_entry is not None
                    else self._backend.ensure_secret(plan.desired)[0]
                )
                journal = WindowsOperationJournal(
                    plan=plan,
                    idempotency_key=idempotency_key,
                    secret_reference=secret_reference,
                    creation_nonce=plan.ownership.creation_nonce
                    if plan.ownership is not None
                    else secrets.token_hex(16),
                    updated_at=self._now(),
                )
            else:
                journal = existing
            self._journals.put(journal)
            for step in plan.steps[len(journal.steps) :]:
                if cancellation.cancelled:
                    cancelled = journal.model_copy(
                        update={"status": ReceiptStatus.CANCELLED, "updated_at": self._now()}
                    )
                    self._journals.put(cancelled)
                    return self._receipt(
                        cancelled,
                        ReceiptStatus.CANCELLED,
                        NetworkErrorCode.CANCELLED,
                        "Windows 操作在安全点取消",
                    )
                try:
                    receipt_hash = await self._backend.execute_step(
                        plan,
                        step,
                        secret_reference=journal.secret_reference,
                        creation_nonce=journal.creation_nonce,
                        idempotency_key=idempotency_key,
                    )
                except WindowsBackendError as exc:
                    failed = journal.model_copy(
                        update={"status": ReceiptStatus.FAILED, "updated_at": self._now()}
                    )
                    self._journals.put(failed)
                    return self._receipt(
                        failed,
                        ReceiptStatus.FAILED,
                        exc.code,
                        str(exc),
                        retryable=exc.retryable,
                    )
                step_receipt = StepReceipt(
                    index=len(journal.steps),
                    kind=step.kind,
                    succeeded=True,
                    system_receipt_hash=receipt_hash,
                )
                journal = journal.model_copy(
                    update={
                        "steps": (*journal.steps, step_receipt),
                        "updated_at": self._now(),
                    }
                )
                self._journals.put(journal)
            await self._commit_ledger(plan, journal)
            applied = journal.model_copy(
                update={"status": ReceiptStatus.APPLIED, "updated_at": self._now()}
            )
            self._journals.put(applied)
            return await self._receipt_from_journal(applied)

    async def verify(self, plan: NetworkPlan) -> VerificationResult:
        observed = await self.observe(plan.desired.interface_name)
        expected_routes = tuple(
            route for peer in plan.desired.peers for route in peer.allowed_host_routes
        )
        if plan.action in {NetworkAction.STOP, NetworkAction.REMOVE}:
            succeeded = observed.ownership is OwnershipState.ABSENT
        else:
            succeeded = (
                observed.ownership is OwnershipState.MANAGED_OWNED
                and plan.desired.address in observed.addresses
                and set(expected_routes) <= set(observed.host_routes)
            )
        result = VerificationResult(
            plan_hash=plan.plan_hash,
            revision=plan.desired.revision,
            succeeded=succeeded,
            checked_dimensions=(
                "service",
                "adapter",
                "address",
                "peer",
                "host_route",
                "ownership",
            ),
            observation=observed,
            error=None
            if succeeded
            else NetworkError(
                code=NetworkErrorCode.VERIFY_FAILED,
                message="Windows 实时状态未达到计划期望",
                correlation_id=plan.plan_hash,
            ),
        )
        if succeeded:
            journal = self._journals.find_by_plan_hash(plan.plan_hash)
            if journal is not None:
                self._journals.put(
                    journal.model_copy(
                        update={"status": ReceiptStatus.VERIFIED, "updated_at": self._now()}
                    )
                )
        return result

    async def rollback(
        self,
        plan: NetworkPlan,
        receipt: ProviderReceipt,
        *,
        cancellation: ToolCancellationToken,
    ) -> ProviderReceipt:
        journal = self._journals.get(receipt.idempotency_key)
        if journal is None:
            return self._error_receipt(
                plan,
                receipt.idempotency_key,
                ReceiptStatus.MANUAL_INTERVENTION,
                NetworkErrorCode.RECOVERY_REQUIRED,
                "找不到 Windows 逐步恢复日志",
            )
        snapshot = await self._backend.observe(plan.desired.interface_name)
        entry = self._ledger.get(plan.desired.network_id, plan.desired.target_node_id)
        if not self._rollback_ownership_matches(snapshot, entry, journal):
            manual = journal.model_copy(
                update={"status": ReceiptStatus.MANUAL_INTERVENTION, "updated_at": self._now()}
            )
            self._journals.put(manual)
            return self._receipt(
                manual,
                ReceiptStatus.MANUAL_INTERVENTION,
                NetworkErrorCode.OWNERSHIP_CONFLICT,
                "实时资源无法与账本或创建 nonce 双重匹配",
            )
        rollback_receipts: list[StepReceipt] = []
        for original in reversed(journal.steps):
            if cancellation.cancelled:
                return self._receipt(
                    journal,
                    ReceiptStatus.CANCELLED,
                    NetworkErrorCode.CANCELLED,
                    "Windows 回滚在安全点取消",
                )
            step = plan.steps[original.index]
            try:
                receipt_hash = await self._backend.rollback_step(
                    plan,
                    step,
                    secret_reference=journal.secret_reference,
                    creation_nonce=journal.creation_nonce,
                    idempotency_key=journal.idempotency_key,
                )
            except WindowsBackendError as exc:
                failed = journal.model_copy(
                    update={
                        "status": ReceiptStatus.MANUAL_INTERVENTION,
                        "updated_at": self._now(),
                    }
                )
                self._journals.put(failed)
                return self._receipt(
                    failed,
                    ReceiptStatus.MANUAL_INTERVENTION,
                    NetworkErrorCode.ROLLBACK_FAILED,
                    str(exc),
                )
            rollback_receipts.append(
                StepReceipt(
                    index=len(rollback_receipts),
                    kind=step.rollback_kind or step.kind,
                    succeeded=True,
                    system_receipt_hash=receipt_hash,
                )
            )
        if entry is not None and plan.action is NetworkAction.CREATE:
            self._ledger.delete(
                entry.ownership.network_id,
                entry.ownership.node_id,
                expected_system_fingerprint=entry.ownership.system_fingerprint,
            )
        rolled = journal.model_copy(
            update={"status": ReceiptStatus.ROLLED_BACK, "updated_at": self._now()}
        )
        self._journals.put(rolled)
        observation = await self.observe(plan.desired.interface_name)
        return ProviderReceipt(
            idempotency_key=journal.idempotency_key,
            plan_hash=plan.plan_hash,
            revision=plan.desired.revision,
            status=ReceiptStatus.ROLLED_BACK,
            steps=tuple(rollback_receipts),
            observation_after=observation,
        )

    async def recover(
        self,
        *,
        cancellation: ToolCancellationToken,
    ) -> tuple[ProviderReceipt, ...]:
        recovered: list[ProviderReceipt] = []
        for journal in self._journals.list_recoverable():
            receipt = self._receipt(
                journal,
                journal.status or ReceiptStatus.FAILED,
                NetworkErrorCode.RECOVERY_REQUIRED,
                "Windows 非原子操作需要恢复",
            )
            recovered.append(
                await self.rollback(
                    journal.plan,
                    receipt,
                    cancellation=cancellation,
                )
            )
        return tuple(recovered)

    async def _commit_ledger(
        self,
        plan: NetworkPlan,
        journal: WindowsOperationJournal,
    ) -> None:
        desired = plan.desired
        if plan.action is NetworkAction.REMOVE:
            entry = self._ledger.get(desired.network_id, desired.target_node_id)
            if entry is not None:
                self._ledger.delete(
                    desired.network_id,
                    desired.target_node_id,
                    expected_system_fingerprint=entry.ownership.system_fingerprint,
                )
            return
        if plan.action is NetworkAction.STOP:
            return
        snapshot = await self._backend.observe(desired.interface_name)
        if (
            not snapshot.interface_present
            or snapshot.stable_interface_id is None
            or snapshot.public_key_hash is None
            or snapshot.creation_nonce != journal.creation_nonce
        ):
            raise WindowsBackendError(
                NetworkErrorCode.OWNERSHIP_CONFLICT,
                "应用后无法建立 Windows 双重所有权证据",
            )
        current = self._ledger.get(desired.network_id, desired.target_node_id)
        now = self._now()
        ownership = ManagedResourceOwnership(
            resource_id=current.ownership.resource_id if current is not None else ResourceId.new(),
            network_id=desired.network_id,
            node_id=desired.target_node_id,
            provider=self._provider_kind,
            interface_name=desired.interface_name,
            stable_interface_id=snapshot.stable_interface_id,
            creation_nonce=journal.creation_nonce,
            public_key_hash=snapshot.public_key_hash,
            parent_revision=desired.revision,
            desired_config_hash=canonical_sha256(desired.model_dump(mode="json")),
            system_fingerprint=snapshot.system_fingerprint,
        )
        self._ledger.put(
            ManagedResourceLedgerEntry(
                ownership=ownership,
                secret_reference=journal.secret_reference,
                created_at=current.created_at if current is not None else now,
                updated_at=now,
            )
        )

    async def _receipt_from_journal(
        self,
        journal: WindowsOperationJournal,
    ) -> ProviderReceipt:
        return ProviderReceipt(
            idempotency_key=journal.idempotency_key,
            plan_hash=journal.plan.plan_hash,
            revision=journal.plan.desired.revision,
            status=ReceiptStatus.APPLIED,
            steps=journal.steps,
            observation_after=await self.observe(journal.plan.desired.interface_name),
        )

    def _receipt(
        self,
        journal: WindowsOperationJournal,
        status: ReceiptStatus,
        code: NetworkErrorCode,
        message: str,
        *,
        retryable: bool = False,
    ) -> ProviderReceipt:
        return ProviderReceipt(
            idempotency_key=journal.idempotency_key,
            plan_hash=journal.plan.plan_hash,
            revision=journal.plan.desired.revision,
            status=status,
            steps=journal.steps,
            error=NetworkError(
                code=code,
                message=message,
                retryable=retryable,
                correlation_id=journal.plan.plan_hash,
            ),
        )

    @staticmethod
    def _error_receipt(
        plan: NetworkPlan,
        idempotency_key: str,
        status: ReceiptStatus,
        code: NetworkErrorCode,
        message: str,
        *,
        retryable: bool = False,
    ) -> ProviderReceipt:
        return ProviderReceipt(
            idempotency_key=idempotency_key,
            plan_hash=plan.plan_hash,
            revision=plan.desired.revision,
            status=status,
            error=NetworkError(
                code=code,
                message=message,
                retryable=retryable,
                correlation_id=plan.plan_hash,
            ),
        )

    def _ledger_entry_for_interface(
        self,
        interface_name: str,
    ) -> ManagedResourceLedgerEntry | None:
        return next(
            (
                item
                for item in self._ledger.list_all()
                if item.ownership.provider is self._provider_kind
                and item.ownership.interface_name == interface_name
            ),
            None,
        )

    def _classify_ownership(
        self,
        snapshot: WindowsTunnelSnapshot,
        entry: ManagedResourceLedgerEntry | None,
    ) -> OwnershipState:
        if not snapshot.interface_present and not snapshot.service_present:
            return OwnershipState.ABSENT
        if entry is None:
            return (
                OwnershipState.OWNERSHIP_UNKNOWN
                if snapshot.interface_name.startswith(_MANAGED_PREFIX)
                else OwnershipState.OBSERVED_USER
            )
        owned = entry.ownership
        if (
            snapshot.stable_interface_id == owned.stable_interface_id
            and snapshot.public_key_hash == owned.public_key_hash
            and snapshot.creation_nonce == owned.creation_nonce
            and snapshot.system_fingerprint == owned.system_fingerprint
        ):
            return OwnershipState.MANAGED_OWNED
        return OwnershipState.OWNERSHIP_CONFLICT

    @staticmethod
    def _rollback_ownership_matches(
        snapshot: WindowsTunnelSnapshot,
        entry: ManagedResourceLedgerEntry | None,
        journal: WindowsOperationJournal,
    ) -> bool:
        if entry is not None:
            owned = entry.ownership
            return (
                snapshot.stable_interface_id == owned.stable_interface_id
                and snapshot.public_key_hash == owned.public_key_hash
                and snapshot.creation_nonce == owned.creation_nonce
                and snapshot.system_fingerprint == owned.system_fingerprint
            )
        if snapshot.creation_nonce == journal.creation_nonce:
            return True
        return (
            not snapshot.interface_present
            and not snapshot.service_present
            and all(
                journal.plan.steps[item.index].kind is PlanStepKind.WRITE_CONFIG
                for item in journal.steps
            )
        )

    @staticmethod
    def _require_owned(
        observed: NetworkObservation,
        ownership: ManagedResourceOwnership | None,
    ) -> None:
        if ownership is None or observed.ownership is not OwnershipState.MANAGED_OWNED:
            raise ValueError("非创建操作要求实时和账本双重所有权")
        if (
            observed.stable_interface_id != ownership.stable_interface_id
            or observed.public_key_hash != ownership.public_key_hash
            or observed.system_fingerprint != ownership.system_fingerprint
        ):
            raise ValueError("实时 Windows 指纹与授权所有权不一致")

    @staticmethod
    def _validate_no_conflicts(
        desired: DesiredNetworkConfig,
        observed: NetworkObservation,
    ) -> None:
        address = ipaddress.ip_interface(desired.address).ip
        if any(address == ipaddress.ip_interface(item).ip for item in observed.addresses):
            raise ValueError("受管地址与现有 Windows 地址冲突")
        requested = {
            ipaddress.ip_network(route, strict=True)
            for peer in desired.peers
            for route in peer.allowed_host_routes
        }
        existing = {ipaddress.ip_network(route, strict=True) for route in observed.host_routes}
        if requested & existing:
            raise ValueError("受管 host route 与现有 Windows route 冲突")

    def _steps(
        self,
        action: NetworkAction,
        interface_name: str,
    ) -> tuple[NetworkPlanStep, ...]:
        kinds = {
            NetworkAction.CREATE: (
                PlanStepKind.WRITE_CONFIG,
                PlanStepKind.CREATE_INTERFACE,
                PlanStepKind.CONFIGURE_ADDRESS,
                PlanStepKind.CONFIGURE_PEER,
                PlanStepKind.ADD_HOST_ROUTE,
            ),
            NetworkAction.UPDATE: (
                PlanStepKind.STOP_INTERFACE,
                PlanStepKind.REMOVE_INTERFACE,
                PlanStepKind.WRITE_CONFIG,
                PlanStepKind.CREATE_INTERFACE,
            ),
            NetworkAction.STOP: (PlanStepKind.STOP_INTERFACE,),
            NetworkAction.REMOVE: (
                PlanStepKind.STOP_INTERFACE,
                PlanStepKind.REMOVE_INTERFACE,
                PlanStepKind.DELETE_CONFIG,
                PlanStepKind.DELETE_SECRET,
            ),
        }[action]
        rollback = {
            PlanStepKind.WRITE_CONFIG: PlanStepKind.DELETE_CONFIG,
            PlanStepKind.CREATE_INTERFACE: PlanStepKind.REMOVE_INTERFACE,
            PlanStepKind.CONFIGURE_ADDRESS: PlanStepKind.CONFIGURE_ADDRESS,
            PlanStepKind.CONFIGURE_PEER: PlanStepKind.CONFIGURE_PEER,
            PlanStepKind.ADD_HOST_ROUTE: PlanStepKind.ADD_HOST_ROUTE,
            PlanStepKind.STOP_INTERFACE: PlanStepKind.CREATE_INTERFACE,
            PlanStepKind.REMOVE_INTERFACE: PlanStepKind.CREATE_INTERFACE,
            PlanStepKind.DELETE_CONFIG: PlanStepKind.WRITE_CONFIG,
            PlanStepKind.DELETE_SECRET: None,
        }
        return tuple(
            NetworkPlanStep(
                index=index,
                kind=kind,
                target=interface_name,
                expected_effect=f"{self._provider_kind.value}:{action.value}:{kind.value}",
                rollback_kind=rollback[kind],
            )
            for index, kind in enumerate(kinds)
        )

    def _now(self) -> datetime:
        now = self._clock()
        if now.tzinfo is None:
            raise ValueError(f"{self._platform_label} Provider 时钟必须包含时区")
        return now.astimezone(UTC)
