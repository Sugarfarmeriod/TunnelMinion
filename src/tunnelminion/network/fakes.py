"""不调用操作系统的确定性内存 NetworkProvider。"""

from __future__ import annotations

import ipaddress
from datetime import UTC, datetime
from enum import StrEnum

from tunnelminion.domain.identifiers import NetworkId, NodeId
from tunnelminion.network.contracts import (
    DesiredNetworkConfig,
    LocalNetworkKeyMaterial,
    ManagedResourceOwnership,
    NetworkAction,
    NetworkError,
    NetworkErrorCode,
    NetworkObservation,
    NetworkPlan,
    NetworkPlanStep,
    OwnershipState,
    PlanStepKind,
    ProviderMode,
    ProviderReceipt,
    ReceiptStatus,
    SignedDesiredConfig,
    StepReceipt,
    VerificationResult,
    canonical_sha256,
    compute_plan_hash,
)
from tunnelminion.tools.contracts import ToolCancellationToken


class FakeProviderBehavior(StrEnum):
    """可注入的 apply/verify/rollback 故障。"""

    SUCCESS = "success"
    RESPONSE_LOST = "response_lost"
    STEP_FAILURE = "step_failure"
    VERIFY_FAILURE = "verify_failure"
    ROLLBACK_FAILURE = "rollback_failure"
    CRASH_AFTER_STEP = "crash_after_step"
    OWNERSHIP_REPLACED = "ownership_replaced"


class InMemoryNetworkProvider:
    """保存回执和假系统状态的 Provider 契约实现。"""

    def __init__(
        self,
        observation: NetworkObservation,
        *,
        behavior: FakeProviderBehavior = FakeProviderBehavior.SUCCESS,
    ) -> None:
        self._observation = observation
        self.behavior = behavior
        self.apply_calls = 0
        self.observe_calls = 0
        self.emergency_stop_calls = 0
        self.verify_calls = 0
        self.rollback_calls = 0
        self._receipts: dict[str, ProviderReceipt] = {}
        self._plans: dict[str, NetworkPlan] = {}
        self._plan_idempotency: dict[str, str] = {}
        self._operations: dict[tuple[str, str], tuple[SignedDesiredConfig, NetworkPlan]] = {}
        self._response_lost_keys: set[str] = set()

    def ensure_local_identity(
        self,
        network_id: NetworkId,
        node_id: NodeId,
    ) -> LocalNetworkKeyMaterial:
        """返回稳定假公钥，不产生真实秘密材料。"""
        return LocalNetworkKeyMaterial(
            secret_reference=f"fake:{network_id}/{node_id}",
            public_key="A" * 43 + "=",
            public_key_hash=canonical_sha256(
                {"network_id": str(network_id), "node_id": str(node_id)}
            ),
        )

    async def observe(self, interface_name: str) -> NetworkObservation:
        """返回指定接口的当前假状态。"""
        self.observe_calls += 1
        if interface_name != self._observation.interface_name:
            raise ValueError("fake Provider 只观察已配置 fixture 接口")
        return self._observation

    async def plan(
        self,
        *,
        action: NetworkAction,
        desired: DesiredNetworkConfig,
        observed: NetworkObservation,
        ownership: ManagedResourceOwnership | None,
    ) -> NetworkPlan:
        """生成固定步骤，并执行所有权和 Provider 预检。"""
        if desired.provider is not observed.provider:
            raise ValueError("desired config 与观察 Provider 不一致")
        if desired.interface_name != observed.interface_name:
            raise ValueError("desired config 与观察接口不一致")
        if action is NetworkAction.CREATE:
            if observed.ownership is not OwnershipState.ABSENT or ownership is not None:
                raise ValueError("创建计划只允许目标接口不存在")
            desired_ip = ipaddress.ip_interface(desired.address).ip
            if any(
                desired_ip in ipaddress.ip_interface(address).network
                for address in observed.addresses
            ):
                raise ValueError("受管地址与本机现有地址冲突")
            if any(
                desired_ip in ipaddress.ip_network(route, strict=True)
                for route in observed.host_routes
            ):
                raise ValueError("受管地址与本机现有 route 重叠")
        else:
            self._validate_owned(observed, ownership)
        steps = self._steps(action, desired)
        plan_hash = compute_plan_hash(
            action=action,
            desired=desired,
            observed_fingerprint=observed.system_fingerprint,
            ownership=ownership,
            steps=steps,
        )
        plan = NetworkPlan(
            action=action,
            desired=desired,
            observed_fingerprint=observed.system_fingerprint,
            ownership=ownership,
            steps=steps,
            plan_hash=plan_hash,
        )
        self._plans[plan.plan_hash] = plan
        return plan

    def remember_operation(
        self,
        envelope: SignedDesiredConfig,
        plan: NetworkPlan,
        *,
        idempotency_key: str,
    ) -> None:
        self._operations[(idempotency_key, plan.plan_hash)] = (envelope, plan)
        self._plan_idempotency.setdefault(plan.plan_hash, idempotency_key)

    def load_operation(
        self,
        *,
        idempotency_key: str,
        plan_hash: str,
    ) -> tuple[SignedDesiredConfig, NetworkPlan] | None:
        return self._operations.get((idempotency_key, plan_hash))

    async def apply(
        self,
        plan: NetworkPlan,
        *,
        idempotency_key: str,
        cancellation: ToolCancellationToken,
    ) -> ProviderReceipt:
        """模拟串行应用、响应丢失、逐步失败、取消和崩溃。"""
        self.apply_calls += 1
        self._plan_idempotency.setdefault(plan.plan_hash, idempotency_key)
        existing = self._receipts.get(idempotency_key)
        if existing is not None:
            return existing
        if cancellation.cancelled:
            return self._store_error(
                plan,
                idempotency_key,
                ReceiptStatus.CANCELLED,
                NetworkErrorCode.CANCELLED,
                "调用在第一个安全点前取消",
            )
        if self._observation.mode is not ProviderMode.MANAGED:
            return self._store_error(
                plan,
                idempotency_key,
                ReceiptStatus.FAILED,
                NetworkErrorCode.PROVIDER_UNAVAILABLE,
                "Provider 当前仅允许只读观察",
            )
        if self._observation.ownership in {
            OwnershipState.OBSERVED_USER,
            OwnershipState.OWNERSHIP_CONFLICT,
            OwnershipState.OWNERSHIP_UNKNOWN,
        }:
            return self._store_error(
                plan,
                idempotency_key,
                ReceiptStatus.FAILED,
                NetworkErrorCode.OWNERSHIP_CONFLICT,
                "实时资源不满足受管所有权",
            )
        if self.behavior in {
            FakeProviderBehavior.STEP_FAILURE,
            FakeProviderBehavior.CRASH_AFTER_STEP,
        }:
            receipt = self._failed_after_first_step(plan, idempotency_key)
            self._receipts[idempotency_key] = receipt
            if self.behavior is FakeProviderBehavior.CRASH_AFTER_STEP:
                raise RuntimeError("injected provider crash")
            return receipt

        step_receipts = tuple(self._step_receipt(step) for step in plan.steps)
        self._observation = self._applied_observation(plan)
        receipt = ProviderReceipt(
            idempotency_key=idempotency_key,
            plan_hash=plan.plan_hash,
            revision=plan.desired.revision,
            status=ReceiptStatus.APPLIED,
            steps=step_receipts,
            provider=plan.desired.provider,
            observation_fingerprint=self._observation.system_fingerprint,
            observation_after=self._observation,
        )
        self._receipts[idempotency_key] = receipt
        if (
            self.behavior is FakeProviderBehavior.RESPONSE_LOST
            and idempotency_key not in self._response_lost_keys
        ):
            self._response_lost_keys.add(idempotency_key)
            raise TimeoutError("injected response loss")
        return receipt

    async def verify(self, plan: NetworkPlan) -> VerificationResult:
        """重新读取假状态，而不是接受 apply 自报成功。"""
        self.verify_calls += 1
        checked = ("interface", "address", "peer", "host_route")
        if self.behavior in {
            FakeProviderBehavior.VERIFY_FAILURE,
            FakeProviderBehavior.OWNERSHIP_REPLACED,
        }:
            code = (
                NetworkErrorCode.OWNERSHIP_CONFLICT
                if self.behavior is FakeProviderBehavior.OWNERSHIP_REPLACED
                else NetworkErrorCode.VERIFY_FAILED
            )
            return VerificationResult(
                idempotency_key=self._plan_idempotency.get(
                    plan.plan_hash, self._fallback_idempotency_key(plan)
                ),
                plan_hash=plan.plan_hash,
                revision=plan.desired.revision,
                provider=plan.desired.provider,
                observation_fingerprint=self._observation.system_fingerprint,
                succeeded=False,
                checked_dimensions=checked,
                observation=self._observation,
                error=NetworkError(
                    code=code,
                    message="注入的独立验证失败",
                    correlation_id=plan.plan_hash,
                ),
            )
        expected_address = plan.desired.address
        succeeded = (
            self._observation.ownership is OwnershipState.ABSENT
            if plan.action is NetworkAction.STOP
            else self._observation.ownership is OwnershipState.MANAGED_OWNED
            and expected_address in self._observation.addresses
        )
        return VerificationResult(
            idempotency_key=self._plan_idempotency.get(
                plan.plan_hash, self._fallback_idempotency_key(plan)
            ),
            plan_hash=plan.plan_hash,
            revision=plan.desired.revision,
            provider=plan.desired.provider,
            observation_fingerprint=self._observation.system_fingerprint,
            succeeded=succeeded,
            checked_dimensions=checked,
            observation=self._observation,
            error=None
            if succeeded
            else NetworkError(
                code=NetworkErrorCode.VERIFY_FAILED,
                message="假系统状态与目标配置不一致",
                correlation_id=plan.plan_hash,
            ),
        )

    async def emergency_stop(
        self,
        plan: NetworkPlan,
        *,
        idempotency_key: str,
        cancellation: ToolCancellationToken,
    ) -> ProviderReceipt:
        """通过独立 fake kill-switch 停止资源，不进入普通 apply 计数。"""
        self.emergency_stop_calls += 1
        existing = self._receipts.get(idempotency_key)
        if existing is not None:
            return existing
        if cancellation.cancelled:
            return self._store_error(
                plan,
                idempotency_key,
                ReceiptStatus.CANCELLED,
                NetworkErrorCode.CANCELLED,
                "紧急停止在安全点前取消",
            )
        self._observation = self._stopped_observation(plan)
        receipt = ProviderReceipt(
            idempotency_key=idempotency_key,
            plan_hash=plan.plan_hash,
            revision=plan.desired.revision,
            provider=plan.desired.provider,
            observation_fingerprint=self._observation.system_fingerprint,
            status=ReceiptStatus.APPLIED,
            steps=tuple(self._step_receipt(step) for step in plan.steps),
            observation_after=self._observation,
        )
        self._receipts[idempotency_key] = receipt
        self._plans[plan.plan_hash] = plan
        self._plan_idempotency.setdefault(plan.plan_hash, idempotency_key)
        return receipt

    async def rollback(
        self,
        plan: NetworkPlan,
        receipt: ProviderReceipt,
        *,
        cancellation: ToolCancellationToken,
    ) -> ProviderReceipt:
        """按回执逆序模拟恢复，并在所有权变化时熔断。"""
        self.rollback_calls += 1
        if cancellation.cancelled:
            return self._error_receipt(
                plan,
                receipt.idempotency_key,
                ReceiptStatus.CANCELLED,
                NetworkErrorCode.CANCELLED,
                "回滚在安全点前取消",
                steps=receipt.steps,
            )
        if self.behavior is FakeProviderBehavior.OWNERSHIP_REPLACED:
            return self._error_receipt(
                plan,
                receipt.idempotency_key,
                ReceiptStatus.MANUAL_INTERVENTION,
                NetworkErrorCode.OWNERSHIP_CONFLICT,
                "实时指纹已变化，停止自动回滚",
                steps=receipt.steps,
            )
        if self.behavior is FakeProviderBehavior.ROLLBACK_FAILURE:
            return self._error_receipt(
                plan,
                receipt.idempotency_key,
                ReceiptStatus.FAILED,
                NetworkErrorCode.ROLLBACK_FAILED,
                "注入的回滚失败",
                steps=receipt.steps,
            )
        self._observation = self._observation.model_copy(
            update={
                "addresses": (),
                "host_routes": (),
                "ownership": OwnershipState.ABSENT,
                "stable_interface_id": None,
                "public_key_hash": None,
                "system_fingerprint": canonical_sha256(
                    {"interface": plan.desired.interface_name, "state": "absent"}
                ),
                "observed_at": datetime.now(UTC),
            }
        )
        rollback_steps = tuple(
            StepReceipt(
                index=index,
                kind=plan.steps[original.index].rollback_kind or original.kind,
                succeeded=True,
                system_receipt_hash=canonical_sha256(
                    {
                        "rollback_of": original.system_receipt_hash,
                        "index": index,
                    }
                ),
            )
            for index, original in enumerate(reversed(receipt.steps))
        )
        rolled_back = ProviderReceipt(
            idempotency_key=receipt.idempotency_key,
            plan_hash=plan.plan_hash,
            revision=plan.desired.revision,
            status=ReceiptStatus.ROLLED_BACK,
            steps=rollback_steps,
            provider=plan.desired.provider,
            observation_fingerprint=self._observation.system_fingerprint,
            observation_after=self._observation,
        )
        self._receipts[receipt.idempotency_key] = rolled_back
        return rolled_back

    async def recover(self, *, cancellation: ToolCancellationToken) -> tuple[ProviderReceipt, ...]:
        """回滚所有 failed/applied 未完成回执。"""
        recovered: list[ProviderReceipt] = []
        for receipt in tuple(self._receipts.values()):
            if receipt.status not in {ReceiptStatus.APPLIED, ReceiptStatus.FAILED}:
                continue
            plan = self._plans[receipt.plan_hash]
            recovered.append(await self.rollback(plan, receipt, cancellation=cancellation))
        return tuple(recovered)

    @staticmethod
    def _validate_owned(
        observed: NetworkObservation,
        ownership: ManagedResourceOwnership | None,
    ) -> None:
        if ownership is None or observed.ownership is not OwnershipState.MANAGED_OWNED:
            raise ValueError("非创建计划要求受管所有权")
        if (
            ownership.stable_interface_id != observed.stable_interface_id
            or ownership.public_key_hash != observed.public_key_hash
            or ownership.system_fingerprint != observed.system_fingerprint
        ):
            raise ValueError("本地账本与实时系统指纹不一致")

    @staticmethod
    def _steps(
        action: NetworkAction,
        desired: DesiredNetworkConfig,
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
                PlanStepKind.WRITE_CONFIG,
                PlanStepKind.CONFIGURE_ADDRESS,
                PlanStepKind.CONFIGURE_PEER,
                PlanStepKind.ADD_HOST_ROUTE,
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
                target=desired.interface_name,
                expected_effect=f"{kind.value}:{desired.revision}",
                rollback_kind=rollback[kind],
            )
            for index, kind in enumerate(kinds)
        )

    @staticmethod
    def _step_receipt(step: NetworkPlanStep) -> StepReceipt:
        return StepReceipt(
            index=step.index,
            kind=step.kind,
            succeeded=True,
            system_receipt_hash=canonical_sha256(step.model_dump(mode="json")),
        )

    def _failed_after_first_step(self, plan: NetworkPlan, idempotency_key: str) -> ProviderReceipt:
        first = self._step_receipt(plan.steps[0])
        return self._error_receipt(
            plan,
            idempotency_key,
            ReceiptStatus.FAILED,
            NetworkErrorCode.APPLY_FAILED,
            "注入的逐步应用失败",
            steps=(first,),
        )

    def _store_error(
        self,
        plan: NetworkPlan,
        idempotency_key: str,
        status: ReceiptStatus,
        code: NetworkErrorCode,
        message: str,
    ) -> ProviderReceipt:
        receipt = self._error_receipt(plan, idempotency_key, status, code, message, steps=())
        self._receipts[idempotency_key] = receipt
        return receipt

    @staticmethod
    def _error_receipt(
        plan: NetworkPlan,
        idempotency_key: str,
        status: ReceiptStatus,
        code: NetworkErrorCode,
        message: str,
        *,
        steps: tuple[StepReceipt, ...],
    ) -> ProviderReceipt:
        return ProviderReceipt(
            idempotency_key=idempotency_key,
            plan_hash=plan.plan_hash,
            revision=plan.desired.revision,
            provider=plan.desired.provider,
            observation_fingerprint=plan.observed_fingerprint,
            status=status,
            steps=steps,
            error=NetworkError(
                code=code,
                message=message,
                retryable=code
                in {
                    NetworkErrorCode.APPLY_FAILED,
                    NetworkErrorCode.VERIFY_FAILED,
                    NetworkErrorCode.ROLLBACK_FAILED,
                },
                correlation_id=plan.plan_hash,
            ),
        )

    def _applied_observation(self, plan: NetworkPlan) -> NetworkObservation:
        routes = tuple(route for peer in plan.desired.peers for route in peer.allowed_host_routes)
        return self._observation.model_copy(
            update={
                "stable_interface_id": f"fake:{plan.desired.interface_name}",
                "addresses": (plan.desired.address,),
                "host_routes": routes,
                "public_key_hash": canonical_sha256(
                    {
                        "network_id": str(plan.desired.network_id),
                        "node_id": str(plan.desired.target_node_id),
                    }
                ),
                "ownership": OwnershipState.MANAGED_OWNED,
                "system_fingerprint": canonical_sha256(
                    {
                        "plan_hash": plan.plan_hash,
                        "revision": plan.desired.revision,
                    }
                ),
                "observed_at": datetime.now(UTC),
            }
        )

    def _stopped_observation(self, plan: NetworkPlan) -> NetworkObservation:
        return self._observation.model_copy(
            update={
                "addresses": (),
                "host_routes": (),
                "ownership": OwnershipState.ABSENT,
                "stable_interface_id": None,
                "public_key_hash": None,
                "system_fingerprint": canonical_sha256(
                    {"plan_hash": plan.plan_hash, "state": "absent"}
                ),
                "observed_at": datetime.now(UTC),
            }
        )

    @staticmethod
    def _fallback_idempotency_key(plan: NetworkPlan) -> str:
        return "netop_" + canonical_sha256({"plan_hash": plan.plan_hash})[7:]
