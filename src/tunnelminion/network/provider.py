"""平台无关的受管网络 Provider 协议。"""

from __future__ import annotations

from typing import Protocol

from tunnelminion.domain.identifiers import NetworkId, NodeId
from tunnelminion.network.contracts import (
    DesiredNetworkConfig,
    LocalNetworkKeyMaterial,
    ManagedResourceOwnership,
    NetworkAction,
    NetworkObservation,
    NetworkPlan,
    ProviderReceipt,
    VerificationResult,
)
from tunnelminion.tools.contracts import ToolCancellationToken


class NetworkProvider(Protocol):
    """固定 observe/plan/apply/verify/rollback/recover 边界。"""

    def ensure_local_identity(
        self,
        network_id: NetworkId,
        node_id: NodeId,
    ) -> LocalNetworkKeyMaterial:
        """在本机生成或复用网络密钥，仅返回公钥和不透明秘密引用。"""
        ...  # pragma: no cover - 结构化 Protocol 没有运行时实现

    async def observe(self, interface_name: str) -> NetworkObservation:
        """读取实时系统状态，不产生写入。"""
        ...  # pragma: no cover - 结构化 Protocol 没有运行时实现

    async def plan(
        self,
        *,
        action: NetworkAction,
        desired: DesiredNetworkConfig,
        observed: NetworkObservation,
        ownership: ManagedResourceOwnership | None,
    ) -> NetworkPlan:
        """生成确定、可预览且不含秘密的计划。"""
        ...  # pragma: no cover - 结构化 Protocol 没有运行时实现

    async def apply(
        self,
        plan: NetworkPlan,
        *,
        idempotency_key: str,
        cancellation: ToolCancellationToken,
    ) -> ProviderReceipt:
        """在安全取消点串行应用已授权计划。"""
        ...  # pragma: no cover - 结构化 Protocol 没有运行时实现

    async def verify(self, plan: NetworkPlan) -> VerificationResult:
        """独立重新观察并验证期望状态。"""
        ...  # pragma: no cover - 结构化 Protocol 没有运行时实现

    async def rollback(
        self,
        plan: NetworkPlan,
        receipt: ProviderReceipt,
        *,
        cancellation: ToolCancellationToken,
    ) -> ProviderReceipt:
        """按已确认回执逆序恢复父 revision。"""
        ...  # pragma: no cover - 结构化 Protocol 没有运行时实现

    async def recover(self, *, cancellation: ToolCancellationToken) -> tuple[ProviderReceipt, ...]:
        """在模型和 Coordinator 不可用时恢复未完成操作。"""
        ...  # pragma: no cover - 结构化 Protocol 没有运行时实现
