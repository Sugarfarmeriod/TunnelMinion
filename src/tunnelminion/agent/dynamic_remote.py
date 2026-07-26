"""Coordinator 目录解析、短期身份与动态远端工具的确定性装配。"""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from collections.abc import Callable, Collection, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Protocol

from pydantic import BaseModel, ConfigDict, Field

from tunnelminion.agent.coordinator import (
    CoordinatorCache,
    CoordinatorClientError,
)
from tunnelminion.agent.remote import (
    PreparedRemoteAgentTools,
    RemoteCapabilityLoader,
    RemotePreparationError,
)
from tunnelminion.coordinator.client_credentials import AgentRefreshCredentialStore
from tunnelminion.coordinator.contracts import (
    AccessAssertionRequest,
    AccessAssertionResponse,
    CapabilityAvailability,
    CapabilitySummary,
    DirectoryFreshness,
    NodeStatus,
    RefreshAuthentication,
)
from tunnelminion.domain.errors import ErrorCode
from tunnelminion.domain.identifiers import NetworkId, NodeId
from tunnelminion.domain.tools import Platform, RiskLevel, ToolDefinition
from tunnelminion.domain.versioning import ProtocolVersion
from tunnelminion.gateway.client import FixedGatewayClient, RemoteGatewayError
from tunnelminion.gateway.contracts import GATEWAY_PROTOCOL, GatewayCapabilities
from tunnelminion.tools.audit import AuditSink
from tunnelminion.tools.contracts import ToolCallContext, ToolCancellationToken


class RemoteTaskStage(StrEnum):
    """任务阶段决定模型能够看到的最高风险，而不是赋予新权限。"""

    DIAGNOSIS = "diagnosis"
    APPROVED_OPERATION = "approved-operation"


class DynamicExclusionReason(StrEnum):
    """不含 endpoint、凭据和 schema 的稳定排除原因。"""

    DIRECTORY_MISSING = "directory_missing"
    NODE_STATUS = "node_status"
    ENDPOINT_STALE = "endpoint_stale"
    UNAUTHORIZED = "unauthorized"
    PLATFORM = "platform"
    VERSION_INCOMPATIBLE = "version_incompatible"
    RISK = "risk"
    TASK_STAGE = "task_stage"
    DIRECT_CONFLICT = "direct_conflict"


class DynamicToolSelectionRecord(BaseModel):
    """一次动态工具选择的可评估证据。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    network_id: NetworkId
    target_node_id: NodeId
    server_revision: int = Field(ge=0)
    direct_capability_revision: str = Field(pattern=r"^[0-9a-f]{64}$")
    candidate_count: int = Field(ge=0)
    retained_count: int = Field(ge=0)
    excluded_count: int = Field(ge=0)
    exclusion_reasons: dict[str, int] = Field(default_factory=dict)
    used_static_fallback: bool = False


class DynamicSelectionSink:
    """进程内有界选择记录；不会保存 assertion 或完整能力 schema。"""

    def __init__(self, max_records: int = 200) -> None:
        if max_records < 1:
            raise ValueError("动态工具记录上限必须为正数")
        self._max_records = max_records
        self._records: list[DynamicToolSelectionRecord] = []

    @property
    def records(self) -> tuple[DynamicToolSelectionRecord, ...]:
        return tuple(self._records)

    def append(self, record: DynamicToolSelectionRecord) -> None:
        self._records.append(record)
        del self._records[: -self._max_records]


@dataclass(frozen=True)
class DynamicPreparedRemote:
    """把现有远端执行对象与选择证据绑定。"""

    tools: PreparedRemoteAgentTools
    selection: DynamicToolSelectionRecord


GatewayClientFactory = Callable[[str, str, NodeId, NodeId, AuditSink], FixedGatewayClient]


class AssertionIssuerTransport(Protocol):
    """动态数据面只依赖最小 assertion 签发能力。"""

    async def issue_assertion(
        self,
        request: AccessAssertionRequest,
    ) -> AccessAssertionResponse: ...


class DynamicRemoteToolCoordinator:
    """模型只提交稳定 node ID；endpoint 与 assertion 始终在模型外解析。"""

    def __init__(
        self,
        *,
        network_id: NetworkId,
        local_node_id: NodeId,
        local_platform: Platform,
        cache: CoordinatorCache,
        transport: AssertionIssuerTransport,
        credentials: AgentRefreshCredentialStore,
        audit_sink: AuditSink,
        selection_sink: DynamicSelectionSink,
        authorized_nodes: Collection[NodeId],
        supported_tools: Mapping[str, ProtocolVersion],
        client_factory: GatewayClientFactory | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._network_id = network_id
        self._local_node_id = local_node_id
        self._local_platform = local_platform
        self._cache = cache
        self._transport = transport
        self._credentials = credentials
        self._audit = audit_sink
        self._selection_sink = selection_sink
        self._authorized_nodes = frozenset(str(item) for item in authorized_nodes)
        self._supported_tools = dict(supported_tools)
        self._client_factory = client_factory or self._default_client
        self._clock = clock or (lambda: datetime.now(UTC))

    async def prepare(
        self,
        target_node_id: NodeId,
        context: ToolCallContext,
        requested_tools: tuple[str, ...],
        *,
        task_stage: RemoteTaskStage = RemoteTaskStage.DIAGNOSIS,
        cancellation: ToolCancellationToken | None = None,
        static_fallback: RemoteCapabilityLoader | None = None,
    ) -> DynamicPreparedRemote:
        """按目录预筛选、获取 assertion、直连复核，再生成模型工具集。"""
        if context.caller_node_id != self._local_node_id:
            raise ValueError("调用上下文 caller 与本地节点不一致")
        if context.execution_node_id != target_node_id:
            raise ValueError("调用上下文 execution 与目标节点不一致")
        try:
            return await self._prepare_managed(
                target_node_id,
                context,
                requested_tools,
                task_stage,
                cancellation,
            )
        except (CoordinatorClientError, RemotePreparationError, RemoteGatewayError):
            if static_fallback is None:
                raise
            prepared = await static_fallback.prepare(context, requested_tools, cancellation)
            record = DynamicToolSelectionRecord(
                network_id=self._network_id,
                target_node_id=target_node_id,
                server_revision=0,
                direct_capability_revision=_capability_revision(()),
                candidate_count=len(requested_tools),
                retained_count=len(prepared.tool_names),
                excluded_count=len(requested_tools) - len(prepared.tool_names),
                used_static_fallback=True,
            )
            self._selection_sink.append(record)
            return DynamicPreparedRemote(prepared, record)

    async def _prepare_managed(
        self,
        target_node_id: NodeId,
        context: ToolCallContext,
        requested_tools: tuple[str, ...],
        task_stage: RemoteTaskStage,
        cancellation: ToolCancellationToken | None,
    ) -> DynamicPreparedRemote:
        view = self._cache.read()
        now = self._clock()
        if view is None or view.network_id != self._network_id:
            raise CoordinatorClientError("directory_missing", "Coordinator 目录不可用")
        if not view.is_fresh(now):
            raise CoordinatorClientError("endpoint_stale", "Coordinator endpoint 缓存已过期")
        node = next(
            (item for item in view.nodes if item.identity.node_id == target_node_id),
            None,
        )
        if node is None:
            raise CoordinatorClientError("directory_missing", "目标节点不在已验证目录")
        if node.status is not NodeStatus.ONLINE or node.freshness is not DirectoryFreshness.FRESH:
            raise CoordinatorClientError("node_status", "目标节点当前不可用于实时调用")
        if str(target_node_id) not in self._authorized_nodes:
            raise CoordinatorClientError("unauthorized", "本机未授权调用目标节点")

        requested = frozenset(requested_tools)
        reasons: Counter[DynamicExclusionReason] = Counter()
        candidates: list[CapabilitySummary] = []
        for capability in node.capabilities:
            reason = self._directory_exclusion(
                capability, requested, node.identity.platform, task_stage
            )
            if reason is None:
                candidates.append(capability)
            else:
                reasons[reason] += 1
        if not candidates:
            self._selection_sink.append(
                DynamicToolSelectionRecord(
                    network_id=self._network_id,
                    target_node_id=target_node_id,
                    server_revision=node.server_revision,
                    direct_capability_revision=_capability_revision(()),
                    candidate_count=len(node.capabilities),
                    retained_count=0,
                    excluded_count=sum(reasons.values()),
                    exclusion_reasons={reason.value: count for reason, count in reasons.items()},
                )
            )
            raise RemotePreparationError(ErrorCode.TOOL_NOT_FOUND, "目录没有符合任务约束的远端工具")

        credential = self._credentials.load(self._network_id, self._local_node_id)
        if credential is None:
            raise CoordinatorClientError("unauthenticated", "Coordinator refresh 凭据不可用")
        assertion = await self._transport.issue_assertion(
            AccessAssertionRequest(
                authentication=RefreshAuthentication(
                    network_id=self._network_id,
                    node_id=self._local_node_id,
                    refresh_credential=credential,
                ),
                audience="tool-gateway",
            )
        )
        endpoint = (
            f"http://{node.identity.gateway_endpoint.host}:{node.identity.gateway_endpoint.port}"
        )
        client = self._client_factory(
            endpoint,
            assertion.assertion,
            self._local_node_id,
            target_node_id,
            self._audit,
        )
        direct = await client.discover()
        retained = self._reconcile(candidates, direct, node.identity.platform, reasons)
        record = DynamicToolSelectionRecord(
            network_id=self._network_id,
            target_node_id=target_node_id,
            server_revision=node.server_revision,
            direct_capability_revision=_capability_revision(direct.tools),
            candidate_count=len(node.capabilities),
            retained_count=len(retained),
            excluded_count=sum(reasons.values()),
            exclusion_reasons={reason.value: count for reason, count in reasons.items()},
        )
        self._selection_sink.append(record)
        if not retained:
            raise RemotePreparationError(
                ErrorCode.TOOL_NOT_FOUND,
                "目标 Gateway 直连复核后没有可用工具",
            )
        prepared = await RemoteCapabilityLoader(
            client,
            self._local_platform,
            target_node_id,
        ).prepare(
            context,
            tuple(retained),
            cancellation,
            capabilities=direct,
        )
        return DynamicPreparedRemote(prepared, record)

    def _directory_exclusion(
        self,
        capability: CapabilitySummary,
        requested: frozenset[str],
        target_platform: Platform,
        task_stage: RemoteTaskStage,
    ) -> DynamicExclusionReason | None:
        if (
            capability.name not in requested
            or capability.availability is not CapabilityAvailability.AVAILABLE
        ):
            return DynamicExclusionReason.TASK_STAGE
        if capability.platform is not target_platform:
            return DynamicExclusionReason.PLATFORM
        supported = self._supported_tools.get(capability.name)
        if supported is None or not supported.is_compatible_with(capability.version):
            return DynamicExclusionReason.VERSION_INCOMPATIBLE
        if capability.risk_level is not RiskLevel.READ_ONLY:
            return (
                DynamicExclusionReason.RISK
                if task_stage is RemoteTaskStage.DIAGNOSIS
                else DynamicExclusionReason.TASK_STAGE
            )
        return None

    @staticmethod
    def _reconcile(
        candidates: list[CapabilitySummary],
        direct: GatewayCapabilities,
        target_platform: Platform,
        reasons: Counter[DynamicExclusionReason],
    ) -> tuple[str, ...]:
        if not GATEWAY_PROTOCOL.is_compatible_with(direct.protocol):
            reasons[DynamicExclusionReason.VERSION_INCOMPATIBLE] += len(candidates)
            return ()
        definitions = {item.name: item for item in direct.tools}
        retained: list[str] = []
        for candidate in candidates:
            current = definitions.get(candidate.name)
            if (
                current is None
                or not candidate.version.is_compatible_with(current.version)
                or target_platform not in current.platforms
                or current.risk_level is not RiskLevel.READ_ONLY
            ):
                reasons[DynamicExclusionReason.DIRECT_CONFLICT] += 1
                continue
            retained.append(candidate.name)
        return tuple(retained)

    @staticmethod
    def _default_client(
        endpoint: str,
        assertion: str,
        local_node_id: NodeId,
        remote_node_id: NodeId,
        audit_sink: AuditSink,
    ) -> FixedGatewayClient:
        return FixedGatewayClient(
            endpoint,
            assertion,
            local_node_id,
            remote_node_id,
            audit_sink,
        )


def _capability_revision(capabilities: Sequence[ToolDefinition]) -> str:
    """对直连能力生成稳定修订，不保留完整 schema。"""
    payload = [
        {
            "name": item.name,
            "version": item.version.model_dump(mode="json"),
            "risk": item.risk_level.value,
            "platforms": sorted(value.value for value in item.platforms),
        }
        for item in capabilities
    ]
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
