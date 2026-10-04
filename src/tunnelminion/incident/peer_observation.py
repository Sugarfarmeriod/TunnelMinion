"""显式静态对端的单端口只读观察，不发现节点或配置网络。"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from ipaddress import ip_address
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from tunnelminion.agent.remote import RemotePreparationError
from tunnelminion.agent.service_observation import compute_static_peer_service_id
from tunnelminion.coordinator.contracts import (
    ServiceAccessibility,
    ServiceLifecycle,
    ServiceProtocol,
)
from tunnelminion.domain.identifiers import NodeId, RunId, ThreadId
from tunnelminion.domain.tools import Platform
from tunnelminion.gateway.client import RemoteGatewayError
from tunnelminion.incident.investigation import InvestigationRemoteToolPreparer
from tunnelminion.platforms.windows.models import Availability, CollectionResult, NetworkListener
from tunnelminion.tools.contracts import (
    ToolCallContext,
    ToolCancellationToken,
    ToolExecutionRequest,
    ToolExecutionStatus,
)
from tunnelminion.web.overview import (
    KnownNodeOverview,
    KnownNodeState,
    KnownServiceOverview,
    KnownServiceState,
    OverviewFreshness,
    OverviewSource,
)


class PeerObservationConfig(BaseModel):
    """单个 TCP 端口的观察选择；不增加 Gateway 授权。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    enabled: bool = False
    node_id: NodeId
    port: int = Field(ge=1, le=65535)


class StaticPeerServiceObserver:
    """复用远端身份预检和监听工具；失败保留旧事实并标记陈旧。"""

    def __init__(
        self,
        config: PeerObservationConfig,
        local_node_id: NodeId,
        preparer: InvestigationRemoteToolPreparer,
    ) -> None:
        if config.node_id == local_node_id:
            raise ValueError("静态观察目标必须是远端节点")
        self.config = config
        self._local_node_id = local_node_id
        self._preparer = preparer
        # 用户指定的是逻辑端口，地址变化不能变成两个不同服务。
        self.service = KnownServiceOverview(
            service_id=compute_static_peer_service_id(config.node_id, config.port),
            node_id=config.node_id,
            protocol=ServiceProtocol.TCP,
            port=config.port,
            state=KnownServiceState.UNKNOWN,
            source=OverviewSource.STATIC_PEER_OBSERVATION,
            freshness=OverviewFreshness.UNKNOWN,
        )
        self.node = KnownNodeOverview(
            node_id=config.node_id,
            display_name="指定对端",
            state=KnownNodeState.UNKNOWN,
            source=OverviewSource.STATIC_PEER_OBSERVATION,
            freshness=OverviewFreshness.UNKNOWN,
        )

    @classmethod
    def from_file(
        cls,
        root: Path,
        local_node_id: NodeId,
        preparer: InvestigationRemoteToolPreparer,
    ) -> StaticPeerServiceObserver | None:
        """缺文件或未开启时不创建；错误配置明确阻止启动。"""
        path = root / "peer-observation.json"
        if not path.exists():
            return None
        config = PeerObservationConfig.model_validate_json(path.read_text(encoding="utf-8"))
        return cls(config, local_node_id, preparer) if config.enabled else None

    async def refresh(self) -> None:
        """每个后台周期查询摘要与监听，不调用模型或其他端口探测。"""
        try:
            async with asyncio.timeout(25):
                context = ToolCallContext(
                    thread_id=ThreadId.new(),
                    run_id=RunId.new(),
                    caller_node_id=self._local_node_id,
                    execution_node_id=self.config.node_id,
                )
                prepared = await self._preparer.prepare(
                    self.config.node_id,
                    context,
                    ("list_network_listeners",),
                    ToolCancellationToken(),
                )
                result = await prepared.executor.execute(
                    ToolExecutionRequest(
                        context=context,
                        tool_name="list_network_listeners",
                        arguments={},
                    )
                )
                if result.status is not ToolExecutionStatus.SUCCESS or result.truncated:
                    raise ValueError("监听证据不完整")
                collection = CollectionResult.model_validate(result.output)
                if collection.availability is not Availability.AVAILABLE:
                    raise ValueError("监听证据不可用")
                listeners = tuple(NetworkListener.model_validate(item) for item in collection.items)
                selected = tuple(
                    item
                    for item in listeners
                    if item.protocol == "tcp" and item.port == self.config.port
                )
                network = tuple(
                    item for item in selected if not ip_address(item.address).is_loopback
                )
                names = {item.process_name for item in selected}
                name = next(iter(names)) if len(names) == 1 else None
                platform = Platform(prepared.node_summary.platform)
                now = datetime.now(UTC)
                self.service = self.service.model_copy(
                    update={
                        "display_name": name[:80] if name else None,
                        "access_address": (network or selected)[0].address if selected else None,
                        "accessibility": ServiceAccessibility.NETWORK
                        if network
                        else ServiceAccessibility.LOOPBACK
                        if selected
                        else ServiceAccessibility.UNKNOWN,
                        "lifecycle": ServiceLifecycle.ACTIVE
                        if selected
                        else ServiceLifecycle.STOPPED,
                        "state": KnownServiceState.AVAILABLE
                        if selected
                        else KnownServiceState.STOPPED,
                        "freshness": OverviewFreshness.LIVE,
                        "evidence_at": now,
                    }
                )
                self.node = self.node.model_copy(
                    update={
                        "display_name": f"已授权 {platform.value} 对端",
                        "platform": platform,
                        "state": KnownNodeState.ONLINE,
                        "freshness": OverviewFreshness.LIVE,
                        "evidence_at": now,
                        "service_count": int(bool(selected)),
                    }
                )
        except (RemotePreparationError, RemoteGatewayError, OSError, ValueError, TimeoutError):
            # 断连、无权限或残缺输出均不能证明服务消失或节点离线。
            self.service = self.service.model_copy(update={"freshness": OverviewFreshness.STALE})
            self.node = self.node.model_copy(
                update={
                    "freshness": OverviewFreshness.STALE,
                    "state": KnownNodeState.STALE,
                }
            )
