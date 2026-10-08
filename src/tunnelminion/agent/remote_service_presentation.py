"""为目录中已授权的远端服务补充短期归属，不改变目录或访问权限。"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import cast

from pydantic import JsonValue

from tunnelminion.agent.coordinator import CoordinatorCache
from tunnelminion.agent.remote import RemotePreparationError
from tunnelminion.agent.service_observation import (
    compute_observed_service_id,
    select_service_display_names,
)
from tunnelminion.agent.services import RemoteServiceInventoryBuilder, ToolObservation
from tunnelminion.coordinator.contracts import (
    DirectoryFreshness,
    DirectoryNodeSummary,
    NodeStatus,
    ServiceLifecycle,
    ServiceProtocol,
)
from tunnelminion.domain.identifiers import NodeId, RunId, ThreadId, ToolRunId
from tunnelminion.gateway.client import RemoteGatewayError
from tunnelminion.incident.investigation import InvestigationRemoteToolPreparer
from tunnelminion.platforms.windows.models import Availability, CollectionResult
from tunnelminion.tools.contracts import (
    ToolCallContext,
    ToolCancellationToken,
    ToolExecutionRequest,
    ToolExecutionStatus,
)


class RemoteServicePresentationObserver:
    """复用已授权的只读工具；前端 GET 只读内存，不触发远端请求。"""

    def __init__(
        self,
        local_node_id: NodeId,
        cache: CoordinatorCache,
        preparer: InvestigationRemoteToolPreparer,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._local_node_id = local_node_id
        self._cache = cache
        self._preparer = preparer
        self._clock = clock or (lambda: datetime.now(UTC))
        self._observations: dict[str, tuple[datetime, dict[str, str]]] = {}
        self._offset = 0

    def _nodes(self) -> tuple[DirectoryNodeSummary, ...]:
        cached = self._cache.read()
        if cached is None or not cached.is_fresh(self._clock()):
            return ()
        return tuple(
            node
            for node in cached.nodes
            if node.identity.node_id != self._local_node_id
            and node.status is NodeStatus.ONLINE
            and node.freshness is DirectoryFreshness.FRESH
            and self._service_ids(node)
        )

    @staticmethod
    def _service_ids(node: DirectoryNodeSummary) -> set[str]:
        return {
            str(service.service_id)
            for service in node.services
            if service.protocol is ServiceProtocol.TCP
            and service.lifecycle is ServiceLifecycle.ACTIVE
            and service.service_id
            == compute_observed_service_id(
                node.identity.node_id, service.protocol, service.host, service.port
            )
        }

    def names(self) -> dict[tuple[str, str], str]:
        """离线、过期、停止或身份不符时立即撤掉名称，不升级服务状态。"""
        now = self._clock()
        names: dict[tuple[str, str], str] = {}
        for node in self._nodes():
            node_id = str(node.identity.node_id)
            observation = self._observations.get(node_id)
            if observation is None or now - observation[0] >= timedelta(seconds=90):
                continue
            allowed = self._service_ids(node)
            names.update(
                ((node_id, service_id), name)
                for service_id, name in observation[1].items()
                if service_id in allowed
            )
        return names

    async def refresh(self) -> None:
        """每轮最多四个节点，每节点十秒；失败清除旧名称。"""
        nodes = self._nodes()
        eligible = {str(node.identity.node_id) for node in nodes}
        self._observations = {
            key: value for key, value in self._observations.items() if key in eligible
        }
        if not nodes:
            return
        # ponytail: 每轮上限四个节点；更大目录先按实测调整预算，不新增调度框架。
        start = self._offset % len(nodes)
        selected = (nodes[start:] + nodes[:start])[:4]
        self._offset = (start + len(selected)) % len(nodes)
        await asyncio.gather(*(self._refresh_node(node) for node in selected))

    async def _refresh_node(self, node: DirectoryNodeSummary) -> None:
        node_id = node.identity.node_id
        try:
            async with asyncio.timeout(10):
                context = ToolCallContext(
                    thread_id=ThreadId.new(),
                    run_id=RunId.new(),
                    caller_node_id=self._local_node_id,
                    execution_node_id=node_id,
                )
                cancellation = ToolCancellationToken()
                prepared = await self._preparer.prepare(
                    node_id,
                    context,
                    ("list_network_listeners", "list_docker_services"),
                    cancellation,
                )
                if (
                    prepared.node_summary.node_id != str(node_id)
                    or prepared.node_summary.platform != node.identity.platform.value
                    or "list_network_listeners" not in prepared.tool_names
                ):
                    raise ValueError("远端身份或监听能力不匹配")
                observations: dict[str, ToolObservation] = {}
                for name in ("list_network_listeners", "list_docker_services"):
                    collection = CollectionResult(availability=Availability.UNAVAILABLE)
                    tool_run_id = ToolRunId.new()
                    if name in prepared.tool_names:
                        result = await prepared.executor.execute(
                            ToolExecutionRequest(context=context, tool_name=name), cancellation
                        )
                        if result.status is not ToolExecutionStatus.SUCCESS or result.truncated:
                            raise ValueError("远端归属证据不完整")
                        collection = CollectionResult.model_validate(result.output)
                        if len(collection.items) > 1024:
                            raise ValueError("远端归属证据超过预算")
                        tool_run_id = result.tool_run_id
                    if collection.availability is not Availability.AVAILABLE:
                        if name == "list_network_listeners":
                            raise ValueError("远端监听不可用")
                        collection = CollectionResult(availability=Availability.UNAVAILABLE)
                    observations[name] = ToolObservation(
                        tool_name=name,
                        tool_run_id=tool_run_id,
                        observed_at=self._clock(),
                        status=ToolExecutionStatus.SUCCESS,
                        output=cast(JsonValue, collection.model_dump(mode="json")),
                    )
                # 监听结果已经携带进程归属，不额外调用进程列表或读取启动参数。
                processes = ToolObservation(
                    tool_name="get_process_summary",
                    tool_run_id=ToolRunId.new(),
                    observed_at=self._clock(),
                    status=ToolExecutionStatus.SUCCESS,
                    output=cast(
                        JsonValue,
                        CollectionResult(availability=Availability.AVAILABLE).model_dump(
                            mode="json"
                        ),
                    ),
                )
                inventory = RemoteServiceInventoryBuilder().build(
                    node_id,
                    observations["list_network_listeners"],
                    processes,
                    observations["list_docker_services"],
                )
                allowed = self._service_ids(node)
                names = select_service_display_names(node_id, inventory.services)
                self._observations[str(node_id)] = (
                    self._clock(),
                    {key: value for key, value in names.items() if key in allowed},
                )
        except (RemotePreparationError, RemoteGatewayError, OSError, ValueError, TimeoutError):
            self._observations.pop(str(node_id), None)
