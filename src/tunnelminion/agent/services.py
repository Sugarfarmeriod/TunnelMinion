"""把远端监听、进程和 Docker 证据合并为确定性服务摘要。"""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime
from enum import StrEnum
from typing import TypeVar

from pydantic import BaseModel, ConfigDict, JsonValue

from tunnelminion.domain.identifiers import NodeId, ToolRunId
from tunnelminion.platforms.windows.models import (
    CollectionResult,
    DockerService,
    NetworkListener,
    ProcessInfo,
    ReachabilityResult,
    WireGuardStatus,
)
from tunnelminion.tools.contracts import ToolExecutionStatus

_PORT_PATTERN = re.compile(
    r"(?:(?P<host>\[[0-9a-fA-F:]+\]|[0-9.]+|\*):)?"
    r"(?P<host_port>\d+)->(?P<container_port>\d+)/(?P<protocol>tcp|udp)"
)
ModelT = TypeVar("ModelT", bound=BaseModel)


class ServiceAccessibility(StrEnum):
    """在主动探测前，仅根据监听范围得出的可访问性分类。"""

    LOCAL_ONLY = "local-only"
    NETWORK_LISTENING = "network-listening"
    UNKNOWN = "unknown"


class EvidenceConfidence(StrEnum):
    """确定性证据交叉印证程度。"""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class ToolObservation(BaseModel):
    """带采集时间与证据 ID 的一次结构化工具观察。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    tool_name: str
    tool_run_id: ToolRunId
    observed_at: datetime
    status: ToolExecutionStatus
    output: JsonValue | None = None


class ServiceEvidence(BaseModel):
    """服务摘要中可回溯的一项来源。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    tool_name: str
    tool_run_id: ToolRunId
    observed_at: datetime


class RemoteServiceSummary(BaseModel):
    """一个远端主机端口及其可获得的进程和容器归属。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    node_id: NodeId
    protocol: str
    address: str
    port: int
    process_pid: int | None = None
    process_name: str | None = None
    container_id: str | None = None
    container_name: str | None = None
    image: str | None = None
    container_port: int | None = None
    accessibility: ServiceAccessibility
    confidence: EvidenceConfidence
    evidence: tuple[ServiceEvidence, ...]


class RemoteServiceInventory(BaseModel):
    """带输入能力降级信息的远端服务清单。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    node_id: NodeId
    services: tuple[RemoteServiceSummary, ...]
    unavailable_sources: tuple[str, ...] = ()


class CrossNodeReachability(StrEnum):
    """综合请求节点探测与远端监听证据后的确定性结论。"""

    REACHABLE = "reachable"
    LOCAL_ONLY = "local-only"
    NODE_UNREACHABLE = "node-unreachable"
    UNREACHABLE = "unreachable"
    NOT_PROBED = "not-probed"


class CrossNodeServiceDiagnostic(BaseModel):
    """一个服务的跨节点可达性结论及完整证据引用。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    service: RemoteServiceSummary
    target_host: str
    reachability: CrossNodeReachability
    explanation: str
    evidence: tuple[ServiceEvidence, ...]


class RemoteServiceInventoryBuilder:
    """使用端口为主键合并监听、进程和 Docker，不依赖模型猜测。"""

    def build(
        self,
        node_id: NodeId,
        listeners: ToolObservation,
        processes: ToolObservation,
        docker: ToolObservation,
    ) -> RemoteServiceInventory:
        listener_values, listener_available = self._items(
            listeners, "list_network_listeners", NetworkListener
        )
        process_values, process_available = self._items(
            processes, "get_process_summary", ProcessInfo
        )
        docker_values, docker_available = self._items(docker, "list_docker_services", DockerService)
        process_by_pid = {item.pid: item for item in process_values}
        published = self._published_ports(docker_values)
        used: set[tuple[str, int, str]] = set()
        services: list[RemoteServiceSummary] = []

        for listener in listener_values:
            process = process_by_pid.get(listener.pid) if listener.pid is not None else None
            container = self._matching_container(listener, published)
            if container is not None:
                used.add((container[1], container[2], container[0].container_id))
            services.append(
                self._from_listener(
                    node_id,
                    listener,
                    process,
                    container,
                    listeners,
                    processes if process is not None else None,
                    docker if container is not None else None,
                )
            )

        for service, protocol, host_port, container_port, host in published:
            if (protocol, host_port, service.container_id) in used:
                continue
            services.append(
                RemoteServiceSummary(
                    node_id=node_id,
                    protocol=protocol,
                    address=host,
                    port=host_port,
                    container_id=service.container_id,
                    container_name=service.name,
                    image=service.image,
                    container_port=container_port,
                    accessibility=self._accessibility(host),
                    confidence=EvidenceConfidence.LOW,
                    evidence=(self._evidence(docker),),
                )
            )

        unavailable = tuple(
            name
            for name, available in (
                ("list_network_listeners", listener_available),
                ("get_process_summary", process_available),
                ("list_docker_services", docker_available),
            )
            if not available
        )
        services.sort(key=lambda item: (item.port, item.protocol, item.address))
        return RemoteServiceInventory(
            node_id=node_id,
            services=tuple(services),
            unavailable_sources=unavailable,
        )

    @staticmethod
    def _items(
        observation: ToolObservation,
        expected_name: str,
        model: type[ModelT],
    ) -> tuple[tuple[ModelT, ...], bool]:
        if observation.tool_name != expected_name:
            raise ValueError(f"期望 {expected_name} 证据，实际为 {observation.tool_name}")
        if observation.status is not ToolExecutionStatus.SUCCESS or observation.output is None:
            return (), False
        value = CollectionResult.model_validate(observation.output)
        available = value.availability.value == "available"
        return tuple(model.model_validate(item) for item in value.items), available

    @staticmethod
    def _published_ports(
        services: tuple[DockerService, ...],
    ) -> tuple[tuple[DockerService, str, int, int, str], ...]:
        values: list[tuple[DockerService, str, int, int, str]] = []
        for candidate in services:
            for match in _PORT_PATTERN.finditer(candidate.ports):
                host = match.group("host") or "0.0.0.0"
                if host == "*":
                    host = "0.0.0.0"
                host = host.strip("[]")
                values.append(
                    (
                        candidate,
                        match.group("protocol"),
                        int(match.group("host_port")),
                        int(match.group("container_port")),
                        host,
                    )
                )
        return tuple(values)

    @staticmethod
    def _matching_container(
        listener: NetworkListener,
        published: tuple[tuple[DockerService, str, int, int, str], ...],
    ) -> tuple[DockerService, str, int, int, str] | None:
        return next(
            (
                item
                for item in published
                if item[1] == listener.protocol and item[2] == listener.port
            ),
            None,
        )

    def _from_listener(
        self,
        node_id: NodeId,
        listener: NetworkListener,
        process: ProcessInfo | None,
        container: tuple[DockerService, str, int, int, str] | None,
        listener_observation: ToolObservation,
        process_observation: ToolObservation | None,
        docker_observation: ToolObservation | None,
    ) -> RemoteServiceSummary:
        docker = container[0] if container is not None else None
        evidence = [self._evidence(listener_observation)]
        if process_observation is not None:
            evidence.append(self._evidence(process_observation))
        if docker_observation is not None:
            evidence.append(self._evidence(docker_observation))
        corroborating = int(process is not None) + int(docker is not None)
        confidence = (
            EvidenceConfidence.HIGH
            if corroborating == 2
            else EvidenceConfidence.MEDIUM
            if corroborating == 1
            else EvidenceConfidence.LOW
        )
        return RemoteServiceSummary(
            node_id=node_id,
            protocol=listener.protocol,
            address=listener.address,
            port=listener.port,
            process_pid=listener.pid,
            process_name=(process.name if process is not None else listener.process_name),
            container_id=docker.container_id if docker is not None else None,
            container_name=docker.name if docker is not None else None,
            image=docker.image if docker is not None else None,
            container_port=container[3] if container is not None else None,
            accessibility=self._accessibility(listener.address),
            confidence=confidence,
            evidence=tuple(evidence),
        )

    @staticmethod
    def _accessibility(address: str) -> ServiceAccessibility:
        try:
            parsed = ipaddress.ip_address(address)
        except ValueError:
            return ServiceAccessibility.UNKNOWN
        return (
            ServiceAccessibility.LOCAL_ONLY
            if parsed.is_loopback
            else ServiceAccessibility.NETWORK_LISTENING
        )

    @staticmethod
    def _evidence(observation: ToolObservation) -> ServiceEvidence:
        return ServiceEvidence(
            tool_name=observation.tool_name,
            tool_run_id=observation.tool_run_id,
            observed_at=observation.observed_at,
        )


class CrossNodeReachabilityAnalyzer:
    """把 A 侧 TCP 探测与 WireGuard、远端监听和容器映射关联。"""

    def analyze(
        self,
        inventory: RemoteServiceInventory,
        target_host: str,
        wireguard: ToolObservation,
        probes: tuple[ToolObservation, ...],
    ) -> tuple[CrossNodeServiceDiagnostic, ...]:
        if wireguard.tool_name != "get_wireguard_status":
            raise ValueError("跨节点诊断需要 get_wireguard_status 证据")
        tunnel_ready = self._tunnel_ready(wireguard, target_host)
        probe_by_port = self._probes(probes, target_host)
        node_reachable = tunnel_ready or any(
            result.reachable for _, result in probe_by_port.values()
        )
        values: list[CrossNodeServiceDiagnostic] = []
        for service in inventory.services:
            probe = probe_by_port.get(service.port) if service.protocol == "tcp" else None
            state, explanation = self._classify(service, probe, node_reachable)
            evidence = [*service.evidence, self._evidence(wireguard)]
            if probe is not None:
                evidence.append(self._evidence(probe[0]))
            values.append(
                CrossNodeServiceDiagnostic(
                    service=service,
                    target_host=target_host,
                    reachability=state,
                    explanation=explanation,
                    evidence=tuple(evidence),
                )
            )
        return tuple(values)

    @staticmethod
    def _tunnel_ready(observation: ToolObservation, target_host: str) -> bool:
        if observation.status is not ToolExecutionStatus.SUCCESS or observation.output is None:
            return False
        status = WireGuardStatus.model_validate(observation.output)
        if status.availability.value != "available" or not status.interface_up:
            return False
        target = ipaddress.ip_address(target_host)
        return any(
            target in ipaddress.ip_network(allowed, strict=False)
            for peer in status.peers
            for allowed in peer.allowed_addresses
        )

    @staticmethod
    def _probes(
        observations: tuple[ToolObservation, ...], target_host: str
    ) -> dict[int, tuple[ToolObservation, ReachabilityResult]]:
        values: dict[int, tuple[ToolObservation, ReachabilityResult]] = {}
        for observation in observations:
            if observation.tool_name != "probe_service_reachability":
                raise ValueError("可达性证据名称不正确")
            if observation.status is not ToolExecutionStatus.SUCCESS or observation.output is None:
                continue
            result = ReachabilityResult.model_validate(observation.output)
            if result.host == target_host:
                values[result.port] = (observation, result)
        return values

    @staticmethod
    def _classify(
        service: RemoteServiceSummary,
        probe: tuple[ToolObservation, ReachabilityResult] | None,
        node_reachable: bool,
    ) -> tuple[CrossNodeReachability, str]:
        if probe is None:
            return CrossNodeReachability.NOT_PROBED, "没有从请求节点获得该 TCP 端口的探测证据"
        if probe[1].reachable:
            return CrossNodeReachability.REACHABLE, "请求节点已通过 TCP 连接确认服务可达"
        if not node_reachable:
            return CrossNodeReachability.NODE_UNREACHABLE, "WireGuard 未确认目标节点路由可用"
        if service.accessibility is ServiceAccessibility.LOCAL_ONLY:
            mapping = "，且容器端口仅发布到环回地址" if service.container_id else ""
            return CrossNodeReachability.LOCAL_ONLY, f"远端服务只监听环回地址{mapping}"
        return CrossNodeReachability.UNREACHABLE, "服务具有网络监听，但请求节点 TCP 探测失败"

    @staticmethod
    def _evidence(observation: ToolObservation) -> ServiceEvidence:
        return ServiceEvidence(
            tool_name=observation.tool_name,
            tool_run_id=observation.tool_run_id,
            observed_at=observation.observed_at,
        )
