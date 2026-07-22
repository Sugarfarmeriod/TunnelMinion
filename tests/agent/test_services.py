"""远端端口、进程和 Docker 确定性服务摘要测试。"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import cast

import pytest
from pydantic import JsonValue

from tunnelminion.agent.services import (
    CrossNodeReachability,
    CrossNodeReachabilityAnalyzer,
    EvidenceConfidence,
    RemoteServiceInventory,
    RemoteServiceInventoryBuilder,
    RemoteServiceSummary,
    ServiceAccessibility,
    ServiceEvidence,
    ToolObservation,
)
from tunnelminion.domain.identifiers import NodeId, ToolRunId
from tunnelminion.platforms.windows.models import (
    Availability,
    ReachabilityResult,
    WireGuardPeerSummary,
    WireGuardStatus,
)
from tunnelminion.tools.contracts import ToolExecutionStatus


def observation(
    name: str,
    items: list[dict[str, JsonValue]],
    *,
    availability: str = "available",
    status: ToolExecutionStatus = ToolExecutionStatus.SUCCESS,
) -> ToolObservation:
    """创建带固定时间和证据 ID 的集合观察。"""
    return ToolObservation(
        tool_name=name,
        tool_run_id=ToolRunId.new(),
        observed_at=datetime(2026, 7, 18, 8, 0, tzinfo=UTC),
        status=status,
        output=cast(
            JsonValue,
            {"availability": availability, "items": items}
            if status is ToolExecutionStatus.SUCCESS
            else None,
        ),
    )


def test_inventory_correlates_listener_process_and_docker_evidence() -> None:
    listeners = observation(
        "list_network_listeners",
        [
            {
                "protocol": "tcp",
                "address": "127.0.0.1",
                "port": 8080,
                "pid": 10,
                "process_name": "fallback",
            },
            {
                "protocol": "tcp",
                "address": "0.0.0.0",
                "port": 9090,
                "pid": 20,
                "process_name": None,
            },
        ],
    )
    processes = observation(
        "get_process_summary",
        [
            {"pid": 10, "name": "pdf-server", "status": "running"},
            {"pid": 20, "name": "web-server", "status": "running"},
        ],
    )
    docker = observation(
        "list_docker_services",
        [
            {
                "container_id": "pdf",
                "name": "pdf-tools",
                "image": "pdf:latest",
                "ports": "127.0.0.1:8080->80/tcp",
                "status": "Up",
            },
            {
                "container_id": "web",
                "name": "web",
                "image": "web:latest",
                "ports": "[::]:9090->90/tcp, *:9090->90/tcp, :::9090->90/tcp",
                "status": "Up",
            },
            {
                "container_id": "orphan",
                "name": "orphan",
                "image": "orphan:latest",
                "ports": "7070->70/tcp, 70/tcp",
                "status": "Up",
            },
        ],
    )

    inventory = RemoteServiceInventoryBuilder().build(NodeId.new(), listeners, processes, docker)

    assert inventory.unavailable_sources == ()
    assert [item.port for item in inventory.services] == [7070, 8080, 9090]
    orphan, pdf, web = inventory.services
    assert orphan.address == "0.0.0.0"
    assert orphan.confidence is EvidenceConfidence.LOW
    assert len(orphan.evidence) == 1
    assert pdf.process_name == "pdf-server"
    assert pdf.container_name == "pdf-tools"
    assert pdf.container_port == 80
    assert pdf.accessibility is ServiceAccessibility.LOCAL_ONLY
    assert pdf.confidence is EvidenceConfidence.HIGH
    assert len(pdf.evidence) == 3
    assert web.accessibility is ServiceAccessibility.NETWORK_LISTENING
    assert web.image == "web:latest"


def test_inventory_survives_degraded_sources_and_unknown_address() -> None:
    listeners = observation(
        "list_network_listeners",
        [
            {
                "protocol": "udp",
                "address": "localhost",
                "port": 5353,
                "pid": None,
                "process_name": "mdns",
            }
        ],
    )
    processes = observation("get_process_summary", [], status=ToolExecutionStatus.FAILED)
    docker = observation("list_docker_services", [], availability="unavailable")

    inventory = RemoteServiceInventoryBuilder().build(NodeId.new(), listeners, processes, docker)

    assert inventory.unavailable_sources == (
        "get_process_summary",
        "list_docker_services",
    )
    assert inventory.services[0].process_name == "mdns"
    assert inventory.services[0].accessibility is ServiceAccessibility.UNKNOWN
    assert inventory.services[0].confidence is EvidenceConfidence.LOW


def test_inventory_rejects_mislabeled_evidence() -> None:
    wrong = observation("wrong_tool", [])
    valid_processes = observation("get_process_summary", [])
    valid_docker = observation("list_docker_services", [])
    with pytest.raises(ValueError, match="list_network_listeners"):
        RemoteServiceInventoryBuilder().build(NodeId.new(), wrong, valid_processes, valid_docker)


def raw_observation(
    name: str,
    output: JsonValue | None,
    status: ToolExecutionStatus = ToolExecutionStatus.SUCCESS,
) -> ToolObservation:
    return ToolObservation(
        tool_name=name,
        tool_run_id=ToolRunId.new(),
        observed_at=datetime(2026, 7, 18, 9, 0, tzinfo=UTC),
        status=status,
        output=output,
    )


def service(
    node: NodeId,
    port: int,
    accessibility: ServiceAccessibility,
    *,
    protocol: str = "tcp",
    container: bool = False,
) -> RemoteServiceSummary:
    evidence = ServiceEvidence(
        tool_name="list_network_listeners",
        tool_run_id=ToolRunId.new(),
        observed_at=datetime(2026, 7, 18, 9, 0, tzinfo=UTC),
    )
    return RemoteServiceSummary(
        node_id=node,
        protocol=protocol,
        address="127.0.0.1" if accessibility is ServiceAccessibility.LOCAL_ONLY else "0.0.0.0",
        port=port,
        container_id="container" if container else None,
        accessibility=accessibility,
        confidence=EvidenceConfidence.MEDIUM,
        evidence=(evidence,),
    )


def wireguard_observation(*, ready: bool = True, include_peer: bool = True) -> ToolObservation:
    peers = (
        (
            WireGuardPeerSummary(
                public_key_summary="peer…abcd",
                allowed_addresses=("10.77.0.1/32",),
            ),
        )
        if include_peer
        else ()
    )
    value = WireGuardStatus(
        availability=Availability.AVAILABLE if ready else Availability.UNAVAILABLE,
        interface="HomeMac",
        interface_up=ready,
        peers=peers,
    )
    return raw_observation("get_wireguard_status", cast(JsonValue, value.model_dump(mode="json")))


def probe(port: int, reachable: bool, *, host: str = "10.77.0.1") -> ToolObservation:
    value = ReachabilityResult(
        host=host,
        port=port,
        reachable=reachable,
        latency_ms=1.5 if reachable else None,
        error_code=None if reachable else "unreachable",
    )
    return raw_observation(
        "probe_service_reachability", cast(JsonValue, value.model_dump(mode="json"))
    )


def test_cross_node_reachability_correlates_probe_listener_container_and_tunnel() -> None:
    node = NodeId.new()
    inventory = RemoteServiceInventory(
        node_id=node,
        services=(
            service(node, 8080, ServiceAccessibility.LOCAL_ONLY, container=True),
            service(node, 9090, ServiceAccessibility.NETWORK_LISTENING),
            service(
                node,
                5353,
                ServiceAccessibility.NETWORK_LISTENING,
                protocol="udp",
            ),
        ),
    )
    ignored = probe(9090, False, host="10.77.0.99")
    failed = raw_observation("probe_service_reachability", None, ToolExecutionStatus.FAILED)
    diagnostics = CrossNodeReachabilityAnalyzer().analyze(
        inventory,
        "10.77.0.1",
        wireguard_observation(),
        (probe(8080, False), probe(9090, True), ignored, failed),
    )

    assert [item.reachability for item in diagnostics] == [
        CrossNodeReachability.LOCAL_ONLY,
        CrossNodeReachability.REACHABLE,
        CrossNodeReachability.NOT_PROBED,
    ]
    assert "容器端口" in diagnostics[0].explanation
    assert len(diagnostics[0].evidence) == 3


def test_cross_node_reachability_distinguishes_node_and_service_failures() -> None:
    node = NodeId.new()
    inventory = RemoteServiceInventory(
        node_id=node,
        services=(service(node, 9090, ServiceAccessibility.NETWORK_LISTENING),),
    )
    analyzer = CrossNodeReachabilityAnalyzer()

    down = analyzer.analyze(
        inventory, "10.77.0.1", wireguard_observation(ready=False), (probe(9090, False),)
    )
    assert down[0].reachability is CrossNodeReachability.NODE_UNREACHABLE

    no_peer = analyzer.analyze(
        inventory,
        "10.77.0.1",
        wireguard_observation(include_peer=False),
        (probe(9090, False),),
    )
    assert no_peer[0].reachability is CrossNodeReachability.NODE_UNREACHABLE

    service_down = analyzer.analyze(
        inventory, "10.77.0.1", wireguard_observation(), (probe(9090, False),)
    )
    assert service_down[0].reachability is CrossNodeReachability.UNREACHABLE

    failed_wg = raw_observation("get_wireguard_status", None, ToolExecutionStatus.FAILED)
    unknown_tunnel = analyzer.analyze(inventory, "10.77.0.1", failed_wg, (probe(9090, False),))
    assert unknown_tunnel[0].reachability is CrossNodeReachability.NODE_UNREACHABLE


def test_successful_peer_port_proves_node_online_when_wireguard_stats_are_hidden() -> None:
    """权限不足时，任一成功 TCP 证据可避免把其他失败端口误判成整机离线。"""
    node = NodeId.new()
    inventory = RemoteServiceInventory(
        node_id=node,
        services=(
            service(node, 80, ServiceAccessibility.NETWORK_LISTENING),
            service(node, 5984, ServiceAccessibility.NETWORK_LISTENING),
        ),
    )
    hidden_stats = raw_observation("get_wireguard_status", None, ToolExecutionStatus.FAILED)

    diagnostics = CrossNodeReachabilityAnalyzer().analyze(
        inventory,
        "10.77.0.1",
        hidden_stats,
        (probe(80, False), probe(5984, True)),
    )

    assert diagnostics[0].reachability is CrossNodeReachability.UNREACHABLE
    assert diagnostics[1].reachability is CrossNodeReachability.REACHABLE


def test_cross_node_reachability_rejects_mislabeled_inputs() -> None:
    node = NodeId.new()
    inventory = RemoteServiceInventory(node_id=node, services=())
    analyzer = CrossNodeReachabilityAnalyzer()
    with pytest.raises(ValueError, match="get_wireguard_status"):
        analyzer.analyze(inventory, "10.77.0.1", raw_observation("wrong", {}), ())

    inventory = RemoteServiceInventory(
        node_id=node,
        services=(service(node, 8080, ServiceAccessibility.LOCAL_ONLY),),
    )
    with pytest.raises(ValueError, match="名称不正确"):
        analyzer.analyze(
            inventory,
            "10.77.0.1",
            wireguard_observation(),
            (raw_observation("wrong_probe", {}),),
        )
