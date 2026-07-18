"""Windows 工具完整注册测试。"""

from __future__ import annotations

from tests.platforms.windows.test_adapters import FakeReader, FakeRunner, command_result

from tunnelminion.domain.identifiers import NodeId
from tunnelminion.domain.tools import Platform, RiskLevel
from tunnelminion.platforms.windows.adapters import (
    DockerServicesAdapter,
    NetworkListenersAdapter,
    NodeSummaryAdapter,
    ProcessSummaryAdapter,
    ServiceReachabilityAdapter,
    WireGuardStatusAdapter,
)
from tunnelminion.platforms.windows.definitions import (
    WindowsToolAdapters,
    register_windows_tools,
)
from tunnelminion.tools.registry import ToolRegistry


def test_registers_exact_windows_read_only_tool_set() -> None:
    reader = FakeReader()
    runner = FakeRunner(
        {
            "peers": command_result(),
            "allowed-ips": command_result(),
            "endpoints": command_result(),
            "latest-handshakes": command_result(),
            "transfer": command_result(),
            "{{json .}}": command_result(),
        }
    )
    registry = ToolRegistry()
    wireguard = WireGuardStatusAdapter(reader, runner, "wg.exe")
    adapters = WindowsToolAdapters(
        wireguard=wireguard,
        listeners=NetworkListenersAdapter(reader),
        processes=ProcessSummaryAdapter(reader),
        docker=DockerServicesAdapter(runner, "docker.exe"),
        reachability=ServiceReachabilityAdapter(),
        node_summary=NodeSummaryAdapter(NodeId.new(), registry, wireguard, lambda: "available"),
    )
    definitions = register_windows_tools(registry, adapters)
    assert [item.name for item in definitions] == [
        "get_wireguard_status",
        "list_network_listeners",
        "get_process_summary",
        "list_docker_services",
        "probe_service_reachability",
        "get_node_summary",
    ]
    assert all(item.risk_level is RiskLevel.READ_ONLY for item in definitions)
    assert all(item.platforms == {Platform.WINDOWS} for item in definitions)
    assert registry.model_tools(Platform.WINDOWS) == definitions
