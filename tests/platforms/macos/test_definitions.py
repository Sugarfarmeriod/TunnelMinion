"""macOS 六工具注册与命令路径测试。"""

from __future__ import annotations

import pytest
from tests.platforms.macos.test_adapters import FakeMacReader, successful_runner

from tunnelminion.domain.identifiers import NodeId
from tunnelminion.domain.tools import Platform, RiskLevel
from tunnelminion.platforms.macos import register_macos_tools
from tunnelminion.platforms.macos.adapters import (
    DockerServicesAdapter,
    MacOSNodeSummaryAdapter,
    MacOSWireGuardStatusAdapter,
    NetworkListenersAdapter,
    ProcessSummaryAdapter,
    ServiceReachabilityAdapter,
)
from tunnelminion.platforms.macos.definitions import MacOSToolAdapters
from tunnelminion.platforms.macos.system import default_docker_path, default_wg_path
from tunnelminion.tools.registry import ToolRegistry


def test_registers_exact_macos_read_only_tool_set() -> None:
    """macOS 仅注册与 Windows 同构的六个只读能力。"""
    reader = FakeMacReader()
    runner = successful_runner()
    registry = ToolRegistry()
    wireguard = MacOSWireGuardStatusAdapter(reader, runner, "wg")
    adapters = MacOSToolAdapters(
        wireguard=wireguard,
        listeners=NetworkListenersAdapter(reader),
        processes=ProcessSummaryAdapter(reader),
        docker=DockerServicesAdapter(runner, "docker"),
        reachability=ServiceReachabilityAdapter(),
        node_summary=MacOSNodeSummaryAdapter(
            NodeId.new(), registry, wireguard, lambda: "unconfigured"
        ),
    )

    definitions = register_macos_tools(registry, adapters)

    assert [item.name for item in definitions] == [
        "get_wireguard_status",
        "list_network_listeners",
        "get_process_summary",
        "list_docker_services",
        "probe_service_reachability",
        "get_node_summary",
    ]
    assert all(item.risk_level is RiskLevel.READ_ONLY for item in definitions)
    assert all(item.platforms == {Platform.MACOS} for item in definitions)
    assert registry.model_tools(Platform.MACOS) == definitions


def test_macos_command_paths_prefer_path_and_have_safe_fallbacks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CLI 路径可适配 Homebrew/Intel，同时始终是固定 argv 而非 Shell。"""

    def custom_path(name: str) -> str:
        return f"/custom/{name}"

    def missing_path(_name: str) -> None:
        return None

    monkeypatch.setattr(
        "tunnelminion.platforms.macos.system.shutil.which",
        custom_path,
    )
    assert default_wg_path() == "/custom/wg"
    assert default_docker_path() == "/custom/docker"

    monkeypatch.setattr("tunnelminion.platforms.macos.system.shutil.which", missing_path)
    assert default_wg_path() == "/opt/homebrew/bin/wg"
    assert default_docker_path() == "/usr/local/bin/docker"
