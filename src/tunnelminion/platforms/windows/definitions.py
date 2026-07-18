"""Windows MVP 六个只读工具的稳定定义与注册。"""

from __future__ import annotations

from dataclasses import dataclass

from pydantic import JsonValue

from tunnelminion.domain.tools import (
    DataSensitivity,
    Platform,
    RiskLevel,
    ToolDefinition,
)
from tunnelminion.domain.versioning import ProtocolVersion
from tunnelminion.platforms.windows.adapters import (
    DockerServicesAdapter,
    NetworkListenersAdapter,
    NodeSummaryAdapter,
    ProcessSummaryAdapter,
    ServiceReachabilityAdapter,
    WireGuardStatusAdapter,
)
from tunnelminion.tools.registry import ToolRegistry


@dataclass(frozen=True)
class WindowsToolAdapters:
    """六个固定 Windows 适配器的显式集合。"""

    wireguard: WireGuardStatusAdapter
    listeners: NetworkListenersAdapter
    processes: ProcessSummaryAdapter
    docker: DockerServicesAdapter
    reachability: ServiceReachabilityAdapter
    node_summary: NodeSummaryAdapter


def _definition(
    name: str,
    description: str,
    input_schema: dict[str, JsonValue],
    *,
    timeout: float,
    max_bytes: int,
) -> ToolDefinition:
    return ToolDefinition.model_validate(
        {
            "name": name,
            "version": ProtocolVersion(major=1, minor=0),
            "description": description,
            "input_schema": input_schema,
            "output_schema": {"type": "object"},
            "risk_level": RiskLevel.READ_ONLY,
            "platforms": [Platform.WINDOWS],
            "permissions": ["read-system-metadata"],
            "timeout_seconds": timeout,
            "max_result_bytes": max_bytes,
            "data_sensitivity": DataSensitivity.SYSTEM_METADATA,
        }
    )


def register_windows_tools(
    registry: ToolRegistry, adapters: WindowsToolAdapters
) -> tuple[ToolDefinition, ...]:
    """注册 Windows MVP 允许的完整只读工具集。"""
    empty: dict[str, JsonValue] = {
        "type": "object",
        "additionalProperties": False,
    }
    definitions = (
        _definition(
            "get_wireguard_status",
            "读取 HomeMac WireGuard 接口和脱敏 peer 状态。",
            empty,
            timeout=8,
            max_bytes=64_000,
        ),
        _definition(
            "list_network_listeners",
            "列出 TCP 和 UDP 本机监听端点。",
            empty,
            timeout=10,
            max_bytes=256_000,
        ),
        _definition(
            "get_process_summary",
            "返回不含命令行和环境变量的进程摘要。",
            {
                "type": "object",
                "properties": {"limit": {"type": "integer", "minimum": 1, "maximum": 200}},
                "additionalProperties": False,
            },
            timeout=10,
            max_bytes=256_000,
        ),
        _definition(
            "list_docker_services",
            "只读列出容器、镜像、端口和状态。",
            empty,
            timeout=12,
            max_bytes=256_000,
        ),
        _definition(
            "probe_service_reachability",
            "从当前节点测试私有或环回地址的 TCP 可达性。",
            {
                "type": "object",
                "properties": {
                    "host": {"type": "string", "format": "ipv4"},
                    "port": {"type": "integer", "minimum": 1, "maximum": 65535},
                    "timeout_seconds": {"type": "number", "minimum": 0.1, "maximum": 10},
                },
                "required": ["host", "port"],
                "additionalProperties": False,
            },
            timeout=12,
            max_bytes=16_000,
        ),
        _definition(
            "get_node_summary",
            "聚合节点、Agent、模型、WireGuard 和工具状态。",
            empty,
            timeout=10,
            max_bytes=64_000,
        ),
    )
    adapter_values = (
        adapters.wireguard,
        adapters.listeners,
        adapters.processes,
        adapters.docker,
        adapters.reachability,
        adapters.node_summary,
    )
    for definition, adapter in zip(definitions, adapter_values, strict=True):
        registry.register(definition, adapter)
    return definitions
