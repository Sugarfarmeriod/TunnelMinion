"""工具注册表与只读暴露策略测试。"""

from __future__ import annotations

import pytest
from pydantic import JsonValue

from tunnelminion.domain.tools import (
    DataSensitivity,
    Platform,
    RiskLevel,
    ToolDefinition,
)
from tunnelminion.domain.versioning import ProtocolVersion
from tunnelminion.tools.fakes import FakeToolAdapter
from tunnelminion.tools.registry import ToolRegistry


def definition(
    name: str,
    risk: RiskLevel = RiskLevel.READ_ONLY,
    *,
    platforms: frozenset[Platform] = frozenset({Platform.WINDOWS}),
    input_schema: dict[str, JsonValue] | None = None,
    output_schema: dict[str, JsonValue] | None = None,
) -> ToolDefinition:
    """返回可复用的测试工具定义。"""
    return ToolDefinition(
        name=name,
        version=ProtocolVersion(major=1, minor=0),
        description="测试工具。",
        input_schema=input_schema or {"type": "object", "additionalProperties": False},
        output_schema=output_schema or {"type": "object"},
        risk_level=risk,
        platforms=platforms,
        permissions=("read-system",),
        timeout_seconds=1,
        max_result_bytes=1024,
        data_sensitivity=DataSensitivity.SYSTEM_METADATA,
    )


def test_registry_lists_capabilities_but_only_exposes_read_only_tools() -> None:
    registry = ToolRegistry()
    adapter = FakeToolAdapter()
    registry.register(definition("read_status"), adapter)
    registry.register(definition("restart_service", RiskLevel.REQUIRES_APPROVAL), adapter)
    registry.register(definition("run_command", RiskLevel.FORBIDDEN), adapter)
    registry.register(definition("mac_status", platforms=frozenset({Platform.MACOS})), adapter)

    assert [item.name for item in registry.capabilities(Platform.WINDOWS)] == [
        "read_status",
        "restart_service",
        "run_command",
    ]
    assert [item.name for item in registry.model_tools(Platform.WINDOWS)] == ["read_status"]
    assert registry.lookup("invented_tool") is None
    assert registry.lookup("read_status") is not None


def test_registry_rejects_duplicate_and_invalid_schemas() -> None:
    registry = ToolRegistry()
    adapter = FakeToolAdapter()
    registry.register(definition("read_status"), adapter)
    with pytest.raises(ValueError, match="已注册"):
        registry.register(definition("read_status"), adapter)

    with pytest.raises(ValueError, match="Schema"):
        registry.register(
            definition("bad_input", input_schema={"type": "not-a-json-type"}),
            adapter,
        )
    with pytest.raises(ValueError, match="Schema"):
        registry.register(
            definition("bad_output", output_schema={"type": "not-a-json-type"}),
            adapter,
        )
