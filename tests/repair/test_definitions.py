"""修法只登记能力，不暴露普通工具执行入口。"""

import asyncio

import pytest

from tunnelminion.domain.errors import ErrorCode
from tunnelminion.domain.tools import Platform, RiskLevel
from tunnelminion.operation.contracts import OperationLevel
from tunnelminion.repair.contracts import REPAIR_TOOL_NAMES
from tunnelminion.repair.definitions import register_repair_operations
from tunnelminion.tools.contracts import ToolAdapterError, ToolCancellationToken
from tunnelminion.tools.registry import ToolRegistry


def test_repair_capabilities_are_l2_and_not_model_tools() -> None:
    registry = ToolRegistry()
    definitions = register_repair_operations(registry)
    assert tuple(item.name for item in definitions) == tuple(REPAIR_TOOL_NAMES.values())
    for platform in (Platform.WINDOWS, Platform.MACOS):
        assert registry.capabilities(platform) == definitions
        assert registry.model_tools(platform) == ()
    for definition in definitions:
        entry = registry.lookup(definition.name)
        assert entry is not None
        assert entry.operation_level is OperationLevel.L2
        assert definition.risk_level is RiskLevel.REQUIRES_APPROVAL
        assert definition.input_schema == {
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        }
        with pytest.raises(ToolAdapterError) as caught:
            asyncio.run(entry.adapter.execute({}, ToolCancellationToken()))
        assert caught.value.error.code is ErrorCode.OPERATION_NOT_SUPPORTED
