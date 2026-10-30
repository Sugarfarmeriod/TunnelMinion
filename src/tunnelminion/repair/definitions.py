"""只允许修复流程执行的固定 L2 能力。"""

from __future__ import annotations

from pydantic import JsonValue

from tunnelminion.domain.errors import ErrorCode, ToolError
from tunnelminion.domain.tools import DataSensitivity, Platform, RiskLevel, ToolDefinition
from tunnelminion.domain.versioning import ProtocolVersion
from tunnelminion.operation.contracts import OperationLevel
from tunnelminion.repair.contracts import REPAIR_TOOL_NAMES, RepairKind
from tunnelminion.tools.contracts import ToolAdapterError, ToolCancellationToken
from tunnelminion.tools.registry import ToolRegistry


class _RepairProtocolOnlyAdapter:
    async def execute(
        self, arguments: dict[str, JsonValue], cancellation: ToolCancellationToken
    ) -> JsonValue:
        raise ToolAdapterError(
            ToolError(
                code=ErrorCode.OPERATION_NOT_SUPPORTED,
                message="这种修法不适用于这个服务。",
            )
        )


def register_repair_operations(registry: ToolRegistry) -> tuple[ToolDefinition, ...]:
    descriptions = {
        RepairKind.RESTART_CONTAINERS: (
            "重启 Docker 容器或 compose 组，只能经本机批准后由修复流程执行。"
        ),
        RepairKind.RELAUNCH_PYTHON: (
            "按启动记录在后台重新拉起已退出的 Python 脚本，只能经本机批准后由修复流程执行。"
        ),
        RepairKind.RESTART_LAUNCH_AGENT: (
            "用 launchctl kickstart 重新启动当前用户已经退出或卡住的 macOS 后台服务，"
            "只能经本机批准后由修复流程执行。"
        ),
        RepairKind.RELAUNCH_PROGRAM: (
            "按启动记录在后台重新运行已退出的普通程序，只能经本机批准后由修复流程执行。"
        ),
        RepairKind.RESTART_STUCK_PROGRAM: (
            "结束巡检确认卡住的程序再按启动记录重新运行，只能经本机批准后由修复流程执行。"
        ),
        RepairKind.RESTART_WINDOWS_SERVICE: (
            "启动或重启主人单独授权过的 Windows 服务，只能经本机批准后由修复流程执行。"
        ),
    }
    definitions: list[ToolDefinition] = []
    for kind, name in REPAIR_TOOL_NAMES.items():
        definition = ToolDefinition(
            name=name,
            version=ProtocolVersion(major=1, minor=0),
            description=descriptions[kind],
            input_schema={"type": "object", "properties": {}, "additionalProperties": False},
            output_schema={"type": "object"},
            risk_level=RiskLevel.REQUIRES_APPROVAL,
            platforms=frozenset({Platform.WINDOWS, Platform.MACOS}),
            permissions=(),
            timeout_seconds=120,
            max_result_bytes=64_000,
            data_sensitivity=DataSensitivity.SYSTEM_METADATA,
        )
        registry.register(
            definition, _RepairProtocolOnlyAdapter(), operation_level=OperationLevel.L2
        )
        definitions.append(definition)
    return tuple(definitions)
