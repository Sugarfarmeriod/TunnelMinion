"""安全操作只通过操作协议执行时使用的固定注册定义。"""

from __future__ import annotations

from pydantic import JsonValue

from tunnelminion.domain.errors import ErrorCode, ToolError
from tunnelminion.domain.tools import DataSensitivity, Platform, RiskLevel, ToolDefinition
from tunnelminion.domain.versioning import ProtocolVersion
from tunnelminion.operation.contracts import OperationLevel
from tunnelminion.tools.contracts import (
    ToolAdapterError,
    ToolCancellationToken,
)
from tunnelminion.tools.registry import ToolRegistry

SAFE_HTTP_SHARING_OPERATION = "share_local_http_service"


class _OperationProtocolOnlyAdapter:
    """防止 L2 操作误走普通 Tool Runtime。"""

    async def execute(
        self,
        arguments: dict[str, JsonValue],
        cancellation: ToolCancellationToken,
    ) -> JsonValue:
        del arguments, cancellation
        raise ToolAdapterError(
            ToolError(
                code=ErrorCode.OPERATION_NOT_SUPPORTED,
                message="L2 临时共享只能通过计划、授权和操作协议执行",
            )
        )


def register_safe_http_sharing_operation(
    registry: ToolRegistry,
) -> ToolDefinition:
    """注册确定性 L2 等级，但不向模型或普通工具调用暴露执行能力。"""
    definition = ToolDefinition.model_validate(
        {
            "name": SAFE_HTTP_SHARING_OPERATION,
            "version": ProtocolVersion(major=1, minor=0),
            "description": "为实时确认的环回 HTTP 服务创建限时、限 peer 的私网入口。",
            "input_schema": {
                "type": "object",
                "properties": {},
                "additionalProperties": False,
            },
            "output_schema": {"type": "object"},
            "risk_level": RiskLevel.REQUIRES_APPROVAL,
            "platforms": [Platform.WINDOWS, Platform.MACOS],
            "permissions": ["manage-tunnelminion-owned-http-proxy"],
            "timeout_seconds": 120,
            "max_result_bytes": 64_000,
            "data_sensitivity": DataSensitivity.SYSTEM_METADATA,
        }
    )
    registry.register(
        definition,
        _OperationProtocolOnlyAdapter(),
        operation_level=OperationLevel.L2,
    )
    return definition
