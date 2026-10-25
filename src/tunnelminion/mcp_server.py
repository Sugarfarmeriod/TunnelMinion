"""通过 MCP stdio 开放本机只读诊断工具。"""

from __future__ import annotations

import json
import os
import sys
from importlib.metadata import version
from pathlib import Path
from typing import cast

from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server
from mcp.types import CallToolResult, TextContent, Tool
from pydantic import JsonValue

from tunnelminion.agent.managed_node import ServiceObservationConfig
from tunnelminion.agent.service_marks import ServiceMarkStore
from tunnelminion.agent.service_observation import DeterministicServiceObserver
from tunnelminion.app import build_windows_node
from tunnelminion.domain.delegation import DELEGATE_TOOL_NAME
from tunnelminion.domain.errors import ErrorCode, ToolError
from tunnelminion.domain.identifiers import NodeId, RunId, ThreadId
from tunnelminion.domain.tools import DataSensitivity, Platform, RiskLevel, ToolDefinition
from tunnelminion.domain.versioning import ProtocolVersion
from tunnelminion.memory.sqlite import SQLiteStores
from tunnelminion.repair.contracts import REPAIR_TOOL_NAMES
from tunnelminion.tools.contracts import (
    ToolCallContext,
    ToolCancellationToken,
    ToolExecutionRequest,
)
from tunnelminion.web.service_map import LocalServiceMap, build_local_service_map

_DENIED_TOOLS = frozenset({DELEGATE_TOOL_NAME, "propose_repair", *REPAIR_TOOL_NAMES.values()})


class _LocalServicesAdapter:
    def __init__(
        self, node_id: NodeId, observer: DeterministicServiceObserver, marks: ServiceMarkStore
    ) -> None:
        self._node_id = node_id
        self._observer = observer
        self._marks = marks

    async def execute(
        self, arguments: dict[str, JsonValue], cancellation: ToolCancellationToken
    ) -> JsonValue:
        snapshot = self._observer.last_snapshot or await self._observer.observe()
        return cast(
            JsonValue,
            build_local_service_map(
                self._node_id, snapshot, self._marks.all(), excluded_pid=os.getpid()
            ).model_dump(mode="json"),
        )


def build_mcp_server(data_dir: Path | None = None) -> Server:
    """复用平台节点及其工具执行边界。"""
    if sys.platform == "darwin":
        from tunnelminion.macos_app import _build_macos_node  # pyright: ignore[reportPrivateUsage]

        node = _build_macos_node(data_dir)
        stores = SQLiteStores.open(node.root / "runtime.sqlite3")
        platform = Platform.MACOS
    else:
        node = build_windows_node(data_dir)
        stores = node.stores
        platform = Platform.WINDOWS

    observer = DeterministicServiceObserver(
        node.node_id,
        ServiceObservationConfig(),
        node.listeners,
        node.processes,
        node.docker,
        marks=stores.service_marks.all,
    )
    node.tool_registry.register(
        ToolDefinition(
            name="list_local_services",
            version=ProtocolVersion(major=1, minor=0),
            description="返回本机服务清单、入口和用户标记。",
            input_schema={"type": "object", "additionalProperties": False},
            output_schema=LocalServiceMap.model_json_schema(),
            risk_level=RiskLevel.READ_ONLY,
            platforms=frozenset({platform}),
            timeout_seconds=12,
            max_result_bytes=262_144,
            data_sensitivity=DataSensitivity.SYSTEM_METADATA,
        ),
        _LocalServicesAdapter(node.node_id, observer, stores.service_marks),
    )
    allowed = {
        definition.name: definition
        for definition in node.tool_registry.model_tools(platform)
        if definition.risk_level is RiskLevel.READ_ONLY and definition.name not in _DENIED_TOOLS
    }
    server = Server("tunnelminion", version=version("tunnelminion"))
    thread_id = ThreadId.new()

    @server.list_tools()
    async def list_tools() -> list[Tool]:
        return [
            Tool(
                name=definition.name,
                description=definition.description,
                inputSchema=definition.input_schema,
            )
            for definition in allowed.values()
        ]

    @server.call_tool(validate_input=False)
    async def call_tool(name: str, arguments: dict[str, JsonValue]) -> CallToolResult:
        try:
            if name not in allowed:
                error = ToolError(code=ErrorCode.TOOL_NOT_FOUND, message="工具未开放")
                output = None
            else:
                result = await node.tool_runtime.execute(
                    ToolExecutionRequest(
                        context=ToolCallContext(
                            thread_id=thread_id,
                            run_id=RunId.new(),
                            caller_node_id=node.node_id,
                            execution_node_id=node.node_id,
                        ),
                        tool_name=name,
                        arguments=arguments,
                    )
                )
                error = result.error
                output = result.output
        except Exception:
            error = ToolError(code=ErrorCode.INTERNAL, message="工具执行失败")
            output = None
        payload = {"code": error.code.value, "message": error.message} if error else output
        return CallToolResult(
            content=[
                TextContent(
                    type="text", text=json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
                )
            ],
            isError=error is not None,
        )

    _ = list_tools, call_tool
    return server


async def run_mcp_server(data_dir: Path | None = None) -> None:
    """只使用标准输入输出传输，不启动监听端口。"""
    server = build_mcp_server(data_dir)
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())
