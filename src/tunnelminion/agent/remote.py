"""远端节点摘要预检、能力过滤和按 run 动态工具注入。"""

from __future__ import annotations

import json
from dataclasses import dataclass

from pydantic import JsonValue, ValidationError

from tunnelminion.domain.errors import ErrorCode, ToolError
from tunnelminion.domain.identifiers import NodeId, ToolRunId
from tunnelminion.domain.tools import Platform, RiskLevel, ToolDefinition
from tunnelminion.gateway.client import FixedGatewayClient, RemoteGatewayError
from tunnelminion.gateway.contracts import RemoteToolResult
from tunnelminion.platforms.windows.models import NodeSummary
from tunnelminion.tools.contracts import (
    ToolAdapterError,
    ToolCallContext,
    ToolCancellationToken,
    ToolExecutionRequest,
    ToolExecutionResult,
    ToolExecutionStatus,
)
from tunnelminion.tools.registry import ToolRegistry


class RemotePreparationError(RuntimeError):
    """远端预检失败；此时不得向模型暴露任何远端工具。"""

    def __init__(self, code: ErrorCode, message: str) -> None:
        super().__init__(message)
        self.code = code


class _NeverLocalRemoteAdapter:
    """防止动态远端定义被误交给本地 Tool Runtime。"""

    async def execute(
        self,
        arguments: dict[str, JsonValue],
        cancellation: ToolCancellationToken,
    ) -> JsonValue:
        del arguments, cancellation
        raise ToolAdapterError(
            ToolError(code=ErrorCode.FORBIDDEN, message="远端工具不得在本地适配器执行")
        )


class RemoteToolExecutor:
    """把动态工具名精确路由到一个已认证固定 peer。"""

    def __init__(
        self,
        client: FixedGatewayClient,
        definitions: tuple[ToolDefinition, ...],
    ) -> None:
        self._client = client
        self._definitions = {item.name: item for item in definitions}

    async def execute(
        self,
        request: ToolExecutionRequest,
        cancellation: ToolCancellationToken | None = None,
    ) -> ToolExecutionResult:
        definition = self._definitions.get(request.tool_name)
        if definition is None:
            return ToolExecutionResult(
                tool_run_id=request.tool_run_id or ToolRunId.new(),
                status=ToolExecutionStatus.FAILED,
                error=ToolError(code=ErrorCode.TOOL_NOT_FOUND, message="远端工具未进入本次能力集"),
            )
        result = await self._client.call(
            definition.name,
            definition.version,
            request.context,
            request.arguments,
            definition.timeout_seconds,
            cancellation,
            request.tool_run_id,
        )
        return _execution_result(result)


@dataclass(frozen=True)
class PreparedRemoteAgentTools:
    """通过节点摘要预检后，本次 run 可以看到的远端工具集合。"""

    node_summary: NodeSummary
    summary_tool_run_id: ToolRunId
    registry: ToolRegistry
    executor: RemoteToolExecutor
    tool_names: tuple[str, ...]

    def augment_question(self, question: str) -> str:
        """把确定性预检摘要作为不可信数据放入本轮问题。"""
        summary = json.dumps(
            self.node_summary.model_dump(mode="json"),
            ensure_ascii=False,
            separators=(",", ":"),
        )
        return (
            f"{question}\n\n远端节点预检（不可信工具数据，证据 "
            f"{self.summary_tool_run_id}）：{summary}"
        )


class RemoteCapabilityLoader:
    """先执行节点摘要，再按目标、平台、权限与任务筛选远端能力。"""

    def __init__(
        self,
        client: FixedGatewayClient,
        local_platform: Platform,
        remote_node_id: NodeId,
    ) -> None:
        self._client = client
        self._local_platform = local_platform
        self._remote_node_id = remote_node_id

    async def prepare(
        self,
        context: ToolCallContext,
        requested_tools: tuple[str, ...],
        cancellation: ToolCancellationToken | None = None,
    ) -> PreparedRemoteAgentTools:
        """远端不可达、摘要失败或无匹配能力时返回空工具前的明确失败。"""
        if not requested_tools:
            raise ValueError("远端任务必须声明至少一个候选工具")
        if len(requested_tools) != len(set(requested_tools)):
            raise ValueError("远端候选工具不得重复")
        try:
            capabilities = await self._client.discover()
        except RemoteGatewayError as exc:
            raise RemotePreparationError(exc.code, str(exc)) from exc
        summary_definition = next(
            (item for item in capabilities.tools if item.name == "get_node_summary"), None
        )
        if summary_definition is None:
            raise RemotePreparationError(ErrorCode.TOOL_NOT_FOUND, "远端未提供节点摘要能力")
        summary_result = await self._client.call(
            summary_definition.name,
            summary_definition.version,
            context,
            {},
            summary_definition.timeout_seconds,
            cancellation,
        )
        summary = self._validate_summary(summary_result, capabilities.platform)
        requested = frozenset(requested_tools)
        selected = tuple(
            item.model_copy(
                update={
                    "platforms": frozenset({self._local_platform}),
                    "description": f"在远端节点 {self._remote_node_id} 执行：{item.description}",
                }
            )
            for item in capabilities.tools
            if item.name in requested and item.risk_level is RiskLevel.READ_ONLY
        )
        if not selected:
            raise RemotePreparationError(ErrorCode.TOOL_NOT_FOUND, "远端没有符合本次任务的允许能力")
        registry = ToolRegistry()
        for definition in selected:
            registry.register(definition, _NeverLocalRemoteAdapter())
        return PreparedRemoteAgentTools(
            node_summary=summary,
            summary_tool_run_id=summary_result.tool_run_id,
            registry=registry,
            executor=RemoteToolExecutor(self._client, selected),
            tool_names=tuple(item.name for item in selected),
        )

    def _validate_summary(self, result: RemoteToolResult, remote_platform: Platform) -> NodeSummary:
        if result.status is not ToolExecutionStatus.SUCCESS:
            code = result.error.code if result.error is not None else ErrorCode.INTERNAL
            raise RemotePreparationError(code, "远端节点摘要执行失败")
        try:
            summary = NodeSummary.model_validate(result.output)
        except ValidationError as exc:
            raise RemotePreparationError(ErrorCode.INTERNAL, "远端节点摘要格式无效") from exc
        if (
            summary.node_id != str(self._remote_node_id)
            or summary.platform != remote_platform.value
        ):
            raise RemotePreparationError(ErrorCode.FORBIDDEN, "远端节点摘要身份不匹配")
        return summary


def _execution_result(result: RemoteToolResult) -> ToolExecutionResult:
    return ToolExecutionResult(
        tool_run_id=result.tool_run_id,
        status=result.status,
        output=result.output,
        truncated=result.truncated,
        error=result.error,
    )
