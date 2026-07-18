"""使用假模型完成本地 A 节点多工具诊断端到端场景。"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Coroutine
from typing import Any, TypeVar

from pydantic import JsonValue

from tunnelminion.agent.conversation import (
    InMemoryConversationService,
    RunEvent,
    RunStatus,
    RunView,
    StartRunInput,
)
from tunnelminion.agent.langchain_model import TunnelMinionChatModel
from tunnelminion.agent.runtime import LangChainReadOnlyAgent
from tunnelminion.domain.identifiers import NodeId
from tunnelminion.domain.tools import DataSensitivity, Platform, RiskLevel, ToolDefinition
from tunnelminion.domain.versioning import ProtocolVersion
from tunnelminion.model.contracts import (
    CancellationToken,
    ModelCapabilities,
    ModelRequest,
    ModelResponse,
    ModelUsage,
    ToolCall,
)
from tunnelminion.tools.audit import InMemoryAuditSink
from tunnelminion.tools.contracts import ToolCancellationToken
from tunnelminion.tools.registry import ToolRegistry
from tunnelminion.tools.runtime import ToolRuntime

T = TypeVar("T")


def run(coroutine: Coroutine[Any, Any, T]) -> T:
    """执行异步端到端场景。"""
    return asyncio.run(coroutine)


class LocalDiagnosticProvider:
    """首轮并行查询三项状态，次轮生成固定证据回答。"""

    def __init__(self) -> None:
        self.requests: list[ModelRequest] = []

    @property
    def capabilities(self) -> ModelCapabilities:
        return ModelCapabilities(tool_calls=True, structured_output=True)

    async def complete(
        self,
        request: ModelRequest,
        cancellation: CancellationToken | None = None,
    ) -> ModelResponse:
        del cancellation
        self.requests.append(request)
        if len(self.requests) == 1:
            return ModelResponse(
                tool_calls=tuple(
                    ToolCall(call_id=f"call-{index}", name=tool.name, arguments={})
                    for index, tool in enumerate(request.tools, start=1)
                ),
                usage=ModelUsage(input_tokens=20, output_tokens=8, total_tokens=28),
            )
        return ModelResponse(
            content="已读取 WireGuard、监听端口和 Docker 三项证据。",
            usage=ModelUsage(input_tokens=40, output_tokens=12, total_tokens=52),
        )


class StaticStatusAdapter:
    """按工具名称返回不访问系统的固定状态。"""

    def __init__(self, name: str) -> None:
        self.name = name
        self.calls = 0

    async def execute(
        self,
        arguments: dict[str, JsonValue],
        cancellation: ToolCancellationToken,
    ) -> JsonValue:
        assert arguments == {}
        assert not cancellation.cancelled
        self.calls += 1
        return {"source": self.name, "availability": "available"}


def definition(name: str) -> ToolDefinition:
    """创建端到端场景的只读工具契约。"""
    return ToolDefinition(
        name=name,
        version=ProtocolVersion(major=1, minor=0),
        description=f"读取 {name} 状态。",
        input_schema={"type": "object", "additionalProperties": False},
        output_schema={"type": "object"},
        risk_level=RiskLevel.READ_ONLY,
        platforms=frozenset({Platform.WINDOWS}),
        timeout_seconds=2,
        max_result_bytes=4096,
        data_sensitivity=DataSensitivity.SYSTEM_METADATA,
    )


async def collect(events: AsyncIterator[RunEvent]) -> list[RunEvent]:
    """收集 run 的公开事件。"""
    return [event async for event in events]


def test_fake_model_queries_wireguard_ports_and_docker_end_to_end() -> None:
    """从 thread 问题到三项证据回答的整条本地链路可重复。"""
    names = (
        "get_wireguard_status",
        "list_network_listeners",
        "list_docker_services",
    )
    registry = ToolRegistry()
    adapters = {name: StaticStatusAdapter(name) for name in names}
    for name, adapter in adapters.items():
        registry.register(definition(name), adapter)
    audit = InMemoryAuditSink()
    runtime = ToolRuntime(registry, Platform.WINDOWS, audit)
    provider = LocalDiagnosticProvider()
    agent = LangChainReadOnlyAgent(
        TunnelMinionChatModel(provider=provider), registry, runtime, Platform.WINDOWS
    )
    conversations = InMemoryConversationService(NodeId.new(), lambda: agent)
    thread = conversations.create_thread()

    async def scenario() -> tuple[RunView, list[RunEvent]]:
        started = await conversations.start_run(
            thread.thread_id,
            StartRunInput(question="查询 A 的 WireGuard、端口和 Docker 状态", tool_names=names),
        )
        events = await collect(conversations.stream_events(started.run_id))
        return conversations.get_run(started.run_id), events

    final, events = run(scenario())

    assert final.status is RunStatus.COMPLETED
    assert final.result is not None
    assert final.result.tool_calls == 3
    assert {item.tool_name for item in final.result.evidence_answer.evidence} == set(names)
    assert final.result.usage.total_tokens == 80
    assert all(adapter.calls == 1 for adapter in adapters.values())
    assert len(audit.records) == 3
    assert len([event for event in events if event.tool_status == "started"]) == 3
    assert len([event for event in events if event.tool_run_id is not None]) == 3
    assert [message.role for message in provider.requests[1].messages].count("tool") == 3
