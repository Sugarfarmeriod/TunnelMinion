"""远端节点摘要预检、动态能力筛选和精确路由测试。"""

from __future__ import annotations

import asyncio
from collections.abc import Coroutine
from typing import Any, TypeVar, cast

import httpx
import pytest
from fastapi import FastAPI
from pydantic import JsonValue
from tests.tools.test_registry import definition

from tunnelminion.agent.langchain_model import TunnelMinionChatModel
from tunnelminion.agent.remote import (
    RemoteCapabilityLoader,
    RemotePreparationError,
)
from tunnelminion.agent.runtime import LangChainReadOnlyAgent
from tunnelminion.domain.errors import ErrorCode, ToolError
from tunnelminion.domain.identifiers import NodeId, RunId, ThreadId
from tunnelminion.domain.tools import Platform
from tunnelminion.gateway import create_gateway_router
from tunnelminion.gateway.audit import InMemoryGatewaySecurityAuditSink
from tunnelminion.gateway.client import FixedGatewayClient
from tunnelminion.gateway.security import GatewayPeerPolicy, GatewaySecurityPolicy
from tunnelminion.model.contracts import (
    CancellationToken,
    ModelCapabilities,
    ModelRequest,
    ModelResponse,
    ToolCall,
)
from tunnelminion.platforms.windows.models import Availability, NodeSummary, WireGuardStatus
from tunnelminion.tools.audit import InMemoryAuditSink
from tunnelminion.tools.contracts import (
    ToolAdapterError,
    ToolCallContext,
    ToolCancellationToken,
    ToolExecutionRequest,
    ToolExecutionStatus,
)
from tunnelminion.tools.registry import ToolRegistry
from tunnelminion.tools.runtime import ToolRuntime

T = TypeVar("T")
TOKEN = "tmn_remote-loader-token-with-more-than-32-characters"


def run(coroutine: Coroutine[Any, Any, T]) -> T:
    return asyncio.run(coroutine)


class StaticAdapter:
    """返回固定节点摘要或工具结果。"""

    def __init__(self, value: JsonValue, *, fail: bool = False) -> None:
        self.value = value
        self.fail = fail

    async def execute(
        self,
        arguments: dict[str, JsonValue],
        cancellation: ToolCancellationToken,
    ) -> JsonValue:
        del arguments, cancellation
        if self.fail:
            raise ToolAdapterError(ToolError(code=ErrorCode.INTERNAL, message="摘要失败"))
        return self.value


class RemoteQuestionProvider:
    """确认预检之后模型只看到筛选完成的远端工具。"""

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
                tool_calls=(
                    ToolCall(
                        call_id="remote-call",
                        name=request.tools[0].name,
                        arguments={},
                    ),
                )
            )
        return ModelResponse(content="已根据 B 的监听证据完成检查。")


def summary(remote: NodeId, *, platform: str = "macos") -> dict[str, JsonValue]:
    value = NodeSummary(
        node_id=str(remote),
        platform=platform,
        agent_status="ready",
        model_status="unconfigured",
        wireguard=WireGuardStatus(
            availability=Availability.AVAILABLE,
            interface="utun4",
            interface_up=True,
            addresses=("10.77.0.1",),
        ),
        available_tools=("get_node_summary", "list_network_listeners"),
    )
    return cast(dict[str, JsonValue], value.model_dump(mode="json"))


def build_loader(
    *,
    include_summary: bool = True,
    summary_value: JsonValue | None = None,
    summary_failure: bool = False,
    summary_platform: str = "macos",
) -> tuple[RemoteCapabilityLoader, ToolCallContext, InMemoryAuditSink, InMemoryAuditSink]:
    remote = NodeId.new()
    local = NodeId.new()
    registry = ToolRegistry()
    allowed = ["list_network_listeners"]
    if include_summary:
        registry.register(
            definition("get_node_summary", platforms=frozenset({Platform.MACOS})),
            StaticAdapter(
                summary(remote, platform=summary_platform)
                if summary_value is None
                else summary_value,
                fail=summary_failure,
            ),
        )
        allowed.insert(0, "get_node_summary")
    registry.register(
        definition("list_network_listeners", platforms=frozenset({Platform.MACOS})),
        StaticAdapter({"availability": "available", "items": []}),
    )
    remote_audit = InMemoryAuditSink()
    runtime = ToolRuntime(registry, Platform.MACOS, remote_audit)
    policy = GatewaySecurityPolicy([GatewayPeerPolicy.from_token(local, TOKEN, allowed)])
    app = FastAPI()
    app.include_router(
        create_gateway_router(
            remote,
            Platform.MACOS,
            registry,
            runtime,
            policy,
            InMemoryGatewaySecurityAuditSink(),
        )
    )
    local_audit = InMemoryAuditSink()
    client = FixedGatewayClient(
        "http://10.77.0.1:8787",
        TOKEN,
        local,
        remote,
        local_audit,
        transport=httpx.ASGITransport(app=app),
    )
    context = ToolCallContext(
        thread_id=ThreadId.new(),
        run_id=RunId.new(),
        caller_node_id=local,
        execution_node_id=remote,
    )
    return (
        RemoteCapabilityLoader(client, Platform.WINDOWS, remote),
        context,
        local_audit,
        remote_audit,
    )


def test_summary_preflight_filters_capabilities_and_routes_remote_call() -> None:
    loader, context, local_audit, remote_audit = build_loader()
    prepared = run(
        loader.prepare(
            context,
            ("list_network_listeners", "list_docker_services"),
        )
    )

    assert prepared.node_summary.node_id == str(context.execution_node_id)
    assert prepared.tool_names == ("list_network_listeners",)
    assert [item.name for item in prepared.registry.model_tools(Platform.WINDOWS)] == [
        "list_network_listeners"
    ]
    assert "不可信工具数据" in prepared.augment_question("B 有哪些服务？")
    assert str(prepared.summary_tool_run_id) in prepared.augment_question("检查 B")
    result = run(
        prepared.executor.execute(
            ToolExecutionRequest(
                context=context,
                tool_name="list_network_listeners",
            )
        )
    )
    assert result.status is ToolExecutionStatus.SUCCESS
    assert len(local_audit.records) == len(remote_audit.records) == 2
    assert local_audit.records[-1].tool_run_id == remote_audit.records[-1].tool_run_id

    invalid = run(
        prepared.executor.execute(
            ToolExecutionRequest(
                context=context,
                tool_name="list_network_listeners",
                arguments={"unexpected": True},
            )
        )
    )
    assert invalid.error is not None
    assert invalid.error.code is ErrorCode.INVALID_ARGUMENT

    missing = run(
        prepared.executor.execute(
            ToolExecutionRequest(context=context, tool_name="list_docker_services")
        )
    )
    assert missing.error is not None
    assert missing.error.code is ErrorCode.TOOL_NOT_FOUND

    entry = prepared.registry.lookup("list_network_listeners")
    assert entry is not None
    with pytest.raises(ToolAdapterError, match="远端工具不得"):
        run(entry.adapter.execute({}, ToolCancellationToken()))


def test_prepared_remote_tools_run_through_langchain_agent() -> None:
    loader, context, _local_audit, _remote_audit = build_loader()
    prepared = run(loader.prepare(context, ("list_network_listeners", "list_docker_services")))
    provider = RemoteQuestionProvider()
    agent = LangChainReadOnlyAgent(
        TunnelMinionChatModel(provider=provider),
        prepared.registry,
        prepared.executor,
        Platform.WINDOWS,
    )

    result = run(
        agent.run(
            prepared.augment_question("B 有哪些监听服务？"),
            context,
            prepared.tool_names,
        )
    )

    assert result.selected_tools == ("list_network_listeners",)
    assert result.tool_calls == 1
    assert [tool.name for tool in provider.requests[0].tools] == ["list_network_listeners"]
    assert "远端节点预检" in provider.requests[0].messages[-1].content


@pytest.mark.parametrize("requested", [(), ("list_network_listeners",) * 2])
def test_remote_candidates_must_be_nonempty_and_unique(requested: tuple[str, ...]) -> None:
    loader, context, _local_audit, _remote_audit = build_loader()
    with pytest.raises(ValueError):
        run(loader.prepare(context, requested))


def test_remote_preparation_rejects_missing_failed_malformed_and_wrong_summary() -> None:
    missing, context, _, _ = build_loader(include_summary=False)
    with pytest.raises(RemotePreparationError) as no_summary:
        run(missing.prepare(context, ("list_network_listeners",)))
    assert no_summary.value.code is ErrorCode.TOOL_NOT_FOUND

    failed, context, _, _ = build_loader(summary_failure=True)
    with pytest.raises(RemotePreparationError) as failed_summary:
        run(failed.prepare(context, ("list_network_listeners",)))
    assert failed_summary.value.code is ErrorCode.INTERNAL

    malformed, context, _, _ = build_loader(summary_value={"invalid": True})
    with pytest.raises(RemotePreparationError) as malformed_summary:
        run(malformed.prepare(context, ("list_network_listeners",)))
    assert malformed_summary.value.code is ErrorCode.INTERNAL

    wrong_node = NodeId.new()
    wrong, context, _, _ = build_loader(summary_value=summary(wrong_node))
    with pytest.raises(RemotePreparationError) as identity:
        run(wrong.prepare(context, ("list_network_listeners",)))
    assert identity.value.code is ErrorCode.FORBIDDEN

    wrong_platform, context, _, _ = build_loader(summary_platform="windows")
    with pytest.raises(RemotePreparationError) as platform:
        run(wrong_platform.prepare(context, ("list_network_listeners",)))
    assert platform.value.code is ErrorCode.FORBIDDEN


def test_remote_preparation_exposes_nothing_when_offline_or_no_task_capability() -> None:
    loader, context, _, _ = build_loader()
    with pytest.raises(RemotePreparationError) as unavailable:
        run(loader.prepare(context, ("list_docker_services",)))
    assert unavailable.value.code is ErrorCode.TOOL_NOT_FOUND

    remote = context.execution_node_id
    local = context.caller_node_id

    def offline(_request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("offline")

    client = FixedGatewayClient(
        "http://10.77.0.1:8787",
        TOKEN,
        local,
        remote,
        InMemoryAuditSink(),
        transport=httpx.MockTransport(offline),
    )
    offline_loader = RemoteCapabilityLoader(client, Platform.WINDOWS, remote)
    with pytest.raises(RemotePreparationError) as unreachable:
        run(offline_loader.prepare(context, ("list_network_listeners",)))
    assert unreachable.value.code is ErrorCode.NODE_UNREACHABLE
