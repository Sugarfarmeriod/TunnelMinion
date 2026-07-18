"""A→B 固定客户端、失败映射和双端关联审计测试。"""

from __future__ import annotations

import asyncio
from collections.abc import Coroutine
from typing import Any, TypeVar

import httpx
import pytest
from fastapi import FastAPI
from tests.tools.test_registry import definition

from tunnelminion.domain.errors import ErrorCode
from tunnelminion.domain.identifiers import NodeId, RunId, ThreadId, ToolRunId
from tunnelminion.domain.tools import Platform
from tunnelminion.domain.versioning import ProtocolVersion
from tunnelminion.gateway import create_gateway_router
from tunnelminion.gateway.audit import InMemoryGatewaySecurityAuditSink
from tunnelminion.gateway.client import FixedGatewayClient, RemoteGatewayError
from tunnelminion.gateway.contracts import (
    GATEWAY_PROTOCOL,
    GatewayCapabilities,
    RemoteToolResult,
)
from tunnelminion.gateway.security import GatewayPeerPolicy, GatewaySecurityPolicy
from tunnelminion.tools.audit import InMemoryAuditSink
from tunnelminion.tools.contracts import (
    ToolCallContext,
    ToolCancellationToken,
    ToolExecutionStatus,
)
from tunnelminion.tools.fakes import FakeToolAdapter, FakeToolBehavior
from tunnelminion.tools.registry import ToolRegistry
from tunnelminion.tools.runtime import ToolRuntime

T = TypeVar("T")
TOKEN = "tmn_fixed-client-token-with-more-than-32-characters"


def run(coroutine: Coroutine[Any, Any, T]) -> T:
    """执行异步固定客户端场景。"""
    return asyncio.run(coroutine)


def gateway() -> tuple[FastAPI, NodeId, NodeId, InMemoryAuditSink]:
    """创建带快/慢工具的已认证 B 网关。"""
    remote = NodeId.new()
    local = NodeId.new()
    registry = ToolRegistry()
    registry.register(definition("read_status"), FakeToolAdapter())
    registry.register(
        definition("slow_status"),
        FakeToolAdapter(FakeToolBehavior.SUCCESS, delay_seconds=0.2),
    )
    audit = InMemoryAuditSink()
    runtime = ToolRuntime(registry, Platform.WINDOWS, audit)
    policy = GatewaySecurityPolicy(
        [GatewayPeerPolicy.from_token(local, TOKEN, ["read_status", "slow_status"])]
    )
    app = FastAPI()
    app.include_router(
        create_gateway_router(
            remote,
            Platform.WINDOWS,
            registry,
            runtime,
            policy,
            InMemoryGatewaySecurityAuditSink(),
        )
    )
    return app, local, remote, audit


def context(local: NodeId, remote: NodeId) -> ToolCallContext:
    """创建完整跨节点关联上下文。"""
    return ToolCallContext(
        thread_id=ThreadId.new(),
        run_id=RunId.new(),
        caller_node_id=local,
        execution_node_id=remote,
    )


def client_for(
    app: FastAPI,
    local: NodeId,
    remote: NodeId,
    audit: InMemoryAuditSink,
    *,
    token: str = TOKEN,
    max_response_bytes: int = 512_000,
) -> FixedGatewayClient:
    """通过内存 ASGI 传输构造固定 peer 客户端。"""
    return FixedGatewayClient(
        "http://10.77.0.1:8787",
        token,
        local,
        remote,
        audit,
        max_response_bytes=max_response_bytes,
        transport=httpx.ASGITransport(app=app),
    )


def test_discovery_success_and_cross_node_audits_share_ids() -> None:
    """能力发现与成功/参数失败调用都在 A、B 留下同一关联 ID。"""
    app, local, remote, remote_audit = gateway()
    local_audit = InMemoryAuditSink()
    client = client_for(app, local, remote, local_audit)
    capabilities = run(client.discover())
    assert capabilities.node_id == remote
    assert [item.name for item in capabilities.tools] == ["read_status", "slow_status"]

    call_context = context(local, remote)
    tool_run_id = ToolRunId.new()
    result = run(
        client.call(
            "read_status",
            ProtocolVersion(major=1, minor=0),
            call_context,
            {},
            1,
            tool_run_id=tool_run_id,
        )
    )
    assert result.status is ToolExecutionStatus.SUCCESS
    assert result.tool_run_id == tool_run_id
    assert local_audit.records[-1].run_id == remote_audit.records[-1].run_id
    assert local_audit.records[-1].tool_run_id == remote_audit.records[-1].tool_run_id
    assert local_audit.records[-1].execution_node_id == remote

    invalid = run(
        client.call(
            "read_status",
            ProtocolVersion(major=1, minor=0),
            call_context,
            {
                "api_key": "must-not-leak",
                "nested": {"password": "hidden"},
                "items": list(range(30)),
                "label": "x" * 200,
                "count": 3,
            },
            1,
        )
    )
    assert invalid.error is not None
    assert invalid.error.code is ErrorCode.INVALID_ARGUMENT
    summary = local_audit.records[-1].arguments_summary
    assert summary["api_key"] == "[REDACTED]"
    assert len(summary["items"]) == 20  # type: ignore[arg-type]
    assert str(summary["label"]).endswith("…")
    assert "must-not-leak" not in str(local_audit.records)


def test_client_maps_gateway_timeout_cancel_auth_and_offline_failures() -> None:
    """超时、取消、未认证和离线均返回稳定错误且不抛出秘密正文。"""
    app, local, remote, _remote_audit = gateway()
    audit = InMemoryAuditSink()
    client = client_for(app, local, remote, audit)
    call_context = context(local, remote)
    timed_out = run(
        client.call(
            "slow_status",
            ProtocolVersion(major=1, minor=0),
            call_context,
            {},
            0.01,
        )
    )
    assert timed_out.error is not None
    assert timed_out.error.code is ErrorCode.REMOTE_TIMEOUT
    assert timed_out.error.retryable is True

    already_cancelled = ToolCancellationToken()
    already_cancelled.cancel()
    cancelled = run(
        client.call(
            "read_status",
            ProtocolVersion(major=1, minor=0),
            call_context,
            {},
            1,
            already_cancelled,
        )
    )
    assert cancelled.status is ToolExecutionStatus.CANCELLED
    assert cancelled.error is not None
    assert cancelled.error.code is ErrorCode.CANCELLED

    async def cancel_during_request() -> RemoteToolResult:
        token = ToolCancellationToken()
        pending = asyncio.create_task(
            client.call(
                "slow_status",
                ProtocolVersion(major=1, minor=0),
                call_context,
                {},
                1,
                token,
            )
        )
        await asyncio.sleep(0.02)
        token.cancel()
        return await pending

    during = run(cancel_during_request())
    assert during.error is not None
    assert during.error.code is ErrorCode.CANCELLED

    bad_client = client_for(app, local, remote, InMemoryAuditSink(), token="x" * 40)
    with pytest.raises(RemoteGatewayError) as unauthenticated:
        run(bad_client.discover())
    assert unauthenticated.value.code is ErrorCode.UNAUTHENTICATED
    bad_call = run(
        bad_client.call(
            "read_status",
            ProtocolVersion(major=1, minor=0),
            call_context,
            {},
            1,
        )
    )
    assert bad_call.error is not None
    assert bad_call.error.code is ErrorCode.UNAUTHENTICATED

    def offline(_request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("offline")

    offline_client = FixedGatewayClient(
        "http://10.77.0.1:8787",
        TOKEN,
        local,
        remote,
        InMemoryAuditSink(),
        transport=httpx.MockTransport(offline),
    )
    with pytest.raises(RemoteGatewayError) as unreachable:
        run(offline_client.discover())
    assert unreachable.value.code is ErrorCode.NODE_UNREACHABLE
    offline_result = run(
        offline_client.call(
            "read_status",
            ProtocolVersion(major=1, minor=0),
            call_context,
            {},
            1,
        )
    )
    assert offline_result.error is not None
    assert offline_result.error.code is ErrorCode.NODE_UNREACHABLE


def test_client_validates_configuration_context_and_remote_envelopes() -> None:
    """固定 URL、身份、响应预算和远端关联信封都必须匹配配置。"""
    app, local, remote, _remote_audit = gateway()
    audit = InMemoryAuditSink()
    with pytest.raises(ValueError, match="HTTP"):
        FixedGatewayClient("https://example.com", TOKEN, local, remote, audit)
    with pytest.raises(ValueError, match="过短"):
        FixedGatewayClient("http://10.77.0.1", "short", local, remote, audit)
    with pytest.raises(ValueError, match="预算"):
        FixedGatewayClient("http://10.77.0.1", TOKEN, local, remote, audit, max_response_bytes=1)
    client = client_for(app, local, remote, audit)
    with pytest.raises(ValueError, match="caller"):
        run(
            client.call(
                "read_status",
                GATEWAY_PROTOCOL,
                context(NodeId.new(), remote),
                {},
                1,
            )
        )
    with pytest.raises(ValueError, match="execution"):
        run(
            client.call(
                "read_status",
                GATEWAY_PROTOCOL,
                context(local, NodeId.new()),
                {},
                1,
            )
        )

    wrong_remote = client_for(app, local, NodeId.new(), audit)
    with pytest.raises(RemoteGatewayError) as identity:
        run(wrong_remote.discover())
    assert identity.value.code is ErrorCode.FORBIDDEN


def test_client_handles_timeout_malformed_oversize_and_mismatched_responses() -> None:
    """客户端不信任网关正文，并限制大小、格式、来源和关联 ID。"""
    local = NodeId.new()
    remote = NodeId.new()
    call_context = context(local, remote)

    def timeout(_request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("slow")

    timed_client = FixedGatewayClient(
        "http://10.77.0.1",
        TOKEN,
        local,
        remote,
        InMemoryAuditSink(),
        transport=httpx.MockTransport(timeout),
    )
    with pytest.raises(RemoteGatewayError) as discover_timeout:
        run(timed_client.discover())
    assert discover_timeout.value.code is ErrorCode.REMOTE_TIMEOUT
    call_timeout = run(timed_client.call("read_status", GATEWAY_PROTOCOL, call_context, {}, 1))
    assert call_timeout.error is not None
    assert call_timeout.error.code is ErrorCode.REMOTE_TIMEOUT

    responses: list[httpx.Response] = []

    def queued(_request: httpx.Request) -> httpx.Response:
        return responses.pop(0)

    client = FixedGatewayClient(
        "http://10.77.0.1",
        TOKEN,
        local,
        remote,
        InMemoryAuditSink(),
        max_response_bytes=512,
        transport=httpx.MockTransport(queued),
    )
    responses.append(httpx.Response(200, content=b"x" * 513))
    with pytest.raises(RemoteGatewayError) as oversized_discovery:
        run(client.discover())
    assert oversized_discovery.value.code is ErrorCode.RESULT_TOO_LARGE
    responses.append(httpx.Response(200, content=b"not-json"))
    with pytest.raises(RemoteGatewayError) as malformed_discovery:
        run(client.discover())
    assert malformed_discovery.value.code is ErrorCode.INTERNAL
    incompatible = GatewayCapabilities(
        protocol=ProtocolVersion(major=2, minor=0),
        node_id=remote,
        platform=Platform.WINDOWS,
        tools=(),
    )
    responses.append(httpx.Response(200, content=incompatible.model_dump_json().encode()))
    with pytest.raises(RemoteGatewayError) as incompatible_discovery:
        run(client.discover())
    assert incompatible_discovery.value.code is ErrorCode.VERSION_INCOMPATIBLE

    responses.append(httpx.Response(500, content=b"not-json"))
    malformed_error = run(client.call("read_status", GATEWAY_PROTOCOL, call_context, {}, 1))
    assert malformed_error.error is not None
    assert malformed_error.error.code is ErrorCode.INTERNAL
    responses.append(httpx.Response(200, content=b"x" * 513))
    oversized_call = run(client.call("read_status", GATEWAY_PROTOCOL, call_context, {}, 1))
    assert oversized_call.error is not None
    assert oversized_call.error.code is ErrorCode.RESULT_TOO_LARGE
    responses.append(httpx.Response(200, content=b"not-json"))
    malformed_call = run(client.call("read_status", GATEWAY_PROTOCOL, call_context, {}, 1))
    assert malformed_call.error is not None
    assert malformed_call.error.code is ErrorCode.INTERNAL

    wrong_ids = RemoteToolResult(
        protocol=GATEWAY_PROTOCOL,
        execution_node_id=remote,
        run_id=RunId.new(),
        tool_run_id=ToolRunId.new(),
        status=ToolExecutionStatus.SUCCESS,
        output={"ok": True},
    )
    responses.append(httpx.Response(200, content=wrong_ids.model_dump_json().encode()))
    mismatch = run(client.call("read_status", GATEWAY_PROTOCOL, call_context, {}, 1))
    assert mismatch.error is not None
    assert mismatch.error.code is ErrorCode.INTERNAL

    wrong_node = wrong_ids.model_copy(
        update={"run_id": call_context.run_id, "execution_node_id": NodeId.new()}
    )
    # 使用客户端下一次自动生成的 tool_run_id 无法预知，因此显式传入。
    expected_tool_run = ToolRunId.new()
    wrong_node = wrong_node.model_copy(update={"tool_run_id": expected_tool_run})
    responses.append(httpx.Response(200, content=wrong_node.model_dump_json().encode()))
    identity = run(
        client.call(
            "read_status",
            GATEWAY_PROTOCOL,
            call_context,
            {},
            1,
            tool_run_id=expected_tool_run,
        )
    )
    assert identity.error is not None
    assert identity.error.code is ErrorCode.FORBIDDEN
