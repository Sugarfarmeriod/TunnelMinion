"""网关绑定、认证摘要、限流、超时、断连取消和响应预算测试。"""

from __future__ import annotations

import asyncio
from collections.abc import Coroutine
from typing import Any, TypeVar

import pytest
from pydantic import ValidationError
from tests.tools.test_registry import definition

from tunnelminion.domain.errors import ErrorCode
from tunnelminion.domain.identifiers import NodeId, RunId, ThreadId, ToolRunId
from tunnelminion.domain.tools import Platform
from tunnelminion.domain.versioning import ProtocolVersion
from tunnelminion.gateway.api import execute_bounded, limit_result
from tunnelminion.gateway.contracts import RemoteToolResult
from tunnelminion.gateway.security import (
    GatewayBindConfig,
    GatewayLimits,
    GatewayPeerPolicy,
    GatewaySecurityPolicy,
)
from tunnelminion.tools.audit import InMemoryAuditSink
from tunnelminion.tools.contracts import (
    ToolCallContext,
    ToolExecutionRequest,
    ToolExecutionStatus,
)
from tunnelminion.tools.fakes import FakeToolAdapter, FakeToolBehavior
from tunnelminion.tools.registry import ToolRegistry
from tunnelminion.tools.runtime import ToolRuntime

T = TypeVar("T")
TOKEN = "another-independent-token-with-more-than-32-characters"


def run(coroutine: Coroutine[Any, Any, T]) -> T:
    """执行异步网关边界。"""
    return asyncio.run(coroutine)


def test_bind_config_only_accepts_explicit_private_wireguard_address() -> None:
    """公网、通配、环回和组播地址都不能作为 Tool Gateway 监听地址。"""
    assert GatewayBindConfig(host="10.77.0.1").port == 8787
    for host in ("0.0.0.0", "127.0.0.1", "8.8.8.8", "224.0.0.1"):
        with pytest.raises(ValidationError, match="WireGuard"):
            GatewayBindConfig(host=host)


def test_peer_policy_hashes_token_and_validates_configuration() -> None:
    """明文 token 不驻留策略对象，错误认证不会匹配任何 peer。"""
    node = NodeId.new()
    peer = GatewayPeerPolicy.from_token(node, TOKEN, ["read_status"])
    assert TOKEN.encode() not in peer.token_digest
    policy = GatewaySecurityPolicy([peer])
    assert policy.authenticate(None) is None
    assert policy.authenticate("Basic wrong") is None
    assert policy.authenticate("Bearer wrong-token-that-is-long-enough") is None
    assert policy.authenticate(f"Bearer {TOKEN}") == peer

    with pytest.raises(ValueError, match="32"):
        GatewayPeerPolicy.from_token(node, "short", ["read_status"])
    with pytest.raises(ValueError, match="至少需要一个"):
        GatewayPeerPolicy.from_token(node, TOKEN, [])
    with pytest.raises(ValueError, match="至少需要一个"):
        GatewaySecurityPolicy([])
    with pytest.raises(ValueError, match="不得重复"):
        GatewaySecurityPolicy([peer, peer])


def test_rate_limit_uses_per_peer_sliding_window() -> None:
    """60 秒窗口过期后 peer 可继续调用，其他 peer 不共享配额。"""
    now = 100.0

    def clock() -> float:
        return now

    first = GatewayPeerPolicy.from_token(NodeId.new(), TOKEN, ["read_status"])
    second = GatewayPeerPolicy.from_token(
        NodeId.new(), "second-independent-token-with-more-than-32-chars", ["read_status"]
    )
    policy = GatewaySecurityPolicy(
        [first, second], GatewayLimits(requests_per_minute=1), clock=clock
    )
    assert policy.consume(first) is True
    assert policy.consume(first) is False
    assert policy.consume(second) is True
    now += 60
    assert policy.consume(first) is True


def bounded_runtime() -> tuple[ToolRuntime, ToolExecutionRequest]:
    """创建会等待的工具 Runtime 与完整关联请求。"""
    registry = ToolRegistry()
    registry.register(
        definition("slow_status"),
        FakeToolAdapter(FakeToolBehavior.SUCCESS, delay_seconds=0.2),
    )
    runtime = ToolRuntime(registry, Platform.WINDOWS, InMemoryAuditSink())
    node = NodeId.new()
    request = ToolExecutionRequest(
        context=ToolCallContext(
            thread_id=ThreadId.new(),
            run_id=RunId.new(),
            caller_node_id=NodeId.new(),
            execution_node_id=node,
        ),
        tool_run_id=ToolRunId.new(),
        tool_name="slow_status",
    )
    return runtime, request


def test_request_deadline_and_disconnect_cancel_runtime() -> None:
    """网关超时和客户端断连都传播取消，并返回不同稳定错误码。"""

    async def connected() -> bool:
        return False

    async def disconnected() -> bool:
        return True

    async def slow_disconnect_check() -> bool:
        await asyncio.sleep(0.1)
        return False

    runtime, request = bounded_runtime()
    timed_out = run(execute_bounded(runtime, request, 0.01, connected))
    assert timed_out.status is ToolExecutionStatus.FAILED
    assert timed_out.error is not None
    assert timed_out.error.code is ErrorCode.REMOTE_TIMEOUT
    assert timed_out.tool_run_id == request.tool_run_id

    runtime, request = bounded_runtime()
    check_timed_out = run(execute_bounded(runtime, request, 0.03, slow_disconnect_check))
    assert check_timed_out.error is not None
    assert check_timed_out.error.code is ErrorCode.REMOTE_TIMEOUT

    runtime, request = bounded_runtime()
    cancelled = run(execute_bounded(runtime, request, 1, disconnected))
    assert cancelled.status is ToolExecutionStatus.CANCELLED
    assert cancelled.error is not None
    assert cancelled.error.code is ErrorCode.CANCELLED


def test_gateway_response_budget_omits_large_body_but_keeps_trace() -> None:
    """外层响应过大时保留关联 ID，并用结构化部分结果替代正文。"""
    result = RemoteToolResult(
        protocol=ProtocolVersion(major=1, minor=0),
        execution_node_id=NodeId.new(),
        run_id=RunId.new(),
        tool_run_id=ToolRunId.new(),
        status=ToolExecutionStatus.SUCCESS,
        output={"payload": "x" * 2_000},
    )
    small = RemoteToolResult(
        protocol=result.protocol,
        execution_node_id=result.execution_node_id,
        run_id=result.run_id,
        tool_run_id=result.tool_run_id,
        status=ToolExecutionStatus.SUCCESS,
        output={"ok": True},
    )
    assert limit_result(small, 1_024) == small

    limited = limit_result(result, 1_024)
    assert limited.tool_run_id == result.tool_run_id
    assert limited.status is ToolExecutionStatus.PARTIAL
    assert limited.truncated is True
    assert limited.error is not None
    assert limited.error.code is ErrorCode.RESULT_TOO_LARGE
