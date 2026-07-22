"""完整跨节点采集与 A 侧探测工作流测试。"""

from __future__ import annotations

import asyncio
from collections.abc import Coroutine
from dataclasses import dataclass
from typing import Any, TypeVar, cast

import pytest
from pydantic import JsonValue

from tunnelminion.agent.diagnostics import (
    CrossNodeDiagnosticAgent,
    CrossNodeDiagnosticWorkflow,
    PreparedRemoteToolSet,
)
from tunnelminion.agent.remote import RemotePreparationError
from tunnelminion.agent.services import CrossNodeReachability
from tunnelminion.domain.errors import ErrorCode
from tunnelminion.domain.identifiers import NodeId, RunId, ThreadId, ToolRunId
from tunnelminion.model.contracts import (
    CancellationToken,
    ModelCapabilities,
    ModelRequest,
    ModelResponse,
    ModelUsage,
    ProviderError,
    ProviderErrorCode,
    ToolCall,
)
from tunnelminion.platforms.windows.models import (
    Availability,
    ReachabilityResult,
    WireGuardPeerSummary,
    WireGuardStatus,
)
from tunnelminion.tools.contracts import (
    ToolCallContext,
    ToolCancellationToken,
    ToolExecutionRequest,
    ToolExecutionResult,
    ToolExecutionStatus,
)

T = TypeVar("T")


def run(coroutine: Coroutine[Any, Any, T]) -> T:
    return asyncio.run(coroutine)


def success(output: JsonValue) -> ToolExecutionResult:
    return ToolExecutionResult(
        tool_run_id=ToolRunId.new(),
        status=ToolExecutionStatus.SUCCESS,
        output=output,
    )


class FakeRemoteExecutor:
    """返回一个环回 PDF 服务和一个网络 Web 服务。"""

    def __init__(self) -> None:
        self.calls: list[ToolExecutionRequest] = []

    async def execute(
        self,
        request: ToolExecutionRequest,
        cancellation: ToolCancellationToken | None = None,
    ) -> ToolExecutionResult:
        del cancellation
        self.calls.append(request)
        outputs: dict[str, JsonValue] = {
            "list_network_listeners": {
                "availability": "available",
                "items": [
                    {
                        "protocol": "tcp",
                        "address": "127.0.0.1",
                        "port": 8080,
                        "pid": 10,
                        "process_name": "pdf-server",
                    },
                    {
                        "protocol": "tcp",
                        "address": "0.0.0.0",
                        "port": 9090,
                        "pid": 20,
                        "process_name": "web-server",
                    },
                ],
            },
            "get_process_summary": {
                "availability": "available",
                "items": [
                    {"pid": 10, "name": "pdf-server", "status": "running"},
                    {"pid": 20, "name": "web-server", "status": "running"},
                ],
            },
            "list_docker_services": {
                "availability": "available",
                "items": [
                    {
                        "container_id": "pdf",
                        "name": "pdf-tools",
                        "image": "pdf:latest",
                        "ports": "127.0.0.1:8080->80/tcp",
                        "status": "Up",
                    }
                ],
            },
        }
        return success(outputs[request.tool_name])


@dataclass
class FakePrepared:
    summary_tool_run_id: ToolRunId
    executor: FakeRemoteExecutor
    tool_names: tuple[str, ...]


class FakePreparer:
    def __init__(self, tool_names: tuple[str, ...]) -> None:
        self.prepared = FakePrepared(ToolRunId.new(), FakeRemoteExecutor(), tool_names)
        self.requested: tuple[str, ...] = ()

    async def prepare(
        self,
        context: ToolCallContext,
        requested_tools: tuple[str, ...],
        cancellation: ToolCancellationToken | None = None,
    ) -> PreparedRemoteToolSet:
        del context, cancellation
        self.requested = requested_tools
        return self.prepared


class FailingPreparer:
    """在能力预检阶段模拟 B 离线或远端超时。"""

    def __init__(self, code: ErrorCode) -> None:
        self.code = code

    async def prepare(
        self,
        context: ToolCallContext,
        requested_tools: tuple[str, ...],
        cancellation: ToolCancellationToken | None = None,
    ) -> PreparedRemoteToolSet:
        del context, requested_tools, cancellation
        raise RemotePreparationError(self.code, "远端不可用")


class FakeLocalExecutor:
    def __init__(self) -> None:
        self.calls: list[ToolExecutionRequest] = []

    async def execute(
        self,
        request: ToolExecutionRequest,
        cancellation: ToolCancellationToken | None = None,
    ) -> ToolExecutionResult:
        del cancellation
        self.calls.append(request)
        if request.tool_name == "get_wireguard_status":
            value = WireGuardStatus(
                availability=Availability.AVAILABLE,
                interface="HomeMac",
                interface_up=True,
                peers=(
                    WireGuardPeerSummary(
                        public_key_summary="peer…abcd",
                        allowed_addresses=("10.77.0.1/32",),
                    ),
                ),
            )
            return success(cast(JsonValue, value.model_dump(mode="json")))
        port = int(cast(int, request.arguments["port"]))
        value = ReachabilityResult(
            host="10.77.0.1",
            port=port,
            reachable=port == 9090,
            error_code=None if port == 9090 else "unreachable",
        )
        return success(cast(JsonValue, value.model_dump(mode="json")))


class ExplainingProvider:
    """记录无工具解释请求，并可模拟模型失败或越界工具响应。"""

    def __init__(self, *, fail: bool = False, return_tool: bool = False) -> None:
        self.fail = fail
        self.return_tool = return_tool
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
        if self.fail:
            raise ProviderError(ProviderErrorCode.TIMEOUT, "模型超时", retryable=True)
        if self.return_tool:
            return ModelResponse(
                tool_calls=(ToolCall(call_id="forbidden", name="restart_service", arguments={}),)
            )
        return ModelResponse(
            content="B 上发现两个服务；PDF 服务的监听范围需要特别注意。",
            usage=ModelUsage(input_tokens=10, output_tokens=5, total_tokens=15),
        )


def context(local: NodeId, remote: NodeId) -> ToolCallContext:
    return ToolCallContext(
        thread_id=ThreadId.new(),
        run_id=RunId.new(),
        caller_node_id=local,
        execution_node_id=remote,
    )


def test_workflow_builds_evidence_report_and_safe_loopback_answer() -> None:
    local, remote = NodeId.new(), NodeId.new()
    preparer = FakePreparer(
        ("list_network_listeners", "get_process_summary", "list_docker_services")
    )
    local_executor = FakeLocalExecutor()
    workflow = CrossNodeDiagnosticWorkflow(preparer, local_executor, local)

    report = run(workflow.inspect(context(local, remote), "10.77.0.1"))

    assert preparer.requested == (
        "list_network_listeners",
        "get_process_summary",
        "list_docker_services",
    )
    assert [item.reachability for item in report.diagnostics] == [
        CrossNodeReachability.LOCAL_ONLY,
        CrossNodeReachability.REACHABLE,
    ]
    assert [call.tool_name for call in preparer.prepared.executor.calls] == list(preparer.requested)
    assert [call.tool_name for call in local_executor.calls] == [
        "get_wireguard_status",
        "probe_service_reachability",
        "probe_service_reachability",
    ]
    answer = report.evidence_answer(8080)
    assert "local-only" in answer
    assert "没有开放端口" in answer
    assert "toolrun_" in answer
    assert "没有开放端口" not in report.evidence_answer(9090)
    assert "untrusted-tool-data" in report.untrusted_context()
    assert "token" not in report.untrusted_context().lower()
    assert report.evidence_answer(12345) == "没有获得匹配服务的监听证据，当前无法确认。"


def test_workflow_marks_missing_capability_and_applies_probe_budget() -> None:
    local, remote = NodeId.new(), NodeId.new()
    preparer = FakePreparer(("list_network_listeners", "get_process_summary"))
    workflow = CrossNodeDiagnosticWorkflow(preparer, FakeLocalExecutor(), local, max_probes=1)

    report = run(workflow.inspect(context(local, remote), "10.77.0.1"))

    assert report.inventory.unavailable_sources == ("list_docker_services",)
    assert [item.reachability for item in report.diagnostics] == [
        CrossNodeReachability.LOCAL_ONLY,
        CrossNodeReachability.NOT_PROBED,
    ]


def test_workflow_rejects_invalid_budget_and_caller() -> None:
    local, remote = NodeId.new(), NodeId.new()
    preparer = FakePreparer(("list_network_listeners",))
    executor = FakeLocalExecutor()
    with pytest.raises(ValueError, match="至少为 1"):
        CrossNodeDiagnosticWorkflow(preparer, executor, local, max_probes=0)

    workflow = CrossNodeDiagnosticWorkflow(preparer, executor, local)
    wrong_context = context(NodeId.new(), remote)
    with pytest.raises(ValueError, match="caller"):
        run(workflow.inspect(wrong_context, "10.77.0.1"))


def test_diagnostic_agent_answers_service_discovery_and_loopback_failure() -> None:
    local, remote = NodeId.new(), NodeId.new()
    preparer = FakePreparer(
        ("list_network_listeners", "get_process_summary", "list_docker_services")
    )
    workflow = CrossNodeDiagnosticWorkflow(preparer, FakeLocalExecutor(), local)
    provider = ExplainingProvider()
    agent = CrossNodeDiagnosticAgent(workflow, provider)

    discovery = run(agent.answer("B 有哪些服务？", context(local, remote), "10.77.0.1"))
    assert "B 上发现两个服务" in discovery.answer
    assert "8080" in discovery.answer
    assert "9090" in discovery.answer
    assert provider.requests[0].tools == ()
    assert "untrusted-tool-data" in provider.requests[0].messages[-1].content
    assert discovery.elapsed_ms >= 0
    assert discovery.model_usage is not None
    assert discovery.model_usage.total_tokens == 15

    loopback = run(
        agent.answer(
            "B 的 PDF 服务为什么打不开？",
            context(local, remote),
            "10.77.0.1",
            port=8080,
        )
    )
    assert "local-only" in loopback.answer
    assert "没有开放端口" in loopback.answer
    assert "toolrun_" in loopback.answer


def test_diagnostic_agent_uses_safe_fallback_for_model_failure_or_tool_response() -> None:
    local, remote = NodeId.new(), NodeId.new()
    preparer = FakePreparer(
        ("list_network_listeners", "get_process_summary", "list_docker_services")
    )
    workflow = CrossNodeDiagnosticWorkflow(preparer, FakeLocalExecutor(), local)

    failed = run(
        CrossNodeDiagnosticAgent(workflow, ExplainingProvider(fail=True)).answer(
            "PDF 为什么打不开？",
            context(local, remote),
            "10.77.0.1",
            port=8080,
        )
    )
    assert failed.model_error_code == "timeout"
    assert failed.model_usage is None
    assert failed.elapsed_ms >= 0
    assert "确定性证据结论" in failed.answer
    assert "local-only" in failed.answer

    tool_response = run(
        CrossNodeDiagnosticAgent(workflow, ExplainingProvider(return_tool=True)).answer(
            "请修复 PDF 服务",
            context(local, remote),
            "10.77.0.1",
            port=8080,
        )
    )
    assert tool_response.model_explanation is None
    assert "restart_service" not in tool_response.answer
    assert "没有开放端口" in tool_response.answer


@pytest.mark.parametrize("code", [ErrorCode.NODE_UNREACHABLE, ErrorCode.REMOTE_TIMEOUT])
def test_diagnostic_agent_reports_remote_failure_without_inventing_services(
    code: ErrorCode,
) -> None:
    local, remote = NodeId.new(), NodeId.new()
    provider = ExplainingProvider()
    workflow = CrossNodeDiagnosticWorkflow(FailingPreparer(code), FakeLocalExecutor(), local)

    answer = run(
        CrossNodeDiagnosticAgent(workflow, provider).answer(
            "B 有哪些服务？", context(local, remote), "10.77.0.1"
        )
    )

    assert answer.remote_error_code == code.value
    assert answer.elapsed_ms >= 0
    assert answer.report is None
    assert "不能确认" in answer.answer
    assert "8080" not in answer.answer
    assert provider.requests == []
