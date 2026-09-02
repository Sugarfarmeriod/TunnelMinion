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
from tunnelminion.agent.planning import (
    CandidateOperationPlanner,
    CandidatePlanIntent,
    CandidatePlanResult,
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
from tunnelminion.operation.contracts import OperationLevel, PlanFailureAttribution
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

    def __init__(
        self,
        *,
        fail: bool = False,
        return_tool: bool = False,
        structured_output: bool = True,
        malformed_plan: bool = False,
    ) -> None:
        self.fail = fail
        self.return_tool = return_tool
        self.structured_output = structured_output
        self.malformed_plan = malformed_plan
        self.requests: list[ModelRequest] = []

    @property
    def capabilities(self) -> ModelCapabilities:
        return ModelCapabilities(tool_calls=True, structured_output=self.structured_output)

    async def complete(
        self,
        request: ModelRequest,
        cancellation: CancellationToken | None = None,
    ) -> ModelResponse:
        del cancellation
        self.requests.append(request)
        if self.fail:
            raise ProviderError(ProviderErrorCode.TIMEOUT, "模型超时", retryable=True)
        if request.response_schema is not None:
            if self.return_tool:
                return ModelResponse(
                    tool_calls=(
                        ToolCall(call_id="forbidden", name="restart_service", arguments={}),
                    )
                )
            if self.malformed_plan:
                return ModelResponse(structured_output={})
            return ModelResponse(
                structured_output={
                    "expected_change": "创建仅限指定 peer 的临时 HTTP 私网入口",
                    "risk_summary": "入口会临时扩大私网内的服务访问面",
                    "verification_method": "由请求节点沿 WireGuard 路径验证健康端点",
                    "rollback_method": "停止并删除本次操作拥有的临时代理资源",
                },
                usage=ModelUsage(input_tokens=20, output_tokens=10, total_tokens=30),
            )
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


def test_workflow_only_probes_explicit_target_port() -> None:
    """指定服务端口时不为无关监听逐个等待网络超时。"""
    local, remote = NodeId.new(), NodeId.new()
    preparer = FakePreparer(
        ("list_network_listeners", "get_process_summary", "list_docker_services")
    )
    executor = FakeLocalExecutor()
    workflow = CrossNodeDiagnosticWorkflow(preparer, executor, local)

    report = run(
        workflow.inspect(
            context(local, remote),
            "10.77.0.1",
            target_port=8080,
        )
    )

    assert [call.tool_name for call in executor.calls] == [
        "get_wireguard_status",
        "probe_service_reachability",
    ]
    assert report.diagnostics[0].reachability is CrossNodeReachability.LOCAL_ONLY
    assert report.diagnostics[1].reachability is CrossNodeReachability.NOT_PROBED


def test_workflow_probes_explicit_port_missing_from_remote_inventory() -> None:
    """显式端口即使未被远端枚举，也必须获得 A 侧实时 TCP 证据。"""
    local, remote = NodeId.new(), NodeId.new()
    preparer = FakePreparer(
        ("list_network_listeners", "get_process_summary", "list_docker_services")
    )
    executor = FakeLocalExecutor()
    workflow = CrossNodeDiagnosticWorkflow(preparer, executor, local)

    report = run(
        workflow.inspect(
            context(local, remote),
            "10.77.0.1",
            target_port=8082,
        )
    )

    assert [call.tool_name for call in executor.calls] == [
        "get_wireguard_status",
        "probe_service_reachability",
    ]
    assert executor.calls[-1].arguments["port"] == 8082
    selected = tuple(item for item in report.diagnostics if item.service.port == 8082)
    assert len(selected) == 1
    assert selected[0].reachability is CrossNodeReachability.UNREACHABLE
    assert selected[0].service.accessibility.value == "unknown"
    assert any(
        evidence.tool_name == "probe_service_reachability" for evidence in selected[0].evidence
    )


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


def test_diagnostic_agent_generates_traced_candidate_plan_from_latest_evidence() -> None:
    local, remote = NodeId.new(), NodeId.new()
    preparer = FakePreparer(
        ("list_network_listeners", "get_process_summary", "list_docker_services")
    )
    provider = ExplainingProvider()
    agent = CrossNodeDiagnosticAgent(
        CrossNodeDiagnosticWorkflow(preparer, FakeLocalExecutor(), local),
        provider,
        CandidateOperationPlanner(
            provider,
            provider_name="fake-provider",
            model_name="fake-model",
        ),
    )

    answer = run(
        agent.answer(
            "请让 A 临时访问 B 的 PDF 服务",
            context(local, remote),
            "10.77.0.1",
            port=8080,
            plan_intent=CandidatePlanIntent(
                confirmed=True,
                service_port=8080,
                bind_host="10.77.0.1",
                bind_port=18881,
                duration_seconds=60,
            ),
        )
    )

    assert answer.candidate_plan is not None
    assert answer.candidate_plan.level is OperationLevel.L2
    assert answer.candidate_plan.request_node_id == local
    assert answer.candidate_plan.target_node_id == remote
    assert answer.candidate_plan.service.port == 8080
    assert answer.candidate_plan.access_scope.bind_port == 18881
    assert answer.candidate_plan.generation_trace is not None
    assert answer.candidate_plan.generation_trace.prompt_version == "v1"
    assert answer.candidate_plan.generation_trace.provider_name == "fake-provider"
    assert answer.candidate_plan.generation_trace.evidence_count == len(
        answer.candidate_plan.tool_run_ids
    )
    assert answer.candidate_plan.generation_trace.realtime_evidence_precedence
    assert answer.plan_trace == answer.candidate_plan.generation_trace
    assert answer.plan_error_code is None
    assert "无权限的 L2 候选计划" in answer.answer
    assert len(provider.requests) == 1
    assert provider.requests[0].response_schema is not None
    assert provider.requests[0].tools == ()
    assert "untrusted-tool-data" in provider.requests[0].messages[-1].content
    assert "expected_change" in provider.requests[0].messages[0].content


def test_candidate_plan_failure_does_not_remove_diagnostic_result() -> None:
    local, remote = NodeId.new(), NodeId.new()
    preparer = FakePreparer(
        ("list_network_listeners", "get_process_summary", "list_docker_services")
    )
    provider = ExplainingProvider(fail=True)
    answer = run(
        CrossNodeDiagnosticAgent(
            CrossNodeDiagnosticWorkflow(preparer, FakeLocalExecutor(), local),
            provider,
        ).answer(
            "请临时共享 PDF 服务",
            context(local, remote),
            "10.77.0.1",
            port=8080,
            plan_intent=CandidatePlanIntent(
                confirmed=True,
                service_port=8080,
                bind_host="10.77.0.1",
                bind_port=18881,
                duration_seconds=60,
            ),
        )
    )

    assert answer.candidate_plan is None
    assert answer.plan_error_code == "timeout"
    assert answer.plan_failure_attribution is PlanFailureAttribution.PROMPT_OR_MODEL
    assert answer.report is not None
    assert "local-only" in answer.answer
    assert "候选计划未生成" in answer.answer


@pytest.mark.parametrize(
    ("provider", "code"),
    [
        (
            ExplainingProvider(structured_output=False),
            "structured_output_unavailable",
        ),
        (ExplainingProvider(return_tool=True), "invalid_plan_response"),
        (ExplainingProvider(malformed_plan=True), "invalid_plan_response"),
    ],
)
def test_candidate_plan_requires_valid_structured_model_output(
    provider: ExplainingProvider,
    code: str,
) -> None:
    local, remote = NodeId.new(), NodeId.new()
    report = run(
        CrossNodeDiagnosticWorkflow(
            FakePreparer(("list_network_listeners", "get_process_summary", "list_docker_services")),
            FakeLocalExecutor(),
            local,
        ).inspect(context(local, remote), "10.77.0.1")
    )

    result = run(
        CandidateOperationPlanner(provider).generate(
            question="临时共享 PDF",
            report=report,
            context=context(local, remote),
            intent=CandidatePlanIntent(
                confirmed=True,
                service_port=8080,
                bind_host="10.77.0.1",
                bind_port=18881,
                duration_seconds=60,
            ),
        )
    )

    assert result.plan is None
    assert result.failure is not None
    assert result.failure.code == code


def test_candidate_plan_rejects_invalid_host_and_missing_tool_evidence() -> None:
    local, remote = NodeId.new(), NodeId.new()
    workflow = CrossNodeDiagnosticWorkflow(
        FakePreparer(("list_network_listeners", "get_process_summary", "list_docker_services")),
        FakeLocalExecutor(),
        local,
    )
    report = run(workflow.inspect(context(local, remote), "10.77.0.1"))
    planner = CandidateOperationPlanner(ExplainingProvider())
    invalid_host = run(
        planner.generate(
            question="临时共享 PDF",
            report=report,
            context=context(local, remote),
            intent=CandidatePlanIntent(
                confirmed=True,
                service_port=8080,
                bind_host="not-an-ip",
                bind_port=18881,
                duration_seconds=60,
            ),
        )
    )
    assert invalid_host.failure is not None
    assert invalid_host.failure.code == "private_bind_address_required"

    missing_evidence = report.model_copy(
        update={
            "diagnostics": (
                report.diagnostics[0].model_copy(update={"evidence": ()}),
                *report.diagnostics[1:],
            )
        }
    )
    result = run(
        planner.generate(
            question="临时共享 PDF",
            report=missing_evidence,
            context=context(local, remote),
            intent=CandidatePlanIntent(
                confirmed=True,
                service_port=8080,
                bind_host="10.77.0.1",
                bind_port=18881,
                duration_seconds=60,
            ),
        )
    )
    assert result.failure is not None
    assert result.failure.code == "verified_evidence_required"
    assert result.failure.attribution is PlanFailureAttribution.HARNESS_OR_TOOL


def test_agent_accepts_injected_candidate_plan_without_trace() -> None:
    local, remote = NodeId.new(), NodeId.new()
    workflow = CrossNodeDiagnosticWorkflow(
        FakePreparer(("list_network_listeners", "get_process_summary", "list_docker_services")),
        FakeLocalExecutor(),
        local,
    )
    report = run(workflow.inspect(context(local, remote), "10.77.0.1"))
    generated = run(
        CandidateOperationPlanner(ExplainingProvider()).generate(
            question="临时共享 PDF",
            report=report,
            context=context(local, remote),
            intent=CandidatePlanIntent(
                confirmed=True,
                service_port=8080,
                bind_host="10.77.0.1",
                bind_port=18881,
                duration_seconds=60,
            ),
        )
    )
    assert generated.plan is not None
    untraced = generated.plan.model_copy(update={"generation_trace": None})

    class UntracedPlanner(CandidateOperationPlanner):
        async def generate(self, **_kwargs: object) -> CandidatePlanResult:
            return CandidatePlanResult(plan=untraced)

    answer = run(
        CrossNodeDiagnosticAgent(
            workflow,
            ExplainingProvider(),
            UntracedPlanner(ExplainingProvider()),
        ).answer(
            "临时共享 PDF",
            context(local, remote),
            "10.77.0.1",
            plan_intent=CandidatePlanIntent(
                confirmed=True,
                service_port=8080,
                bind_host="10.77.0.1",
                bind_port=18881,
                duration_seconds=60,
            ),
        )
    )
    assert answer.candidate_plan == untraced
    assert answer.plan_trace is None

    class EmptyPlanner(CandidateOperationPlanner):
        async def generate(self, **_kwargs: object) -> CandidatePlanResult:
            return CandidatePlanResult()

    empty = run(
        CrossNodeDiagnosticAgent(
            workflow,
            ExplainingProvider(),
            EmptyPlanner(ExplainingProvider()),
        ).answer(
            "只诊断",
            context(local, remote),
            "10.77.0.1",
            plan_intent=CandidatePlanIntent(
                confirmed=True,
                service_port=8080,
                bind_host="10.77.0.1",
                bind_port=18881,
                duration_seconds=60,
            ),
        )
    )
    assert empty.candidate_plan is None
    assert empty.plan_error_code is None


@pytest.mark.parametrize(
    ("intent", "code"),
    [
        (
            CandidatePlanIntent(
                confirmed=False,
                service_port=8080,
                bind_host="10.77.0.1",
                bind_port=18881,
                duration_seconds=60,
            ),
            "explicit_intent_required",
        ),
        (
            CandidatePlanIntent(
                confirmed=True,
                service_port=8080,
                bind_host="127.0.0.1",
                bind_port=18881,
                duration_seconds=60,
            ),
            "private_bind_address_required",
        ),
        (
            CandidatePlanIntent(
                confirmed=True,
                service_port=12345,
                bind_host="10.77.0.1",
                bind_port=18881,
                duration_seconds=60,
            ),
            "service_evidence_ambiguous",
        ),
        (
            CandidatePlanIntent(
                confirmed=True,
                service_port=9090,
                bind_host="10.77.0.1",
                bind_port=18881,
                duration_seconds=60,
            ),
            "service_not_local_http_candidate",
        ),
    ],
)
def test_candidate_plan_requires_explicit_safe_current_context(
    intent: CandidatePlanIntent,
    code: str,
) -> None:
    local, remote = NodeId.new(), NodeId.new()
    provider = ExplainingProvider()
    answer = run(
        CrossNodeDiagnosticAgent(
            CrossNodeDiagnosticWorkflow(
                FakePreparer(
                    ("list_network_listeners", "get_process_summary", "list_docker_services")
                ),
                FakeLocalExecutor(),
                local,
            ),
            provider,
        ).answer(
            "请临时共享服务",
            context(local, remote),
            "10.77.0.1",
            port=intent.service_port,
            plan_intent=intent,
        )
    )

    assert answer.candidate_plan is None
    assert answer.plan_error_code == code
    assert answer.plan_failure_attribution in {
        PlanFailureAttribution.CONTEXT,
        PlanFailureAttribution.GOVERNANCE,
    }
    assert len(provider.requests) == 0


def test_candidate_plan_rejects_port_missing_from_existing_report() -> None:
    """计划目标必须在既有诊断报告中唯一匹配，不能依赖未执行的推断。"""
    local, remote = NodeId.new(), NodeId.new()
    tool_context = context(local, remote)
    report = run(
        CrossNodeDiagnosticWorkflow(
            FakePreparer(("list_network_listeners", "get_process_summary", "list_docker_services")),
            FakeLocalExecutor(),
            local,
        ).inspect(tool_context, "10.77.0.1")
    )
    provider = ExplainingProvider()

    result = run(
        CandidateOperationPlanner(provider).generate(
            question="请临时共享服务",
            report=report,
            context=tool_context,
            intent=CandidatePlanIntent(
                confirmed=True,
                service_port=12345,
                bind_host="10.77.0.1",
                bind_port=18881,
                duration_seconds=60,
            ),
        )
    )

    assert result.plan is None
    assert result.failure is not None
    assert result.failure.code == "service_evidence_ambiguous"
    assert result.failure.attribution is PlanFailureAttribution.CONTEXT
    assert provider.requests == []


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
