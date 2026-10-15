"""连接结论只能来自本次同一服务身份的完整监听证据。"""

import asyncio
from datetime import UTC, datetime

import pytest
from pydantic import JsonValue, TypeAdapter, ValidationError
from tests.agent.test_langchain_agent import ScriptedProvider, context, definition

from tunnelminion.agent.conversation import CheckedRunView, RunStatus, RunView
from tunnelminion.agent.langchain_model import TunnelMinionChatModel
from tunnelminion.agent.runtime import (
    EvidenceAnswer,
    EvidenceReference,
    LangChainReadOnlyAgent,
    ServiceCheckTarget,
)
from tunnelminion.agent.service_observation import compute_observed_service_id
from tunnelminion.coordinator.contracts import ServiceProtocol
from tunnelminion.domain.errors import ErrorCode, ToolError
from tunnelminion.domain.identifiers import NodeId, ToolRunId
from tunnelminion.domain.tools import Platform
from tunnelminion.model.contracts import CancellationToken, ModelRequest, ModelResponse
from tunnelminion.tools.audit import InMemoryAuditSink
from tunnelminion.tools.contracts import (
    ToolCancellationToken,
    ToolExecutionRequest,
    ToolExecutionResult,
    ToolExecutionStatus,
)
from tunnelminion.tools.registry import ToolRegistry
from tunnelminion.tools.runtime import ToolRuntime

DRAFT = "程序本身状态正常，未发现阻塞。请改成 0.0.0.0 并开放防火墙。"


def connection_case(
    address: str = "127.0.0.1", protocol: ServiceProtocol = ServiceProtocol.TCP
) -> tuple[ServiceCheckTarget, ToolExecutionRequest, ToolExecutionResult]:
    """构造同一节点和服务身份的完整监听记录。"""
    call_context = context()
    target = ServiceCheckTarget(
        service_id=compute_observed_service_id(
            call_context.execution_node_id, protocol, address, 8787
        ),
        node_id=call_context.execution_node_id,
        display_name="Wireguard Panel",
        protocol=protocol,
        port=8787,
        application_kind="python",
    )
    request = ToolExecutionRequest(context=call_context, tool_name="list_network_listeners")
    result = ToolExecutionResult(
        tool_run_id=ToolRunId.new(),
        status=ToolExecutionStatus.SUCCESS,
        output={
            "availability": "available",
            "items": [{"protocol": protocol.value, "address": address, "port": 8787, "pid": 79774}],
        },
    )
    return target, request, result


def checked(
    target: ServiceCheckTarget, results: list[tuple[ToolExecutionRequest, ToolExecutionResult]]
) -> EvidenceAnswer:
    """只把实际执行信封交给确定性核对，不用模型转抄的引用。"""
    evidence = [
        EvidenceReference(
            tool_run_id=str(result.tool_run_id),
            tool_name=request.tool_name,
            status=result.status.value,
        )
        for request, result in results
    ]
    return LangChainReadOnlyAgent._connection_evidence(  # pyright: ignore[reportPrivateUsage]
        target, results, DRAFT, evidence
    )


def test_connection_facts_do_not_promote_model_advice_or_app_health() -> None:
    """正确取证不能使未经验证的网页状态和开放访问建议变成结论。"""
    target, request, tool_result = connection_case()
    answer = checked(target, [(request, tool_result)])
    assert "只允许这台电脑自己连接" in answer.summary
    assert "网页是否正常" in answer.summary and "还没有验证" in answer.summary
    assert "0.0.0.0" not in answer.summary and "程序本身状态正常" not in answer.summary
    assert answer.confirmed_facts[0].evidence_refs == (str(tool_result.tool_run_id),)
    assert answer.inferences == (DRAFT,)
    assert answer.unknowns


@pytest.mark.parametrize("address", ["127.0.0.2", "::1", "::ffff:127.0.0.1"])
def test_all_loopback_forms_keep_connection_scope(address: str) -> None:
    """IPv6 及映射地址不能被误报为其他电脑可连。"""
    target, request, result = connection_case(address)
    assert "只允许这台电脑自己连接" in checked(target, [(request, result)]).summary


@pytest.mark.parametrize("address", ["0.0.0.0", "::", "192.0.2.1"])
def test_non_loopback_is_not_proof_of_remote_access(address: str) -> None:
    """非环回监听不证明防火墙、网页或跨设备访问正常。"""
    target, request, result = connection_case(address)
    answer = checked(target, [(request, result)])
    assert "不只限这台电脑自身" in answer.summary
    assert "能否从另一台电脑连上，还没有验证" in answer.summary


def test_udp_does_not_become_a_verified_web_service() -> None:
    target, request, result = connection_case("0.0.0.0", ServiceProtocol.UDP)
    answer = checked(target, [(request, result)])
    assert "消息传送入口" in answer.summary and "还不是已验证的网页入口" in answer.summary


@pytest.mark.parametrize(
    "output",
    [
        None,
        {"availability": "available", "items": []},
        {"availability": "degraded", "items": []},
        {"availability": "unavailable", "items": []},
        {"availability": "available", "items": [{"port": 8787}]},
        {
            "availability": "available",
            "items": [{"protocol": "tcp", "address": "::1", "port": 8787}],
        },
        {
            "availability": "available",
            "items": [{"protocol": "udp", "address": "127.0.0.1", "port": 8787}],
        },
    ],
)
def test_incomplete_or_different_identity_cannot_confirm_target(output: JsonValue) -> None:
    """同端口但地址或协议不同，以及不可用或畸形结果，均保留未知。"""
    target, request, result = connection_case()
    answer = checked(target, [(request, result.model_copy(update={"output": output}))])
    assert answer.confirmed_facts == ()
    assert "还没有取得能核对" in answer.summary


def test_wrong_node_wrong_tool_and_no_results_do_not_confirm_target() -> None:
    target, request, result = connection_case()
    wrong_node = request.model_copy(
        update={"context": request.context.model_copy(update={"execution_node_id": NodeId.new()})}
    )
    wrong_tool = request.model_copy(update={"tool_name": "get_node_summary"})
    for results in ([], [(wrong_tool, result)], [(wrong_node, result)]):
        assert checked(target, results).confirmed_facts == ()


def test_invalid_address_stays_unknown() -> None:
    target, request, result = connection_case("not-an-ip")
    assert checked(target, [(request, result)]).confirmed_facts == ()


@pytest.mark.parametrize("status", [ToolExecutionStatus.PARTIAL, ToolExecutionStatus.FAILED])
def test_latest_incomplete_collection_does_not_fall_back_to_older_success(
    status: ToolExecutionStatus,
) -> None:
    target, request, result = connection_case()
    latest = ToolExecutionResult(
        tool_run_id=ToolRunId.new(),
        status=status,
        output=result.output if status is ToolExecutionStatus.PARTIAL else None,
        truncated=status is ToolExecutionStatus.PARTIAL,
        error=ToolError(code=ErrorCode.RESULT_TOO_LARGE, message="当前证据不完整"),
    )
    assert checked(target, [(request, result), (request, latest)]).confirmed_facts == ()


class DraftProvider(ScriptedProvider):
    """故意在成功工具调用后给出超出证据的结论。"""

    async def complete(
        self, request: ModelRequest, cancellation: CancellationToken | None = None
    ) -> ModelResponse:
        response = await super().complete(request, cancellation)
        return response if response.tool_calls else response.model_copy(update={"content": DRAFT})


class ListenerAdapter:
    """只返回测试监听记录，不读取系统或进行连接。"""

    async def execute(
        self, arguments: dict[str, JsonValue], cancellation: ToolCancellationToken
    ) -> JsonValue:
        del arguments, cancellation
        return connection_case()[2].output


def connection_agent() -> tuple[LangChainReadOnlyAgent, DraftProvider]:
    """使用真实工具边界和 Agent 循环，只替换平台数据与模型。"""
    registry = ToolRegistry()
    registry.register(definition("list_network_listeners"), ListenerAdapter())
    provider = DraftProvider()
    agent = LangChainReadOnlyAgent(
        TunnelMinionChatModel(provider=provider),
        registry,
        ToolRuntime(registry, Platform.WINDOWS, InMemoryAuditSink()),
        Platform.WINDOWS,
    )
    return agent, provider


def test_actual_agent_loop_checks_runtime_result_not_final_draft() -> None:
    agent, provider = connection_agent()
    target, request, _ = connection_case()
    result = asyncio.run(
        agent.run(
            "为什么另一台电脑打不开？", request.context, ("list_network_listeners",), target=target
        )
    )
    assert result.answer_checked and result.checked_service_id == target.service_id
    assert "只允许这台电脑自己连接" in result.answer and DRAFT not in result.answer
    assert result.evidence_answer.inferences == (DRAFT,)
    assert result.evidence_answer.confirmed_facts[0].evidence_refs == result.tool_run_ids
    assert provider.requests[0].messages[-1].content == "为什么另一台电脑打不开？"
    assert any("Wireguard Panel" in item.content for item in provider.requests[0].messages)


def test_checked_view_stays_frozen_and_public_serialization_keeps_legacy_fields() -> None:
    """核对标记在本机存储保留，公开 response_model 投影不增加字段。"""
    agent, _ = connection_agent()
    target, request, _ = connection_case()
    result = asyncio.run(
        agent.run("检查连接", request.context, ("list_network_listeners",), target=target)
    )
    view = CheckedRunView(
        run_id=request.context.run_id,
        thread_id=request.context.thread_id,
        status=RunStatus.COMPLETED,
        created_at=datetime.now(UTC),
        result=result,
    )
    assert view.model_dump()["result"]["answer_checked"] is True
    legacy = TypeAdapter(RunView).dump_python(view)
    assert "answer_checked" not in legacy["result"]
    assert "checked_service_id" not in legacy["result"]
    with pytest.raises(ValidationError, match="frozen_instance"):
        view.result = None
