"""技能按需查阅与系统检查共享预算，但方法文字不能变成事实或权限。"""

from __future__ import annotations

import json

import pytest
from tests.agent.test_langchain_agent import ScriptedProvider, context, definition, run

from tunnelminion.agent.langchain_model import TunnelMinionChatModel
from tunnelminion.agent.runtime import AgentRunLimits, AgentStopReason, LangChainReadOnlyAgent
from tunnelminion.domain.tools import Platform
from tunnelminion.model.contracts import CancellationToken, ModelRequest, ModelResponse, ToolCall
from tunnelminion.tools.audit import InMemoryAuditSink
from tunnelminion.tools.fakes import FakeToolAdapter
from tunnelminion.tools.registry import ToolRegistry
from tunnelminion.tools.runtime import ToolRuntime


class SkillProvider(ScriptedProvider):
    def __init__(self, *, version: str = "1", checks: bool = True) -> None:
        super().__init__()
        self.version = version
        self.checks = checks

    async def complete(
        self, request: ModelRequest, cancellation: CancellationToken | None = None
    ) -> ModelResponse:
        del cancellation
        self.requests.append(request)
        round_number = len(self.requests)
        if round_number == 1:
            return ModelResponse(
                tool_calls=(
                    ToolCall(
                        call_id="read-method",
                        name="read_investigation_skill",
                        arguments={"skill_id": "service.local-only", "version": self.version},
                    ),
                )
            )
        if self.checks and round_number == 2:
            return ModelResponse(
                tool_calls=(
                    ToolCall(
                        call_id="real-check",
                        name="list_network_listeners",
                        arguments={"port": 8082},
                    ),
                )
            )
        return ModelResponse(content="方法不能替代检查，仍有未核实部分。")


def skill_agent(provider: SkillProvider) -> tuple[LangChainReadOnlyAgent, FakeToolAdapter]:
    registry = ToolRegistry()
    adapter = FakeToolAdapter()
    registry.register(definition("list_network_listeners"), adapter)
    return (
        LangChainReadOnlyAgent(
            TunnelMinionChatModel(provider=provider),
            registry,
            ToolRuntime(registry, Platform.WINDOWS, InMemoryAuditSink()),
            Platform.WINDOWS,
        ),
        adapter,
    )


def test_agent_reads_only_catalogue_summary_until_method_is_requested() -> None:
    provider = SkillProvider()
    agent, adapter = skill_agent(provider)
    result = run(agent.run("查清服务访问限制", context(), ("list_network_listeners",)))

    description = provider.requests[0].tools[-1].description
    assert "service.local-only" in description and "服务只能从本机访问" in description
    assert "confirmation_conditions" not in description
    method = json.loads(provider.requests[1].messages[-1].content)
    assert method["kind"] == "investigation-method-not-evidence"
    assert method["grants_permissions"] is False
    assert method["skill"]["confirmation_conditions"]
    assert {item["tool_name"] for item in method["missing_checks"]} == {
        "get_node_summary",
        "probe_service_reachability",
    }
    assert adapter.calls == [{"port": 8082}]
    assert result.selected_tools == ("list_network_listeners",)
    assert result.model_rounds == 3 and result.tool_calls == len(result.tool_run_ids) == 1
    assert all(
        item.tool_name == "list_network_listeners" for item in result.evidence_answer.evidence
    )


@pytest.mark.parametrize("version", ["1", "9", "../SKILL.md"])
def test_reading_method_never_generates_system_evidence(version: str) -> None:
    provider = SkillProvider(version=version, checks=False)
    agent, adapter = skill_agent(provider)
    result = run(agent.run("这是什么方法？", context(), ("list_network_listeners",)))

    method = json.loads(provider.requests[1].messages[-1].content)
    if version != "1":
        assert method == {"available": False, "reason": "技能或版本不在本次目录中"}
    assert adapter.calls == []
    assert result.tool_calls == 0 and result.tool_run_ids == ()
    assert result.evidence_answer.evidence == () and result.evidence_answer.confirmed_facts == ()


def test_skill_lookup_consumes_budget_before_any_additional_machine_check() -> None:
    provider = SkillProvider()
    agent, adapter = skill_agent(provider)
    result = run(
        agent.run(
            "调查访问限制",
            context(),
            ("list_network_listeners",),
            AgentRunLimits(max_tool_calls=1),
        )
    )
    assert result.stop_reason is AgentStopReason.TOOL_LIMIT
    assert adapter.calls == [] and result.tool_calls == 0
    assert result.evidence_answer.evidence == ()
