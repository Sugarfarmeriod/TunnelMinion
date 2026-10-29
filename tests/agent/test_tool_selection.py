"""按问题挑工具：只在允许集合内收窄，认不出就全给，模型可以要回全部工具。"""

from __future__ import annotations

import asyncio
import json

import pytest
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from pydantic import ValidationError

from tunnelminion.agent.tool_selection import (
    MAX_TOOL_LIMIT,
    REQUEST_MORE_TOOLS,
    TOOL_USAGE,
    ToolSelectionSettings,
    detect_topics,
    request_more_tools_description,
    select_tools,
    usage_description,
)
from tunnelminion.domain.delegation import DELEGATE_TOOL_NAME
from tunnelminion.evaluation.tool_selection import (
    WEB_TOOL_NAMES,
    SelectionProbeProvider,
    ToolSelectionCase,
    build_agent,
    build_registry,
    case_inputs,
)
from tunnelminion.model.contracts import (
    CancellationToken,
    ModelCapabilities,
    ModelRequest,
    ModelResponse,
    ToolCall,
)

DEFAULT = ToolSelectionSettings()


def test_container_question_keeps_docker_tools_and_hides_unrelated() -> None:
    selection = select_tools("相册容器是不是停了？", WEB_TOOL_NAMES, settings=DEFAULT)

    assert selection.topics == ("container", "repair")
    assert {"list_docker_services", "read_container_logs", "propose_repair"} <= set(
        selection.visible
    )
    assert "get_wireguard_status" in selection.hidden
    assert "list_launch_records" in selection.hidden
    assert set(selection.visible) | set(selection.hidden) == set(WEB_TOOL_NAMES)
    assert [name for name in WEB_TOOL_NAMES if name in selection.visible] == list(selection.visible)


def test_unknown_topic_keeps_every_allowed_tool() -> None:
    selection = select_tools("帮我看看有什么问题", WEB_TOOL_NAMES, settings=DEFAULT)

    assert selection.topics == ()
    assert selection.visible == WEB_TOOL_NAMES
    assert selection.hidden == ()


def test_focus_off_returns_allowed_unchanged() -> None:
    selection = select_tools(
        "相册容器是不是停了？", WEB_TOOL_NAMES, settings=ToolSelectionSettings(focus=False)
    )

    assert selection.visible == WEB_TOOL_NAMES
    assert selection.topics == ()


def test_application_kind_adds_topic_without_keywords() -> None:
    assert detect_topics("为什么用不了？", "docker") == ("container", "repair")
    assert detect_topics("这个程序还在吗？", "python") == ("script",)
    assert detect_topics("这个程序还在吗？", "program") == ()
    assert detect_topics("这个程序还在吗？") == ()


def test_repair_without_kind_keeps_both_playbooks() -> None:
    selection = select_tools("服务挂了，帮我修一下", WEB_TOOL_NAMES, settings=DEFAULT)

    assert {
        "propose_repair",
        "list_network_listeners",
        "list_docker_services",
        "read_container_logs",
        "list_launch_records",
    } <= set(selection.visible)


def test_cap_keeps_required_and_highest_scores() -> None:
    selection = select_tools(
        "相册打不开了，它是用 Docker 跑的，帮我修一下",
        WEB_TOOL_NAMES,
        settings=ToolSelectionSettings(max_tools=3),
        required=("get_wireguard_status",),
    )

    assert len(selection.visible) == 3
    assert "get_wireguard_status" in selection.visible
    assert "list_network_listeners" in selection.visible


def test_cap_never_drops_unknown_or_delegate_tools() -> None:
    allowed = (*WEB_TOOL_NAMES, "custom_probe", DELEGATE_TOOL_NAME)
    selection = select_tools(
        "WireGuard 通不通", allowed, settings=ToolSelectionSettings(max_tools=3)
    )

    assert "custom_probe" in selection.visible
    assert DELEGATE_TOOL_NAME in selection.visible
    assert "get_wireguard_status" in selection.visible
    assert set(selection.visible) <= set(allowed)


def test_cap_without_topic_uses_base_order() -> None:
    selection = select_tools(
        "帮我看看有什么问题", WEB_TOOL_NAMES, settings=ToolSelectionSettings(max_tools=4)
    )

    assert set(selection.visible) == {
        "list_network_listeners",
        "list_docker_services",
        "get_process_summary",
        "probe_service_reachability",
    }


def test_cap_bounds_are_validated() -> None:
    with pytest.raises(ValidationError):
        ToolSelectionSettings(max_tools=2)
    with pytest.raises(ValidationError):
        ToolSelectionSettings(max_tools=MAX_TOOL_LIMIT + 1)


def test_descriptions_explain_when_to_use() -> None:
    assert usage_description("list_docker_services", "只读列出容器。").startswith(
        "只读列出容器。什么时候用："
    )
    assert usage_description("custom", "原说明。") == "原说明。"
    text = request_more_tools_description(("list_docker_services", "custom"))
    assert TOOL_USAGE["list_docker_services"] in text
    assert "custom；" not in text and text.endswith("custom")
    assert "不扩大权限" in text


class _CallsHiddenToolProvider:
    """第一轮直接调用被藏起来、但本次允许的工具；第二轮结束。"""

    def __init__(self) -> None:
        self.seen: list[tuple[str, ...]] = []

    @property
    def capabilities(self) -> ModelCapabilities:
        return ModelCapabilities(tool_calls=True, structured_output=True)

    async def complete(
        self, request: ModelRequest, cancellation: CancellationToken | None = None
    ) -> ModelResponse:
        del cancellation
        self.seen.append(tuple(tool.name for tool in request.tools))
        if len(self.seen) == 1:
            return ModelResponse(
                tool_calls=(ToolCall(call_id="c1", name="get_wireguard_status", arguments={}),)
            )
        return ModelResponse(content="查完了。")


def _case(question: str, **values: object) -> ToolSelectionCase:
    return ToolSelectionCase.model_validate(
        {
            "case_id": "t",
            "question": question,
            "must_see": [],
            "acceptable_first_tools": ["list_docker_services"],
            **values,
        }
    )


def test_agent_hides_tools_then_restores_them_on_request(monkeypatch: pytest.MonkeyPatch) -> None:
    exporter = InMemorySpanExporter()
    tracing = TracerProvider()
    tracing.add_span_processor(SimpleSpanProcessor(exporter))
    monkeypatch.setattr("tunnelminion.telemetry.trace.get_tracer", tracing.get_tracer)
    provider = SelectionProbeProvider()
    agent = build_agent(provider, build_registry({}), ToolSelectionSettings(max_tools=5))
    context, allowed, target = case_inputs(_case("相册容器是不是停了？"))

    result = asyncio.run(agent.run("相册容器是不是停了？", context, allowed, target=target))

    first, second = provider.seen
    assert "get_wireguard_status" not in first
    assert REQUEST_MORE_TOOLS in first
    assert set(allowed) <= set(second)
    assert REQUEST_MORE_TOOLS not in second
    # 请求更多工具不产生证据，也不改变本次允许的集合。
    assert result.tool_calls == 0
    assert result.selected_tools == allowed
    agent_span = next(item for item in exporter.get_finished_spans() if item.name == "agent.run")
    assert agent_span.attributes is not None
    assert agent_span.attributes["agent.tool_selection.expanded"] is True
    assert agent_span.attributes["agent.tool_selection.topics"] == ("container", "repair")
    hidden = agent_span.attributes["agent.tool_selection.hidden"]
    assert isinstance(hidden, tuple) and "get_wireguard_status" in hidden
    tracing.shutdown()


def test_agent_still_runs_hidden_allowed_tool_when_model_calls_it() -> None:
    provider = _CallsHiddenToolProvider()
    agent = build_agent(provider, build_registry({"get_wireguard_status": {"peers": []}}), DEFAULT)
    context, allowed, _ = case_inputs(_case("相册容器是不是停了？"))

    result = asyncio.run(agent.run("相册容器是不是停了？", context, allowed))

    assert "get_wireguard_status" not in provider.seen[0]
    assert result.tool_calls == 1
    assert result.evidence_answer.evidence[0].tool_name == "get_wireguard_status"


def test_workbench_target_keeps_listener_check_and_skill_catalogue_follows_visible() -> None:
    provider = SelectionProbeProvider()
    agent = build_agent(provider, build_registry({}), ToolSelectionSettings(max_tools=3))
    context, allowed, target = case_inputs(
        _case("WireGuard 隧道通不通？", with_target=True, application_kind="program")
    )

    asyncio.run(agent.run("WireGuard 隧道通不通？", context, allowed, target=target))

    assert "list_network_listeners" in provider.seen[0]
    assert "get_wireguard_status" in provider.seen[0]


def test_unknown_topic_has_no_request_more_tools() -> None:
    provider = SelectionProbeProvider()
    agent = build_agent(provider, build_registry({}), DEFAULT)
    context, allowed, _ = case_inputs(_case("帮我看看有什么问题"))

    asyncio.run(agent.run("帮我看看有什么问题", context, allowed))

    assert len(provider.seen) == 1
    assert REQUEST_MORE_TOOLS not in provider.seen[0]
    assert set(allowed) <= set(provider.seen[0])


def test_request_more_tools_result_is_not_evidence() -> None:
    provider = SelectionProbeProvider()
    agent = build_agent(provider, build_registry({}), DEFAULT)
    context, allowed, _ = case_inputs(_case("相册容器是不是停了？"))

    result = asyncio.run(agent.run("相册容器是不是停了？", context, allowed))

    assert result.evidence_answer.evidence == ()
    assert json.loads(json.dumps(result.selected_tools)) == list(allowed)
