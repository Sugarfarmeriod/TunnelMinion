"""收尾前查漏：只在要修且证据显示没在运行、却还没提出修法时提醒，而且最多一次。"""

from __future__ import annotations

import asyncio
from collections.abc import Sequence

import pytest
from pydantic import JsonValue

from tunnelminion.agent.follow_through import (
    FOLLOW_THROUGH_MARK,
    missing_steps,
    reminder,
    shows_not_running,
    wants_repair,
)
from tunnelminion.agent.tool_selection import ToolSelectionSettings
from tunnelminion.domain.errors import ErrorCode, ToolError
from tunnelminion.domain.identifiers import NodeId, RunId, ThreadId, ToolRunId
from tunnelminion.evaluation.tool_selection import (
    WEB_TOOL_NAMES,
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
from tunnelminion.tools.contracts import (
    ToolCallContext,
    ToolExecutionRequest,
    ToolExecutionResult,
    ToolExecutionStatus,
)

EXITED: JsonValue = {
    "availability": "available",
    "items": [{"name": "photos-app-1", "status": "Exited (137) 6 minutes ago"}],
}
UP: JsonValue = {"availability": "available", "items": [{"name": "notes", "status": "Up 3 hours"}]}
OUTPUTS: dict[str, JsonValue] = {
    "list_docker_services": EXITED,
    "read_container_logs": {"containers": [{"name": "photos-app-1", "running": False}]},
    "list_network_listeners": {"availability": "available", "items": []},
    "propose_repair": {"proposed": True},
}


def _context() -> ToolCallContext:
    node = NodeId.new()
    return ToolCallContext(
        thread_id=ThreadId.new(), run_id=RunId.new(), caller_node_id=node, execution_node_id=node
    )


def _result(
    name: str, output: JsonValue, *, partial: bool = False
) -> tuple[ToolExecutionRequest, ToolExecutionResult]:
    error = ToolError(code=next(iter(ErrorCode)), message="只拿到一部分") if partial else None
    return (
        ToolExecutionRequest(context=_context(), tool_name=name),
        ToolExecutionResult(
            tool_run_id=ToolRunId.new(),
            status=ToolExecutionStatus.PARTIAL if partial else ToolExecutionStatus.SUCCESS,
            output=output,
            truncated=partial,
            error=error,
        ),
    )


@pytest.mark.parametrize(
    ("question", "expected"),
    [
        ("相册打不开了，帮我修一下", True),
        ("巡检自动提问：相册 挂了（容器已退出），请查明原因；能修的话提出修法。", True),
        ("把脚本重新跑起来", True),
        ("Please restart the photos stack", True),
        ("相册打不开了", False),
        ("相册容器是不是停了？", False),
    ],
)
def test_repair_request_needs_an_explicit_ask(question: str, expected: bool) -> None:
    assert wants_repair(question) is expected


@pytest.mark.parametrize(
    ("name", "output", "expected"),
    [
        ("list_docker_services", EXITED, True),
        ("list_docker_services", UP, False),
        ("list_docker_services", {"items": [{"state": "exited"}]}, True),
        ("list_docker_services", {"items": [{"state": "running"}]}, False),
        ("list_docker_services", {"items": [{"name": "no-state"}, "bad"]}, False),
        ("list_docker_services", {"availability": "unavailable", "items": None}, False),
        ("list_docker_services", ["not", "a", "dict"], False),
        ("read_container_logs", {"containers": [{"running": False}]}, True),
        ("read_container_logs", {"containers": [{"running": True}]}, False),
        ("list_launch_records", {"records": [{"running": False}]}, True),
        ("list_launch_records", {"records": [{"running": True}]}, False),
        ("get_process_summary", {"items": [{"status": "Exited"}]}, False),
    ],
)
def test_not_running_comes_from_structured_fields(
    name: str, output: JsonValue, expected: bool
) -> None:
    assert shows_not_running([_result(name, output)]) is expected


def test_incomplete_tool_results_are_not_evidence() -> None:
    assert not shows_not_running([_result("list_docker_services", EXITED, partial=True)])


def test_missing_steps_cover_listener_and_repair() -> None:
    down = [_result("list_docker_services", EXITED)]
    fix = "帮我修一下相册"

    assert missing_steps(fix, down, check_listener=False, can_propose=True)
    assert not missing_steps("相册是不是停了", down, check_listener=False, can_propose=True)
    assert not missing_steps(fix, down, check_listener=False, can_propose=False)
    assert not missing_steps(
        fix, [_result("list_docker_services", UP)], check_listener=False, can_propose=True
    )
    refused = [*down, _result("propose_repair", {"proposed": False})]
    assert not missing_steps(fix, refused, check_listener=False, can_propose=True)
    both = missing_steps(fix, down, check_listener=True, can_propose=True)
    assert len(both) == 2 and "list_network_listeners" in both[0]
    listened = [*down, _result("list_network_listeners", {"items": []})]
    assert len(missing_steps(fix, listened, check_listener=True, can_propose=True)) == 1
    text = reminder(both)
    assert text.startswith(FOLLOW_THROUGH_MARK) and "不要硬提" in text


class _StubbornProvider:
    """按脚本回答；记录每次请求里是否带了查漏提醒。"""

    def __init__(self, script: Sequence[ModelResponse]) -> None:
        self._script = list(script)
        self.reminders: list[int] = []

    @property
    def capabilities(self) -> ModelCapabilities:
        return ModelCapabilities(tool_calls=True, structured_output=True)

    async def complete(
        self, request: ModelRequest, cancellation: CancellationToken | None = None
    ) -> ModelResponse:
        del cancellation
        self.reminders.append(
            sum(
                message.role == "user" and message.content.startswith(FOLLOW_THROUGH_MARK)
                for message in request.messages
            )
        )
        return self._script.pop(0) if len(self._script) > 1 else self._script[0]


def _call(name: str, arguments: dict[str, JsonValue] | None = None) -> ModelResponse:
    return ModelResponse(
        tool_calls=(ToolCall(call_id=f"call-{name}", name=name, arguments=arguments or {}),)
    )


REPAIR_ARGS: dict[str, JsonValue] = {
    "service_key": "docker:compose:photos",
    "kind": "restart_containers",
    "reason": "容器退出了",
}


def _run(
    question: str,
    script: Sequence[ModelResponse],
    *,
    with_target: bool = False,
    settings: ToolSelectionSettings | None = None,
) -> tuple[_StubbornProvider, tuple[str, ...], str]:
    provider = _StubbornProvider(script)
    agent = build_agent(provider, build_registry(OUTPUTS), settings or ToolSelectionSettings())
    case = ToolSelectionCase(
        case_id="case",
        question=question,
        with_target=with_target,
        application_kind="docker" if with_target else None,
        must_see=("list_docker_services",),
        acceptable_first_tools=("list_docker_services",),
    )
    context, allowed, target = case_inputs(case)
    result = asyncio.run(agent.run(question, context, allowed, target=target))
    called = tuple(item.tool_name for item in result.evidence_answer.evidence)
    return provider, called, result.answer


def test_agent_reminds_once_then_model_proposes() -> None:
    provider, called, answer = _run(
        "相册打不开了，它是用 Docker 跑的，帮我修一下",
        [
            _call("list_docker_services"),
            ModelResponse(content="相册容器退出了。"),
            _call("read_container_logs", {"service_key": "docker:compose:photos"}),
            _call("propose_repair", REPAIR_ARGS),
            ModelResponse(content="已提出重启修法，等你批准。"),
        ],
    )

    assert called == (
        "list_docker_services",
        "read_container_logs",
        "propose_repair",
    )
    assert provider.reminders == [0, 0, 1, 1, 1]
    assert answer.startswith("已提出重启修法")


def test_agent_reminds_at_most_once_and_keeps_the_honest_answer() -> None:
    provider, called, answer = _run(
        "帮我修一下相册",
        [_call("list_docker_services"), ModelResponse(content="日志看不出原因，暂时不修。")],
    )

    assert called == ("list_docker_services",)
    assert provider.reminders == [0, 0, 1]
    assert answer.startswith("日志看不出原因")


def test_agent_does_not_remind_without_repair_request_or_when_running() -> None:
    provider, _, _ = _run(
        "相册容器是不是停了？",
        [_call("list_docker_services"), ModelResponse(content="停了。")],
    )
    assert provider.reminders == [0, 0]


def test_agent_reminds_target_listener_check_once() -> None:
    provider, called, _ = _run(
        "为什么用不了？",
        [
            _call("list_docker_services"),
            ModelResponse(content="容器停了。"),
            _call("list_network_listeners"),
            ModelResponse(content="入口也没有在听。"),
        ],
        with_target=True,
        settings=ToolSelectionSettings(max_tools=5),
    )

    assert called == ("list_docker_services", "list_network_listeners")
    assert provider.reminders == [0, 0, 1, 1]


def test_hidden_propose_repair_is_not_pushed() -> None:
    provider, _, _ = _run(
        "帮我修一下相册容器",
        [_call("list_docker_services"), ModelResponse(content="容器停了。")],
        settings=ToolSelectionSettings(max_tools=3),
    )

    assert provider.reminders == [0, 0]
    assert "propose_repair" in WEB_TOOL_NAMES
