"""统一任务在对象、模型、历史结果与节点事实边界上的离线回归。"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock

import pytest
from tests.agent.test_conversation import collect, run
from tests.agent.test_langchain_agent import build_agent
from tests.agent.test_task_continuation import ContinueProvider
from tests.incident.test_investigation import (
    NODE,
    NOW,
    ScriptedProvider,
    _incident,  # pyright: ignore[reportPrivateUsage]
)
from tests.incident.test_tasks import task_harness

from tunnelminion.agent.conversation import RunStatus, StartRunInput
from tunnelminion.agent.task_progress import TaskProgress
from tunnelminion.domain.errors import ErrorCode, ToolError
from tunnelminion.domain.identifiers import NodeId, RunId, ServiceId, ThreadId, ToolRunId
from tunnelminion.incident.contracts import IncidentEventType, IncidentStatus
from tunnelminion.incident.investigation import READ_ONLY_INVESTIGATION_TOOLS
from tunnelminion.incident.tasks import _IncidentTaskAgent  # pyright: ignore[reportPrivateUsage]
from tunnelminion.platforms.windows.models import Availability, NodeSummary, WireGuardStatus
from tunnelminion.tools.contracts import (
    ToolCallContext,
    ToolExecutionRequest,
    ToolExecutionResult,
    ToolExecutionStatus,
)


def task_context() -> ToolCallContext:
    return ToolCallContext(
        thread_id=ThreadId.new(), run_id=RunId.new(), caller_node_id=NODE, execution_node_id=NODE
    )


def test_selecting_same_program_retains_incident_and_switching_program_clears_it(
    tmp_path: Path,
) -> None:
    harness, _, _, stores = task_harness(tmp_path)
    incident = _incident(harness.store, event_type=IncidentEventType.SERVICE_ADDED)
    completed = run(harness.run(incident))
    assert completed.run_id is not None
    thread = harness.conversations.get_run(completed.run_id).thread_id
    target = harness.target(incident)
    assert target is not None

    async def ask() -> None:
        same = await harness.conversations.start_run(
            thread,
            StartRunInput(question="继续看这个程序", tool_names=READ_ONLY_INVESTIGATION_TOOLS),
            target,
        )
        await collect(harness.conversations.stream_events(same.run_id))
        checkpoint = stores.checkpoints.get(same.run_id)
        assert checkpoint is not None
        continuation = checkpoint.public_state["continuation"]
        assert isinstance(continuation, dict)
        assert continuation["incident_id"] == str(incident.incident_id)
        switched = await harness.conversations.start_run(
            thread,
            StartRunInput(question="检查另一个程序", tool_names=READ_ONLY_INVESTIGATION_TOOLS),
            target.model_copy(update={"service_id": ServiceId.new()}),
        )
        await collect(harness.conversations.stream_events(switched.run_id))
        checkpoint = stores.checkpoints.get(switched.run_id)
        assert checkpoint is not None
        continuation = checkpoint.public_state["continuation"]
        assert isinstance(continuation, dict) and continuation["incident_id"] is None

    run(ask())


def test_task_driver_works_without_optional_observers_and_rejects_other_node(
    tmp_path: Path,
) -> None:
    harness, _, _, _ = task_harness(tmp_path)
    incident = _incident(harness.store, event_type=IncidentEventType.SERVICE_ADDED)
    driver = _IncidentTaskAgent(harness, incident.incident_id)
    context = task_context()
    with pytest.raises(ValueError, match="节点与原调查不一致"):
        run(
            driver.run(
                "检查原对象",
                context.model_copy(update={"execution_node_id": NodeId.new()}),
                READ_ONLY_INVESTIGATION_TOOLS,
            )
        )
    result = run(driver.run("检查原对象", context, READ_ONLY_INVESTIGATION_TOOLS))
    assert result.tool_calls == 2 and result.model_rounds == 3


@pytest.mark.parametrize("malformed", [False, True])
def test_failed_or_missing_report_never_fabricates_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, malformed: bool
) -> None:
    harness, _, _, _ = task_harness(tmp_path, provider=ScriptedProvider("unknown_tool"))
    incident = _incident(harness.store, event_type=IncidentEventType.SERVICE_ADDED)
    if malformed:
        monkeypatch.setattr(harness.runner, "run", AsyncMock(return_value=incident))

    async def investigate() -> None:
        started = await harness.follow_up(incident.incident_id, "检查原对象")
        await collect(harness.conversations.stream_events(started.run_id))
        view = harness.conversations.get_run(started.run_id)
        assert view.status is RunStatus.FAILED and view.result is None

    run(investigate())


def test_saved_failed_check_is_not_reused_as_successful_evidence(tmp_path: Path) -> None:
    harness, _, _, _ = task_harness(tmp_path)
    incident = _incident(harness.store, event_type=IncidentEventType.SERVICE_ADDED)
    context = task_context()
    failed = ToolExecutionResult(
        tool_run_id=ToolRunId.new(),
        status=ToolExecutionStatus.FAILED,
        error=ToolError(code=ErrorCode.INTERNAL, message="上次检查失败"),
    )
    progress = TaskProgress().record(
        ToolExecutionRequest(context=context, tool_name="list_network_listeners"), failed, NOW
    )
    driver = _IncidentTaskAgent(harness, incident.incident_id)
    result = run(
        driver.run("补查原对象", context, READ_ONLY_INVESTIGATION_TOOLS, progress=progress)
    )
    final = harness.store.get(incident.incident_id)
    assert final is not None and final.status is IncidentStatus.CONFIRMED
    assert result.tool_calls == 2 and str(failed.tool_run_id) not in result.tool_run_ids


@pytest.mark.parametrize(
    ("case", "facts"),
    [
        ("old-run", 0),
        ("other-tool", 0),
        ("failed", 0),
        ("malformed", 0),
        ("other-node", 0),
        ("unknown-interface", 1),
        ("interface-down", 2),
        ("interface-up", 2),
    ],
)
def test_node_health_claims_require_fresh_successful_same_node_summary(
    case: str, facts: int
) -> None:
    context = task_context()
    draft = run(build_agent(ContinueProvider())[0].run("解释记录", context, ("probe_service",)))
    summary = NodeSummary(
        node_id=str(NodeId.new() if case == "other-node" else NODE),
        platform="windows",
        agent_status="ready",
        model_status="ready",
        wireguard=WireGuardStatus(
            interface="wg-test",
            availability=Availability.DEGRADED
            if case == "unknown-interface"
            else Availability.AVAILABLE,
            interface_up=case != "interface-down",
            addresses=(),
        ),
        available_tools=(),
    )
    request = ToolExecutionRequest(
        context=context.model_copy(update={"run_id": RunId.new()})
        if case == "old-run"
        else context,
        tool_name="list_network_listeners" if case == "other-tool" else "get_node_summary",
    )
    observation = ToolExecutionResult(
        tool_run_id=ToolRunId.new(),
        status=ToolExecutionStatus.FAILED if case == "failed" else ToolExecutionStatus.SUCCESS,
        error=ToolError(code=ErrorCode.INTERNAL, message="检查失败") if case == "failed" else None,
        output=None
        if case == "failed"
        else {}
        if case == "malformed"
        else summary.model_dump(mode="json"),
    )
    checked = _IncidentTaskAgent._node_result(  # pyright: ignore[reportPrivateUsage]
        draft, context, TaskProgress().record(request, observation, NOW)
    )
    assert len(checked.evidence_answer.confirmed_facts) == facts
    assert "还不能确认故障根因" in checked.answer
    if case == "interface-down":
        assert "接口尚未启用" in checked.answer


def test_missing_model_after_interruption_keeps_original_task_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    harness, _, fallback, _ = task_harness(tmp_path)
    incident = _incident(harness.store, event_type=IncidentEventType.SERVICE_ADDED)
    first = run(harness.run(incident))
    harness.store.put_incident(first.model_copy(update={"status": IncidentStatus.INTERRUPTED}))

    def unavailable() -> None:
        raise ValueError("模型配置不再可用")

    monkeypatch.setattr(harness.runner, "_provider_factory", unavailable)

    async def investigate() -> None:
        started = await harness.follow_up(incident.incident_id, "继续原调查")
        await collect(harness.conversations.stream_events(started.run_id))
        assert harness.conversations.get_run(started.run_id).status is RunStatus.FAILED
        source = harness.store.get(incident.incident_id)
        assert source is not None and source.run_id == started.run_id
        assert source.status is IncidentStatus.INVESTIGATION_UNAVAILABLE

    run(investigate())
    assert fallback.requests == []
