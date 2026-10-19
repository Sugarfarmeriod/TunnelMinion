"""事件调查读取共享方法目录，旧版本或平台不适用时保留未知。"""

from __future__ import annotations

import asyncio
from dataclasses import replace
from pathlib import Path

import pytest
from tests.incident.test_investigation import (
    NODE,
    NOW,
    REQUEST_NODE,
    _incident,  # pyright: ignore[reportPrivateUsage]
    _remote_runtime,  # pyright: ignore[reportPrivateUsage]
)

from tunnelminion.agent.langchain_model import ModelRunMetrics
from tunnelminion.agent.task_progress import TaskProgress
from tunnelminion.domain.identifiers import RunId, ThreadId, ToolRunId
from tunnelminion.domain.tools import Platform
from tunnelminion.incident.contracts import IncidentStatus, SnapshotSource
from tunnelminion.incident.investigation import (
    READ_ONLY_INVESTIGATION_TOOLS,
    IncidentInvestigator,
    InvestigationCancellation,
    InvestigationLimits,
    InvestigationTaskExecution,
)
from tunnelminion.tools.contracts import ToolCallContext, ToolExecutionRequest, ToolExecutionResult


def test_event_model_receives_selected_method_from_same_versioned_catalogue(tmp_path: Path) -> None:
    investigator, store, _, _, provider, _, _ = _remote_runtime(tmp_path, "catalogue")
    result = asyncio.run(
        investigator.run(_incident(store, source=SnapshotSource.COORDINATOR_DIRECTORY))
    )
    assert result.status is IncidentStatus.CONFIRMED
    assert result.investigation is not None
    assert (result.investigation.skill_id, result.investigation.skill_version) == (
        "service.local-only",
        "1",
    )
    method = next(
        message.content
        for message in provider.requests[0].messages
        if "本次目录匹配的调查方法" in message.content
    )
    assert "服务只能从本机访问" in method and "confirmation_conditions" in method


def test_old_method_version_cannot_resume_or_accept_new_confirmed_evidence(tmp_path: Path) -> None:
    investigator, store, _, _, provider, preparer, _ = _remote_runtime(tmp_path, "old-method")
    first = asyncio.run(
        investigator.run(_incident(store, source=SnapshotSource.COORDINATOR_DIRECTORY))
    )
    assert first.investigation is not None
    unknown = first.model_copy(
        update={
            "status": IncidentStatus.INTERRUPTED,
            "investigation": first.investigation.model_copy(update={"skill_version": "9"}),
        }
    )
    store.put_incident(unknown)
    requests = len(provider.requests)
    preparations = len(preparer.calls)
    result = asyncio.run(investigator.run(unknown))
    assert result.status is IncidentStatus.INSUFFICIENT_EVIDENCE
    assert result.report is not None and "版本当前不可用" in result.report.unknowns[0]
    assert len(provider.requests) == requests and len(preparer.calls) == preparations
    assert not investigator._skill_can_confirm(unknown)  # pyright: ignore[reportPrivateUsage]
    assert (
        investigator._record_skill_step(  # pyright: ignore[reportPrivateUsage]
            unknown, "get_node_summary", None, {}, tool_calls=1
        )
        == unknown
    )


def test_target_platform_is_checked_against_actual_remote_preflight(tmp_path: Path) -> None:
    investigator, store, local, remote, provider, preparer, _ = _remote_runtime(
        tmp_path, "unsupported-platform"
    )
    assert preparer.prepared is not None
    preparer.prepared = replace(
        preparer.prepared,
        node_summary=preparer.prepared.node_summary.model_copy(update={"platform": "unsupported"}),
    )
    result = asyncio.run(
        investigator.run(_incident(store, source=SnapshotSource.COORDINATOR_DIRECTORY))
    )
    assert result.status is IncidentStatus.INSUFFICIENT_EVIDENCE
    assert result.report is not None and "不适用于目标电脑" in result.report.unknowns[0]
    assert provider.requests == [] and local.calls == [] and remote.calls == []
    assert preparer.prepared.summary_tool_run_id in (
        item.tool_run_id for item in result.report.evidence
    )


@pytest.mark.parametrize("allow_target_tools", [True, False])
def test_shared_remote_skill_resumes_remaining_steps_with_current_permissions(
    tmp_path: Path, allow_target_tools: bool
) -> None:
    base, store, local, remote, provider, preparer, _ = _remote_runtime(tmp_path, "shared-skill")
    current = _incident(store, source=SnapshotSource.COORDINATOR_DIRECTORY)
    thread_id = ThreadId.new()
    progress = TaskProgress()

    def observe(
        request: ToolExecutionRequest, result: ToolExecutionResult, elapsed_ms: float
    ) -> None:
        nonlocal progress
        assert elapsed_ms >= 0
        progress = progress.record(request, result, NOW)

    for attempt in range(2 if allow_target_tools else 1):
        investigator = IncidentInvestigator(
            base._model,  # pyright: ignore[reportPrivateUsage]
            base._registry,  # pyright: ignore[reportPrivateUsage]
            base._tools,  # pyright: ignore[reportPrivateUsage]
            store,
            Platform.WINDOWS,
            local_node_id=REQUEST_NODE,
            remote_tools=preparer,
            clock=lambda: NOW,
            task_execution=InvestigationTaskExecution(
                context=ToolCallContext(
                    thread_id=thread_id,
                    run_id=RunId.new(),
                    caller_node_id=REQUEST_NODE,
                    execution_node_id=NODE,
                ),
                question="补查同一事件缺少的证据",
                limits=InvestigationLimits(max_model_rounds=1 if attempt == 0 else 8),
                cancellation=InvestigationCancellation(),
                metrics=ModelRunMetrics(),
                progress=progress,
                allowed_tools=READ_ONLY_INVESTIGATION_TOOLS
                if allow_target_tools
                else ("get_process_summary",),
                observe=observe,
            ),
        )
        current = asyncio.run(investigator.run(current))
        if attempt == 0 and allow_target_tools:
            assert current.status is IncidentStatus.BUDGET_EXHAUSTED
            previous_preparation = preparer.prepared
            assert previous_preparation is not None
            preparer.prepared = replace(previous_preparation, summary_tool_run_id=ToolRunId.new())
    if allow_target_tools:
        assert current.status is IncidentStatus.CONFIRMED
        assert len(remote.calls) == len(local.calls) == 1
        assert len(preparer.calls) == 2 and len(progress.observations) == 4
        assert current.investigation is not None and current.investigation.model_rounds == 2
    else:
        assert current.status is IncidentStatus.INSUFFICIENT_EVIDENCE
        assert preparer.calls == [] and provider.requests == []
