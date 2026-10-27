"""委派进度的阶段、取消、续传与持久化。"""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncGenerator, Awaitable, Callable
from pathlib import Path
from typing import cast
from unittest.mock import AsyncMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import JsonValue
from tests.agent.test_langchain_agent import ScriptedProvider, run
from tests.gateway.test_delegation import A, B, FakeClient
from tests.test_delegation_apps import configure
from tests.web.test_conversation import ApiClient

from tunnelminion.agent.conversation import InMemoryConversationService, RunEvent, StartRunInput
from tunnelminion.agent.delegation_progress import DelegationProgress, DelegationProgressSink
from tunnelminion.agent.delegation_tool import DelegateToNodeAdapter, delegate_tool_definition
from tunnelminion.agent.langchain_model import TunnelMinionChatModel
from tunnelminion.agent.runtime import LangChainReadOnlyAgent
from tunnelminion.app import WindowsApplication, build_windows_application
from tunnelminion.domain.delegation import (
    DELEGATE_TOOL_NAME,
    DelegationErrorCode,
    DelegationResult,
    DelegationStatus,
)
from tunnelminion.domain.errors import ErrorCode
from tunnelminion.domain.identifiers import RunId, ThreadId
from tunnelminion.domain.tools import Platform
from tunnelminion.gateway.client import RemoteGatewayError
from tunnelminion.macos_app import MacOSLocalApplication, build_macos_local_application
from tunnelminion.memory.sqlite import SQLiteStores
from tunnelminion.model.contracts import CancellationToken, ModelRequest, ModelResponse, ToolCall
from tunnelminion.tools.audit import InMemoryAuditSink
from tunnelminion.tools.contracts import (
    ToolAdapterError,
    ToolCallContext,
    ToolCancellationToken,
    ToolExecutionRequest,
)
from tunnelminion.tools.registry import ToolRegistry
from tunnelminion.tools.runtime import ToolRuntime, current_tool_call_context
from tunnelminion.web.conversation import create_conversation_router

CONTEXT = ToolCallContext(
    thread_id=ThreadId.new(), run_id=RunId.new(), caller_node_id=A, execution_node_id=A
)
ARGUMENTS: dict[str, JsonValue] = {"node_id": str(B), "question": "不应进入进度的问题"}


async def no_sleep(_: float) -> None:
    await asyncio.sleep(0)


def adapter(
    client: FakeClient,
    events: list[DelegationProgress],
    *,
    clock: Callable[[], float] = lambda: 0.0,
    sleep: Callable[[float], Awaitable[None]] = no_sleep,
) -> DelegateToNodeAdapter:
    def report(context: ToolCallContext, progress: DelegationProgress) -> None:
        assert context == CONTEXT
        assert "first" in client.calls
        if progress.phase == "cancelled" and "cancel" in client.calls:
            assert client.calls[-1] == "cancel"
        events.append(progress)

    return DelegateToNodeAdapter(lambda _: client, progress_sink=report, clock=clock, sleep=sleep)


async def call(
    tool: DelegateToNodeAdapter, cancellation: ToolCancellationToken | None = None
) -> JsonValue:
    token = current_tool_call_context.set(CONTEXT)
    try:
        return await tool.execute(ARGUMENTS, cancellation or ToolCancellationToken())
    finally:
        current_tool_call_context.reset(token)


@pytest.mark.parametrize(
    ("statuses", "phases"),
    [
        (
            ["running", "running", "running", "completed"],
            ["submitted", "investigating", "answered"],
        ),
        (["running", "failed"], ["submitted", "failed"]),
        (["running", "cancelled"], ["submitted", "cancelled"]),
        (["completed"], ["submitted", "answered"]),
        (["failed"], ["submitted", "failed"]),
        (["cancelled"], ["submitted", "cancelled"]),
    ],
)
def test_progress_reports_each_phase_once_without_remote_content(
    statuses: list[str], phases: list[str]
) -> None:
    client = FakeClient([DelegationStatus(status) for status in statuses])
    client.base = client.base.model_copy(
        update={
            "result": DelegationResult(
                summary="不应进入进度的远端证据",
                stop_reason="completed",
                model_rounds=1,
                tool_calls=0,
                elapsed_ms=1,
            ),
            "error_code": DelegationErrorCode.FAILED,
        }
    )
    events: list[DelegationProgress] = []
    output = run(call(adapter(client, events)))
    assert isinstance(output, dict)
    assert set(output) == {"answered_by", "status", "error_code", "result"}
    assert output["status"] == statuses[-1]
    assert [event.phase for event in events] == phases
    assert len(phases) == len(set(phases))
    for event, phase in zip(events, phases, strict=True):
        assert event.model_dump(mode="json") == {
            "delegation_id": str(client.base.delegation_id),
            "peer_node_id": str(B),
            "phase": phase,
        }


@pytest.mark.parametrize(
    "error", [RemoteGatewayError(ErrorCode.FORBIDDEN, "拒绝提交"), RuntimeError("提交失败")]
)
def test_rejected_submission_has_no_progress(error: Exception) -> None:
    client = FakeClient([])
    client.submit_delegation = AsyncMock(side_effect=error)
    events: list[DelegationProgress] = []
    with pytest.raises(ToolAdapterError if isinstance(error, RemoteGatewayError) else RuntimeError):
        run(call(adapter(client, events)))
    assert events == []


@pytest.mark.parametrize(
    "error",
    [RemoteGatewayError(ErrorCode.NODE_UNREACHABLE, "无法联系"), RuntimeError("轮询失败")],
)
def test_errors_after_submission_end_in_failed(error: Exception) -> None:
    client = FakeClient([DelegationStatus.RUNNING])
    client.get_delegation = AsyncMock(side_effect=error)
    events: list[DelegationProgress] = []
    with pytest.raises(ToolAdapterError if isinstance(error, RemoteGatewayError) else RuntimeError):
        run(call(adapter(client, events)))
    assert [event.phase for event in events] == ["submitted", "failed"]


def test_timeout_cancels_peer_and_ends_in_failed() -> None:
    client = FakeClient([DelegationStatus.RUNNING])
    ticks = iter([0.0, 0.0, 1000.0])
    events: list[DelegationProgress] = []
    with pytest.raises(ToolAdapterError) as raised:
        run(call(adapter(client, events, clock=lambda: next(ticks))))
    assert raised.value.error.code is ErrorCode.REMOTE_TIMEOUT
    assert client.calls[-1] == "cancel"
    assert [event.phase for event in events] == ["submitted", "investigating", "failed"]


def test_local_cancellation_is_reported_after_remote_cancel() -> None:
    client = FakeClient([DelegationStatus.RUNNING])
    events: list[DelegationProgress] = []
    cancellation = ToolCancellationToken()
    cancellation.cancel()
    run(call(adapter(client, events), cancellation))
    assert client.calls[-1] == "cancel"
    assert [event.phase for event in events] == ["submitted", "cancelled"]


@pytest.mark.parametrize("cancel_run", [True, False])
@pytest.mark.parametrize("cancel_fails", [True, False])
def test_runtime_cancellation_and_timeout_keep_one_terminal_phase(
    cancel_run: bool, cancel_fails: bool
) -> None:
    client = FakeClient([DelegationStatus.RUNNING])
    if cancel_fails:
        client.cancel_delegation = AsyncMock(side_effect=RuntimeError("取消请求失败"))
    events: list[DelegationProgress] = []

    async def scenario() -> None:
        polling = asyncio.Event()

        async def pause(_: float) -> None:
            polling.set()
            await asyncio.Event().wait()

        tool = adapter(client, events, sleep=pause)
        registry = ToolRegistry()
        definition = delegate_tool_definition([], Platform.WINDOWS).model_copy(
            update={"timeout_seconds": 1 if cancel_run else 0.01}
        )
        registry.register(definition, tool)
        runtime = ToolRuntime(registry, Platform.WINDOWS, InMemoryAuditSink())
        cancellation = ToolCancellationToken()
        task = asyncio.create_task(
            runtime.execute(
                ToolExecutionRequest(
                    context=CONTEXT, tool_name=DELEGATE_TOOL_NAME, arguments=ARGUMENTS
                ),
                cancellation,
            )
        )
        await polling.wait()
        if cancel_run:
            cancellation.cancel()
        result = await task
        assert result.error is not None
        assert result.error.code is (ErrorCode.CANCELLED if cancel_run else ErrorCode.TIMEOUT)

    run(scenario())
    if not cancel_fails:
        assert client.calls[-1] == "cancel"
    assert [event.phase for event in events] == [
        "submitted",
        "cancelled" if cancel_run and not cancel_fails else "failed",
    ]


def test_progress_sink_without_tool_context_is_ignored() -> None:
    events: list[DelegationProgress] = []
    client = FakeClient([DelegationStatus.COMPLETED])
    run(adapter(client, events).execute(ARGUMENTS, ToolCancellationToken()))
    assert events == []


class DelegatingProvider(ScriptedProvider):
    async def complete(
        self, request: ModelRequest, cancellation: CancellationToken | None = None
    ) -> ModelResponse:
        if not self.requests:
            self.requests.append(request)
            return ModelResponse(
                tool_calls=(
                    ToolCall(call_id="delegate", name=DELEGATE_TOOL_NAME, arguments=ARGUMENTS),
                )
            )
        return await super().complete(request, cancellation)


def conversation(stores: SQLiteStores, client: FakeClient) -> InMemoryConversationService:
    registry = ToolRegistry()
    service = InMemoryConversationService(
        A,
        lambda: LangChainReadOnlyAgent(
            TunnelMinionChatModel(provider=DelegatingProvider()),
            registry,
            ToolRuntime(registry, Platform.WINDOWS, InMemoryAuditSink()),
            Platform.WINDOWS,
        ),
        stores.checkpoints,
    )
    sink: DelegationProgressSink = service.append_delegation_progress
    registry.register(
        delegate_tool_definition([], Platform.WINDOWS),
        DelegateToNodeAdapter(lambda _: client, progress_sink=sink, sleep=no_sleep),
    )
    return service


def test_delegation_replay_and_restart_preserve_sequence_and_payload(tmp_path: Path) -> None:
    stores = SQLiteStores.open(tmp_path / "runtime.sqlite3")
    client = FakeClient(
        [DelegationStatus.RUNNING, DelegationStatus.RUNNING, DelegationStatus.COMPLETED]
    )
    service = conversation(stores, client)

    async def scenario() -> list[RunEvent]:
        started = await service.start_run(
            service.create_thread().thread_id,
            StartRunInput(question="检查对端服务", tool_names=(DELEGATE_TOOL_NAME,)),
        )
        stream = cast(AsyncGenerator[RunEvent, None], service.stream_events(started.run_id))
        prefix = [await anext(stream) for _ in range(3)]
        await stream.aclose()
        assert prefix[-1].phase == "submitted"
        saved = stores.checkpoints.get(started.run_id)
        assert saved is not None
        saved_events = saved.public_state["events"]
        assert isinstance(saved_events, list)
        assert prefix[-1].model_dump(mode="json") in saved_events
        suffix = [event async for event in service.stream_events(started.run_id, after=3)]
        return prefix + suffix

    events = run(scenario())
    assert [event.sequence for event in events] == list(range(1, 8))
    assert [event.event_type.value for event in events] == [
        "goal",
        "tool",
        "delegation",
        "delegation",
        "delegation",
        "tool",
        "finished",
    ]
    for event, phase in zip(events[2:5], ["submitted", "investigating", "answered"], strict=True):
        assert event.model_dump(mode="json", exclude_none=True) == {
            "sequence": event.sequence,
            "event_type": "delegation",
            "created_at": event.created_at.isoformat().replace("+00:00", "Z"),
            "run_id": str(event.run_id),
            "delegation_id": str(client.base.delegation_id),
            "peer_node_id": str(B),
            "phase": phase,
        }
    assert events[1].target_node_id == str(A)
    assert events[1].delegation_id is None and events[5].phase is None
    restored = InMemoryConversationService(
        A, lambda: pytest.fail("恢复事件不得执行模型"), stores.checkpoints
    )
    app = FastAPI()
    app.include_router(create_conversation_router(restored))
    with TestClient(app, base_url="http://127.0.0.1") as raw:
        http = cast(ApiClient, raw)
        for after in range(len(events) + 1):
            response = http.get(f"/api/runs/{events[0].run_id}/events?after={after}")
            replay = [
                RunEvent.model_validate(json.loads(line.removeprefix("data: ")))
                for line in response.text.splitlines()
                if line.startswith("data: ")
            ]
            assert replay == events[after:]

    progress = DelegationProgress(
        delegation_id=client.base.delegation_id, peer_node_id=B, phase="failed"
    )
    restored.append_delegation_progress(CONTEXT, progress)
    restored.append_delegation_progress(
        CONTEXT.model_copy(update={"run_id": events[0].run_id}), progress
    )
    assert run(_collect(restored, events[0].run_id)) == events


async def _collect(service: InMemoryConversationService, run_id: RunId) -> list[RunEvent]:
    return [event async for event in service.stream_events(run_id)]


@pytest.mark.parametrize("factory", [build_windows_application, build_macos_local_application])
def test_platform_applications_connect_delegation_progress(
    factory: Callable[[Path], WindowsApplication | MacOSLocalApplication],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configure(tmp_path, allow_delegation=True)
    client = FakeClient([DelegationStatus.COMPLETED])

    def gateway(*args: object) -> FakeClient:
        return client

    def provider(_self: object) -> DelegatingProvider:
        return DelegatingProvider()

    monkeypatch.setattr("tunnelminion.agent.delegation_tool.FixedGatewayClient", gateway)
    monkeypatch.setattr(
        "tunnelminion.model.configuration.ModelConfigurationService.create_provider",
        provider,
    )
    service = factory(tmp_path).conversation_service

    async def scenario() -> list[RunEvent]:
        started = await service.start_run(
            service.create_thread().thread_id,
            StartRunInput(question="检查对端服务", tool_names=(DELEGATE_TOOL_NAME,)),
        )
        return await _collect(service, started.run_id)

    events = run(scenario())
    assert [event.phase for event in events if event.event_type.value == "delegation"] == [
        "submitted",
        "answered",
    ]
