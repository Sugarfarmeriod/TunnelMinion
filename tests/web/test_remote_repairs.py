"""远端修复只在本机内存中保存摘要。"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import Mock, patch

import httpx
import pytest
from fastapi import FastAPI
from tests.agent.test_delegation_progress import ARGUMENTS, DelegatingProvider
from tests.gateway.test_delegation import A, B, FakeClient
from tests.test_delegation_apps import configure
from tests.web.test_peers import configuration, peer, snapshot

from tunnelminion.agent.conversation import StartRunInput
from tunnelminion.agent.delegation_tool import DelegateToNodeAdapter
from tunnelminion.app import WindowsApplication, build_windows_application
from tunnelminion.domain.delegation import (
    DELEGATE_TOOL_NAME,
    DelegationProposedRepair,
    DelegationResult,
    DelegationStatus,
)
from tunnelminion.domain.errors import ErrorCode
from tunnelminion.domain.identifiers import OperationId
from tunnelminion.domain.tools import Platform
from tunnelminion.gateway.client import RemoteGatewayError
from tunnelminion.gateway.contracts import GatewayServices
from tunnelminion.macos_app import MacOSLocalApplication, build_macos_local_application
from tunnelminion.repair.contracts import REPAIR_TERMINAL_STATUSES
from tunnelminion.tools.audit import InMemoryAuditSink
from tunnelminion.tools.contracts import ToolAdapterError, ToolCancellationToken
from tunnelminion.web.peers import PeerServicePoller, create_peers_router
from tunnelminion.web.service_map import LocalServiceMap


def repair(index: int = 1, *, status: str = "awaiting_authorization") -> DelegationProposedRepair:
    return DelegationProposedRepair(
        repair_id=OperationId(f"operation_{index:032x}"),
        service_name="示例服务",
        action="重启示例服务",
        status=status,
        how_to_approve="请到对方的地图上批准",
        expires_at=datetime.now(UTC) + timedelta(minutes=9, seconds=index),
    )


def result(*repairs: DelegationProposedRepair) -> DelegationResult:
    return DelegationResult(
        summary="不应保存的远端原始内容",
        confirmed_facts=("不应保存的事实",),
        proposed_repairs=repairs,
        stop_reason="completed",
        model_rounds=1,
        tool_calls=0,
        elapsed_ms=1,
    )


@pytest.mark.parametrize("status", list(DelegationStatus)[1:])
@pytest.mark.parametrize("has_repairs", [True, False])
def test_adapter_sends_only_successful_nonempty_summaries(
    status: DelegationStatus, has_repairs: bool
) -> None:
    client = FakeClient([status])
    proposed = (repair(),) if has_repairs else ()
    client.base = client.base.model_copy(update={"result": result(*proposed)})
    sink = Mock()
    adapter = DelegateToNodeAdapter(lambda _: client, proposed_repairs_sink=sink)
    asyncio.run(adapter.execute(ARGUMENTS, ToolCancellationToken()))
    if status is DelegationStatus.COMPLETED and has_repairs:
        sink.assert_called_once_with(B, proposed)
        stored = sink.call_args.args[1][0].model_dump()
        assert set(stored) == {
            "repair_id",
            "service_name",
            "action",
            "status",
            "how_to_approve",
            "expires_at",
        }
        assert "不应保存" not in str(stored)
    else:
        sink.assert_not_called()


def test_adapter_does_not_store_on_gateway_failure() -> None:
    client = FakeClient([], error=RemoteGatewayError(ErrorCode.NODE_UNREACHABLE, "无法联系"))
    sink = Mock()
    adapter = DelegateToNodeAdapter(lambda _: client, proposed_repairs_sink=sink)
    with pytest.raises(ToolAdapterError):
        asyncio.run(adapter.execute(ARGUMENTS, ToolCancellationToken()))
    sink.assert_not_called()


def test_cache_is_per_peer_bounded_newest_first_and_updates_same_id(tmp_path: Path) -> None:
    poller = PeerServicePoller(configuration(tmp_path, peer(B)), A, InMemoryAuditSink())
    first, second, third, fourth = (repair(index) for index in range(1, 5))
    poller.remember_repairs(B, (first, second, third))
    poller.remember_repairs(A, (first,))
    poller.remember_repairs(B, (fourth,))
    assert poller.pending_repairs(B) == (fourth, third, second)
    assert poller.pending_repairs(A) == (first,)
    updated = third.model_copy(update={"action": "更新后的摘要"})
    poller.remember_repairs(B, (updated,))
    assert poller.pending_repairs(B) == (fourth, updated, second)


@pytest.mark.parametrize("status", REPAIR_TERMINAL_STATUSES)
def test_terminal_update_removes_previous_summary(tmp_path: Path, status: str) -> None:
    poller = PeerServicePoller(configuration(tmp_path, peer(B)), A, InMemoryAuditSink())
    summary = repair()
    poller.remember_repairs(B, (summary,))
    poller.remember_repairs(B, (summary.model_copy(update={"status": status}),))
    assert not poller.pending_repairs(B)


def test_expired_summaries_are_removed_on_read_and_not_restored(tmp_path: Path) -> None:
    poller = PeerServicePoller(configuration(tmp_path, peer(B)), A, InMemoryAuditSink())
    summary = repair()
    with patch("tunnelminion.web.peers.datetime") as clock:
        clock.now.return_value = summary.expires_at - timedelta(seconds=1)
        poller.remember_repairs(B, (summary,))
        assert poller.pending_repairs(B) == (summary,)
        clock.now.return_value = summary.expires_at
        assert not poller.pending_repairs(B)
        poller.remember_repairs(B, (summary,))
        assert not poller.pending_repairs(B)
    assert not poller.pending_repairs(B)


def test_only_new_running_service_poll_clears_matching_name(tmp_path: Path) -> None:
    value = GatewayServices.model_validate_json(snapshot().content)
    state = "running"
    failed = False

    def response(_: httpx.Request) -> httpx.Response:
        if failed:
            return httpx.Response(503)
        service = value.services[0].model_copy(update={"key": "different-key", "state": state})
        return httpx.Response(
            200, content=value.model_copy(update={"services": (service,)}).model_dump_json()
        )

    poller = PeerServicePoller(
        configuration(tmp_path, peer(B)),
        A,
        InMemoryAuditSink(),
        transport=httpx.MockTransport(response),
    )
    summary = repair()
    other = repair(2).model_copy(update={"service_name": "另一个服务"})
    asyncio.run(poller.refresh())
    poller.remember_repairs(B, (summary, other))
    assert summary in poller.pending_repairs(B)
    failed = True
    asyncio.run(poller.refresh())
    assert summary in poller.pending_repairs(B)
    failed, state = False, "stopped"
    asyncio.run(poller.refresh())
    assert summary in poller.pending_repairs(B)
    state = "running"
    asyncio.run(poller.refresh())
    assert poller.pending_repairs(B) == (other,)


def test_peers_api_exposes_only_pending_summary_fields(tmp_path: Path) -> None:
    poller = PeerServicePoller(configuration(tmp_path, peer(B)), A, InMemoryAuditSink())
    summary = repair()
    poller.remember_repairs(B, (summary,))
    app = FastAPI()
    app.include_router(
        create_peers_router(
            A, Platform.WINDOWS, lambda: "本机", poller, lambda: LocalServiceMap(node_id=A)
        )
    )

    async def scenario() -> None:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app), base_url="http://127.0.0.1"
        ) as client:
            response = await client.get("/api/peers")
            peers = response.json()["peers"]
            assert peers[0]["pending_repairs"] == []
            assert peers[1]["pending_repairs"] == [summary.model_dump(mode="json")]
            assert "不应保存" not in response.text

    asyncio.run(scenario())


@pytest.mark.parametrize("factory", [build_windows_application, build_macos_local_application])
def test_both_platforms_wire_delegation_summaries_into_peers(
    factory: Callable[[Path], WindowsApplication | MacOSLocalApplication],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configure(tmp_path, allow_delegation=True)
    client = FakeClient([DelegationStatus.COMPLETED])
    summary = repair()
    client.base = client.base.model_copy(update={"result": result(summary)})

    def gateway(*args: object) -> FakeClient:
        return client

    def provider(_: object) -> DelegatingProvider:
        return DelegatingProvider()

    monkeypatch.setattr("tunnelminion.agent.delegation_tool.FixedGatewayClient", gateway)
    monkeypatch.setattr(
        "tunnelminion.model.configuration.ModelConfigurationService.create_provider",
        provider,
    )
    bundle = factory(tmp_path)
    service = bundle.conversation_service

    async def scenario() -> None:
        started = await service.start_run(
            service.create_thread().thread_id,
            StartRunInput(question="检查对端服务", tool_names=(DELEGATE_TOOL_NAME,)),
        )
        events = [event async for event in service.stream_events(started.run_id)]
        assert events[-1].event_type.value == "finished"
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(bundle.app), base_url="http://127.0.0.1:8765"
        ) as http:
            peers = (await http.get("/api/peers")).json()["peers"]
            remote = next(peer for peer in peers if peer["node_id"] == str(B))
            assert remote["pending_repairs"] == [summary.model_dump(mode="json")]

    asyncio.run(scenario())
