"""静态观察的关闭边界、真实装配和证据退化测试。"""

import asyncio
import json
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest
from pydantic import JsonValue

from tunnelminion.agent.remote import PreparedRemoteAgentTools, RemoteToolExecutor
from tunnelminion.agent.service_observation import ServiceObservationSnapshot
from tunnelminion.app import build_windows_application
from tunnelminion.coordinator.contracts import ServiceAccessibility, ServiceProtocol, ServiceSummary
from tunnelminion.domain.identifiers import NodeId, ServiceId, ToolRunId
from tunnelminion.incident.investigation import InvestigationRemoteToolPreparer
from tunnelminion.incident.observer import IncidentObservationService
from tunnelminion.incident.peer_observation import PeerObservationConfig, StaticPeerServiceObserver
from tunnelminion.incident.storage import SQLiteIncidentStore
from tunnelminion.macos_app import build_macos_local_application
from tunnelminion.model.configuration import ModelConfigurationService
from tunnelminion.model.contracts import ProviderError, ProviderErrorCode
from tunnelminion.platforms.windows.models import NodeSummary
from tunnelminion.tools.contracts import (
    ToolCallContext,
    ToolCancellationToken,
    ToolExecutionRequest,
    ToolExecutionResult,
    ToolExecutionStatus,
)
from tunnelminion.tools.registry import ToolRegistry
from tunnelminion.web.overview import ResourceOverview

LOCAL = NodeId("node_" + "1" * 32)
TARGET = NodeId("node_" + "2" * 32)


class Remote:
    def __init__(self) -> None:
        self.items: list[dict[str, object]] = []
        self.availability = "available"
        self.error: Exception | None = None
        self.cancelled = False
        self.invalid_result = False
        self.requests: list[ToolExecutionRequest] = []

    async def prepare(
        self,
        target_node_id: NodeId,
        context: ToolCallContext,
        requested_tools: tuple[str, ...],
        cancellation: ToolCancellationToken | None = None,
    ) -> PreparedRemoteAgentTools:
        assert target_node_id == TARGET and context.execution_node_id == TARGET
        assert requested_tools == ("list_network_listeners",)
        if self.cancelled:
            raise asyncio.CancelledError
        if self.error is not None:
            raise self.error
        return PreparedRemoteAgentTools(
            node_summary=NodeSummary.model_validate(
                {
                    "node_id": str(TARGET),
                    "platform": "macos",
                    "agent_status": "ready",
                    "model_status": "unconfigured",
                    "available_tools": [],
                    "wireguard": {
                        "availability": "available",
                        "interface": "utun4",
                        "interface_up": True,
                        "addresses": ["10.77.0.1"],
                    },
                }
            ),
            summary_tool_run_id=ToolRunId.new(),
            registry=ToolRegistry(),
            executor=cast(RemoteToolExecutor, self),
            tool_names=("list_network_listeners",),
        )

    async def execute(
        self,
        request: ToolExecutionRequest,
        cancellation: ToolCancellationToken | None = None,
    ) -> ToolExecutionResult:
        self.requests.append(request)
        output = {"availability": self.availability, "items": self.items}
        result = ToolExecutionResult(
            tool_run_id=ToolRunId.new(),
            status=ToolExecutionStatus.SUCCESS,
            output=cast(JsonValue, output),
        )
        return result.model_copy(update={"truncated": True}) if self.invalid_result else result


def listener(address: str, port: int = 43123, name: str | None = "demo") -> dict[str, object]:
    return {"protocol": "tcp", "address": address, "port": port, "process_name": name}


def observer(remote: Remote) -> StaticPeerServiceObserver:
    return StaticPeerServiceObserver(
        PeerObservationConfig(enabled=True, node_id=TARGET, port=43123),
        LOCAL,
        cast(InvestigationRemoteToolPreparer, remote),
    )


def test_config_is_opt_in_and_rejects_invalid_or_local_targets(tmp_path: Path) -> None:
    remote = cast(InvestigationRemoteToolPreparer, Remote())
    assert StaticPeerServiceObserver.from_file(tmp_path, LOCAL, remote) is None
    path = tmp_path / "peer-observation.json"
    path.write_text(json.dumps({"node_id": str(TARGET), "port": 43123}), encoding="utf-8")
    assert StaticPeerServiceObserver.from_file(tmp_path, LOCAL, remote) is None
    path.write_text(json.dumps({"enabled": True, "node_id": str(TARGET), "port": 43123}))
    assert StaticPeerServiceObserver.from_file(tmp_path, LOCAL, remote) is not None
    path.write_text('{"enabled":true,"port":0}')
    with pytest.raises(ValueError):
        StaticPeerServiceObserver.from_file(tmp_path, LOCAL, remote)
    with pytest.raises(ValueError, match="远端"):
        StaticPeerServiceObserver(PeerObservationConfig(node_id=LOCAL, port=43123), LOCAL, remote)


@pytest.mark.parametrize(
    "items,accessibility,name",
    [
        (
            [listener("10.77.0.1"), listener("127.0.0.1"), listener("0.0.0.0", 1234)],
            "network",
            "demo",
        ),
        ([listener("127.0.0.1")], "loopback", "demo"),
        ([listener("::1", name=None)], "loopback", None),
        ([listener("127.0.0.1", name="a"), listener("::1", name="b")], "loopback", None),
        ([], "unknown", None),
    ],
)
def test_selected_port_only_and_address_changes_keep_identity(
    items: list[dict[str, object]],
    accessibility: str,
    name: str | None,
) -> None:
    remote = Remote()
    value = observer(remote)
    identity = value.service.service_id
    remote.items = items
    asyncio.run(value.refresh())
    assert value.service.service_id == identity
    assert value.service.accessibility == accessibility
    assert value.service.display_name == name
    assert value.service.port == 43123 and value.service.freshness == "live"
    assert value.node.platform == "macos" and value.node.state == "online"
    assert remote.requests[0].tool_name == "list_network_listeners"
    assert remote.requests[0].arguments == {}


@pytest.mark.parametrize(
    "failure", ["connection", "unavailable", "malformed", "invalid-ip", "truncated"]
)
def test_failed_observation_preserves_last_fact(failure: str) -> None:
    remote = Remote()
    value = observer(remote)
    remote.items = [listener("10.77.0.1")]
    asyncio.run(value.refresh())
    previous = value.service
    if failure == "connection":
        remote.error = OSError("disconnected")
    elif failure == "unavailable":
        remote.availability = "unavailable"
    elif failure == "malformed":
        remote.items = [{"port": 43123}]
    elif failure == "invalid-ip":
        remote.items = [listener("not-an-ip")]
    else:
        remote.invalid_result = True
    asyncio.run(value.refresh())
    assert value.service == previous.model_copy(update={"freshness": "stale"})
    assert value.node.state == "stale"


def test_cancel_does_not_publish_partial_or_stale_results() -> None:
    remote = Remote()
    value = observer(remote)
    remote.cancelled = True
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(value.refresh())
    assert value.service.freshness == "unknown" and remote.requests == []


@pytest.mark.parametrize("platform", ["windows", "macos"])
@pytest.mark.parametrize("initial", ["10.77.0.1", "127.0.0.1", "unknown"])
def test_factories_feed_remote_changes_to_normal_incident_observer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    platform: str,
    initial: str,
) -> None:
    remote = Remote()
    remote.items = [listener(initial)]
    watches = observer(remote)
    captured: list[IncidentObservationService] = []
    overview_providers: list[Callable[[], ResourceOverview]] = []
    model_calls = 0

    async def empty_services(_self: object) -> ServiceObservationSnapshot:
        return ServiceObservationSnapshot(
            observed_at=datetime.now(UTC),
            services=(
                ServiceSummary(
                    service_id=ServiceId("service_" + "3" * 32),
                    protocol=ServiceProtocol.TCP,
                    host="127.0.0.1",
                    port=5555,
                    accessibility=ServiceAccessibility.LOOPBACK,
                    source="list_network_listeners",
                    confidence=1,
                    observed_at=datetime.now(UTC),
                ),
            )
            if remote.items[0]["address"] == "127.0.0.1"
            else (),
        )

    def unavailable(_self: ModelConfigurationService) -> None:
        nonlocal model_calls
        model_calls += 1
        raise ProviderError(ProviderErrorCode.MODEL_NOT_FOUND, "unconfigured")

    def capture(*args: object, **kwargs: object) -> IncidentObservationService:
        overview_providers.append(cast(Callable[[], ResourceOverview], args[0]))
        value = IncidentObservationService(*args, **kwargs)  # pyright: ignore[reportArgumentType]
        captured.append(value)
        return value

    def from_file(*args: object) -> StaticPeerServiceObserver:
        return watches

    monkeypatch.setattr(StaticPeerServiceObserver, "from_file", from_file)
    monkeypatch.setattr(
        "tunnelminion.agent.service_observation.DeterministicServiceObserver.observe",
        empty_services,
    )
    monkeypatch.setattr(ModelConfigurationService, "create_provider", unavailable)
    module = "tunnelminion.app" if platform == "windows" else "tunnelminion.macos_app"
    monkeypatch.setattr(f"{module}.IncidentObservationService", capture)
    build = build_windows_application if platform == "windows" else build_macos_local_application
    bundle = build(tmp_path)

    async def run() -> None:
        await captured[0].observe_once()
        await captured[0].observe_once()
        assert model_calls == 0
        remote.items = [listener("127.0.0.1")]
        assert (await captured[0].observe_once()).incidents == ()
        result = await captured[0].observe_once()
        if initial == "10.77.0.1":
            assert len(result.incidents) == 1
            assert result.incidents[0].event.event_type == "local_only"
            assert result.incidents[0].event.source == "static_peer_observation"
        else:
            assert result.incidents == ()
        await captured[0].observe_once()

    asyncio.run(run())
    assert model_calls == int(initial == "10.77.0.1")
    from fastapi.testclient import TestClient

    client: Any
    with TestClient(bundle.app, base_url="http://127.0.0.1") as client:
        overview = client.get("/api/resources/overview").json()
        assert any(
            item["source"] == "static_peer_observation" for item in overview["services"]["items"]
        )

    # 范围切回普通观察、再切回指定端口，均不得把历史对象误判为新增或消失。
    store = SQLiteIncidentStore(tmp_path / "incidents.sqlite3")
    snapshot = store.latest_snapshot()
    assert snapshot is not None
    current_overview = overview_providers[0]
    resumed = IncidentObservationService(
        current_overview,
        store,
        watched_service_id=watches.service.service_id,
    )
    assert asyncio.run(resumed.observe_once()).incidents == ()
    normal = IncidentObservationService(current_overview, store)
    assert asyncio.run(normal.observe_once()).incidents == ()
    assert asyncio.run(normal.observe_once()).incidents == ()
    restricted = IncidentObservationService(
        current_overview,
        store,
        watched_service_id=ServiceId("service_" + "4" * 32),
    )
    assert asyncio.run(restricted.observe_once()).incidents == ()
    assert asyncio.run(restricted.observe_once()).incidents == ()


@pytest.mark.parametrize("platform", ["windows", "macos"])
def test_factories_reject_duplicate_directory_observation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    platform: str,
) -> None:
    def from_file(*args: object) -> StaticPeerServiceObserver:
        return observer(Remote())

    monkeypatch.setattr(StaticPeerServiceObserver, "from_file", from_file)
    # 只触发装配冲突分支，不启动任何目录或网络循环。
    managed = SimpleNamespace(coordinator=SimpleNamespace(service_cache=object()))
    module = "tunnelminion.app" if platform == "windows" else "tunnelminion.macos_app"

    def build_managed(*args: object, **kwargs: object) -> SimpleNamespace:
        return managed

    monkeypatch.setattr(f"{module}.build_managed_node_application", build_managed)
    build = build_windows_application if platform == "windows" else build_macos_local_application
    with pytest.raises(ValueError, match="同时启用"):
        build(tmp_path)
