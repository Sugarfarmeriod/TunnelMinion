"""远端服务精选的身份、授权、预算和过期边界。"""

import asyncio
import os
from datetime import timedelta
from typing import cast

import pytest
from pydantic import JsonValue
from tests.agent.test_coordinator import key_set
from tests.coordinator.test_registry import NETWORK, NOW, identity

from tunnelminion.agent.coordinator import CoordinatorAuthorizationView, CoordinatorCache
from tunnelminion.agent.remote import (
    PreparedRemoteAgentTools,
    RemotePreparationError,
    RemoteToolExecutor,
)
from tunnelminion.agent.remote_service_presentation import RemoteServicePresentationObserver
from tunnelminion.agent.service_observation import compute_observed_service_id
from tunnelminion.coordinator.contracts import (
    DirectoryFreshness,
    DirectoryNodeSummary,
    NodeStatus,
    ServiceAccessibility,
    ServiceLifecycle,
    ServiceProtocol,
    ServiceSummary,
)
from tunnelminion.domain.errors import ErrorCode, ToolError
from tunnelminion.domain.identifiers import NodeId, ServiceId, ToolRunId
from tunnelminion.incident.investigation import InvestigationRemoteToolPreparer
from tunnelminion.platforms.windows.models import NodeSummary
from tunnelminion.tools.contracts import (
    ToolCallContext,
    ToolCancellationToken,
    ToolExecutionRequest,
    ToolExecutionResult,
    ToolExecutionStatus,
)
from tunnelminion.tools.registry import ToolRegistry

LOCAL = NodeId("node_" + "1" * 32)
REMOTE = NodeId("node_" + "2" * 32)
TOOLS = ("list_network_listeners", "list_docker_services")


def node(node_id: NodeId = REMOTE) -> DirectoryNodeSummary:
    services = tuple(
        ServiceSummary(
            service_id=compute_observed_service_id(node_id, ServiceProtocol.TCP, host, port),
            protocol=ServiceProtocol.TCP,
            host=host,
            port=port,
            accessibility=ServiceAccessibility.LOOPBACK,
            source="list_network_listeners",
            confidence=0.5,
            observed_at=NOW,
        )
        for host, port in (("127.0.0.1", 43123), ("0.0.0.0", 8088), ("127.0.0.2", 43123))
    )
    return DirectoryNodeSummary(
        identity=identity(node_id),
        status=NodeStatus.ONLINE,
        freshness=DirectoryFreshness.FRESH,
        last_received_at=NOW,
        services=services,
        capability_count=0,
        service_count=len(services),
        server_revision=1,
    )


def cache(*nodes: DirectoryNodeSummary) -> CoordinatorCache:
    result = CoordinatorCache()
    result.replace(
        CoordinatorAuthorizationView(
            network_id=NETWORK,
            generated_at=NOW,
            expires_at=NOW + timedelta(minutes=5),
            nodes=nodes,
            verification_keys=key_set(),
        )
    )
    return result


class Remote:
    def __init__(self) -> None:
        self.tools: tuple[str, ...] = TOOLS
        self.error: BaseException | None = None
        self.platform = "macos"
        self.wrong_identity = False
        self.truncated = False
        self.failed = False
        self.prepared: list[str] = []
        self.executed: list[str] = []
        self.outputs: dict[str, JsonValue] = {
            TOOLS[0]: {
                "availability": "available",
                "items": [
                    {
                        "protocol": "tcp",
                        "address": "127.0.0.1",
                        "port": 43123,
                        "pid": os.getpid(),
                        "process_name": "python3.13",
                    },
                    {
                        "protocol": "tcp",
                        "address": "127.0.0.2",
                        "port": 43123,
                        "pid": 44,
                        "process_name": "system",
                    },
                    {"protocol": "tcp", "address": "0.0.0.0", "port": 8088},
                ],
            },
            TOOLS[1]: {
                "availability": "available",
                "items": [
                    {
                        "container_id": "abc",
                        "name": "my-app",
                        "image": "demo",
                        "ports": "0.0.0.0:8088->80/tcp",
                        "status": "Up",
                    }
                ],
            },
        }

    async def prepare(
        self,
        target_node_id: NodeId,
        context: ToolCallContext,
        requested_tools: tuple[str, ...],
        cancellation: ToolCancellationToken | None = None,
    ) -> PreparedRemoteAgentTools:
        assert requested_tools == TOOLS
        assert context.caller_node_id == LOCAL and context.execution_node_id == target_node_id
        self.prepared.append(str(target_node_id))
        if self.error is not None:
            raise self.error
        return PreparedRemoteAgentTools(
            node_summary=NodeSummary.model_validate(
                {
                    "node_id": str(LOCAL if self.wrong_identity else target_node_id),
                    "platform": self.platform,
                    "agent_status": "ready",
                    "model_status": "unconfigured",
                    "available_tools": [],
                    "wireguard": {
                        "availability": "unavailable",
                        "interface": "utun4",
                        "interface_up": False,
                    },
                }
            ),
            summary_tool_run_id=ToolRunId.new(),
            registry=ToolRegistry(),
            executor=cast(RemoteToolExecutor, self),
            tool_names=self.tools,
        )

    async def execute(
        self,
        request: ToolExecutionRequest,
        cancellation: ToolCancellationToken | None = None,
    ) -> ToolExecutionResult:
        assert request.arguments == {} and request.tool_name in self.tools
        self.executed.append(request.tool_name)
        if self.failed:
            return ToolExecutionResult(
                tool_run_id=ToolRunId.new(),
                status=ToolExecutionStatus.FAILED,
                error=ToolError(code=ErrorCode.INTERNAL, message="证据不可用"),
            )
        result = ToolExecutionResult(
            tool_run_id=ToolRunId.new(),
            status=ToolExecutionStatus.SUCCESS,
            output=self.outputs[request.tool_name],
        )
        return result.model_copy(update={"truncated": True}) if self.truncated else result


def observer(remote: Remote, directory: CoordinatorCache) -> RemoteServicePresentationObserver:
    return RemoteServicePresentationObserver(
        LOCAL, directory, cast(InvestigationRemoteToolPreparer, remote), clock=lambda: NOW
    )


def test_exact_endpoint_names_without_port_guessing_or_local_pid_exclusion() -> None:
    remote = Remote()
    target = node()
    view = observer(remote, cache(target, node(LOCAL)))
    assert view.names() == {}
    asyncio.run(view.refresh())
    assert view.names() == {
        (str(REMOTE), str(target.services[0].service_id)): "Python 服务 · 43123",
        (str(REMOTE), str(target.services[1].service_id)): "Docker · my-app · 8088",
    }
    assert remote.prepared == [str(REMOTE)] and remote.executed == list(TOOLS)


@pytest.mark.parametrize(
    "tools,output",
    [
        ((TOOLS[0],), None),
        (TOOLS, {"availability": "unavailable", "items": [{"name": "不得使用"}]}),
    ],
)
def test_optional_docker_never_expands_authorization(
    tools: tuple[str, ...], output: JsonValue
) -> None:
    remote = Remote()
    target = node()
    view = observer(remote, cache(target))
    asyncio.run(view.refresh())
    remote.tools = tools
    remote.outputs[TOOLS[1]] = output
    remote.executed.clear()
    asyncio.run(view.refresh())
    assert view.names() == {
        (str(REMOTE), str(target.services[0].service_id)): "Python 服务 · 43123"
    }
    assert remote.executed == list(tools)


@pytest.mark.parametrize(
    "failure",
    [
        "permission",
        "timeout",
        "os",
        "identity",
        "platform",
        "capability",
        "truncated",
        "failed",
        "unavailable",
        "invalid",
        "budget",
    ],
)
def test_failure_clears_old_names(failure: str) -> None:
    remote = Remote()
    view = observer(remote, cache(node()))
    asyncio.run(view.refresh())
    assert len(view.names()) == 2
    if failure == "permission":
        remote.error = RemotePreparationError(ErrorCode.FORBIDDEN, "未授权")
    elif failure == "timeout":
        remote.error = TimeoutError()
    elif failure == "os":
        remote.error = OSError()
    elif failure == "identity":
        remote.wrong_identity = True
    elif failure == "platform":
        remote.platform = "windows"
    elif failure == "capability":
        remote.tools = (TOOLS[1],)
    elif failure == "truncated":
        remote.truncated = True
    elif failure == "failed":
        remote.failed = True
    elif failure == "unavailable":
        remote.outputs[TOOLS[0]] = {"availability": "unavailable"}
    elif failure == "invalid":
        remote.outputs[TOOLS[0]] = {"availability": "available", "items": [{}]}
    else:
        remote.outputs[TOOLS[0]] = cast(
            JsonValue, {"availability": "available", "items": [{}] * 1025}
        )
    asyncio.run(view.refresh())
    assert view.names() == {}


@pytest.mark.parametrize(
    "change", ["offline", "revoked", "stale", "removed", "stopped", "id", "host", "udp"]
)
def test_directory_changes_immediately_hide_names(change: str) -> None:
    remote = Remote()
    target = node()
    directory = cache(target)
    view = observer(remote, directory)
    asyncio.run(view.refresh())
    if change in {"offline", "revoked"}:
        target = target.model_copy(update={"status": NodeStatus(change)})
    elif change == "stale":
        target = target.model_copy(update={"freshness": DirectoryFreshness.STALE})
    else:
        changes: dict[str, dict[str, object]] = {
            "stopped": {"lifecycle": ServiceLifecycle.STOPPED},
            "id": {"service_id": ServiceId.new()},
            "host": {"host": "127.0.0.3"},
            "udp": {"protocol": ServiceProtocol.UDP},
        }
        updates = changes.get(change, {})
        target = target.model_copy(
            update={"services": tuple(s.model_copy(update=updates) for s in target.services)}
        )
    updated = cache(*(() if change == "removed" else (target,))).read()
    assert updated is not None
    directory.replace(updated)
    assert view.names() == {}
    asyncio.run(view.refresh())
    assert view.names() == {}


def test_expiry_empty_cache_round_robin_and_cancellation() -> None:
    remote = Remote()
    empty = observer(remote, CoordinatorCache())
    asyncio.run(empty.refresh())
    assert empty.names() == {} and not remote.prepared
    nodes = tuple(node(NodeId(f"node_{index:032x}")) for index in range(2, 8))
    directory = cache(*nodes)
    now = NOW
    view = RemoteServicePresentationObserver(
        LOCAL, directory, cast(InvestigationRemoteToolPreparer, remote), clock=lambda: now
    )
    asyncio.run(view.refresh())
    assert remote.prepared == [str(n.identity.node_id) for n in nodes[:4]]
    asyncio.run(view.refresh())
    assert remote.prepared[4:] == [str(n.identity.node_id) for n in nodes[4:] + nodes[:2]]
    assert len(view.names()) == 12
    now += timedelta(seconds=90)
    assert view.names() == {}
    asyncio.run(view.refresh())
    assert view.names()
    now += timedelta(minutes=5)
    assert view.names() == {}
    asyncio.run(view.refresh())
    assert view.names() == {}
    now = NOW
    remote.error = asyncio.CancelledError()
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(view.refresh())


def test_default_clock_does_not_promote_expired_directory() -> None:
    remote = Remote()
    view = RemoteServicePresentationObserver(
        LOCAL, cache(node()), cast(InvestigationRemoteToolPreparer, remote)
    )
    asyncio.run(view.refresh())
    assert view.names() == {} and not remote.prepared
