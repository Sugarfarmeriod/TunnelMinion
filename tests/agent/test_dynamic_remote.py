"""Coordinator 目录到目标 Gateway 的动态工具装配测试。"""

from __future__ import annotations

import asyncio
from collections import Counter
from collections.abc import Coroutine
from datetime import timedelta
from pathlib import Path
from typing import Any, TypeVar, cast

import httpx
import pytest
from fastapi import FastAPI
from tests.agent.test_remote import StaticAdapter, build_loader, summary
from tests.coordinator.test_identity import online_identity_stack
from tests.coordinator.test_registry import (
    NETWORK,
    NOW,
    MemorySecrets,
    identity,
)
from tests.tools.test_registry import definition

from tunnelminion.agent.coordinator import (
    CoordinatorAuthorizationView,
    CoordinatorCache,
    CoordinatorClientError,
)
from tunnelminion.agent.dynamic_remote import (
    AssertionIssuerTransport,
    DynamicExclusionReason,
    DynamicRemoteToolCoordinator,
    DynamicSelectionSink,
    RemoteTaskStage,
)
from tunnelminion.agent.remote import RemotePreparationError
from tunnelminion.coordinator.client_credentials import (
    AgentRefreshCredentialStore,
    coordinator_refresh_name,
)
from tunnelminion.coordinator.contracts import (
    AccessAssertionRequest,
    AccessAssertionResponse,
    CapabilityAvailability,
    CapabilitySummary,
    DirectoryFreshness,
    DirectoryNodeSummary,
    NodeStatus,
)
from tunnelminion.domain.identifiers import NodeId, RunId, ThreadId
from tunnelminion.domain.tools import Platform, RiskLevel
from tunnelminion.domain.versioning import ProtocolVersion
from tunnelminion.gateway import create_gateway_router
from tunnelminion.gateway.audit import InMemoryGatewaySecurityAuditSink
from tunnelminion.gateway.client import FixedGatewayClient
from tunnelminion.gateway.contracts import GatewayCapabilities
from tunnelminion.gateway.security import (
    GatewayManagedPeerPolicy,
    GatewaySecurityPolicy,
)
from tunnelminion.tools.audit import AuditSink, InMemoryAuditSink
from tunnelminion.tools.contracts import ToolCallContext
from tunnelminion.tools.registry import ToolRegistry
from tunnelminion.tools.runtime import ToolRuntime

T = TypeVar("T")
VERSION = ProtocolVersion(major=1, minor=0)


def run(coroutine: Coroutine[Any, Any, T]) -> T:
    return asyncio.run(coroutine)


class AssertionTransport:
    """测试只需要 assertion 端点，其余控制面方法不会被动态链路调用。"""

    def __init__(self, issue: Any) -> None:
        self._issue = issue
        self.requests: list[AccessAssertionRequest] = []

    async def issue_assertion(
        self,
        request: AccessAssertionRequest,
    ) -> AccessAssertionResponse:
        self.requests.append(request)
        return cast(AccessAssertionResponse, self._issue(request))


def capability(name: str) -> CapabilitySummary:
    return CapabilitySummary(
        name=name,
        version=VERSION,
        platform=Platform.MACOS,
        risk_level=definition(name).risk_level,
        availability=CapabilityAvailability.AVAILABLE,
        schema_hash="a" * 64,
    )


def build_dynamic(
    tmp_path: Path,
    *,
    directory_tools: tuple[str, ...] = (
        "get_node_summary",
        "list_network_listeners",
    ),
    direct_tools: tuple[str, ...] = (
        "get_node_summary",
        "list_network_listeners",
    ),
) -> tuple[
    DynamicRemoteToolCoordinator,
    ToolCallContext,
    DynamicSelectionSink,
    AssertionTransport,
    CoordinatorCache,
    MemorySecrets,
]:
    clock, _, keys, assertions, assertion_request = online_identity_stack(tmp_path)
    local = assertion_request.authentication.node_id
    target = NodeId.new()
    local_identity = identity(local, display_name="WindowsA")
    target_identity = identity(target, display_name="MacB")
    target_node = DirectoryNodeSummary(
        identity=target_identity,
        status=NodeStatus.ONLINE,
        freshness=DirectoryFreshness.FRESH,
        last_received_at=NOW,
        capabilities=tuple(capability(name) for name in directory_tools),
        capability_count=len(directory_tools),
        service_count=0,
        server_revision=9,
    )
    local_node = DirectoryNodeSummary(
        identity=local_identity,
        status=NodeStatus.ONLINE,
        freshness=DirectoryFreshness.FRESH,
        last_received_at=NOW,
        capability_count=0,
        service_count=0,
        server_revision=9,
    )
    key_set = keys.verification_keys()
    cache = CoordinatorCache()
    cache.replace(
        CoordinatorAuthorizationView(
            network_id=NETWORK,
            generated_at=NOW,
            expires_at=NOW + timedelta(seconds=60),
            nodes=(local_node, target_node),
            verification_keys=key_set,
        )
    )

    registry = ToolRegistry()
    for name in direct_tools:
        registry.register(
            definition(name, platforms=frozenset({Platform.MACOS})),
            StaticAdapter(
                summary(target)
                if name == "get_node_summary"
                else {"availability": "available", "items": []}
            ),
        )
    runtime = ToolRuntime(registry, Platform.MACOS, InMemoryAuditSink())
    gateway_policy = GatewaySecurityPolicy(
        [],
        managed_peers=[GatewayManagedPeerPolicy(local, frozenset(direct_tools))],
        coordinator_cache=cache,
        pinned_fingerprints={key_set.keys[0].fingerprint},
        wall_clock=clock.utcnow,
    )
    app = FastAPI()
    app.include_router(
        create_gateway_router(
            target,
            Platform.MACOS,
            registry,
            runtime,
            gateway_policy,
            InMemoryGatewaySecurityAuditSink(),
        )
    )

    def client_factory(
        endpoint: str,
        assertion: str,
        local_node_id: NodeId,
        remote_node_id: NodeId,
        audit_sink: AuditSink,
    ) -> FixedGatewayClient:
        return FixedGatewayClient(
            endpoint,
            assertion,
            local_node_id,
            remote_node_id,
            audit_sink,
            transport=httpx.ASGITransport(app=app),
        )

    secrets = MemorySecrets()
    secrets.set(
        coordinator_refresh_name(NETWORK, local),
        assertion_request.authentication.refresh_credential,
    )
    transport = AssertionTransport(assertions.issue)
    selection = DynamicSelectionSink()
    coordinator = DynamicRemoteToolCoordinator(
        network_id=NETWORK,
        local_node_id=local,
        local_platform=Platform.WINDOWS,
        cache=cache,
        transport=cast(AssertionIssuerTransport, transport),
        credentials=AgentRefreshCredentialStore(secrets),
        audit_sink=InMemoryAuditSink(),
        selection_sink=selection,
        authorized_nodes=(target,),
        supported_tools={name: VERSION for name in directory_tools},
        client_factory=client_factory,
        clock=clock.utcnow,
    )
    context = ToolCallContext(
        thread_id=ThreadId.new(),
        run_id=RunId.new(),
        caller_node_id=local,
        execution_node_id=target,
    )
    return coordinator, context, selection, transport, cache, secrets


def test_dynamic_chain_uses_node_id_assertion_and_direct_capability(tmp_path: Path) -> None:
    coordinator, context, sink, transport, _, _ = build_dynamic(tmp_path)
    result = run(
        coordinator.prepare(
            context.execution_node_id,
            context,
            ("list_network_listeners",),
        )
    )

    assert result.tools.tool_names == ("list_network_listeners",)
    assert transport.requests[0].audience == "tool-gateway"
    assert result.selection.server_revision == 9
    assert len(result.selection.direct_capability_revision) == 64
    assert result.selection.retained_count == 1
    assert result.selection.exclusion_reasons == {"task_stage": 1}
    assert sink.records == (result.selection,)


def test_target_direct_evidence_wins_over_tampered_directory(tmp_path: Path) -> None:
    coordinator, context, sink, _, _, _ = build_dynamic(
        tmp_path,
        directory_tools=("list_docker_services",),
        direct_tools=("get_node_summary", "list_network_listeners"),
    )

    with pytest.raises(RemotePreparationError, match="直连复核"):
        run(
            coordinator.prepare(
                context.execution_node_id,
                context,
                ("list_docker_services",),
            )
        )
    assert sink.records[-1].retained_count == 0
    assert sink.records[-1].exclusion_reasons == {DynamicExclusionReason.DIRECT_CONFLICT.value: 1}


def test_coordinator_failure_can_use_explicit_static_peer() -> None:
    def no_assertion(_: AccessAssertionRequest) -> AccessAssertionResponse:
        raise AssertionError("static fallback 不应申请 assertion")

    static_loader, context, _, _ = build_loader()
    cache = CoordinatorCache()
    secrets = MemorySecrets()
    selection = DynamicSelectionSink(max_records=1)
    coordinator = DynamicRemoteToolCoordinator(
        network_id=NETWORK,
        local_node_id=context.caller_node_id,
        local_platform=Platform.WINDOWS,
        cache=cache,
        transport=cast(AssertionIssuerTransport, AssertionTransport(no_assertion)),
        credentials=AgentRefreshCredentialStore(secrets),
        audit_sink=InMemoryAuditSink(),
        selection_sink=selection,
        authorized_nodes=(context.execution_node_id,),
        supported_tools={"list_network_listeners": VERSION},
    )

    result = run(
        coordinator.prepare(
            context.execution_node_id,
            context,
            ("list_network_listeners",),
            static_fallback=static_loader,
        )
    )
    assert result.selection.used_static_fallback is True
    assert result.tools.tool_names == ("list_network_listeners",)


def test_dynamic_boundary_rejects_context_and_directory_failures(tmp_path: Path) -> None:
    coordinator, context, sink, _, cache, secrets = build_dynamic(tmp_path)
    with pytest.raises(ValueError, match="caller"):
        run(
            coordinator.prepare(
                context.execution_node_id,
                context.model_copy(update={"caller_node_id": NodeId.new()}),
                ("list_network_listeners",),
            )
        )
    with pytest.raises(ValueError, match="execution"):
        run(
            coordinator.prepare(
                NodeId.new(),
                context,
                ("list_network_listeners",),
            )
        )

    original = cache.read()
    assert original is not None
    cache.replace(original.model_copy(update={"expires_at": NOW}))
    with pytest.raises(CoordinatorClientError, match="缓存已过期"):
        run(
            coordinator.prepare(
                context.execution_node_id,
                context,
                ("list_network_listeners",),
            )
        )
    cache.replace(original.model_copy(update={"nodes": original.nodes[:1]}))
    with pytest.raises(CoordinatorClientError, match="不在已验证目录"):
        run(
            coordinator.prepare(
                context.execution_node_id,
                context,
                ("list_network_listeners",),
            )
        )
    target = original.nodes[-1]
    cache.replace(
        original.model_copy(
            update={
                "nodes": (
                    original.nodes[0],
                    target.model_copy(update={"status": NodeStatus.OFFLINE}),
                )
            }
        )
    )
    with pytest.raises(CoordinatorClientError, match="不可用于实时调用"):
        run(
            coordinator.prepare(
                context.execution_node_id,
                context,
                ("list_network_listeners",),
            )
        )
    cache.replace(original)
    coordinator._authorized_nodes = frozenset()  # pyright: ignore[reportPrivateUsage]
    with pytest.raises(CoordinatorClientError, match="未授权"):
        run(
            coordinator.prepare(
                context.execution_node_id,
                context,
                ("list_network_listeners",),
            )
        )
    coordinator._authorized_nodes = frozenset(  # pyright: ignore[reportPrivateUsage]
        {str(context.execution_node_id)}
    )
    secrets.delete(coordinator_refresh_name(NETWORK, context.caller_node_id))
    with pytest.raises(CoordinatorClientError, match="refresh 凭据"):
        run(
            coordinator.prepare(
                context.execution_node_id,
                context,
                ("list_network_listeners",),
            )
        )
    assert not sink.records


def test_directory_filter_reasons_and_empty_selection_are_recorded(tmp_path: Path) -> None:
    coordinator, context, sink, _, _, _ = build_dynamic(tmp_path)
    with pytest.raises(RemotePreparationError, match="目录没有"):
        run(
            coordinator.prepare(
                context.execution_node_id,
                context,
                ("unknown_tool",),
            )
        )
    assert sink.records[-1].retained_count == 0

    base = capability("list_network_listeners")
    assert (
        coordinator._directory_exclusion(  # pyright: ignore[reportPrivateUsage]
            base.model_copy(update={"platform": Platform.WINDOWS}),
            frozenset({base.name}),
            Platform.MACOS,
            RemoteTaskStage.DIAGNOSIS,
        )
        is DynamicExclusionReason.PLATFORM
    )
    assert (
        coordinator._directory_exclusion(  # pyright: ignore[reportPrivateUsage]
            base.model_copy(update={"version": ProtocolVersion(major=2, minor=0)}),
            frozenset({base.name}),
            Platform.MACOS,
            RemoteTaskStage.DIAGNOSIS,
        )
        is DynamicExclusionReason.VERSION_INCOMPATIBLE
    )
    risky = base.model_copy(update={"risk_level": RiskLevel.REQUIRES_APPROVAL})
    assert (
        coordinator._directory_exclusion(  # pyright: ignore[reportPrivateUsage]
            risky,
            frozenset({base.name}),
            Platform.MACOS,
            RemoteTaskStage.DIAGNOSIS,
        )
        is DynamicExclusionReason.RISK
    )
    assert (
        coordinator._directory_exclusion(  # pyright: ignore[reportPrivateUsage]
            risky,
            frozenset({base.name}),
            Platform.MACOS,
            RemoteTaskStage.APPROVED_OPERATION,
        )
        is DynamicExclusionReason.TASK_STAGE
    )
    reasons: Counter[DynamicExclusionReason] = Counter()
    assert (
        coordinator._reconcile(  # pyright: ignore[reportPrivateUsage]
            [base],
            GatewayCapabilities(
                protocol=ProtocolVersion(major=2, minor=0),
                node_id=context.execution_node_id,
                platform=Platform.MACOS,
                tools=(),
            ),
            Platform.MACOS,
            reasons,
        )
        == ()
    )
    assert reasons == {DynamicExclusionReason.VERSION_INCOMPATIBLE: 1}


def test_selection_sink_bounds_and_default_client_validation() -> None:
    with pytest.raises(ValueError, match="上限"):
        DynamicSelectionSink(0)
    with pytest.raises(ValueError, match="私网"):
        DynamicRemoteToolCoordinator._default_client(  # pyright: ignore[reportPrivateUsage]
            "https://example.invalid",
            "x" * 80,
            NodeId.new(),
            NodeId.new(),
            InMemoryAuditSink(),
        )
