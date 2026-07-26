"""本机资源 API 和基础页面测试。"""

from __future__ import annotations

from datetime import timedelta
from typing import Protocol, cast

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import JsonValue
from tests.agent.test_coordinator import key_set
from tests.coordinator.test_directory import capability, service_summary
from tests.coordinator.test_registry import NETWORK, NOW, identity
from tests.tools.test_registry import definition

from tunnelminion.agent.coordinator import (
    CoordinatorAuthorizationView,
    CoordinatorCache,
    CoordinatorSyncStatus,
    SyncPhase,
)
from tunnelminion.coordinator.contracts import (
    DirectoryFreshness,
    DirectoryNodeSummary,
    NodeStatus,
)
from tunnelminion.domain.identifiers import NodeId, ServiceId
from tunnelminion.domain.tools import Platform
from tunnelminion.network.contracts import ProviderKind
from tunnelminion.network.path_controller import (
    DirectPathEvidence,
    NetworkPathType,
    PathSelection,
)
from tunnelminion.tools.audit import InMemoryAuditSink
from tunnelminion.tools.fakes import FakeToolAdapter
from tunnelminion.tools.registry import ToolRegistry
from tunnelminion.tools.runtime import ToolRuntime
from tunnelminion.web.resources import (
    CoordinatorResourceState,
    coordinator_resource_view,
    create_resource_router,
)


class ApiClient(Protocol):
    """屏蔽 TestClient 当前缺失的严格类型标注。"""

    def get(self, url: str, *, params: dict[str, object] | None = None) -> httpx.Response: ...

    def post(self, url: str, *, json: object) -> httpx.Response: ...


def test_resource_routes_work_without_model_provider() -> None:
    registry = ToolRegistry()
    for name in (
        "get_wireguard_status",
        "list_network_listeners",
        "get_process_summary",
        "list_docker_services",
        "probe_service_reachability",
        "get_node_summary",
    ):
        schema: dict[str, JsonValue] | None = (
            {"type": "object"}
            if name in {"get_process_summary", "probe_service_reachability"}
            else None
        )
        registry.register(definition(name, input_schema=schema), FakeToolAdapter())
    runtime = ToolRuntime(registry, Platform.WINDOWS, InMemoryAuditSink())
    app = FastAPI()
    app.include_router(create_resource_router(runtime, NodeId.new()))
    client = cast(ApiClient, TestClient(app))

    for path in ("wireguard", "listeners", "processes", "docker", "node-summary"):
        response = client.get(f"/api/resources/{path}")
        assert response.status_code == 200
        assert response.json()["status"] == "success"
    limited = client.get("/api/resources/processes", params={"limit": 2})
    assert limited.status_code == 200
    probe = client.post(
        "/api/resources/probe",
        json={"host": "127.0.0.1", "port": 8080},
    )
    assert probe.status_code == 200
    assert probe.json()["status"] == "success"

    page = client.get("/resources")
    assert page.status_code == 200
    assert "即使模型不可用" in page.text
    assert "refreshAll" in page.text
    assert page.headers["cache-control"] == "no-store"
    assert client.get("/api/resources/network-path").json() == {
        "configured": False,
        "provider": None,
        "revision": 0,
        "authorization_state": "unconfigured",
        "path_type": None,
        "candidate_count": 0,
        "handshake_fresh": False,
        "host_route_present": False,
        "target_probe_succeeded": False,
        "last_handshake_at": None,
        "last_probe_at": None,
        "stable_error_code": None,
    }


def test_network_path_resource_is_redacted_and_explicit() -> None:
    registry = ToolRegistry()
    runtime = ToolRuntime(registry, Platform.WINDOWS, InMemoryAuditSink())
    selection = PathSelection(
        path_type=NetworkPathType.DIRECT,
        provider=ProviderKind.WINDOWS,
        revision=2,
        last_known_good_revision=2,
        candidate_count=2,
        consecutive_failures=0,
        consecutive_successes=2,
        selected_at=NOW,
        last_evidence_at=NOW,
    )
    evidence = DirectPathEvidence(
        provider=ProviderKind.WINDOWS,
        revision=2,
        candidate_count=2,
        selected_candidate_hash=f"sha256:{'a' * 64}",
        endpoint_probe_at=NOW,
        endpoint_probe_succeeded=True,
        last_handshake_at=NOW,
        handshake_fresh=True,
        host_route_present=True,
        target_probe_at=NOW,
        target_probe_succeeded=True,
        verified=True,
        observed_at=NOW,
    )
    app = FastAPI()
    app.include_router(
        create_resource_router(
            runtime,
            NodeId.new(),
            path_selection=lambda: selection,
            path_evidence=lambda: evidence,
            path_authorization=lambda: "authorized-l3",
        )
    )
    body = cast(ApiClient, TestClient(app)).get("/api/resources/network-path").json()
    assert body["path_type"] == "direct"
    assert body["provider"] == "windows"
    assert body["revision"] == 2
    assert body["authorization_state"] == "authorized-l3"
    assert body["handshake_fresh"]
    serialized = str(body).lower()
    for forbidden in ("endpoint", "private_key", "selected_candidate_hash", "10.203"):
        assert forbidden not in serialized


def test_coordinator_resource_api_reports_safe_freshness_and_summaries() -> None:
    registry = ToolRegistry()
    for name in (
        "get_wireguard_status",
        "list_network_listeners",
        "get_process_summary",
        "list_docker_services",
        "probe_service_reachability",
        "get_node_summary",
    ):
        registry.register(definition(name), FakeToolAdapter())
    runtime = ToolRuntime(registry, Platform.WINDOWS, InMemoryAuditSink())
    cache = CoordinatorCache()
    remote = identity()
    cache.replace(
        CoordinatorAuthorizationView(
            network_id=NETWORK,
            generated_at=NOW,
            expires_at=NOW + timedelta(seconds=60),
            verification_keys=key_set(),
            nodes=(
                DirectoryNodeSummary(
                    identity=remote,
                    status=NodeStatus.ONLINE,
                    freshness=DirectoryFreshness.FRESH,
                    last_received_at=NOW,
                    capabilities=(capability(),),
                    services=(service_summary(ServiceId.new()),),
                    capability_count=1,
                    service_count=1,
                    server_revision=7,
                ),
            ),
        )
    )
    status = CoordinatorSyncStatus(
        phase=SyncPhase.IDLE,
        last_success_at=NOW,
        server_revision=7,
        capability_count=1,
        service_count=1,
    )
    app = FastAPI()
    app.include_router(
        create_resource_router(
            runtime,
            NodeId.new(),
            coordinator_status=lambda: status,
            coordinator_cache=cache,
            clock=lambda: NOW,
        )
    )
    client = cast(ApiClient, TestClient(app))

    response = client.get("/api/resources/coordinator")
    assert response.status_code == 200
    body = response.json()
    assert body["state"] == "ready"
    assert body["directory_may_be_stale"] is False
    assert body["server_revision"] == 7
    assert body["nodes"][0]["capabilities"][0]["name"]
    assert body["nodes"][0]["services"][0]["port"]
    serialized = response.text.lower()
    for forbidden in ("refresh_credential", "authorization", "assertion", "private_key"):
        assert forbidden not in serialized


def test_coordinator_resource_states_are_explicit() -> None:
    with pytest.raises(ValueError, match="时区"):
        coordinator_resource_view(None, None, now=NOW.replace(tzinfo=None))
    assert (
        coordinator_resource_view(None, None, now=NOW).state
        is CoordinatorResourceState.UNCONFIGURED
    )
    cache = CoordinatorCache()
    status = CoordinatorSyncStatus(
        phase=SyncPhase.BACKOFF,
        last_error_code="offline",
        server_revision=2,
    )
    assert (
        coordinator_resource_view(status, cache, now=NOW).state
        is CoordinatorResourceState.CONNECTING
    )
    node = DirectoryNodeSummary(
        identity=identity(),
        status=NodeStatus.STALE,
        freshness=DirectoryFreshness.STALE,
        last_received_at=NOW,
        capability_count=0,
        service_count=0,
        server_revision=3,
    )
    view = CoordinatorAuthorizationView(
        network_id=NETWORK,
        generated_at=NOW,
        expires_at=NOW + timedelta(seconds=60),
        verification_keys=key_set(),
        nodes=(node,),
    )
    cache.replace(view)
    assert coordinator_resource_view(status, cache, now=NOW).state is CoordinatorResourceState.STALE
    cache.replace(
        view.model_copy(
            update={
                "nodes": (
                    node.model_copy(
                        update={
                            "status": NodeStatus.INCOMPATIBLE,
                            "freshness": DirectoryFreshness.OFFLINE,
                        }
                    ),
                )
            }
        )
    )
    assert (
        coordinator_resource_view(status, cache, now=NOW).state
        is CoordinatorResourceState.INCOMPATIBLE
    )
    cache.replace(
        view.model_copy(
            update={
                "nodes": (
                    node.model_copy(
                        update={
                            "status": NodeStatus.OFFLINE,
                            "freshness": DirectoryFreshness.OFFLINE,
                        }
                    ),
                )
            }
        )
    )
    assert (
        coordinator_resource_view(status, cache, now=NOW).state is CoordinatorResourceState.OFFLINE
    )
    cache.replace(view.model_copy(update={"expires_at": NOW}))
    assert (
        coordinator_resource_view(status, cache, now=NOW).state
        is CoordinatorResourceState.MANAGED_AUTH_EXPIRED
    )
