"""本机资源总览强类型契约测试。"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from typing import Never, Protocol, cast

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import ValidationError

from tunnelminion.coordinator.contracts import (
    ServiceAccessibility,
    ServiceLifecycle,
    ServiceProtocol,
)
from tunnelminion.domain.identifiers import NodeId, ServiceId
from tunnelminion.domain.tools import Platform
from tunnelminion.network.contracts import ProviderKind
from tunnelminion.web.overview import (
    CoordinatorOverview,
    CoordinatorOverviewState,
    EvidenceStatus,
    KnownNodeOverview,
    KnownNodesOverview,
    KnownNodeState,
    KnownServiceOverview,
    KnownServicesOverview,
    KnownServiceState,
    LocalRuntimeOverview,
    ModelOverview,
    ModelStatus,
    NetworkEvidenceOverview,
    NetworkPathOverview,
    NetworkPathOverviewState,
    OverviewError,
    OverviewFreshness,
    OverviewService,
    OverviewSource,
    RuntimePackageKind,
    RuntimePackageOverview,
    RuntimeReadiness,
    RuntimeState,
    create_overview_router,
)

NOW = datetime(2026, 8, 8, 8, 30, tzinfo=UTC)
NODE = NodeId("node_0123456789abcdef0123456789abcdef")
SERVICE = ServiceId("service_0123456789abcdef0123456789abcdef")


class ApiClient(Protocol):
    """屏蔽 TestClient 当前缺失的严格类型标注。"""

    def get(self, url: str) -> httpx.Response: ...


def _complete_service() -> OverviewService:
    return OverviewService(
        local=lambda: LocalRuntimeOverview(
            source=OverviewSource.LOCAL_RUNTIME,
            evidence_at=NOW,
            freshness=OverviewFreshness.LIVE,
            runtime=RuntimeState.RUNNING,
            platform=Platform.WINDOWS,
            version="0.1.0",
            package=RuntimePackageOverview(
                kind=RuntimePackageKind.STANDALONE,
                version="0.1.0",
                manifest_schema="runtime-package-manifest/v2",
            ),
            readiness=RuntimeReadiness.READY,
        ),
        model=lambda: ModelOverview(
            source=OverviewSource.MODEL_CONFIGURATION,
            evidence_at=NOW,
            freshness=OverviewFreshness.FRESH,
            configured=True,
            status=ModelStatus.AVAILABLE,
        ),
        coordinator=lambda: CoordinatorOverview(
            source=OverviewSource.COORDINATOR_SYNC,
            evidence_at=NOW,
            freshness=OverviewFreshness.FRESH,
            configured=True,
            state=CoordinatorOverviewState.READY,
            revision=7,
            last_success_at=NOW,
        ),
        network_path=lambda: NetworkPathOverview(
            source=OverviewSource.NETWORK_PATH_EVIDENCE,
            evidence_at=NOW,
            freshness=OverviewFreshness.FRESH,
            configured=True,
            state=NetworkPathOverviewState.DIRECT,
            provider=ProviderKind.WINDOWS,
            revision=7,
            handshake=NetworkEvidenceOverview(
                status=EvidenceStatus.PASSED,
                observed_at=NOW,
            ),
            route=NetworkEvidenceOverview(
                status=EvidenceStatus.PASSED,
                observed_at=NOW,
            ),
            probe=NetworkEvidenceOverview(
                status=EvidenceStatus.PASSED,
                observed_at=NOW,
            ),
        ),
        nodes=lambda: KnownNodesOverview(
            source=OverviewSource.COORDINATOR_DIRECTORY,
            evidence_at=NOW,
            freshness=OverviewFreshness.FRESH,
            items=(
                KnownNodeOverview(
                    node_id=NODE,
                    display_name="工作节点",
                    platform=Platform.MACOS,
                    state=KnownNodeState.ONLINE,
                    source=OverviewSource.COORDINATOR_DIRECTORY,
                    evidence_at=NOW,
                    freshness=OverviewFreshness.FRESH,
                    service_count=1,
                ),
            ),
        ),
        services=lambda: KnownServicesOverview(
            source=OverviewSource.COORDINATOR_DIRECTORY,
            evidence_at=NOW,
            freshness=OverviewFreshness.FRESH,
            items=(
                KnownServiceOverview(
                    service_id=SERVICE,
                    node_id=NODE,
                    display_name="媒体服务",
                    protocol=ServiceProtocol.HTTP,
                    port=8080,
                    accessibility=ServiceAccessibility.NETWORK,
                    lifecycle=ServiceLifecycle.ACTIVE,
                    state=KnownServiceState.AVAILABLE,
                    source=OverviewSource.COORDINATOR_DIRECTORY,
                    evidence_at=NOW,
                    freshness=OverviewFreshness.FRESH,
                ),
            ),
        ),
        clock=lambda: NOW,
    )


def test_overview_router_returns_complete_redacted_contract_and_openapi() -> None:
    app = FastAPI()
    app.include_router(create_overview_router(_complete_service()))
    client = cast(ApiClient, TestClient(app))

    response = client.get("/api/resources/overview")
    assert response.status_code == 200
    body = response.json()
    assert body["schema_version"] == "resource-overview/v1"
    assert body["generated_at"] == "2026-08-08T08:30:00Z"
    assert body["local"] == {
        "source": "local_runtime",
        "evidence_at": "2026-08-08T08:30:00Z",
        "freshness": "live",
        "error": None,
        "runtime": "running",
        "platform": "windows",
        "version": "0.1.0",
        "package": {
            "name": "tunnelminion",
            "kind": "standalone",
            "version": "0.1.0",
            "manifest_schema": "runtime-package-manifest/v2",
        },
        "readiness": "ready",
    }
    assert body["model"]["configured"] is True
    assert body["coordinator"]["revision"] == 7
    assert body["network_path"]["handshake"]["status"] == "passed"
    assert body["network_path"]["route"]["status"] == "passed"
    assert body["network_path"]["probe"]["status"] == "passed"
    assert body["nodes"]["items"][0]["state"] == "online"
    assert body["services"]["items"][0]["protocol"] == "http"
    serialized = response.text.lower()
    for forbidden in (
        "private_key",
        "refresh_credential",
        "authorization",
        "gateway_endpoint",
        "selected_candidate_hash",
        "process_or_container",
    ):
        assert forbidden not in serialized

    schema_response = client.get("/openapi.json")
    assert schema_response.status_code == 200
    schema_text = schema_response.text
    assert '"ResourceOverview"' in schema_text
    assert '"KnownServiceOverview"' in schema_text
    assert '"additionalProperties":false' in schema_text
    assert '"/api/resources/overview"' in schema_text


def test_missing_providers_are_unknown_instead_of_unconfigured() -> None:
    view = OverviewService(clock=lambda: NOW).view()

    sections = (
        view.local,
        view.model,
        view.coordinator,
        view.network_path,
        view.nodes,
        view.services,
    )
    assert all(item.source is OverviewSource.UNKNOWN for item in sections)
    assert all(item.freshness is OverviewFreshness.UNKNOWN for item in sections)
    assert all(
        item.error is not None and item.error.code == "overview_provider_missing"
        for item in sections
    )
    assert view.local.runtime is RuntimeState.UNKNOWN
    assert view.local.readiness is RuntimeReadiness.UNKNOWN
    assert view.model.configured is None
    assert view.model.status is ModelStatus.UNKNOWN
    assert view.coordinator.configured is None
    assert view.coordinator.state is CoordinatorOverviewState.UNKNOWN
    assert view.network_path.configured is None
    assert view.network_path.state is NetworkPathOverviewState.UNKNOWN
    assert view.network_path.handshake.status is EvidenceStatus.UNKNOWN
    assert view.nodes.items == ()
    assert view.services.items == ()


def test_provider_failures_are_isolated_and_exception_text_is_not_returned() -> None:
    def fail() -> Never:
        raise RuntimeError("provider exception detail must not leak")

    service = OverviewService(
        local=fail,
        model=fail,
        coordinator=fail,
        network_path=fail,
        nodes=fail,
        services=fail,
        clock=lambda: NOW,
    )
    app = FastAPI()
    app.include_router(create_overview_router(service))
    response = cast(ApiClient, TestClient(app)).get("/api/resources/overview")

    assert response.status_code == 200
    body = response.json()
    for name in ("local", "model", "coordinator", "network_path", "nodes", "services"):
        assert body[name]["error"] == {
            "code": "overview_provider_failed",
            "retryable": True,
        }
    assert "exception detail" not in response.text


def test_malformed_provider_result_degrades_without_widening_the_contract() -> None:
    malformed = cast(
        "Callable[[], ModelOverview]",
        lambda: {"configured": True, "api_key": "secret"},
    )
    view = OverviewService(model=malformed, clock=lambda: NOW).view()

    assert view.model.status is ModelStatus.UNKNOWN
    assert view.model.error == OverviewError(
        code="overview_provider_failed",
        retryable=True,
    )
    assert "secret" not in view.model.model_dump_json()


def test_contract_rejects_extra_secret_fields_invalid_codes_and_naive_times() -> None:
    with pytest.raises(ValidationError):
        RuntimePackageOverview.model_validate({"kind": "unknown", "private_key": "should-not-fit"})
    with pytest.raises(ValidationError):
        OverviewError.model_validate({"code": "Invalid Code"})
    with pytest.raises(ValidationError):
        NetworkEvidenceOverview(
            status=EvidenceStatus.MISSING,
            observed_at=datetime(2026, 8, 8, 8, 30),
        )


def test_overview_clock_must_include_timezone() -> None:
    service = OverviewService(clock=lambda: datetime(2026, 8, 8, 8, 30))

    with pytest.raises(ValueError, match="时区"):
        service.view()
