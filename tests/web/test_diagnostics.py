"""本机诊断下载的强类型、降级与脱敏契约测试。"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import ValidationError

from tunnelminion.domain.identifiers import NodeId, ServiceId
from tunnelminion.web.diagnostics import (
    DiagnosticsExport,
    DiagnosticsExportService,
    OptionalDiagnosticSource,
    OptionalDiagnosticSourceName,
    OptionalDiagnosticSourceStatus,
    create_diagnostics_router,
)
from tunnelminion.web.overview import (
    KnownNodeOverview,
    KnownNodesOverview,
    KnownNodeState,
    KnownServiceOverview,
    KnownServicesOverview,
    KnownServiceState,
    OverviewFreshness,
    OverviewService,
    OverviewSource,
    ResourceOverview,
)

NOW = datetime(2026, 8, 8, 6, 7, 8, tzinfo=UTC)


class StaticOverview:
    """返回固定公开总览的测试 provider。"""

    def __init__(self, value: ResourceOverview) -> None:
        self.value = value

    def view(self) -> ResourceOverview:
        return self.value


class ExplodingOverview:
    """异常正文可能夹带秘密，但不能进入下载。"""

    def __init__(self, secret: str) -> None:
        self.secret = secret

    def view(self) -> ResourceOverview:
        raise RuntimeError(f"provider failed with {self.secret}")


def client_for(service: DiagnosticsExportService) -> Any:
    app = FastAPI()
    app.include_router(create_diagnostics_router(service))
    return TestClient(app, base_url="http://127.0.0.1")


def test_export_download_has_stable_schema_headers_and_optional_degradation() -> None:
    service = DiagnosticsExportService(
        OverviewService(clock=lambda: NOW),
        clock=lambda: NOW,
    )
    client = client_for(service)

    response = client.get("/api/diagnostics/export")

    assert response.status_code == 200
    assert response.headers["content-type"] == "application/json; charset=utf-8"
    assert response.headers["content-disposition"] == (
        'attachment; filename="tunnelminion-diagnostics-20260808T060708Z.json"'
    )
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["x-content-type-options"] == "nosniff"
    body = response.json()
    assert body["schema_version"] == "diagnostics-export/v1"
    assert body["product"]["name"] == "tunnelminion"
    assert body["overview"]["known_node_count"] == 0
    assert body["overview"]["known_service_count"] == 0
    source_states = [
        (item["source"], item["status"], item["required"]) for item in body["optional_sources"]
    ]
    assert source_states == [
        ("firewall_logging", "unavailable", False),
        ("vendor_vpn_cli", "unavailable", False),
    ]
    assert body["warnings"] == []
    assert "raw_firewall_rules" in body["excluded_categories"]
    assert "wireguard_secrets" in body["excluded_categories"]
    assert len(body["recovery_steps"]) == 3

    operation = client.get("/openapi.json").json()["paths"]["/api/diagnostics/export"]["get"]
    schema = operation["responses"]["200"]["content"]["application/json"]["schema"]
    assert schema["$ref"].endswith("/DiagnosticsExport")
    assert "500" in operation["responses"]


def test_export_omits_untrusted_names_ids_and_rejects_wrong_optional_source() -> None:
    base = OverviewService(clock=lambda: NOW).view()
    malicious = "<script>x</script>"
    gateway_token = "tmn_" + "A" * 40
    node = KnownNodeOverview(
        node_id=NodeId.new(),
        display_name=f"{malicious}{gateway_token}",
        state=KnownNodeState.ONLINE,
        source=OverviewSource.COORDINATOR_DIRECTORY,
        evidence_at=NOW,
        freshness=OverviewFreshness.FRESH,
    )
    service = KnownServiceOverview(
        service_id=ServiceId.new(),
        node_id=node.node_id,
        display_name=f"{malicious}{gateway_token}",
        state=KnownServiceState.AVAILABLE,
        source=OverviewSource.COORDINATOR_DIRECTORY,
        evidence_at=NOW,
        freshness=OverviewFreshness.FRESH,
    )
    overview = base.model_copy(
        update={
            "nodes": KnownNodesOverview(
                source=OverviewSource.COORDINATOR_DIRECTORY,
                evidence_at=NOW,
                freshness=OverviewFreshness.FRESH,
                items=(node,),
            ),
            "services": KnownServicesOverview(
                source=OverviewSource.COORDINATOR_DIRECTORY,
                evidence_at=NOW,
                freshness=OverviewFreshness.FRESH,
                items=(service,),
            ),
        }
    )

    def firewall_status() -> OptionalDiagnosticSource:
        return OptionalDiagnosticSource(
            source=OptionalDiagnosticSourceName.FIREWALL_LOGGING,
            status=OptionalDiagnosticSourceStatus.AVAILABLE,
            evidence_at=NOW,
        )

    def wrong_vpn_status() -> OptionalDiagnosticSource:
        return OptionalDiagnosticSource(
            source=OptionalDiagnosticSourceName.FIREWALL_LOGGING,
            status=OptionalDiagnosticSourceStatus.AVAILABLE,
            evidence_at=NOW,
        )

    payload = DiagnosticsExportService(
        StaticOverview(overview),
        firewall_logging=firewall_status,
        vendor_vpn_cli=wrong_vpn_status,
        clock=lambda: NOW,
    ).build()
    serialized = payload.model_dump_json()

    assert payload.overview.known_node_count == 1
    assert payload.overview.known_service_count == 1
    assert payload.optional_sources[0].status is OptionalDiagnosticSourceStatus.AVAILABLE
    assert payload.optional_sources[1].status is OptionalDiagnosticSourceStatus.UNKNOWN
    assert payload.optional_sources[1].error is not None
    assert payload.optional_sources[1].error.code == "vendor_vpn_cli_status_unknown"
    for forbidden in (malicious, gateway_token, str(node.node_id), str(service.service_id)):
        assert forbidden not in serialized

    with pytest.raises(ValidationError):
        DiagnosticsExport.model_validate({**payload.model_dump(), "api_key": gateway_token})


def test_provider_exceptions_are_redacted_and_overview_failure_is_non_blocking() -> None:
    gateway_token = "tmn_" + "B" * 40
    bearer = "Bearer " + "C" * 40

    def firewall_failure() -> object:
        raise PermissionError(f"{bearer} cannot read firewall log")

    payload = DiagnosticsExportService(
        ExplodingOverview(gateway_token),
        firewall_logging=firewall_failure,
        clock=lambda: NOW,
    ).build()
    serialized = json.dumps(payload.model_dump(mode="json"), ensure_ascii=False)

    assert payload.warnings[0].code == "overview_unavailable"
    assert payload.overview.runtime.runtime.value == "unknown"
    assert payload.optional_sources[0].status is OptionalDiagnosticSourceStatus.UNKNOWN
    assert payload.optional_sources[0].error is not None
    assert payload.optional_sources[0].error.code == "firewall_logging_status_unknown"
    assert payload.optional_sources[1].status is OptionalDiagnosticSourceStatus.UNAVAILABLE
    assert gateway_token not in serialized
    assert bearer not in serialized
    assert "cannot read firewall log" not in serialized


def test_unusable_clock_returns_only_stable_failure_code() -> None:
    secret = "sk-" + "D" * 24

    def bad_clock() -> datetime:
        return NOW.replace(tzinfo=None)

    response = client_for(
        DiagnosticsExportService(OverviewService(clock=lambda: NOW), clock=bad_clock)
    ).get("/api/diagnostics/export")

    assert response.status_code == 500
    assert response.json() == {"detail": {"code": "diagnostics_export_failed", "retryable": True}}
    assert secret not in response.text
