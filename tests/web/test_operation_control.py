"""本地操作授权页面、API 与持久化降级行为测试。"""

# pyright: reportUnknownMemberType=false, reportUnknownVariableType=false

from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path
from typing import cast

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import ValidationError
from tests.operation.factories import FINGERPRINT, NOW, plan

from tunnelminion.domain.identifiers import AuthorizationId, NodeId, OperationId, ResourceId
from tunnelminion.memory.sqlite import SQLiteStores
from tunnelminion.operation.contracts import (
    AuthorizationDecision,
    AuthorizationKind,
    AuthorizationRecord,
    CleanupRecord,
    CleanupResult,
    OperationError,
    OperationErrorCode,
    OperationRecord,
    OperationStatus,
    ResourceOwnership,
    VerificationRecord,
    VerificationResult,
    transition_operation,
)
from tunnelminion.operation.policy import AuthorizationService, OperationPolicy
from tunnelminion.tools.registry import ToolRegistry
from tunnelminion.web.operations import (
    OperationControlService,
    PreauthorizationInput,
    create_operation_router,
)


class FakeLifecycle:
    """模拟实际持有代理资源的进程执行主动撤销。"""

    def __init__(self, stores: SQLiteStores) -> None:
        self.stores = stores
        self.calls = 0

    async def revoke(self, operation_id: OperationId, *, at: datetime) -> OperationRecord:
        self.calls += 1
        record = self.stores.operations.get(operation_id)
        assert record is not None
        assert record.status is OperationStatus.SUCCEEDED
        assert at.tzinfo is not None
        rolling = transition_operation(
            record,
            OperationStatus.ROLLING_BACK,
            reason="本地用户主动撤销",
            occurred_at=NOW,
        )
        rolled_back = transition_operation(
            rolling,
            OperationStatus.ROLLED_BACK,
            reason="自有资源已清理",
            occurred_at=NOW,
        )
        self.stores.operations.put(rolled_back)
        return rolled_back


def _awaiting_record(*, sensitive: bool = False) -> OperationRecord:
    operation_plan = plan(
        expected_change=("Authorization: Bearer hidden-value" if sensitive else "创建临时私网入口"),
        risk_summary=(
            "x-tunnelminion-share-token=tmn_share_should_not_render"
            if sensitive
            else "指定访问者可临时访问"
        ),
    )
    return transition_operation(
        OperationRecord.planned(operation_plan),
        OperationStatus.AWAITING_AUTHORIZATION,
        reason="等待目标节点本地用户批准",
        occurred_at=NOW,
    )


def _succeeded_record() -> OperationRecord:
    awaiting = _awaiting_record()
    authorization = AuthorizationRecord(
        authorization_id=AuthorizationId.new(),
        operation_id=awaiting.plan.operation_id,
        kind=AuthorizationKind.ONE_TIME,
        decision=AuthorizationDecision.APPROVED,
        operator="target-local-user",
        basis="本地批准",
        decided_at=NOW,
        expires_at=NOW + timedelta(minutes=5),
    )
    authorized = transition_operation(
        awaiting.model_copy(update={"authorization": authorization}),
        OperationStatus.AUTHORIZED,
        reason="本地批准",
        occurred_at=NOW,
    )
    executing = transition_operation(
        authorized,
        OperationStatus.EXECUTING,
        reason="正在创建",
        occurred_at=NOW,
    )
    verifying = transition_operation(
        executing,
        OperationStatus.VERIFYING,
        reason="等待请求节点验证",
        occurred_at=NOW,
    )
    return transition_operation(
        verifying,
        OperationStatus.SUCCEEDED,
        reason="请求节点验证通过",
        occurred_at=NOW,
    )


def _cleanup_failed_record() -> OperationRecord:
    succeeded = _succeeded_record()
    operation_id = succeeded.plan.operation_id
    assert succeeded.authorization is not None
    enriched = succeeded.model_copy(
        update={
            "authorization": succeeded.authorization.model_copy(
                update={"basis": "tmn_gateway_authorization-secret"}
            ),
            "resources": (
                ResourceOwnership(
                    resource_id=ResourceId.new(),
                    operation_id=operation_id,
                    kind="embedded_proxy tmn_gateway_resource-secret",
                    bind_host="10.77.0.1",
                    bind_port=18881,
                    owner_fingerprint=f"sha256:{'2' * 64}",
                    process_id=1234,
                    created_at=NOW,
                ),
            ),
            "verifications": (
                VerificationRecord(
                    operation_id=operation_id,
                    verifier_node_id=succeeded.plan.request_node_id,
                    result=VerificationResult.FAILED,
                    status_code=503,
                    evidence_summary="Authorization: Bearer must-not-leak-verification",
                    verified_at=NOW,
                ),
            ),
            "error": OperationError(
                code=OperationErrorCode.CLEANUP_FAILED,
                message="tmn_gateway_error-secret",
                correlation_id="corr-cleanup-test",
            ),
        }
    )
    rolling_back = transition_operation(
        enriched,
        OperationStatus.ROLLING_BACK,
        reason="Bearer must-not-leak-transition",
        occurred_at=NOW,
    )
    cleanup = CleanupRecord(
        operation_id=operation_id,
        result=CleanupResult.OWNERSHIP_MISMATCH,
        reason="x-tunnelminion-share-token=tmn_share_cleanup-secret",
        manual_action="Authorization: Bearer must-not-leak-manual",
        completed_at=NOW,
    )
    with_cleanup = rolling_back.model_copy(update={"cleanup": cleanup})
    return transition_operation(
        with_cleanup,
        OperationStatus.CLEANUP_FAILED,
        reason=cleanup.reason,
        occurred_at=NOW,
    )


TARGET_NODE = NodeId.new()


def _bundle(
    path: Path,
    *,
    lifecycle: FakeLifecycle | None = None,
) -> tuple[TestClient, SQLiteStores, OperationControlService]:
    stores = SQLiteStores.open(path)
    registry = ToolRegistry()
    authorization = AuthorizationService(
        stores.operations,
        stores.preauthorizations,
        OperationPolicy(registry, stores.preauthorizations),
    )
    service = OperationControlService(
        node_id=TARGET_NODE,
        operations=stores.operations,
        preauthorizations=stores.preauthorizations,
        authorization=authorization,
        lifecycle=lifecycle,
        clock=lambda: NOW,
    )
    app = FastAPI()
    app.include_router(create_operation_router(service))
    return TestClient(app), stores, service


def test_page_and_detail_render_all_decision_fields_without_credentials(tmp_path: Path) -> None:
    client, stores, _ = _bundle(tmp_path / "runtime.sqlite3")
    record = _awaiting_record(sensitive=True)
    stores.operations.put(record)

    page = client.get("/operations")
    assert page.status_code == 200
    assert "最终授权权属于当前目标节点" in page.text
    assert "正在创建入口，尚未成功" in page.text
    assert "入口已创建，正在等待请求节点验证" in page.text
    assert "innerHTML" not in page.text
    assert "X-TunnelMinion-Request" in page.text
    assert client.get("/legacy/operations").text == page.text

    detail = client.get(f"/api/operations/{record.plan.operation_id}")
    assert detail.status_code == 200
    body = detail.json()
    assert body["summary"]["level"] == 2
    assert body["state"] == "awaiting_authorization"
    assert body["allowed_actions"] == ["approve", "reject", "cancel"]
    assert body["service_endpoint"] == "http://127.0.0.1:8080"
    assert body["duration_seconds"] == 300
    assert body["owned_resources"] == []
    assert body["verification_summaries"] == []
    assert body["cleanup_record"] is None
    assert body["manual_action"] is None
    serialized = detail.text
    assert "hidden-value" not in serialized
    assert "tmn_share_should_not_render" not in serialized
    assert serialized.count("[REDACTED]") == 2
    assert client.get("/api/operations/not-an-id").status_code == 404


def test_approval_is_persistent_idempotent_and_does_not_require_model(tmp_path: Path) -> None:
    database = tmp_path / "runtime.sqlite3"
    client, stores, _ = _bundle(database)
    record = _awaiting_record()
    stores.operations.put(record)
    url = f"/api/operations/{record.plan.operation_id}/approve"
    payload = {
        "operator": "target-local-user",
        "expires_at": (NOW + timedelta(minutes=2)).isoformat(),
    }

    first = client.post(url, json=payload)
    second = client.post(url, json=payload)
    assert first.status_code == second.status_code == 200
    assert first.json()["status"] == second.json()["status"] == "authorized"
    assert (
        first.json()["authorization_basis"]
        == second.json()["authorization_basis"]
        == "目标节点本地用户逐次批准"
    )
    assert (
        client.post(
            url,
            json={"operator": "target-local-user", "expires_at": NOW.isoformat()},
        ).status_code
        == 409
    )

    restarted, _, _ = _bundle(database)
    listed = restarted.get("/api/operations").json()
    assert listed[0]["status"] == "authorized"
    assert "state" not in listed[0]
    assert "allowed_actions" not in listed[0]
    detail = restarted.get(f"/api/operations/{record.plan.operation_id}").json()
    assert detail["summary"]["operation_id"] == str(record.plan.operation_id)
    assert detail["state"] == "authorized"
    assert detail["allowed_actions"] == ["cancel"]


def test_detail_exposes_redacted_lifecycle_records_and_typed_openapi(tmp_path: Path) -> None:
    client, stores, _ = _bundle(tmp_path / "runtime.sqlite3")
    record = _cleanup_failed_record()
    stores.operations.put(record)

    response = client.get(f"/api/operations/{record.plan.operation_id}")
    assert response.status_code == 200
    body = response.json()
    assert body["state"] == "cleanup_failed"
    assert body["allowed_actions"] == []
    assert body["owned_resources"] == [
        {
            "resource_id": str(record.resources[0].resource_id),
            "kind": "embedded_proxy [REDACTED]",
            "bind_host": "10.77.0.1",
            "bind_port": 18881,
            "created_at": NOW.isoformat().replace("+00:00", "Z"),
        }
    ]
    assert "process_id" not in body["owned_resources"][0]
    assert "owner_fingerprint" not in body["owned_resources"][0]
    assert body["verification_summaries"] == [
        {
            "verifier_node_id": str(record.plan.request_node_id),
            "result": "failed",
            "status_code": 503,
            "evidence_summary": "[REDACTED]",
            "verified_at": NOW.isoformat().replace("+00:00", "Z"),
        }
    ]
    assert body["cleanup_record"] == {
        "result": "ownership_mismatch",
        "reason": "[REDACTED]",
        "completed_at": NOW.isoformat().replace("+00:00", "Z"),
    }
    assert body["manual_action"] == "[REDACTED]"
    assert body["summary"]["authorization_basis"] == "[REDACTED]"
    assert body["summary"]["error"]["message"] == "[REDACTED]"
    assert "transition-secret" not in response.text
    for secret in (
        "authorization-secret",
        "resource-secret",
        "verification-secret",
        "cleanup-secret",
        "manual-secret",
        "error-secret",
    ):
        assert secret not in response.text

    openapi = client.get("/openapi.json").json()
    detail_schema = openapi["paths"]["/api/operations/{value}"]["get"]["responses"]["200"][
        "content"
    ]["application/json"]["schema"]
    assert detail_schema == {"$ref": "#/components/schemas/OperationDetailView"}
    components = openapi["components"]["schemas"]
    properties = components["OperationDetailView"]["properties"]
    assert properties["state"] == {"$ref": "#/components/schemas/OperationStatus"}
    assert properties["allowed_actions"]["items"] == {
        "$ref": "#/components/schemas/OperationAction"
    }
    assert properties["owned_resources"]["items"] == {
        "$ref": "#/components/schemas/OwnedResourceView"
    }
    assert properties["verification_summaries"]["items"] == {
        "$ref": "#/components/schemas/VerificationSummaryView"
    }
    required_fields = cast(list[str], components["OperationDetailView"]["required"])
    assert {
        "state",
        "allowed_actions",
        "owned_resources",
        "verification_summaries",
        "cleanup_record",
        "manual_action",
    }.issubset(required_fields)


def test_reject_cancel_and_missing_records_are_explicit(tmp_path: Path) -> None:
    client, stores, _ = _bundle(tmp_path / "runtime.sqlite3")
    rejected = _awaiting_record()
    cancelled = _awaiting_record()
    stores.operations.put(rejected)
    stores.operations.put(cancelled)

    response = client.post(
        f"/api/operations/{rejected.plan.operation_id}/reject",
        json={"operator": "owner", "reason": "范围不合适"},
    )
    assert response.status_code == 200
    assert response.json()["status"] == "rejected"
    response = client.post(
        f"/api/operations/{cancelled.plan.operation_id}/cancel",
        json={"operator": "owner", "reason": "不再需要"},
    )
    assert response.status_code == 200
    assert response.json()["status"] == "cancelled"
    missing = str(OperationId.new())
    assert (
        client.post(
            f"/api/operations/{missing}/reject",
            json={"operator": "owner", "reason": "missing"},
        ).status_code
        == 404
    )
    assert (
        client.post(
            f"/api/operations/{missing}/cancel",
            json={"operator": "owner", "reason": "missing"},
        ).status_code
        == 404
    )
    assert (
        client.post(
            f"/api/operations/{rejected.plan.operation_id}/cancel",
            json={"operator": "owner", "reason": "too late"},
        ).status_code
        == 409
    )


def _preauthorization_payload() -> dict[str, object]:
    return {
        "request_peer_id": str(NodeId.new()),
        "tool_name": "share_local_http_service",
        "service_ids": ["home-dashboard"],
        "service_fingerprints": [FINGERPRINT],
        "minimum_port": 18880,
        "maximum_port": 18890,
        "maximum_duration_seconds": 600,
        "valid_from": NOW.isoformat(),
        "valid_until": (NOW + timedelta(hours=1)).isoformat(),
        "created_by": "target-local-user",
        "confirm_peer": True,
        "confirm_tool": True,
        "confirm_service": True,
        "confirm_port": True,
        "confirm_duration": True,
        "confirm_validity": True,
    }


def test_preauthorization_requires_every_confirmation_and_revoke_is_idempotent(
    tmp_path: Path,
) -> None:
    client, _, _ = _bundle(tmp_path / "runtime.sqlite3")
    payload = _preauthorization_payload()
    payload["confirm_port"] = False
    rejected = client.post("/api/preauthorizations", json=payload)
    assert rejected.status_code == 422
    assert "必须分别确认" in rejected.text

    payload["confirm_port"] = True
    payload["minimum_port"] = 18890
    payload["maximum_port"] = 18880
    assert client.post("/api/preauthorizations", json=payload).status_code == 409
    payload["minimum_port"] = 18880
    payload["maximum_port"] = 18890
    created = client.post("/api/preauthorizations", json=payload)
    assert created.status_code == 200
    grant = created.json()
    assert grant["target_node_id"] == str(TARGET_NODE)
    listed = client.get("/api/preauthorizations")
    assert listed.json()[0]["authorization_id"] == grant["authorization_id"]
    url = f"/api/preauthorizations/{grant['authorization_id']}/revoke"
    first = client.post(url)
    second = client.post(url)
    assert first.status_code == second.status_code == 200
    assert first.json()["revoked_at"] == second.json()["revoked_at"]
    assert client.post(f"/api/preauthorizations/{AuthorizationId.new()}/revoke").status_code == 404
    assert client.post("/api/preauthorizations/not-an-id/revoke").status_code == 404


def test_active_revoke_uses_resource_owner_and_never_claims_success_without_it(
    tmp_path: Path,
) -> None:
    database = tmp_path / "runtime.sqlite3"
    client, stores, _ = _bundle(database)
    succeeded = _succeeded_record()
    stores.operations.put(succeeded)
    url = f"/api/operations/{succeeded.plan.operation_id}/revoke"
    unavailable = client.post(url)
    assert unavailable.status_code == 503
    unavailable_detail = client.get(f"/api/operations/{succeeded.plan.operation_id}")
    assert unavailable_detail.json()["allowed_actions"] == []
    unchanged = stores.operations.get(succeeded.plan.operation_id)
    assert unchanged is not None
    assert unchanged.status is OperationStatus.SUCCEEDED

    lifecycle = FakeLifecycle(stores)
    active_client, _, _ = _bundle(database, lifecycle=lifecycle)
    active_detail = active_client.get(f"/api/operations/{succeeded.plan.operation_id}")
    assert active_detail.json()["allowed_actions"] == ["revoke"]
    revoked = active_client.post(url)
    assert revoked.status_code == 200
    assert revoked.json()["status"] == "rolled_back"
    assert lifecycle.calls == 1


def test_direct_input_validation_and_conflict_paths(tmp_path: Path) -> None:
    payload = _preauthorization_payload()
    payload["confirm_validity"] = False
    with pytest.raises(ValidationError):
        PreauthorizationInput.model_validate(payload)

    client, stores, service = _bundle(tmp_path / "runtime.sqlite3")
    assert service.list_operations() == ()
    with pytest.raises(KeyError):
        service.get_operation(OperationId.new())
    assert (
        client.post(
            f"/api/operations/{OperationId.new()}/approve",
            json={
                "operator": "owner",
                "expires_at": (NOW + timedelta(minutes=1)).isoformat(),
            },
        ).status_code
        == 404
    )
    assert (
        client.post(
            f"/api/operations/{OperationId.new()}/revoke",
        ).status_code
        == 503
    )
    stores.operations.put(_awaiting_record())
