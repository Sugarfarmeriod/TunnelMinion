"""Gateway 操作协议、请求节点验证和跨节点关联测试。"""

# pyright: reportUnknownMemberType=false, reportUnknownVariableType=false

from __future__ import annotations

import asyncio
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import JsonValue
from tests.operation.factories import NOW, plan
from tests.tools.test_registry import definition

from tunnelminion.domain.errors import ErrorCode
from tunnelminion.domain.identifiers import LeaseId, NodeId, OperationId
from tunnelminion.domain.tools import Platform, RiskLevel
from tunnelminion.domain.versioning import ProtocolVersion
from tunnelminion.gateway.api import create_gateway_router
from tunnelminion.gateway.audit import InMemoryGatewaySecurityAuditSink
from tunnelminion.gateway.client import FixedGatewayClient, RemoteGatewayError
from tunnelminion.gateway.contracts import (
    GATEWAY_PROTOCOL,
    RemoteOperationExecution,
    RemoteOperationResult,
    RemoteVerificationRequest,
    RemoteVerificationResult,
    RequesterVerificationCallback,
)
from tunnelminion.gateway.operations import (
    CallbackRequesterVerifier,
    GatewayRequesterVerifier,
    RequesterVerificationConfig,
    TargetOperationGatewayService,
    create_requester_verification_router,
)
from tunnelminion.gateway.security import (
    GatewayLimits,
    GatewayPeerPolicy,
    GatewaySecurityPolicy,
)
from tunnelminion.memory.sqlite import SQLiteStores
from tunnelminion.operation.contracts import (
    AuthorizationKind,
    LeaseRecord,
    OperationLevel,
    OperationPlan,
    OperationRecord,
    OperationStatus,
    OperationSummary,
    VerificationRecord,
    VerificationResult,
    compute_idempotency_key,
)
from tunnelminion.operation.fakes import (
    FakeRequesterVerifier,
    FakeServiceEvidenceProvider,
    FakeSharingAdapter,
)
from tunnelminion.operation.policy import AuthorizationService, OperationPolicy
from tunnelminion.operation.workflow import OperationWorkflow
from tunnelminion.tools.audit import InMemoryAuditSink
from tunnelminion.tools.fakes import FakeToolAdapter
from tunnelminion.tools.registry import ToolRegistry
from tunnelminion.tools.runtime import ToolRuntime

TOKEN = "tmn_operation-gateway-token-with-more-than-32-characters"
SECOND_TOKEN = "tmn_second-operation-token-with-more-than-32-characters"


class MemorySecretStore:
    """测试用内存秘密存储。"""

    def __init__(self) -> None:
        self.values: dict[str, str] = {}

    def get(self, name: str) -> str | None:
        return self.values.get(name)

    def set(self, name: str, value: str) -> None:
        self.values[name] = value

    def delete(self, name: str) -> None:
        self.values.pop(name, None)


def _remote_plan(caller: NodeId, target: NodeId) -> OperationPlan:
    source = plan()
    key = compute_idempotency_key(
        request_node_id=caller,
        target_node_id=target,
        tool_name="share_local_http_service",
        plan_version=source.plan_version,
        service_fingerprint=source.service.fingerprint,
        access_scope=source.access_scope.model_copy(update={"allowed_peer_id": caller}),
    )
    return OperationPlan.model_validate(
        {
            **source.model_dump(),
            "request_node_id": caller,
            "target_node_id": target,
            "tool_name": "share_local_http_service",
            "level": OperationLevel.L2,
            "access_scope": source.access_scope.model_copy(update={"allowed_peer_id": caller}),
            "idempotency_key": key,
        }
    )


def _payload(operation_plan: OperationPlan) -> dict[str, object]:
    return {
        "protocol": GATEWAY_PROTOCOL.model_dump(mode="json"),
        "plan": operation_plan.model_dump(mode="json"),
    }


def _execute_payload(operation_plan: OperationPlan) -> dict[str, JsonValue]:
    return cast(
        dict[str, JsonValue],
        RemoteOperationExecution(
            protocol=GATEWAY_PROTOCOL,
            operation_id=operation_plan.operation_id,
            plan_version=operation_plan.plan_version,
            idempotency_key=operation_plan.idempotency_key,
            request_node_id=operation_plan.request_node_id,
            target_node_id=operation_plan.target_node_id,
            thread_id=operation_plan.thread_id,
            run_id=operation_plan.run_id,
            tool_run_ids=operation_plan.tool_run_ids,
        ).model_dump(mode="json"),
    )


def _auth(token: str = TOKEN) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _gateway(
    path: Path,
    operation_plan: OperationPlan,
    *,
    verification_result: VerificationResult = VerificationResult.PASSED,
    allowed_operations: frozenset[str] = frozenset({"share_local_http_service"}),
    limits: GatewayLimits | None = None,
    extra_peers: tuple[GatewayPeerPolicy, ...] = (),
    expose_operation_service: bool = True,
) -> tuple[
    FastAPI,
    AuthorizationService,
    TargetOperationGatewayService,
    InMemoryGatewaySecurityAuditSink,
]:
    stores = SQLiteStores.open(path)
    registry = ToolRegistry()
    registry.register(definition("read_status"), FakeToolAdapter())
    registry.register(
        definition("share_local_http_service", RiskLevel.REQUIRES_APPROVAL),
        FakeToolAdapter(),
    )
    policy = OperationPolicy(registry, stores.preauthorizations)
    authorization = AuthorizationService(stores.operations, stores.preauthorizations, policy)
    workflow = OperationWorkflow(
        stores.operations,
        MemorySecretStore(),
        FakeServiceEvidenceProvider(operation_plan.service),
        FakeSharingAdapter(),
        FakeRequesterVerifier(operation_plan.request_node_id, verification_result),
    )
    operation_service = TargetOperationGatewayService(
        stores.operations,
        authorization,
        workflow,
    )
    security = GatewaySecurityPolicy(
        (
            GatewayPeerPolicy.from_token(
                operation_plan.request_node_id,
                TOKEN,
                ["read_status"],
                allowed_operations,
                source_host="10.77.0.2",
            ),
            *extra_peers,
        ),
        limits,
    )
    runtime = ToolRuntime(registry, Platform.WINDOWS, InMemoryAuditSink())
    security_audit = InMemoryGatewaySecurityAuditSink()
    app = FastAPI()
    app.include_router(
        create_gateway_router(
            operation_plan.target_node_id,
            Platform.WINDOWS,
            registry,
            runtime,
            security,
            security_audit,
            operation_service if expose_operation_service else None,
        )
    )
    return app, authorization, operation_service, security_audit


def test_capabilities_submit_idempotency_approve_execute_and_status(tmp_path: Path) -> None:
    caller = NodeId.new()
    target = NodeId.new()
    operation_plan = _remote_plan(caller, target)
    app, authorization, _service, _audit = _gateway(
        tmp_path / "lifecycle.sqlite3",
        operation_plan,
    )
    client = TestClient(app)

    capabilities = client.get("/v1/capabilities", headers=_auth())
    assert capabilities.status_code == 200
    assert capabilities.json()["operations"] == ["share_local_http_service"]
    assert capabilities.json()["operation_protocol"] == {"major": 1, "minor": 0}

    submitted = client.post("/v1/operations:submit", json=_payload(operation_plan), headers=_auth())
    duplicate = client.post("/v1/operations:submit", json=_payload(operation_plan), headers=_auth())
    assert submitted.status_code == 200
    assert duplicate.json() == submitted.json()
    summary = submitted.json()["summary"]
    assert summary["status"] == "awaiting_authorization"
    assert summary["thread_id"] == str(operation_plan.thread_id)
    assert summary["run_id"] == str(operation_plan.run_id)
    assert summary["tool_run_ids"] == [str(item) for item in operation_plan.tool_run_ids]

    waiting = client.post(
        "/v1/operations:execute",
        json=_execute_payload(operation_plan),
        headers=_auth(),
    )
    assert waiting.status_code == 409
    assert waiting.json()["error"]["code"] == "operation_state_conflict"

    decided_at = datetime.now(UTC)
    approved = authorization.approve_once(
        operation_plan.operation_id,
        operator="target-local-user",
        decided_at=decided_at,
        expires_at=decided_at + timedelta(minutes=1),
        local_control=True,
    )
    assert approved.authorization is not None
    assert approved.authorization.kind is AuthorizationKind.ONE_TIME

    executed = client.post(
        "/v1/operations:execute",
        json=_execute_payload(operation_plan),
        headers=_auth(),
    )
    assert executed.status_code == 200
    assert executed.json()["summary"]["status"] == "succeeded"

    status_response = client.get(
        f"/v1/operations/{operation_plan.operation_id}",
        headers=_auth(),
    )
    assert status_response.status_code == 200
    assert status_response.json()["summary"]["verification_results"] == ["passed"]


def test_gateway_reauthenticates_and_rejects_identity_allowlist_version_and_tampering(
    tmp_path: Path,
) -> None:
    caller = NodeId.new()
    target = NodeId.new()
    operation_plan = _remote_plan(caller, target)
    app, authorization, _service, security_audit = _gateway(
        tmp_path / "security.sqlite3",
        operation_plan,
    )
    client = TestClient(app)
    assert client.post("/v1/operations:submit", json=_payload(operation_plan)).status_code == 401
    assert (
        client.post("/v1/operations:execute", json=_execute_payload(operation_plan)).status_code
        == 401
    )
    assert client.get(f"/v1/operations/{operation_plan.operation_id}").status_code == 401

    wrong_caller = _remote_plan(NodeId.new(), target)
    wrong = client.post("/v1/operations:submit", json=_payload(wrong_caller), headers=_auth())
    assert wrong.status_code == 403

    incompatible = _payload(operation_plan)
    incompatible["protocol"] = {"major": 2, "minor": 0}
    version = client.post("/v1/operations:submit", json=incompatible, headers=_auth())
    assert version.status_code == 409

    wrong_target = _remote_plan(caller, NodeId.new())
    target_rejected = client.post(
        "/v1/operations:submit",
        json=_payload(wrong_target),
        headers=_auth(),
    )
    assert target_rejected.status_code == 403

    submitted = client.post("/v1/operations:submit", json=_payload(operation_plan), headers=_auth())
    assert submitted.status_code == 200
    now = datetime.now(UTC)
    authorization.approve_once(
        operation_plan.operation_id,
        operator="local",
        decided_at=now,
        expires_at=now + timedelta(minutes=1),
        local_control=True,
    )
    tampered = _execute_payload(operation_plan)
    tampered["plan_version"] = 2
    rejected = client.post("/v1/operations:execute", json=tampered, headers=_auth())
    assert rejected.status_code == 409
    assert rejected.json()["error"]["code"] == "plan_tampered"

    incompatible_execute = _execute_payload(operation_plan)
    incompatible_execute["protocol"] = {"major": 2, "minor": 0}
    assert (
        client.post(
            "/v1/operations:execute",
            json=incompatible_execute,
            headers=_auth(),
        ).status_code
        == 409
    )
    missing_execute = _execute_payload(operation_plan)
    missing_execute["operation_id"] = str(OperationId.new())
    assert (
        client.post(
            "/v1/operations:execute",
            json=missing_execute,
            headers=_auth(),
        ).status_code
        == 404
    )

    invalid_id = client.get("/v1/operations/not-an-id", headers=_auth())
    missing = client.get(f"/v1/operations/{OperationId.new()}", headers=_auth())
    assert invalid_id.status_code == 404
    assert missing.status_code == 404
    assert all(TOKEN not in item.model_dump_json() for item in security_audit.records)

    denied_app, _, _, _ = _gateway(
        tmp_path / "denied.sqlite3",
        operation_plan,
        allowed_operations=frozenset(),
    )
    denied = TestClient(denied_app).post(
        "/v1/operations:submit",
        json=_payload(operation_plan),
        headers=_auth(),
    )
    assert denied.status_code == 403
    assert denied.json()["error"]["code"] == "operation_not_allowed"

    second_peer = NodeId.new()
    second_policy = GatewayPeerPolicy.from_token(
        second_peer,
        SECOND_TOKEN,
        ["read_status"],
        ["share_local_http_service"],
    )
    shared_app, _, _, _ = _gateway(
        tmp_path / "second-peer.sqlite3",
        operation_plan,
        extra_peers=(second_policy,),
    )
    shared_client = TestClient(shared_app)
    shared_client.post(
        "/v1/operations:submit",
        json=_payload(operation_plan),
        headers=_auth(),
    )
    second_headers = _auth(SECOND_TOKEN)
    assert (
        shared_client.get(
            f"/v1/operations/{operation_plan.operation_id}",
            headers=second_headers,
        ).status_code
        == 403
    )
    assert (
        shared_client.post(
            "/v1/operations:execute",
            json=_execute_payload(operation_plan),
            headers=second_headers,
        ).status_code
        == 403
    )

    disabled_app, _, _, _ = _gateway(
        tmp_path / "disabled.sqlite3",
        operation_plan,
        expose_operation_service=False,
    )
    disabled = TestClient(disabled_app)
    assert disabled.get("/v1/capabilities", headers=_auth()).json()["operations"] == []
    assert (
        disabled.post(
            "/v1/operations:submit",
            json=_payload(operation_plan),
            headers=_auth(),
        ).status_code
        == 404
    )
    assert (
        disabled.post(
            "/v1/operations:execute",
            json=_execute_payload(operation_plan),
            headers=_auth(),
        ).status_code
        == 404
    )
    assert (
        disabled.get(
            f"/v1/operations/{operation_plan.operation_id}",
            headers=_auth(),
        ).status_code
        == 404
    )


def test_gateway_rolls_back_failed_requester_verification_and_limits_response(
    tmp_path: Path,
) -> None:
    caller = NodeId.new()
    target = NodeId.new()
    operation_plan = _remote_plan(caller, target)
    app, authorization, _, _ = _gateway(
        tmp_path / "verify-fail.sqlite3",
        operation_plan,
        verification_result=VerificationResult.REQUESTER_OFFLINE,
    )
    client = TestClient(app)
    client.post("/v1/operations:submit", json=_payload(operation_plan), headers=_auth())
    now = datetime.now(UTC)
    authorization.approve_once(
        operation_plan.operation_id,
        operator="local",
        decided_at=now,
        expires_at=now + timedelta(minutes=1),
        local_control=True,
    )
    failed = client.post(
        "/v1/operations:execute",
        json=_execute_payload(operation_plan),
        headers=_auth(),
    )
    assert failed.status_code == 200
    assert failed.json()["summary"]["status"] == "rolled_back"

    limited_app, _, _, _ = _gateway(
        tmp_path / "limited.sqlite3",
        _remote_plan(caller, target),
        limits=GatewayLimits(max_response_bytes=512),
    )
    limited_plan = _remote_plan(caller, target)
    # 使用另一个计划会在身份检查后进入本地策略，响应预算独立生效。
    limited = TestClient(limited_app).post(
        "/v1/operations:submit",
        json=_payload(limited_plan),
        headers=_auth(),
    )
    assert limited.status_code == 413
    assert limited.json()["error"]["code"] == "response_too_large"


def test_gateway_only_calls_authenticated_peer_verification_address(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    caller = NodeId.new()
    target = NodeId.new()
    operation_plan = _remote_plan(caller, target)
    app, authorization, _, _ = _gateway(tmp_path / "callback.sqlite3", operation_plan)
    client = TestClient(app)
    client.post("/v1/operations:submit", json=_payload(operation_plan), headers=_auth())
    now = datetime.now(UTC)
    authorization.approve_once(
        operation_plan.operation_id,
        operator="local",
        decided_at=now,
        expires_at=now + timedelta(minutes=1),
        local_control=True,
    )
    callback: dict[str, JsonValue] = {
        "endpoint": "http://10.77.0.3:18882",
        "token": "tmn_test-callback-token-with-more-than-forty-three-characters",
    }
    payload = _execute_payload(operation_plan)
    payload["verification_callback"] = callback
    denied = client.post("/v1/operations:execute", json=payload, headers=_auth())
    assert denied.status_code == 403

    callback["endpoint"] = "http://10.77.0.2:18882"

    def fake_callback_verifier(
        _callback: RequesterVerificationCallback,
    ) -> FakeRequesterVerifier:
        return FakeRequesterVerifier(caller)

    monkeypatch.setattr(
        "tunnelminion.gateway.api.CallbackRequesterVerifier",
        fake_callback_verifier,
    )
    executed = client.post("/v1/operations:execute", json=payload, headers=_auth())
    assert executed.status_code == 200
    assert executed.json()["summary"]["status"] == "succeeded"


def test_requester_callback_authenticates_and_verifies_from_requester_path() -> None:
    caller = NodeId.new()
    target = NodeId.new()
    operation_plan = _remote_plan(caller, target)
    lease = LeaseRecord(
        lease_id=LeaseId.new(),
        operation_id=operation_plan.operation_id,
        starts_at=NOW,
        expires_at=NOW + timedelta(minutes=1),
    )
    callback_token = "tmn_test-callback-token-with-more-than-forty-three-characters"
    with pytest.raises(ValueError, match="熵不足"):
        create_requester_verification_router(
            local_node_id=caller,
            target_node_id=target,
            callback_token="short",
            verifier=FakeRequesterVerifier(caller),
        )
    requester = FakeRequesterVerifier(caller)
    callback_app = FastAPI()
    callback_app.include_router(
        create_requester_verification_router(
            local_node_id=caller,
            target_node_id=target,
            callback_token=callback_token,
            verifier=requester,
        )
    )
    request = RemoteVerificationRequest(
        plan=operation_plan,
        lease=lease,
        access_token="tmn_test-share-token-with-more-than-forty-three-characters",
    )
    transport = httpx.ASGITransport(app=callback_app)

    async def scenario() -> VerificationRecord:
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://requester.test",
        ) as client:
            assert (
                await client.post(
                    "/v1/operations:verify-callback",
                    content=request.model_dump_json(),
                    headers={"Content-Type": "application/json"},
                )
            ).status_code == 401
            assert (
                await client.post(
                    "/v1/operations:verify-callback",
                    content=request.model_dump_json(),
                    headers={
                        "Authorization": "Basic invalid",
                        "Content-Type": "application/json",
                    },
                )
            ).status_code == 401
            wrong = request.model_copy(update={"plan": _remote_plan(caller, NodeId.new())})
            assert (
                await client.post(
                    "/v1/operations:verify-callback",
                    content=wrong.model_dump_json(),
                    headers={
                        "Authorization": f"Bearer {callback_token}",
                        "Content-Type": "application/json",
                    },
                )
            ).status_code == 403
        verifier = CallbackRequesterVerifier(
            RequesterVerificationCallback(
                endpoint="http://requester.test",
                token=callback_token,
            ),
            transport=transport,
        )
        return await verifier.verify(operation_plan, lease, request.access_token)

    result = asyncio.run(scenario())
    assert result.result is VerificationResult.PASSED
    assert result.verifier_node_id == caller


def _denied_callback(_request: httpx.Request) -> httpx.Response:
    return httpx.Response(401, json={"error": "denied"})


def _invalid_callback(_request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, content=b"not-json")


def _timeout_callback(request: httpx.Request) -> httpx.Response:
    raise httpx.ReadTimeout("timeout", request=request)


@pytest.mark.parametrize("handler", [_denied_callback, _invalid_callback, _timeout_callback])
def test_callback_verifier_rejects_invalid_callback_responses(
    handler: Callable[[httpx.Request], httpx.Response],
) -> None:
    caller = NodeId.new()
    operation_plan = _remote_plan(caller, NodeId.new())
    lease = LeaseRecord(
        lease_id=LeaseId.new(),
        operation_id=operation_plan.operation_id,
        starts_at=NOW,
        expires_at=NOW + timedelta(minutes=1),
    )
    verifier = CallbackRequesterVerifier(
        RequesterVerificationCallback(
            endpoint="http://10.77.0.2:18882",
            token="tmn_test-callback-token-with-more-than-forty-three-characters",
        ),
        transport=httpx.MockTransport(handler),
    )
    result = asyncio.run(
        verifier.verify(
            operation_plan,
            lease,
            "tmn_test-share-token-with-more-than-forty-three-characters",
        )
    )
    expected = (
        VerificationResult.TIMEOUT
        if handler is _timeout_callback
        else VerificationResult.REQUESTER_OFFLINE
    )
    assert result.result is expected


def test_callback_verifier_rejects_forged_verification_identity() -> None:
    caller = NodeId.new()
    operation_plan = _remote_plan(caller, NodeId.new())
    lease = LeaseRecord(
        lease_id=LeaseId.new(),
        operation_id=operation_plan.operation_id,
        starts_at=NOW,
        expires_at=NOW + timedelta(minutes=1),
    )

    def forged(_request: httpx.Request) -> httpx.Response:
        body = RemoteVerificationResult(
            verification=VerificationRecord(
                operation_id=OperationId.new(),
                verifier_node_id=caller,
                result=VerificationResult.PASSED,
                evidence_summary="伪造关联",
                verified_at=NOW,
            )
        )
        return httpx.Response(200, content=body.model_dump_json())

    verifier = CallbackRequesterVerifier(
        RequesterVerificationCallback(
            endpoint="http://10.77.0.2:18882",
            token="tmn_test-callback-token-with-more-than-forty-three-characters",
        ),
        transport=httpx.MockTransport(forged),
    )
    result = asyncio.run(
        verifier.verify(
            operation_plan,
            lease,
            "tmn_test-share-token-with-more-than-forty-three-characters",
        )
    )
    assert result.result is VerificationResult.REQUESTER_OFFLINE


@pytest.mark.anyio
async def test_fixed_client_runs_remote_operation_and_validates_envelopes(tmp_path: Path) -> None:
    caller = NodeId.new()
    target = NodeId.new()
    operation_plan = _remote_plan(caller, target)
    app, authorization, operation_service, _ = _gateway(tmp_path / "client.sqlite3", operation_plan)
    client = FixedGatewayClient(
        "http://10.77.0.1:8787",
        TOKEN,
        caller,
        target,
        InMemoryAuditSink(),
        transport=httpx.ASGITransport(app=app),
    )
    submitted = await client.submit_operation(operation_plan)
    assert submitted.summary.status is OperationStatus.AWAITING_AUTHORIZATION
    now = datetime.now(UTC)
    authorization.approve_once(
        operation_plan.operation_id,
        operator="local",
        decided_at=now,
        expires_at=now + timedelta(minutes=1),
        local_control=True,
    )
    executed = await client.execute_operation(operation_plan)
    queried = await client.get_operation(operation_plan.operation_id)
    assert executed.summary.status is OperationStatus.SUCCEEDED
    assert queried.summary.operation_id == operation_plan.operation_id

    with pytest.raises(KeyError, match="not_found"):
        await operation_service.execute(
            operation_id=OperationId.new(),
            plan_version=operation_plan.plan_version,
            idempotency_key=operation_plan.idempotency_key,
            request_node_id=operation_plan.request_node_id,
            target_node_id=operation_plan.target_node_id,
            thread_id=operation_plan.thread_id,
            run_id=operation_plan.run_id,
            tool_run_ids=operation_plan.tool_run_ids,
            at=datetime.now(UTC),
        )

    with pytest.raises(ValueError, match="本地节点"):
        await client.submit_operation(_remote_plan(NodeId.new(), target))
    with pytest.raises(ValueError, match="远端节点"):
        await client.submit_operation(_remote_plan(caller, NodeId.new()))

    waiting_plan = _remote_plan(caller, target)
    waiting_app, _, _, _ = _gateway(tmp_path / "client-waiting.sqlite3", waiting_plan)
    waiting_client = FixedGatewayClient(
        "http://10.77.0.1:8787",
        TOKEN,
        caller,
        target,
        InMemoryAuditSink(),
        transport=httpx.ASGITransport(app=waiting_app),
    )
    await waiting_client.submit_operation(waiting_plan)
    with pytest.raises(RemoteGatewayError) as conflict:
        await waiting_client.execute_operation(waiting_plan)
    assert conflict.value.code is ErrorCode.INVALID_ARGUMENT


@pytest.mark.anyio
async def test_fixed_client_rejects_operation_transport_and_envelope_failures() -> None:
    caller = NodeId.new()
    target = NodeId.new()
    operation_plan = _remote_plan(caller, target)
    other_plan = _remote_plan(caller, target)

    def result_response(
        response_plan: OperationPlan,
        *,
        execution_node: NodeId = target,
        protocol: ProtocolVersion = GATEWAY_PROTOCOL,
    ) -> httpx.Response:
        result = RemoteOperationResult(
            protocol=protocol,
            execution_node_id=execution_node,
            summary=OperationSummary.from_record(OperationRecord.planned(response_plan)),
        )
        return httpx.Response(200, content=result.model_dump_json().encode())

    responses = [
        result_response(other_plan),
        result_response(other_plan),
        httpx.Response(200, content=b"not-json"),
        result_response(operation_plan, execution_node=NodeId.new()),
        result_response(operation_plan, protocol=ProtocolVersion(major=2, minor=0)),
    ]

    def queued(_request: httpx.Request) -> httpx.Response:
        return responses.pop(0)

    client = FixedGatewayClient(
        "http://10.77.0.1:8787",
        TOKEN,
        caller,
        target,
        InMemoryAuditSink(),
        transport=httpx.MockTransport(queued),
    )
    with pytest.raises(RemoteGatewayError, match="ID"):
        await client.submit_operation(operation_plan)
    with pytest.raises(RemoteGatewayError, match="ID"):
        await client.get_operation(operation_plan.operation_id)
    with pytest.raises(RemoteGatewayError, match="格式"):
        await client.execute_operation(operation_plan)
    with pytest.raises(RemoteGatewayError, match="节点身份"):
        await client.execute_operation(operation_plan)
    with pytest.raises(RemoteGatewayError, match="协议"):
        await client.execute_operation(operation_plan)

    def timeout(_request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("slow")

    def offline(_request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("offline")

    timeout_client = FixedGatewayClient(
        "http://10.77.0.1:8787",
        TOKEN,
        caller,
        target,
        InMemoryAuditSink(),
        transport=httpx.MockTransport(timeout),
    )
    offline_client = FixedGatewayClient(
        "http://10.77.0.1:8787",
        TOKEN,
        caller,
        target,
        InMemoryAuditSink(),
        transport=httpx.MockTransport(offline),
    )
    with pytest.raises(RemoteGatewayError) as timed_out:
        await timeout_client.submit_operation(operation_plan)
    with pytest.raises(RemoteGatewayError) as unreachable:
        await offline_client.submit_operation(operation_plan)
    assert timed_out.value.code is ErrorCode.REMOTE_TIMEOUT
    assert unreachable.value.code is ErrorCode.NODE_UNREACHABLE


@pytest.mark.anyio
async def test_requester_verifier_uses_real_path_status_and_response_budget() -> None:
    operation_plan = _remote_plan(NodeId.new(), NodeId.new())
    lease = LeaseRecord(
        lease_id=LeaseId.new(),
        operation_id=operation_plan.operation_id,
        starts_at=NOW,
        expires_at=NOW + timedelta(minutes=1),
    )

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.headers.get("X-TunnelMinion-Share-Token") != "share-token":
            return httpx.Response(401)
        return httpx.Response(200, content=b"healthy")

    verifier = GatewayRequesterVerifier(
        RequesterVerificationConfig(
            allowed_target_addresses=frozenset({operation_plan.access_scope.bind_host}),
            max_response_bytes=16,
        ),
        transport=httpx.MockTransport(handler),
    )
    passed = await verifier.verify(operation_plan, lease, "share-token")
    assert passed.result is VerificationResult.PASSED
    assert passed.status_code == 200

    wrong_token = await verifier.verify(operation_plan, lease, "wrong")
    assert wrong_token.result is VerificationResult.FAILED
    assert wrong_token.status_code == 401

    oversized = GatewayRequesterVerifier(
        RequesterVerificationConfig(
            allowed_target_addresses=frozenset({operation_plan.access_scope.bind_host}),
            max_response_bytes=4,
        ),
        transport=httpx.MockTransport(handler),
    )
    assert (
        await oversized.verify(operation_plan, lease, "share-token")
    ).result is VerificationResult.FAILED


@pytest.mark.anyio
async def test_requester_verifier_rejects_target_timeout_and_offline() -> None:
    operation_plan = _remote_plan(NodeId.new(), NodeId.new())
    lease = LeaseRecord(
        lease_id=LeaseId.new(),
        operation_id=operation_plan.operation_id,
        starts_at=NOW,
        expires_at=NOW + timedelta(minutes=1),
    )
    denied = GatewayRequesterVerifier(
        RequesterVerificationConfig(allowed_target_addresses=frozenset({"10.77.0.9"}))
    )
    assert (await denied.verify(operation_plan, lease, TOKEN)).result is VerificationResult.FAILED

    public_plan = operation_plan.model_copy(
        update={
            "access_scope": operation_plan.access_scope.model_copy(update={"bind_host": "8.8.8.8"})
        }
    )
    public = GatewayRequesterVerifier(
        RequesterVerificationConfig(allowed_target_addresses=frozenset({"8.8.8.8"}))
    )
    assert (await public.verify(public_plan, lease, TOKEN)).result is VerificationResult.FAILED

    def timeout(_request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("slow")

    def offline(_request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("offline")

    config = RequesterVerificationConfig(
        allowed_target_addresses=frozenset({operation_plan.access_scope.bind_host})
    )
    timeout_result = await GatewayRequesterVerifier(
        config,
        transport=httpx.MockTransport(timeout),
    ).verify(operation_plan, lease, TOKEN)
    offline_result = await GatewayRequesterVerifier(
        config,
        transport=httpx.MockTransport(offline),
    ).verify(operation_plan, lease, TOKEN)
    assert timeout_result.result is VerificationResult.TIMEOUT
    assert offline_result.result is VerificationResult.REQUESTER_OFFLINE
