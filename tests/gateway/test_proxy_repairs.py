"""代批准只能决定已有修复，执行和安全核对仍留在目标节点。"""

from __future__ import annotations

import asyncio
from datetime import timedelta
from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI
from tests.repair.factories import NODE, NOW, container, launch_record, plan
from tests.repair.fakes import RepairHarness, local_launch

from tunnelminion.domain.identifiers import NodeId, OperationId
from tunnelminion.domain.tools import Platform
from tunnelminion.gateway.api import create_gateway_router
from tunnelminion.gateway.audit import InMemoryGatewaySecurityAuditSink
from tunnelminion.gateway.contracts import GatewayErrorCode, GatewayErrorResponse, PeerRepairView
from tunnelminion.gateway.security import GatewayLimits, GatewayPeerPolicy, GatewaySecurityPolicy
from tunnelminion.repair.contracts import (
    PortOwner,
    PythonRepairTarget,
    RepairErrorCode,
    RepairRecord,
)
from tunnelminion.repair.peer_view import peer_repair_view
from tunnelminion.repair.service import ProxyRepairApprover
from tunnelminion.tools.audit import InMemoryAuditSink
from tunnelminion.tools.runtime import ToolRuntime

PEER = NodeId("node_" + "2" * 32)
TOKEN = "tmn_" + "proxy-approval-test-" * 3
HEADERS = {"Authorization": f"Bearer {TOKEN}"}


def pending(h: RepairHarness) -> RepairRecord:
    return h.authorization.submit(RepairRecord.planned(plan(), actor="agent"), at=h.clock())


def gateway(
    h: RepairHarness,
    *,
    allowed: bool = True,
    available: bool = True,
    named: bool = True,
    limits: GatewayLimits | None = None,
) -> tuple[FastAPI, InMemoryGatewaySecurityAuditSink]:
    policy = GatewaySecurityPolicy(
        [
            GatewayPeerPolicy.from_token(
                PEER, TOKEN, ("get_node_summary",), allow_proxy_repair_approval=allowed
            )
        ],
        limits,
    )
    audit = InMemoryGatewaySecurityAuditSink()
    app = FastAPI()
    app.include_router(
        create_gateway_router(
            NODE,
            Platform.WINDOWS,
            h.registry,
            ToolRuntime(h.registry, Platform.WINDOWS, InMemoryAuditSink()),
            policy,
            audit,
            repair_service=h.service if available else None,
            peer_display_name=(lambda _: "本机保存的名字") if named else None,
        )
    )
    return app, audit


@pytest.mark.parametrize("action", [None, "approve", "reject"])
@pytest.mark.parametrize(
    ("authenticated", "available", "allowed", "status", "code"),
    [
        (False, False, False, 401, GatewayErrorCode.UNAUTHENTICATED),
        (True, False, False, 503, GatewayErrorCode.REPAIR_UNAVAILABLE),
        (True, True, False, 403, GatewayErrorCode.REPAIR_APPROVAL_NOT_ALLOWED),
    ],
)
def test_checks_authentication_and_permission_before_reading_repairs(
    tmp_path: Path,
    action: str | None,
    authenticated: bool,
    available: bool,
    allowed: bool,
    status: int,
    code: GatewayErrorCode,
) -> None:
    h = RepairHarness(tmp_path)
    record = pending(h)
    app, audit = gateway(h, allowed=allowed, available=available)

    async def scenario() -> None:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app), base_url="http://127.0.0.1"
        ) as client:
            for identifier in (str(record.plan.operation_id), "invalid"):
                response = await client.request(
                    "POST" if action else "GET",
                    f"/v1/repairs/{identifier}" + (f":{action}" if action else ""),
                    headers=HEADERS if authenticated else {},
                )
                assert response.status_code == status
                error = GatewayErrorResponse.model_validate(response.json()).error
                assert error.code is code
                if status == 403:
                    assert error.message == "本机没有允许这台电脑替它批准修复"
                assert audit.records[-1].error_code is code
                assert audit.records[-1].action == f"repair_{action or 'status'}"
        assert h.store.list_all() == (record,)
        assert not h.containers.calls and not h.launcher.calls

    asyncio.run(scenario())


@pytest.mark.parametrize("action", [None, "approve", "reject"])
@pytest.mark.parametrize("identifier", ["invalid", "missing", "foreign"])
def test_only_existing_repairs_on_this_node_are_visible(
    tmp_path: Path, action: str | None, identifier: str
) -> None:
    h = RepairHarness(tmp_path)
    record = pending(h)
    if identifier == "foreign":
        h.store.put(
            record.model_copy(update={"plan": record.plan.model_copy(update={"node_id": PEER})})
        )
    repair_id = (
        str(record.plan.operation_id)
        if identifier == "foreign"
        else str(OperationId.new())
        if identifier == "missing"
        else "../invalid"
    )
    # 编号放在一个路径段内，确保由修复路由统一拒绝。
    repair_id = "invalid" if identifier == "invalid" else repair_id
    app, audit = gateway(h)

    async def scenario() -> None:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app), base_url="http://127.0.0.1"
        ) as client:
            response = await client.request(
                "POST" if action else "GET",
                f"/v1/repairs/{repair_id}" + (f":{action}" if action else ""),
                headers=HEADERS,
            )
            assert response.status_code == 404
            assert response.json()["error"] == {
                "code": "repair_not_found",
                "message": "修复不存在",
                "retryable": False,
            }
        assert audit.records[-1].error_code is GatewayErrorCode.REPAIR_NOT_FOUND
        assert not h.containers.calls and len(h.store.list_all()) == 1

    asyncio.run(scenario())


@pytest.mark.parametrize("action", ["approve", "reject"])
@pytest.mark.parametrize("state", ["expired", "authorized", "rejected", "succeeded"])
def test_processed_or_expired_repairs_cannot_be_decided(
    tmp_path: Path, action: str, state: str
) -> None:
    h = RepairHarness(tmp_path)
    record = pending(h)
    identifier = record.plan.operation_id
    if state == "expired":
        h.clock.now += timedelta(minutes=10)
    elif state == "rejected":
        h.service.reject(identifier, operator="local-web", reason=None)
    else:
        h.service.approve(identifier, operator="local-web")
        if state == "succeeded":
            asyncio.run(h.service.execute(identifier))
    calls = list(h.containers.calls)
    app, audit = gateway(h)

    async def scenario() -> None:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app), base_url="http://127.0.0.1"
        ) as client:
            response = await client.post(f"/v1/repairs/{identifier}:{action}", headers=HEADERS)
            assert response.status_code == 409
            assert response.json()["error"]["message"] == "这个修复现在不等批准"
        assert audit.records[-1].error_code is GatewayErrorCode.REPAIR_STATE_CONFLICT
        assert h.containers.calls == calls

    asyncio.run(scenario())


@pytest.mark.parametrize("action", ["approve", "reject"])
@pytest.mark.parametrize(
    "body",
    [None, {"command": "rm -rf /", "kind": "arbitrary", "reason": "注入", "display_name": "冒名"}],
)
def test_decisions_ignore_body_use_trusted_name_and_never_execute_twice(
    tmp_path: Path, action: str, body: dict[str, str] | None
) -> None:
    h = RepairHarness(tmp_path)
    record = pending(h)
    identifier = record.plan.operation_id
    app, _ = gateway(h)

    async def scenario() -> None:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app), base_url="http://127.0.0.1", headers=HEADERS
        ) as client:
            before = await client.get(f"/v1/repairs/{identifier}")
            waiting = PeerRepairView.model_validate(before.json())
            assert waiting.approval_expires_at == NOW + timedelta(minutes=10)
            assert waiting.approved_by_peer is None
            response = await client.post(f"/v1/repairs/{identifier}:{action}", json=body)
            assert response.status_code == (202 if action == "approve" else 200)
            decided = PeerRepairView.model_validate(response.json())
            assert decided.approval_expires_at is None
            assert decided.approved_by_peer is (True if action == "approve" else None)
            latest = h.store.get(identifier)
            assert latest is not None and latest.authorization is not None
            assert latest.authorization.operator == f"peer:{PEER}"
            assert latest.authorization.basis == "目标节点已授权的对端代为批准"
            event = next(
                item
                for item in latest.audit
                if item.action.value == ("approved" if action == "approve" else "rejected")
            )
            assert event.actor == f"peer:{PEER}"
            assert event.detail == (
                f"由 本机保存的名字（{PEER}）代为批准了修复。"
                if action == "approve"
                else "本机保存的名字 代为选择先不修。"
            )
            assert "冒名" not in latest.model_dump_json() and "注入" not in latest.model_dump_json()
            duplicate = await client.post(f"/v1/repairs/{identifier}:{action}")
            assert duplicate.status_code == 409
            final = PeerRepairView.model_validate(
                (await client.get(f"/v1/repairs/{identifier}")).json()
            )
            assert final.status == ("succeeded" if action == "approve" else "rejected")
            assert final.verification_passed is (True if action == "approve" else None)
        assert len(h.store.list_all()) == 1
        assert len(h.containers.calls) == (1 if action == "approve" else 0)

    asyncio.run(scenario())


@pytest.mark.parametrize("kind", ["container", "python"])
def test_proxy_approval_still_rechecks_target_before_executing(tmp_path: Path, kind: str) -> None:
    h = RepairHarness(tmp_path)
    if kind == "container":
        record = pending(h)
        h.containers.items = (container("b"),)
    else:
        launch = local_launch(tmp_path)
        record = h.authorization.submit(
            RepairRecord.planned(plan(PythonRepairTarget(launch=launch)), actor="agent"), at=NOW
        )
        h.host.owners[8765] = PortOwner(pid=99, process_name="other", matches_launch=False)
    app, _ = gateway(h, named=False)

    async def scenario() -> None:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app), base_url="http://127.0.0.1", headers=HEADERS
        ) as client:
            response = await client.post(f"/v1/repairs/{record.plan.operation_id}:approve")
            assert response.status_code == 202
            result = PeerRepairView.model_validate(
                (await client.get(f"/v1/repairs/{record.plan.operation_id}")).json()
            )
            assert result.status == "cancelled"
            assert result.error_code == (
                RepairErrorCode.SERVICE_CHANGED
                if kind == "container"
                else RepairErrorCode.PORT_IN_USE
            )
            latest = h.store.get(record.plan.operation_id)
            assert latest is not None and latest.error is not None
            assert latest.error.next_step == "情况变了，让 Agent 重新看一下。"
        assert not h.containers.calls and not h.launcher.calls

    asyncio.run(scenario())


@pytest.mark.parametrize("action", [None, "approve", "reject"])
def test_response_budget_and_rate_limit_are_audited(tmp_path: Path, action: str | None) -> None:
    h = RepairHarness(tmp_path)
    record = pending(h)
    app, audit = gateway(h, limits=GatewayLimits(max_response_bytes=512, requests_per_minute=1))

    async def scenario() -> None:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app), base_url="http://127.0.0.1", headers=HEADERS
        ) as client:
            path = f"/v1/repairs/{record.plan.operation_id}" + (f":{action}" if action else "")
            response = await client.request("POST" if action else "GET", path)
            assert response.status_code == 413
            assert audit.records[-1].error_code is GatewayErrorCode.RESPONSE_TOO_LARGE
            response = await client.request("POST" if action else "GET", path)
            assert response.status_code == 429
            assert audit.records[-1].error_code is GatewayErrorCode.RATE_LIMITED

    asyncio.run(scenario())


def test_peer_summary_never_includes_execution_material(tmp_path: Path) -> None:
    h = RepairHarness(tmp_path)
    launch = launch_record()
    record = h.authorization.submit(
        RepairRecord.planned(plan(PythonRepairTarget(launch=launch)), actor="agent"), at=NOW
    )
    value = peer_repair_view(record)
    forbidden = (
        "interpreter",
        "arguments",
        "working_directory",
        "container_id",
        "command",
        launch.interpreter,
        launch.working_directory,
    )
    assert all(item not in value.model_dump_json() for item in forbidden)
    approved = h.service.approve(record.plan.operation_id, operator="local-web")
    assert peer_repair_view(approved).approved_by_peer is False
    h2 = RepairHarness(tmp_path)
    waiting = pending(h2)
    rejected = h2.service.reject(
        waiting.plan.operation_id,
        operator="ignored",
        reason="不可信理由",
        proxy_approver=ProxyRepairApprover(PEER, "本机名字"),
    )
    assert rejected.transitions[-1].reason == "本机名字 代为选择先不修。"
    assert peer_repair_view(rejected).approved_by_peer is None
