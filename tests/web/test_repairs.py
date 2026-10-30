"""独立修复路由只在本机同源控制面批准。"""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path
from typing import Protocol, cast

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from tests.repair.factories import NOW, container, launch_agent_target, plan
from tests.repair.fakes import RepairHarness, local_launch

from tunnelminion.domain.identifiers import OperationId
from tunnelminion.operation.contracts import OperationStatus
from tunnelminion.repair.contracts import ContainerRepairTarget, PythonRepairTarget, RepairRecord
from tunnelminion.web.repairs import RepairDetail, RepairList, create_repair_router
from tunnelminion.web.request_guard import install_local_request_guard

SAME_ORIGIN = {"origin": "http://127.0.0.1", "x-tunnelminion-request": "same-origin"}


class ApiClient(Protocol):
    def get(self, url: str) -> httpx.Response: ...

    def post(
        self, url: str, *, json: object = None, headers: dict[str, str] | None = None
    ) -> httpx.Response: ...


def client_for(h: RepairHarness, *, preview: bool = False) -> ApiClient:
    app = FastAPI()
    app.include_router(create_repair_router(h.service))
    install_local_request_guard(app, read_only_preview=preview)
    return cast(ApiClient, TestClient(app, base_url="http://127.0.0.1"))


def pending(h: RepairHarness, record: RepairRecord | None = None) -> RepairRecord:
    return h.authorization.submit(
        record or RepairRecord.planned(plan(), actor="local-cli"), at=h.clock()
    )


def test_list_and_details_show_only_local_advanced_fields(tmp_path: Path) -> None:
    h = RepairHarness(tmp_path)
    client = client_for(h)
    assert client.get("/api/repairs").json() == {"repairs": []}
    first = pending(h)
    items = (
        container("b", name="photos-db-1", running=True),
        container("c", name="photos-extra-1"),
    )
    second_plan = plan(
        ContainerRepairTarget(compose_project="photos", containers=items)
    ).model_copy(update={"created_at": NOW + timedelta(seconds=1)})
    h.clock.now = second_plan.created_at
    second = pending(h, RepairRecord.planned(second_plan, actor="local-cli"))
    response = client.get("/api/repairs")
    assert response.status_code == 200
    listing = RepairList.model_validate_json(response.text)
    assert [item.repair_id for item in listing.repairs] == [
        str(second.plan.operation_id),
        str(first.plan.operation_id),
    ]
    assert listing.repairs[0].approval_expires_at == second.plan.created_at + timedelta(minutes=10)
    assert listing.repairs[0].verification_passed is None
    assert listing.repairs[0].node_id == second.plan.node_id
    assert listing.repairs[0].origin == second.plan.origin
    assert "advanced" not in response.json()["repairs"][0]
    detail_response = client.get(f"/api/repairs/{second.plan.operation_id}")
    detail = RepairDetail.model_validate_json(detail_response.text)
    assert detail.status is OperationStatus.AWAITING_AUTHORIZATION
    assert detail.authorization is None
    assert detail.impact_summary == second.plan.impact_summary
    assert detail.origin == second.plan.origin
    assert detail.audit == second.audit and detail.transitions == second.transitions
    assert detail_response.json()["advanced"]["commands"] == [
        "docker start " + "c" * 64,
        "docker restart " + "b" * 64,
    ]
    assert detail_response.json()["advanced"]["containers"][0]["container_id"] == "b" * 64


def test_python_detail_exposes_launch_only_locally(tmp_path: Path) -> None:
    h = RepairHarness(tmp_path)
    launch = local_launch(tmp_path).model_copy(
        update={"arguments": (*local_launch(tmp_path).arguments, "--token=fixture-private")}
    )
    record = pending(
        h, RepairRecord.planned(plan(PythonRepairTarget(launch=launch)), actor="local-cli")
    )
    client = client_for(h)
    detail = client.get(f"/api/repairs/{record.plan.operation_id}")
    # 启动参数里像密钥的部分不给网页看。
    assert "fixture-private" not in detail.text
    assert detail.json()["advanced"] == {
        "interpreter": launch.interpreter,
        "arguments": [*launch.arguments[:-1], "--token=（原来的值）"],
        "working_directory": launch.working_directory,
        "ports": [8765],
    }
    listing = client.get("/api/repairs").text
    assert "interpreter" not in listing and "working_directory" not in listing


def test_launch_agent_detail_shows_fixed_command_locally(tmp_path: Path) -> None:
    h = RepairHarness(tmp_path)
    record = pending(h, RepairRecord.planned(plan(launch_agent_target()), actor="local-cli"))
    detail = client_for(h).get(f"/api/repairs/{record.plan.operation_id}")
    assert detail.json()["advanced"] == {
        "command": "launchctl kickstart gui/501/local.photos.web",
        "plist_path": "/Users/me/Library/LaunchAgents/local.photos.web.plist",
        "ports": [8765],
    }
    assert detail.json()["kind"] == "restart_launch_agent"


def test_approve_returns_202_and_schedules_execution_once(tmp_path: Path) -> None:
    h = RepairHarness(tmp_path)
    record = pending(h)
    client = client_for(h)
    path = f"/api/repairs/{record.plan.operation_id}"
    response = client.post(path + "/approve", headers=SAME_ORIGIN)
    assert response.status_code == 202
    approved = RepairDetail.model_validate_json(response.text)
    assert approved.status is OperationStatus.AUTHORIZED
    assert approved.approval_expires_at == NOW + timedelta(minutes=10)
    assert approved.authorization is not None
    assert approved.authorization.operator == "local-web"
    assert approved.authorization.decision.value == "approved"
    result = RepairDetail.model_validate_json(client.get(path).text)
    assert result.status is OperationStatus.SUCCEEDED
    assert result.verification_passed is True
    assert result.approval_expires_at is None
    assert result.execution is not None and result.verification is not None
    assert client.post(path + "/approve", headers=SAME_ORIGIN).json() == {
        "detail": "这个修复现在不等批准"
    }
    assert client.post(path + "/approve", headers=SAME_ORIGIN).status_code == 409
    assert len(h.containers.calls) == 1


def test_reject_records_optional_reason_and_does_nothing(tmp_path: Path) -> None:
    h = RepairHarness(tmp_path)
    record = pending(h)
    client = client_for(h)
    path = f"/api/repairs/{record.plan.operation_id}"
    response = client.post(path + "/reject", json={}, headers=SAME_ORIGIN)
    assert response.status_code == 200
    rejected = RepairDetail.model_validate_json(response.text)
    assert rejected.authorization is not None and rejected.authorization.operator == "local-web"
    assert rejected.status is OperationStatus.REJECTED
    assert rejected.approval_expires_at is None
    assert rejected.audit[-1].detail == "主人选择先不修。"
    assert not h.containers.queries and not h.launcher.calls
    assert (
        client.post(path + "/reject", json={"reason": "稍后"}, headers=SAME_ORIGIN).status_code
        == 409
    )
    assert client.post(path + "/reject", json={"reason": "稍后"}, headers=SAME_ORIGIN).json() == {
        "detail": "这个修复现在不等批准"
    }


@pytest.mark.parametrize(
    "body", [{"reason": "x" * 201}, {"reason": "先不修", "operator": "remote"}]
)
def test_reject_input_forbids_extra_fields_and_long_reason(
    tmp_path: Path, body: dict[str, str]
) -> None:
    h = RepairHarness(tmp_path)
    record = pending(h)
    response = client_for(h).post(
        f"/api/repairs/{record.plan.operation_id}/reject", json=body, headers=SAME_ORIGIN
    )
    assert response.status_code == 422
    assert h.store.get(record.plan.operation_id) == record


@pytest.mark.parametrize("repair_id", ["bad-id", str(OperationId.new())])
@pytest.mark.parametrize("action", ["get", "approve", "reject"])
def test_bad_and_unknown_ids_are_404(tmp_path: Path, repair_id: str, action: str) -> None:
    client = client_for(RepairHarness(tmp_path))
    path = f"/api/repairs/{repair_id}"
    response = (
        client.get(path)
        if action == "get"
        else client.post(path + "/" + action, json={}, headers=SAME_ORIGIN)
    )
    assert response.status_code == 404
    assert response.json() == {"detail": "修复不存在"}


@pytest.mark.parametrize(
    ("headers", "preview", "code"),
    [
        ({"host": "remote.invalid"}, False, "invalid_host"),
        (
            {"origin": "https://other.invalid", "x-tunnelminion-request": "same-origin"},
            False,
            "invalid_origin",
        ),
        ({"origin": "http://127.0.0.1"}, False, "request_header_required"),
        ({"sec-fetch-site": "cross-site"}, False, "cross_site_request"),
        (SAME_ORIGIN, True, "read_only_preview"),
    ],
)
def test_local_guard_blocks_approval_before_service(
    tmp_path: Path, headers: dict[str, str], preview: bool, code: str
) -> None:
    h = RepairHarness(tmp_path)
    record = pending(h)
    response = client_for(h, preview=preview).post(
        f"/api/repairs/{record.plan.operation_id}/approve", headers=headers
    )
    assert response.status_code == 403
    assert response.json()["detail"]["code"] == code
    assert h.store.get(record.plan.operation_id) == record
    assert not h.containers.queries and not h.launcher.calls


def test_error_and_verification_failure_show_up_in_local_details(tmp_path: Path) -> None:
    h = RepairHarness(tmp_path)
    record = pending(h)
    h.containers.stay_stopped = True
    client = client_for(h)
    path = f"/api/repairs/{record.plan.operation_id}"
    assert client.post(path + "/approve", headers=SAME_ORIGIN).status_code == 202
    detail = RepairDetail.model_validate_json(client.get(path).text)
    assert detail.error is not None and detail.error.code.value == "verification_failed"
    assert detail.verification_passed is False and detail.cleanup is not None
    assert detail.verification is not None and detail.verification.log_excerpt == "startup failed"


def test_pending_expiry_is_visible_as_error(tmp_path: Path) -> None:
    h = RepairHarness(tmp_path)
    record = pending(h)
    h.clock.now += timedelta(minutes=10)
    client = client_for(h)
    response = client.post(f"/api/repairs/{record.plan.operation_id}/approve", headers=SAME_ORIGIN)
    assert response.status_code == 409
    result = RepairDetail.model_validate_json(
        client.get(f"/api/repairs/{record.plan.operation_id}").text
    )
    assert result.status is OperationStatus.AUTHORIZATION_EXPIRED
    assert result.error is not None and result.error.code.value == "authorization_expired"
