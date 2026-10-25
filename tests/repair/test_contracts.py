"""修复计划、启动记录和修复记录的契约测试。"""

from __future__ import annotations

from datetime import timedelta

import pytest
from pydantic import JsonValue, ValidationError
from tests.repair.factories import NODE, NOW, container, launch_record, plan

from tunnelminion.domain.identifiers import AuthorizationId, OperationId
from tunnelminion.domain.tools import DataSensitivity, Platform, RiskLevel, ToolDefinition
from tunnelminion.domain.versioning import ProtocolVersion
from tunnelminion.operation.contracts import (
    AuthorizationDecision,
    AuthorizationKind,
    AuthorizationRecord,
    OperationLevel,
    OperationStatus,
    transition_operation,
)
from tunnelminion.operation.policy import AuthorizationService, OperationPolicy
from tunnelminion.repair.contracts import (
    REPAIR_TOOL_NAMES,
    ContainerRepairTarget,
    PythonRepairTarget,
    RepairAuditAction,
    RepairCheck,
    RepairCheckName,
    RepairError,
    RepairErrorCode,
    RepairKind,
    RepairRecord,
    RepairSummary,
    RepairVerification,
    compute_repair_idempotency_key,
)
from tunnelminion.tools.fakes import FakeToolAdapter
from tunnelminion.tools.registry import ToolRegistry


class _MemoryRepairStore:
    def __init__(self) -> None:
        self.records: dict[str, RepairRecord] = {}

    def put(self, record: RepairRecord) -> None:
        self.records[str(record.plan.operation_id)] = record

    def get(self, operation_id: OperationId) -> RepairRecord | None:
        return self.records.get(str(operation_id))

    def get_by_idempotency_key(self, key: str) -> RepairRecord | None:
        return next(
            (item for item in self.records.values() if item.plan.idempotency_key == key), None
        )


class _NoPreauthorizations:
    def put(self, authorization: object) -> None:
        raise AssertionError("修复不使用预授权")

    def get(self, authorization_id: AuthorizationId) -> None:
        return None

    def list_all(self) -> tuple[()]:
        return ()

    def list_active(self, *, at: object) -> tuple[()]:
        return ()


def _registry() -> ToolRegistry:
    registry = ToolRegistry()
    for name in REPAIR_TOOL_NAMES.values():
        schema: dict[str, JsonValue] = {"type": "object"}
        registry.register(
            ToolDefinition(
                name=name,
                version=ProtocolVersion(major=1, minor=0),
                description="修复",
                input_schema=schema,
                output_schema=schema,
                risk_level=RiskLevel.REQUIRES_APPROVAL,
                platforms=frozenset({Platform.WINDOWS, Platform.MACOS}),
                permissions=(),
                timeout_seconds=60,
                max_result_bytes=1_000,
                data_sensitivity=DataSensitivity.SYSTEM_METADATA,
            ),
            FakeToolAdapter(),
            operation_level=OperationLevel.L2,
        )
    return registry


def test_container_target_scope_and_fingerprint() -> None:
    group = ContainerRepairTarget(
        compose_project="photos",
        containers=(container("b", ports=(8081, 8080)), container("a", name="photos-db-1")),
    )
    reordered = ContainerRepairTarget(
        compose_project="photos",
        containers=(container("a", name="photos-db-1"), container("b", ports=(8081, 8080))),
    )
    assert group.fingerprint == reordered.fingerprint
    assert group.ports == (8080, 8081)
    single = ContainerRepairTarget(
        container_name="solo", containers=(container(name="solo", compose_project=None),)
    )
    assert single.ports == (8080,)

    invalid: tuple[dict[str, object], ...] = (
        {"containers": (container(),)},
        {"compose_project": "photos", "container_name": "x", "containers": (container(),)},
        {"container_name": "other", "containers": (container(),)},
        {"compose_project": "other", "containers": (container(),)},
        {"compose_project": "photos", "containers": (container(), container())},
    )
    for values in invalid:
        with pytest.raises(ValidationError):
            ContainerRepairTarget.model_validate(values)


def test_launch_record_belongs_to_python_and_fingerprints_launch_only() -> None:
    record = launch_record(ports=(8766, 8765))
    later = record.model_copy(update={"recorded_at": NOW + timedelta(hours=1), "process_id": 7})
    assert record.fingerprint == later.fingerprint
    target = PythonRepairTarget(launch=record)
    assert target.fingerprint == record.fingerprint
    assert target.ports == (8765, 8766)
    with pytest.raises(ValidationError):
        launch_record(service_key="docker:photos")


def test_plan_rejects_inconsistent_kind_tool_level_key_and_launch() -> None:
    container_plan = plan()
    python_plan = plan(PythonRepairTarget(launch=launch_record()))
    assert container_plan.kind is RepairKind.RESTART_CONTAINERS
    assert python_plan.tool_name == REPAIR_TOOL_NAMES[RepairKind.RELAUNCH_PYTHON]

    base = container_plan.model_dump()
    mismatches: tuple[dict[str, object], ...] = (
        {"kind": RepairKind.RELAUNCH_PYTHON},
        {"tool_name": "share_local_http_service"},
        {"level": OperationLevel.L3},
        {"idempotency_key": "repkey_" + "0" * 64},
    )
    for update in mismatches:
        with pytest.raises(ValidationError):
            type(container_plan).model_validate({**base, **update})

    python_base = python_plan.model_dump()
    wrong_prefix = "docker:compose:photos"
    with pytest.raises(ValidationError, match="服务身份"):
        type(python_plan).model_validate(
            {
                **python_base,
                "service_key": wrong_prefix,
                "idempotency_key": compute_repair_idempotency_key(
                    node_id=NODE,
                    service_key=wrong_prefix,
                    kind=RepairKind.RELAUNCH_PYTHON,
                    target_fingerprint=python_plan.target.fingerprint,
                ),
            }
        )
    other_key = "python:other.py@9000"
    with pytest.raises(ValidationError, match="启动记录"):
        type(python_plan).model_validate(
            {
                **python_base,
                "service_key": other_key,
                "idempotency_key": compute_repair_idempotency_key(
                    node_id=NODE,
                    service_key=other_key,
                    kind=RepairKind.RELAUNCH_PYTHON,
                    target_fingerprint=python_plan.target.fingerprint,
                ),
            }
        )


def test_verification_must_match_checks() -> None:
    passed = RepairCheck(name=RepairCheckName.PORT_LISTENING, passed=True, detail="端口在听")
    failed = RepairCheck(name=RepairCheckName.WEB_PAGE, passed=False, detail="网页打不开")
    assert RepairVerification(passed=True, checks=(passed,), verified_at=NOW).passed
    with pytest.raises(ValidationError):
        RepairVerification(passed=True, checks=(passed, failed), verified_at=NOW)


def test_record_reuses_operation_state_machine_and_audit() -> None:
    record = RepairRecord.planned(plan(), actor="local-cli")
    assert record.status is OperationStatus.PLANNED
    assert record.audit[0].action is RepairAuditAction.PROPOSED

    later = NOW + timedelta(minutes=1)
    noted = record.with_event(
        RepairAuditAction.PRECHECK_FAILED, "情况变了", actor="repair-workflow", at=later
    )
    assert noted.updated_at == later
    assert (
        noted.with_event(
            RepairAuditAction.FINISHED, "结束", actor="repair-workflow", at=NOW
        ).updated_at
        == later
    )

    waiting = transition_operation(
        record, OperationStatus.AWAITING_AUTHORIZATION, reason="等批准", occurred_at=later
    )
    assert isinstance(waiting, RepairRecord)
    with pytest.raises(ValueError, match="不允许"):
        transition_operation(waiting, OperationStatus.SUCCEEDED, reason="跳过", occurred_at=later)

    foreign = AuthorizationRecord(
        authorization_id=AuthorizationId.new(),
        operation_id=OperationId.new(),
        kind=AuthorizationKind.ONE_TIME,
        decision=AuthorizationDecision.APPROVED,
        operator="local-web",
        basis="批准",
        decided_at=later,
    )
    with pytest.raises(ValidationError, match="operation_id"):
        RepairRecord.model_validate({**waiting.model_dump(), "authorization": foreign})


def test_authorization_service_requires_local_approval_for_repairs() -> None:
    store = _MemoryRepairStore()
    policy = OperationPolicy(_registry(), _NoPreauthorizations())
    service = AuthorizationService(store, _NoPreauthorizations(), policy)
    record = RepairRecord.planned(plan(), actor="local-cli")

    waiting = service.submit(record, at=NOW)
    assert waiting.status is OperationStatus.AWAITING_AUTHORIZATION
    assert service.submit(RepairRecord.planned(plan(), actor="local-cli"), at=NOW) is waiting
    with pytest.raises(PermissionError):
        service.approve_once(
            waiting.plan.operation_id,
            operator="peer",
            decided_at=NOW,
            expires_at=NOW + timedelta(minutes=10),
            local_control=False,
        )
    approved = service.approve_once(
        waiting.plan.operation_id,
        operator="local-web",
        decided_at=NOW,
        expires_at=NOW + timedelta(minutes=10),
        local_control=True,
    )
    assert approved.status is OperationStatus.AUTHORIZED
    assert isinstance(store.get(approved.plan.operation_id), RepairRecord)


def test_summary_omits_paths_and_commands() -> None:
    record = RepairRecord.planned(plan(PythonRepairTarget(launch=launch_record())), actor="cli")
    summary = RepairSummary.from_record(record)
    assert summary.verification_passed is None
    assert summary.error_code is None
    encoded = summary.model_dump_json()
    assert "C:/work/site" not in encoded
    assert "python.exe" not in encoded

    failed = record.model_copy(
        update={
            "verification": RepairVerification(
                passed=False,
                checks=(
                    RepairCheck(name=RepairCheckName.PORT_LISTENING, passed=False, detail="没在听"),
                ),
                verified_at=NOW,
            ),
            "error": RepairError(code=RepairErrorCode.VERIFICATION_FAILED, message="没修好"),
        }
    )
    failed_summary = RepairSummary.from_record(failed)
    assert failed_summary.verification_passed is False
    assert failed_summary.error_code is RepairErrorCode.VERIFICATION_FAILED
    assert failed_summary.error_message == "没修好"
