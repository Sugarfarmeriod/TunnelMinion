"""L0-L4 策略、预授权和本地授权服务测试。"""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path

import pytest
from pydantic import JsonValue, ValidationError
from tests.operation.factories import NOW, plan

from tunnelminion.domain.identifiers import AuthorizationId, NodeId, OperationId
from tunnelminion.domain.tools import (
    DataSensitivity,
    Platform,
    RiskLevel,
    ToolDefinition,
)
from tunnelminion.domain.versioning import ProtocolVersion
from tunnelminion.memory.sqlite import SQLiteStores
from tunnelminion.operation.contracts import (
    OperationLevel,
    OperationPlan,
    OperationRecord,
    OperationStatus,
    Preauthorization,
    compute_idempotency_key,
    transition_operation,
)
from tunnelminion.operation.policy import (
    AuthorizationService,
    OperationPolicy,
    PolicyAction,
)
from tunnelminion.tools.fakes import FakeToolAdapter
from tunnelminion.tools.registry import ToolRegistry


def _definition(name: str, risk: RiskLevel) -> ToolDefinition:
    schema: dict[str, JsonValue] = {"type": "object", "additionalProperties": False}
    return ToolDefinition(
        name=name,
        version=ProtocolVersion(major=1, minor=0),
        description="策略测试工具。",
        input_schema=schema,
        output_schema={"type": "object"},
        risk_level=risk,
        platforms=frozenset({Platform.WINDOWS}),
        permissions=("test",),
        timeout_seconds=1,
        max_result_bytes=1024,
        data_sensitivity=DataSensitivity.SYSTEM_METADATA,
    )


def _registry() -> ToolRegistry:
    registry = ToolRegistry()
    adapter = FakeToolAdapter()
    registry.register(_definition("read_status", RiskLevel.READ_ONLY), adapter)
    registry.register(_definition("suggest_change", RiskLevel.ADVISORY), adapter)
    registry.register(_definition("share_local_http_service", RiskLevel.REQUIRES_APPROVAL), adapter)
    registry.register(_definition("restart_service", RiskLevel.SENSITIVE), adapter)
    registry.register(_definition("run_arbitrary_code", RiskLevel.FORBIDDEN), adapter)
    return registry


def _plan_for(tool_name: str, level: OperationLevel) -> OperationPlan:
    base = plan()
    key = compute_idempotency_key(
        request_node_id=base.request_node_id,
        target_node_id=base.target_node_id,
        tool_name=tool_name,
        plan_version=base.plan_version,
        service_fingerprint=base.service.fingerprint,
        access_scope=base.access_scope,
    )
    return OperationPlan.model_validate(
        {
            **base.model_dump(),
            "tool_name": tool_name,
            "level": level,
            "idempotency_key": key,
        }
    )


def _preauthorization(operation_plan: OperationPlan, **updates: object) -> Preauthorization:
    values: dict[str, object] = {
        "authorization_id": AuthorizationId.new(),
        "target_node_id": operation_plan.target_node_id,
        "request_peer_id": operation_plan.request_node_id,
        "tool_name": operation_plan.tool_name,
        "service_ids": frozenset({operation_plan.service.service_id}),
        "service_fingerprints": frozenset({operation_plan.service.fingerprint}),
        "minimum_port": 18880,
        "maximum_port": 18890,
        "maximum_duration_seconds": 600,
        "created_by": "target-local-user",
        "valid_from": NOW - timedelta(minutes=1),
        "valid_until": NOW + timedelta(hours=1),
    }
    values.update(updates)
    return Preauthorization.model_validate(values)


def _services(path: Path) -> tuple[AuthorizationService, OperationPolicy]:
    stores = SQLiteStores.open(path)
    policy = OperationPolicy(_registry(), stores.preauthorizations)
    return AuthorizationService(stores.operations, stores.preauthorizations, policy), policy


def test_policy_uses_registry_level_and_refuses_model_downgrade(tmp_path: Path) -> None:
    _, policy = _services(tmp_path / "policy.sqlite3")
    expected = (
        ("read_status", OperationLevel.L0, PolicyAction.EXECUTE),
        ("suggest_change", OperationLevel.L1, PolicyAction.PLAN_ONLY),
        ("share_local_http_service", OperationLevel.L2, PolicyAction.AWAIT_AUTHORIZATION),
        ("restart_service", OperationLevel.L3, PolicyAction.REFUSE),
        ("run_arbitrary_code", OperationLevel.L4, PolicyAction.REFUSE),
        ("unknown_tool", OperationLevel.L4, PolicyAction.REFUSE),
    )
    for tool_name, level, action in expected:
        decision = policy.evaluate(_plan_for(tool_name, level), at=NOW)
        assert decision.actual_level is level
        assert decision.action is action

    downgraded = _plan_for("restart_service", OperationLevel.L2)
    decision = policy.evaluate(downgraded, at=NOW)
    assert decision.actual_level is OperationLevel.L3
    assert decision.code == "model_level_mismatch"
    assert decision.action is PolicyAction.REFUSE


def test_explicit_l3_workflow_requires_dedicated_governance_and_stays_out_of_model_tools(
    tmp_path: Path,
) -> None:
    registry = _registry()
    registry.register(
        _definition("managed_network_apply", RiskLevel.SENSITIVE),
        FakeToolAdapter(),
    )
    stores = SQLiteStores.open(tmp_path / "l3-governance.sqlite3")
    policy = OperationPolicy(
        registry,
        stores.preauthorizations,
        l3_governance_workflows=frozenset({"managed_network_apply"}),
    )
    decision = policy.evaluate(
        _plan_for("managed_network_apply", OperationLevel.L3),
        at=NOW,
    )
    assert decision.action is PolicyAction.AWAIT_AUTHORIZATION
    assert decision.code == "dedicated_governance_required"
    assert "managed_network_apply" not in {
        definition.name for definition in registry.model_tools(Platform.WINDOWS)
    }


def test_preauthorization_requires_every_scope_dimension_to_match(tmp_path: Path) -> None:
    stores = SQLiteStores.open(tmp_path / "preauth.sqlite3")
    policy = OperationPolicy(_registry(), stores.preauthorizations)
    operation_plan = _plan_for("share_local_http_service", OperationLevel.L2)
    authorization = _preauthorization(operation_plan)
    stores.preauthorizations.put(authorization)

    matched = policy.evaluate(operation_plan, at=NOW)
    assert matched.action is PolicyAction.EXECUTE
    assert matched.matched_authorization_id == authorization.authorization_id

    mismatches = (
        {"target_node_id": NodeId.new()},
        {"request_peer_id": NodeId.new()},
        {"tool_name": "another_tool"},
        {"service_ids": frozenset({"other-service"})},
        {"service_fingerprints": frozenset({f"sha256:{'9' * 64}"})},
        {"minimum_port": 18882},
        {"maximum_port": 18880},
        {"maximum_duration_seconds": 299},
        {"valid_from": NOW + timedelta(seconds=1)},
        {"valid_until": NOW},
        {"revoked_at": NOW},
    )
    for updates in mismatches:
        stores = SQLiteStores.open(tmp_path / f"mismatch-{len(str(updates))}.sqlite3")
        candidate = _preauthorization(operation_plan, **updates)
        stores.preauthorizations.put(candidate)
        decision = OperationPolicy(_registry(), stores.preauthorizations).evaluate(
            operation_plan, at=NOW
        )
        assert decision.action is PolicyAction.AWAIT_AUTHORIZATION


def test_preauthorization_validates_range_and_dates() -> None:
    operation_plan = _plan_for("share_local_http_service", OperationLevel.L2)
    with pytest.raises(ValidationError, match="最大端口"):
        _preauthorization(operation_plan, minimum_port=19000, maximum_port=18000)
    with pytest.raises(ValidationError, match="有效期"):
        _preauthorization(operation_plan, valid_until=NOW - timedelta(minutes=2))
    with pytest.raises(ValidationError, match="撤销时间"):
        _preauthorization(operation_plan, revoked_at=NOW - timedelta(minutes=2))


def test_authorization_service_enforces_local_control_and_persists_decisions(
    tmp_path: Path,
) -> None:
    path = tmp_path / "authorization.sqlite3"
    stores = SQLiteStores.open(path)
    policy = OperationPolicy(_registry(), stores.preauthorizations)
    service = AuthorizationService(stores.operations, stores.preauthorizations, policy)
    operation_plan = _plan_for("share_local_http_service", OperationLevel.L2)
    authorization = _preauthorization(operation_plan)

    with pytest.raises(PermissionError, match="本地"):
        service.create_preauthorization(authorization, local_control=False)
    service.create_preauthorization(authorization, local_control=True)
    assert stores.preauthorizations.get(authorization.authorization_id) == authorization
    assert stores.preauthorizations.list_all() == (authorization,)
    with pytest.raises(PermissionError, match="本地"):
        service.revoke_preauthorization(
            authorization.authorization_id,
            revoked_at=NOW,
            local_control=False,
        )
    with pytest.raises(KeyError, match="不存在"):
        service.revoke_preauthorization(
            AuthorizationId.new(),
            revoked_at=NOW,
            local_control=True,
        )
    revoked = service.revoke_preauthorization(
        authorization.authorization_id,
        revoked_at=NOW,
        local_control=True,
    )
    assert revoked.revoked_at == NOW
    assert stores.preauthorizations.list_active(at=NOW) == ()

    awaiting = service.submit(OperationRecord.planned(operation_plan), at=NOW)
    assert awaiting.status is OperationStatus.AWAITING_AUTHORIZATION
    assert service.submit(OperationRecord.planned(operation_plan), at=NOW) == awaiting

    with pytest.raises(PermissionError, match="本地"):
        service.approve_once(
            operation_plan.operation_id,
            operator="remote",
            decided_at=NOW + timedelta(seconds=1),
            expires_at=NOW + timedelta(minutes=1),
            local_control=False,
        )
    approved = service.approve_once(
        operation_plan.operation_id,
        operator="local-user",
        decided_at=NOW + timedelta(seconds=1),
        expires_at=NOW + timedelta(minutes=1),
        local_control=True,
    )
    assert approved.status is OperationStatus.AUTHORIZED
    assert approved.authorization is not None

    with pytest.raises(ValueError, match="不等待"):
        service.approve_once(
            operation_plan.operation_id,
            operator="local-user",
            decided_at=NOW + timedelta(seconds=2),
            expires_at=NOW + timedelta(minutes=1),
            local_control=True,
        )
    expired = service.expire_once(
        operation_plan.operation_id,
        expired_at=NOW + timedelta(minutes=2),
    )
    assert expired.status is OperationStatus.AUTHORIZATION_EXPIRED
    with pytest.raises(ValueError, match="可过期"):
        service.expire_once(
            operation_plan.operation_id,
            expired_at=NOW + timedelta(minutes=3),
        )


def test_authorization_service_handles_preauthorized_rejected_and_invalid_records(
    tmp_path: Path,
) -> None:
    path = tmp_path / "decisions.sqlite3"
    stores = SQLiteStores.open(path)
    policy = OperationPolicy(_registry(), stores.preauthorizations)
    service = AuthorizationService(stores.operations, stores.preauthorizations, policy)
    preauthorized_plan = _plan_for("share_local_http_service", OperationLevel.L2)
    service.create_preauthorization(
        _preauthorization(preauthorized_plan),
        local_control=True,
    )
    authorized = service.submit(OperationRecord.planned(preauthorized_plan), at=NOW)
    assert authorized.status is OperationStatus.AUTHORIZED
    assert authorized.authorization is not None
    assert authorized.authorization.kind.value == "preauthorization"

    read_only = service.submit(
        OperationRecord.planned(_plan_for("read_status", OperationLevel.L0)),
        at=NOW,
    )
    assert read_only.status is OperationStatus.AUTHORIZED
    assert read_only.authorization is not None
    assert read_only.authorization.kind.value == "one_time"

    forbidden = service.submit(
        OperationRecord.planned(_plan_for("run_arbitrary_code", OperationLevel.L4)),
        at=NOW,
    )
    assert forbidden.status is OperationStatus.CANCELLED

    rejected_plan = _plan_for("share_local_http_service", OperationLevel.L2)
    awaiting = service.submit(OperationRecord.planned(rejected_plan), at=NOW)
    with pytest.raises(PermissionError, match="本地"):
        service.reject_once(
            rejected_plan.operation_id,
            operator="remote",
            reason="拒绝",
            decided_at=NOW + timedelta(seconds=1),
            local_control=False,
        )
    rejected = service.reject_once(
        rejected_plan.operation_id,
        operator="local-user",
        reason="目标不正确",
        decided_at=NOW + timedelta(seconds=1),
        local_control=True,
    )
    assert awaiting.status is OperationStatus.AWAITING_AUTHORIZATION
    assert rejected.status is OperationStatus.REJECTED
    assert rejected.authorization is not None
    assert rejected.authorization.decision.value == "rejected"
    with pytest.raises(ValueError, match="不等待"):
        service.reject_once(
            rejected_plan.operation_id,
            operator="local-user",
            reason="重复",
            decided_at=NOW + timedelta(seconds=2),
            local_control=True,
        )

    cancellable_plan = _plan_for("share_local_http_service", OperationLevel.L2)
    cancellable = service.submit(OperationRecord.planned(cancellable_plan), at=NOW)
    assert cancellable.status is OperationStatus.AWAITING_AUTHORIZATION
    with pytest.raises(PermissionError, match="本地"):
        service.cancel(
            cancellable_plan.operation_id,
            reason="远端不能取消",
            cancelled_at=NOW + timedelta(seconds=1),
            local_control=False,
        )
    cancelled = service.cancel(
        cancellable_plan.operation_id,
        reason="用户撤销请求",
        cancelled_at=NOW + timedelta(seconds=1),
        local_control=True,
    )
    assert cancelled.status is OperationStatus.CANCELLED
    with pytest.raises(ValueError, match="不能直接取消"):
        service.cancel(
            cancellable_plan.operation_id,
            reason="重复",
            cancelled_at=NOW + timedelta(seconds=2),
            local_control=True,
        )

    with pytest.raises(KeyError, match="不存在"):
        service.approve_once(
            OperationId.new(),
            operator="local-user",
            decided_at=NOW,
            expires_at=NOW + timedelta(minutes=1),
            local_control=True,
        )
    nonplanned = transition_operation(
        OperationRecord.planned(_plan_for("share_local_http_service", OperationLevel.L2)),
        OperationStatus.AWAITING_AUTHORIZATION,
        reason="already",
        occurred_at=NOW + timedelta(seconds=1),
    )
    with pytest.raises(ValueError, match="planned"):
        service.submit(nonplanned, at=NOW + timedelta(seconds=2))
