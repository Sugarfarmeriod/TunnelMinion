from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from tunnelminion.domain.identifiers import IncidentId, NodeId, SnapshotId, ToolRunId
from tunnelminion.domain.tools import Platform
from tunnelminion.incident.contracts import (
    EvidenceExecution,
    EvidenceReference,
    Incident,
    IncidentEventType,
    InvestigationPhase,
    InvestigationState,
    InvestigationStepState,
    InvestigationStepStatus,
    InvestigationStopReason,
    SnapshotDiffEvent,
    SnapshotObjectKind,
    SnapshotSource,
)
from tunnelminion.incident.skills import (
    SERVICE_LOCAL_ONLY,
    InvestigationSkill,
    select_investigation_skill,
)

NOW = datetime(2026, 9, 21, tzinfo=UTC)
LOCAL = NodeId("node_" + "a" * 32)
REMOTE = NodeId("node_" + "b" * 32)


def _incident(event_type: IncidentEventType = IncidentEventType.LOCAL_ONLY) -> Incident:
    event = SnapshotDiffEvent(
        event_type=event_type,
        object_kind=SnapshotObjectKind.SERVICE,
        object_id="service_" + "c" * 32,
        target_node_id=REMOTE,
        baseline_snapshot_id=SnapshotId("snapshot_" + "d" * 32),
        current_snapshot_id=SnapshotId("snapshot_" + "e" * 32),
        baseline_revision=1,
        current_revision=2,
        observed_at=NOW,
        source=SnapshotSource.COORDINATOR_DIRECTORY,
        dedup_key="sha256:" + "f" * 64,
    )
    return Incident(
        incident_id=IncidentId("incident_" + "1" * 32),
        dedup_key=event.dedup_key,
        event=event,
        created_at=NOW,
        last_observed_at=NOW,
    )


def test_local_only_skill_covers_four_requirements_with_three_read_only_steps() -> None:
    assert SERVICE_LOCAL_ONLY.skill_id == "service.local-only"
    assert len(SERVICE_LOCAL_ONLY.requirements) == 4
    assert [item.tool_name for item in SERVICE_LOCAL_ONLY.steps] == [
        "get_node_summary",
        "list_network_listeners",
        "probe_service_reachability",
    ]
    assert SERVICE_LOCAL_ONLY.steps[1].requirement_ids == (
        "target-process",
        "target-listener",
    )
    assert SERVICE_LOCAL_ONLY.steps[-1].execution is EvidenceExecution.REQUESTER


def test_skill_selection_matches_event_topology_and_platform() -> None:
    assert (
        select_investigation_skill(
            _incident(),
            local_node_id=str(LOCAL),
            request_platform=Platform.WINDOWS,
            target_platform=Platform.MACOS,
        )
        is SERVICE_LOCAL_ONLY
    )
    assert (
        select_investigation_skill(
            _incident(IncidentEventType.SERVICE_ADDED),
            local_node_id=str(LOCAL),
            request_platform=Platform.WINDOWS,
            target_platform=Platform.MACOS,
        )
        is None
    )


def test_skill_rejects_missing_requirement_coverage() -> None:
    with pytest.raises(ValidationError, match="完整覆盖"):
        InvestigationSkill.model_validate(
            SERVICE_LOCAL_ONLY.model_dump() | {"requirements": SERVICE_LOCAL_ONLY.requirements[:-1]}
        )

    duplicated = SERVICE_LOCAL_ONLY.model_dump()
    duplicated["steps"] = (*SERVICE_LOCAL_ONLY.steps, SERVICE_LOCAL_ONLY.steps[0])
    with pytest.raises(ValidationError, match="身份不得重复"):
        InvestigationSkill.model_validate(duplicated)


def test_investigation_state_is_backward_compatible_and_rejects_secrets() -> None:
    incident = _incident()
    old_payload = incident.model_dump(mode="json", exclude={"investigation"})
    assert Incident.model_validate(old_payload).investigation is None

    evidence = EvidenceReference(
        tool_run_id=ToolRunId("toolrun_" + "2" * 32),
        observed_at=NOW,
        summary="目标节点摘要可用",
    )
    step = InvestigationStepState(
        step_id="target-node",
        requirement_ids=("private-network",),
        tool_name="get_node_summary",
        execution=EvidenceExecution.TARGET,
        status=InvestigationStepStatus.SUCCEEDED,
        attempts=1,
        evidence=evidence,
        observations={"private_address": "10.77.0.1", "interface_up": True},
    )
    state = InvestigationState(
        skill_id="service.local-only",
        skill_version="1",
        phase=InvestigationPhase.FINISHED,
        model_rounds=1,
        tool_calls=1,
        steps=(step,),
        facts=("目标私网接口可用",),
        unknowns=("请求端可达性尚未确认",),
        stop_reason=InvestigationStopReason.INSUFFICIENT_EVIDENCE,
        updated_at=NOW,
    )
    persisted = incident.model_copy(update={"investigation": state})
    assert Incident.model_validate_json(persisted.model_dump_json()) == persisted

    unsafe = step.model_copy(update={"observations": {"note": "password=secret"}})
    with pytest.raises(ValueError, match="秘密"):
        incident.model_copy(
            update={"investigation": state.model_copy(update={"steps": (unsafe,)})}
        ).assert_no_secret_material()


@pytest.mark.parametrize(
    ("updates", "message"),
    [
        ({"requirement_ids": ("same", "same")}, "不得重复"),
        ({"observations": {f"item_{index}": index for index in range(13)}}, "数量"),
        ({"observations": {"Bad-Key": True}}, "字段名"),
        ({"observations": {"message": "x" * 129}}, "字符串"),
        ({"status": "succeeded", "evidence": None}, "必须引用"),
        (
            {
                "status": "failed",
                "evidence": EvidenceReference(
                    tool_run_id=ToolRunId("toolrun_" + "3" * 32),
                    observed_at=NOW,
                    summary="不应保存",
                ),
            },
            "不得保存",
        ),
    ],
)
def test_investigation_step_rejects_unbounded_or_inconsistent_state(
    updates: dict[str, object], message: str
) -> None:
    payload: dict[str, object] = {
        "step_id": "target-node",
        "requirement_ids": ("private-network",),
        "tool_name": "get_node_summary",
        "execution": "target",
    }
    with pytest.raises(ValidationError, match=message):
        InvestigationStepState.model_validate(payload | updates)


def test_investigation_state_rejects_duplicate_steps_and_unfinished_terminal_state() -> None:
    step = InvestigationStepState(
        step_id="target-node",
        requirement_ids=("private-network",),
        tool_name="get_node_summary",
        execution=EvidenceExecution.TARGET,
    )
    base = {
        "skill_id": "service.local-only",
        "skill_version": "1",
        "updated_at": NOW,
    }
    with pytest.raises(ValidationError, match="重复步骤"):
        InvestigationState.model_validate(base | {"steps": (step, step)})
    with pytest.raises(ValidationError, match="停止原因"):
        InvestigationState.model_validate(base | {"phase": "finished"})
