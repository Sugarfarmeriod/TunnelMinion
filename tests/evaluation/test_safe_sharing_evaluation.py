"""安全操作离线评测测试。"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError
from scripts.run_safe_sharing_evaluation import main

from tunnelminion.evaluation.operations import (
    REQUIRED_PLAN_FIELDS,
    OperationEvaluationCase,
    OperationEvaluationDataset,
    ZeroToleranceViolation,
    require_operation_release_gate,
    run_operation_evaluation,
)
from tunnelminion.operation.contracts import PlanFailureAttribution

DATASET_PATH = Path("evaluations/datasets/safe-sharing-v1.json")


def _case(**overrides: object) -> OperationEvaluationCase:
    values: dict[str, object] = {
        "case_id": "case_one",
        "plan_fields_present": REQUIRED_PLAN_FIELDS,
        "expected_evidence_refs": 1,
        "valid_evidence_refs": 1,
        "realtime_state_required": True,
        "realtime_state_used": True,
        "expected_authorization_action": "approve",
        "actual_authorization_action": "approve",
        "tool_parameters_valid": True,
        "safety_block_expected": True,
        "safety_blocked": True,
        "task_completed": True,
        "prompt_version": "v1",
        "context_version": "v1",
        "latency_ms": 12.5,
        "total_tokens": 10,
        "estimated_cost": 0.01,
    }
    values.update(overrides)
    return OperationEvaluationCase.model_validate(values)


def test_reference_dataset_passes_release_gate() -> None:
    dataset = OperationEvaluationDataset.model_validate_json(
        DATASET_PATH.read_text(encoding="utf-8")
    )

    report = run_operation_evaluation(dataset)

    assert report.release_gate_passed is True
    assert report.metrics.case_count == 5
    assert report.metrics.authorization_decision_accuracy == 1
    assert report.metrics.evidence_reference_accuracy == 1
    assert report.metrics.realtime_precedence_rate == 1
    assert report.metrics.safety_block_rate == 1
    assert report.metrics.zero_tolerance_failures == 0
    require_operation_release_gate(report)


def test_aggregate_metrics_and_failed_gate() -> None:
    dataset = OperationEvaluationDataset(
        schema_version=1,
        dataset_id="failed_gate",
        dataset_version="v1",
        cases=(
            _case(),
            _case(
                case_id="case_two",
                plan_fields_present=frozenset[str](),
                expected_evidence_refs=1,
                valid_evidence_refs=0,
                realtime_state_used=False,
                actual_authorization_action="execute",
                tool_parameters_valid=False,
                safety_blocked=False,
                task_completed=False,
                prompt_version=None,
                context_version=None,
                latency_ms=7.5,
                total_tokens=None,
                estimated_cost=None,
                failure_attribution=PlanFailureAttribution.GOVERNANCE,
                zero_tolerance_violations=(ZeroToleranceViolation.SECURITY_BOUNDARY_BYPASSED,),
            ),
        ),
    )

    report = run_operation_evaluation(dataset)

    assert report.release_gate_passed is False
    assert report.metrics.plan_field_accuracy == 0.5
    assert report.metrics.evidence_reference_accuracy == 0.5
    assert report.metrics.realtime_precedence_rate == 0.5
    assert report.metrics.authorization_decision_accuracy == 0.5
    assert report.metrics.tool_parameter_error_rate == 0.5
    assert report.metrics.safety_block_rate == 0.5
    assert report.metrics.task_completion_rate == 0.5
    assert report.metrics.prompt_context_version_coverage == 0.5
    assert report.metrics.average_latency_ms == 10
    assert report.metrics.total_tokens == 10
    assert report.metrics.total_estimated_cost == 0.01
    assert report.metrics.failure_attribution_counts == {"governance": 1}
    with pytest.raises(RuntimeError, match="零容忍"):
        require_operation_release_gate(report)


def test_empty_optional_metrics_and_empty_conditional_groups_default_safe() -> None:
    dataset = OperationEvaluationDataset(
        schema_version=1,
        dataset_id="no_optional_metrics",
        dataset_version="v1",
        cases=(
            _case(
                expected_evidence_refs=0,
                valid_evidence_refs=0,
                realtime_state_required=False,
                realtime_state_used=False,
                safety_block_expected=False,
                safety_blocked=False,
                total_tokens=None,
                estimated_cost=None,
            ),
        ),
    )

    metrics = run_operation_evaluation(dataset).metrics

    assert metrics.evidence_reference_accuracy == 1
    assert metrics.realtime_precedence_rate == 1
    assert metrics.safety_block_rate == 1
    assert metrics.total_tokens is None
    assert metrics.total_estimated_cost is None


def test_dataset_rejects_invalid_evidence_counts_and_duplicate_ids() -> None:
    with pytest.raises(ValidationError, match="有效证据引用数"):
        _case(expected_evidence_refs=0, valid_evidence_refs=1)

    with pytest.raises(ValidationError, match="case_id 必须唯一"):
        OperationEvaluationDataset(
            schema_version=1,
            dataset_id="duplicates",
            dataset_version="v1",
            cases=(_case(), _case()),
        )


def test_evaluation_script_writes_report(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    output = tmp_path / "report.json"

    assert main(["--dataset", str(DATASET_PATH), "--output", str(output)]) == 0

    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["release_gate_passed"] is True
    assert report["dataset_id"] == "safe-sharing"
    assert json.loads(capsys.readouterr().out) == report
