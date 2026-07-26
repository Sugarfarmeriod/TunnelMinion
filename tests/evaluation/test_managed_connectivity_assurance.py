"""受管连接第 9 阶段的固定数据集与模型不变量门禁。"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError
from scripts.run_managed_connectivity_assurance import (
    AssuranceCase,
    AssuranceDataset,
    AssuranceReport,
    CaseObservation,
    deterministic_observations,
    evaluate,
    load_dataset,
    main,
)


def test_dataset_covers_required_failure_matrix_and_passes() -> None:
    dataset = load_dataset()
    assert {case.case_id for case in dataset.cases} == {
        "address-conflict",
        "signature-tamper",
        "cross-node-replay",
        "policy-escalation",
        "partial-success",
        "rollback-failure",
        "ownership-conflict",
        "control-plane-offline",
        "verified-direct",
        "relay-unavailable",
    }
    report = evaluate(dataset, deterministic_observations(dataset))
    assert report.passed is True
    assert report.metrics.convergence_accuracy == 1
    assert report.metrics.path_selection_accuracy == 1
    assert report.metrics.safety_block_rate == 1
    assert report.metrics.rollback_success_rate == 1
    assert report.metrics.model_invariance_rate == 1
    assert report.metrics.model_explanation_tokens == 300


@pytest.mark.parametrize(
    ("case_id", "updates"),
    [
        ("verified-direct", {"state": "degraded"}),
        ("verified-direct", {"selected_path": "static"}),
        ("address-conflict", {"blocked": False}),
        ("partial-success", {"rollback_result": "failed"}),
        ("signature-tamper", {"invalid_parameter_count": 1}),
    ],
)
def test_each_correctness_or_safety_metric_can_fail(
    case_id: str,
    updates: dict[str, object],
) -> None:
    dataset = load_dataset()
    observations = tuple(
        item.model_copy(
            update={
                "model_disabled": item.model_disabled.model_copy(update=updates),
                "model_enabled": item.model_enabled.model_copy(update=updates),
            }
        )
        if item.case_id == case_id
        else item
        for item in deterministic_observations(dataset)
    )
    assert evaluate(dataset, observations).passed is False


def test_model_cannot_change_operational_result() -> None:
    dataset = load_dataset()
    observations = deterministic_observations(dataset)
    changed = observations[0].model_copy(
        update={
            "model_enabled": observations[0].model_enabled.model_copy(
                update={"authorization_decision": "allowed"}
            )
        }
    )
    report = evaluate(dataset, (changed, *observations[1:]))
    assert report.passed is False
    assert report.metrics.model_invariance_rate < 1


def test_dataset_and_observations_are_strict() -> None:
    case = AssuranceCase(
        case_id="same-case",
        expected_path="static",
        expected_state="degraded",
        must_block=False,
        rollback_required=False,
    )
    with pytest.raises(ValueError, match="必须唯一"):
        AssuranceDataset(
            schema_version="managed-connectivity-assurance/v1",
            cases=(case, case),
        )
    with pytest.raises(ValidationError):
        AssuranceCase.model_validate({**case.model_dump(), "endpoint": "forbidden"})

    dataset = AssuranceDataset(
        schema_version="managed-connectivity-assurance/v1",
        cases=(case,),
    )
    observation = deterministic_observations(dataset)[0]
    with pytest.raises(ValueError, match="必须唯一"):
        evaluate(dataset, (observation, observation))
    with pytest.raises(ValueError, match="完整匹配"):
        evaluate(dataset, ())


def test_cli_writes_report_and_returns_failure_status(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = tmp_path / "report.json"
    assert main(["--output", str(output), "--check"]) == 0
    assert json.loads(output.read_text(encoding="utf-8"))["passed"] is True

    from scripts import run_managed_connectivity_assurance as module

    original = module.evaluate

    def failed_evaluate(
        dataset: AssuranceDataset,
        observations: tuple[CaseObservation, ...],
    ) -> AssuranceReport:
        return original(dataset, observations).model_copy(update={"passed": False})

    monkeypatch.setattr(
        module,
        "evaluate",
        failed_evaluate,
    )
    assert main(["--check"]) == 1
