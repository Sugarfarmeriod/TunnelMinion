"""Coordinator 网络数据集、安全门槛、路径对比与故障归因测试。"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from tunnelminion.evaluation.coordinator_network import (
    CoordinatorEvaluationCase,
    CoordinatorEvaluationDataset,
    CoordinatorEvaluationObservation,
    CoordinatorEvaluationThresholds,
    CoordinatorPath,
    CoordinatorScenarioCategory,
    coordinator_evaluation_dataset,
    evaluate_coordinator_network,
)


def passing_observations() -> tuple[CoordinatorEvaluationObservation, ...]:
    dataset = coordinator_evaluation_dataset()
    values: list[CoordinatorEvaluationObservation] = []
    for case in dataset.cases:
        values.append(
            CoordinatorEvaluationObservation(
                case_id=case.case_id,
                path=case.path,
                convergence_correct=True,
                freshness_correct=True,
                safety_blocked=case.expected_blocked,
                degraded_deterministically=case.expected_degraded,
                fault_attribution=case.expected_fault,
                out_of_order_rejected=(True if case.case_id == "out-of-order-snapshot" else None),
                revocation_propagation_ms=(250 if case.case_id == "node-revocation" else None),
                query_latency_ms=10,
                sync_latency_ms=20,
                storage_bytes=1_024,
                server_revisions=1,
                total_latency_ms=(30 if case.path is CoordinatorPath.STATIC else 40),
                input_tokens=10,
                output_tokens=5,
                estimated_cost=0.001,
            )
        )
    return tuple(values)


def test_dataset_covers_lifecycle_security_faults_and_path_comparison() -> None:
    dataset = coordinator_evaluation_dataset()
    identifiers = {case.case_id for case in dataset.cases}
    assert dataset.dataset_version == "v1"
    assert len(dataset.cases) == 21
    assert {
        "registration-success",
        "token-replay",
        "cross-network",
        "node-revocation",
        "heartbeat-timeout",
        "out-of-order-snapshot",
        "service-disappearance",
        "protocol-incompatible",
        "coordinator-offline",
        "signature-tamper",
        "unknown-key",
        "wrong-audience",
        "assertion-expired",
        "auth-cache-expired",
        "identity-confusion",
        "coordinator-fault",
        "model-fault",
        "gateway-fault",
        "synchronizer-fault",
        "static-path-baseline",
        "managed-path-baseline",
    } == identifiers


def test_report_measures_convergence_security_growth_and_static_managed_paths() -> None:
    report = evaluate_coordinator_network(
        coordinator_evaluation_dataset(),
        passing_observations(),
    )
    assert report.passed is True
    assert report.convergence_accuracy == report.freshness_accuracy == 1
    assert report.out_of_order_rejection_rate == 1
    assert report.fault_attribution_accuracy == 1
    assert report.revocation_propagation_p95_ms == 250
    assert report.query_latency_p95_ms == 10
    assert report.sync_latency_p95_ms == 20
    assert report.storage_bytes_per_revision == 1_024
    assert report.safety_failures == 0
    assert report.static_path.sample_count == report.managed_path.sample_count == 1
    assert report.static_path.average_latency_ms == 30
    assert report.managed_path.average_latency_ms == 40
    assert report.static_path.total_tokens == 15
    assert report.managed_path.total_estimated_cost == 0.001


@pytest.mark.parametrize(
    ("case_id", "updates", "thresholds"),
    [
        ("registration-success", {"convergence_correct": False}, {}),
        ("registration-success", {"freshness_correct": False}, {}),
        ("out-of-order-snapshot", {"out_of_order_rejected": False}, {}),
        ("coordinator-fault", {"fault_attribution": None}, {}),
        (
            "node-revocation",
            {"revocation_propagation_ms": 1_001},
            {},
        ),
        (
            "registration-success",
            {"storage_bytes": 100_000},
            {"maximum_storage_bytes_per_revision": 5_000},
        ),
        ("token-replay", {"safety_blocked": False}, {}),
        (
            "coordinator-offline",
            {"degraded_deterministically": False},
            {},
        ),
    ],
)
def test_each_quality_or_safety_threshold_can_fail(
    case_id: str,
    updates: dict[str, object],
    thresholds: dict[str, object],
) -> None:
    observations = tuple(
        item.model_copy(update=updates) if item.case_id == case_id else item
        for item in passing_observations()
    )
    limits = CoordinatorEvaluationThresholds.model_validate(thresholds)
    report = evaluate_coordinator_network(
        coordinator_evaluation_dataset(),
        observations,
        limits,
    )
    assert report.passed is False


def test_dataset_and_observation_identity_are_strict() -> None:
    case = CoordinatorEvaluationCase(
        case_id="one-case",
        category=CoordinatorScenarioCategory.LIFECYCLE,
    )
    with pytest.raises(ValidationError, match="唯一"):
        CoordinatorEvaluationDataset(cases=(case, case))

    dataset = CoordinatorEvaluationDataset(cases=(case,))
    observation = CoordinatorEvaluationObservation(
        case_id=case.case_id,
        path=CoordinatorPath.CONTROL,
        convergence_correct=True,
        freshness_correct=True,
        safety_blocked=False,
        degraded_deterministically=False,
    )
    with pytest.raises(ValueError, match="唯一"):
        evaluate_coordinator_network(dataset, (observation, observation))
    with pytest.raises(ValueError, match="完整匹配"):
        evaluate_coordinator_network(dataset, ())
    with pytest.raises(ValueError, match="路径"):
        evaluate_coordinator_network(
            dataset,
            (observation.model_copy(update={"path": CoordinatorPath.STATIC}),),
        )


def test_empty_optional_metric_groups_are_defined() -> None:
    case = CoordinatorEvaluationCase(
        case_id="minimal-case",
        category=CoordinatorScenarioCategory.LIFECYCLE,
    )
    report = evaluate_coordinator_network(
        CoordinatorEvaluationDataset(cases=(case,)),
        (
            CoordinatorEvaluationObservation(
                case_id=case.case_id,
                path=CoordinatorPath.CONTROL,
                convergence_correct=True,
                freshness_correct=True,
                safety_blocked=False,
                degraded_deterministically=False,
            ),
        ),
    )
    assert report.passed is True
    assert report.revocation_propagation_p95_ms == 0
    assert report.out_of_order_rejection_rate == 1
    assert report.fault_attribution_accuracy == 1
    assert report.storage_bytes_per_revision == 0
    assert report.static_path.sample_count == 0
    assert report.managed_path.sample_count == 0
