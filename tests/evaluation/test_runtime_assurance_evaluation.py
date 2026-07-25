from scripts.run_runtime_assurance_evaluation import evaluate, main


def test_runtime_assurance_stage_gate() -> None:
    report = evaluate(iterations=5)

    assert report.metrics.observability_completeness_rate == 1.0
    assert report.metrics.failure_classification_rate == 1.0
    assert report.metrics.fault_isolation_rate == 1.0
    assert report.metrics.metadata_leakage_rate == 0.0
    assert report.metrics.deterministic_degradation_rate == 1.0
    assert report.metrics.provider_tokens == 0
    assert report.metrics.estimated_cost == 0.0
    assert main(["--check"]) == 0
