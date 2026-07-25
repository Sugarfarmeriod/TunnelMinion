from scripts.run_artifact_context_evaluation import evaluate, main


def test_artifact_context_stage_gate() -> None:
    report = evaluate(iterations=5)

    assert report.metrics.context_limit_rate == 1.0
    assert report.metrics.artifact_isolation_rate == 1.0
    assert report.metrics.security_contamination_rate == 0.0
    assert report.metrics.provider_tokens == 0
    assert report.metrics.estimated_cost == 0.0
    assert main(["--check"]) == 0
