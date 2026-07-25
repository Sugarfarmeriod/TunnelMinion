from scripts.run_context_history_evaluation import evaluate, main


def test_context_history_stage_gate() -> None:
    report = evaluate(iterations=5)

    assert report.metrics.task_completion_rate == 1.0
    assert report.metrics.evidence_consistency_rate == 1.0
    assert report.metrics.trimming_correctness_rate == 1.0
    assert report.metrics.provider_tokens == 0
    assert report.metrics.estimated_cost == 0.0
    assert main(["--check"]) == 0
