from scripts.run_memory_context_evaluation import evaluate, main


def test_memory_context_stage_gate() -> None:
    report = evaluate(iterations=5)

    assert report.metrics.memory_hit_correctness == 1.0
    assert report.metrics.incorrect_injection_rate == 0.0
    assert report.metrics.namespace_leakage_rate == 0.0
    assert report.metrics.lifecycle_residual_rate == 0.0
    assert report.metrics.provider_tokens == 0
    assert report.metrics.estimated_cost == 0.0
    assert main(["--check"]) == 0
