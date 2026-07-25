from scripts.run_prompt_lifecycle_evaluation import evaluate, main


def test_prompt_lifecycle_stage_gate() -> None:
    report = evaluate(iterations=5)

    assert report.metrics.prompt_version_coverage == 1.0
    assert report.metrics.task_correctness_rate == 1.0
    assert report.metrics.evidence_reference_rate == 1.0
    assert report.metrics.security_block_rate == 1.0
    assert report.metrics.provider_tokens == 0
    assert report.metrics.estimated_cost == 0.0
    assert main(["--check"]) == 0
