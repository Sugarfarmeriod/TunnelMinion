"""综合 Context、Prompt 与 Runtime 离线门禁测试。"""

from pathlib import Path

from scripts.run_integrated_context_evaluation import REQUIRED_SCENARIOS, evaluate


def test_integrated_context_evaluation_covers_all_required_risks() -> None:
    report = evaluate(Path("evaluations/datasets/context-safety-v1.json"))

    assert set(report.scenario_ids) == REQUIRED_SCENARIOS
    assert report.zero_tolerance_violations == ()
    assert report.metrics.required_scenario_coverage == 1
    assert report.metrics.tool_selection_correctness == 1
    assert report.metrics.task_completion_rate == 1
    assert report.metrics.invalid_parameter_rate == 0
    assert report.metrics.security_block_rate == 1
    assert report.metrics.fact_freshness_rate == 1
    assert report.metrics.memory_isolation_rate == 1
    assert report.metrics.prompt_version_coverage == 1
    assert report.metrics.input_tokens == 0
    assert report.metrics.output_tokens == 0
    assert report.metrics.total_tokens == 0
    assert report.metrics.estimated_cost == 0
