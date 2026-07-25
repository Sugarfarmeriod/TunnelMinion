import json
from pathlib import Path
from typing import Any, cast

from tunnelminion.evaluation.cli import load_dataset
from tunnelminion.evaluation.runner import run_dataset

ROOT = Path(__file__).parents[2]


def test_context_runtime_baseline_matches_versioned_offline_evaluation() -> None:
    baseline = cast(
        dict[str, Any],
        json.loads(
            (ROOT / "evaluations/baselines/context-runtime-v1.json").read_text(encoding="utf-8")
        ),
    )
    dataset = load_dataset(ROOT / "evaluations/datasets/mvp-v1.json")
    report = run_dataset(dataset)
    results = {item.scenario_id: item for item in report.scenarios}

    assert baseline["source_dataset_id"] == report.dataset_id
    assert baseline["source_dataset_version"] == report.dataset_version
    assert baseline["prompt_version"] == report.prompt_version
    for expected in baseline["scenarios"]:
        result = results[expected["scenario_id"]]
        assert result.final_answer == expected["answer"]
        assert [item.name for item in result.attempts if item.executed] == expected["tools"]
        assert result.total_latency_ms == expected["latency_ms"]
        assert result.input_tokens == expected["input_tokens"]
        assert result.output_tokens == expected["output_tokens"]
        assert result.total_tokens == expected["total_tokens"]
        assert result.estimated_cost == expected["estimated_cost"]
