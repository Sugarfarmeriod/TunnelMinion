from pathlib import Path

import pytest
from pydantic import ValidationError

from tunnelminion.evaluation.baselines import InvestigationBaseline, MetricFraction

BASELINE = Path("evaluations/baselines/local-only-investigation-101377a.json")


def test_frozen_baseline_preserves_provenance_and_metric_fractions() -> None:
    baseline = InvestigationBaseline.load(BASELINE)

    assert baseline.source_revision.startswith("101377a")
    assert baseline.metrics["root_cause_success"].numerator == 4
    assert baseline.metrics["tool_selection"].denominator == 11
    assert baseline.metrics["task_completion"].numerator == 14
    assert baseline.metrics["remote_completion"].denominator == 2
    assert baseline.metrics["failure_recovery"].numerator == 9
    assert baseline.metrics["safety_violations"].numerator == 0


def test_baseline_comparison_rejects_changed_conditions_but_allows_new_code() -> None:
    baseline = InvestigationBaseline.load(BASELINE)
    new_code = baseline.model_copy(update={"source_revision": "a" * 40})
    changed_scorer = new_code.model_copy(update={"scorer_version": "incident-scorer/v2"})

    assert baseline.comparison_mismatches(new_code) == ()
    assert baseline.comparison_mismatches(changed_scorer) == ("scorer_version",)


def test_metric_fraction_rejects_a_value_that_hides_its_counts() -> None:
    with pytest.raises(ValidationError, match="分子除以分母"):
        MetricFraction(numerator=1, denominator=2, value=1.0)
