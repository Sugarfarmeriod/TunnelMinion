"""自主 incident 固定矩阵、六项指标与本机端到端门禁。"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
from pydantic import ValidationError
from scripts.run_incident_evaluation import main

from tunnelminion.evaluation import incidents as incidents_module
from tunnelminion.evaluation.incidents import (
    IncidentEvaluationDataset,
    run_incident_dataset,
    run_incident_scenario,
)
from tunnelminion.incident.contracts import (
    IncidentEventType,
    IncidentStatus,
    InvestigationStopReason,
)
from tunnelminion.incident.investigation import READ_ONLY_INVESTIGATION_TOOLS
from tunnelminion.incident.storage import SQLiteIncidentStore
from tunnelminion.tools.contracts import ToolCancellationToken

DATASET = Path("evaluations/datasets/autonomous-incidents-v2.json")


def load_dataset() -> IncidentEvaluationDataset:
    return IncidentEvaluationDataset.model_validate_json(DATASET.read_text(encoding="utf-8"))


def test_fixed_matrix_runs_real_local_runtime_and_passes_six_value_metrics(
    tmp_path: Path,
) -> None:
    dataset = load_dataset()
    report = asyncio.run(
        run_incident_dataset(dataset, SQLiteIncidentStore(tmp_path / "incidents.sqlite3"))
    )

    assert {item.category for item in report.scenarios} == {
        "normal",
        "service_added",
        "service_removed",
        "node_offline",
        "state_stale",
        "local_only",
        "remote_unreachable",
        "docker_unavailable",
        "tool_failure",
        "model_failure",
        "budget_exhausted",
    }
    assert report.scope == "offline-scripted-local-runtime"
    stale = next(item for item in report.scenarios if item.category == "state_stale")
    assert stale.status is IncidentStatus.INSUFFICIENT_EVIDENCE
    assert stale.failure_recovered is True
    assert report.metrics.root_cause_success_rate == 1.0
    assert report.metrics.tool_selection_rate == 1.0
    assert report.metrics.unnecessary_tool_call_rate == 0.0
    assert report.metrics.unsupported_assertion_rate == 0.0
    assert report.metrics.failure_recovery_rate == 1.0
    assert report.metrics.average_latency_ms >= 0
    assert report.metrics.maximum_latency_ms >= report.metrics.average_latency_ms
    assert report.metrics.normal_incident_count == 0
    assert report.metrics.normal_model_calls == 0
    assert report.metrics.forbidden_tool_executions == 0
    assert report.gate_violations == ()
    assert {tool for item in report.scenarios for tool in item.executed_tools}.issubset(
        READ_ONLY_INVESTIGATION_TOOLS
    )
    assert all(
        item.failure_recovered is True
        for item in report.scenarios
        if item.failure_class is not None
    )


def test_dataset_rejects_missing_category_unknown_tool_and_overlap() -> None:
    dataset = load_dataset()
    with pytest.raises(ValidationError, match="缺少必要故障类别"):
        replacement = dataset.scenarios[0].model_copy(update={"scenario_id": "second-normal"})
        IncidentEvaluationDataset.model_validate(
            dataset.model_dump() | {"scenarios": (*dataset.scenarios[:-1], replacement)}
        )
    scenario = dataset.scenarios[1]
    with pytest.raises(ValidationError, match="六个只读工具"):
        scenario.model_validate(scenario.model_dump() | {"tool_sequence": ["shell"]})
    with pytest.raises(ValidationError, match="不得重叠"):
        scenario.model_validate(
            scenario.model_dump() | {"forbidden_tools": list(scenario.required_tools)}
        )


def test_cli_writes_versioned_report_and_enforces_gate(tmp_path: Path) -> None:
    output = tmp_path / "report.json"

    assert main([str(DATASET), "--output", str(output), "--check"]) == 0
    payload = output.read_text(encoding="utf-8")
    assert '"scope": "offline-scripted-local-runtime"' in payload
    assert '"gate_violations": []' in payload


def test_dataset_rejects_incoherent_expectations_and_versions() -> None:
    dataset = load_dataset()
    scenario = dataset.scenarios[1]
    missing_tool = next(
        name for name in READ_ONLY_INVESTIGATION_TOOLS if name not in scenario.tool_sequence
    )
    with pytest.raises(ValidationError, match="必须出现在脚本序列"):
        scenario.model_validate(scenario.model_dump() | {"required_tools": [missing_tool]})
    with pytest.raises(ValidationError, match="无事件场景"):
        dataset.scenarios[0].model_validate(
            dataset.scenarios[0].model_dump() | {"outcome": "confirmed"}
        )
    with pytest.raises(ValidationError, match="必须声明终态"):
        scenario.model_validate(scenario.model_dump() | {"expected_status": None})
    with pytest.raises(ValidationError, match="场景 ID 必须唯一"):
        duplicate = dataset.scenarios[0].model_copy(
            update={"scenario_id": dataset.scenarios[1].scenario_id}
        )
        IncidentEvaluationDataset.model_validate(
            dataset.model_dump() | {"scenarios": (duplicate, *dataset.scenarios[1:])}
        )
    with pytest.raises(ValidationError, match="全部六个"):
        versions = dict(dataset.tool_versions)
        versions.pop(next(iter(versions)))
        versions["future_tool"] = "v1"
        IncidentEvaluationDataset.model_validate(dataset.model_dump() | {"tool_versions": versions})


def test_fixture_cancellation_capabilities_and_missing_event_guard(tmp_path: Path) -> None:
    dataset = load_dataset()
    token = ToolCancellationToken()
    token.cancel()
    adapter = incidents_module._FixtureAdapter(  # pyright: ignore[reportPrivateUsage]
        "get_node_summary", fail=False
    )
    with pytest.raises(RuntimeError, match="cancelled"):
        asyncio.run(adapter.execute({}, token))

    scenario = dataset.scenarios[1]
    current = incidents_module._snapshot(  # pyright: ignore[reportPrivateUsage]
        scenario.current, revision=2
    )
    provider = incidents_module._FixtureProvider(  # pyright: ignore[reportPrivateUsage]
        scenario, current
    )
    assert provider.capabilities.tool_calls is True

    impossible = dataset.scenarios[0].model_copy(
        update={
            "expected_event": IncidentEventType.SERVICE_ADDED,
            "expected_status": IncidentStatus.CONFIRMED,
            "expected_stop_reason": InvestigationStopReason.EVIDENCE_SUFFICIENT,
            "outcome": "confirmed",
        }
    )
    with pytest.raises(ValueError, match="未产生期望事件"):
        asyncio.run(
            run_incident_scenario(
                impossible,
                SQLiteIncidentStore(tmp_path / "missing-event.sqlite3"),
            )
        )
