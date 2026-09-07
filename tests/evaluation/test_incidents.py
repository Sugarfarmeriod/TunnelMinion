"""自主 incident 固定矩阵、六项指标与本机端到端门禁。"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError
from scripts.run_incident_evaluation import main

from tunnelminion.coordinator.contracts import ServiceAccessibility
from tunnelminion.domain.identifiers import SnapshotId
from tunnelminion.evaluation import incidents as incidents_module
from tunnelminion.evaluation.incidents import (
    IncidentEvaluationDataset,
    run_incident_dataset,
    run_incident_scenario,
)
from tunnelminion.incident.contracts import (
    EvidenceReference,
    HypothesisStatus,
    IncidentEventType,
    IncidentHypothesis,
    IncidentReport,
    IncidentStatus,
    InvestigationStopReason,
)
from tunnelminion.incident.investigation import READ_ONLY_INVESTIGATION_TOOLS
from tunnelminion.incident.storage import SQLiteIncidentStore
from tunnelminion.tools.contracts import ToolCancellationToken

DATASET = Path("evaluations/datasets/autonomous-incidents-v4.json")


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
        "evidence_conflict",
    }
    assert report.scope == "offline-scripted-local-runtime"
    stale = next(item for item in report.scenarios if item.category == "state_stale")
    assert stale.status is IncidentStatus.INSUFFICIENT_EVIDENCE
    assert stale.failure_recovered is True
    assert report.metrics.root_cause_success_rate >= 0.8
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
    remote = next(item for item in report.scenarios if item.category == "remote_unreachable")
    assert remote.status is IncidentStatus.INSUFFICIENT_EVIDENCE
    assert remote.root_cause_success is None
    assert remote.model_calls == 3


def test_dataset_rejects_missing_category_unknown_tool_and_overlap() -> None:
    dataset = load_dataset()
    with pytest.raises(ValidationError, match="缺少必要故障类别"):
        replacement = dataset.scenarios[0].model_copy(update={"scenario_id": "second-normal"})
        IncidentEvaluationDataset.model_validate(
            dataset.model_dump()
            | {
                "scenarios": tuple(
                    replacement if item.category == "budget_exhausted" else item
                    for item in dataset.scenarios
                )
            }
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
    with pytest.raises(ValidationError, match="必须声明反向状态词"):
        unprotected = scenario.model_copy(update={"root_cause_forbidden_terms": ()})
        IncidentEvaluationDataset.model_validate(
            dataset.model_dump()
            | {
                "scenarios": tuple(
                    unprotected if item.scenario_id == scenario.scenario_id else item
                    for item in dataset.scenarios
                )
            }
        )


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
    scenario_without_arguments = scenario.model_copy(update={"tool_arguments": {}})
    loopback = current.model_copy(
        update={
            "services": (
                current.services[0].model_copy(
                    update={"accessibility": ServiceAccessibility.LOOPBACK}
                ),
            )
        }
    )
    fallback = incidents_module._FixtureProvider(  # pyright: ignore[reportPrivateUsage]
        scenario_without_arguments,
        loopback,
    )
    assert fallback._arguments(  # pyright: ignore[reportPrivateUsage]
        "probe_service_reachability"
    ) == {"host": "127.0.0.1", "port": 43123}
    empty = incidents_module._FixtureProvider(  # pyright: ignore[reportPrivateUsage]
        scenario_without_arguments,
        current.model_copy(update={"services": ()}),
    )
    assert empty._arguments(  # pyright: ignore[reportPrivateUsage]
        "probe_service_reachability"
    ) == {"host": "10.77.0.2", "port": 43123}

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


def test_exact_root_cause_match_is_supported_without_term_overrides(tmp_path: Path) -> None:
    scenario = load_dataset().scenarios[1].model_copy(update={"root_cause_terms": ()})

    result = asyncio.run(
        run_incident_scenario(
            scenario,
            SQLiteIncidentStore(tmp_path / "exact-root.sqlite3"),
        )
    )

    assert result.root_cause_success is True


def test_root_cause_terms_only_credit_supported_public_findings() -> None:
    scenario = next(item for item in load_dataset().scenarios if item.category == "local_only")
    report = IncidentReport(
        facts=("私网地址 10.77.0.2 的端口 43123 拒绝连接",),
        candidate_explanations=("服务只监听 127.0.0.1",),
        conclusion="监听配置导致远程不可达",
        stop_reason=InvestigationStopReason.EVIDENCE_SUFFICIENT,
        evidence=(
            EvidenceReference(
                snapshot_id=SnapshotId("snapshot_00000000000000000000000000000001"),
                observed_at=datetime(2026, 9, 7, tzinfo=UTC),
                summary="固定测试证据",
            ),
        ),
    )

    supported = IncidentHypothesis(
        hypothesis_id="hypothesis_0123456789abcdef",
        summary="服务只监听 127.0.0.1",
        status=HypothesisStatus.SUPPORTED,
        evidence=report.evidence,
    )
    candidate = supported.model_copy(update={"status": HypothesisStatus.CANDIDATE})

    assert incidents_module._root_cause_matches(  # pyright: ignore[reportPrivateUsage]
        report, scenario, (supported,)
    )
    assert not incidents_module._root_cause_matches(  # pyright: ignore[reportPrivateUsage]
        report, scenario, (candidate,)
    )


@pytest.mark.parametrize(
    ("scenario_id", "opposite_conclusion"),
    [
        ("service-added-process", "tunnelminion-demo 未监听 43123，进程已崩溃"),
        (
            "service-removed-process",
            "Docker 并非 Exited，tunnelminion-demo 仍在运行并监听 43123",
        ),
        (
            "loopback-listener",
            "服务并非只监听 127.0.0.1，10.77.0.2:43123 可正常访问",
        ),
    ],
)
def test_scored_root_cause_scenarios_reject_opposite_states(
    scenario_id: str,
    opposite_conclusion: str,
) -> None:
    scenario = next(item for item in load_dataset().scenarios if item.scenario_id == scenario_id)
    expected = IncidentReport(
        conclusion=scenario.expected_root_cause,
        stop_reason=InvestigationStopReason.EVIDENCE_SUFFICIENT,
        evidence=(
            EvidenceReference(
                snapshot_id=SnapshotId("snapshot_00000000000000000000000000000001"),
                observed_at=datetime(2026, 9, 7, tzinfo=UTC),
                summary="固定评分证据",
            ),
        ),
    )
    opposite = expected.model_copy(update={"conclusion": opposite_conclusion})
    assert incidents_module._root_cause_matches(  # pyright: ignore[reportPrivateUsage]
        expected, scenario
    )
    assert not incidents_module._root_cause_matches(  # pyright: ignore[reportPrivateUsage]
        opposite, scenario
    )


def test_structured_unavailable_collection_cannot_confirm_root_cause(tmp_path: Path) -> None:
    scenario = next(
        item for item in load_dataset().scenarios if item.category == "docker_unavailable"
    )

    result = asyncio.run(
        run_incident_scenario(
            scenario,
            SQLiteIncidentStore(tmp_path / "docker-unavailable.sqlite3"),
        )
    )

    assert result.status is IncidentStatus.INSUFFICIENT_EVIDENCE
    assert result.conclusion is None
    assert result.tool_runs[0].status.value == "success"
    assert isinstance(result.tool_runs[0].output, dict)
    assert result.tool_runs[0].output["availability"] == "unavailable"
    assert result.failure_recovered is True


def test_non_probe_listener_conflict_cannot_confirm_root_cause(tmp_path: Path) -> None:
    scenario = next(
        item
        for item in load_dataset().scenarios
        if item.scenario_id == "snapshot-listener-conflict"
    )

    result = asyncio.run(
        run_incident_scenario(
            scenario,
            SQLiteIncidentStore(tmp_path / "listener-conflict.sqlite3"),
        )
    )

    assert result.status is IncidentStatus.INSUFFICIENT_EVIDENCE
    assert result.conclusion is None
    assert result.executed_tools == ("get_node_summary", "list_network_listeners")
    assert result.failure_recovered is True
