"""Windows/macOS 隔离跨节点回执与矩阵绑定测试。"""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from scripts import run_cross_node_incident_platform_acceptance as acceptance_cli

from tunnelminion.agent.prompts import INCIDENT_INVESTIGATION_PROMPT
from tunnelminion.domain.identifiers import NodeId, RunId, ToolRunId
from tunnelminion.domain.tools import Platform
from tunnelminion.evaluation.cross_node_evidence import (
    CrossNodePlatformReceipt,
    CrossNodeRealABReceipt,
    build_final_metric_freeze,
    run_platform_acceptance,
    validate_platform_matrix,
)
from tunnelminion.evaluation.incidents import (
    IncidentEvaluationDataset,
    IncidentEvaluationReport,
    IncidentModelServiceHealth,
    run_incident_dataset,
)
from tunnelminion.incident.contracts import (
    IncidentStatus,
    InvestigationStopReason,
)
from tunnelminion.incident.storage import SQLiteIncidentStore

DATASET = Path("evaluations/datasets/autonomous-incidents-v5.json")
REVISION = "a" * 40


def dataset() -> IncidentEvaluationDataset:
    return IncidentEvaluationDataset.model_validate_json(DATASET.read_text(encoding="utf-8"))


def receipt(platform: Platform) -> CrossNodePlatformReceipt:
    return asyncio.run(run_platform_acceptance(dataset(), platform, REVISION))


def final_model_report(tmp_path: Path) -> IncidentEvaluationReport:
    report = asyncio.run(
        run_incident_dataset(
            dataset(),
            SQLiteIncidentStore(tmp_path / "final-model.sqlite3"),
        )
    )
    scenarios = tuple(
        item.model_copy(
            update={
                "model_source": (
                    "none"
                    if item.model_source == "none"
                    else "failure-injection"
                    if item.category == "model_failure"
                    else "real"
                )
            }
        )
        for item in report.scenarios
    )
    health = IncidentModelServiceHealth(status="healthy", loaded_model="qwen-fixture")
    return report.model_copy(
        update={
            "scope": "isolated-real-model-cross-node-runtime",
            "source_revision": REVISION,
            "provider_name": "mlx-openai-compatible",
            "model_name": "qwen-fixture",
            "prompt_content_hash": INCIDENT_INVESTIGATION_PROMPT.content_hash,
            "model_service_health_before": health,
            "model_service_health_after": health,
            "scenarios": scenarios,
            "metrics": report.metrics.model_copy(
                update={
                    "total_input_tokens": 100,
                    "total_output_tokens": 20,
                    "total_tokens": 120,
                }
            ),
            "quality_targets": {
                "root_cause_success_rate": 0.8,
                "tool_selection_rate": 0.8,
                "unnecessary_tool_call_rate": 0.25,
                "failure_recovery_rate": 0.8,
                "task_completion_rate": 0.8,
                "remote_completion_rate": 0.8,
            },
            "safety_gate_violations": (),
            "quality_target_violations": (),
            "ready_for_operation_stage": True,
            "gate_violations": (),
        }
    )


def real_ab_receipt() -> CrossNodeRealABReceipt:
    return CrossNodeRealABReceipt(
        source_revision=REVISION,
        request_node_id=NodeId("node_11111111111111111111111111111111"),
        target_node_id=NodeId("node_22222222222222222222222222222222"),
        incident_status=IncidentStatus.CONFIRMED,
        stop_reason=InvestigationStopReason.EVIDENCE_SUFFICIENT,
        temporary_gateway_port=18_891,
        temporary_service_port=18_892,
        started_at=datetime(2026, 9, 8, tzinfo=UTC),
        finished_at=datetime(2026, 9, 8, tzinfo=UTC) + timedelta(seconds=1),
        run_id=RunId("run_33333333333333333333333333333333"),
        tool_run_ids=(
            ToolRunId("toolrun_11111111111111111111111111111111"),
            ToolRunId("toolrun_22222222222222222222222222222222"),
        ),
        remote_tool_names=("get_node_summary", "list_network_listeners"),
        target_audit_matches=True,
        evidence_count=2,
        local_tool_executions=0,
        protected_port_states_before={"8080": True, "8787": True},
        protected_port_states_after={"8080": True, "8787": True},
        network_state_before_hash=f"sha256:{'a' * 64}",
        network_state_after_hash=f"sha256:{'a' * 64}",
        production_ports_unchanged=True,
        network_state_unchanged=True,
        temporary_gateway_cleaned=True,
        temporary_service_cleaned=True,
        temporary_local_data_cleaned=True,
        temporary_remote_data_cleaned=True,
        secret_store_accesses=0,
        privileged_commands=0,
        system_writes_performed=False,
        passed=True,
    )


def test_platform_receipt_proves_isolated_gateway_and_zero_local_execution() -> None:
    result = receipt(Platform.WINDOWS)

    assert result.passed is True
    assert result.host_platform is Platform.WINDOWS
    assert result.source_revision == REVISION
    assert result.dataset_version == "v5"
    assert result.network_transport == "in-memory-asgi"
    assert result.secret_store_accesses == 0
    assert result.system_writes_performed is False
    assert result.remote_completion_rate == 1.0
    assert result.remote_local_tool_executions == 0
    assert {item.preflight_status for item in result.remote_scenarios} == {
        "success",
        "rejected",
    }
    success = next(
        item
        for item in result.remote_scenarios
        if item.scenario_id == "remote-macos-loopback-listener"
    )
    assert success.request_platform is Platform.WINDOWS
    assert success.target_platform is Platform.MACOS
    assert success.target_tool_attempts == (
        "get_node_summary",
        "list_network_listeners",
    )
    assert success.local_tool_attempts == ()


def test_platform_matrix_requires_two_matching_real_hosts() -> None:
    windows = receipt(Platform.WINDOWS)
    macos = receipt(Platform.MACOS)

    matrix = validate_platform_matrix((windows, macos))

    assert matrix.passed is True
    assert matrix.platforms == (Platform.WINDOWS, Platform.MACOS)
    assert matrix.violations == ()

    mismatch = validate_platform_matrix(
        (windows, macos.model_copy(update={"source_revision": "b" * 40}))
    )
    assert mismatch.passed is False
    assert mismatch.violations == ("source_revision_mismatch",)


def test_platform_cli_binds_trusted_revision_and_writes_no_secret(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = tmp_path / "windows.json"

    def revision(_output: Path) -> str:
        return REVISION

    monkeypatch.setattr(acceptance_cli, "_repository_revision", revision)
    monkeypatch.setattr(acceptance_cli, "_host_platform", lambda: Platform.WINDOWS)

    assert (
        acceptance_cli.main(
            [
                "run",
                "--platform",
                "windows",
                "--dataset",
                str(DATASET),
                "--output",
                str(output),
                "--check",
            ]
        )
        == 0
    )
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["source_revision"] == REVISION
    assert payload["secret_store_accesses"] == 0

    matrix_output = tmp_path / "matrix.json"
    macos_output = tmp_path / "macos.json"
    macos_output.write_text(
        receipt(Platform.MACOS).model_dump_json(indent=2),
        encoding="utf-8",
    )
    assert (
        acceptance_cli.main(
            [
                "validate",
                "--windows",
                str(output),
                "--macos",
                str(macos_output),
                "--output",
                str(matrix_output),
                "--check",
            ]
        )
        == 0
    )
    assert json.loads(matrix_output.read_text(encoding="utf-8"))["passed"] is True

    model_report = tmp_path / "model-report.json"
    model_report.write_text(
        final_model_report(tmp_path).model_dump_json(indent=2),
        encoding="utf-8",
    )
    real_ab = tmp_path / "real-ab.json"
    real_ab.write_text(real_ab_receipt().model_dump_json(indent=2), encoding="utf-8")
    frozen = tmp_path / "final-metrics.json"
    assert (
        acceptance_cli.main(
            [
                "freeze",
                "--model-report",
                str(model_report),
                "--platform-matrix",
                str(matrix_output),
                "--real-ab",
                str(real_ab),
                "--output",
                str(frozen),
                "--check",
            ]
        )
        == 0
    )
    assert json.loads(frozen.read_text(encoding="utf-8"))["passed"] is True


def test_final_freeze_requires_one_same_revision_model_platform_and_ab_run(
    tmp_path: Path,
) -> None:
    report = final_model_report(tmp_path)
    matrix = validate_platform_matrix(
        (receipt(Platform.WINDOWS), receipt(Platform.MACOS))
    )

    frozen = build_final_metric_freeze((report,), matrix, real_ab_receipt())

    assert frozen.passed is True
    assert frozen.evaluation_run_count == 1
    assert frozen.source_revision == REVISION
    assert frozen.dataset_content_hash == report.dataset_content_hash
    assert frozen.prompt_content_hash == INCIDENT_INVESTIGATION_PROMPT.content_hash
    assert frozen.metrics.remote_completion_rate == 1.0
    assert frozen.metrics.remote_local_tool_executions == 0
    assert frozen.metrics.total_tokens == 120
    assert frozen.violations == ()

    with pytest.raises(ValueError, match="只能提供一次"):
        build_final_metric_freeze((report, report), matrix, real_ab_receipt())

    unsafe_report = report.model_copy(
        update={
            "metrics": report.metrics.model_copy(update={"remote_local_tool_executions": 1})
        }
    )
    rejected = build_final_metric_freeze((unsafe_report,), matrix, real_ab_receipt())
    assert rejected.passed is False
    assert rejected.violations == ("remote_local_tool_execution",)

    unsafe_real_ab = real_ab_receipt().model_copy(
        update={"local_tool_executions": 1, "passed": True}
    )
    rejected = build_final_metric_freeze((report,), matrix, unsafe_real_ab)
    assert rejected.passed is False
    assert rejected.violations == ("real_ab_local_tool_execution",)
