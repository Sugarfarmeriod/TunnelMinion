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
from tunnelminion.domain.tools import Platform
from tunnelminion.evaluation import incidents as incidents_module
from tunnelminion.evaluation.incidents import (
    IncidentEvaluationDataset,
    run_incident_dataset,
    run_incident_scenario,
)
from tunnelminion.gateway.configuration import GatewayConfiguration
from tunnelminion.gateway.security import GatewayBindConfig
from tunnelminion.incident.contracts import (
    EvidenceReference,
    HypothesisStatus,
    IncidentEventType,
    IncidentHypothesis,
    IncidentReport,
    IncidentStatus,
    InvestigationStopReason,
    SnapshotSource,
)
from tunnelminion.incident.investigation import READ_ONLY_INVESTIGATION_TOOLS
from tunnelminion.incident.storage import SQLiteIncidentStore
from tunnelminion.tools.audit import InMemoryAuditSink
from tunnelminion.tools.contracts import ToolCancellationToken

DATASET = Path("evaluations/datasets/autonomous-incidents-v6.json")


def load_dataset() -> IncidentEvaluationDataset:
    return IncidentEvaluationDataset.model_validate_json(DATASET.read_text(encoding="utf-8"))


def test_fixed_matrix_runs_real_local_runtime_and_passes_six_value_metrics(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def reject_system_secret_read(_service: str, _name: str) -> str | None:
        raise AssertionError("固定评测不得读取系统秘密")

    monkeypatch.setattr("keyring.get_password", reject_system_secret_read)
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
        "remote_local_only",
        "remote_identity",
    }
    assert report.scope == "offline-scripted-cross-node-runtime"
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
    assert report.metrics.remote_scenario_count == 2
    assert report.metrics.remote_completion_rate == 1.0
    assert report.metrics.remote_local_tool_executions == 0
    assert report.metrics.remote_fallback_tool_calls == 0
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

    remote_loopback = next(
        item for item in report.scenarios if item.scenario_id == "remote-macos-loopback-listener"
    )
    assert remote_loopback.execution_scope == "remote"
    assert remote_loopback.request_platform == "windows"
    assert remote_loopback.target_platform == "macos"
    assert remote_loopback.snapshot_source == "coordinator_directory"
    assert remote_loopback.preflight_status == "success"
    assert remote_loopback.selected_tools == ("list_network_listeners",)
    assert remote_loopback.local_tool_attempts == ()
    assert remote_loopback.target_tool_attempts == (
        "get_node_summary",
        "list_network_listeners",
    )
    assert remote_loopback.status is IncidentStatus.CONFIRMED
    assert remote_loopback.evidence_count == 2

    identity = next(
        item for item in report.scenarios if item.scenario_id == "remote-macos-identity-mismatch"
    )
    assert identity.preflight_status == "rejected"
    assert identity.model_calls == 0
    assert identity.local_tool_attempts == ()
    assert identity.target_tool_attempts == ("get_node_summary",)
    assert identity.status is IncidentStatus.INSUFFICIENT_EVIDENCE


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
    assert '"scope": "offline-scripted-cross-node-runtime"' in payload
    assert '"gate_violations": []' in payload


def test_dataset_rejects_incoherent_expectations_and_versions() -> None:
    dataset = load_dataset()
    scenario = dataset.scenarios[1]
    with pytest.raises(ValidationError, match="本机场景必须"):
        scenario.model_validate(scenario.model_dump() | {"target_platform": Platform.MACOS})
    remote = next(item for item in dataset.scenarios if item.execution_scope == "remote")
    with pytest.raises(ValidationError, match="远端场景必须"):
        remote.model_validate(
            remote.model_dump() | {"snapshot_source": SnapshotSource.LOCAL_OBSERVATION}
        )
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
    with pytest.raises(ValidationError, match="Windows 请求 macOS"):
        IncidentEvaluationDataset.model_validate(
            dataset.model_dump()
            | {
                "scenarios": tuple(
                    item.model_copy(update={"request_platform": Platform.MACOS})
                    if item.execution_scope == "remote"
                    else item
                    for item in dataset.scenarios
                )
            }
        )
    with pytest.raises(ValidationError, match="平台身份不得作为根因文本评分词"):
        platform_scored = remote.model_copy(
            update={"root_cause_terms": (*remote.root_cause_terms, remote.target_platform.value)}
        )
        IncidentEvaluationDataset.model_validate(
            dataset.model_dump()
            | {
                "scenarios": tuple(
                    platform_scored if item.scenario_id == remote.scenario_id else item
                    for item in dataset.scenarios
                )
            }
        )


def test_fixture_cancellation_capabilities_and_missing_event_guard(tmp_path: Path) -> None:
    dataset = load_dataset()
    configuration = GatewayConfiguration(bind=GatewayBindConfig(host="10.77.0.2"))
    repository = incidents_module._FixtureGatewayRepository(  # pyright: ignore[reportPrivateUsage]
        configuration
    )
    assert repository.load() is configuration
    repository.save(configuration)
    repository.delete()
    assert repository.load() is None
    secrets = incidents_module._FixtureSecrets({})  # pyright: ignore[reportPrivateUsage]
    assert secrets.get("token") is None
    secrets.set("token", "fixture")
    assert secrets.get("token") == "fixture"
    secrets.delete("token")
    assert secrets.get("token") is None

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


def test_external_remote_preparer_requires_audit_pair_and_reuses_gateway(
    tmp_path: Path,
) -> None:
    scenario = next(
        item
        for item in load_dataset().scenarios
        if item.scenario_id == "remote-macos-loopback-listener"
    )
    with pytest.raises(ValueError, match="必须同时提供"):
        asyncio.run(
            run_incident_scenario(
                scenario,
                SQLiteIncidentStore(tmp_path / "missing-remote-preparer.sqlite3"),
                remote_request_audit=InMemoryAuditSink(),
            )
        )

    prepared, request_audit, _ = incidents_module._remote_preparer(  # pyright: ignore[reportPrivateUsage]
        scenario,
        None,  # type: ignore[arg-type]
    )
    result = asyncio.run(
        run_incident_scenario(
            scenario,
            SQLiteIncidentStore(tmp_path / "external-remote-preparer.sqlite3"),
            remote_preparer=prepared._preparer,  # pyright: ignore[reportPrivateUsage]
            remote_request_audit=request_audit,
        )
    )

    assert result.status is IncidentStatus.CONFIRMED
    assert result.local_tool_attempts == ()
    assert tuple(item.tool_name for item in request_audit.records) == (
        "get_node_summary",
        "list_network_listeners",
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


def test_root_cause_forbidden_terms_do_not_reject_negated_facts() -> None:
    scenario = next(
        item
        for item in load_dataset().scenarios
        if item.scenario_id == "remote-macos-loopback-listener"
    )
    report = IncidentReport(
        facts=("服务未同时监听 0.0.0.0",),
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

    assert incidents_module._root_cause_matches(  # pyright: ignore[reportPrivateUsage]
        report, scenario
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
