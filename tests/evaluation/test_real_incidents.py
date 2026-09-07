"""真实模型 incident 评测不得把脚本答案冒充模型能力。"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import cast

import httpx
import pytest
from pydantic import JsonValue
from scripts import run_real_incident_evaluation as real_cli

from tunnelminion.evaluation.incidents import (
    IncidentEvaluationDataset,
    IncidentEvaluationScenario,
    run_incident_dataset,
    run_incident_scenario,
)
from tunnelminion.incident.storage import SQLiteIncidentStore
from tunnelminion.model.contracts import (
    CancellationToken,
    ModelCapabilities,
    ModelRequest,
    ModelResponse,
    ModelUsage,
    ToolCall,
)
from tunnelminion.model.openai_compatible import OpenAICompatibleConfig

V2_DATASET = Path("evaluations/datasets/autonomous-incidents-v2.json")
V3_DATASET = Path("evaluations/datasets/autonomous-incidents-v3.json")
V4_DATASET = Path("evaluations/datasets/autonomous-incidents-v4.json")
REVISION = "a" * 40


class _CapturingProvider:
    def __init__(self, first_call: ToolCall | None, *, with_usage: bool = True) -> None:
        self.first_call = first_call
        self.with_usage = with_usage
        self.requests: list[ModelRequest] = []

    @property
    def capabilities(self) -> ModelCapabilities:
        return ModelCapabilities(tool_calls=True, structured_output=True)

    async def complete(
        self,
        request: ModelRequest,
        cancellation: CancellationToken | None = None,
    ) -> ModelResponse:
        del cancellation
        self.requests.append(request)
        if len(self.requests) == 1 and self.first_call is not None:
            return ModelResponse(
                tool_calls=(self.first_call,),
                usage=(
                    ModelUsage(input_tokens=10, output_tokens=2, total_tokens=12)
                    if self.with_usage
                    else ModelUsage()
                ),
            )
        refs = [
            str(json.loads(message.content)["result"]["tool_run_id"])
            for message in request.messages
            if message.role == "tool"
        ]
        return ModelResponse(
            structured_output=cast(
                JsonValue,
                {
                    "hypotheses": [
                        {
                            "summary": "当前证据不足",
                            "status": "unknown",
                            "evidence_refs": refs,
                        }
                    ],
                    "facts": [],
                    "unknowns": ["无法确认根因"],
                    "conclusion": None,
                    "stop_reason": "insufficient_evidence",
                },
            ),
            usage=(
                ModelUsage(input_tokens=20, output_tokens=5, total_tokens=25)
                if self.with_usage
                else ModelUsage()
            ),
        )


class _UnsupportedProvider:
    @property
    def capabilities(self) -> ModelCapabilities:
        return ModelCapabilities(tool_calls=True, structured_output=True)

    async def complete(
        self,
        request: ModelRequest,
        cancellation: CancellationToken | None = None,
    ) -> ModelResponse:
        del request, cancellation
        return ModelResponse(
            structured_output=cast(
                JsonValue,
                {
                    "hypotheses": [
                        {
                            "summary": "没有证据的猜测",
                            "status": "supported",
                            "evidence_refs": [],
                        }
                    ],
                    "facts": [],
                    "unknowns": [],
                    "conclusion": "没有证据的猜测",
                    "stop_reason": "evidence_sufficient",
                },
            )
        )


class _TextReportProvider:
    @property
    def capabilities(self) -> ModelCapabilities:
        return ModelCapabilities(tool_calls=True, structured_output=True)

    async def complete(
        self,
        request: ModelRequest,
        cancellation: CancellationToken | None = None,
    ) -> ModelResponse:
        del request, cancellation
        return ModelResponse(
            content=json.dumps(
                {
                    "hypotheses": [],
                    "facts": [],
                    "unknowns": ["证据不足"],
                    "conclusion": None,
                    "stop_reason": "insufficient_evidence",
                },
                ensure_ascii=False,
            )
        )


class _ConflictProvider:
    def __init__(self, *, confirm: bool = False, probe_port: int = 43123) -> None:
        self.confirm = confirm
        self.probe_port = probe_port
        self.requests: list[ModelRequest] = []

    @property
    def capabilities(self) -> ModelCapabilities:
        return ModelCapabilities(tool_calls=True, structured_output=True)

    async def complete(
        self,
        request: ModelRequest,
        cancellation: CancellationToken | None = None,
    ) -> ModelResponse:
        del cancellation
        self.requests.append(request)
        tool_messages = [message for message in request.messages if message.role == "tool"]
        refs = [
            str(json.loads(message.content)["result"]["tool_run_id"]) for message in tool_messages
        ]
        if not tool_messages:
            return ModelResponse(
                tool_calls=(
                    ToolCall(
                        call_id="discover-probe-host",
                        name="get_node_summary",
                        arguments={},
                    ),
                )
            )
        if len(tool_messages) == 1:
            return ModelResponse(
                tool_calls=(
                    ToolCall(
                        call_id="run-conflict-probe",
                        name="probe_service_reachability",
                        arguments={"host": "10.77.0.2", "port": self.probe_port},
                    ),
                )
            )
        if self.confirm:
            return ModelResponse(
                structured_output=cast(
                    JsonValue,
                    {
                        "hypotheses": [
                            {
                                "summary": "服务当前可达",
                                "status": "supported",
                                "evidence_refs": refs,
                            }
                        ],
                        "facts": [{"statement": "探测成功", "evidence_refs": refs}],
                        "unknowns": [],
                        "conclusion": "服务当前可达",
                        "stop_reason": "evidence_sufficient",
                    },
                )
            )
        return ModelResponse(
            structured_output=cast(
                JsonValue,
                {
                    "hypotheses": [],
                    "facts": [],
                    "unknowns": ["证据不足"],
                    "conclusion": None,
                    "stop_reason": "insufficient_evidence",
                },
            )
        )


def _scenario(scenario_id: str) -> IncidentEvaluationScenario:
    dataset = IncidentEvaluationDataset.model_validate_json(V4_DATASET.read_text(encoding="utf-8"))
    return next(item for item in dataset.scenarios if item.scenario_id == scenario_id)


def _v3_dataset() -> IncidentEvaluationDataset:
    return IncidentEvaluationDataset.model_validate_json(V3_DATASET.read_text(encoding="utf-8"))


def _v4_dataset() -> IncidentEvaluationDataset:
    return IncidentEvaluationDataset.model_validate_json(V4_DATASET.read_text(encoding="utf-8"))


def _serialized_requests(provider: _CapturingProvider) -> str:
    return json.dumps(
        [request.model_dump(mode="json") for request in provider.requests],
        ensure_ascii=False,
    )


def test_real_mode_rejects_tool_outside_current_information_gap_without_leaking_answers(
    tmp_path: Path,
) -> None:
    provider = _CapturingProvider(
        ToolCall(call_id="unexpected", name="get_wireguard_status", arguments={})
    )
    result = asyncio.run(
        run_incident_scenario(
            next(
                item for item in _v4_dataset().scenarios if item.scenario_id == "loopback-listener"
            ),
            SQLiteIncidentStore(tmp_path / "unexpected.sqlite3"),
            provider=provider,
            provider_name="test-provider",
            model_name="test-model",
        )
    )

    assert result.selected_tools == ("get_wireguard_status",)
    assert result.executed_tools == ()
    assert result.fallback_tools == ()
    assert result.tool_selection_success is False
    assert result.unnecessary_tool_calls == 1
    assert result.task_completed is False
    assert result.model_input_tokens == 10
    assert result.model_output_tokens == 2
    assert result.model_total_tokens == 12
    captured = _serialized_requests(provider)
    assert "tool_sequence" not in captured
    assert "required_tools" not in captured
    assert "expected_root_cause" not in captured
    assert "root_cause_terms" not in captured
    assert "root_cause_forbidden_terms" not in captured
    assert "tool_arguments" not in captured
    assert "expected_stop_reason" not in captured
    assert "loopback-listener" not in captured
    assert any(
        '"affected_object":{"snapshot_id"' in message.content and '"port":43123' in message.content
        for message in provider.requests[0].messages
    )


def test_real_mode_does_not_credit_runtime_fallback_as_model_selection(tmp_path: Path) -> None:
    provider = _CapturingProvider(None)
    result = asyncio.run(
        run_incident_scenario(
            _scenario("service-added-process"),
            SQLiteIncidentStore(tmp_path / "fallback.sqlite3"),
            provider=provider,
            provider_name="test-provider",
            model_name="test-model",
        )
    )

    assert result.selected_tools == ()
    assert result.executed_tools == ("list_network_listeners", "get_process_summary")
    assert result.fallback_tools == ("list_network_listeners", "get_process_summary")
    assert result.tool_selection_success is False


def test_repeated_no_tool_responses_use_bounded_fallback_with_discovered_probe_target(
    tmp_path: Path,
) -> None:
    provider = _CapturingProvider(None)
    scenario = next(
        item for item in _v4_dataset().scenarios if item.scenario_id == "loopback-listener"
    )

    result = asyncio.run(
        run_incident_scenario(
            scenario,
            SQLiteIncidentStore(tmp_path / "probe-fallback.sqlite3"),
            provider=provider,
            provider_name="test-provider",
            model_name="test-model",
        )
    )

    assert result.selected_tools == ()
    assert result.runtime_tool_attempts == (
        "get_node_summary",
        "list_network_listeners",
        "probe_service_reachability",
    )
    assert result.fallback_tools == result.runtime_tool_attempts
    assert result.executed_tools == result.runtime_tool_attempts
    assert result.tool_runs[-1].arguments == {"host": "10.77.0.2", "port": 43123}


def test_real_mode_rejects_schema_valid_but_wrong_fixture_target(tmp_path: Path) -> None:
    provider = _ConflictProvider(probe_port=1)
    result = asyncio.run(
        run_incident_scenario(
            next(
                item for item in _v4_dataset().scenarios if item.scenario_id == "loopback-listener"
            ),
            SQLiteIncidentStore(tmp_path / "invalid.sqlite3"),
            provider=provider,
            provider_name="test-provider",
            model_name="test-model",
        )
    )

    assert result.invalid_tool_arguments == 1
    assert result.runtime_tool_attempts == (
        "get_node_summary",
        "probe_service_reachability",
    )
    assert result.executed_tools == ("get_node_summary",)
    assert result.tool_runs[1].error_code == "invalid_argument"
    assert result.evidence_count == 1
    assert result.tool_selection_success is False
    assert result.task_completed is False


def test_real_mode_blocks_unadvertised_tool_request(tmp_path: Path) -> None:
    provider = _CapturingProvider(ToolCall(call_id="shell", name="shell", arguments={}))
    result = asyncio.run(
        run_incident_scenario(
            _scenario("loopback-listener"),
            SQLiteIncidentStore(tmp_path / "forbidden.sqlite3"),
            provider=provider,
            provider_name="test-provider",
            model_name="test-model",
        )
    )

    assert result.forbidden_tool_requests == 1
    assert result.executed_tools == ()
    assert result.status == "failed"


def test_real_mode_records_plain_text_report_without_persisting_body(tmp_path: Path) -> None:
    result = asyncio.run(
        run_incident_scenario(
            _scenario("loopback-listener"),
            SQLiteIncidentStore(tmp_path / "text-report.sqlite3"),
            provider=_TextReportProvider(),
            provider_name="test-provider",
            model_name="test-model",
        )
    )

    assert result.model_rounds[0].response_kind == "text_report"
    assert result.conclusion is None


def test_v3_scripted_matrix_keeps_fast_regression_and_adds_conflict(tmp_path: Path) -> None:
    report = asyncio.run(
        run_incident_dataset(_v3_dataset(), SQLiteIncidentStore(tmp_path / "scripted-v3.sqlite3"))
    )

    assert report.gate_violations == ()
    assert report.metrics.scenario_count == 12
    assert {item.category for item in report.scenarios} >= {"normal", "evidence_conflict"}
    normal = next(item for item in report.scenarios if item.category == "normal")
    conflict = next(item for item in report.scenarios if item.category == "evidence_conflict")
    assert (normal.incident_count, normal.model_calls) == (0, 0)
    assert conflict.status == "insufficient_evidence"
    assert conflict.conclusion is None


def test_real_dataset_preserves_honest_quality_failure_and_safety_pass(tmp_path: Path) -> None:
    provider = _CapturingProvider(None)
    report = asyncio.run(
        run_incident_dataset(
            _v4_dataset(),
            SQLiteIncidentStore(tmp_path / "real-v3.sqlite3"),
            provider=provider,
            provider_name="test-provider",
            model_name="test-model",
            source_revision=REVISION,
        )
    )

    assert report.scope == "isolated-real-model-local-runtime"
    assert report.source_revision == REVISION
    assert report.dataset_content_hash == (
        "sha256:6d909c470328b2b5ea00fa8211ad304d3793c2a91b97a50d4064976d52bb9aa0"
    )
    assert report.safety_gate_violations == ()
    assert report.quality_target_violations
    assert report.ready_for_operation_stage is False
    assert report.metrics.normal_incident_count == 0
    assert report.metrics.normal_model_calls == 0
    assert report.metrics.total_tokens is not None
    assert any(item.model_source == "failure-injection" for item in report.scenarios)
    assert all(item.model_source != "scripted" for item in report.scenarios)


def test_real_dataset_highlights_unsupported_confirmation_attempt(tmp_path: Path) -> None:
    report = asyncio.run(
        run_incident_dataset(
            _v4_dataset(),
            SQLiteIncidentStore(tmp_path / "unsupported.sqlite3"),
            provider=_UnsupportedProvider(),
            provider_name="test-provider",
            model_name="test-model",
            source_revision=REVISION,
        )
    )

    assert report.metrics.unsupported_assertion_rate > 0
    assert "unsupported_assertion_rate" in report.safety_gate_violations
    assert all(item.status != "confirmed" for item in report.scenarios)


def test_conflicting_evidence_stays_unknown_and_missing_usage_stays_unknown(
    tmp_path: Path,
) -> None:
    scenario = next(
        item for item in _v4_dataset().scenarios if item.category == "evidence_conflict"
    )
    provider = _ConflictProvider()
    result = asyncio.run(
        run_incident_scenario(
            scenario,
            SQLiteIncidentStore(tmp_path / "conflict.sqlite3"),
            provider=provider,
            provider_name="test-provider",
            model_name="test-model",
        )
    )

    assert result.status == "insufficient_evidence"
    assert result.conclusion is None
    assert result.failure_recovered is True
    assert result.tool_selection_success is True
    assert result.task_completed is True
    assert result.model_total_tokens is None
    assert result.evidence_count == 0
    assert any(
        "10.77.0.2" in message.content
        for message in provider.requests[1].messages
        if message.role == "tool"
    )
    assert result.tool_runs[1].arguments == {"host": "10.77.0.2", "port": 43123}
    assert isinstance(result.tool_runs[1].output, dict)
    assert result.tool_runs[1].output["reachable"] is True


def test_conflict_wrong_target_cannot_pass_success_metrics(tmp_path: Path) -> None:
    scenario = next(
        item for item in _v4_dataset().scenarios if item.category == "evidence_conflict"
    )
    result = asyncio.run(
        run_incident_scenario(
            scenario,
            SQLiteIncidentStore(tmp_path / "wrong-conflict-target.sqlite3"),
            provider=_ConflictProvider(probe_port=1),
            provider_name="test-provider",
            model_name="test-model",
        )
    )

    assert result.status == "insufficient_evidence"
    assert result.invalid_tool_arguments == 1
    assert result.tool_selection_success is False
    assert result.failure_recovered is False
    assert result.task_completed is False


def test_conflict_confirmation_is_a_hard_readiness_failure(tmp_path: Path) -> None:
    dataset = _v4_dataset()
    conflict = next(
        item for item in dataset.scenarios if item.scenario_id == "snapshot-probe-conflict"
    )
    others = tuple(item for item in dataset.scenarios if item.scenario_id != conflict.scenario_id)
    reordered = IncidentEvaluationDataset.model_validate(
        dataset.model_dump() | {"scenarios": (others[0], conflict, *others[1:])}
    )
    report = asyncio.run(
        run_incident_dataset(
            reordered,
            SQLiteIncidentStore(tmp_path / "confirmed-conflict.sqlite3"),
            provider=_ConflictProvider(confirm=True),
            provider_name="test-provider",
            model_name="test-model",
            source_revision=REVISION,
        )
    )

    assert report.metrics.conflict_confirmations == 0
    assert report.metrics.unsupported_assertion_rate > 0
    assert "unsupported_assertion_rate" in report.safety_gate_violations
    assert report.ready_for_operation_stage is False


def test_real_dataset_requires_v3_and_version_metadata(tmp_path: Path) -> None:
    provider = _CapturingProvider(None)
    with pytest.raises(ValueError, match="Provider、模型和代码提交"):
        asyncio.run(
            run_incident_dataset(
                _v4_dataset(),
                SQLiteIncidentStore(tmp_path / "missing-meta.sqlite3"),
                provider=provider,
            )
        )
    with pytest.raises(ValueError, match="完整的小写 Git 提交"):
        asyncio.run(
            run_incident_dataset(
                _v4_dataset(),
                SQLiteIncidentStore(tmp_path / "short-revision.sqlite3"),
                provider=provider,
                provider_name="test-provider",
                model_name="test-model",
                source_revision="abc1234",
            )
        )
    v2 = IncidentEvaluationDataset.model_validate_json(V2_DATASET.read_text(encoding="utf-8"))
    with pytest.raises(ValueError, match="v3"):
        asyncio.run(
            run_incident_dataset(
                v2,
                SQLiteIncidentStore(tmp_path / "v2-real.sqlite3"),
                provider=provider,
                provider_name="test-provider",
                model_name="test-model",
                source_revision=REVISION,
            )
        )

    dataset = _v4_dataset()
    with pytest.raises(ValueError, match="Prompt 版本"):
        asyncio.run(
            run_incident_dataset(
                dataset.model_copy(update={"prompt_version": "incident-investigation-v99"}),
                SQLiteIncidentStore(tmp_path / "wrong-prompt.sqlite3"),
                provider=provider,
                provider_name="test-provider",
                model_name="test-model",
                source_revision=REVISION,
            )
        )
    wrong_versions = dict(dataset.tool_versions)
    wrong_versions["get_node_summary"] = "9.9"
    with pytest.raises(ValueError, match="工具版本"):
        asyncio.run(
            run_incident_dataset(
                dataset.model_copy(update={"tool_versions": wrong_versions}),
                SQLiteIncidentStore(tmp_path / "wrong-tools.sqlite3"),
                provider=provider,
                provider_name="test-provider",
                model_name="test-model",
                source_revision=REVISION,
            )
        )


def test_v3_contract_rejects_leaky_or_incomplete_fixture_fields() -> None:
    dataset = _v4_dataset()
    scenario = dataset.scenarios[1]
    with pytest.raises(ValueError, match="工具夹具只能包含"):
        IncidentEvaluationScenario.model_validate(
            scenario.model_dump() | {"tool_results": {"shell": {"result": "wrong"}}}
        )
    with pytest.raises(ValueError, match="工具参数夹具只能包含"):
        IncidentEvaluationScenario.model_validate(
            scenario.model_dump() | {"tool_arguments": {"shell": {}}}
        )
    with pytest.raises(ValueError, match="不得超过 16KB"):
        IncidentEvaluationScenario.model_validate(
            scenario.model_dump()
            | {"tool_results": {"list_network_listeners": {"value": "x" * 16_001}}}
        )
    with pytest.raises(ValueError, match="根因评分词必须关联"):
        IncidentEvaluationScenario.model_validate(
            scenario.model_dump() | {"expected_root_cause": None}
        )

    without_conflicts = tuple(
        item.model_copy(update={"category": "tool_failure"})
        if item.category == "evidence_conflict"
        else item
        for item in dataset.scenarios
    )
    with pytest.raises(ValueError, match="必须包含证据冲突"):
        IncidentEvaluationDataset.model_validate(
            dataset.model_dump() | {"scenarios": without_conflicts}
        )

    missing_result = scenario.model_copy(update={"tool_results": {}})
    with pytest.raises(ValueError, match="必须提供结果或确定性失败"):
        IncidentEvaluationDataset.model_validate(
            dataset.model_dump()
            | {"scenarios": (dataset.scenarios[0], missing_result, *dataset.scenarios[2:])}
        )
    probe = next(item for item in dataset.scenarios if item.category == "local_only")
    missing_arguments = probe.model_copy(update={"tool_arguments": {}})
    with pytest.raises(ValueError, match="必须绑定目标参数"):
        IncidentEvaluationDataset.model_validate(
            dataset.model_dump()
            | {
                "scenarios": tuple(
                    missing_arguments if item.scenario_id == probe.scenario_id else item
                    for item in dataset.scenarios
                )
            }
        )
    hidden_probe_host = probe.model_copy(
        update={"required_tools": probe.required_tools - {"get_node_summary"}}
    )
    with pytest.raises(ValueError, match="必须让模型先发现探测地址"):
        IncidentEvaluationDataset.model_validate(
            dataset.model_dump()
            | {
                "scenarios": tuple(
                    hidden_probe_host if item.scenario_id == probe.scenario_id else item
                    for item in dataset.scenarios
                )
            }
        )
    incomplete_summary = dict(probe.tool_results["get_node_summary"])
    incomplete_summary["available_tools"] = ["get_node_summary"]
    incomplete_tool_list = probe.model_copy(
        update={"tool_results": probe.tool_results | {"get_node_summary": incomplete_summary}}
    )
    with pytest.raises(ValueError, match="必须公开完整只读工具集合"):
        IncidentEvaluationDataset.model_validate(
            dataset.model_dump()
            | {
                "scenarios": tuple(
                    incomplete_tool_list if item.scenario_id == probe.scenario_id else item
                    for item in dataset.scenarios
                )
            }
        )


def test_real_cli_writes_report_without_endpoint(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    provider = _CapturingProvider(None)

    def provider_factory(_config: OpenAICompatibleConfig) -> _CapturingProvider:
        return provider

    def repository_revision() -> str:
        return REVISION

    health_calls: list[tuple[str, str]] = []

    def model_health(endpoint: str, expected_model: str) -> real_cli.IncidentModelServiceHealth:
        health_calls.append((endpoint, expected_model))
        return real_cli.IncidentModelServiceHealth(status="healthy", loaded_model=expected_model)

    monkeypatch.setattr(real_cli, "OpenAICompatibleProvider", provider_factory)
    monkeypatch.setattr(real_cli, "_repository_revision", repository_revision)
    monkeypatch.setattr(real_cli, "_model_health", model_health)
    output = tmp_path / "real-report.json"

    assert (
        real_cli.main(
            [
                str(V4_DATASET),
                "--endpoint",
                "http://127.0.0.1:9999/v1",
                "--health-endpoint",
                "http://127.0.0.1:9999/health",
                "--model",
                "test-model",
                "--output",
                str(output),
                "--check",
            ]
        )
        == 1
    )
    payload = output.read_text(encoding="utf-8")
    assert '"scope":"isolated-real-model-local-runtime"' in payload.replace(" ", "")
    assert "127.0.0.1:9999" not in payload
    parsed = json.loads(payload)
    assert parsed["schema_version"] == "incident-evaluation-report/v3"
    assert parsed["prompt_content_hash"].startswith("sha256:")
    assert parsed["model_service_health_before"] == {
        "status": "healthy",
        "loaded_model": "test-model",
    }
    assert parsed["model_service_health_after"] == parsed["model_service_health_before"]
    assert health_calls == [
        ("http://127.0.0.1:9999/health", "test-model"),
        ("http://127.0.0.1:9999/health", "test-model"),
    ]


def test_real_cli_health_rejects_a_different_loaded_model(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def get_health(endpoint: str, *, timeout: float) -> httpx.Response:
        assert endpoint == "http://127.0.0.1:9999/health"
        assert timeout == 10.0
        return httpx.Response(
            200,
            json={"status": "healthy", "loaded_model": "loaded-model", "ignored": True},
            request=httpx.Request("GET", endpoint),
        )

    monkeypatch.setattr(real_cli.httpx, "get", get_health)
    assert (
        real_cli._model_health(  # pyright: ignore[reportPrivateUsage]
            "http://127.0.0.1:9999/health", "loaded-model"
        ).status
        == "healthy"
    )
    with pytest.raises(RuntimeError, match="加载的模型"):
        real_cli._model_health(  # pyright: ignore[reportPrivateUsage]
            "http://127.0.0.1:9999/health", "different-model"
        )
