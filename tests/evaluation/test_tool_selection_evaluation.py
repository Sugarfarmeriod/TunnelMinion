"""挑工具评测：固定数据集全部通过，真实模型对比脚本的打分和汇总可复现。"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest
from scripts import run_tool_selection_evaluation, run_tool_selection_real_evaluation

from tunnelminion.agent.runtime import (
    AgentRunLimits,
    AgentStopReason,
    AgentUsage,
    CheckedAgentTurnResult,
    EvidenceAnswer,
    EvidenceReference,
)
from tunnelminion.evaluation.tool_selection import (
    CannedToolAdapter,
    RealCaseRun,
    SelectionProbeProvider,
    ToolSelectionCase,
    failed_run,
    load_dataset,
    run_offline,
    score_run,
    summarize,
    summary_markdown,
)
from tunnelminion.model.contracts import (
    CancellationToken,
    ModelCapabilities,
    ModelRequest,
    ModelResponse,
    ProviderError,
    ProviderErrorCode,
    ToolCall,
)
from tunnelminion.model.openai_compatible import OpenAICompatibleConfig
from tunnelminion.tools.contracts import ToolCancellationToken

DATASET = Path("evaluations/datasets/tool-selection-v1.json")
REPORT = Path("evaluations/reports/tool-selection-offline-2026-10-29.json")


def test_dataset_passes_and_matches_committed_report() -> None:
    report = asyncio.run(run_offline(load_dataset(DATASET)))

    assert report.cases == report.passed == 21
    assert json.loads(REPORT.read_text(encoding="utf-8")) == report.model_dump(mode="json")


def test_offline_report_flags_missing_tools() -> None:
    dataset = load_dataset(DATASET)
    broken = dataset.model_copy(
        update={
            "cases": (
                dataset.cases[0].model_copy(
                    update={"must_see": ("get_wireguard_status",), "max_tools": 3}
                ),
            )
        }
    )

    report = asyncio.run(run_offline(broken))

    assert report.passed == 0
    assert report.results[0].missing == ("get_wireguard_status",)


def test_canned_adapter_and_probe_without_hidden_tools() -> None:
    assert asyncio.run(CannedToolAdapter({"a": 1}).execute({}, ToolCancellationToken())) == {"a": 1}
    probe = SelectionProbeProvider()
    assert probe.capabilities.tool_calls


def _case() -> ToolSelectionCase:
    return ToolSelectionCase(
        case_id="docker",
        question="相册容器是不是停了？",
        must_see=("list_docker_services",),
        acceptable_first_tools=("list_docker_services",),
        expected_tools=("list_docker_services", "read_container_logs"),
    )


def _result(answer: str, tools: tuple[str, ...]) -> CheckedAgentTurnResult:
    evidence = tuple(
        EvidenceReference(tool_run_id=f"toolrun_{index}", tool_name=name, status="success")
        for index, name in enumerate(tools)
    )
    return CheckedAgentTurnResult(
        answer=answer,
        model_rounds=2,
        tool_calls=len(tools),
        selected_tools=(),
        stop_reason=AgentStopReason.COMPLETED,
        elapsed_ms=1,
        usage=AgentUsage(input_tokens=10, output_tokens=5, total_tokens=15),
        limits=AgentRunLimits(),
        evidence_answer=EvidenceAnswer(
            summary=answer,
            confirmed_facts=(),
            inferences=(),
            unknowns=(),
            evidence=evidence,
            stop_reason=AgentStopReason.COMPLETED,
        ),
    )


@pytest.mark.parametrize(
    ("answer", "claims"),
    [
        ("我没有查看 Docker 的工具。", True),
        ("无法查看容器状态。", True),
        ("I have no docker tool here.", True),
        ("相册容器已经退出。", False),
    ],
)
def test_score_run_detects_missing_tool_claims(answer: str, claims: bool) -> None:
    run = score_run(_case(), "B", 1, _result(answer, ()), ())

    assert run.claimed_missing_tool is claims
    assert run.first_tool is None and not run.first_tool_ok


def test_score_and_summarize_two_variants() -> None:
    case = _case()
    good = score_run(
        case,
        "B",
        1,
        _result("容器退出了。", ("list_docker_services", "read_container_logs")),
        ("request_more_tools", "list_docker_services"),
    )
    bad = score_run(case, "A", 1, _result("没有 Docker 工具。", ("list_network_listeners",)), ())
    failed = failed_run(case, "A", 2, "timeout")

    assert good.first_tool_ok and good.expected_covered and good.asked_for_more
    assert not bad.first_tool_ok and bad.claimed_missing_tool
    assert failed.stop_reason == "provider-error:timeout" and failed.total_tokens == 0
    summaries = summarize((bad, good, failed))
    assert [item.variant for item in summaries] == ["A", "B"]
    assert summaries[0].runs == 2 and summaries[0].missing_tool_claims == 1
    assert summaries[1].first_tool_hits == 1 and summaries[1].mean_total_tokens == 15
    markdown = summary_markdown("qwen", summaries)
    assert markdown.startswith("# 挑工具前后对比：qwen\n")
    assert "| B | 1 | 1/1 | 1/1 | 0 | 1 | 2.0 | 15.0 |" in markdown


def test_offline_script_writes_report(tmp_path: Path) -> None:
    output = tmp_path / "report.json"

    assert run_tool_selection_evaluation.main(["--output", str(output)]) == 0
    assert json.loads(output.read_text(encoding="utf-8"))["passed"] == 21


class _ScriptedRealProvider:
    """代替真实模型：先调 Docker 工具再回答；指定轮次直接失败。"""

    fail_next = False

    def __init__(self, config: OpenAICompatibleConfig, api_key: str | None) -> None:
        assert config.disable_thinking and api_key is None
        self.calls = 0

    @property
    def capabilities(self) -> ModelCapabilities:
        return ModelCapabilities(tool_calls=True, structured_output=True)

    async def complete(
        self, request: ModelRequest, cancellation: CancellationToken | None = None
    ) -> ModelResponse:
        del request, cancellation
        if _ScriptedRealProvider.fail_next:
            _ScriptedRealProvider.fail_next = False
            raise ProviderError(ProviderErrorCode.TIMEOUT, "模拟超时")
        self.calls += 1
        if self.calls == 1:
            return ModelResponse(
                tool_calls=(ToolCall(call_id="c1", name="list_docker_services", arguments={}),)
            )
        return ModelResponse(content="相册容器已经退出。")


def test_real_script_compares_variants_without_network(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        run_tool_selection_real_evaluation, "OpenAICompatibleProvider", _ScriptedRealProvider
    )
    _ScriptedRealProvider.fail_next = True

    code = run_tool_selection_real_evaluation.main(
        [
            "--endpoint",
            "http://127.0.0.1:9/v1",
            "--model",
            "fake",
            "--label",
            "fake",
            "--disable-thinking",
            "--max-tools",
            "5",
            "--rounds",
            "1",
            "--cases",
            "docker-stopped",
            "--output-dir",
            str(tmp_path),
        ]
    )

    assert code == 0
    payload = json.loads((tmp_path / "runs.json").read_text(encoding="utf-8"))
    runs = [RealCaseRun.model_validate(item) for item in payload["runs"]]
    assert [item.variant for item in runs] == ["A-全部工具", "B-按问题挑"]
    assert runs[0].stop_reason == "provider-error:timeout"
    assert runs[1].first_tool == "list_docker_services" and runs[1].first_tool_ok
    assert "http://" not in (tmp_path / "summary.md").read_text(encoding="utf-8")
