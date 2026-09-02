"""离线复算面试展示 fixture 基线并验证评估发布边界。"""

from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path
from typing import Literal, cast

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, JsonValue

from tunnelminion.evaluation.cli import load_dataset
from tunnelminion.evaluation.operations import (
    OperationEvaluationDataset,
    OperationEvaluationMetrics,
    run_operation_evaluation,
)
from tunnelminion.evaluation.runner import EvaluationMetrics, EvaluationReport, run_dataset

ROOT = Path(__file__).resolve().parents[2]
WORK_PACKAGE = Path(__file__).resolve().parent
SUITE_PATH = WORK_PACKAGE / "evaluation" / "evaluation-suite.json"
BASELINE_PATH = WORK_PACKAGE / "evaluation" / "offline-baseline.fixture.json"
EXPECTED_METRICS = {
    "tool-selection-accuracy",
    "task-completion-rate",
    "tool-parameter-error-rate",
    "safety-interception-rate",
    "end-to-end-latency",
    "model-call-count",
    "token-usage",
    "estimated-cost",
}
EXPECTED_METRIC_SOURCES = {
    "tool-selection-accuracy": {"expected_tool_hit_rate", "unnecessary_tool_rate"},
    "task-completion-rate": {"task_completion_rate"},
    "tool-parameter-error-rate": {
        "tool_parameter_error_rate",
    },
    "safety-interception-rate": {
        "forbidden_tool_attempts",
        "forbidden_tool_executions",
        "safety_block_rate",
    },
    "end-to-end-latency": {"average_total_latency_ms", "average_latency_ms"},
    "model-call-count": {"average_model_rounds"},
    "token-usage": {"input_tokens", "output_tokens", "total_tokens"},
    "estimated-cost": {"total_estimated_cost"},
}
EXPECTED_METRIC_STATUS = {
    "tool-selection-accuracy": "supporting-only",
    "task-completion-rate": "measured-fixture",
    "tool-parameter-error-rate": "measured-fixture",
    "safety-interception-rate": "measured-fixture",
    "end-to-end-latency": "measured-fixture",
    "model-call-count": "measured-fixture",
    "token-usage": "partial-fixture",
    "estimated-cost": "partial-fixture",
}
EXPECTED_REAL_FIELDS = {
    "stable_source_sha",
    "dataset_hashes",
    "model_provider_and_version",
    "prompt_and_tool_versions",
    "windows_and_macos_environment",
    "capture_time",
    "per_case_model_call_count",
    "per_case_input_tokens",
    "per_case_output_tokens",
    "per_case_total_tokens",
    "per_case_estimated_cost",
    "per_case_end_to_end_latency_ms",
    "raw_report_references",
    "all_metric_values",
    "redaction_review",
    "independent_audit",
}
EXPECTED_DATASETS = {
    "tunnelminion-mvp": {
        "dataset_version": "v1",
        "path": "evaluations/datasets/mvp-v1.json",
        "source_commit": "8a0692d65861a72b1dce0780e40eee312c9a60e2",
        "normalized_sha256": "a9d8817efadb2d42ba2dec94dbb16b56c64cb825bcdaaaa02b4b31bc0e117e67",
        "runner": (
            "uv run python scripts/run_offline_evaluation.py "
            "evaluations/datasets/mvp-v1.json --check"
        ),
        "case_count": 8,
    },
    "safe-sharing": {
        "dataset_version": "v1",
        "path": "evaluations/datasets/safe-sharing-v1.json",
        "source_commit": "25fc533e258ba78c0345af0288d3d376e31fb242",
        "normalized_sha256": "fb4b2b6504f52e2a1fcbfd8b10111369f366f21fdafd796934443c4be0dc18e1",
        "runner": "uv run python scripts/run_safe_sharing_evaluation.py",
        "case_count": 5,
    },
}
REAL_RUN_ID = "deepseek-v4-flash-release-20260902"
SAFE_RUN_ID = "deepseek-v4-flash-safe-sharing-release-20260902"
QWEN_RUN_ID = "qwen3.6-35b-a3b-windows-to-macos-20260902"
QWEN_SAFE_RUN_ID = "qwen3.6-35b-a3b-safe-sharing-20260902"


class DatasetSpec(BaseModel):
    """版本化 fixture 数据集引用。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    dataset_id: str
    dataset_version: str
    kind: Literal["fixture"]
    path: str
    source_commit: str = Field(pattern=r"^[0-9a-f]{40}$")
    normalized_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    runner: str
    case_count: int = Field(ge=1)
    role: str


class Threshold(BaseModel):
    """真实基线完成后固定的单项发布阈值。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    operator: Literal["gte", "lte"]
    value: float
    unit: str
    baseline_value: float
    source_run_id: str


class MetricSpec(BaseModel):
    """真实基线后的指标与发布阈值。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    metric_id: str
    offline_sources: tuple[str, ...] = Field(min_length=1)
    offline_status: Literal["supporting-only", "measured-fixture", "partial-fixture"]
    real_baseline_required: Literal[True]
    threshold: Threshold


class RealBaselineGate(BaseModel):
    """真实模型基线的完整性门禁。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    state: Literal["passed"]
    required_fields: tuple[str, ...] = Field(min_length=1)
    threshold_policy: str
    independent_audit: str


class Publication(BaseModel):
    """禁止 fixture 进入最终成果。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    include_in_final_metrics: Literal[False]
    include_in_success_media: Literal[False]
    notes: str | None = None


class EvaluationSuite(BaseModel):
    """展示评估组合契约。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal[1]
    suite_id: str
    status: Literal["real-baseline-thresholded"]
    authoring_baseline: str = Field(pattern=r"^[0-9a-f]{40}$")
    hash_normalization: Literal["utf8-lf"]
    datasets: tuple[DatasetSpec, ...] = Field(min_length=2, max_length=2)
    metrics: tuple[MetricSpec, ...] = Field(min_length=8, max_length=8)
    real_baseline_gate: RealBaselineGate
    real_runs: tuple[dict[str, JsonValue], ...] = Field(min_length=2)
    publication: Publication


class AgentDerived(BaseModel):
    """从现有 Agent 指标明确推导的展示口径。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    expected_tool_recall: float = Field(ge=0, le=1)
    tool_call_rejection_rate: float = Field(ge=0, le=1)
    safety_interception_rate: float = Field(ge=0, le=1)
    average_model_calls: float = Field(ge=0)


class AgentFixtureReport(BaseModel):
    """固定假模型 Agent 报告。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    dataset_id: str
    dataset_version: str
    model_name: str
    provider_name: str
    metrics: EvaluationMetrics
    derived: AgentDerived


class TokenCoverage(BaseModel):
    """Operation token 覆盖率，防止把部分 case 冒充总量。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    cases_with_tokens: int = Field(ge=0)
    total_cases: int = Field(ge=1)
    complete: Literal[False]


class OperationFixtureReport(BaseModel):
    """安全候选与批准决策报告。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    dataset_id: str
    dataset_version: str
    release_gate_passed: bool
    metrics: OperationEvaluationMetrics
    token_coverage: TokenCoverage


class FixtureBaseline(BaseModel):
    """不得用于最终成果的离线基线。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal[1]
    status: Literal["fixture-baseline"]
    source_head: str = Field(pattern=r"^[0-9a-f]{40}$")
    captured_at: AwareDatetime
    agent: AgentFixtureReport
    operation: OperationFixtureReport
    thresholds: None
    interpretation: tuple[str, ...] = Field(min_length=3)
    publication: Publication


def _normalized_digest(path: Path) -> str:
    text = path.read_text(encoding="utf-8").replace("\r\n", "\n").replace("\r", "\n")
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _raw_digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _close(actual: float, expected: float) -> bool:
    return math.isclose(actual, expected, rel_tol=1e-12, abs_tol=1e-12)


def _real_run(suite: EvaluationSuite, run_id: str) -> dict[str, JsonValue]:
    matches = tuple(item for item in suite.real_runs if item.get("run_id") == run_id)
    if len(matches) != 1:
        raise ValueError(f"真实基线 run_id 不唯一或不存在：{run_id}")
    return matches[0]


def _report_path(run: dict[str, JsonValue]) -> Path:
    path = (ROOT / cast(str, run["report"])).resolve()
    if ROOT.resolve() not in path.parents or not path.is_file():
        raise ValueError("真实基线报告路径越界或不存在")
    if _raw_digest(path) != run.get("report_sha256"):
        raise ValueError(f"真实基线报告哈希不匹配：{run['run_id']}")
    return path


def main() -> None:
    suite = EvaluationSuite.model_validate_json(SUITE_PATH.read_text(encoding="utf-8"))
    baseline = FixtureBaseline.model_validate_json(BASELINE_PATH.read_text(encoding="utf-8"))

    if {item.metric_id for item in suite.metrics} != EXPECTED_METRICS:
        raise ValueError("评估契约没有精确覆盖任务 4.3 的八类指标")
    for metric in suite.metrics:
        if set(metric.offline_sources) != EXPECTED_METRIC_SOURCES[metric.metric_id]:
            raise ValueError(f"评估指标来源字段不一致：{metric.metric_id}")
        if metric.offline_status != EXPECTED_METRIC_STATUS[metric.metric_id]:
            raise ValueError(f"评估指标离线状态不一致：{metric.metric_id}")
    if set(suite.real_baseline_gate.required_fields) != EXPECTED_REAL_FIELDS:
        raise ValueError("真实基线门禁字段不完整")
    if baseline.source_head != suite.authoring_baseline:
        raise ValueError("fixture 基线与评估契约作者基线不一致")
    if len({item.dataset_id for item in suite.datasets}) != len(suite.datasets):
        raise ValueError("评估数据集 ID 必须唯一")

    datasets = {item.dataset_id: item for item in suite.datasets}
    if set(datasets) != set(EXPECTED_DATASETS):
        raise ValueError("评估数据集集合发生漂移")
    for dataset in suite.datasets:
        expected_dataset = EXPECTED_DATASETS[dataset.dataset_id]
        for field, expected_value in expected_dataset.items():
            if getattr(dataset, field) != expected_value:
                raise ValueError(f"评估数据集契约漂移：{dataset.dataset_id}.{field}")
        path = (ROOT / dataset.path).resolve()
        if ROOT.resolve() not in path.parents or not path.is_file():
            raise ValueError(f"评估数据集路径越界或不存在：{dataset.dataset_id}")
        if _normalized_digest(path) != dataset.normalized_sha256:
            raise ValueError(f"评估数据集哈希不匹配：{dataset.dataset_id}")

    real_run = _real_run(suite, REAL_RUN_ID)
    safe_run = _real_run(suite, SAFE_RUN_ID)
    qwen_run = _real_run(suite, QWEN_RUN_ID)
    qwen_safe_run = _real_run(suite, QWEN_SAFE_RUN_ID)
    if (
        real_run.get("stable_sha") != safe_run.get("stable_sha")
        or qwen_run.get("stable_sha") != qwen_safe_run.get("stable_sha")
    ):
        raise ValueError("同一 Provider 的主评估与 Safe Sharing 不是同一稳定提交")
    qwen_report_path = _report_path(qwen_run)
    qwen_safe_report_path = _report_path(qwen_safe_run)
    if (
        "Windows" not in cast(str, qwen_run.get("caller_environment"))
        or "macOS" not in cast(str, qwen_run.get("provider_environment"))
    ):
        raise ValueError("Qwen 对照没有覆盖 Windows 调用端与 macOS 推理端")
    qwen_report = EvaluationReport.model_validate_json(
        qwen_report_path.read_text(encoding="utf-8")
    )
    qwen_safe_report = cast(
        dict[str, JsonValue],
        json.loads(qwen_safe_report_path.read_text(encoding="utf-8")),
    )
    if (
        qwen_report.model_name != qwen_run.get("actual_model")
        or qwen_safe_report.get("model") != qwen_safe_run.get("model")
    ):
        raise ValueError("Qwen 对照声明的模型与原始请求模型不一致")
    if (
        qwen_report.metrics.task_completion_rate >= 1.0
        or qwen_safe_report.get("release_gate_passed") is not False
    ):
        raise ValueError("Qwen 未达标对照的分类与原始报告不一致")
    real_report = EvaluationReport.model_validate_json(
        _report_path(real_run).read_text(encoding="utf-8")
    )
    safe_report = cast(
        dict[str, JsonValue],
        json.loads(_report_path(safe_run).read_text(encoding="utf-8")),
    )
    if (
        real_report.model_name != real_run.get("actual_model")
        or safe_report.get("model") != safe_run.get("model")
    ):
        raise ValueError("DeepSeek 基线声明的模型与原始请求模型不一致")
    if not all(
        item.input_tokens is not None
        and item.output_tokens is not None
        and item.total_tokens is not None
        and item.estimated_cost is not None
        and item.model_rounds >= 1
        and item.total_latency_ms >= 0
        for item in real_report.scenarios
    ):
        raise ValueError("主评估逐 case 资源字段不完整")
    safe_cases = safe_report.get("cases")
    if (
        safe_report.get("release_gate_passed") is not True
        or safe_report.get("structured_output_success_rate") != 1.0
        or safe_report.get("fixed_field_safety_rate") != 1.0
        or not isinstance(safe_cases, list)
        or len(safe_cases) != 2
        or not all(
            isinstance(item, dict)
            and item.get("input_tokens") is not None
            and item.get("output_tokens") is not None
            and item.get("total_tokens") is not None
            and item.get("estimated_cost") is not None
            and item.get("safe_fixed_fields") is True
            for item in safe_cases
        )
    ):
        raise ValueError("Safe Sharing 真实门禁或逐 case 资源字段不完整")

    metrics = real_report.metrics
    actual_values = {
        "tool-selection-accuracy": metrics.expected_tool_hit_rate,
        "task-completion-rate": metrics.task_completion_rate,
        "tool-parameter-error-rate": 1 - metrics.parameter_validity_rate,
        "safety-interception-rate": 1 - metrics.safety_failures / metrics.scenario_count,
        "end-to-end-latency": metrics.average_total_latency_ms,
        "model-call-count": metrics.average_model_rounds,
        "token-usage": float(cast(int, metrics.total_tokens)),
        "estimated-cost": cast(float, metrics.total_estimated_cost),
    }
    for metric in suite.metrics:
        threshold = metric.threshold
        actual = actual_values[metric.metric_id]
        if threshold.source_run_id != REAL_RUN_ID or not _close(
            threshold.baseline_value, actual
        ):
            raise ValueError(f"阈值基线不能从真实报告复算：{metric.metric_id}")
        passed = (
            actual >= threshold.value
            if threshold.operator == "gte"
            else actual <= threshold.value
        )
        if not passed:
            raise ValueError(f"真实基线未达到发布阈值：{metric.metric_id}")

    audit_path = (ROOT / suite.real_baseline_gate.independent_audit).resolve()
    if ROOT.resolve() not in audit_path.parents or not audit_path.is_file():
        raise ValueError("独立审计记录不存在或路径越界")
    audit_text = audit_path.read_text(encoding="utf-8")
    for evidence in (
        cast(str, real_run["stable_sha"]),
        cast(str, qwen_run["stable_sha"]),
        cast(str, real_run["report_sha256"]),
        cast(str, safe_run["report_sha256"]),
        cast(str, qwen_run["report_sha256"]),
        cast(str, qwen_safe_run["report_sha256"]),
        "审计结论：通过",
    ):
        if evidence not in audit_text:
            raise ValueError("独立审计记录缺少当前真实基线证据")

    agent_spec = datasets[baseline.agent.dataset_id]
    if baseline.agent.dataset_version != agent_spec.dataset_version:
        raise ValueError("Agent fixture 数据集版本不一致")
    agent_report = run_dataset(load_dataset(ROOT / agent_spec.path))
    if (
        agent_report.dataset_id,
        agent_report.dataset_version,
        agent_report.model_name,
        agent_report.provider_name,
    ) != (
        baseline.agent.dataset_id,
        baseline.agent.dataset_version,
        baseline.agent.model_name,
        baseline.agent.provider_name,
    ):
        raise ValueError("Agent fixture 报告元数据与实际数据集不一致")
    if agent_report.metrics != baseline.agent.metrics:
        raise ValueError("Agent fixture 指标无法从当前数据集复算")
    if len(agent_report.scenarios) != agent_spec.case_count:
        raise ValueError("Agent fixture case_count 与数据集不一致")

    agent_metrics = agent_report.metrics
    forbidden_attempts = agent_metrics.forbidden_tool_attempts
    safety_interception = (
        (forbidden_attempts - agent_metrics.forbidden_tool_executions) / forbidden_attempts
        if forbidden_attempts
        else 1.0
    )
    expected_derived = AgentDerived(
        expected_tool_recall=agent_metrics.expected_tool_hit_rate,
        tool_call_rejection_rate=1 - agent_metrics.parameter_validity_rate,
        safety_interception_rate=safety_interception,
        average_model_calls=agent_metrics.average_model_rounds,
    )
    for field in AgentDerived.model_fields:
        if not _close(
            getattr(expected_derived, field),
            getattr(baseline.agent.derived, field),
        ):
            raise ValueError(f"Agent 派生指标不一致：{field}")

    operation_spec = datasets[baseline.operation.dataset_id]
    if baseline.operation.dataset_version != operation_spec.dataset_version:
        raise ValueError("Operation fixture 数据集版本不一致")
    operation_dataset = OperationEvaluationDataset.model_validate_json(
        (ROOT / operation_spec.path).read_text(encoding="utf-8")
    )
    operation_report = run_operation_evaluation(operation_dataset)
    if (
        operation_report.dataset_id,
        operation_report.dataset_version,
    ) != (
        baseline.operation.dataset_id,
        baseline.operation.dataset_version,
    ):
        raise ValueError("Operation fixture 报告元数据与实际数据集不一致")
    if operation_report.metrics != baseline.operation.metrics:
        raise ValueError("Operation fixture 指标无法从当前数据集复算")
    if len(operation_report.cases) != operation_spec.case_count:
        raise ValueError("Operation fixture case_count 与数据集不一致")
    if operation_report.release_gate_passed != baseline.operation.release_gate_passed:
        raise ValueError("Operation release gate 结果不一致")

    token_cases = sum(item.total_tokens is not None for item in operation_report.cases)
    coverage = baseline.operation.token_coverage
    if (coverage.cases_with_tokens, coverage.total_cases) != (
        token_cases,
        len(operation_report.cases),
    ):
        raise ValueError("Operation token 覆盖 case 数不一致")

    print(f"评估契约离线验证通过：{len(suite.datasets)} 套数据集，{len(suite.metrics)} 类指标")


if __name__ == "__main__":
    main()
