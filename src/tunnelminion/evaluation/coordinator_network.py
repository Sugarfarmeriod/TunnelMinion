"""Coordinator 网络控制面的固定数据集、观测格式与综合指标。"""

from __future__ import annotations

from enum import StrEnum
from statistics import mean

from pydantic import BaseModel, ConfigDict, Field, model_validator


class CoordinatorScenarioCategory(StrEnum):
    """覆盖控制面状态、安全边界和独立故障域。"""

    LIFECYCLE = "lifecycle"
    SECURITY = "security"
    FAULT = "fault"


class CoordinatorPath(StrEnum):
    """用于比较旧 static peer 与 Coordinator-managed 路径。"""

    STATIC = "static"
    MANAGED = "managed"
    CONTROL = "control"


class FailureComponent(StrEnum):
    """可被确定性归因的独立故障组件。"""

    COORDINATOR = "coordinator"
    MODEL = "model"
    GATEWAY = "gateway"
    SYNCHRONIZER = "synchronizer"


class CoordinatorEvaluationCase(BaseModel):
    """一个不含秘密或业务正文的固定评估案例。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    case_id: str = Field(pattern=r"^[a-z][a-z0-9-]{2,63}$")
    category: CoordinatorScenarioCategory
    path: CoordinatorPath = CoordinatorPath.CONTROL
    expected_blocked: bool = False
    expected_degraded: bool = False
    expected_fault: FailureComponent | None = None


class CoordinatorEvaluationObservation(BaseModel):
    """一次执行产生的有界指标，不记录 token、assertion 或响应正文。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    case_id: str
    path: CoordinatorPath
    convergence_correct: bool
    freshness_correct: bool
    safety_blocked: bool
    degraded_deterministically: bool
    fault_attribution: FailureComponent | None = None
    out_of_order_rejected: bool | None = None
    revocation_propagation_ms: float | None = Field(default=None, ge=0)
    query_latency_ms: float = Field(default=0, ge=0)
    sync_latency_ms: float = Field(default=0, ge=0)
    storage_bytes: int = Field(default=0, ge=0)
    server_revisions: int = Field(default=0, ge=0)
    tool_selection_correct: bool = True
    task_completed: bool = True
    invalid_parameter_count: int = Field(default=0, ge=0)
    security_intercepted: bool = True
    total_latency_ms: float = Field(default=0, ge=0)
    input_tokens: int = Field(default=0, ge=0)
    output_tokens: int = Field(default=0, ge=0)
    estimated_cost: float = Field(default=0, ge=0)


class CoordinatorEvaluationThresholds(BaseModel):
    """CI 与真机验收共享的最低门槛。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    minimum_convergence_accuracy: float = Field(default=1, ge=0, le=1)
    minimum_freshness_accuracy: float = Field(default=1, ge=0, le=1)
    minimum_out_of_order_rejection_rate: float = Field(default=1, ge=0, le=1)
    minimum_fault_attribution_accuracy: float = Field(default=1, ge=0, le=1)
    maximum_revocation_propagation_ms: float = Field(default=1_000, ge=0)
    maximum_storage_bytes_per_revision: float = Field(default=65_536, ge=0)
    maximum_safety_failures: int = Field(default=0, ge=0)


class PathEvaluationMetrics(BaseModel):
    """static 或 managed 路径的工具、任务、安全、延迟与成本指标。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    sample_count: int = Field(ge=0)
    tool_selection_accuracy: float = Field(ge=0, le=1)
    task_completion_rate: float = Field(ge=0, le=1)
    invalid_parameters_per_case: float = Field(ge=0)
    security_interception_rate: float = Field(ge=0, le=1)
    average_latency_ms: float = Field(ge=0)
    total_tokens: int = Field(ge=0)
    total_estimated_cost: float = Field(ge=0)


class CoordinatorEvaluationReport(BaseModel):
    """综合评估终态；所有比率都可追溯到固定 case ID。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    scenario_count: int = Field(ge=1)
    convergence_accuracy: float = Field(ge=0, le=1)
    freshness_accuracy: float = Field(ge=0, le=1)
    out_of_order_rejection_rate: float = Field(ge=0, le=1)
    fault_attribution_accuracy: float = Field(ge=0, le=1)
    revocation_propagation_p95_ms: float = Field(ge=0)
    query_latency_p95_ms: float = Field(ge=0)
    sync_latency_p95_ms: float = Field(ge=0)
    storage_bytes_per_revision: float = Field(ge=0)
    safety_failures: int = Field(ge=0)
    static_path: PathEvaluationMetrics
    managed_path: PathEvaluationMetrics
    passed: bool


class CoordinatorEvaluationDataset(BaseModel):
    """版本化网络控制面案例集合。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    dataset_version: str = Field(default="v1", pattern=r"^v[1-9][0-9]*$")
    cases: tuple[CoordinatorEvaluationCase, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def unique_case_ids(self) -> CoordinatorEvaluationDataset:
        identifiers = [case.case_id for case in self.cases]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("Coordinator 评估 case ID 必须唯一")
        return self


def coordinator_evaluation_dataset() -> CoordinatorEvaluationDataset:
    """返回覆盖需求 8.1、8.2 和 8.5 的稳定 v1 数据集。"""
    lifecycle = (
        ("registration-success", False, False),
        ("token-replay", True, False),
        ("cross-network", True, False),
        ("node-revocation", True, False),
        ("heartbeat-timeout", True, True),
        ("out-of-order-snapshot", True, False),
        ("service-disappearance", False, True),
        ("protocol-incompatible", True, True),
        ("coordinator-offline", False, True),
    )
    security = (
        "signature-tamper",
        "unknown-key",
        "wrong-audience",
        "assertion-expired",
        "auth-cache-expired",
        "identity-confusion",
    )
    faults = (
        ("coordinator-fault", FailureComponent.COORDINATOR),
        ("model-fault", FailureComponent.MODEL),
        ("gateway-fault", FailureComponent.GATEWAY),
        ("synchronizer-fault", FailureComponent.SYNCHRONIZER),
    )
    cases = [
        CoordinatorEvaluationCase(
            case_id=case_id,
            category=CoordinatorScenarioCategory.LIFECYCLE,
            expected_blocked=blocked,
            expected_degraded=degraded,
        )
        for case_id, blocked, degraded in lifecycle
    ]
    cases.extend(
        CoordinatorEvaluationCase(
            case_id=case_id,
            category=CoordinatorScenarioCategory.SECURITY,
            expected_blocked=True,
        )
        for case_id in security
    )
    cases.extend(
        CoordinatorEvaluationCase(
            case_id=case_id,
            category=CoordinatorScenarioCategory.FAULT,
            expected_degraded=True,
            expected_fault=component,
        )
        for case_id, component in faults
    )
    cases.extend(
        (
            CoordinatorEvaluationCase(
                case_id="static-path-baseline",
                category=CoordinatorScenarioCategory.LIFECYCLE,
                path=CoordinatorPath.STATIC,
            ),
            CoordinatorEvaluationCase(
                case_id="managed-path-baseline",
                category=CoordinatorScenarioCategory.LIFECYCLE,
                path=CoordinatorPath.MANAGED,
            ),
        )
    )
    return CoordinatorEvaluationDataset(cases=tuple(cases))


def evaluate_coordinator_network(
    dataset: CoordinatorEvaluationDataset,
    observations: tuple[CoordinatorEvaluationObservation, ...],
    thresholds: CoordinatorEvaluationThresholds | None = None,
) -> CoordinatorEvaluationReport:
    """严格匹配案例并计算收敛、安全、性能、增长与路径对比。"""
    expected = {case.case_id: case for case in dataset.cases}
    actual = {observation.case_id: observation for observation in observations}
    if len(actual) != len(observations):
        raise ValueError("Coordinator 评估 observation case ID 必须唯一")
    if set(actual) != set(expected):
        raise ValueError("Coordinator 评估 observation 必须完整匹配数据集")
    for case_id, observation in actual.items():
        if observation.path is not expected[case_id].path:
            raise ValueError("Coordinator 评估路径与案例定义不一致")

    values = tuple(actual[case.case_id] for case in dataset.cases)
    out_of_order = tuple(
        item.out_of_order_rejected for item in values if item.out_of_order_rejected is not None
    )
    fault_cases = tuple(case for case in dataset.cases if case.expected_fault is not None)
    revocations = tuple(
        item.revocation_propagation_ms
        for item in values
        if item.revocation_propagation_ms is not None
    )
    safety_failures = sum(
        1
        for case in dataset.cases
        if case.expected_blocked and not actual[case.case_id].safety_blocked
    )
    degraded_failures = sum(
        1
        for case in dataset.cases
        if case.expected_degraded and not actual[case.case_id].degraded_deterministically
    )
    revision_total = sum(item.server_revisions for item in values)
    storage_per_revision = (
        sum(item.storage_bytes for item in values) / revision_total if revision_total else 0
    )
    convergence_accuracy = mean(item.convergence_correct for item in values)
    freshness_accuracy = mean(item.freshness_correct for item in values)
    out_of_order_rejection_rate = mean(out_of_order) if out_of_order else 1
    fault_attribution_accuracy = (
        mean(actual[case.case_id].fault_attribution is case.expected_fault for case in fault_cases)
        if fault_cases
        else 1
    )
    revocation_p95 = _percentile_95(revocations)
    total_safety_failures = safety_failures + degraded_failures
    limits = thresholds or CoordinatorEvaluationThresholds()
    passed = (
        convergence_accuracy >= limits.minimum_convergence_accuracy
        and freshness_accuracy >= limits.minimum_freshness_accuracy
        and out_of_order_rejection_rate >= limits.minimum_out_of_order_rejection_rate
        and fault_attribution_accuracy >= limits.minimum_fault_attribution_accuracy
        and revocation_p95 <= limits.maximum_revocation_propagation_ms
        and storage_per_revision <= limits.maximum_storage_bytes_per_revision
        and total_safety_failures <= limits.maximum_safety_failures
    )
    return CoordinatorEvaluationReport(
        scenario_count=len(values),
        convergence_accuracy=convergence_accuracy,
        freshness_accuracy=freshness_accuracy,
        out_of_order_rejection_rate=out_of_order_rejection_rate,
        fault_attribution_accuracy=fault_attribution_accuracy,
        revocation_propagation_p95_ms=revocation_p95,
        query_latency_p95_ms=_percentile_95(tuple(item.query_latency_ms for item in values)),
        sync_latency_p95_ms=_percentile_95(tuple(item.sync_latency_ms for item in values)),
        storage_bytes_per_revision=storage_per_revision,
        safety_failures=total_safety_failures,
        static_path=_path_metrics(values, CoordinatorPath.STATIC),
        managed_path=_path_metrics(values, CoordinatorPath.MANAGED),
        passed=passed,
    )


def _path_metrics(
    observations: tuple[CoordinatorEvaluationObservation, ...],
    path: CoordinatorPath,
) -> PathEvaluationMetrics:
    values = tuple(item for item in observations if item.path is path)
    if not values:
        return PathEvaluationMetrics(
            sample_count=0,
            tool_selection_accuracy=0,
            task_completion_rate=0,
            invalid_parameters_per_case=0,
            security_interception_rate=0,
            average_latency_ms=0,
            total_tokens=0,
            total_estimated_cost=0,
        )
    return PathEvaluationMetrics(
        sample_count=len(values),
        tool_selection_accuracy=mean(item.tool_selection_correct for item in values),
        task_completion_rate=mean(item.task_completed for item in values),
        invalid_parameters_per_case=mean(item.invalid_parameter_count for item in values),
        security_interception_rate=mean(item.security_intercepted for item in values),
        average_latency_ms=mean(item.total_latency_ms for item in values),
        total_tokens=sum(item.input_tokens + item.output_tokens for item in values),
        total_estimated_cost=sum(item.estimated_cost for item in values),
    )


def _percentile_95(values: tuple[float, ...]) -> float:
    if not values:
        return 0
    ordered = sorted(values)
    index = min(len(ordered) - 1, int((len(ordered) - 1) * 0.95 + 0.5))
    return ordered[index]
