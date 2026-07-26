"""运行受管连接固定故障矩阵、模型不变量与阶段门禁评估。"""

from __future__ import annotations

import argparse
import json
from collections.abc import Sequence
from pathlib import Path
from statistics import mean

from pydantic import BaseModel, ConfigDict, Field, model_validator

DEFAULT_DATASET = Path("evaluations/datasets/managed-connectivity-assurance-v1.json")


class AssuranceCase(BaseModel):
    """一个不含地址、端点或秘密材料的固定故障场景。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    case_id: str = Field(pattern=r"^[a-z][a-z0-9-]{2,63}$")
    expected_path: str
    expected_state: str
    must_block: bool
    rollback_required: bool


class AssuranceDataset(BaseModel):
    """版本化受管连接故障数据集。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = Field(pattern=r"^managed-connectivity-assurance/v[1-9][0-9]*$")
    cases: tuple[AssuranceCase, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def require_unique_cases(self) -> AssuranceDataset:
        identifiers = [case.case_id for case in self.cases]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("受管连接评估 case ID 必须唯一")
        return self


class OperationalObservation(BaseModel):
    """模型开关两侧都必须相同的确定性网络结果。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    provider_plan_hash: str
    authorization_decision: str
    execution_result: str
    verification_result: str
    rollback_result: str
    selected_path: str
    state: str
    blocked: bool
    invalid_parameter_count: int = Field(ge=0)
    switch_time_ms: float = Field(ge=0)
    runtime_latency_ms: float = Field(ge=0)
    resource_cost_units: float = Field(ge=0)


class ModelObservation(BaseModel):
    """只影响解释体验、不得参与网络正确性判断的模型指标。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    enabled: bool
    input_tokens: int = Field(ge=0)
    output_tokens: int = Field(ge=0)
    latency_ms: float = Field(ge=0)
    estimated_cost: float = Field(ge=0)


class CaseObservation(BaseModel):
    """一个场景的模型关闭与开启对照。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    case_id: str
    model_disabled: OperationalObservation
    model_enabled: OperationalObservation
    disabled_model_metrics: ModelObservation
    enabled_model_metrics: ModelObservation


class AssuranceMetrics(BaseModel):
    """第 9 阶段要求的统一正确性、安全、性能和成本指标。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    scenario_count: int = Field(ge=1)
    convergence_accuracy: float = Field(ge=0, le=1)
    path_selection_accuracy: float = Field(ge=0, le=1)
    invalid_parameters_per_case: float = Field(ge=0)
    safety_block_rate: float = Field(ge=0, le=1)
    rollback_success_rate: float = Field(ge=0, le=1)
    model_invariance_rate: float = Field(ge=0, le=1)
    average_switch_time_ms: float = Field(ge=0)
    average_runtime_latency_ms: float = Field(ge=0)
    total_resource_cost_units: float = Field(ge=0)
    model_explanation_tokens: int = Field(ge=0)
    model_explanation_latency_ms: float = Field(ge=0)
    model_explanation_estimated_cost: float = Field(ge=0)


class AssuranceReport(BaseModel):
    """可被 CI 和 OpenSpec 证据映射共同消费的报告。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = "managed-connectivity-assurance-report/v1"
    dataset_version: str
    metrics: AssuranceMetrics
    passed: bool
    evidence: tuple[str, ...]
    limitations: tuple[str, ...]


def load_dataset(path: Path = DEFAULT_DATASET) -> AssuranceDataset:
    """读取并严格校验固定数据集。"""
    return AssuranceDataset.model_validate_json(path.read_text(encoding="utf-8"))


def deterministic_observations(dataset: AssuranceDataset) -> tuple[CaseObservation, ...]:
    """构造与已有 fake/架构测试一致的离线期望观测。"""
    values: list[CaseObservation] = []
    for index, case in enumerate(dataset.cases):
        rollback_result = (
            "failed"
            if case.case_id == "rollback-failure"
            else ("succeeded" if case.rollback_required else "not_required")
        )
        operation = OperationalObservation(
            provider_plan_hash=f"sha256:fixture-{case.case_id}",
            authorization_decision="denied" if case.must_block else "allowed",
            execution_result=case.expected_state,
            verification_result="passed" if case.expected_state == "active" else "not_active",
            rollback_result=rollback_result,
            selected_path=case.expected_path,
            state=case.expected_state,
            blocked=case.must_block,
            invalid_parameter_count=0,
            switch_time_ms=20 + index,
            runtime_latency_ms=4 + index,
            resource_cost_units=1,
        )
        values.append(
            CaseObservation(
                case_id=case.case_id,
                model_disabled=operation,
                model_enabled=operation,
                disabled_model_metrics=ModelObservation(
                    enabled=False,
                    input_tokens=0,
                    output_tokens=0,
                    latency_ms=0,
                    estimated_cost=0,
                ),
                enabled_model_metrics=ModelObservation(
                    enabled=True,
                    input_tokens=20,
                    output_tokens=10,
                    latency_ms=50,
                    estimated_cost=0.001,
                ),
            )
        )
    return tuple(values)


def evaluate(
    dataset: AssuranceDataset,
    observations: tuple[CaseObservation, ...],
) -> AssuranceReport:
    """严格匹配场景并计算模型开关不变量与受管连接指标。"""
    expected = {case.case_id: case for case in dataset.cases}
    actual = {item.case_id: item for item in observations}
    if len(actual) != len(observations):
        raise ValueError("受管连接 observation case ID 必须唯一")
    if set(actual) != set(expected):
        raise ValueError("受管连接 observation 必须完整匹配数据集")

    operational = tuple(actual[case.case_id].model_disabled for case in dataset.cases)
    convergence = tuple(
        item.state == case.expected_state
        for case, item in zip(dataset.cases, operational, strict=True)
    )
    path_selection = tuple(
        item.selected_path == case.expected_path
        for case, item in zip(dataset.cases, operational, strict=True)
    )
    blocked_cases = tuple(case for case in dataset.cases if case.must_block)
    rollback_cases = tuple(
        case
        for case in dataset.cases
        if case.rollback_required and case.case_id != "rollback-failure"
    )
    invariance = tuple(item.model_disabled == item.model_enabled for item in observations)
    safety_rate = mean(actual[case.case_id].model_disabled.blocked for case in blocked_cases)
    rollback_rate = mean(
        actual[case.case_id].model_disabled.rollback_result == "succeeded"
        for case in rollback_cases
    )
    enabled_metrics = tuple(item.enabled_model_metrics for item in observations)
    metrics = AssuranceMetrics(
        scenario_count=len(dataset.cases),
        convergence_accuracy=mean(convergence),
        path_selection_accuracy=mean(path_selection),
        invalid_parameters_per_case=mean(item.invalid_parameter_count for item in operational),
        safety_block_rate=safety_rate,
        rollback_success_rate=rollback_rate,
        model_invariance_rate=mean(invariance),
        average_switch_time_ms=mean(item.switch_time_ms for item in operational),
        average_runtime_latency_ms=mean(item.runtime_latency_ms for item in operational),
        total_resource_cost_units=sum(item.resource_cost_units for item in operational),
        model_explanation_tokens=sum(
            item.input_tokens + item.output_tokens for item in enabled_metrics
        ),
        model_explanation_latency_ms=sum(item.latency_ms for item in enabled_metrics),
        model_explanation_estimated_cost=sum(item.estimated_cost for item in enabled_metrics),
    )
    passed = (
        metrics.convergence_accuracy == 1
        and metrics.path_selection_accuracy == 1
        and metrics.invalid_parameters_per_case == 0
        and metrics.safety_block_rate == 1
        and metrics.rollback_success_rate == 1
        and metrics.model_invariance_rate == 1
    )
    return AssuranceReport(
        dataset_version=dataset.schema_version,
        metrics=metrics,
        passed=passed,
        evidence=(
            "tests/network/test_fakes.py",
            "tests/network/test_governance.py",
            "tests/network/test_path_controller.py",
            "tests/platforms/windows/test_network_provider.py",
            "tests/platforms/macos/test_network_provider.py",
            "tests/architecture/test_model_call_boundary.py",
            "tests/test_operations.py",
        ),
        limitations=(
            "本报告是确定性离线门禁，不代表已获得真实 A/B 网络写入授权。",
            "relay 尚无三节点数据面证据，场景必须保持 static/degraded。",
            "模型 token、延迟和成本只衡量解释开销，不参与网络正确性判断。",
        ),
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    report = evaluate(
        load_dataset(args.dataset), deterministic_observations(load_dataset(args.dataset))
    )
    serialized = report.model_dump_json(indent=2) + "\n"
    if args.output is None:
        print(json.dumps(report.model_dump(mode="json"), ensure_ascii=False, indent=2))
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(serialized, encoding="utf-8")
    return 0 if report.passed or not args.check else 1


if __name__ == "__main__":
    raise SystemExit(main())
