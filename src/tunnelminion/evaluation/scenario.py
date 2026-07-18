"""可重复离线 Agent 场景与数据集的版本化文件格式。"""

from __future__ import annotations

import re
from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, JsonValue, model_validator


class ScriptedToolCall(BaseModel):
    """假模型发出的一次确定性工具请求。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(pattern=r"^[a-z][a-z0-9_]{2,63}$")
    arguments: dict[str, JsonValue] = Field(default_factory=dict)


class ScriptedModelTurn(BaseModel):
    """假模型的一次动作，只能是调用工具或生成回答之一。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    tool_call: ScriptedToolCall | None = None
    final_answer: str | None = None

    @model_validator(mode="after")
    def require_exactly_one_action(self) -> Self:
        if (self.tool_call is None) == (self.final_answer is None):
            raise ValueError("脚本轮次必须且只能包含一个模型动作")
        return self


class ToolFixture(BaseModel):
    """假工具的一次预期调用及其确定性结果。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(pattern=r"^[a-z][a-z0-9_]{2,63}$")
    expected_arguments: dict[str, JsonValue] = Field(default_factory=dict)
    result: JsonValue
    duration_ms: int = Field(default=0, ge=0)


class RecordedModelUsage(BaseModel):
    """录制或真模型运行时可获得的 token 与成本数据。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    input_tokens: int | None = Field(default=None, ge=0)
    output_tokens: int | None = Field(default=None, ge=0)
    total_tokens: int | None = Field(default=None, ge=0)
    estimated_cost: float | None = Field(default=None, ge=0)


class EvaluationScenario(BaseModel):
    """供 CI 和未来真模型评估使用的可移植 JSON 格式。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: int = Field(ge=1, le=1)
    scenario_id: str = Field(pattern=r"^[a-z][a-z0-9_-]{2,63}$")
    category: Literal[
        "normal",
        "failure",
        "prompt-injection",
        "invented-tool",
        "invalid-arguments",
        "secret-request",
        "write-request",
    ] = "normal"
    question: str = Field(min_length=1)
    model_script: tuple[ScriptedModelTurn, ...] = Field(min_length=1)
    tool_fixtures: tuple[ToolFixture, ...] = ()
    expected_tools: frozenset[str] = frozenset()
    forbidden_tools: frozenset[str] = frozenset()
    required_answer_facts: tuple[str, ...] = ()
    required_answer_fact_groups: tuple[tuple[str, ...], ...] = ()
    required_unknown_markers: tuple[str, ...] = ()
    required_unknown_marker_groups: tuple[tuple[str, ...], ...] = ()
    forbidden_answer_claims: tuple[str, ...] = ()
    forbidden_answer_claim_groups: tuple[tuple[str, ...], ...] = ()
    forbidden_answer_patterns: tuple[str, ...] = ()
    recorded_model_usage: RecordedModelUsage = RecordedModelUsage()
    recorded_total_latency_ms: int = Field(default=0, ge=0)

    @model_validator(mode="after")
    def require_disjoint_tool_expectations(self) -> Self:
        overlap = self.expected_tools & self.forbidden_tools
        if overlap:
            raise ValueError(f"工具不能同时属于预期和禁止集合：{sorted(overlap)}")
        groups = (
            self.required_answer_fact_groups
            + self.required_unknown_marker_groups
            + self.forbidden_answer_claim_groups
        )
        if any(not group or any(not value for value in group) for group in groups):
            raise ValueError("答案事实组和冲突组不得为空")
        try:
            for pattern in self.forbidden_answer_patterns:
                re.compile(pattern)
        except re.error as exc:
            raise ValueError("答案冲突正则表达式无效") from exc
        return self


class EvaluationDataset(BaseModel):
    """可在 CI、真模型和版本对比中复用的一组固定场景。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: int = Field(ge=1, le=1)
    dataset_id: str = Field(pattern=r"^[a-z][a-z0-9_-]{2,63}$")
    dataset_version: str = Field(pattern=r"^v[1-9][0-9]*$")
    prompt_version: str = Field(min_length=1)
    model_name: str = Field(min_length=1)
    provider_name: str = Field(min_length=1)
    tool_versions: dict[str, str] = Field(min_length=1)
    scenarios: tuple[EvaluationScenario, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def require_unique_scenario_ids(self) -> Self:
        identifiers = [scenario.scenario_id for scenario in self.scenarios]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("数据集中的 scenario_id 必须唯一")
        return self
