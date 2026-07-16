"""可重复离线 Agent 场景的版本化文件格式。"""

from __future__ import annotations

from typing import Self

from pydantic import BaseModel, ConfigDict, Field, model_validator


class ScriptedToolCall(BaseModel):
    """假模型发出的一次确定性工具请求。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(pattern=r"^[a-z][a-z0-9_]{2,63}$")
    arguments: dict[str, str] = Field(default_factory=dict)


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
    expected_arguments: dict[str, str] = Field(default_factory=dict)
    result: dict[str, str]


class EvaluationScenario(BaseModel):
    """供 CI 和未来真模型评估使用的可移植 JSON 格式。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: int = Field(ge=1, le=1)
    scenario_id: str = Field(pattern=r"^[a-z][a-z0-9_-]{2,63}$")
    question: str = Field(min_length=1)
    model_script: tuple[ScriptedModelTurn, ...] = Field(min_length=1)
    tool_fixtures: tuple[ToolFixture, ...] = ()
    expected_tools: frozenset[str] = frozenset()
    forbidden_tools: frozenset[str] = frozenset()
    required_answer_facts: tuple[str, ...] = ()

    @model_validator(mode="after")
    def require_disjoint_tool_expectations(self) -> Self:
        overlap = self.expected_tools & self.forbidden_tools
        if overlap:
            raise ValueError(f"工具不能同时属于预期和禁止集合：{sorted(overlap)}")
        return self
