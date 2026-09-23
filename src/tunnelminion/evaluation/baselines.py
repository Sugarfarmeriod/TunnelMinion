"""可追溯调查基线及同口径比较条件。"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Self

from pydantic import BaseModel, ConfigDict, Field, model_validator


class MetricFraction(BaseModel):
    """保留比率的分子、分母和展示值。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    numerator: int = Field(ge=0)
    denominator: int = Field(gt=0)
    value: float = Field(ge=0, le=1)

    @model_validator(mode="after")
    def validate_value(self) -> Self:
        if abs(self.value - self.numerator / self.denominator) > 1e-12:
            raise ValueError("指标值必须等于分子除以分母")
        return self


class InvestigationBudget(BaseModel):
    """影响调查结果的固定预算。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    max_model_rounds: int = Field(gt=0)
    max_tool_calls: int = Field(gt=0)
    timeout_seconds: float = Field(gt=0)
    context: dict[str, int]


class InvestigationBaseline(BaseModel):
    """用于简历和前后评测的不可变比较清单。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str
    baseline_id: str
    source_revision: str = Field(pattern=r"^[0-9a-f]{40}$")
    source_report: str
    source_report_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    dataset_id: str
    dataset_version: str
    dataset_content_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    provider_name: str
    model_name: str
    prompt_version: str
    prompt_content_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    tool_versions: dict[str, str]
    budget: InvestigationBudget
    scorer_version: str
    scorer_content_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    evaluation_run_count: int = Field(gt=0)
    metrics: dict[str, MetricFraction]

    @classmethod
    def load(cls, path: Path) -> InvestigationBaseline:
        return cls.model_validate_json(path.read_text(encoding="utf-8"))

    def comparison_mismatches(self, other: InvestigationBaseline) -> tuple[str, ...]:
        """返回除被评测代码外会破坏同口径比较的字段。"""
        fields = (
            "dataset_id",
            "dataset_version",
            "dataset_content_hash",
            "provider_name",
            "model_name",
            "prompt_version",
            "prompt_content_hash",
            "tool_versions",
            "budget",
            "scorer_version",
            "scorer_content_hash",
            "evaluation_run_count",
        )
        return tuple(
            name
            for name in fields
            if json.dumps(getattr(self, name), default=str, sort_keys=True)
            != json.dumps(getattr(other, name), default=str, sort_keys=True)
        )
