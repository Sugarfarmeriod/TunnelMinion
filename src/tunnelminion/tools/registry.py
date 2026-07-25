"""工具注册表与 MVP 只读暴露策略。"""

from __future__ import annotations

from dataclasses import dataclass

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError

from tunnelminion.domain.tools import Platform, RiskLevel, ToolDefinition
from tunnelminion.operation.contracts import OperationLevel
from tunnelminion.tools.contracts import ToolAdapter


@dataclass(frozen=True)
class RegisteredTool:
    """已经通过 schema 检查的工具定义及固定适配器。"""

    definition: ToolDefinition
    adapter: ToolAdapter
    operation_level: OperationLevel


class ToolRegistry:
    """只允许显式注册，不执行动态导入或名称猜测。"""

    def __init__(self) -> None:
        self._tools: dict[str, RegisteredTool] = {}

    def register(
        self,
        definition: ToolDefinition,
        adapter: ToolAdapter,
        *,
        operation_level: OperationLevel | None = None,
    ) -> None:
        """检查 schema 后注册稳定名称；重复名称直接拒绝。"""
        if definition.name in self._tools:
            raise ValueError(f"工具 {definition.name} 已注册")
        try:
            Draft202012Validator.check_schema(definition.input_schema)
            Draft202012Validator.check_schema(definition.output_schema)
        except SchemaError as exc:
            raise ValueError(f"工具 {definition.name} 的 JSON Schema 无效") from exc
        level = (
            operation_level
            if operation_level is not None
            else {
                RiskLevel.READ_ONLY: OperationLevel.L0,
                RiskLevel.ADVISORY: OperationLevel.L1,
                RiskLevel.REQUIRES_APPROVAL: OperationLevel.L2,
                RiskLevel.SENSITIVE: OperationLevel.L3,
                RiskLevel.FORBIDDEN: OperationLevel.L4,
            }[definition.risk_level]
        )
        allowed_levels = {
            RiskLevel.READ_ONLY: frozenset({OperationLevel.L0}),
            RiskLevel.ADVISORY: frozenset({OperationLevel.L1}),
            RiskLevel.REQUIRES_APPROVAL: frozenset({OperationLevel.L2, OperationLevel.L3}),
            RiskLevel.SENSITIVE: frozenset({OperationLevel.L3}),
            RiskLevel.FORBIDDEN: frozenset({OperationLevel.L4}),
        }[definition.risk_level]
        if level not in allowed_levels:
            raise ValueError("工具风险标记与确定性操作等级不一致")
        self._tools[definition.name] = RegisteredTool(definition, adapter, level)

    def lookup(self, name: str) -> RegisteredTool | None:
        """精确查找注册项，不尝试相似名称。"""
        return self._tools.get(name)

    def capabilities(self, platform: Platform) -> tuple[ToolDefinition, ...]:
        """返回当前平台的所有已注册能力，包含策略不可暴露项。"""
        return tuple(
            entry.definition
            for entry in self._tools.values()
            if platform in entry.definition.platforms
        )

    def model_tools(self, platform: Platform) -> tuple[ToolDefinition, ...]:
        """只向模型暴露当前平台明确注册的只读工具。"""
        return tuple(
            definition
            for definition in self.capabilities(platform)
            if self._tools[definition.name].operation_level is OperationLevel.L0
        )
