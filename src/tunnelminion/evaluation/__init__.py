"""确定性的 Agent 评估基础组件。"""

from tunnelminion.evaluation.fakes import FakeModel, FakeToolRuntime, SmokeResult, run_smoke
from tunnelminion.evaluation.scenario import (
    EvaluationScenario,
    ScriptedModelTurn,
    ScriptedToolCall,
    ToolFixture,
)

__all__ = [
    "EvaluationScenario",
    "FakeModel",
    "FakeToolRuntime",
    "ScriptedModelTurn",
    "ScriptedToolCall",
    "SmokeResult",
    "ToolFixture",
    "run_smoke",
]
