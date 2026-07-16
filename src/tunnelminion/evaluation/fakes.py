"""供 CI 使用的确定性假模型与假工具运行时。"""

from __future__ import annotations

from collections import deque

from pydantic import BaseModel, ConfigDict

from tunnelminion.evaluation.scenario import (
    EvaluationScenario,
    ScriptedModelTurn,
    ToolFixture,
)


class FakeModel:
    """无需网络或模型 API，按照固定顺序返回动作。"""

    def __init__(self, turns: tuple[ScriptedModelTurn, ...]) -> None:
        self._turns = deque(turns)

    def next_turn(self) -> ScriptedModelTurn:
        """返回脚本中的下一个动作。"""
        if not self._turns:
            raise RuntimeError("假模型脚本已耗尽，但尚未生成最终回答")
        return self._turns.popleft()


class FakeToolRuntime:
    """根据 fixture 校验调用并记录确定性轨迹。"""

    def __init__(self, fixtures: tuple[ToolFixture, ...]) -> None:
        self._fixtures = {fixture.name: fixture for fixture in fixtures}
        self.called_tools: list[str] = []

    def call(self, name: str, arguments: dict[str, str]) -> dict[str, str]:
        """仅在名称和参数匹配时返回固定结果。"""
        fixture = self._fixtures.get(name)
        if fixture is None:
            raise LookupError(f"没有为 {name} 注册假工具 fixture")
        if arguments != fixture.expected_arguments:
            raise ValueError(f"{name} 的参数与 fixture 不匹配")
        self.called_tools.append(name)
        return fixture.result


class SmokeResult(BaseModel):
    """供 CI 冒烟场景断言的精简确定性结果。"""

    model_config = ConfigDict(frozen=True)

    scenario_id: str
    called_tools: tuple[str, ...]
    final_answer: str
    passed: bool


def run_smoke(scenario: EvaluationScenario) -> SmokeResult:
    """运行固定场景并评估基础工具及回答契约。"""
    model = FakeModel(scenario.model_script)
    tools = FakeToolRuntime(scenario.tool_fixtures)

    while True:
        turn = model.next_turn()
        if turn.tool_call is not None:
            tools.call(turn.tool_call.name, turn.tool_call.arguments)
            continue

        assert turn.final_answer is not None
        called = frozenset(tools.called_tools)
        passed = (
            scenario.expected_tools <= called
            and called.isdisjoint(scenario.forbidden_tools)
            and all(fact in turn.final_answer for fact in scenario.required_answer_facts)
        )
        return SmokeResult(
            scenario_id=scenario.scenario_id,
            called_tools=tuple(tools.called_tools),
            final_answer=turn.final_answer,
            passed=passed,
        )
