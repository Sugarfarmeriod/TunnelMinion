import json
from pathlib import Path
from typing import Any, cast

import pytest
from pydantic import ValidationError

from tunnelminion.evaluation import (
    EvaluationScenario,
    FakeModel,
    FakeToolRuntime,
    ScriptedModelTurn,
    ScriptedToolCall,
    ToolFixture,
    run_smoke,
)


def load_smoke_scenario() -> EvaluationScenario:
    path = Path("evaluations/scenarios/local-node-summary.json")
    payload = cast(dict[str, Any], json.loads(path.read_text(encoding="utf-8")))
    return EvaluationScenario.model_validate(payload)


def test_fixed_scenario_runs_without_a_model_api() -> None:
    result = run_smoke(load_smoke_scenario())

    assert result.passed is True
    assert result.called_tools == ("get_node_summary",)
    assert "在线" in result.final_answer


def test_scripted_turn_requires_exactly_one_action() -> None:
    with pytest.raises(ValidationError):
        ScriptedModelTurn()
    with pytest.raises(ValidationError):
        ScriptedModelTurn(
            tool_call=ScriptedToolCall(name="get_node_summary", arguments={}),
            final_answer="冲突动作",
        )


def test_scenario_rejects_conflicting_tool_expectations() -> None:
    payload = load_smoke_scenario().model_dump()
    payload["forbidden_tools"] = {"get_node_summary"}

    with pytest.raises(ValidationError):
        EvaluationScenario.model_validate(payload)


def test_fake_model_fails_when_script_is_exhausted() -> None:
    model = FakeModel((ScriptedModelTurn(final_answer="完成"),))
    model.next_turn()

    with pytest.raises(RuntimeError, match="脚本已耗尽"):
        model.next_turn()


def test_fake_tool_rejects_unknown_tool_and_wrong_arguments() -> None:
    runtime = FakeToolRuntime(
        (
            ToolFixture(
                name="get_node_summary",
                expected_arguments={"node_id": "node_a"},
                result={"status": "online"},
            ),
        )
    )

    with pytest.raises(LookupError, match=r"没有.*假工具"):
        runtime.call("unknown_tool", {})
    with pytest.raises(ValueError, match="不匹配"):
        runtime.call("get_node_summary", {"node_id": "node_b"})


def test_smoke_result_fails_missing_required_fact() -> None:
    scenario = load_smoke_scenario().model_copy(
        update={"required_answer_facts": ("固定回答中不存在的事实",)}
    )

    assert run_smoke(scenario).passed is False
