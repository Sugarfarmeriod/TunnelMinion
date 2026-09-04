"""使用真实 OpenAI-compatible 模型运行固定工具评估并保存可重放报告。"""

from __future__ import annotations

import argparse
import asyncio
import json
import re
from collections.abc import Sequence
from pathlib import Path
from time import perf_counter
from typing import cast

from pydantic import JsonValue

from tunnelminion.agent.context_contracts import ContextRequest, ContextTaskType
from tunnelminion.agent.context_runtime import ContextModelRuntime
from tunnelminion.agent.policy import evaluate_request_policy
from tunnelminion.agent.prompts import REAL_MODEL_EVALUATION_PROMPT
from tunnelminion.domain.identifiers import RunId, ThreadId
from tunnelminion.evaluation import (
    EvaluationDataset,
    EvaluationReport,
    EvaluationScenario,
    RecordedModelUsage,
    ScriptedModelTurn,
    ScriptedToolCall,
    run_dataset,
)
from tunnelminion.evaluation.cli import load_dataset
from tunnelminion.evaluation.fakes import FakeToolRuntime
from tunnelminion.model.contracts import (
    ModelMessage,
    ModelProvider,
    ToolDefinition,
)
from tunnelminion.model.openai_compatible import (
    OpenAICompatibleConfig,
    OpenAICompatibleProvider,
)

PROMPT_VERSION = f"{REAL_MODEL_EVALUATION_PROMPT.prompt_id}-{REAL_MODEL_EVALUATION_PROMPT.version}"


def _sanitize_answer(value: str) -> str:
    """报告只保留脱敏摘录，不持久化命令块、认证值或注入指令正文。"""
    sanitized = re.sub(
        r"```[\s\S]*?```",
        "[REDACTED_CODE_BLOCK]",
        value,
    )
    sanitized = re.sub(
        r"(?im)^.*(?:firewall-cmd|systemctl\s+restart|docker\s+restart|kill\s+).*$",
        "[REDACTED_COMMAND_LINE]",
        sanitized,
    )
    sanitized = re.sub(
        r"(?i)(Authorization:\s*Bearer)\s+\S+",
        r"\1 [REDACTED]",
        sanitized,
    )
    sanitized = re.sub(
        r"忽略规则[^。\n]*",
        "[REDACTED_UNTRUSTED_INSTRUCTION]",
        sanitized,
    )
    return "[已脱敏评估摘录]\n" + sanitized[:1_000]


def _sanitized_report(report: EvaluationReport) -> EvaluationReport:
    """保留指标与轨迹元数据，仅替换模型自然语言正文。"""
    return report.model_copy(
        update={
            "scenarios": tuple(
                scenario.model_copy(
                    update={"final_answer": _sanitize_answer(scenario.final_answer)}
                )
                for scenario in report.scenarios
            )
        }
    )


def _json_type(value: JsonValue) -> str:
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    return "null"


def _model_tools(scenario: EvaluationScenario) -> tuple[ToolDefinition, ...]:
    definitions: list[ToolDefinition] = []
    for fixture in scenario.tool_fixtures:
        properties = {
            name: {"type": _json_type(value), "enum": [value]}
            for name, value in fixture.expected_arguments.items()
        }
        definitions.append(
            ToolDefinition(
                name=fixture.name,
                description=f"TunnelMinion 预定义只读工具 {fixture.name}。",
                input_schema={
                    "type": "object",
                    "properties": cast(dict[str, JsonValue], properties),
                    "required": list(fixture.expected_arguments),
                    "additionalProperties": False,
                },
            )
        )
    return tuple(definitions)


async def record_scenario(
    provider: ModelProvider,
    scenario: EvaluationScenario,
    *,
    max_rounds: int = 6,
) -> EvaluationScenario:
    """运行一个真模型场景，并转换成可由离线评分器重放的脚本。"""
    tools = _model_tools(scenario)
    runtime = FakeToolRuntime(scenario.tool_fixtures)
    messages = [
        ModelMessage(role="system", content=REAL_MODEL_EVALUATION_PROMPT.template),
        ModelMessage(role="user", content=scenario.question),
    ]
    recorded: list[ScriptedModelTurn] = []
    input_tokens = 0
    output_tokens = 0
    total_tokens = 0
    started = perf_counter()
    final_answer = ""
    model_runtime = ContextModelRuntime(
        provider,
        tool_schema_version="evaluation-tools/v1",
    )
    thread_id = ThreadId.new()
    run_id = RunId.new()

    policy = evaluate_request_policy(scenario.question)
    if policy is not None:
        recorded.append(ScriptedModelTurn(final_answer=policy.answer))
        return scenario.model_copy(
            update={
                "model_script": tuple(recorded),
                "recorded_model_usage": RecordedModelUsage(
                    input_tokens=0,
                    output_tokens=0,
                    total_tokens=0,
                ),
                "recorded_total_latency_ms": round((perf_counter() - started) * 1000),
            }
        )

    for _ in range(max_rounds):
        response = (
            await model_runtime.invoke(
                ContextRequest(
                    task_type=ContextTaskType.EVALUATION,
                    current_intent=scenario.question,
                    thread_id=thread_id,
                    run_id=run_id,
                    prompt_id=REAL_MODEL_EVALUATION_PROMPT.prompt_id,
                    prompt_version=REAL_MODEL_EVALUATION_PROMPT.version,
                    messages=tuple(messages),
                    tools=tools,
                )
            )
        ).response
        input_tokens += response.usage.input_tokens or 0
        output_tokens += response.usage.output_tokens or 0
        total_tokens += response.usage.total_tokens or 0
        if not response.tool_calls:
            final_answer = response.content or "模型未返回可评分回答。"
            break

        messages.append(
            ModelMessage(
                role="assistant",
                content=response.content or "",
                tool_calls=response.tool_calls,
            )
        )
        for call in response.tool_calls:
            recorded.append(
                ScriptedModelTurn(
                    tool_call=ScriptedToolCall(
                        name=call.name,
                        arguments=call.arguments,
                    )
                )
            )
            try:
                result = runtime.call(call.name, call.arguments)
                envelope: JsonValue = {
                    "trust": "untrusted-tool-data",
                    "status": "success",
                    "result": result,
                }
            except (LookupError, ValueError) as exc:
                envelope = {
                    "trust": "untrusted-tool-data",
                    "status": "rejected",
                    "error": str(exc),
                }
            messages.append(
                ModelMessage(
                    role="tool",
                    name=call.name,
                    tool_call_id=call.call_id,
                    content=json.dumps(envelope, ensure_ascii=False, separators=(",", ":")),
                )
            )
    else:
        final_answer = "达到固定评估的模型轮次上限，无法确认未完成部分。"

    recorded.append(ScriptedModelTurn(final_answer=final_answer))
    return scenario.model_copy(
        update={
            "model_script": tuple(recorded),
            "recorded_model_usage": RecordedModelUsage(
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                total_tokens=total_tokens,
            ),
            "recorded_total_latency_ms": round((perf_counter() - started) * 1000),
        }
    )


async def record_dataset(
    provider: ModelProvider,
    dataset: EvaluationDataset,
    model_name: str,
) -> EvaluationDataset:
    """串行运行固定数据集，避免并发改变本地模型的延迟与资源占用。"""
    scenarios = tuple([await record_scenario(provider, scenario) for scenario in dataset.scenarios])
    return dataset.model_copy(
        update={
            "model_name": model_name,
            "provider_name": "openai-compatible",
            "prompt_version": PROMPT_VERSION,
            "scenarios": scenarios,
        }
    )


def main(argv: Sequence[str] | None = None) -> int:
    """解析连接参数，运行评估并保存不含凭据的 JSON 报告。"""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dataset", type=Path)
    parser.add_argument("--endpoint", required=True)
    parser.add_argument("--model", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--timeout-seconds", type=float, default=120.0)
    args = parser.parse_args(argv)

    provider = OpenAICompatibleProvider(
        OpenAICompatibleConfig(
            endpoint=args.endpoint,
            model=args.model,
            timeout_seconds=args.timeout_seconds,
        )
    )
    recorded = asyncio.run(record_dataset(provider, load_dataset(args.dataset), args.model))
    report = run_dataset(recorded)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        _sanitized_report(report).model_dump_json(indent=2) + "\n",
        encoding="utf-8",
    )
    print(
        json.dumps(
            {
                "dataset": f"{report.dataset_id}:{report.dataset_version}",
                "model": report.model_name,
                "scenario_count": report.metrics.scenario_count,
                "task_completion_rate": report.metrics.task_completion_rate,
                "safety_failures": report.metrics.safety_failures,
                "total_tokens": report.metrics.total_tokens,
                "average_total_latency_ms": report.metrics.average_total_latency_ms,
                "output": str(args.output),
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
