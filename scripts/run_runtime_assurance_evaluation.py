"""运行上下文可观测性、失败归因、零泄漏和安全降级门禁。"""

from __future__ import annotations

import argparse
import asyncio
import json
from collections.abc import Sequence
from pathlib import Path
from time import perf_counter

from pydantic import BaseModel, ConfigDict, Field

from tunnelminion.agent.context_contracts import (
    ContextContentKind,
    ContextRequest,
    FailurePhase,
)
from tunnelminion.agent.context_runtime import (
    ContextBuildError,
    ContextModelRuntime,
    ContextSnapshotBuilder,
)
from tunnelminion.agent.observability import classify_failure
from tunnelminion.agent.policy import evaluate_request_policy
from tunnelminion.agent.prompts import READONLY_AGENT_PROMPT
from tunnelminion.domain.errors import ErrorCode, ToolError
from tunnelminion.domain.identifiers import RunId, ThreadId
from tunnelminion.model.contracts import (
    CancellationToken,
    ModelCapabilities,
    ModelMessage,
    ModelRequest,
    ModelResponse,
    ProviderError,
    ProviderErrorCode,
    ToolDefinition,
)
from tunnelminion.tools.contracts import ToolAdapterError


class CountingProvider:
    """记录是否越过 ContextBuilder 失败边界的固定 Provider。"""

    def __init__(self) -> None:
        self.calls = 0

    @property
    def capabilities(self) -> ModelCapabilities:
        return ModelCapabilities(tool_calls=True, structured_output=True)

    async def complete(
        self,
        request: ModelRequest,
        cancellation: CancellationToken | None = None,
    ) -> ModelResponse:
        del request, cancellation
        self.calls += 1
        return ModelResponse(content="ok")


class RuntimeAssuranceMetrics(BaseModel):
    """7.x 阶段可重复计算的运行保障指标。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    scenario_count: int = Field(ge=1)
    observability_completeness_rate: float = Field(ge=0, le=1)
    failure_classification_rate: float = Field(ge=0, le=1)
    fault_isolation_rate: float = Field(ge=0, le=1)
    metadata_leakage_rate: float = Field(ge=0, le=1)
    deterministic_degradation_rate: float = Field(ge=0, le=1)
    average_builder_latency_ms: float = Field(ge=0)
    provider_tokens: int = Field(ge=0)
    estimated_cost: float = Field(ge=0)


class RuntimeAssuranceReport(BaseModel):
    """带运行保障策略版本的阶段评测报告。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: int = 1
    change: str
    stage: str
    assurance_policy: str
    metrics: RuntimeAssuranceMetrics
    notes: tuple[str, ...]


def _request(*, prompt_id: str = "readonly-agent") -> ContextRequest:
    private_value = "cross-node-private-body-" + ("x" * 40)
    credential_value = "credential-value-" + ("y" * 32)
    return ContextRequest(
        task_type=READONLY_AGENT_PROMPT.task_type,
        current_intent="读取节点状态",
        thread_id=ThreadId.new(),
        run_id=RunId.new(),
        prompt_id=prompt_id,
        prompt_version=READONLY_AGENT_PROMPT.version,
        messages=(
            ModelMessage(role="system", content=READONLY_AGENT_PROMPT.template),
            ModelMessage(
                role="user",
                content=f"{private_value}; authorization={credential_value}",
            ),
        ),
        tools=(
            ToolDefinition(
                name="node_summary",
                description="读取节点摘要",
                input_schema={"type": "object", "properties": {}},
            ),
        ),
    )


def evaluate(iterations: int = 100) -> RuntimeAssuranceReport:
    """验证失败不会调用 Provider，元数据不含正文，确定性治理仍可用。"""
    provider = CountingProvider()
    try:
        asyncio.run(
            ContextModelRuntime(provider).invoke(
                _request(prompt_id="unregistered"),
            )
        )
    except ContextBuildError:
        context_stopped = True
    else:
        context_stopped = False

    builder = ContextSnapshotBuilder()
    started = perf_counter()
    snapshots = tuple(
        builder.build(
            _request(),
            provider_name="offline",
            model_name="none",
            tool_schema_version="readonly-tools/v1",
        )
        for _ in range(iterations)
    )
    average_latency = (perf_counter() - started) * 1_000 / iterations
    latest = snapshots[-1]
    expected_kinds = {
        ContextContentKind.MESSAGE,
        ContextContentKind.TOOL_SCHEMA,
        ContextContentKind.TOOL_RESULT,
        ContextContentKind.ARTIFACT,
        ContextContentKind.MEMORY,
        ContextContentKind.EVIDENCE,
        ContextContentKind.HISTORY_SUMMARY,
    }
    metadata = json.dumps(
        {
            "trace": latest.trace.model_dump(mode="json"),
            "composition": [item.model_dump(mode="json") for item in latest.composition],
            "budgets": [item.model_dump(mode="json") for item in latest.budget_decisions],
            "truncations": [item.model_dump(mode="json") for item in latest.truncations],
            "references": [item.model_dump(mode="json") for item in latest.content_references],
        },
        ensure_ascii=False,
    )
    failures = (
        classify_failure(
            ValueError("private-context"),
            phase=FailurePhase.CONTEXT_BUILD,
        ),
        classify_failure(
            ProviderError(ProviderErrorCode.TIMEOUT, "private-provider"),
            phase=FailurePhase.MODEL_INVOKE,
        ),
        classify_failure(
            ToolAdapterError(ToolError(code=ErrorCode.TIMEOUT, message="private-tool")),
            phase=FailurePhase.TOOL_EXECUTE,
        ),
        classify_failure(
            PermissionError("private-governance"),
            phase=FailurePhase.GOVERNANCE_CHECK,
        ),
    )
    serialized_failures = "".join(item.model_dump_json() for item in failures)
    categories = {item.category.value for item in failures}
    policy = evaluate_request_policy("请重启远端服务")
    leaked = any(
        marker in metadata or marker in serialized_failures
        for marker in (
            "cross-node-private-body",
            "credential-value",
            "private-context",
            "private-provider",
            "private-tool",
            "private-governance",
        )
    )
    scenarios = (
        {item.kind for item in latest.composition} == expected_kinds,
        all(item.limit_chars >= item.used_chars for item in latest.budget_decisions),
        categories == {"context", "prompt_or_model", "harness_or_tool", "governance"},
        context_stopped and provider.calls == 0,
        not leaked,
        policy is not None and "策略拒绝" in policy.answer,
    )
    return RuntimeAssuranceReport(
        change="integrate-agent-context-and-prompt-runtime",
        stage="runtime-assurance",
        assurance_policy="redacted-observability/v1",
        metrics=RuntimeAssuranceMetrics(
            scenario_count=len(scenarios),
            observability_completeness_rate=1.0 if all(scenarios[:2]) else 0.0,
            failure_classification_rate=1.0 if scenarios[2] else 0.0,
            fault_isolation_rate=1.0 if scenarios[3] else 0.0,
            metadata_leakage_rate=0.0 if scenarios[4] else 1.0,
            deterministic_degradation_rate=1.0 if scenarios[5] else 0.0,
            average_builder_latency_ms=average_latency,
            provider_tokens=0,
            estimated_cost=0.0,
        ),
        notes=(
            "本门禁不调用真实模型；故障注入必须在 Provider 前停止。",
            "资源 API 与操作控制面的实际降级可用性由集成测试验证。",
        ),
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    report = evaluate()
    serialized = report.model_dump_json(indent=2) + "\n"
    if args.output is None:
        print(json.dumps(report.model_dump(mode="json"), ensure_ascii=False, indent=2))
    else:
        args.output.write_text(serialized, encoding="utf-8")
    metrics = report.metrics
    if args.check and (
        metrics.observability_completeness_rate != 1.0
        or metrics.failure_classification_rate != 1.0
        or metrics.fault_isolation_rate != 1.0
        or metrics.metadata_leakage_rate != 0.0
        or metrics.deterministic_degradation_rate != 1.0
        or metrics.average_builder_latency_ms > 50
    ):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
