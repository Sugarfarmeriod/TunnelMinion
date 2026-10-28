"""调用主模型前分类请求，分类失败时由工具权限边界继续把关。"""

from __future__ import annotations

import asyncio
import json
from enum import StrEnum
from time import perf_counter
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from tunnelminion.agent.context_contracts import ContextRequest, ContextTaskType
from tunnelminion.agent.context_runtime import ContextBuildError, ContextModelRuntime
from tunnelminion.agent.policy import (
    OFF_TOPIC_REFUSAL,
    SECRET_ACCESS_REFUSAL,
    WRITE_OPERATION_REFUSAL,
    RequestPolicyDecision,
)
from tunnelminion.agent.prompts import REQUEST_GATE_PROMPT
from tunnelminion.domain.identifiers import RunId, ThreadId
from tunnelminion.model.contracts import (
    CancellationToken,
    ModelMessage,
    ModelProvider,
    ModelUsage,
    ProviderError,
)


class RequestGateOutcome(StrEnum):
    """请求分类是否正常完成，以及是否提前拒绝。"""

    ALLOWED = "allowed"
    REFUSED = "refused"
    FAILED_OPEN = "failed_open"


class RequestGateResult(BaseModel):
    """分类结论与实际可获得的模型用量。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    decision: RequestPolicyDecision | None
    usage: ModelUsage
    elapsed_ms: float = Field(ge=0)
    outcome: RequestGateOutcome


class _Classification(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    category: Literal["allowed", "secret", "dangerous", "off_topic"]


_REFUSALS = {
    "secret": RequestPolicyDecision(code="secret_access_refused", answer=SECRET_ACCESS_REFUSAL),
    "dangerous": RequestPolicyDecision(
        code="write_operation_refused", answer=WRITE_OPERATION_REFUSAL
    ),
    "off_topic": RequestPolicyDecision(code="off_topic_refused", answer=OFF_TOPIC_REFUSAL),
}


# 分类结果只有十来个 token，但思考型模型的思考内容也计入 max_tokens：
# deepseek-flash 实测一次分类用掉 54-64 个输出 token，256 为思考留出余量。
# 计费按实际用量，放宽上限不增加正常调用的消耗。
REQUEST_GATE_MAX_OUTPUT_TOKENS = 256


class RequestGate:
    """用同一 Provider 的短结构化调用节省无关请求的主模型额度。"""

    def __init__(
        self,
        provider: ModelProvider,
        *,
        provider_name: str,
        model_name: str,
        timeout_seconds: float = 10.0,
        max_output_tokens: int = REQUEST_GATE_MAX_OUTPUT_TOKENS,
    ) -> None:
        self._provider = provider
        self._runtime = ContextModelRuntime(
            provider,
            provider_name=provider_name,
            model_name=model_name,
            tool_schema_version="request-gate/v1",
        )
        self._timeout_seconds = timeout_seconds
        self._max_output_tokens = max_output_tokens

    async def evaluate(
        self, question: str, *, thread_id: ThreadId, run_id: RunId
    ) -> RequestGateResult:
        """只采用合法分类；超时与模型协议失败均放行，调用取消继续向上传播。"""
        started = perf_counter()
        cancellation = CancellationToken()
        usage = ModelUsage()
        decision = None
        outcome = RequestGateOutcome.FAILED_OPEN
        try:
            if self._provider.capabilities.structured_output:
                invocation = await asyncio.wait_for(
                    self._runtime.invoke(
                        ContextRequest(
                            task_type=ContextTaskType.REQUEST_GATE,
                            current_intent="调用主模型前分类用户请求",
                            thread_id=thread_id,
                            run_id=run_id,
                            prompt_id=REQUEST_GATE_PROMPT.prompt_id,
                            prompt_version=REQUEST_GATE_PROMPT.version,
                            messages=(
                                ModelMessage(role="system", content=REQUEST_GATE_PROMPT.template),
                                ModelMessage(role="user", content=question[:2000]),
                            ),
                            response_schema={
                                "type": "object",
                                "properties": {
                                    "category": {
                                        "type": "string",
                                        "enum": ["allowed", "secret", "dangerous", "off_topic"],
                                    }
                                },
                                "required": ["category"],
                                "additionalProperties": False,
                            },
                            max_output_tokens=self._max_output_tokens,
                        ),
                        cancellation,
                    ),
                    timeout=self._timeout_seconds,
                )
                response = invocation.response
                usage = response.usage
                if not response.tool_calls:
                    value = (
                        response.structured_output
                        if response.structured_output is not None
                        else json.loads(response.content or "")
                    )
                    category = _Classification.model_validate(value).category
                    decision = _REFUSALS.get(category)
                    outcome = (
                        RequestGateOutcome.REFUSED
                        if decision is not None
                        else RequestGateOutcome.ALLOWED
                    )
        except asyncio.CancelledError:
            cancellation.cancel()
            raise
        except (
            ProviderError,
            ContextBuildError,
            TimeoutError,
            ValidationError,
            json.JSONDecodeError,
        ):
            cancellation.cancel()
        return RequestGateResult(
            decision=decision,
            usage=usage,
            elapsed_ms=(perf_counter() - started) * 1000,
            outcome=outcome,
        )
