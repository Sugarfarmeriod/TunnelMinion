"""把结构化上下文请求组装为快照，并隔离原始 Provider 调用。"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from uuid import uuid4

from pydantic import BaseModel, ConfigDict

from tunnelminion.agent.context_contracts import (
    ContextBudgetDecision,
    ContextContentKind,
    ContextContentReference,
    ContextRequest,
    ContextSnapshot,
    ContextTruncation,
    ContextTruncationReason,
    ContextTrust,
    RedactedContextTrace,
)
from tunnelminion.memory.context import ContextBuilder
from tunnelminion.model.contracts import (
    CancellationToken,
    ModelMessage,
    ModelProvider,
    ModelRequest,
    ModelResponse,
    ProviderError,
    ProviderErrorCode,
)


def make_context_reference(
    kind: ContextContentKind,
    source_id: str,
    content: str,
    trust: ContextTrust,
    *,
    observed_at: datetime | None = None,
) -> ContextContentReference:
    """为正文生成只含哈希和规模的脱敏来源引用。"""
    return ContextContentReference(
        kind=kind,
        source_id=source_id,
        content_hash=f"sha256:{hashlib.sha256(content.encode()).hexdigest()}",
        content_chars=len(content),
        trust=trust,
        observed_at=observed_at,
    )


class ContextInvocation(BaseModel):
    """一次 Provider 调用的不可变快照和响应。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    snapshot: ContextSnapshot
    response: ModelResponse


class ContextSnapshotBuilder:
    """在分项预算内生成可校验、可追踪的 Provider 快照。"""

    VERSION = "context-builder/v1"

    def __init__(self, builder: ContextBuilder | None = None) -> None:
        self._builder = builder

    def build(
        self,
        request: ContextRequest,
        *,
        provider_name: str,
        model_name: str,
        tool_schema_version: str,
    ) -> ContextSnapshot:
        """组装已有上下文部件，并把取舍记录到不可变快照。"""
        builder = self._builder or ContextBuilder(request.budgets)
        built = builder.build(
            request.messages,
            request.tools,
            request.tool_results,
            request.memories,
        )
        messages = self._messages_with_context(built.messages, built.tool_results, built.memories)
        model_request = ModelRequest(
            messages=messages,
            tools=built.tools,
            require_tool_call=request.require_tool_call,
            response_schema=request.response_schema,
        )
        generated_references = tuple(
            make_context_reference(
                (
                    ContextContentKind.TOOL_RESULT
                    if item.role == "tool"
                    else ContextContentKind.MESSAGE
                ),
                f"message:{index}",
                item.content,
                (
                    ContextTrust.SYSTEM_CONSTRAINT
                    if item.role == "system"
                    else ContextTrust.UNTRUSTED_DATA
                ),
            )
            for index, item in enumerate(messages)
        ) + tuple(
            make_context_reference(
                ContextContentKind.TOOL_SCHEMA,
                f"tool:{item.name}",
                json.dumps(item.model_dump(mode="json"), ensure_ascii=False, sort_keys=True),
                ContextTrust.SYSTEM_CONSTRAINT,
            )
            for item in built.tools
        )
        references = generated_references + request.evidence + request.artifact_references
        decisions = (
            ContextBudgetDecision(
                kind=ContextContentKind.MESSAGE,
                limit_chars=request.budgets.message_chars,
                used_chars=built.size.message_chars,
                included_count=len(built.messages),
                dropped_count=built.dropped.messages,
                truncated_count=0,
            ),
            ContextBudgetDecision(
                kind=ContextContentKind.TOOL_SCHEMA,
                limit_chars=request.budgets.tool_schema_chars,
                used_chars=built.size.tool_schema_chars,
                included_count=len(built.tools),
                dropped_count=built.dropped.tools,
                truncated_count=0,
            ),
            ContextBudgetDecision(
                kind=ContextContentKind.TOOL_RESULT,
                limit_chars=request.budgets.tool_result_chars,
                used_chars=built.size.tool_result_chars,
                included_count=len(built.tool_results),
                dropped_count=built.dropped.tool_results,
                truncated_count=0,
            ),
            ContextBudgetDecision(
                kind=ContextContentKind.MEMORY,
                limit_chars=request.budgets.memory_chars,
                used_chars=built.size.memory_chars,
                included_count=len(built.memories),
                dropped_count=built.dropped.memories,
                truncated_count=0,
            ),
        )
        truncations = tuple(
            ContextTruncation(
                kind=kind,
                source_id=f"{kind.value}:budget",
                reason=ContextTruncationReason.BUDGET_EXCEEDED,
                original_chars=0,
                retained_chars=0,
            )
            for kind, count in (
                (ContextContentKind.MESSAGE, built.dropped.messages),
                (ContextContentKind.TOOL_SCHEMA, built.dropped.tools),
                (ContextContentKind.TOOL_RESULT, built.dropped.tool_results),
                (ContextContentKind.MEMORY, built.dropped.memories),
            )
            if count
        )
        return ContextSnapshot(
            snapshot_id=f"context_{uuid4().hex}",
            task_type=request.task_type,
            thread_id=request.thread_id,
            run_id=request.run_id,
            created_at=datetime.now(UTC),
            builder_version=self.VERSION,
            model_request=model_request,
            content_references=references,
            budget_decisions=decisions,
            truncations=truncations,
            trace=RedactedContextTrace(
                prompt_id=request.prompt_id,
                prompt_version=request.prompt_version,
                provider_name=provider_name,
                model_name=model_name,
                builder_version=self.VERSION,
                tool_schema_version=tool_schema_version,
                message_count=len(messages),
                tool_count=len(built.tools),
                result_count=len(built.tool_results),
                memory_count=len(built.memories),
                input_chars=(
                    sum(len(item.content) for item in messages) + built.size.tool_schema_chars
                ),
            ),
        )

    @staticmethod
    def _messages_with_context(
        messages: tuple[ModelMessage, ...],
        tool_results: tuple[object, ...],
        memories: tuple[object, ...],
    ) -> tuple[ModelMessage, ...]:
        # 2.x 只迁移等价生产入口；3.x/4.x 再定义历史、结果和记忆的注入顺序。
        if tool_results or memories:
            raise ValueError("工具结果与记忆的生产注入将在后续独立阶段启用")
        return messages


class SnapshotModelProvider:
    """唯一允许把快照中的请求交给原始 Provider 的生产边界。"""

    def __init__(
        self,
        provider: ModelProvider,
        *,
        supported_builder_version: str = ContextSnapshotBuilder.VERSION,
    ) -> None:
        self._provider = provider
        self._supported_builder_version = supported_builder_version

    async def invoke(
        self,
        snapshot: ContextSnapshot,
        cancellation: CancellationToken | None = None,
    ) -> ModelResponse:
        """拒绝缺少版本关联或不兼容的上下文快照。"""
        if (
            snapshot.builder_version != self._supported_builder_version
            or snapshot.trace.builder_version != snapshot.builder_version
        ):
            raise ProviderError(ProviderErrorCode.INVALID_CONTEXT, "上下文快照版本无效")
        return await self._provider.complete(snapshot.model_request, cancellation)


class ContextModelRuntime:
    """供生产 Agent 使用的统一“请求 -> 快照 -> Provider”入口。"""

    def __init__(
        self,
        provider: ModelProvider,
        *,
        provider_name: str = "configured-provider",
        model_name: str = "configured-model",
        tool_schema_version: str = "unversioned-tools",
        builder: ContextSnapshotBuilder | None = None,
    ) -> None:
        self._builder = builder or ContextSnapshotBuilder()
        self._provider = SnapshotModelProvider(provider)
        self._provider_name = provider_name
        self._model_name = model_name
        self._tool_schema_version = tool_schema_version

    async def invoke(
        self,
        request: ContextRequest,
        cancellation: CancellationToken | None = None,
    ) -> ContextInvocation:
        """构造一次有效快照，且每个请求只调用 Provider 一次。"""
        snapshot = self._builder.build(
            request,
            provider_name=self._provider_name,
            model_name=self._model_name,
            tool_schema_version=self._tool_schema_version,
        )
        response = await self._provider.invoke(snapshot, cancellation)
        return ContextInvocation(snapshot=snapshot, response=response)
