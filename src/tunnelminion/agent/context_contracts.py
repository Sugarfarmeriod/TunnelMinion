"""统一生产模型调用使用的上下文请求与不可变快照契约。"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, JsonValue

from tunnelminion.domain.identifiers import ArtifactId, RunId, ThreadId
from tunnelminion.memory.context import (
    ContextBudgets,
    ToolResultContext,
)
from tunnelminion.memory.contracts import LongTermMemory
from tunnelminion.model.contracts import ModelMessage, ModelRequest, ToolDefinition


class ContextTaskType(StrEnum):
    """决定 prompt、工具集合和分项预算的生产任务类型。"""

    LOCAL_CONVERSATION = "local-conversation"
    CROSS_NODE_DIAGNOSTIC = "cross-node-diagnostic"
    OPERATION_PLAN = "operation-plan"
    PROVIDER_VALIDATION = "provider-validation"
    EVALUATION = "evaluation"


class ContextContentKind(StrEnum):
    """快照中可独立预算、追踪和裁剪的内容类别。"""

    PROMPT = "prompt"
    MESSAGE = "message"
    TOOL_SCHEMA = "tool-schema"
    TOOL_RESULT = "tool-result"
    EVIDENCE = "evidence"
    MEMORY = "memory"
    ARTIFACT = "artifact"
    HISTORY_SUMMARY = "history-summary"
    WORKFLOW_STATE = "workflow-state"


class ContextTrust(StrEnum):
    """内容在进入 prompt 前的确定性信任边界。"""

    SYSTEM_CONSTRAINT = "system-constraint"
    VERIFIED_EVIDENCE = "verified-evidence"
    USER_CONFIRMED = "user-confirmed"
    UNTRUSTED_DATA = "untrusted-data"


class ContextTruncationReason(StrEnum):
    """内容未进入快照或只保留预览的稳定原因。"""

    BUDGET_EXCEEDED = "budget-exceeded"
    OVERSIZED_RESULT_ARTIFACT = "oversized-result-artifact"
    STALE = "stale"
    SCOPE_MISMATCH = "scope-mismatch"
    UNCONFIRMED = "unconfirmed"
    SUPERSEDED = "superseded"
    DELETED = "deleted"
    REDACTED = "redacted"
    SUMMARY_FAILED = "summary-failed"


class ContextContentReference(BaseModel):
    """不复制敏感正文的内容来源、规模和完整性引用。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: ContextContentKind
    source_id: str = Field(min_length=1, max_length=256)
    content_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    content_chars: int = Field(ge=0)
    trust: ContextTrust
    observed_at: datetime | None = None
    artifact_id: ArtifactId | None = None


class ContextBudgetDecision(BaseModel):
    """某类内容的预算使用和确定性取舍结果。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: ContextContentKind
    limit_chars: int = Field(ge=0)
    used_chars: int = Field(ge=0)
    included_count: int = Field(ge=0)
    dropped_count: int = Field(ge=0)
    truncated_count: int = Field(ge=0)


class ContextCompositionMetric(BaseModel):
    """一种上下文内容的数量和原始字符规模。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: ContextContentKind
    count: int = Field(ge=0)
    chars: int = Field(ge=0)


class ContextTruncation(BaseModel):
    """单个来源被裁剪、排除或制品化的审计决定。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: ContextContentKind
    source_id: str = Field(min_length=1, max_length=256)
    reason: ContextTruncationReason
    original_chars: int = Field(ge=0)
    retained_chars: int = Field(ge=0)


class RedactedContextTrace(BaseModel):
    """普通日志可保存的脱敏快照组成，不包含消息或凭据正文。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    prompt_id: str = Field(min_length=1, max_length=128)
    prompt_version: str = Field(min_length=1, max_length=64)
    prompt_content_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    provider_name: str = Field(min_length=1, max_length=128)
    model_name: str = Field(min_length=1, max_length=256)
    builder_version: str = Field(min_length=1, max_length=64)
    tool_schema_version: str = Field(min_length=1, max_length=128)
    message_count: int = Field(ge=0)
    tool_count: int = Field(ge=0)
    result_count: int = Field(ge=0)
    memory_count: int = Field(ge=0)
    input_chars: int = Field(ge=0)
    model_parameters: dict[str, JsonValue] = Field(default_factory=dict)
    input_summary_hashes: tuple[str, ...] = ()


class FailureCategory(StrEnum):
    """跨生产与评估共用的四类主失败工程边界。"""

    CONTEXT = "context"
    PROMPT_OR_MODEL = "prompt_or_model"
    HARNESS_OR_TOOL = "harness_or_tool"
    GOVERNANCE = "governance"


class FailurePhase(StrEnum):
    """失败发生的稳定阶段，不包含异常正文。"""

    CONTEXT_BUILD = "context-build"
    HISTORY_SUMMARY = "history-summary"
    MODEL_INVOKE = "model-invoke"
    TOOL_EXECUTE = "tool-execute"
    AGENT_RUNTIME = "agent-runtime"
    GOVERNANCE_CHECK = "governance-check"


class FailureReason(StrEnum):
    """可审计、可聚合且不会携带秘密的次级原因。"""

    CONTEXT_INVALID = "context_invalid"
    SUMMARY_FAILED = "summary_failed"
    MODEL_AUTHENTICATION_FAILED = "model_authentication_failed"
    MODEL_NOT_FOUND = "model_not_found"
    MODEL_TIMEOUT = "model_timeout"
    MODEL_NETWORK_UNREACHABLE = "model_network_unreachable"
    MODEL_INVALID_RESPONSE = "model_invalid_response"
    MODEL_CAPABILITY_INCOMPATIBLE = "model_capability_incompatible"
    MODEL_CANCELLED = "model_cancelled"
    TOOL_FAILED = "tool_failed"
    AGENT_RUNTIME_FAILED = "agent_runtime_failed"
    GOVERNANCE_DENIED = "governance_denied"


class FailureRecord(BaseModel):
    """普通日志与 checkpoint 可保存的脱敏失败归因。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    category: FailureCategory
    phase: FailurePhase
    reason: FailureReason
    retryable: bool = False
    occurred_at: datetime
    source_refs: tuple[str, ...] = ()


class RedactedContextRecord(BaseModel):
    """一次成功模型调用的可复现元数据，不包含输入或输出正文。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    snapshot_id: str = Field(pattern=r"^context_[0-9a-f]{32}$")
    created_at: datetime
    trace: RedactedContextTrace
    composition: tuple[ContextCompositionMetric, ...]
    budget_decisions: tuple[ContextBudgetDecision, ...]
    truncations: tuple[ContextTruncation, ...] = ()
    latency_ms: float = Field(ge=0)
    input_tokens: int | None = Field(default=None, ge=0)
    output_tokens: int | None = Field(default=None, ge=0)
    total_tokens: int | None = Field(default=None, ge=0)
    estimated_cost: None = None


class RollingSummary(BaseModel):
    """更早 thread 消息的版本化导航摘要，不承担安全约束或实时事实。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    version: str = Field(pattern=r"^rolling-summary/v[1-9][0-9]*$")
    content: str = Field(min_length=1, max_length=20_000)
    covered_message_count: int = Field(ge=1)
    source_message_refs: tuple[str, ...] = Field(min_length=1)
    generated_at: datetime
    invalidation_conditions: tuple[str, ...] = Field(min_length=1)


class WorkflowContextState(BaseModel):
    """不得依赖自由文本摘要恢复的未完成工作流状态。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    status: str = Field(min_length=1, max_length=64)
    pending_steps: tuple[str, ...] = ()
    source_run_ids: tuple[RunId, ...] = ()
    safety_constraints: tuple[str, ...] = Field(min_length=1)


class HistoryContext(BaseModel):
    """独立预算后的近期原文、滚动摘要与结构化工作流状态。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    recent_messages: tuple[ModelMessage, ...] = ()
    rolling_summary: RollingSummary | None = None
    workflow_state: WorkflowContextState | None = None
    dropped_message_count: int = Field(ge=0)
    history_chars: int = Field(ge=0)
    summary_error_code: str | None = Field(default=None, max_length=128)


class FactSource(StrEnum):
    """越靠前越可信的确定性事实来源。"""

    REALTIME_EVIDENCE = "realtime-evidence"
    CONFIRMED_MEMORY = "confirmed-memory"
    HISTORY = "history"
    MODEL_INFERENCE = "model-inference"


class ContextFact(BaseModel):
    """可按稳定键比较的事实候选。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    key: str = Field(min_length=1, max_length=256)
    value: str = Field(min_length=1, max_length=20_000)
    source: FactSource
    source_id: str = Field(min_length=1, max_length=256)
    observed_at: datetime | None = None


class ResolvedFact(BaseModel):
    """确定性优先级选出的当前事实。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    key: str
    value: str
    source: FactSource
    source_id: str
    observed_at: datetime | None = None


class FactConflict(BaseModel):
    """被更高优先级或更新来源否决的陈旧事实。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    key: str
    selected_source_id: str
    stale_value: str
    stale_source: FactSource
    stale_source_id: str
    reason: str = "lower-priority-or-older"


class ContextRequest(BaseModel):
    """Agent 提交给 ContextBuilder 的结构化输入，不能直接交给 Provider。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    task_type: ContextTaskType
    current_intent: str = Field(min_length=1, max_length=20_000)
    thread_id: ThreadId
    run_id: RunId
    prompt_id: str = Field(min_length=1, max_length=128)
    prompt_version: str = Field(min_length=1, max_length=64)
    model_parameters: dict[str, JsonValue] = Field(default_factory=dict)
    messages: tuple[ModelMessage, ...] = ()
    tools: tuple[ToolDefinition, ...] = ()
    tool_results: tuple[ToolResultContext, ...] = ()
    memories: tuple[LongTermMemory, ...] = ()
    evidence: tuple[ContextContentReference, ...] = ()
    artifact_references: tuple[ContextContentReference, ...] = ()
    budgets: ContextBudgets = Field(default_factory=ContextBudgets)
    require_tool_call: bool = False
    response_schema: dict[str, JsonValue] | None = None
    history: HistoryContext | None = None
    facts: tuple[ContextFact, ...] = ()


class ContextSnapshot(BaseModel):
    """Builder 生成且 Provider 边界将校验的不可变、可追踪上下文。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    snapshot_id: str = Field(pattern=r"^context_[0-9a-f]{32}$")
    task_type: ContextTaskType
    thread_id: ThreadId
    run_id: RunId
    created_at: datetime
    builder_version: str = Field(min_length=1, max_length=64)
    model_request: ModelRequest
    content_references: tuple[ContextContentReference, ...]
    composition: tuple[ContextCompositionMetric, ...]
    budget_decisions: tuple[ContextBudgetDecision, ...]
    truncations: tuple[ContextTruncation, ...] = ()
    resolved_facts: tuple[ResolvedFact, ...] = ()
    fact_conflicts: tuple[FactConflict, ...] = ()
    trace: RedactedContextTrace
