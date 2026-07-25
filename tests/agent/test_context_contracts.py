from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from tunnelminion.agent.context_contracts import (
    ContextBudgetDecision,
    ContextContentKind,
    ContextContentReference,
    ContextRequest,
    ContextSnapshot,
    ContextTaskType,
    ContextTrust,
    RedactedContextTrace,
)
from tunnelminion.domain.identifiers import RunId, ThreadId
from tunnelminion.model.contracts import ModelMessage, ModelRequest


def _trace() -> RedactedContextTrace:
    return RedactedContextTrace(
        prompt_id="readonly-agent",
        prompt_version="v1",
        provider_name="openai-compatible",
        model_name="qwen",
        builder_version="v1",
        tool_schema_version="readonly-tools/v1",
        message_count=1,
        tool_count=0,
        result_count=0,
        memory_count=0,
        input_chars=4,
    )


def test_context_request_and_snapshot_are_frozen_and_traceable() -> None:
    thread_id = ThreadId.new()
    run_id = RunId.new()
    message = ModelMessage(role="user", content="状态？")
    reference = ContextContentReference(
        kind=ContextContentKind.MESSAGE,
        source_id="message:current",
        content_hash=f"sha256:{'a' * 64}",
        content_chars=3,
        trust=ContextTrust.UNTRUSTED_DATA,
    )
    request = ContextRequest(
        task_type=ContextTaskType.LOCAL_CONVERSATION,
        current_intent="查看节点状态",
        thread_id=thread_id,
        run_id=run_id,
        prompt_id="readonly-agent",
        prompt_version="v1",
        messages=(message,),
        evidence=(reference,),
    )
    snapshot = ContextSnapshot(
        snapshot_id=f"context_{'b' * 32}",
        task_type=request.task_type,
        thread_id=thread_id,
        run_id=run_id,
        created_at=datetime.now(UTC),
        builder_version="v1",
        model_request=ModelRequest(messages=(message,)),
        content_references=(reference,),
        budget_decisions=(
            ContextBudgetDecision(
                kind=ContextContentKind.MESSAGE,
                limit_chars=16_000,
                used_chars=3,
                included_count=1,
                dropped_count=0,
                truncated_count=0,
            ),
        ),
        trace=_trace(),
    )

    assert snapshot.trace.model_name == "qwen"
    assert snapshot.model_request.messages == request.messages
    with pytest.raises(ValidationError):
        snapshot.task_type = ContextTaskType.EVALUATION


def test_context_contracts_reject_untracked_hash_and_unknown_trace_fields() -> None:
    with pytest.raises(ValidationError):
        ContextContentReference(
            kind=ContextContentKind.EVIDENCE,
            source_id="toolrun:1",
            content_hash="raw-evidence",
            content_chars=10,
            trust=ContextTrust.VERIFIED_EVIDENCE,
        )

    with pytest.raises(ValidationError):
        RedactedContextTrace.model_validate(
            _trace().model_dump() | {"authorization": "Bearer secret"}
        )
