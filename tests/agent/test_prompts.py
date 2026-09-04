import hashlib

import pytest

from tunnelminion.agent.context_contracts import ContextTaskType
from tunnelminion.agent.prompts import (
    INCIDENT_INVESTIGATION_PROMPT,
    PROMPT_REGISTRY,
    READONLY_AGENT_PROMPT,
    REAL_MODEL_EVALUATION_PROMPT,
    PromptRegistry,
)


def test_registry_exposes_versioned_hashed_prompts() -> None:
    definitions = PROMPT_REGISTRY.definitions

    assert len(definitions) == 7
    assert len({(item.prompt_id, item.version) for item in definitions}) == len(definitions)
    for definition in definitions:
        assert definition.content_hash == (
            f"sha256:{hashlib.sha256(definition.template.encode()).hexdigest()}"
        )
        assert definition.change_note

    assert INCIDENT_INVESTIGATION_PROMPT.version == "v2"
    assert INCIDENT_INVESTIGATION_PROMPT.semantic_version == "2.0.0"

    assert (
        PROMPT_REGISTRY.resolve(
            REAL_MODEL_EVALUATION_PROMPT.prompt_id,
            REAL_MODEL_EVALUATION_PROMPT.version,
            ContextTaskType.EVALUATION,
        )
        == REAL_MODEL_EVALUATION_PROMPT
    )
    assert "不得拼接状态、说明或自造标签" in INCIDENT_INVESTIGATION_PROMPT.template
    assert "至少引用一项真实 `toolrun_...` 证据" in INCIDENT_INVESTIGATION_PROMPT.template


def test_registry_rejects_duplicate_unknown_and_task_mismatch() -> None:
    with pytest.raises(ValueError, match="必须唯一"):
        PromptRegistry((READONLY_AGENT_PROMPT, READONLY_AGENT_PROMPT))
    with pytest.raises(ValueError, match="prompt_not_registered"):
        PROMPT_REGISTRY.resolve(
            "unknown",
            "v1",
            ContextTaskType.LOCAL_CONVERSATION,
        )
    with pytest.raises(ValueError, match="prompt_task_mismatch"):
        PROMPT_REGISTRY.resolve(
            READONLY_AGENT_PROMPT.prompt_id,
            READONLY_AGENT_PROMPT.version,
            ContextTaskType.OPERATION_PLAN,
        )
