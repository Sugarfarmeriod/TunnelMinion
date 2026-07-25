import hashlib

import pytest

from tunnelminion.agent.context_contracts import ContextTaskType
from tunnelminion.agent.prompts import (
    PROMPT_REGISTRY,
    READONLY_AGENT_PROMPT,
    PromptRegistry,
)


def test_registry_exposes_versioned_hashed_prompts() -> None:
    definitions = PROMPT_REGISTRY.definitions

    assert len(definitions) == 5
    assert len({(item.prompt_id, item.version) for item in definitions}) == len(definitions)
    for definition in definitions:
        assert definition.semantic_version == "1.0.0"
        assert definition.content_hash == (
            f"sha256:{hashlib.sha256(definition.template.encode()).hexdigest()}"
        )
        assert definition.change_note


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
