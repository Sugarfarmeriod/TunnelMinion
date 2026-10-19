import hashlib

import pytest

from tunnelminion.agent.context_contracts import ContextTaskType
from tunnelminion.agent.prompts import (
    INCIDENT_INVESTIGATION_PROMPT,
    PROMPT_REGISTRY,
    READONLY_AGENT_PROMPT,
    READONLY_AGENT_PROMPT_V1,
    READONLY_AGENT_PROMPT_V2,
    READONLY_AGENT_PROMPT_V3,
    REAL_MODEL_EVALUATION_PROMPT,
    PromptRegistry,
)


def test_registry_exposes_versioned_hashed_prompts() -> None:
    definitions = PROMPT_REGISTRY.definitions

    assert len(definitions) == 10
    assert len({(item.prompt_id, item.version) for item in definitions}) == len(definitions)
    for definition in definitions:
        assert definition.content_hash == (
            f"sha256:{hashlib.sha256(definition.template.encode()).hexdigest()}"
        )
        assert definition.change_note

    assert INCIDENT_INVESTIGATION_PROMPT.version == "v3"
    assert INCIDENT_INVESTIGATION_PROMPT.semantic_version == "3.0.0"
    assert READONLY_AGENT_PROMPT.version == "v4"
    assert "read_investigation_skill" in READONLY_AGENT_PROMPT.template
    assert (
        PROMPT_REGISTRY.resolve("readonly-agent", "v3", ContextTaskType.LOCAL_CONVERSATION)
        == READONLY_AGENT_PROMPT_V3
    )
    assert "不使用 Markdown" in READONLY_AGENT_PROMPT.template
    assert "没有实际检查的部分必须说还不能确认" in READONLY_AGENT_PROMPT.template
    assert "不建议向所有设备开放" in READONLY_AGENT_PROMPT.template
    assert "只调查用户当前提到的程序和问题" in READONLY_AGENT_PROMPT.template
    assert "不得声称执行了修改" in READONLY_AGENT_PROMPT.template
    assert (
        PROMPT_REGISTRY.resolve("readonly-agent", "v1", ContextTaskType.LOCAL_CONVERSATION)
        == READONLY_AGENT_PROMPT_V1
    )
    assert READONLY_AGENT_PROMPT_V1.content_hash == (
        "sha256:863e16161fb8fb816156bd95acaec5c6784081972a090769b6a0a8700b4ec839"
    )
    assert (
        PROMPT_REGISTRY.resolve("readonly-agent", "v2", ContextTaskType.LOCAL_CONVERSATION)
        == READONLY_AGENT_PROMPT_V2
    )
    assert READONLY_AGENT_PROMPT_V2.content_hash == (
        "sha256:2b2a6547eeca0dcc4edcccbcc74a4dc9002bc8f1eb75f87e7c85a79f3f85efc8"
    )

    assert (
        PROMPT_REGISTRY.resolve(
            REAL_MODEL_EVALUATION_PROMPT.prompt_id,
            REAL_MODEL_EVALUATION_PROMPT.version,
            ContextTaskType.EVALUATION,
        )
        == REAL_MODEL_EVALUATION_PROMPT
    )
    assert "不得拼接状态、说明或自造标签" in INCIDENT_INVESTIGATION_PROMPT.template
    assert "information_gaps 非空时" in INCIDENT_INVESTIGATION_PROMPT.template
    assert "required_arguments_this_round" in INCIDENT_INVESTIGATION_PROMPT.template
    assert "不得只复述" in INCIDENT_INVESTIGATION_PROMPT.template
    assert "120 个汉字" in INCIDENT_INVESTIGATION_PROMPT.template
    assert "successful_evidence 中全部真实 `toolrun_...` 证据" in (
        INCIDENT_INVESTIGATION_PROMPT.template
    )


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
