import pytest
from pydantic import ValidationError

from tunnelminion.domain import (
    DataSensitivity,
    ErrorCode,
    Platform,
    ProtocolVersion,
    RiskLevel,
    ToolDefinition,
    ToolError,
    VersionCompatibility,
)


def test_tool_definition_is_strict_and_serializable() -> None:
    definition = ToolDefinition(
        name="get_node_summary",
        version=ProtocolVersion(major=1, minor=0),
        description="返回经过脱敏的节点摘要。",
        input_schema={"type": "object", "additionalProperties": False},
        output_schema={"type": "object"},
        risk_level=RiskLevel.READ_ONLY,
        platforms=frozenset({Platform.WINDOWS, Platform.MACOS}),
        timeout_seconds=5,
        max_result_bytes=64_000,
        data_sensitivity=DataSensitivity.SYSTEM_METADATA,
    )

    assert definition.model_dump(mode="json")["risk_level"] == "read-only"
    assert definition.platforms == {Platform.WINDOWS, Platform.MACOS}


def test_tool_definition_rejects_unknown_fields() -> None:
    with pytest.raises(ValidationError):
        ToolDefinition.model_validate(
            {
                "name": "get_node_summary",
                "version": {"major": 1, "minor": 0},
                "description": "返回节点摘要。",
                "input_schema": {},
                "output_schema": {},
                "risk_level": "read-only",
                "platforms": ["windows"],
                "timeout_seconds": 5,
                "max_result_bytes": 100,
                "data_sensitivity": "system-metadata",
                "command": "whoami",
            }
        )


def test_tool_error_has_stable_machine_readable_code() -> None:
    error = ToolError(
        code=ErrorCode.NODE_UNREACHABLE,
        message="对等节点未在截止时间前响应。",
        retryable=True,
        details={"node": "B"},
    )

    assert error.model_dump(mode="json")["code"] == "node_unreachable"


def test_protocol_versions_negotiate_common_minor() -> None:
    result = VersionCompatibility.evaluate(
        ProtocolVersion(major=1, minor=3), ProtocolVersion(major=1, minor=1)
    )

    assert result.compatible is True
    assert result.negotiated == ProtocolVersion(major=1, minor=1)


def test_protocol_versions_reject_different_major() -> None:
    result = VersionCompatibility.evaluate(
        ProtocolVersion(major=2, minor=0), ProtocolVersion(major=1, minor=9)
    )

    assert result.compatible is False
    assert result.negotiated is None


def test_compatibility_model_rejects_inconsistent_result() -> None:
    with pytest.raises(ValidationError):
        VersionCompatibility(
            local=ProtocolVersion(major=1, minor=0),
            remote=ProtocolVersion(major=2, minor=0),
            compatible=True,
            negotiated=ProtocolVersion(major=1, minor=0),
        )
