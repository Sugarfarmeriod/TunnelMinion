import pytest
from pydantic import ValidationError

from tunnelminion.domain import (
    ArtifactId,
    AuthorizationId,
    LeaseId,
    MemoryId,
    NodeId,
    OperationId,
    ResourceId,
    RunId,
    ThreadId,
    ToolRunId,
)


@pytest.mark.parametrize("identifier_type", [NodeId, ThreadId, RunId, ToolRunId])
def test_identifiers_generate_unique_prefixed_values(identifier_type: type[NodeId]) -> None:
    first = identifier_type.new()
    second = identifier_type.new()

    assert first != second
    assert str(first).startswith(f"{identifier_type.prefix}_")
    assert first.model_dump() == str(first)


def test_identifier_rejects_wrong_prefix() -> None:
    with pytest.raises(ValidationError):
        NodeId("run_0123456789abcdef0123456789abcdef")


@pytest.mark.parametrize(
    "identifier_type",
    [ArtifactId, MemoryId, OperationId, AuthorizationId, LeaseId, ResourceId],
)
def test_storage_identifiers_are_stable(
    identifier_type: type[
        ArtifactId | MemoryId | OperationId | AuthorizationId | LeaseId | ResourceId
    ],
) -> None:
    value = identifier_type.new()
    assert str(value).startswith(f"{identifier_type.prefix}_")
