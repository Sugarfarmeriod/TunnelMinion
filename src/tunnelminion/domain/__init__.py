"""供 TunnelMinion 各运行时边界共享的领域模型。"""

from tunnelminion.domain.errors import ErrorCode, ToolError
from tunnelminion.domain.identifiers import (
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
from tunnelminion.domain.tools import DataSensitivity, Platform, RiskLevel, ToolDefinition
from tunnelminion.domain.versioning import ProtocolVersion, VersionCompatibility

__all__ = [
    "ArtifactId",
    "AuthorizationId",
    "DataSensitivity",
    "ErrorCode",
    "LeaseId",
    "MemoryId",
    "NodeId",
    "OperationId",
    "Platform",
    "ProtocolVersion",
    "ResourceId",
    "RiskLevel",
    "RunId",
    "ThreadId",
    "ToolDefinition",
    "ToolError",
    "ToolRunId",
    "VersionCompatibility",
]
