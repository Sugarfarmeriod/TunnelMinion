"""供 TunnelMinion 各运行时边界共享的领域模型。"""

from tunnelminion.domain.errors import ErrorCode, ToolError
from tunnelminion.domain.identifiers import (
    ArtifactId,
    AuthorizationId,
    CoordinatorAuditId,
    EnrollmentTokenId,
    IncidentId,
    LeaseId,
    MemoryId,
    NetworkId,
    NodeId,
    OperationId,
    RefreshCredentialId,
    ResourceId,
    RunId,
    ServiceId,
    SnapshotId,
    ThreadId,
    ToolRunId,
)
from tunnelminion.domain.tools import DataSensitivity, Platform, RiskLevel, ToolDefinition
from tunnelminion.domain.versioning import ProtocolVersion, VersionCompatibility

__all__ = [
    "ArtifactId",
    "AuthorizationId",
    "CoordinatorAuditId",
    "DataSensitivity",
    "EnrollmentTokenId",
    "ErrorCode",
    "IncidentId",
    "LeaseId",
    "MemoryId",
    "NetworkId",
    "NodeId",
    "OperationId",
    "Platform",
    "ProtocolVersion",
    "RefreshCredentialId",
    "ResourceId",
    "RiskLevel",
    "RunId",
    "ServiceId",
    "SnapshotId",
    "ThreadId",
    "ToolDefinition",
    "ToolError",
    "ToolRunId",
    "VersionCompatibility",
]
