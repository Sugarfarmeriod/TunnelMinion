"""供 TunnelMinion 各运行时边界共享的领域模型。"""

from tunnelminion.domain.errors import ErrorCode, ToolError
from tunnelminion.domain.identifiers import NodeId, RunId, ThreadId, ToolRunId
from tunnelminion.domain.tools import DataSensitivity, Platform, RiskLevel, ToolDefinition
from tunnelminion.domain.versioning import ProtocolVersion, VersionCompatibility

__all__ = [
    "DataSensitivity",
    "ErrorCode",
    "NodeId",
    "Platform",
    "ProtocolVersion",
    "RiskLevel",
    "RunId",
    "ThreadId",
    "ToolDefinition",
    "ToolError",
    "ToolRunId",
    "VersionCompatibility",
]
