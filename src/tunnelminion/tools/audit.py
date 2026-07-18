"""不保存秘密或工具正文的结构化工具审计。"""

from __future__ import annotations

from datetime import datetime
from typing import Protocol

from pydantic import BaseModel, ConfigDict, JsonValue

from tunnelminion.domain.errors import ErrorCode
from tunnelminion.domain.identifiers import NodeId, RunId, ThreadId, ToolRunId
from tunnelminion.domain.versioning import ProtocolVersion
from tunnelminion.tools.contracts import ToolExecutionStatus


class AuditRecord(BaseModel):
    """一次工具调用的脱敏关联记录。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    thread_id: ThreadId
    run_id: RunId
    tool_run_id: ToolRunId
    caller_node_id: NodeId
    execution_node_id: NodeId
    tool_name: str
    tool_version: ProtocolVersion | None
    arguments_summary: dict[str, JsonValue]
    started_at: datetime
    finished_at: datetime
    status: ToolExecutionStatus
    error_code: ErrorCode | None = None


class AuditSink(Protocol):
    """审计记录的持久化边界。"""

    def append(self, record: AuditRecord) -> None:
        """追加一条不可变审计记录。"""
        ...


class InMemoryAuditSink:
    """供单元测试和早期本地 Runtime 使用的审计存储。"""

    def __init__(self) -> None:
        self.records: list[AuditRecord] = []

    def append(self, record: AuditRecord) -> None:
        """按执行完成顺序保存审计记录。"""
        self.records.append(record)
