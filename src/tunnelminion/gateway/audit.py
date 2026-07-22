"""不记录认证材料和请求正文的网关安全审计。"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Protocol

from pydantic import BaseModel, ConfigDict

from tunnelminion.domain.identifiers import NodeId
from tunnelminion.gateway.contracts import GatewayErrorCode


class GatewaySecurityAuditRecord(BaseModel):
    """一次在工具运行前被网关策略拒绝的安全事件。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    occurred_at: datetime
    action: str
    error_code: GatewayErrorCode
    peer_node_id: NodeId | None = None


class GatewaySecurityAuditSink(Protocol):
    """网关安全事件的持久化边界。"""

    def append(self, record: GatewaySecurityAuditRecord) -> None:
        """追加一条不含 token、认证头和请求正文的事件。"""
        ...


class InMemoryGatewaySecurityAuditSink:
    """供本地 MVP 和测试使用的安全审计存储。"""

    def __init__(self) -> None:
        self.records: list[GatewaySecurityAuditRecord] = []

    def append(self, record: GatewaySecurityAuditRecord) -> None:
        """按发生顺序保存安全事件。"""
        self.records.append(record)


def security_event(
    action: str,
    error_code: GatewayErrorCode,
    peer_node_id: NodeId | None = None,
) -> GatewaySecurityAuditRecord:
    """创建只包含可信分类字段的安全事件。"""
    return GatewaySecurityAuditRecord(
        occurred_at=datetime.now(UTC),
        action=action,
        error_code=error_code,
        peer_node_id=peer_node_id,
    )
