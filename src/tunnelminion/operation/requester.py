"""请求节点发起和恢复批准操作所需的最小本地契约。"""

from __future__ import annotations

from datetime import datetime
from typing import Protocol, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from tunnelminion.domain.identifiers import NodeId, OperationId
from tunnelminion.operation.contracts import OperationPlan, OperationSummary


class RequesterOperationInput(BaseModel):
    """浏览器可提交的有限临时共享参数。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    target_node_id: NodeId
    service_port: int = Field(ge=1, le=65535)
    bind_port: int = Field(ge=1024, le=65535)
    duration_seconds: int = Field(ge=1, le=86_400)
    confirmed: bool = Field(strict=True)


class RequesterOperationRecord(BaseModel):
    """可恢复但不持有目标端权威证据或访问凭据的请求端记录。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    plan: OperationPlan
    remote_summary: OperationSummary | None = None
    submission_result_unknown: bool = False
    execution_result_unknown: bool = False
    last_checked_at: datetime | None = None
    error_code: str | None = Field(default=None, pattern=r"^[a-z][a-z0-9_]{0,127}$")
    updated_at: datetime

    @model_validator(mode="after")
    def validate_record(self) -> Self:
        if self.submission_result_unknown and self.execution_result_unknown:
            raise ValueError("同一请求端记录不能同时标记两种写结果未知")
        if self.last_checked_at is not None and self.last_checked_at > self.updated_at:
            raise ValueError("最后远端查询时间不得晚于本地更新时间")
        summary = self.remote_summary
        if summary is None:
            return self
        plan = self.plan
        expected = (
            plan.operation_id,
            plan.thread_id,
            plan.run_id,
            plan.tool_run_ids,
            plan.request_node_id,
            plan.target_node_id,
            plan.tool_name,
            plan.level,
            plan.access_scope.bind_host,
            plan.access_scope.bind_port,
        )
        actual = (
            summary.operation_id,
            summary.thread_id,
            summary.run_id,
            summary.tool_run_ids,
            summary.request_node_id,
            summary.target_node_id,
            summary.tool_name,
            summary.level,
            summary.bind_host,
            summary.bind_port,
        )
        if actual != expected:
            raise ValueError("远端操作摘要与本地计划引用不一致")
        return self

    @classmethod
    def planned(cls, plan: OperationPlan) -> Self:
        """在任何远端写请求之前保存计划。"""
        return cls(plan=plan, updated_at=plan.created_at)


class RequesterOperationStore(Protocol):
    """请求端操作索引的持久化边界。"""

    def put(self, record: RequesterOperationRecord) -> None: ...

    def get(self, operation_id: OperationId) -> RequesterOperationRecord | None: ...

    def list_all(self) -> tuple[RequesterOperationRecord, ...]: ...
