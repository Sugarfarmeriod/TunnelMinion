"""委派：把一件事交给另一台电脑的 Agent 去查。

请求里只有问题、可选的相关服务和预算，没有任何命令；结果只有结论和证据摘要，
原始工具输出留在被委派的电脑上。
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from tunnelminion.domain.identifiers import DelegationId, NodeId, OperationId
from tunnelminion.domain.service_marks import MARK_KEY_PATTERN

# 请求方 Agent 用来发起委派的工具名。
DELEGATE_TOOL_NAME = "delegate_to_node"

# 被委派方执行的上限，请求方不能调高。
MAX_MODEL_ROUNDS = 8
MAX_TOOL_CALLS = 12
MAX_SECONDS = 90.0


class DelegationStatus(StrEnum):
    """一次委派所处的阶段。"""

    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


TERMINAL_DELEGATION_STATUSES = frozenset(
    {DelegationStatus.COMPLETED, DelegationStatus.FAILED, DelegationStatus.CANCELLED}
)


class DelegationErrorCode(StrEnum):
    """委派没能给出结论时的原因。"""

    MODEL_UNAVAILABLE = "model_unavailable"
    TIMEOUT = "timeout"
    FAILED = "failed"


class DelegationBusyError(RuntimeError):
    """同一台电脑已有一个委派在本机处理中。"""


class DelegationRequest(BaseModel):
    """请求方发来的委派：一句问题，可选指明相关服务。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    caller_node_id: NodeId
    question: str = Field(min_length=1, max_length=1000)
    service_key: str | None = Field(default=None, pattern=MARK_KEY_PATTERN)


class DelegationEvidence(BaseModel):
    """一条证据的摘要：用了哪个工具、结果如何；不含工具原始输出。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    tool_name: str = Field(min_length=1, max_length=80)
    status: str = Field(min_length=1, max_length=40)


class DelegationProposedRepair(BaseModel):
    """对端提出的修复摘要，批准只能在服务所在的电脑上进行。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    repair_id: OperationId
    service_name: str = Field(min_length=1, max_length=120)
    action: str = Field(min_length=1, max_length=300)
    status: str = Field(min_length=1, max_length=40)
    how_to_approve: str = Field(min_length=1, max_length=500)
    expires_at: datetime


class DelegationResult(BaseModel):
    """被委派方查明的结论。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    summary: str = Field(max_length=4000)
    confirmed_facts: tuple[str, ...] = Field(default=(), max_length=20)
    inferences: tuple[str, ...] = Field(default=(), max_length=20)
    unknowns: tuple[str, ...] = Field(default=(), max_length=20)
    evidence: tuple[DelegationEvidence, ...] = Field(default=(), max_length=MAX_TOOL_CALLS)
    proposed_repairs: tuple[DelegationProposedRepair, ...] = Field(default=(), max_length=3)
    stop_reason: str = Field(min_length=1, max_length=40)
    model_rounds: int = Field(ge=0)
    tool_calls: int = Field(ge=0)
    elapsed_ms: float = Field(ge=0)


class DelegationRecord(BaseModel):
    """被委派方保存的一次委派：谁问的、问了什么、查到了什么。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    delegation_id: DelegationId
    caller_node_id: NodeId
    executing_node_id: NodeId
    question: str
    service_key: str | None = None
    status: DelegationStatus
    created_at: datetime
    finished_at: datetime | None = None
    result: DelegationResult | None = None
    error_code: DelegationErrorCode | None = None
