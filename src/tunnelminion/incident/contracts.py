"""自主调查只允许持久化的有界、脱敏公开合同。"""

from __future__ import annotations

import re
from datetime import datetime
from enum import StrEnum
from typing import Annotated, Literal, Self

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, field_validator, model_validator

from tunnelminion.coordinator.contracts import (
    ServiceAccessibility,
    ServiceLifecycle,
    ServiceProtocol,
)
from tunnelminion.domain.identifiers import (
    IncidentId,
    NodeId,
    RunId,
    ServiceId,
    SnapshotId,
    ToolRunId,
)

_PUBLIC_TEXT_LIMIT = 320
_SENSITIVE_TEXT = re.compile(
    r"(?i)(authorization|api[_-]?key|password|private[_-]?key|preshared[_-]?key)"
    r"\s*[:=]\s*\S+|bearer\s+\S+|tmn_share_[A-Za-z0-9_-]+"
)
_FORBIDDEN_KEYS = (
    '"authorization"',
    '"api_key"',
    '"password"',
    '"private_key"',
    '"preshared_key"',
    '"response_body"',
)

PublicText = Annotated[str, Field(min_length=1, max_length=_PUBLIC_TEXT_LIMIT)]


def _redact_public_text(value: str) -> str:
    """删除公开摘要中意外出现的常见认证材料。"""
    return _SENSITIVE_TEXT.sub("[REDACTED]", value)


class SnapshotSource(StrEnum):
    """快照允许保留的来源，不包含 endpoint 或文件路径。"""

    LOCAL_RUNTIME = "local_runtime"
    COORDINATOR_DIRECTORY = "coordinator_directory"
    NETWORK_PATH_EVIDENCE = "network_path_evidence"
    LOCAL_OBSERVATION = "local_observation"
    AGGREGATED = "aggregated"
    UNKNOWN = "unknown"


class SnapshotFreshness(StrEnum):
    """规范化后的证据新鲜度。"""

    LIVE = "live"
    FRESH = "fresh"
    STALE = "stale"
    EXPIRED = "expired"
    UNAVAILABLE = "unavailable"
    UNKNOWN = "unknown"


class SnapshotNodeState(StrEnum):
    """节点比较只需要的稳定状态。"""

    LOCAL = "local"
    ONLINE = "online"
    STALE = "stale"
    OFFLINE = "offline"
    REVOKED = "revoked"
    INCOMPATIBLE = "incompatible"
    UNKNOWN = "unknown"


class SnapshotServiceState(StrEnum):
    """服务比较只需要的稳定状态。"""

    AVAILABLE = "available"
    DEGRADED = "degraded"
    UNAVAILABLE = "unavailable"
    STOPPED = "stopped"
    UNKNOWN = "unknown"


class SnapshotNode(BaseModel):
    """不含显示名、地址或认证材料的节点状态。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    node_id: NodeId
    state: SnapshotNodeState
    source: SnapshotSource
    freshness: SnapshotFreshness
    evidence_at: AwareDatetime | None = None


class SnapshotService(BaseModel):
    """不含业务正文、进程参数和完整访问地址的服务状态。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    service_id: ServiceId
    node_id: NodeId
    state: SnapshotServiceState
    source: SnapshotSource
    freshness: SnapshotFreshness
    evidence_at: AwareDatetime | None = None
    protocol: ServiceProtocol | None = None
    port: int | None = Field(default=None, ge=1, le=65535)
    accessibility: ServiceAccessibility | None = None
    lifecycle: ServiceLifecycle | None = None


class NormalizedSnapshot(BaseModel):
    """有界、可重复比较的节点与服务快照。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["incident-snapshot/v1"] = "incident-snapshot/v1"
    snapshot_id: SnapshotId
    observed_at: AwareDatetime
    revision: int = Field(ge=0)
    nodes: tuple[SnapshotNode, ...] = Field(default=(), max_length=200)
    services: tuple[SnapshotService, ...] = Field(default=(), max_length=1024)

    @model_validator(mode="after")
    def validate_identity_sets(self) -> Self:
        if len({str(item.node_id) for item in self.nodes}) != len(self.nodes):
            raise ValueError("快照节点身份不得重复")
        if len({str(item.service_id) for item in self.services}) != len(self.services):
            raise ValueError("快照服务身份不得重复")
        return self


class IncidentEventType(StrEnum):
    """模型外固定识别的六类变化。"""

    SERVICE_ADDED = "service_added"
    SERVICE_REMOVED = "service_removed"
    NODE_OFFLINE = "node_offline"
    STATE_STALE = "state_stale"
    LOCAL_ONLY = "local_only"
    REMOTE_UNREACHABLE = "remote_unreachable"


class SnapshotObjectKind(StrEnum):
    """差异事件目标类型。"""

    NODE = "node"
    SERVICE = "service"


class SnapshotDiffEvent(BaseModel):
    """固定规则生成的差异证据，不含原始工具结果。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    event_type: IncidentEventType
    object_kind: SnapshotObjectKind
    object_id: str = Field(min_length=37, max_length=40)
    baseline_snapshot_id: SnapshotId
    current_snapshot_id: SnapshotId
    baseline_revision: int = Field(ge=0)
    current_revision: int = Field(ge=0)
    observed_at: AwareDatetime
    source: SnapshotSource
    before_state: str | None = Field(default=None, max_length=64)
    after_state: str | None = Field(default=None, max_length=64)
    dedup_key: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_object_identity(self) -> Self:
        expected = f"{self.object_kind.value}_"
        if not self.object_id.startswith(expected):
            raise ValueError("差异对象身份与类型不匹配")
        return self


class IncidentStatus(StrEnum):
    """incident 与调查的公开生命周期。"""

    PENDING = "pending"
    INVESTIGATING = "investigating"
    CONFIRMED = "confirmed"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"
    BUDGET_EXHAUSTED = "budget_exhausted"
    CANCELLED = "cancelled"
    FAILED = "failed"
    INTERRUPTED = "interrupted"
    INVESTIGATION_UNAVAILABLE = "investigation_unavailable"
    CLOSED = "closed"


class HypothesisStatus(StrEnum):
    """公开候选根因状态。"""

    CANDIDATE = "candidate"
    SUPPORTED = "supported"
    REJECTED = "rejected"
    UNKNOWN = "unknown"


class InvestigationStopReason(StrEnum):
    """Runtime 强制的公开停止原因。"""

    EVIDENCE_SUFFICIENT = "evidence_sufficient"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"
    BUDGET_EXHAUSTED = "budget_exhausted"
    CANCELLED = "cancelled"
    FAILED = "failed"
    INTERRUPTED = "interrupted"
    MODEL_UNAVAILABLE = "model_unavailable"


class EvidenceReference(BaseModel):
    """只引用有界快照或公开 tool run。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    snapshot_id: SnapshotId | None = None
    tool_run_id: ToolRunId | None = None
    observed_at: AwareDatetime
    summary: PublicText

    @field_validator("summary")
    @classmethod
    def redact_summary(cls, value: str) -> str:
        return _redact_public_text(value)

    @model_validator(mode="after")
    def validate_single_reference(self) -> Self:
        if (self.snapshot_id is None) == (self.tool_run_id is None):
            raise ValueError("证据必须且只能引用一个 snapshot 或 tool run")
        return self


class IncidentHypothesis(BaseModel):
    """不保存隐藏思维链的候选根因。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    hypothesis_id: str = Field(pattern=r"^hypothesis_[0-9a-f]{16}$")
    summary: PublicText
    status: HypothesisStatus = HypothesisStatus.CANDIDATE
    evidence: tuple[EvidenceReference, ...] = Field(default=(), max_length=24)

    @field_validator("summary")
    @classmethod
    def redact_summary(cls, value: str) -> str:
        return _redact_public_text(value)


class PublicTraceEntry(BaseModel):
    """调查可公开的一次状态或工具动作。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    occurred_at: AwareDatetime
    kind: Literal["status", "hypothesis", "tool", "evidence", "report"]
    summary: PublicText
    tool_name: str | None = Field(default=None, pattern=r"^[a-z][a-z0-9_]{1,63}$")
    evidence: tuple[EvidenceReference, ...] = Field(default=(), max_length=12)

    @field_validator("summary")
    @classmethod
    def redact_summary(cls, value: str) -> str:
        return _redact_public_text(value)


class IncidentReport(BaseModel):
    """固定区分事实、解释、未知项和停止原因的公开报告。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    facts: tuple[PublicText, ...] = Field(default=(), max_length=24)
    candidate_explanations: tuple[PublicText, ...] = Field(default=(), max_length=12)
    unknowns: tuple[PublicText, ...] = Field(default=(), max_length=12)
    conclusion: PublicText | None = None
    stop_reason: InvestigationStopReason
    evidence: tuple[EvidenceReference, ...] = Field(default=(), max_length=24)

    @field_validator("facts", "candidate_explanations", "unknowns")
    @classmethod
    def redact_items(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(_redact_public_text(value) for value in values)

    @field_validator("conclusion")
    @classmethod
    def redact_conclusion(cls, value: str | None) -> str | None:
        return _redact_public_text(value) if value is not None else None

    @model_validator(mode="after")
    def validate_confirmed_conclusion(self) -> Self:
        if self.conclusion is not None and not self.evidence:
            raise ValueError("确认结论必须引用有效证据")
        return self


class Incident(BaseModel):
    """可恢复且不产生任何写操作的 incident 聚合。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["incident/v1"] = "incident/v1"
    incident_id: IncidentId
    dedup_key: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    event: SnapshotDiffEvent
    status: IncidentStatus = IncidentStatus.PENDING
    created_at: AwareDatetime
    last_observed_at: AwareDatetime
    run_id: RunId | None = None
    hypotheses: tuple[IncidentHypothesis, ...] = Field(default=(), max_length=12)
    trace: tuple[PublicTraceEntry, ...] = Field(default=(), max_length=96)
    report: IncidentReport | None = None

    @model_validator(mode="after")
    def validate_lifecycle(self) -> Self:
        if self.last_observed_at < self.created_at:
            raise ValueError("incident 最后观测时间不得早于创建时间")
        if self.dedup_key != self.event.dedup_key:
            raise ValueError("incident 去重键必须与差异事件一致")
        if self.status is IncidentStatus.CONFIRMED and (
            self.report is None or self.report.conclusion is None
        ):
            raise ValueError("已确认 incident 必须包含证据化结论")
        return self

    def assert_no_secret_material(self) -> None:
        """验证持久化载荷不含禁止字段或常见认证正文。"""
        payload = self.model_dump_json().lower()
        if any(key in payload for key in _FORBIDDEN_KEYS) or _SENSITIVE_TEXT.search(payload):
            raise ValueError("incident 载荷包含禁止的秘密或业务正文字段")

    def transition(
        self,
        status: IncidentStatus,
        *,
        at: datetime,
        run_id: RunId | None = None,
        report: IncidentReport | None = None,
    ) -> Incident:
        """只允许显式生命周期迁移，避免重启或并发跳过安全状态。"""
        allowed = {
            IncidentStatus.PENDING: {
                IncidentStatus.INVESTIGATING,
                IncidentStatus.INVESTIGATION_UNAVAILABLE,
                IncidentStatus.CLOSED,
            },
            IncidentStatus.INVESTIGATING: {
                IncidentStatus.CONFIRMED,
                IncidentStatus.INSUFFICIENT_EVIDENCE,
                IncidentStatus.BUDGET_EXHAUSTED,
                IncidentStatus.CANCELLED,
                IncidentStatus.FAILED,
                IncidentStatus.INTERRUPTED,
            },
            IncidentStatus.INTERRUPTED: {
                IncidentStatus.INVESTIGATING,
                IncidentStatus.CLOSED,
            },
            IncidentStatus.INVESTIGATION_UNAVAILABLE: {
                IncidentStatus.INVESTIGATING,
                IncidentStatus.CLOSED,
            },
        }
        if status not in allowed.get(self.status, set()):
            raise ValueError(f"不允许从 {self.status.value} 迁移到 {status.value}")
        if at.tzinfo is None or at < self.created_at:
            raise ValueError("incident 迁移时间必须有效且包含时区")
        next_run_id = run_id if status is IncidentStatus.INVESTIGATING else self.run_id
        if status is IncidentStatus.INVESTIGATING and next_run_id is None:
            raise ValueError("开始调查必须绑定 run ID")
        return Incident.model_validate(
            self.model_dump()
            | {
                "status": status,
                "last_observed_at": at,
                "run_id": next_run_id,
                "report": report if report is not None else self.report,
            }
        )
