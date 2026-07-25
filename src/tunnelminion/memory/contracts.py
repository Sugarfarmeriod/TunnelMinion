"""四类状态中三类持久数据的独立契约；实时状态不得写入这里。"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Protocol

from pydantic import BaseModel, ConfigDict, Field, JsonValue

from tunnelminion.domain.identifiers import (
    ArtifactId,
    MemoryId,
    NodeId,
    RunId,
    ThreadId,
    ToolRunId,
)


class CheckpointStatus(StrEnum):
    """可在重启后判断是否中断的工作流状态。"""

    RUNNING = "running"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    FAILED = "failed"
    INTERRUPTED = "interrupted"


class CheckpointRecord(BaseModel):
    """仅保存公开流程状态、预算和证据引用。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    thread_id: ThreadId
    run_id: RunId
    status: CheckpointStatus
    public_state: dict[str, JsonValue]
    tool_run_ids: tuple[ToolRunId, ...] = ()
    updated_at: datetime


class ToolArtifact(BaseModel):
    """不直接塞入模型上下文的大型工具结果。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    artifact_id: ArtifactId
    tool_run_id: ToolRunId
    content: JsonValue
    content_bytes: int = Field(ge=0)
    content_type: str = Field(default="application/json", min_length=1, max_length=128)
    content_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    created_at: datetime


class MemoryKind(StrEnum):
    """MVP 允许长期存在的稳定信息类别。"""

    NODE_ALIAS = "node-alias"
    PREFERENCE = "preference"
    SECURITY_CONSTRAINT = "security-constraint"
    STABLE_SERVICE_FACT = "stable-service-fact"


class MemoryNamespace(BaseModel):
    """按用户、网络、节点、任务和安全域五层隔离长期记忆。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    user: str = Field(min_length=1, max_length=128)
    network: str = Field(min_length=1, max_length=128)
    node_id: NodeId
    task_type: str = Field(default="local-conversation", min_length=1, max_length=128)
    security_scope: str = Field(default="read-only-agent", min_length=1, max_length=128)


class LongTermMemory(BaseModel):
    """带来源、确认状态与更新时间的长期事实或偏好。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    memory_id: MemoryId
    namespace: MemoryNamespace
    kind: MemoryKind
    content: str = Field(min_length=1, max_length=20_000)
    source: str = Field(min_length=1, max_length=2_000)
    user_confirmed: bool
    updated_at: datetime
    valid_until: datetime | None = None
    revision_of: MemoryId | None = None
    superseded_by: MemoryId | None = None
    deleted_at: datetime | None = None


class CheckpointStore(Protocol):
    """工作流 checkpoint 独立访问接口。"""

    def put(self, record: CheckpointRecord) -> None: ...

    def get(self, run_id: RunId) -> CheckpointRecord | None: ...

    def list_all(self) -> tuple[CheckpointRecord, ...]: ...

    def list_thread(self, thread_id: ThreadId) -> tuple[CheckpointRecord, ...]: ...

    def delete_thread(self, thread_id: ThreadId) -> None: ...


class ToolArtifactStore(Protocol):
    """大型工具 artifact 独立访问接口。"""

    def put(self, artifact: ToolArtifact) -> None: ...

    def get(self, artifact_id: ArtifactId) -> ToolArtifact | None: ...

    def delete(self, artifact_id: ArtifactId) -> None: ...


class LongTermMemoryStore(Protocol):
    """长期记忆独立访问接口。"""

    def put(self, memory: LongTermMemory) -> None: ...

    def get(self, memory_id: MemoryId) -> LongTermMemory | None: ...

    def list_all(self) -> tuple[LongTermMemory, ...]: ...

    def list_namespace(self, namespace: MemoryNamespace) -> tuple[LongTermMemory, ...]: ...

    def delete(self, memory_id: MemoryId) -> None: ...

    def clear_namespace(self, namespace: MemoryNamespace) -> None: ...
