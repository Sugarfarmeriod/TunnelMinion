"""动手修服务的计划、启动记录、执行与验证记录，以及执行层的固定接口。

修复复用操作状态机和授权服务。计划只由本机代码根据服务身份、Docker 实时状态、启动记录
和 launchd 状态生成；提出修法的一方只能给出服务身份、修法种类和理由，理由只用于展示，
永远不进入任何命令。
完整命令和路径只保存在本机记录里，对模型和别的电脑只给 `RepairSummary`。
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Literal, Protocol, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from tunnelminion.domain.identifiers import DelegationId, NodeId, OperationId, RunId, ThreadId
from tunnelminion.domain.service_marks import MARK_KEY_PATTERN
from tunnelminion.operation.contracts import (
    TERMINAL_OPERATION_STATUSES,
    LifecycleRecord,
    OperationLevel,
    OperationStatus,
    OperationTransition,
)

# 一次批准只修一次：待批准的修复和批准本身都只在 10 分钟内有效。
REPAIR_AUTHORIZATION_SECONDS = 600
# 同一个服务在这段时间内最多开始执行的修复次数。
REPAIR_RATE_WINDOW_SECONDS = 3600
REPAIR_RATE_LIMIT = 3

REPAIR_TERMINAL_STATUSES = TERMINAL_OPERATION_STATUSES | {OperationStatus.SUCCEEDED}
# 处于这些状态的修复说明本机正在动手，同一台电脑同时只允许一个。
REPAIR_ACTIVE_STATUSES = frozenset(
    {OperationStatus.EXECUTING, OperationStatus.VERIFYING, OperationStatus.ROLLING_BACK}
)

_CONTAINER_ID = r"^[0-9a-f]{12,64}$"


class RepairKind(StrEnum):
    """固定的修法种类；没有"执行任意命令"这一种。"""

    RESTART_CONTAINERS = "restart_containers"
    RELAUNCH_PYTHON = "relaunch_python"
    # 重新启动当前用户 `~/Library/LaunchAgents` 里已经退出的 macOS 后台服务。
    RESTART_LAUNCH_AGENT = "restart_launch_agent"


# 每种修法在工具注册表里登记为 L2，模型拿不到它们的执行入口。
REPAIR_TOOL_NAMES: dict[RepairKind, str] = {
    RepairKind.RESTART_CONTAINERS: "repair_restart_containers",
    RepairKind.RELAUNCH_PYTHON: "repair_relaunch_python",
    RepairKind.RESTART_LAUNCH_AGENT: "repair_restart_launch_agent",
}

# 每种修法只适用于一种服务身份前缀。
REPAIR_KEY_PREFIXES: dict[RepairKind, str] = {
    RepairKind.RESTART_CONTAINERS: "docker:",
    RepairKind.RELAUNCH_PYTHON: "python:",
    RepairKind.RESTART_LAUNCH_AGENT: "launchd:",
}

# launchd 标签：只允许字母、数字和 `._@-`，用于服务身份和固定命令参数。
LAUNCH_AGENT_LABEL_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._@-]{0,127}$"


class RepairOriginKind(StrEnum):
    """修复由谁提出。"""

    CONVERSATION = "conversation"
    DELEGATION = "delegation"
    LOCAL_CLI = "local_cli"
    # 巡检确认服务挂了以后提出。
    PATROL = "patrol"


class RepairOrigin(BaseModel):
    """提出修复的那次对话或委派，以及它依据的证据要点。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: RepairOriginKind
    thread_id: ThreadId | None = None
    run_id: RunId | None = None
    delegation_id: DelegationId | None = None
    evidence: tuple[Annotated[str, Field(min_length=1, max_length=300)], ...] = Field(
        default=(), max_length=10
    )


class ContainerSnapshot(BaseModel):
    """`docker ps -a` 和 `docker inspect` 读到的一个容器的只读事实。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    container_id: str = Field(pattern=_CONTAINER_ID)
    name: str = Field(min_length=1, max_length=128)
    image: str = Field(min_length=1, max_length=256)
    running: bool
    status: str = Field(min_length=1, max_length=256)
    # 容器配置里发布到本机的端口；停掉的容器在 `docker ps` 里看不到端口，所以从配置读。
    published_ports: tuple[Annotated[int, Field(ge=1, le=65535)], ...] = ()
    compose_project: str | None = Field(default=None, min_length=1, max_length=80)


class ContainerRepairTarget(BaseModel):
    """重启一个容器或一个 compose 组：生成计划时看到的全部容器。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: Literal[RepairKind.RESTART_CONTAINERS] = RepairKind.RESTART_CONTAINERS
    compose_project: str | None = Field(default=None, min_length=1, max_length=80)
    container_name: str | None = Field(default=None, min_length=1, max_length=128)
    containers: tuple[ContainerSnapshot, ...] = Field(min_length=1, max_length=32)

    @model_validator(mode="after")
    def validate_scope(self) -> Self:
        if (self.compose_project is None) == (self.container_name is None):
            raise ValueError("容器修复必须且只能指定 compose 项目或单个容器名")
        if self.container_name is not None and (
            len(self.containers) != 1 or self.containers[0].name != self.container_name
        ):
            raise ValueError("单个容器修复只能包含这个容器")
        if self.compose_project is not None and any(
            item.compose_project != self.compose_project for item in self.containers
        ):
            raise ValueError("compose 组修复只能包含同一项目的容器")
        if len({item.container_id for item in self.containers}) != len(self.containers):
            raise ValueError("容器不能重复")
        return self

    @property
    def fingerprint(self) -> str:
        """容器编号集合的指纹；执行前核对编号有没有变。"""
        return _digest(sorted(item.container_id for item in self.containers))

    @property
    def ports(self) -> tuple[int, ...]:
        """验证时要确认在听的本机端口。"""
        return tuple(sorted({port for item in self.containers for port in item.published_ports}))


class LaunchRecord(BaseModel):
    """脚本活着时记下的启动方式；只存在本机，不记环境变量。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    service_key: str = Field(pattern=MARK_KEY_PATTERN)
    # 解释器的完整路径；用的是虚拟环境里的 Python 时记虚拟环境里的那个。
    interpreter: str = Field(min_length=1, max_length=1_024)
    # 解释器之后的完整启动参数。
    arguments: tuple[Annotated[str, Field(max_length=4_096)], ...] = Field(
        min_length=1, max_length=64
    )
    working_directory: str = Field(min_length=1, max_length=1_024)
    # 这个进程当时监听的全部 TCP 端口。
    ports: tuple[Annotated[int, Field(ge=1, le=65535)], ...] = Field(min_length=1, max_length=32)
    username: str = Field(min_length=1, max_length=256)
    # 不看用户标记、只按分档规则时它是否直接显示；资格检查据此判断取消标记后的情况。
    rule_shown: bool
    process_id: int = Field(gt=0)
    process_started_at: datetime
    recorded_at: datetime

    @model_validator(mode="after")
    def validate_key(self) -> Self:
        if not self.service_key.startswith("python:"):
            raise ValueError("启动记录只属于 Python 脚本")
        return self

    @property
    def fingerprint(self) -> str:
        """启动方式的指纹；同一启动方式的待批准修复只保留一条。"""
        return _digest(
            [self.interpreter, list(self.arguments), self.working_directory, self.username]
        )


class PythonRepairTarget(BaseModel):
    """按启动记录重新拉起一个已经退出的 Python 脚本。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: Literal[RepairKind.RELAUNCH_PYTHON] = RepairKind.RELAUNCH_PYTHON
    launch: LaunchRecord

    @property
    def fingerprint(self) -> str:
        return self.launch.fingerprint

    @property
    def ports(self) -> tuple[int, ...]:
        return tuple(sorted(set(self.launch.ports)))


class LaunchAgentRecord(BaseModel):
    """见过 macOS 后台服务正常运行时记下的事实；只有标签和端口，不记命令和路径。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    service_key: str = Field(pattern=MARK_KEY_PATTERN)
    label: str = Field(pattern=LAUNCH_AGENT_LABEL_PATTERN)
    # 当时这个后台服务监听的全部 TCP 端口；修好以后据此验证。
    ports: tuple[Annotated[int, Field(ge=1, le=65535)], ...] = Field(min_length=1, max_length=32)
    # 不看用户标记、只按分档规则时它是否直接显示。
    rule_shown: bool
    recorded_at: datetime

    @model_validator(mode="after")
    def validate_key(self) -> Self:
        if self.service_key != f"launchd:{self.label}":
            raise ValueError("后台服务记录的身份必须是 launchd:<标签>")
        return self


# 启动记录存储里的一条：Python 脚本的启动方式，或 macOS 后台服务的标签和端口。
AnyLaunchRecord = LaunchRecord | LaunchAgentRecord


class LaunchAgentJob(BaseModel):
    """本机现读的一个用户后台服务：plist 事实和 launchd 里的状态，只在本机使用。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    label: str = Field(pattern=LAUNCH_AGENT_LABEL_PATTERN)
    uid: int = Field(gt=0)
    plist_path: str = Field(min_length=1, max_length=1_024)
    plist_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    # plist 里 `Program` 或 `ProgramArguments` 的第一项；读不出时为 None。
    program: str | None = Field(default=None, max_length=1_024)
    # plist 里配置的 `StandardErrorPath`、`StandardOutPath`。
    log_paths: tuple[Annotated[str, Field(max_length=1_024)], ...] = Field(default=(), max_length=2)
    # 是否已加载在 `gui/<uid>` 域里，以及 launchd 记的配置文件位置。
    loaded: bool
    loaded_path: str | None = Field(default=None, max_length=1_024)
    pid: int | None = Field(default=None, gt=0)
    last_exit_code: int | None = None


class LaunchAgentProblem(StrEnum):
    """在用户 `~/Library/LaunchAgents` 里找不到可用的 plist 的原因。"""

    MISSING = "missing"
    # 符号链接、不属于当前用户、组或其他人可写。
    UNSAFE = "unsafe"
    # 读不出 `Label` 或要运行的程序。
    INVALID = "invalid"


class LaunchAgentRepairTarget(BaseModel):
    """重新启动一个已退出的用户后台服务：生成计划时看到的 plist。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: Literal[RepairKind.RESTART_LAUNCH_AGENT] = RepairKind.RESTART_LAUNCH_AGENT
    label: str = Field(pattern=LAUNCH_AGENT_LABEL_PATTERN)
    uid: int = Field(gt=0)
    plist_path: str = Field(min_length=1, max_length=1_024)
    plist_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    # 验证时要确认在听的本机端口，来自后台服务记录。
    listen_ports: tuple[Annotated[int, Field(ge=1, le=65535)], ...] = Field(
        min_length=1, max_length=32
    )

    @property
    def fingerprint(self) -> str:
        """plist 位置和内容的指纹；执行前核对配置有没有变。"""
        return _digest([self.label, self.uid, self.plist_path, self.plist_sha256])

    @property
    def ports(self) -> tuple[int, ...]:
        return tuple(sorted(set(self.listen_ports)))


RepairTarget = Annotated[
    ContainerRepairTarget | PythonRepairTarget | LaunchAgentRepairTarget,
    Field(discriminator="kind"),
]


def _digest(value: object) -> str:
    canonical = json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


def compute_repair_idempotency_key(
    *, node_id: NodeId, service_key: str, kind: RepairKind, target_fingerprint: str
) -> str:
    """同一服务、同一修法、同一目标的未结束修复只保留一条。"""
    return "repkey_" + _digest(
        {
            "node_id": str(node_id),
            "service_key": service_key,
            "kind": kind.value,
            "target": target_fingerprint,
        }
    )


class RepairPlan(BaseModel):
    """本机代码生成的修复计划；批准框里的五件事都来自这里。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    operation_id: OperationId
    idempotency_key: str = Field(pattern=r"^repkey_[0-9a-f]{64}$")
    node_id: NodeId
    service_key: str = Field(pattern=MARK_KEY_PATTERN)
    # 给人看的服务名，例如"Docker 容器组 photos"。
    service_name: str = Field(min_length=1, max_length=120)
    kind: RepairKind
    tool_name: str = Field(min_length=1, max_length=128)
    level: OperationLevel
    target: RepairTarget
    # 提出方的一句理由，只展示，不进入命令。
    reason: str = Field(min_length=1, max_length=500)
    origin: RepairOrigin
    # 要做什么、会有什么影响、怎么确认修好、没修好怎么办：均由本机固定文案生成。
    action_summary: str = Field(min_length=1, max_length=300)
    impact_summary: str = Field(min_length=1, max_length=500)
    verification_summary: str = Field(min_length=1, max_length=300)
    failure_summary: str = Field(min_length=1, max_length=300)
    created_at: datetime

    @model_validator(mode="after")
    def validate_plan(self) -> Self:
        if self.target.kind is not self.kind:
            raise ValueError("修复目标与修法种类不一致")
        if self.tool_name != REPAIR_TOOL_NAMES[self.kind]:
            raise ValueError("修复工具名与修法种类不一致")
        if self.level is not OperationLevel.L2:
            raise ValueError("修复必须是 L2 操作")
        if not self.service_key.startswith(REPAIR_KEY_PREFIXES[self.kind]):
            raise ValueError("服务身份与修法种类不一致")
        if (
            isinstance(self.target, PythonRepairTarget)
            and self.target.launch.service_key != self.service_key
        ):
            raise ValueError("启动记录不属于这个服务")
        if (
            isinstance(self.target, LaunchAgentRepairTarget)
            and f"launchd:{self.target.label}" != self.service_key
        ):
            raise ValueError("后台服务标签与服务身份不一致")
        expected = compute_repair_idempotency_key(
            node_id=self.node_id,
            service_key=self.service_key,
            kind=self.kind,
            target_fingerprint=self.target.fingerprint,
        )
        if self.idempotency_key != expected:
            raise ValueError("幂等键与计划稳定字段不一致")
        return self


class RepairCommand(BaseModel):
    """实际执行过的一条固定命令。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    argv: tuple[str, ...] = Field(min_length=1, max_length=64)
    exit_code: int | None = None
    output_excerpt: str = Field(default="", max_length=2_000)
    started_at: datetime
    finished_at: datetime


class SpawnedProcess(BaseModel):
    """修复拉起的进程；按进程号加启动时间确认是不是我们自己拉起的那个。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    pid: int = Field(gt=0)
    started_at: datetime
    log_path: str = Field(min_length=1, max_length=1_024)


class RepairExecution(BaseModel):
    """一次执行实际做了什么。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    started_at: datetime
    finished_at: datetime | None = None
    commands: tuple[RepairCommand, ...] = ()
    spawned: SpawnedProcess | None = None


class RepairCheckName(StrEnum):
    """本机验证的检查项。"""

    CONTAINER_RUNNING = "container_running"
    LAUNCH_AGENT_RUNNING = "launch_agent_running"
    PORT_LISTENING = "port_listening"
    WEB_PAGE = "web_page"


class RepairCheck(BaseModel):
    """一项验证结果，`detail` 是给人看的一句话。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: RepairCheckName
    passed: bool
    detail: str = Field(min_length=1, max_length=500)


class RepairVerification(BaseModel):
    """执行后本机再探测一次的结果；失败时带上日志要点。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    passed: bool
    checks: tuple[RepairCheck, ...] = Field(min_length=1)
    log_excerpt: str | None = Field(default=None, max_length=4_000)
    verified_at: datetime

    @model_validator(mode="after")
    def validate_result(self) -> Self:
        if self.passed != all(item.passed for item in self.checks):
            raise ValueError("验证结论必须与各检查项一致")
        return self


class RepairCleanupResult(StrEnum):
    """失败后收场的结果。"""

    # 容器修复失败后不再动它；或者失败发生在动手之前。
    NOTHING_TO_UNDO = "nothing_to_undo"
    STOPPED_SPAWNED = "stopped_spawned"
    SPAWNED_ALREADY_EXITED = "spawned_already_exited"
    STOP_FAILED = "stop_failed"


class RepairCleanup(BaseModel):
    """失败后尽量回到动手前的样子。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    result: RepairCleanupResult
    detail: str = Field(min_length=1, max_length=500)
    completed_at: datetime


class RepairErrorCode(StrEnum):
    """修不了或没修好的稳定原因。"""

    NOT_ELIGIBLE = "not_eligible"
    PROTECTED_TARGET = "protected_target"
    NO_LAUNCH_RECORD = "no_launch_record"
    UNSUPPORTED_LAUNCH = "unsupported_launch"
    INTERPRETER_MISSING = "interpreter_missing"
    ENTRY_MISSING = "entry_missing"
    WORKING_DIRECTORY_MISSING = "working_directory_missing"
    OTHER_ACCOUNT = "other_account"
    PORT_IN_USE = "port_in_use"
    ALREADY_RUNNING = "already_running"
    DOCKER_UNAVAILABLE = "docker_unavailable"
    CONTAINER_MISSING = "container_missing"
    # 后台服务已经从 launchd 里卸载（例如 `brew services stop`），不会替主人重新加载。
    NOT_LOADED = "not_loaded"
    SERVICE_CHANGED = "service_changed"
    BUSY = "busy"
    RATE_LIMITED = "rate_limited"
    AUTHORIZATION_EXPIRED = "authorization_expired"
    EXECUTION_FAILED = "execution_failed"
    VERIFICATION_FAILED = "verification_failed"
    INTERRUPTED = "interrupted"


class RepairError(BaseModel):
    """给人看的失败说明和下一步建议。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    code: RepairErrorCode
    message: str = Field(min_length=1, max_length=500)
    next_step: str | None = Field(default=None, min_length=1, max_length=500)


class RepairAuditAction(StrEnum):
    """本机审计记录里的一步。"""

    PROPOSED = "proposed"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"
    PRECHECK_PASSED = "precheck_passed"
    PRECHECK_FAILED = "precheck_failed"
    COMMAND_EXECUTED = "command_executed"
    PROCESS_SPAWNED = "process_spawned"
    VERIFIED = "verified"
    CLEANED_UP = "cleaned_up"
    FINISHED = "finished"


class RepairAuditEvent(BaseModel):
    """谁、什么时候、做了什么；只留在本机。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    at: datetime
    actor: str = Field(min_length=1, max_length=128)
    action: RepairAuditAction
    detail: str = Field(min_length=1, max_length=2_000)


class RepairRecord(LifecycleRecord):
    """一次修复的完整本机记录：计划、批准、执行、验证、收场和审计。"""

    plan: RepairPlan
    execution: RepairExecution | None = None
    verification: RepairVerification | None = None
    cleanup: RepairCleanup | None = None
    error: RepairError | None = None
    audit: tuple[RepairAuditEvent, ...] = ()

    @property
    def authorizable_plan(self) -> RepairPlan:
        return self.plan

    @classmethod
    def planned(cls, plan: RepairPlan, *, actor: str) -> Self:
        """为本机已生成的计划创建初始记录。"""
        transition = OperationTransition(
            from_status=None,
            to_status=OperationStatus.PLANNED,
            reason="本机已生成修复计划",
            occurred_at=plan.created_at,
        )
        event = RepairAuditEvent(
            at=plan.created_at,
            actor=actor,
            action=RepairAuditAction.PROPOSED,
            detail=plan.action_summary,
        )
        return cls(
            plan=plan,
            status=OperationStatus.PLANNED,
            transitions=(transition,),
            audit=(event,),
            updated_at=plan.created_at,
        )

    def with_event(
        self, action: RepairAuditAction, detail: str, *, actor: str, at: datetime
    ) -> Self:
        """追加一条审计记录。"""
        event = RepairAuditEvent(at=at, actor=actor, action=action, detail=detail)
        return self.model_copy(
            update={"audit": (*self.audit, event), "updated_at": max(self.updated_at, at)}
        )


class RepairSummary(BaseModel):
    """给模型和别的电脑看的摘要：没有完整路径、命令和启动参数。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    operation_id: OperationId
    node_id: NodeId
    service_key: str
    service_name: str
    kind: RepairKind
    status: OperationStatus
    reason: str
    action_summary: str
    verification_passed: bool | None
    error_code: RepairErrorCode | None
    error_message: str | None
    created_at: datetime
    updated_at: datetime

    @classmethod
    def from_record(cls, record: RepairRecord) -> Self:
        plan = record.plan
        return cls(
            operation_id=plan.operation_id,
            node_id=plan.node_id,
            service_key=plan.service_key,
            service_name=plan.service_name,
            kind=plan.kind,
            status=record.status,
            reason=plan.reason,
            action_summary=plan.action_summary,
            verification_passed=(
                record.verification.passed if record.verification is not None else None
            ),
            error_code=record.error.code if record.error is not None else None,
            error_message=record.error.message if record.error is not None else None,
            created_at=plan.created_at,
            updated_at=record.updated_at,
        )


class RepairClaimResult(StrEnum):
    """开始执行前原子占用的结果。"""

    CLAIMED = "claimed"
    BUSY = "busy"
    RATE_LIMITED = "rate_limited"
    STATE_CONFLICT = "state_conflict"


class RepairStore(Protocol):
    """修复记录的本机持久化；多个进程（网页和命令行）共用同一个数据库。"""

    def put(self, record: RepairRecord) -> None: ...

    def get(self, operation_id: OperationId) -> RepairRecord | None: ...

    def get_by_idempotency_key(self, key: str) -> RepairRecord | None:
        """只返回尚未结束（不在 `REPAIR_TERMINAL_STATUSES`）的同键修复。"""
        ...  # pragma: no cover - Protocol 无运行时实现

    def list_all(self) -> tuple[RepairRecord, ...]:
        """最新创建的在前。"""
        ...  # pragma: no cover - Protocol 无运行时实现

    def claim_execution(
        self, executing: RepairRecord, *, rate_window_start: datetime, rate_limit: int
    ) -> RepairClaimResult:
        """在一个事务里原子地开始执行。

        `executing` 是已转到 executing 并带 `execution.started_at` 的记录。只有库里这条修复仍是
        authorized、没有别的修复处于 `REPAIR_ACTIVE_STATUSES`、同一 `service_key` 自
        `rate_window_start` 起开始执行的修复少于 `rate_limit` 次时才写入并返回 CLAIMED。
        """
        ...  # pragma: no cover - Protocol 无运行时实现


class LaunchRecordStore(Protocol):
    """启动记录的本机持久化，按服务身份保留最新一条。"""

    def put(self, record: AnyLaunchRecord) -> None: ...

    def get(self, service_key: str) -> AnyLaunchRecord | None: ...

    def list_all(self) -> tuple[AnyLaunchRecord, ...]: ...


class PortOwner(BaseModel):
    """当前在某个 TCP 端口上监听的进程。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    pid: int | None
    process_name: str | None
    # 这个进程是不是按同一份启动记录跑起来的同一个脚本（解释器、参数、目录都一致）。
    matches_launch: bool


class ContainerRuntime(Protocol):
    """固定的 Docker 命令：只读查询，以及 `docker start` / `docker restart`。

    不用 `docker compose up`、不拉镜像、不重建容器、不删除任何东西。
    """

    async def list_containers(
        self, *, compose_project: str | None, container_name: str | None
    ) -> tuple[ContainerSnapshot, ...] | None:
        """按 compose 项目标签或容器名找出容器；Docker 没在运行时返回 None。"""
        ...  # pragma: no cover - Protocol 无运行时实现

    async def start(self, container_ids: tuple[str, ...]) -> RepairCommand: ...

    async def restart(self, container_ids: tuple[str, ...]) -> RepairCommand: ...

    async def logs_tail(self, container_id: str, *, lines: int) -> str:
        """最后几行日志，已去掉常见认证材料；读不到时返回空串。"""
        ...  # pragma: no cover - Protocol 无运行时实现


class ProcessLauncher(Protocol):
    """按启动记录在后台拉起脚本，并且只停掉自己拉起的进程。"""

    def launch(self, record: LaunchRecord, *, log_path: Path) -> SpawnedProcess:
        """用原解释器、原参数、原目录在后台启动；TunnelMinion 退出后脚本照常运行。

        失败时抛出 `OSError`。
        """
        ...  # pragma: no cover - Protocol 无运行时实现

    def is_alive(self, spawned: SpawnedProcess) -> bool: ...

    def stop(self, spawned: SpawnedProcess) -> bool:
        """进程号和启动时间都对得上才停（连同它的子进程）；已经退出也算成功。"""
        ...  # pragma: no cover - Protocol 无运行时实现

    def log_tail(self, log_path: Path, *, lines: int) -> str: ...


class HostInspector(Protocol):
    """生成计划和执行前核对用到的本机事实。"""

    def current_username(self) -> str: ...

    def port_owner(self, port: int, launch: LaunchRecord | None = None) -> PortOwner | None:
        """端口没人监听时返回 None；给了启动记录时顺带判断是不是同一个脚本。"""
        ...  # pragma: no cover - Protocol 无运行时实现


class LaunchAgentRuntime(Protocol):
    """当前用户 `gui/<uid>` 域里的后台服务：只读查询和固定的 `launchctl kickstart`。

    只看 `~/Library/LaunchAgents` 下属于当前用户、别人不能写的 plist；不改 plist，
    不加载、卸载、启用或禁用任何服务。
    """

    def unsupported_reason(self) -> str | None:
        """这台电脑上不能用这种修法的原因（不是 macOS、以 root 运行）；能用时返回 None。"""
        ...  # pragma: no cover - Protocol 无运行时实现

    async def labels_for_pids(self, pids: frozenset[int]) -> dict[int, str]:
        """监听进程号到后台服务标签；进程本身或它往上的父进程是后台服务的进程都算。"""
        ...  # pragma: no cover - Protocol 无运行时实现

    async def inspect(self, label: str) -> LaunchAgentJob | LaunchAgentProblem: ...

    async def kickstart(self, label: str) -> RepairCommand:
        """`launchctl kickstart gui/<uid>/<标签>`，不带 `-k`：已经在跑时什么都不做。"""
        ...  # pragma: no cover - Protocol 无运行时实现

    def log_tail(self, job: LaunchAgentJob, *, lines: int) -> str:
        """plist 配置的日志文件最后几行，只读当前用户自己的普通文件，已去掉认证材料。"""
        ...  # pragma: no cover - Protocol 无运行时实现


class LocalVerifier(Protocol):
    """修复后在本机再探测一次。"""

    async def port_listening(self, port: int) -> bool: ...

    async def web_status(self, port: int) -> int | None:
        """首页的 HTTP 状态码；端口不说 HTTP 或连不上时返回 None。"""
        ...  # pragma: no cover - Protocol 无运行时实现
