"""动手修服务的计划、启动记录、执行与验证记录，以及执行层的固定接口。

修复复用操作状态机和授权服务。计划只由本机代码根据服务身份、Docker 实时状态、启动记录、
launchd 和 Windows 服务管理器的状态生成；提出修法的一方只能给出服务身份、修法种类和理由，
理由只用于展示，永远不进入任何命令。
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
    # 重新启动当前用户 `~/Library/LaunchAgents` 里已经退出或卡住的 macOS 后台服务。
    RESTART_LAUNCH_AGENT = "restart_launch_agent"
    # 按启动记录重新运行主人自己从终端或用户目录启动、已经退出的普通程序。
    RELAUNCH_PROGRAM = "relaunch_program"
    # 结束巡检确认卡住的程序或 Python 脚本，再按启动记录重新运行。
    RESTART_STUCK_PROGRAM = "restart_stuck_program"
    # 启动或重启主人自己装、并单独授权过的 Windows 服务。
    RESTART_WINDOWS_SERVICE = "restart_windows_service"


# 每种修法在工具注册表里登记为 L2，模型拿不到它们的执行入口。
REPAIR_TOOL_NAMES: dict[RepairKind, str] = {
    RepairKind.RESTART_CONTAINERS: "repair_restart_containers",
    RepairKind.RELAUNCH_PYTHON: "repair_relaunch_python",
    RepairKind.RESTART_LAUNCH_AGENT: "repair_restart_launch_agent",
    RepairKind.RELAUNCH_PROGRAM: "repair_relaunch_program",
    RepairKind.RESTART_STUCK_PROGRAM: "repair_restart_stuck_program",
    RepairKind.RESTART_WINDOWS_SERVICE: "repair_restart_windows_service",
}

# 每种修法适用的服务身份前缀。
REPAIR_KEY_PREFIXES: dict[RepairKind, tuple[str, ...]] = {
    RepairKind.RESTART_CONTAINERS: ("docker:",),
    RepairKind.RELAUNCH_PYTHON: ("python:",),
    RepairKind.RESTART_LAUNCH_AGENT: ("launchd:",),
    RepairKind.RELAUNCH_PROGRAM: ("program:",),
    RepairKind.RESTART_STUCK_PROGRAM: ("program:", "python:"),
    RepairKind.RESTART_WINDOWS_SERVICE: ("program:",),
}

# launchd 标签：只允许字母、数字和 `._@-`，用于服务身份和固定命令参数。
LAUNCH_AGENT_LABEL_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._@-]{0,127}$"
# Windows 服务名：只允许字母、数字和 `._-`，用于固定命令参数。
WINDOWS_SERVICE_NAME_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$"


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
    # compose 写在容器上的服务名和它依赖的服务名，只用来排启动顺序；读不出时为空。
    compose_service: str | None = Field(default=None, min_length=1, max_length=128)
    depends_on: tuple[Annotated[str, Field(min_length=1, max_length=128)], ...] = Field(
        default=(), max_length=32
    )
    # `State.Health.Status`；容器没有健康检查时为 None。
    health: str | None = Field(default=None, min_length=1, max_length=32)


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


class ProgramLaunchRecord(BaseModel):
    """普通程序活着时记下的启动方式；只存在本机，不记环境变量。

    `elevated` 为真表示当前账户读不全它的启动信息（例如它以管理员身份运行），这时只记得
    账户和端口，资格检查据此拒绝并给出现成步骤。
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    service_key: str = Field(pattern=MARK_KEY_PATTERN)
    executable: str | None = Field(default=None, min_length=1, max_length=1_024)
    # 记录时可执行文件的大小和修改时间；执行前据此确认还是同一个文件。
    executable_size: int | None = Field(default=None, ge=0)
    executable_mtime_ns: int | None = Field(default=None, ge=0)
    # 可执行文件之后的完整启动参数。
    arguments: tuple[Annotated[str, Field(max_length=4_096)], ...] = Field(
        default=(), max_length=64
    )
    working_directory: str | None = Field(default=None, min_length=1, max_length=1_024)
    ports: tuple[Annotated[int, Field(ge=1, le=65535)], ...] = Field(min_length=1, max_length=32)
    username: str | None = Field(default=None, min_length=1, max_length=256)
    elevated: bool = False
    rule_shown: bool
    process_id: int = Field(gt=0)
    process_started_at: datetime
    recorded_at: datetime

    @model_validator(mode="after")
    def validate_record(self) -> Self:
        if not self.service_key.startswith("program:"):
            raise ValueError("程序启动记录只属于普通程序")
        if not self.elevated and (
            self.executable is None
            or self.executable_size is None
            or self.executable_mtime_ns is None
            or self.working_directory is None
            or self.username is None
        ):
            raise ValueError("读全了的启动记录必须有可执行文件、工作目录和账户")
        return self

    @property
    def fingerprint(self) -> str:
        """启动方式的指纹；同一启动方式的待批准修复只保留一条。"""
        return _digest(
            [
                self.executable,
                list(self.arguments),
                self.working_directory,
                self.username,
                self.elevated,
            ]
        )


# 能按启动记录重新运行的两种进程：Python 脚本和普通程序。
ProcessLaunchRecord = LaunchRecord | ProgramLaunchRecord


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


class ProgramRepairTarget(BaseModel):
    """按启动记录重新运行一个已经退出的普通程序。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: Literal[RepairKind.RELAUNCH_PROGRAM] = RepairKind.RELAUNCH_PROGRAM
    launch: ProgramLaunchRecord

    @property
    def fingerprint(self) -> str:
        return self.launch.fingerprint

    @property
    def ports(self) -> tuple[int, ...]:
        return tuple(sorted(set(self.launch.ports)))


class StuckProgramRepairTarget(BaseModel):
    """结束卡住的那个进程再按启动记录重新运行；只结束和记录对得上的那一个。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: Literal[RepairKind.RESTART_STUCK_PROGRAM] = RepairKind.RESTART_STUCK_PROGRAM
    launch: LaunchRecord | ProgramLaunchRecord
    # 生成计划时占着端口、和启动记录对得上的进程。
    process_id: int = Field(gt=0)
    process_started_at: datetime

    @property
    def fingerprint(self) -> str:
        return _digest([self.launch.fingerprint, self.process_id])

    @property
    def ports(self) -> tuple[int, ...]:
        return tuple(sorted(set(self.launch.ports)))


class WindowsServiceRecord(BaseModel):
    """见过 Windows 服务正常运行时记下的服务名和端口；不记命令和路径。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    service_key: str = Field(pattern=MARK_KEY_PATTERN)
    service_name: str = Field(pattern=WINDOWS_SERVICE_NAME_PATTERN)
    ports: tuple[Annotated[int, Field(ge=1, le=65535)], ...] = Field(min_length=1, max_length=32)
    rule_shown: bool
    recorded_at: datetime

    @model_validator(mode="after")
    def validate_key(self) -> Self:
        if not self.service_key.startswith("program:"):
            raise ValueError("Windows 服务记录的身份必须是 program:<程序名>@<端口>")
        return self


# 启动记录存储里的一条：Python 脚本或普通程序的启动方式，macOS 后台服务的标签和端口，
# 或 Windows 服务的服务名和端口。
AnyLaunchRecord = LaunchRecord | ProgramLaunchRecord | LaunchAgentRecord | WindowsServiceRecord


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
    # 巡检确认它卡住了：用 `launchctl kickstart -k` 结束再拉起，而不是只拉起已退出的。
    stuck: bool = False

    @property
    def fingerprint(self) -> str:
        """plist 位置和内容的指纹；执行前核对配置有没有变。"""
        values: list[object] = [self.label, self.uid, self.plist_path, self.plist_sha256]
        return _digest([*values, "stuck"] if self.stuck else values)

    @property
    def ports(self) -> tuple[int, ...]:
        return tuple(sorted(set(self.listen_ports)))


class WindowsServiceInfo(BaseModel):
    """本机现读的一个 Windows 服务，只在本机使用。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(pattern=WINDOWS_SERVICE_NAME_PATTERN)
    display_name: str = Field(min_length=1, max_length=256)
    # 服务配置里的可执行文件完整路径（已去掉引号和参数）。
    binary_path: str = Field(min_length=1, max_length=1_024)
    start_type: Literal["automatic", "manual", "disabled"]
    running: bool
    pid: int | None = Field(default=None, gt=0)
    # 当前用户是否已经被主人授予启停这个服务的权限。
    granted: bool


class WindowsServiceRepairTarget(BaseModel):
    """启动已停止的、或重启卡住的 Windows 服务：生成计划时看到的服务配置。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: Literal[RepairKind.RESTART_WINDOWS_SERVICE] = RepairKind.RESTART_WINDOWS_SERVICE
    service_name: str = Field(pattern=WINDOWS_SERVICE_NAME_PATTERN)
    binary_path: str = Field(min_length=1, max_length=1_024)
    listen_ports: tuple[Annotated[int, Field(ge=1, le=65535)], ...] = Field(
        min_length=1, max_length=32
    )
    # 生成计划时它在运行（卡住了）：先停再启动；否则只启动。
    restart: bool

    @property
    def fingerprint(self) -> str:
        return _digest([self.service_name, self.binary_path, self.restart])

    @property
    def ports(self) -> tuple[int, ...]:
        return tuple(sorted(set(self.listen_ports)))


RepairTarget = Annotated[
    ContainerRepairTarget
    | PythonRepairTarget
    | LaunchAgentRepairTarget
    | ProgramRepairTarget
    | StuckProgramRepairTarget
    | WindowsServiceRepairTarget,
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
            isinstance(
                self.target, PythonRepairTarget | ProgramRepairTarget | StuckProgramRepairTarget
            )
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
    # 卡住的程序：结束了哪个进程，以及是不是用了强制结束。
    ended_process_id: int | None = Field(default=None, gt=0)
    ended_forcibly: bool | None = None


class RepairCheckName(StrEnum):
    """本机验证的检查项。"""

    CONTAINER_RUNNING = "container_running"
    LAUNCH_AGENT_RUNNING = "launch_agent_running"
    WINDOWS_SERVICE_RUNNING = "windows_service_running"
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
    # 它原来以管理员或 root 身份运行，普通账户读不全启动信息，也没法同样拉起。
    NEEDS_ADMIN = "needs_admin"
    # 可执行文件不在了，或者和记录时不是同一个文件。
    EXECUTABLE_CHANGED = "executable_changed"
    # 巡检还没确认它卡住了，它可能只是慢。
    NOT_STUCK = "not_stuck"
    # Windows 服务被主人设成了"已禁用"。
    SERVICE_DISABLED = "service_disabled"
    # 主人还没对这个 Windows 服务打开这种修法（没有授权启停权限）。
    NOT_AUTHORIZED = "not_authorized"
    SERVICE_CHANGED = "service_changed"
    BUSY = "busy"
    RATE_LIMITED = "rate_limited"
    AUTHORIZATION_EXPIRED = "authorization_expired"
    EXECUTION_FAILED = "execution_failed"
    VERIFICATION_FAILED = "verification_failed"
    INTERRUPTED = "interrupted"


class ManualStep(BaseModel):
    """修不了时给主人照抄的一步：由本机代码按固定模板生成，不含密钥，只显示、不执行。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    # 用大白话说这一步在哪做，例如"以管理员身份打开 PowerShell，运行"。
    text: str = Field(min_length=1, max_length=200)
    command: str | None = Field(default=None, min_length=1, max_length=2_000)


class RepairError(BaseModel):
    """给人看的失败说明和下一步建议。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    code: RepairErrorCode
    message: str = Field(min_length=1, max_length=500)
    next_step: str | None = Field(default=None, min_length=1, max_length=500)
    manual_steps: tuple[ManualStep, ...] = Field(default=(), max_length=5)


class RepairAuditAction(StrEnum):
    """本机审计记录里的一步。"""

    PROPOSED = "proposed"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"
    PRECHECK_PASSED = "precheck_passed"
    PRECHECK_FAILED = "precheck_failed"
    COMMAND_EXECUTED = "command_executed"
    PROCESS_ENDED = "process_ended"
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
    # 这个进程是不是按同一份启动记录跑起来的同一个程序（可执行文件、参数、目录都一致）。
    matches_launch: bool
    # 进程的启动时间；读不到时为 None。
    started_at: datetime | None = None


class ContainerRuntime(Protocol):
    """固定的 Docker 命令：只读查询，以及 `docker start` / `docker restart` / `docker stop`。

    不用 `docker compose up`、不拉镜像、不重建容器、不删除任何东西。
    """

    async def list_containers(
        self, *, compose_project: str | None, container_name: str | None
    ) -> tuple[ContainerSnapshot, ...] | None:
        """按 compose 项目标签或容器名找出容器；Docker 没在运行时返回 None。"""
        ...  # pragma: no cover - Protocol 无运行时实现

    async def start(self, container_ids: tuple[str, ...]) -> RepairCommand: ...

    async def restart(self, container_ids: tuple[str, ...]) -> RepairCommand: ...

    async def stop(self, container_ids: tuple[str, ...]) -> RepairCommand:
        """停下已有容器，供 compose 组按依赖反向顺序重启；不删除容器。"""
        ...  # pragma: no cover - Protocol 无运行时实现

    async def logs_tail(self, container_id: str, *, lines: int) -> str:
        """最后几行日志，已去掉常见认证材料；读不到时返回空串。"""
        ...  # pragma: no cover - Protocol 无运行时实现


class ProcessLauncher(Protocol):
    """按启动记录在后台拉起程序，并且只停掉自己拉起的或和记录对得上的进程。"""

    def launch(self, record: ProcessLaunchRecord, *, log_path: Path) -> SpawnedProcess:
        """用原可执行文件、原参数、原目录在后台启动；TunnelMinion 退出后程序照常运行。

        失败时抛出 `OSError`。
        """
        ...  # pragma: no cover - Protocol 无运行时实现

    def end_stuck(
        self,
        pid: int,
        started_at: datetime,
        launch: ProcessLaunchRecord,
        *,
        grace_seconds: float,
    ) -> bool | None:
        """先礼貌结束，等 `grace_seconds` 还在再强制结束（连同子进程）。

        进程号、启动时间和启动记录都对得上才动手；返回是否用了强制结束，没能结束或对不上
        启动记录时返回 None。进程已经不在也算结束（返回 False）。
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

    def port_owner(self, port: int, launch: ProcessLaunchRecord | None = None) -> PortOwner | None:
        """端口没人监听时返回 None；给了启动记录时顺带判断是不是同一个程序。"""
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

    async def kickstart(self, label: str, *, kill: bool = False) -> RepairCommand:
        """`launchctl kickstart gui/<uid>/<标签>`；`kill` 为真时带 `-k`，先结束在跑的再拉起。"""
        ...  # pragma: no cover - Protocol 无运行时实现

    def log_tail(self, job: LaunchAgentJob, *, lines: int) -> str:
        """plist 配置的日志文件最后几行，只读当前用户自己的普通文件，已去掉认证材料。"""
        ...  # pragma: no cover - Protocol 无运行时实现


class WindowsServiceRuntime(Protocol):
    """当前电脑上的 Windows 服务：只读查询、固定的启动和停止，以及单个服务的授权。

    只用 Windows 自带的服务管理；授权只给当前用户加上启停这一个服务的权限，撤回时去掉。
    """

    def unsupported_reason(self) -> str | None:
        """这台电脑上不能用这种修法的原因（不是 Windows）；能用时返回 None。"""
        ...  # pragma: no cover - Protocol 无运行时实现

    def services_for_pids(self, pids: frozenset[int]) -> dict[int, str]:
        """监听进程号到 Windows 服务名；进程本身或它往上的父进程是服务进程都算。"""
        ...  # pragma: no cover - Protocol 无运行时实现

    def inspect(self, name: str) -> WindowsServiceInfo | None: ...

    async def set_granted(self, name: str, *, granted: bool) -> bool:
        """弹一次管理员确认，给当前用户加上或去掉启停这个服务的权限；主人拒绝时返回 False。"""
        ...  # pragma: no cover - Protocol 无运行时实现

    async def start(self, name: str) -> RepairCommand: ...

    async def stop(self, name: str) -> RepairCommand: ...


class LocalVerifier(Protocol):
    """修复后在本机再探测一次。"""

    async def port_listening(self, port: int) -> bool: ...

    async def web_status(self, port: int) -> int | None:
        """首页的 HTTP 状态码；端口不说 HTTP 或连不上时返回 None。"""
        ...  # pragma: no cover - Protocol 无运行时实现
