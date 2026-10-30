"""巡检状态、"挂了可以自动修"开关和对网页公开的巡检视图。

巡检只读本机服务缓存和本机网页首页状态码，不调模型；状态只存在本机，不发给别的电脑。
"""

from __future__ import annotations

from datetime import date, datetime
from enum import StrEnum
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field

from tunnelminion.domain.identifiers import OperationId, ThreadId
from tunnelminion.domain.service_marks import MARK_KEY_PATTERN
from tunnelminion.repair.contracts import ManualStep, RepairKind

# 连续这么多轮异常才确认挂了；连续这么多轮正常才算恢复。
PATROL_CONFIRM_ROUNDS = 3
PATROL_RECOVER_ROUNDS = 2
PATROL_INTERVAL_SECONDS = 30.0
# 同一服务的调查和自动修各自 1 小时最多 1 次。
PATROL_INVESTIGATION_COOLDOWN_SECONDS = 3600
PATROL_AUTO_REPAIR_COOLDOWN_SECONDS = 3600
# 整台电脑每天最多为巡检调查这么多次。
PATROL_DAILY_INVESTIGATIONS = 12
# 每轮最多探测的网页入口数，以及等一次探测的上限。探测线程里每一步都有自己的超时
# （见 `SocketLocalVerifier`），最慢也在这个时间内自己结束；等不到结果只算这一轮看不清。
PATROL_MAX_PROBES = 16
PATROL_PROBE_TIMEOUT_SECONDS = 30.0
# 一次巡检调查最多等这么久，超时就取消，不让自动修一直等模型。
PATROL_INVESTIGATION_WAIT_SECONDS = 300.0

ServiceKey = Annotated[str, Field(pattern=MARK_KEY_PATTERN)]


class PatrolStatus(StrEnum):
    """一个被巡检服务现在的状态。"""

    OK = "ok"
    # 已经有异常，但还没连续够确认次数。
    SUSPECT = "suspect"
    DOWN = "down"
    # 主人说这次是有意停的：再次看到它正常运行之前不提醒、不自动修。
    ACKNOWLEDGED = "acknowledged"


class PatrolReason(StrEnum):
    """挂了的原因，由固定规则判断。"""

    CONTAINER_EXITED = "container_exited"
    SCRIPT_EXITED = "script_exited"
    AGENT_EXITED = "agent_exited"
    PROGRAM_EXITED = "program_exited"
    SERVICE_STOPPED = "service_stopped"
    PORT_CLOSED = "port_closed"
    WEB_FAILED = "web_failed"
    # 进程在、端口在听，但以前能打开的网页打不开了，或者以前会先回话的端口不回话了。
    STUCK = "stuck"


REASON_TEXT: dict[PatrolReason, str] = {
    PatrolReason.CONTAINER_EXITED: "容器已退出",
    PatrolReason.SCRIPT_EXITED: "脚本已退出",
    PatrolReason.AGENT_EXITED: "后台服务已退出",
    PatrolReason.PROGRAM_EXITED: "程序已退出",
    PatrolReason.SERVICE_STOPPED: "Windows 服务已停止",
    PatrolReason.PORT_CLOSED: "端口不再监听",
    PatrolReason.WEB_FAILED: "网页打不开",
    PatrolReason.STUCK: "卡住了：端口还在听，但不再响应",
}


class AutoRepairResult(StrEnum):
    """最近一次自动修的结果。"""

    SUCCEEDED = "succeeded"
    FAILED = "failed"


class PatrolRecord(BaseModel):
    """一个服务的巡检记录：见没见过正常、现在的状态、开关和最近一次自动修。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    key: ServiceKey
    name: str = Field(min_length=1, max_length=80)
    # 巡检见过它正常运行；只有见过正常的服务再出问题才算挂了。
    seen_running: bool = False
    status: PatrolStatus = PatrolStatus.OK
    reason: PatrolReason | None = None
    # 第一次看到异常的时间和确认挂了的时间。
    down_since: datetime | None = None
    confirmed_at: datetime | None = None
    # 见到正常时的端口，以及其中能打开网页的端口。
    ports: tuple[Annotated[int, Field(ge=1, le=65535)], ...] = Field(default=(), max_length=32)
    web_ports: tuple[Annotated[int, Field(ge=1, le=65535)], ...] = Field(default=(), max_length=32)
    # 正常时连上就先回话的端口（例如 SSH 先报版本号），和连上以后不说话、等客户端先开口的端口。
    # 只有以前会回话的端口不回话了才算卡住；本来就不说话的端口永远不会被判成卡住。
    talk_ports: tuple[Annotated[int, Field(ge=1, le=65535)], ...] = Field(default=(), max_length=32)
    quiet_ports: tuple[Annotated[int, Field(ge=1, le=65535)], ...] = Field(
        default=(), max_length=32
    )
    thread_id: ThreadId | None = None
    repair_id: OperationId | None = None
    # 这次挂了以后巡检想提出修法却被拒绝的原因，以及本机生成的现成步骤。
    repair_refusal: str | None = Field(default=None, max_length=1_000)
    manual_steps: tuple[ManualStep, ...] = Field(default=(), max_length=5)
    last_investigated_at: datetime | None = None
    auto_repair_enabled: bool = False
    # 主人打开开关的日期，写进自动修的批准依据。
    auto_repair_enabled_on: date | None = None
    auto_repair_paused: bool = False
    # 卡住了也自动修：要在"挂了可以自动修"之外单独打开。
    auto_repair_stuck_enabled: bool = False
    last_auto_repair_at: datetime | None = None
    last_auto_repair_result: AutoRepairResult | None = None


class AutoRepairView(BaseModel):
    """ "挂了可以自动修"开关的公开状态。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    # 这个服务有没有现成的修法；没有就没有开关。
    available: bool
    kind: RepairKind | None = None
    enabled: bool
    enabled_on: date | None = None
    paused: bool
    last_attempt_at: datetime | None = None
    last_result: AutoRepairResult | None = None
    # 卡住时有没有现成修法，以及主人有没有单独打开"卡住了也自动修"。
    stuck_available: bool = False
    stuck_enabled: bool = False


class WindowsServiceView(BaseModel):
    """主人自己装的 Windows 服务：实际的服务名、程序路径，以及有没有允许 Agent 启停它。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str
    display_name: str
    binary_path: str
    granted: bool
    # 为假时只能撤回：服务不再标成"是我的服务"，或落进了保护名单。
    allowed: bool


class PatrolServiceView(BaseModel):
    """地图上一个服务的巡检状态。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    key: str
    name: str
    status: PatrolStatus
    reason: PatrolReason | None = None
    reason_text: str | None = None
    down_since: datetime | None = None
    confirmed_at: datetime | None = None
    thread_id: ThreadId | None = None
    repair_id: OperationId | None = None
    repair_refusal: str | None = None
    manual_steps: tuple[ManualStep, ...] = ()
    auto_repair: AutoRepairView
    windows_service: WindowsServiceView | None = None


class PatrolView(BaseModel):
    """`GET /api/patrol` 的返回。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    checked_at: datetime | None = None
    investigations_left_today: int = Field(ge=0)
    services: tuple[PatrolServiceView, ...] = ()


class AutoRepairInput(BaseModel):
    """打开或关闭"挂了可以自动修"。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    enabled: bool
    # 同时设置"卡住了也自动修"；不给时保持原样，关掉"挂了可以自动修"时一并关掉。
    stuck: bool | None = None


class WindowsServiceGrantInput(BaseModel):
    """允许或撤回 Agent 启停这个 Windows 服务。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    granted: bool


def repair_kind_for(
    key: str, reason: PatrolReason | None = None, *, windows_service: bool = False
) -> RepairKind | None:
    """按服务种类和挂掉的原因选固定修法；卡住的程序和脚本先结束再重新运行。"""
    stuck = reason is PatrolReason.STUCK
    if key.startswith("docker:"):
        return RepairKind.RESTART_CONTAINERS
    if key.startswith("launchd:"):
        return RepairKind.RESTART_LAUNCH_AGENT
    if key.startswith("program:") and windows_service:
        return RepairKind.RESTART_WINDOWS_SERVICE
    if key.startswith(("python:", "program:")) and stuck:
        return RepairKind.RESTART_STUCK_PROGRAM
    if key.startswith("python:"):
        return RepairKind.RELAUNCH_PYTHON
    if key.startswith("program:"):
        return RepairKind.RELAUNCH_PROGRAM
    return None
