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
from tunnelminion.repair.contracts import REPAIR_KEY_PREFIXES, RepairKind

# 连续这么多轮异常才确认挂了；连续这么多轮正常才算恢复。
PATROL_CONFIRM_ROUNDS = 3
PATROL_RECOVER_ROUNDS = 2
PATROL_INTERVAL_SECONDS = 30.0
# 同一服务的调查和自动修各自 1 小时最多 1 次。
PATROL_INVESTIGATION_COOLDOWN_SECONDS = 3600
PATROL_AUTO_REPAIR_COOLDOWN_SECONDS = 3600
# 整台电脑每天最多为巡检调查这么多次。
PATROL_DAILY_INVESTIGATIONS = 12
# 每轮最多探测的网页入口数和每次探测的超时。
PATROL_MAX_PROBES = 16
PATROL_PROBE_TIMEOUT_SECONDS = 3.0
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
    PORT_CLOSED = "port_closed"
    WEB_FAILED = "web_failed"


REASON_TEXT: dict[PatrolReason, str] = {
    PatrolReason.CONTAINER_EXITED: "容器已退出",
    PatrolReason.SCRIPT_EXITED: "脚本已退出",
    PatrolReason.AGENT_EXITED: "后台服务已退出",
    PatrolReason.PORT_CLOSED: "端口不再监听",
    PatrolReason.WEB_FAILED: "网页打不开",
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
    thread_id: ThreadId | None = None
    repair_id: OperationId | None = None
    last_investigated_at: datetime | None = None
    auto_repair_enabled: bool = False
    # 主人打开开关的日期，写进自动修的批准依据。
    auto_repair_enabled_on: date | None = None
    auto_repair_paused: bool = False
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
    auto_repair: AutoRepairView


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


def repair_kind_for(key: str) -> RepairKind | None:
    """每个服务只有一种现成修法：容器重启，脚本按启动记录重新拉起，后台服务重新启动。"""
    return next(
        (kind for kind, prefix in REPAIR_KEY_PREFIXES.items() if key.startswith(prefix)), None
    )
