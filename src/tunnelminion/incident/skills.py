"""版本化 Investigation Skill 数据契约与内置注册表。"""

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, model_validator

from tunnelminion.domain.tools import Platform
from tunnelminion.incident.contracts import (
    EvidenceExecution,
    Incident,
    IncidentEventType,
)


class InvestigationTopology(StrEnum):
    LOCAL = "local"
    REMOTE = "remote"


class SkillEvidenceRequirement(BaseModel):
    """Skill 需要确认的一项语义事实。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    requirement_id: str = Field(pattern=r"^[a-z][a-z0-9-]{1,63}$")
    description: str = Field(min_length=1, max_length=160)


class SkillEvidenceStep(BaseModel):
    """取得一项或多项语义证据的只读工具步骤。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    step_id: str = Field(pattern=r"^[a-z][a-z0-9-]{1,63}$")
    requirement_ids: tuple[str, ...] = Field(min_length=1, max_length=8)
    tool_name: str = Field(pattern=r"^[a-z][a-z0-9_]{1,63}$")
    execution: EvidenceExecution
    depends_on: tuple[str, ...] = Field(default=(), max_length=8)


class InvestigationSkill(BaseModel):
    """只描述调查约束，不执行工具、不保存状态也不授予权限。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    skill_id: str = Field(pattern=r"^[a-z][a-z0-9.-]{2,79}$")
    version: str = Field(pattern=r"^[1-9][0-9]*$")
    title: str = Field(min_length=1, max_length=80)
    description: str = Field(min_length=1, max_length=240)
    event_types: frozenset[IncidentEventType]
    topologies: frozenset[InvestigationTopology]
    request_platforms: frozenset[Platform]
    target_platforms: frozenset[Platform]
    requirements: tuple[SkillEvidenceRequirement, ...] = Field(min_length=1, max_length=16)
    steps: tuple[SkillEvidenceStep, ...] = Field(min_length=1, max_length=16)
    confirmation_conditions: tuple[str, ...] = Field(min_length=1, max_length=12)
    unknown_conditions: tuple[str, ...] = Field(min_length=1, max_length=12)
    failure_handling: tuple[str, ...] = Field(min_length=1, max_length=12)
    output_schema: str

    @model_validator(mode="after")
    def validate_graph(self) -> "InvestigationSkill":
        requirements = {item.requirement_id for item in self.requirements}
        step_ids = {item.step_id for item in self.steps}
        if len(requirements) != len(self.requirements) or len(step_ids) != len(self.steps):
            raise ValueError("Skill requirement 和 step 身份不得重复")
        covered = {value for step in self.steps for value in step.requirement_ids}
        dependencies = {value for step in self.steps for value in step.depends_on}
        if covered != requirements or not dependencies.issubset(step_ids):
            raise ValueError("Skill 步骤必须完整覆盖 requirement 且依赖已定义")
        return self


SERVICE_LOCAL_ONLY = InvestigationSkill(
    skill_id="service.local-only",
    version="1",
    title="服务只能从本机访问",
    description="核对目标进程、监听范围、私网接口和请求端探测，区分访问限制与证据不足。",
    event_types=frozenset({IncidentEventType.LOCAL_ONLY}),
    topologies=frozenset({InvestigationTopology.LOCAL, InvestigationTopology.REMOTE}),
    request_platforms=frozenset({Platform.WINDOWS, Platform.MACOS, Platform.LINUX}),
    target_platforms=frozenset({Platform.WINDOWS, Platform.MACOS, Platform.LINUX}),
    requirements=(
        SkillEvidenceRequirement(
            requirement_id="target-process",
            description="目标端口具有可识别的活动进程",
        ),
        SkillEvidenceRequirement(
            requirement_id="target-listener",
            description="目标端口只绑定回环地址",
        ),
        SkillEvidenceRequirement(
            requirement_id="private-network",
            description="目标节点私网接口可用且具有地址",
        ),
        SkillEvidenceRequirement(
            requirement_id="requester-reachability",
            description="请求端无法访问目标私网地址和端口",
        ),
    ),
    steps=(
        SkillEvidenceStep(
            step_id="target-node",
            requirement_ids=("private-network",),
            tool_name="get_node_summary",
            execution=EvidenceExecution.TARGET,
        ),
        SkillEvidenceStep(
            step_id="target-listener",
            requirement_ids=("target-process", "target-listener"),
            tool_name="list_network_listeners",
            execution=EvidenceExecution.TARGET,
            depends_on=("target-node",),
        ),
        SkillEvidenceStep(
            step_id="requester-probe",
            requirement_ids=("requester-reachability",),
            tool_name="probe_service_reachability",
            execution=EvidenceExecution.REQUESTER,
            depends_on=("target-node",),
        ),
    ),
    confirmation_conditions=(
        "private_network_ready=true",
        "process_present=true",
        "loopback_only=true",
        "reachable=false",
    ),
    unknown_conditions=(
        "required_evidence_missing",
        "required_evidence_conflict",
        "evidence_unavailable",
    ),
    failure_handling=(
        "target_preflight_failure=insufficient_evidence",
        "tool_failure=retain_unknown",
        "budget_exhausted=preserve_partial_state",
        "cancelled=preserve_partial_state",
    ),
    output_schema="incident-report/v1",
)

INVESTIGATION_SKILLS = (SERVICE_LOCAL_ONLY,)


def available_investigation_skills(
    *,
    topology: InvestigationTopology,
    request_platform: Platform,
    target_platform: str | None,
    event_type: IncidentEventType | None = None,
) -> tuple[InvestigationSkill, ...]:
    """按已知任务条件列目录；远端预检后还须核对实际目标平台和工具。"""
    return tuple(
        skill
        for skill in INVESTIGATION_SKILLS
        if topology in skill.topologies
        and request_platform in skill.request_platforms
        and (target_platform is None or target_platform in skill.target_platforms)
        and (event_type is None or event_type in skill.event_types)
    )


def get_investigation_skill(skill_id: str, version: str) -> InvestigationSkill | None:
    """只精确读取受版本控制的内置方法，不解析文件路径或执行方法中的文字。"""
    return next(
        (
            skill
            for skill in INVESTIGATION_SKILLS
            if skill.skill_id == skill_id and skill.version == version
        ),
        None,
    )


def select_investigation_skill(
    incident: Incident,
    *,
    local_node_id: str | None,
    request_platform: Platform,
    target_platform: str | None,
) -> InvestigationSkill | None:
    """事件调查与聊天共用目录，不匹配时保留既有无技能调查路径。"""
    topology = (
        InvestigationTopology.LOCAL
        if local_node_id is None or str(incident.event.target_node_id) == local_node_id
        else InvestigationTopology.REMOTE
    )
    return next(
        iter(
            available_investigation_skills(
                topology=topology,
                request_platform=request_platform,
                target_platform=target_platform,
                event_type=incident.event.event_type,
            )
        ),
        None,
    )
