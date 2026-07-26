"""受管连接的确定性状态机。"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from tunnelminion.domain.identifiers import NetworkId, NodeId


class ManagedPathState(StrEnum):
    """配置应用、探测、路径与恢复状态。"""

    UNCONFIGURED = "unconfigured"
    AWAITING_AUTHORIZATION = "awaiting_authorization"
    APPLYING = "applying"
    PROBING = "probing"
    DIRECT = "direct"
    RELAYED = "relayed"
    DEGRADED = "degraded"
    ROLLING_BACK = "rolling_back"
    OWNERSHIP_CONFLICT = "ownership_conflict"
    MANUAL_INTERVENTION = "manual_intervention"


_ALLOWED: dict[ManagedPathState, frozenset[ManagedPathState]] = {
    ManagedPathState.UNCONFIGURED: frozenset(
        {ManagedPathState.AWAITING_AUTHORIZATION, ManagedPathState.APPLYING}
    ),
    ManagedPathState.AWAITING_AUTHORIZATION: frozenset(
        {ManagedPathState.APPLYING, ManagedPathState.UNCONFIGURED}
    ),
    ManagedPathState.APPLYING: frozenset(
        {
            ManagedPathState.PROBING,
            ManagedPathState.ROLLING_BACK,
            ManagedPathState.OWNERSHIP_CONFLICT,
            ManagedPathState.MANUAL_INTERVENTION,
        }
    ),
    ManagedPathState.PROBING: frozenset(
        {
            ManagedPathState.DIRECT,
            ManagedPathState.RELAYED,
            ManagedPathState.DEGRADED,
            ManagedPathState.ROLLING_BACK,
        }
    ),
    ManagedPathState.DIRECT: frozenset(
        {
            ManagedPathState.RELAYED,
            ManagedPathState.DEGRADED,
            ManagedPathState.ROLLING_BACK,
        }
    ),
    ManagedPathState.RELAYED: frozenset(
        {
            ManagedPathState.DIRECT,
            ManagedPathState.DEGRADED,
            ManagedPathState.ROLLING_BACK,
        }
    ),
    ManagedPathState.DEGRADED: frozenset(
        {
            ManagedPathState.PROBING,
            ManagedPathState.ROLLING_BACK,
            ManagedPathState.MANUAL_INTERVENTION,
        }
    ),
    ManagedPathState.ROLLING_BACK: frozenset(
        {
            ManagedPathState.UNCONFIGURED,
            ManagedPathState.PROBING,
            ManagedPathState.OWNERSHIP_CONFLICT,
            ManagedPathState.MANUAL_INTERVENTION,
        }
    ),
    ManagedPathState.OWNERSHIP_CONFLICT: frozenset({ManagedPathState.MANUAL_INTERVENTION}),
}


class ManagedPathTransition(BaseModel):
    """一次连续且可审计的状态变化。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    from_state: ManagedPathState | None
    to_state: ManagedPathState
    revision: int = Field(ge=0)
    reason: str = Field(min_length=1, max_length=500)
    occurred_at: datetime


class ManagedPathRecord(BaseModel):
    """单 network/node 的完整状态历史。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    network_id: NetworkId
    node_id: NodeId
    state: ManagedPathState
    revision: int = Field(ge=0)
    transitions: tuple[ManagedPathTransition, ...] = Field(min_length=1, max_length=256)
    updated_at: datetime

    @model_validator(mode="after")
    def validate_history(self) -> Self:
        previous: ManagedPathState | None = None
        revision = 0
        occurred_at: datetime | None = None
        for transition in self.transitions:
            if transition.from_state is not previous:
                raise ValueError("受管路径状态历史不连续")
            if previous is not None and transition.to_state not in _ALLOWED.get(
                previous, frozenset()
            ):
                raise ValueError("受管路径状态历史包含非法转换")
            if transition.revision < revision:
                raise ValueError("配置 revision 不得倒退")
            if occurred_at is not None and transition.occurred_at < occurred_at:
                raise ValueError("状态时间不得倒退")
            previous = transition.to_state
            revision = transition.revision
            occurred_at = transition.occurred_at
        if self.state is not previous or self.revision != revision:
            raise ValueError("当前状态/revision 必须匹配最后一条历史")
        if self.updated_at < self.transitions[-1].occurred_at:
            raise ValueError("更新时间不得早于最后状态变化")
        return self

    @classmethod
    def unconfigured(
        cls,
        *,
        network_id: NetworkId,
        node_id: NodeId,
        occurred_at: datetime,
    ) -> Self:
        """建立 revision 0 的初始状态。"""
        transition = ManagedPathTransition(
            from_state=None,
            to_state=ManagedPathState.UNCONFIGURED,
            revision=0,
            reason="尚未配置受管网络",
            occurred_at=occurred_at,
        )
        return cls(
            network_id=network_id,
            node_id=node_id,
            state=ManagedPathState.UNCONFIGURED,
            revision=0,
            transitions=(transition,),
            updated_at=occurred_at,
        )


def transition_managed_path(
    record: ManagedPathRecord,
    to_state: ManagedPathState,
    *,
    revision: int,
    reason: str,
    occurred_at: datetime,
) -> ManagedPathRecord:
    """执行单次合法转换并拒绝终态重开或 revision 倒退。"""
    if to_state not in _ALLOWED.get(record.state, frozenset()):
        raise ValueError(f"不允许从 {record.state.value} 转换到 {to_state.value}")
    transition = ManagedPathTransition(
        from_state=record.state,
        to_state=to_state,
        revision=revision,
        reason=reason,
        occurred_at=occurred_at,
    )
    return ManagedPathRecord.model_validate(
        {
            **record.model_dump(),
            "state": to_state,
            "revision": revision,
            "transitions": (*record.transitions, transition),
            "updated_at": occurred_at,
        }
    )
