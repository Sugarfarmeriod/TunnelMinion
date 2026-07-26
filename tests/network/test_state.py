"""受管路径状态机测试。"""

from __future__ import annotations

from datetime import timedelta

import pytest
from pydantic import ValidationError
from tests.network.factories import NETWORK_ID, NODE_A, NOW

from tunnelminion.network.state import (
    ManagedPathRecord,
    ManagedPathState,
    ManagedPathTransition,
    transition_managed_path,
)


def test_state_machine_accepts_direct_relay_degraded_and_rollback_paths() -> None:
    record = ManagedPathRecord.unconfigured(network_id=NETWORK_ID, node_id=NODE_A, occurred_at=NOW)
    states = (
        ManagedPathState.AWAITING_AUTHORIZATION,
        ManagedPathState.APPLYING,
        ManagedPathState.PROBING,
        ManagedPathState.DIRECT,
        ManagedPathState.RELAYED,
        ManagedPathState.DEGRADED,
        ManagedPathState.ROLLING_BACK,
        ManagedPathState.PROBING,
        ManagedPathState.DIRECT,
    )
    for index, state in enumerate(states, start=1):
        record = transition_managed_path(
            record,
            state,
            revision=1,
            reason=state.value,
            occurred_at=NOW + timedelta(seconds=index),
        )
    assert record.state is ManagedPathState.DIRECT


def test_state_machine_accepts_conflict_and_manual_intervention() -> None:
    record = ManagedPathRecord.unconfigured(network_id=NETWORK_ID, node_id=NODE_A, occurred_at=NOW)
    record = transition_managed_path(
        record,
        ManagedPathState.APPLYING,
        revision=1,
        reason="authorized",
        occurred_at=NOW + timedelta(seconds=1),
    )
    record = transition_managed_path(
        record,
        ManagedPathState.OWNERSHIP_CONFLICT,
        revision=1,
        reason="fingerprint mismatch",
        occurred_at=NOW + timedelta(seconds=2),
    )
    record = transition_managed_path(
        record,
        ManagedPathState.MANUAL_INTERVENTION,
        revision=1,
        reason="operator required",
        occurred_at=NOW + timedelta(seconds=3),
    )
    assert record.state is ManagedPathState.MANUAL_INTERVENTION


def test_state_machine_rejects_invalid_transition_and_history() -> None:
    record = ManagedPathRecord.unconfigured(network_id=NETWORK_ID, node_id=NODE_A, occurred_at=NOW)
    with pytest.raises(ValueError, match="不允许"):
        transition_managed_path(
            record,
            ManagedPathState.DIRECT,
            revision=1,
            reason="skip",
            occurred_at=NOW,
        )

    initial = record.transitions[0]
    invalid = (
        (
            (
                initial,
                ManagedPathTransition(
                    from_state=ManagedPathState.APPLYING,
                    to_state=ManagedPathState.PROBING,
                    revision=1,
                    reason="broken",
                    occurred_at=NOW,
                ),
            ),
            "不连续",
        ),
        (
            (
                initial,
                ManagedPathTransition(
                    from_state=ManagedPathState.UNCONFIGURED,
                    to_state=ManagedPathState.DIRECT,
                    revision=1,
                    reason="illegal",
                    occurred_at=NOW,
                ),
            ),
            "非法转换",
        ),
    )
    for transitions, match in invalid:
        with pytest.raises(ValidationError, match=match):
            ManagedPathRecord.model_validate(
                {
                    **record.model_dump(),
                    "state": transitions[-1].to_state,
                    "revision": transitions[-1].revision,
                    "transitions": transitions,
                }
            )


def test_state_history_rejects_revision_time_and_summary_mismatch() -> None:
    record = ManagedPathRecord.unconfigured(network_id=NETWORK_ID, node_id=NODE_A, occurred_at=NOW)
    applying = transition_managed_path(
        record,
        ManagedPathState.APPLYING,
        revision=2,
        reason="apply",
        occurred_at=NOW + timedelta(seconds=2),
    )
    cases = (
        {
            "transition": ManagedPathTransition(
                from_state=ManagedPathState.APPLYING,
                to_state=ManagedPathState.PROBING,
                revision=1,
                reason="old",
                occurred_at=NOW + timedelta(seconds=3),
            ),
            "match": "revision",
        },
        {
            "transition": ManagedPathTransition(
                from_state=ManagedPathState.APPLYING,
                to_state=ManagedPathState.PROBING,
                revision=2,
                reason="past",
                occurred_at=NOW,
            ),
            "match": "时间",
        },
    )
    for case in cases:
        transition = case["transition"]
        assert isinstance(transition, ManagedPathTransition)
        with pytest.raises(ValidationError, match=str(case["match"])):
            ManagedPathRecord.model_validate(
                {
                    **applying.model_dump(),
                    "state": transition.to_state,
                    "revision": transition.revision,
                    "transitions": (*applying.transitions, transition),
                }
            )

    with pytest.raises(ValidationError, match="当前状态"):
        ManagedPathRecord.model_validate(
            {**record.model_dump(), "state": ManagedPathState.APPLYING}
        )
    with pytest.raises(ValidationError, match="更新时间"):
        ManagedPathRecord.model_validate(
            {**record.model_dump(), "updated_at": NOW - timedelta(seconds=1)}
        )
