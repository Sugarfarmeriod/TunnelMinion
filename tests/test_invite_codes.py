"""邀请码的编码与解析。"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from tunnelminion.domain.identifiers import NodeId
from tunnelminion.domain.invites import (
    INVITE_CODE_PREFIX,
    InvalidInviteCodeError,
    InviteCode,
    InvitePermissions,
)
from tunnelminion.domain.tools import Platform

CODE = InviteCode(
    node_id=NodeId("node_cfa83719e09d4720b7de7307d5e68c4d"),
    platform=Platform.MACOS,
    host="10.77.0.1",
    port=8787,
    token="tmn_" + "a" * 40,
    permissions=InvitePermissions(allow_model_borrowing=True, daily_quota=1000),
    expires_at=datetime(2026, 10, 26, tzinfo=UTC),
)


def test_round_trip_ignores_surrounding_whitespace() -> None:
    text = CODE.encode()
    assert text.startswith(INVITE_CODE_PREFIX) and "=" not in text
    assert InviteCode.decode(f"  {text}\n") == CODE


@pytest.mark.parametrize(
    "value", ["", "hello", "tmi1_", "tmi1_!!!", "tmi1_e30", CODE.encode()[:-8]]
)
def test_invalid_codes_are_rejected(value: str) -> None:
    with pytest.raises(InvalidInviteCodeError):
        InviteCode.decode(value)


def test_token_is_hidden_from_repr() -> None:
    assert CODE.token not in repr(CODE)
