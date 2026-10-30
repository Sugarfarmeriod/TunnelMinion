"""钥匙串在等授权框时，读取身份密钥照实报“等授权”，不改写成笼统的读取失败。"""

from __future__ import annotations

from collections.abc import Callable

import pytest

from tunnelminion.model.secrets import SecretStore, SecretStoreApprovalPendingError
from tunnelminion.trust.backup import read_backup
from tunnelminion.trust.keys import load_private_key


class WaitingSecrets:
    """授权框还没点：读取等不到。"""

    def get(self, name: str) -> str | None:
        raise SecretStoreApprovalPendingError

    def set(self, name: str, value: str) -> None:
        raise AssertionError

    def delete(self, name: str) -> None:
        raise AssertionError


ACTIONS: tuple[Callable[[SecretStore], object], ...] = (
    lambda store: load_private_key(store, "trust-owner-key"),
    read_backup,
)


@pytest.mark.parametrize("action", ACTIONS)
def test_waiting_keychain_is_not_reported_as_a_broken_one(
    action: Callable[[SecretStore], object],
) -> None:
    with pytest.raises(SecretStoreApprovalPendingError, match="始终允许"):
        action(WaitingSecrets())
