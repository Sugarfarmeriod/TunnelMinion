"""钥匙串在等授权框时，身份密钥的读写照实报“等授权”，不改写成笼统的读写失败。"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime

import pytest

from tunnelminion.model.secrets import SecretStore, SecretStoreApprovalPendingError
from tunnelminion.trust.backup import IdentityState, KeyBackup, read_backup, write_backup
from tunnelminion.trust.keys import (
    PrivateKey,
    delete_private_key,
    load_private_key,
    save_private_key,
)


class WaitingSecrets:
    """授权框还没点：任何读写都等不到。"""

    def get(self, name: str) -> str | None:
        raise SecretStoreApprovalPendingError

    def set(self, name: str, value: str) -> None:
        raise SecretStoreApprovalPendingError

    def delete(self, name: str) -> None:
        raise SecretStoreApprovalPendingError


BACKUP = KeyBackup(
    created_at=datetime(2026, 1, 1, tzinfo=UTC),
    before=IdentityState(),
    after=IdentityState(),
    keys={},
)


ACTIONS: tuple[Callable[[SecretStore], object], ...] = (
    lambda store: load_private_key(store, "trust-owner-key"),
    lambda store: save_private_key(store, "trust-owner-key", PrivateKey.generate()),
    lambda store: delete_private_key(store, "trust-owner-key"),
    read_backup,
    lambda store: write_backup(store, BACKUP),
)


@pytest.mark.parametrize("action", ACTIONS)
def test_waiting_keychain_is_not_reported_as_a_broken_one(
    action: Callable[[SecretStore], object],
) -> None:
    with pytest.raises(SecretStoreApprovalPendingError, match="始终允许"):
        action(WaitingSecrets())
