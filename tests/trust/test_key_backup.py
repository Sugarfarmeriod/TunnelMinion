"""换身份密钥中断后能找回旧密钥；回滚时每把密钥单独处理、最后统一报错。"""

from __future__ import annotations

import sqlite3
from collections.abc import Callable
from pathlib import Path

import pytest
from fastapi import FastAPI
from tests.trust.test_own_devices import Computer, computer
from tests.trust.test_recovery import recoverable_computer

from tunnelminion.domain.trust import PassScope, key_fingerprint
from tunnelminion.gateway.security import GatewayBindConfig
from tunnelminion.model.secrets import SecretStoreError
from tunnelminion.trust.backup import (
    KEY_BACKUP_NAME,
    IdentityState,
    KeyBackup,
    read_backup,
    restore_keys,
    settle_key_backup,
)
from tunnelminion.trust.contracts import IdentityError
from tunnelminion.trust.keys import (
    DEVICE_KEY_NAME,
    IDENTITY_KEY_NAMES,
    OWNER_KEY_NAME,
    InitializationKeys,
    PrivateKey,
    parse_recovery_code,
)
from tunnelminion.trust.passes import issue_pass
from tunnelminion.trust.recovery import recover_owner
from tunnelminion.trust.service import IdentityKeySwap, OwnerIdentityService


class Killed(BaseException):
    """模拟进程在钥匙串写完、事务提交前被杀：不是 Exception，任何回滚都来不及执行。"""


def kill_after_keys(monkeypatch: pytest.MonkeyPatch) -> None:
    original = IdentityKeySwap.persist

    def persist_then_die(self: IdentityKeySwap) -> None:
        original(self)
        raise Killed

    monkeypatch.setattr(IdentityKeySwap, "persist", persist_then_die)


def interrupted_recovery(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[Computer, dict[str, str], PrivateKey]:
    a, keys = recoverable_computer(tmp_path / "a", 1, {})
    before = dict(a.secrets.values)
    new_owner = PrivateKey.generate()
    with monkeypatch.context() as patch:
        kill_after_keys(patch)
        with pytest.raises(Killed):
            recover_owner(
                a.service, parse_recovery_code(keys.recovery_code), new_owner, PrivateKey.generate()
            )
    return a, before, new_owner


def test_owner_key_survives_kill_between_keychain_and_commit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    a, before, new_owner = interrupted_recovery(tmp_path, monkeypatch)
    # 数据库没提交，钥匙串里却已经是新机主密钥；旧密钥只剩备份里那一份。
    assert a.service.store.owner_fingerprint() == key_fingerprint(
        PrivateKey.from_seed_text(before[OWNER_KEY_NAME]).public_key
    )
    assert a.secrets.values[OWNER_KEY_NAME] == new_owner.seed_text()
    backup = read_backup(a.secrets)
    assert backup is not None and backup.keys[OWNER_KEY_NAME] == before[OWNER_KEY_NAME]
    assert "seed" not in repr(backup) and before[OWNER_KEY_NAME] not in repr(backup)
    # 下次读取身份时自动还原，备份随即删除。
    assert a.service.owner_key().seed_text() == before[OWNER_KEY_NAME]
    assert a.secrets.values == before


def test_status_restores_interrupted_swap(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    a, before, _ = interrupted_recovery(tmp_path, monkeypatch)
    status = OwnerIdentityService(a.service.store, a.secrets).status()
    assert status.has_owner_key
    assert a.secrets.values == before


def test_committed_swap_only_drops_leftover_backup(tmp_path: Path) -> None:
    a, keys = recoverable_computer(tmp_path / "a", 1, {})
    old = dict(a.secrets.values)
    new_owner = PrivateKey.generate()
    recover_owner(
        a.service, parse_recovery_code(keys.recovery_code), new_owner, PrivateKey.generate()
    )
    assert KEY_BACKUP_NAME not in a.secrets.values
    # 事务已提交、删备份前断电：备份对得上"换之后"的身份，只删备份，不动新密钥。
    a.secrets.set(
        KEY_BACKUP_NAME,
        KeyBackup.model_validate(
            {
                "created_at": "2026-10-01T00:00:00Z",
                "before": {"owner_fingerprint": "sha256:old"},
                "after": {
                    "owner_fingerprint": key_fingerprint(new_owner.public_key),
                    "device_public_key": a.key.public_key,
                },
                "keys": {OWNER_KEY_NAME: old[OWNER_KEY_NAME]},
            }
        ).model_dump_json(),
    )
    assert a.service.owner_key().seed_text() == new_owner.seed_text()
    assert KEY_BACKUP_NAME not in a.secrets.values


def test_mismatched_backup_is_kept_with_clear_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    a, _, new_owner = interrupted_recovery(tmp_path, monkeypatch)
    text = a.secrets.values[KEY_BACKUP_NAME]
    stranger = KeyBackup.model_validate_json(text).model_copy(
        update={"before": IdentityState(owner_fingerprint="sha256:" + "0" * 64)}
    )
    a.secrets.set(KEY_BACKUP_NAME, stranger.model_dump_json())
    with pytest.raises(IdentityError, match=r"对不上.*备份已保留"):
        a.service.owner_key()
    with pytest.raises(IdentityError, match="对不上"):
        issue_pass(a.service, a.service.node_id, PassScope.TRUST_SYNC)
    assert a.secrets.values[KEY_BACKUP_NAME] == stranger.model_dump_json()
    assert a.secrets.values[OWNER_KEY_NAME] == new_owner.seed_text()


def test_corrupt_backup_is_reported_and_kept(tmp_path: Path) -> None:
    a, _ = recoverable_computer(tmp_path / "a", 1, {})
    a.secrets.set(KEY_BACKUP_NAME, "不是 JSON")
    with pytest.raises(SecretStoreError, match="备份已损坏"):
        a.service.owner_key()
    broken = KeyBackup.model_validate(
        {
            "created_at": "2026-10-01T00:00:00Z",
            "before": {"owner_fingerprint": a.service.store.owner_fingerprint()},
            "after": {},
            "keys": {OWNER_KEY_NAME: "不是种子"},
        }
    )
    a.secrets.set(KEY_BACKUP_NAME, broken.model_dump_json())
    with pytest.raises(SecretStoreError, match="备份已损坏"):
        a.service.owner_key()
    assert KEY_BACKUP_NAME in a.secrets.values


def test_unreadable_backup_backend(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    a, _ = recoverable_computer(tmp_path / "a", 1, {})

    def broken(_name: str) -> str | None:
        raise OSError("钥匙串不可用")

    monkeypatch.setattr(a.secrets, "get", broken)
    with pytest.raises(SecretStoreError, match="无法读取身份密钥备份"):
        settle_key_backup(a.service.store, a.secrets)


@pytest.mark.parametrize("action", ["init", "reset", "join"])
def test_replace_and_reset_restore_after_kill(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, action: str
) -> None:
    apps: dict[str, FastAPI] = {}
    a = computer(tmp_path / "a", 1, apps)
    b = computer(tmp_path / "b", 2, apps, a)
    target = a if action != "join" else b
    before = dict(target.secrets.values)
    with monkeypatch.context() as patch:
        kill_after_keys(patch)
        with pytest.raises(Killed):
            if action == "init":
                OwnerIdentityService(a.service.store, a.secrets).init(
                    a.service.node_id,
                    GatewayBindConfig(host=a.host),
                    "新身份",
                    InitializationKeys.generate(),
                    replace=True,
                )
            elif action == "reset":
                OwnerIdentityService(a.service.store, a.secrets).reset()
            else:
                swap = IdentityKeySwap(
                    b.service.store,
                    b.secrets,
                    {DEVICE_KEY_NAME: PrivateKey.generate()},
                    IdentityState(owner_fingerprint="sha256:new"),
                    replaced=IDENTITY_KEY_NAMES,
                )
                swap.persist()
    assert target.secrets.values != before
    settle_key_backup(target.service.store, target.secrets)
    assert target.secrets.values == before


def test_new_swap_refuses_to_overwrite_pending_backup(tmp_path: Path) -> None:
    a, _ = recoverable_computer(tmp_path / "a", 1, {})
    swap = IdentityKeySwap(
        a.service.store,
        a.secrets,
        {OWNER_KEY_NAME: PrivateKey.generate()},
        IdentityState(),
        replaced=(OWNER_KEY_NAME,),
    )
    # 另一个进程在构造之后、写入之前留下了备份。
    pending = KeyBackup.model_validate(
        {"created_at": "2026-10-01T00:00:00Z", "before": {}, "after": {}, "keys": {}}
    ).model_dump_json()
    a.secrets.set(KEY_BACKUP_NAME, pending)
    with pytest.raises(IdentityError, match="备份还没处理完"):
        swap.persist()
    assert a.secrets.values[KEY_BACKUP_NAME] == pending


def test_backup_write_failure_leaves_keys_alone(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    a, keys = recoverable_computer(tmp_path / "a", 1, {})
    before = dict(a.secrets.values)
    original = a.secrets.set

    def refuse_backup(name: str, value: str) -> None:
        if name == KEY_BACKUP_NAME:
            raise SecretStoreError("钥匙串已满")
        original(name, value)

    monkeypatch.setattr(a.secrets, "set", refuse_backup)
    with pytest.raises(SecretStoreError, match="无法保存身份密钥备份"):
        recover_owner(
            a.service,
            parse_recovery_code(keys.recovery_code),
            PrivateKey.generate(),
            PrivateKey.generate(),
        )
    assert a.secrets.values == before


def test_backup_left_when_delete_fails_is_cleaned_later(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    a, keys = recoverable_computer(tmp_path / "a", 1, {})
    new_owner = PrivateKey.generate()
    original = a.secrets.delete

    def keep_backup(name: str) -> None:
        if name == KEY_BACKUP_NAME:
            raise SecretStoreError("钥匙串忙")
        original(name)

    with monkeypatch.context() as patch:
        patch.setattr(a.secrets, "delete", keep_backup)
        recover_owner(
            a.service, parse_recovery_code(keys.recovery_code), new_owner, PrivateKey.generate()
        )
    assert "没能删除身份密钥备份" in caplog.text
    assert KEY_BACKUP_NAME in a.secrets.values
    assert a.service.owner_key().seed_text() == new_owner.seed_text()
    assert KEY_BACKUP_NAME not in a.secrets.values


def test_rollback_restores_every_key_and_reports_failures_together(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    a, _ = recoverable_computer(tmp_path / "a", 1, {})
    before = dict(a.secrets.values)
    original = a.secrets.set
    restoring = False

    def flaky(name: str, value: str) -> None:
        # 回滚时写回机主密钥失败；电脑密钥排在后面，仍要写回去。
        if restoring and name == OWNER_KEY_NAME:
            raise SecretStoreError("钥匙串不可用")
        original(name, value)

    monkeypatch.setattr(a.secrets, "set", flaky)
    swap = IdentityKeySwap(
        a.service.store,
        a.secrets,
        {OWNER_KEY_NAME: PrivateKey.generate(), DEVICE_KEY_NAME: PrivateKey.generate()},
        IdentityState(),
        replaced=IDENTITY_KEY_NAMES,
    )
    swap.persist()
    restoring = True
    with pytest.raises(SecretStoreError, match="机主密钥没能恢复原样；旧密钥备份已保留") as error:
        swap.rollback()
    assert "电脑密钥" not in str(error.value)
    assert a.secrets.values[DEVICE_KEY_NAME] == before[DEVICE_KEY_NAME]
    assert KEY_BACKUP_NAME in a.secrets.values
    # 钥匙串恢复后，下次读取身份用备份补齐没写回的那把。
    restoring = False
    assert a.service.owner_key().seed_text() == before[OWNER_KEY_NAME]
    assert a.secrets.values == before


def test_restore_keys_names_every_failed_key(tmp_path: Path) -> None:
    a, _ = recoverable_computer(tmp_path / "a", 1, {})

    class Broken:
        def get(self, name: str) -> str | None:
            assert name
            return None

        def set(self, name: str, value: str) -> None:
            raise OSError(name, len(value))

        def delete(self, name: str) -> None:
            raise OSError(name)

    with pytest.raises(SecretStoreError, match=r"机主密钥、电脑密钥没能恢复原样$"):
        restore_keys(Broken(), {OWNER_KEY_NAME: PrivateKey.generate(), DEVICE_KEY_NAME: None})
    # 新密钥写在另一个后端时，旧密钥写回原后端，新密钥从另一个后端删掉。
    other = type(a.secrets)()
    other.set(DEVICE_KEY_NAME, "new")
    old = PrivateKey.generate()
    restore_keys(a.secrets, {DEVICE_KEY_NAME: old}, written=other, written_names=(DEVICE_KEY_NAME,))
    assert a.secrets.values[DEVICE_KEY_NAME] == old.seed_text()
    assert other.values == {}


def test_reset_rollback_after_database_failure_keeps_no_backup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    a, _ = recoverable_computer(tmp_path / "a", 1, {})
    before = dict(a.secrets.values)

    def broken_reset(clear_keys: Callable[[], None]) -> None:
        clear_keys()
        raise sqlite3.OperationalError("磁盘已满")

    monkeypatch.setattr(a.service.store, "reset", broken_reset)
    with pytest.raises(sqlite3.OperationalError):
        OwnerIdentityService(a.service.store, a.secrets).reset()
    assert a.secrets.values == before
