"""重置身份要么整体换成新身份，要么原样不动：校验失败、确认输错、加入失败都不能丢掉旧身份。"""

from __future__ import annotations

import asyncio
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

import pytest
from fastapi import FastAPI
from tests.test_owner_cli import confirmation
from tests.trust.test_own_devices import computer
from tests.trust.test_recovery import dump, recoverable_computer
from tests.trust.test_recovery_cli import files, use_secrets

from tunnelminion.domain.trust import JoinCodeKind
from tunnelminion.gateway.security import GatewayBindConfig
from tunnelminion.model.secrets import SecretStoreError
from tunnelminion.trust.cli import owner_command
from tunnelminion.trust.contracts import IdentityError
from tunnelminion.trust.join import join_owner
from tunnelminion.trust.keys import (
    DEVICE_KEY_NAME,
    OWNER_KEY_NAME,
    InitializationKeys,
    PrivateKey,
    parse_recovery_code,
)
from tunnelminion.trust.recovery import recover_owner
from tunnelminion.trust.service import IdentityKeySwap, OwnerIdentityService
from tunnelminion.trust.signatures import VerificationError


def test_join_reset_with_broken_code_keeps_old_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    a, _ = recoverable_computer(tmp_path / "a", 1, {})
    before, private = files(a.root), dict(a.secrets.values)
    use_secrets(monkeypatch, a)
    assert (
        owner_command(
            ["owner", "join", "tmo1_garbage", "--reset", "--data-dir", str(a.root)],
            input_fn=lambda prompt: "重置",
        )
        == 2
    )
    assert "损坏" in capsys.readouterr().out
    assert files(a.root) == before and a.secrets.values == private


def test_init_reset_with_wrong_confirmation_keeps_old_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    a, _ = recoverable_computer(tmp_path / "a", 1, {})
    before, private = files(a.root), dict(a.secrets.values)
    shown: list[str] = []

    def respond(prompt: str) -> str:
        if "重置" in prompt:
            return "重置"
        # 只输对前 4 个字符不算确认。
        return confirmation(capsys, shown).replace(" ", "")[:4]

    use_secrets(monkeypatch, a)
    assert (
        owner_command(["owner", "init", "--reset", "--data-dir", str(a.root)], input_fn=respond)
        == 2
    )
    assert "未保存身份或密钥" in capsys.readouterr().out
    assert files(a.root) == before and a.secrets.values == private


def test_join_reset_handshake_failure_keeps_old_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    apps: dict[str, FastAPI] = {}
    a, _ = recoverable_computer(tmp_path / "a", 1, apps)
    f = computer(tmp_path / "f", 3, apps)
    f.service.clock = lambda: datetime.now(UTC)
    code = f.service.invite()
    a.mesh.offline.add(f.host)
    before = dump(a.root / "runtime.sqlite3")
    private = dict(a.secrets.values)
    use_secrets(monkeypatch, a)
    with pytest.raises(IdentityError, match="连不上"):
        asyncio.run(join_owner(code, a.root, transport=a.mesh, reset=True))
    assert dump(a.root / "runtime.sqlite3") == before
    assert a.secrets.values == private
    assert code.kind is JoinCodeKind.OWNER


def test_replace_rolls_back_database_and_keys_when_saving_new_key_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    a, _ = recoverable_computer(tmp_path / "a", 1, {})
    before = dump(a.root / "runtime.sqlite3")
    private = dict(a.secrets.values)
    original = a.secrets.set
    calls: list[str] = []

    def flaky(name: str, value: str) -> None:
        calls.append(name)
        if name == DEVICE_KEY_NAME and len(calls) == 2:
            raise SecretStoreError("钥匙串不可用")
        original(name, value)

    monkeypatch.setattr(a.secrets, "set", flaky)
    keys = InitializationKeys.generate()
    with pytest.raises(SecretStoreError):
        OwnerIdentityService(a.service.store, a.secrets).init(
            a.service.node_id,
            GatewayBindConfig(host=a.host),
            "新身份",
            keys,
            replace=True,
        )
    monkeypatch.setattr(a.secrets, "set", original)
    assert dump(a.root / "runtime.sqlite3") == before
    assert a.secrets.values == private


def test_duplicate_rotation_write_is_a_verification_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    a, keys = recoverable_computer(tmp_path / "a", 1, {})

    def collide(*_args: object, **_kwargs: object) -> None:
        raise sqlite3.IntegrityError("UNIQUE constraint failed")

    monkeypatch.setattr(a.service.store, "_rotate", collide)
    with pytest.raises(VerificationError):
        recover_owner(
            a.service,
            parse_recovery_code(keys.recovery_code),
            PrivateKey.generate(),
            PrivateKey.generate(),
        )


def test_stale_owner_key_is_dropped_after_rotation_arrives(tmp_path: Path) -> None:
    apps: dict[str, FastAPI] = {}
    a, keys = recoverable_computer(tmp_path / "a", 1, apps)
    b = computer(tmp_path / "b", 2, apps, a)
    # B 上残留着一份旧机主密钥。
    b.secrets.set(OWNER_KEY_NAME, a.secrets.values[OWNER_KEY_NAME])
    recover_owner(
        a.service,
        parse_recovery_code(keys.recovery_code),
        PrivateKey.generate(),
        PrivateKey.generate(),
    )
    b.service.receive(a.service.message(), "测试")
    assert b.service.roster().owner_fingerprint == a.service.roster().owner_fingerprint
    assert OWNER_KEY_NAME not in b.secrets.values


def test_key_swap_rollback_restores_only_keys_that_existed(tmp_path: Path) -> None:
    apps: dict[str, FastAPI] = {}
    a = computer(tmp_path / "a", 1, apps)
    b = computer(tmp_path / "b", 2, apps, a)
    before = dict(b.secrets.values)
    assert OWNER_KEY_NAME not in before
    swap = IdentityKeySwap(b.secrets, {DEVICE_KEY_NAME: PrivateKey.generate()}, replace=True)
    swap.persist()
    assert b.secrets.values[DEVICE_KEY_NAME] != before[DEVICE_KEY_NAME]
    swap.rollback()
    assert b.secrets.values == before
