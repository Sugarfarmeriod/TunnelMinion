"""换机主密钥的边界：过期机主的同步、声明链异常、朋友冲突、恢复前置检查与回滚。"""

from __future__ import annotations

import asyncio
import sqlite3
from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI
from tests.trust.test_friends import pair, token
from tests.trust.test_own_devices import computer
from tests.trust.test_recovery import recoverable_computer

from tunnelminion.domain.identifiers import NodeId
from tunnelminion.domain.trust import OwnerRoster, OwnerRotation, SignaturePurpose, key_fingerprint
from tunnelminion.memory.sqlite import SQLiteStores, SQLiteTrustStore
from tunnelminion.trust.contracts import IdentityError, OwnerRotationStep, TrustSyncMessage
from tunnelminion.trust.keys import OWNER_KEY_NAME, PrivateKey, parse_recovery_code
from tunnelminion.trust.recovery import check_recovery_devices, recover_owner
from tunnelminion.trust.service import OwnerIdentityService
from tunnelminion.trust.signatures import VerificationError, seal


def rotation_step(
    roster: OwnerRoster,
    old_recovery: PrivateKey,
    new_owner: PrivateKey,
    new_recovery: PrivateKey,
    **changes: object,
) -> OwnerRotationStep:
    """手工签一张换密钥声明和随附的新名单。"""
    updated = roster.model_copy(
        update={
            "owner_public_key": new_owner.public_key,
            "recovery_fingerprint": key_fingerprint(new_recovery.public_key),
            "version": roster.version + 1,
            **changes,
        }
    )
    return OwnerRotationStep(
        rotation=seal(
            SignaturePurpose.OWNER_ROTATION,
            OwnerRotation(
                previous_owner_fingerprint=roster.owner_fingerprint,
                recovery_public_key=old_recovery.public_key,
                new_owner_public_key=new_owner.public_key,
                new_recovery_fingerprint=updated.recovery_fingerprint,
                issued_at=roster.issued_at,
            ),
            old_recovery,
        ),
        roster=seal(SignaturePurpose.OWNER_ROSTER, updated, new_owner),
    )


def test_retired_owner_material_needs_my_computer_pass(tmp_path: Path) -> None:
    apps: dict[str, FastAPI] = {}
    a, keys = recoverable_computer(tmp_path / "a", 1, apps)
    b = computer(tmp_path / "b", 2, apps, a)
    stranger = computer(tmp_path / "x", 9, apps)
    stale = TrustSyncMessage(roster=a.service.message().roster)
    recover_owner(
        a.service,
        parse_recovery_code(keys.recovery_code),
        PrivateKey.generate(),
        PrivateKey.generate(),
    )

    async def post(authorization: str | None) -> int:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(apps[a.host], client=(b.host, 1234)),
            base_url="http://10.20.0.1:8787",
        ) as client:
            response = await client.post(
                "/v1/trust:sync",
                content=stale.model_dump_json(),
                headers={"Authorization": authorization} if authorization else {},
            )
        return response.status_code

    async def scenario() -> None:
        assert await post(None) == 401
        # 不在名单上的电脑签的通行证：本机要求先同步，这里按认证失败处理。
        assert await post(f"Bearer {token(stranger, a)}") == 401

    asyncio.run(scenario())


def test_rotation_rejects_empty_malformed_and_cyclic_chains(tmp_path: Path) -> None:
    apps: dict[str, FastAPI] = {}
    a, keys = recoverable_computer(tmp_path / "a", 1, apps)
    roster = a.service.roster()
    first_recovery = parse_recovery_code(keys.recovery_code)
    second_owner, second_recovery = PrivateKey.generate(), PrivateKey.generate()
    first = rotation_step(roster, first_recovery, second_owner, second_recovery)
    store = a.service.store
    with pytest.raises(VerificationError):
        store.rotate((), first.roster, None, "空声明链")
    broken = first.model_copy(
        update={
            "rotation": first.rotation.model_copy(
                update={"payload": {**first.rotation.payload, "recovery_public_key": 1}}
            )
        }
    )
    with pytest.raises(VerificationError):
        store.rotate((broken,), first.roster, None, "格式不对")
    # 换出去又换回原来的机主密钥：声明链里出现重复的机主，整条拒收。
    back = rotation_step(
        first.roster.parse(OwnerRoster, SignaturePurpose.OWNER_ROSTER),
        second_recovery,
        a.service.owner_key(),
        PrivateKey.generate(),
    )
    with pytest.raises(VerificationError):
        store.rotate((first, back), back.roster, None, "换回旧密钥")


def test_rotation_back_to_retired_owner_is_rejected(tmp_path: Path) -> None:
    apps: dict[str, FastAPI] = {}
    a, keys = recoverable_computer(tmp_path / "a", 1, apps)
    b = computer(tmp_path / "b", 2, apps, a)
    old_owner = a.service.owner_key()
    new_owner, new_recovery = PrivateKey.generate(), PrivateKey.generate()
    recover_owner(b.service, parse_recovery_code(keys.recovery_code), new_owner, new_recovery)
    back = rotation_step(b.service.roster(), new_recovery, old_owner, PrivateKey.generate())
    with pytest.raises(VerificationError):
        b.service.store.rotate((back,), back.roster, None, "换回已作废的机主密钥")
    assert b.service.roster().owner_public_key == new_owner.public_key


def test_uninitialized_store_cannot_apply_rotation(tmp_path: Path) -> None:
    apps: dict[str, FastAPI] = {}
    a, keys = recoverable_computer(tmp_path / "a", 1, apps)
    recover_owner(
        a.service,
        parse_recovery_code(keys.recovery_code),
        PrivateKey.generate(),
        PrivateKey.generate(),
    )
    message = a.service.message()
    assert message.roster is not None
    fresh = SQLiteStores.open(tmp_path / "fresh.sqlite3").trust
    with pytest.raises(IdentityError):
        fresh.rotate(message.rotations, message.roster, message.trust_list, "未初始化")
    with pytest.raises(IdentityError):
        SQLiteTrustStore.read_roster(tmp_path / "fresh.sqlite3")
    # 没有任何身份时重置也不出错。
    fresh.reset(lambda: None)


def test_friend_rotation_cannot_bring_conflicting_computers(tmp_path: Path) -> None:
    apps: dict[str, FastAPI] = {}
    a = computer(tmp_path / "a", 1, apps)
    f, keys = recoverable_computer(tmp_path / "f", 3, apps)
    pair(a, f)
    roster = f.service.roster()
    impostor = roster.devices[0].model_copy(
        update={"node_id": a.service.node_id, "device_public_key": PrivateKey.generate().public_key}
    )
    step = rotation_step(
        roster,
        parse_recovery_code(keys.recovery_code),
        PrivateKey.generate(),
        PrivateKey.generate(),
        devices=(*roster.devices, impostor),
    )
    with pytest.raises(VerificationError, match="冲突"):
        a.service.store.rotate((step,), step.roster, None, "朋友换了机主密钥")
    assert a.service.friends()[0][1].owner_public_key == roster.owner_public_key


def test_lost_rotation_record_blocks_certificate_check(tmp_path: Path) -> None:
    apps: dict[str, FastAPI] = {}
    a, keys = recoverable_computer(tmp_path / "a", 1, apps)
    second_recovery = PrivateKey.generate()
    recover_owner(
        a.service, parse_recovery_code(keys.recovery_code), PrivateKey.generate(), second_recovery
    )
    with sqlite3.connect(tmp_path / "a" / "runtime.sqlite3") as connection:
        connection.execute("DELETE FROM trust_rotations")
    with pytest.raises(VerificationError):
        recover_owner(a.service, second_recovery, PrivateKey.generate(), PrivateKey.generate())


def test_recovery_preconditions(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    apps: dict[str, FastAPI] = {}
    a, keys = recoverable_computer(tmp_path / "a", 1, apps)
    b = computer(tmp_path / "b", 2, apps, a)
    roster = a.service.roster()
    with pytest.raises(IdentityError, match="名单上的电脑"):
        check_recovery_devices(roster, NodeId.new(), ())
    with pytest.raises(IdentityError, match="不能移除本机"):
        check_recovery_devices(roster, a.service.node_id, (a.service.node_id,))
    with pytest.raises(IdentityError, match="没有这个节点"):
        check_recovery_devices(roster, a.service.node_id, (NodeId.new(),))
    recovery = parse_recovery_code(keys.recovery_code)
    monkeypatch.setattr(b.service, "active", lambda: False)
    with pytest.raises(IdentityError, match="本机电脑身份无效"):
        recover_owner(b.service, recovery, PrivateKey.generate(), PrivateKey.generate())


def test_recovery_failure_before_saving_keys_leaves_keys_alone(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    apps: dict[str, FastAPI] = {}
    a, keys = recoverable_computer(tmp_path / "a", 1, apps)
    before = dict(a.secrets.values)

    def refuse(*_args: object, **_kwargs: object) -> None:
        raise VerificationError("身份签名验证失败")

    monkeypatch.setattr(a.service.store, "rotate", refuse)
    with pytest.raises(VerificationError):
        recover_owner(
            a.service,
            parse_recovery_code(keys.recovery_code),
            PrivateKey.generate(),
            PrivateKey.generate(),
        )
    assert a.secrets.values == before


def test_reset_failure_restores_only_existing_keys(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    apps: dict[str, FastAPI] = {}
    a = computer(tmp_path / "a", 1, apps)
    b = computer(tmp_path / "b", 2, apps, a)
    assert OWNER_KEY_NAME not in b.secrets.values
    before = dict(b.secrets.values)

    def broken_reset(clear_keys: object) -> None:
        assert callable(clear_keys)
        clear_keys()
        raise sqlite3.OperationalError("磁盘已满")

    monkeypatch.setattr(b.service.store, "reset", broken_reset)
    with pytest.raises(sqlite3.OperationalError):
        OwnerIdentityService(b.service.store, b.secrets).reset()
    assert b.secrets.values == before


def test_friend_rotation_overlapping_another_friend_is_kept_but_flagged(tmp_path: Path) -> None:
    apps: dict[str, FastAPI] = {}
    a = computer(tmp_path / "a", 1, apps)
    f, keys = recoverable_computer(tmp_path / "f", 3, apps)
    g = computer(tmp_path / "g", 4, apps)
    pair(a, f)
    pair(a, g)
    roster = f.service.roster()
    impostor = roster.devices[0].model_copy(
        update={"node_id": g.service.node_id, "device_public_key": PrivateKey.generate().public_key}
    )
    new_owner = PrivateKey.generate()
    step = rotation_step(
        roster,
        parse_recovery_code(keys.recovery_code),
        new_owner,
        PrivateKey.generate(),
        devices=(*roster.devices, impostor),
    )
    a.service.store.rotate((step,), step.roster, None, "朋友换了机主密钥")
    assert any(other.owner_public_key == new_owner.public_key for _, other in a.service.friends())
    audits = SQLiteStores.open(a.root / "runtime.sqlite3").trust.audits()
    assert "编号冲突" in audits[-1].reason
