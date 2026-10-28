"""恢复码换钥匙、声明链、朋友免配对及旧机主撤销的验收。"""

from __future__ import annotations

import asyncio
import sqlite3
import traceback
from pathlib import Path

import pytest
from fastapi import FastAPI
from tests.trust.test_friends import pair, token
from tests.trust.test_identity import initialized
from tests.trust.test_own_devices import Computer, computer

from tunnelminion.domain.trust import FriendPermissions, PassScope, SignaturePurpose
from tunnelminion.gateway.security import GatewayBindConfig
from tunnelminion.memory.sqlite import SQLiteStores, SQLiteTrustStore
from tunnelminion.model.secrets import SecretStoreError
from tunnelminion.trust.contracts import IdentityError
from tunnelminion.trust.devices import OwnDevicesService
from tunnelminion.trust.friends import FriendsService
from tunnelminion.trust.keys import (
    OWNER_KEY_NAME,
    InitializationKeys,
    PrivateKey,
    parse_recovery_code,
)
from tunnelminion.trust.passes import TrustSyncRequired
from tunnelminion.trust.recovery import recover_owner
from tunnelminion.trust.service import OwnerIdentityService
from tunnelminion.trust.signatures import VerificationError, seal


def dump(path: Path) -> str:
    with sqlite3.connect(path) as connection:
        return "\n".join(connection.iterdump())


def recoverable_computer(
    root: Path, index: int, apps: dict[str, FastAPI]
) -> tuple[Computer, InitializationKeys]:
    a = computer(root, index, apps, uninitialized=True)
    keys = InitializationKeys.generate()
    keys = InitializationKeys(keys.owner, a.key, keys.recovery_code, keys.recovery_fingerprint)
    OwnerIdentityService(a.service.store, a.secrets).init(
        a.service.node_id, GatewayBindConfig(host=a.host), "主电脑", keys
    )
    return a, keys


def test_lost_owner_recovers_on_b_removes_a_keeps_friend_and_adds_computer(tmp_path: Path) -> None:
    apps: dict[str, FastAPI] = {}
    a, keys = recoverable_computer(tmp_path / "a", 1, apps)
    b = computer(tmp_path / "b", 2, apps, a)
    f = computer(tmp_path / "f", 3, apps)
    pair(a, f)
    asyncio.run(a.service.push())
    old_message = a.service.message()
    old_owner = a.service.owner_key()
    assert OWNER_KEY_NAME not in b.secrets.values
    b.mesh.offline.add(a.host)
    replacement, recovery = PrivateKey.generate(), PrivateKey.generate()
    targets = recover_owner(
        b.service,
        parse_recovery_code(keys.recovery_code),
        replacement,
        recovery,
        (a.service.node_id,),
    )

    async def scenario() -> None:
        await b.service.push(targets)
        assert f.service.friends()[0][1].owner_public_key == replacement.public_key
        assert (await b.client(f).discover()).node_id == f.service.node_id
        c = computer(tmp_path / "c", 4, apps, b)
        await b.service.push()
        assert (await c.client(f).discover()).node_id == f.service.node_id
        assert (await f.client(c).discover()).node_id == c.service.node_id
        for receiver in (b, c, f):
            assert old_message.roster is not None
            forged = seal(
                SignaturePurpose.OWNER_ROSTER,
                {**old_message.roster.payload, "version": 10000},
                old_owner,
            )
            with pytest.raises(VerificationError):
                receiver.service.store.accept(forged, "旧机主伪造大版本")
            with pytest.raises(TrustSyncRequired):
                receiver.policy.authenticate(
                    "Bearer " + token(a, receiver, PassScope.TOOL_GATEWAY), source_host=a.host
                )
        assert b.service.owner_key().public_key == replacement.public_key
        assert b.service.roster().device(a.service.node_id) is None

    asyncio.run(scenario())


def test_wrong_recovery_key_cannot_change_files_or_keys(tmp_path: Path) -> None:
    path = tmp_path / "runtime.sqlite3"
    _, secrets, _, status = initialized(path)
    service = OwnDevicesService(status.devices[0].node_id, SQLiteStores.open(path).trust, secrets)
    before, private = dump(path), dict(secrets.values)
    with pytest.raises(IdentityError, match="恢复码无效"):
        recover_owner(service, PrivateKey.generate(), PrivateKey.generate(), PrivateKey.generate())
    assert dump(path) == before and secrets.values == private


@pytest.mark.parametrize("index", [0, 1])
@pytest.mark.parametrize(
    "fault",
    ["signature", "purpose", "previous", "recovery", "new_owner", "roster_recovery", "version"],
)
def test_every_rotation_step_is_verified_before_any_write(
    tmp_path: Path, index: int, fault: str
) -> None:
    apps: dict[str, FastAPI] = {}
    a, keys = recoverable_computer(tmp_path / "a", 1, apps)
    b = computer(tmp_path / "b", 2, apps, a)
    old_recovery = parse_recovery_code(keys.recovery_code)
    first_owner, first_recovery = PrivateKey.generate(), PrivateKey.generate()
    second_owner, second_recovery = PrivateKey.generate(), PrivateKey.generate()
    recover_owner(a.service, old_recovery, first_owner, first_recovery)
    recover_owner(a.service, first_recovery, second_owner, second_recovery)
    message = a.service.message()
    step = message.rotations[index]
    rotation, roster = step.rotation, step.roster
    signer = (old_recovery, first_recovery)[index]
    owner = (first_owner, second_owner)[index]
    if fault == "signature":
        rotation = seal(SignaturePurpose.OWNER_ROTATION, rotation.payload, PrivateKey.generate())
    elif fault == "purpose":
        rotation = seal(SignaturePurpose.OWNER_ROSTER, rotation.payload, signer)
    elif fault == "previous":
        rotation = seal(
            SignaturePurpose.OWNER_ROTATION,
            {**rotation.payload, "previous_owner_fingerprint": "sha256:" + "1" * 64},
            signer,
        )
    elif fault == "recovery":
        other = PrivateKey.generate()
        rotation = seal(
            SignaturePurpose.OWNER_ROTATION,
            {**rotation.payload, "recovery_public_key": other.public_key},
            other,
        )
    elif fault == "new_owner":
        rotation = seal(
            SignaturePurpose.OWNER_ROTATION,
            {**rotation.payload, "new_owner_public_key": PrivateKey.generate().public_key},
            signer,
        )
    elif fault == "roster_recovery":
        roster = seal(
            SignaturePurpose.OWNER_ROSTER,
            {**roster.payload, "recovery_fingerprint": "sha256:" + "2" * 64},
            owner,
        )
    else:
        roster = seal(
            SignaturePurpose.OWNER_ROSTER, {**roster.payload, "version": index + 1}, owner
        )
    steps = list(message.rotations)
    steps[index] = step.model_copy(update={"rotation": rotation, "roster": roster})
    message = message.model_copy(update={"rotations": tuple(steps)})
    before, secrets = dump(b.root / "runtime.sqlite3"), dict(b.secrets.values)
    with pytest.raises(VerificationError):
        b.service.receive(message, "不可信声明链")
    assert dump(b.root / "runtime.sqlite3") == before and b.secrets.values == secrets


@pytest.mark.parametrize(
    "fault",
    [
        "missing_trust",
        "trust_signature",
        "trust_version",
        "final_roster",
        "missing_roster",
        "missing_step",
        "reverse",
    ],
)
def test_rotation_requires_matching_new_documents_and_unbroken_chain(
    tmp_path: Path, fault: str
) -> None:
    apps: dict[str, FastAPI] = {}
    a, keys = recoverable_computer(tmp_path / "a", 1, apps)
    b = computer(tmp_path / "b", 2, apps, a)
    owner1, recovery1 = PrivateKey.generate(), PrivateKey.generate()
    owner2, recovery2 = PrivateKey.generate(), PrivateKey.generate()
    recover_owner(a.service, parse_recovery_code(keys.recovery_code), owner1, recovery1)
    recover_owner(a.service, recovery1, owner2, recovery2)
    message = a.service.message()
    assert message.trust_list is not None and message.roster is not None
    if fault == "missing_trust":
        message = message.model_copy(update={"trust_list": None})
    elif fault == "trust_signature":
        message = message.model_copy(
            update={
                "trust_list": seal(SignaturePurpose.TRUST_LIST, message.trust_list.payload, owner1)
            }
        )
    elif fault == "trust_version":
        message = message.model_copy(
            update={
                "trust_list": seal(
                    SignaturePurpose.TRUST_LIST,
                    {**message.trust_list.payload, "version": 1},
                    owner2,
                )
            }
        )
    elif fault == "final_roster":
        message = message.model_copy(
            update={
                "roster": seal(
                    SignaturePurpose.OWNER_ROSTER,
                    {**message.roster.payload, "issued_at": "2026-10-29T00:00:00Z"},
                    owner2,
                )
            }
        )
    elif fault == "missing_roster":
        message = message.model_copy(update={"roster": None})
    elif fault == "missing_step":
        message = message.model_copy(update={"rotations": message.rotations[1:]})
    else:
        message = message.model_copy(update={"rotations": tuple(reversed(message.rotations))})
    before = dump(b.root / "runtime.sqlite3")
    with pytest.raises((IdentityError, VerificationError)):
        b.service.receive(message, "新材料不符")
    assert dump(b.root / "runtime.sqlite3") == before


def test_friend_non_owner_accepts_chain_relay_and_owner_later_signs_new_friend_key(
    tmp_path: Path,
) -> None:
    apps: dict[str, FastAPI] = {}
    a, keys = recoverable_computer(tmp_path / "a", 1, apps)
    b = computer(tmp_path / "b", 2, apps, a)
    f = computer(tmp_path / "f", 3, apps)
    g = computer(tmp_path / "g", 4, apps, f)
    pair(a, f)
    asyncio.run(a.service.push())
    asyncio.run(f.service.push())
    original_trust = g.service.store.load(SignaturePurpose.TRUST_LIST)
    old_fingerprint = a.service.roster().owner_fingerprint
    FriendsService(g.service).restrict("小明", FriendPermissions(daily_quota=1000))
    replacement, recovery = PrivateKey.generate(), PrivateKey.generate()
    recover_owner(
        b.service,
        parse_recovery_code(keys.recovery_code),
        replacement,
        recovery,
        (a.service.node_id,),
    )
    own_friend = g.service.roster().owner_fingerprint
    g.service.receive(b.service.message(include_private=False), "朋友直接同步")
    assert g.service.store.owner_fingerprint() == own_friend
    assert g.service.store.load(SignaturePurpose.TRUST_LIST) == original_trust
    assert g.service.friends()[0][1].owner_public_key == replacement.public_key
    assert (
        g.service.store.friend_permissions(b.service.roster().owner_fingerprint).daily_quota == 1000
    )
    assert g.service.trust_list().people[0].owner_fingerprint == old_fingerprint
    # 持钥的 F 从 G 学到朋友换钥匙，再修改自己的朋友名单时归入新公钥。
    f.service.receive(g.service.message(), "我的其他电脑")
    FriendsService(f.service).permissions("小明", FriendPermissions(allow_model_borrowing=True))
    assert f.service.trust_list().people[0].owner_public_key == replacement.public_key
    g.service.receive(f.service.message(), "已改签的朋友名单")
    assert g.service.friends()[0][1].owner_public_key == replacement.public_key
    assert (
        g.service.store.friend_permissions(b.service.roster().owner_fingerprint).daily_quota == 1000
    )
    assert g.policy.authenticate("Bearer " + token(b, g), source_host=b.host) is not None


@pytest.mark.parametrize("existing_owner", [False, True])
def test_key_store_failure_rolls_back_rotation_and_hides_recovery_codes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, existing_owner: bool
) -> None:
    apps: dict[str, FastAPI] = {}
    a, keys = recoverable_computer(tmp_path / "a", 1, apps)
    target = a if existing_owner else computer(tmp_path / "b", 2, apps, a)
    before, old_secrets = dump(target.root / "runtime.sqlite3"), dict(target.secrets.values)
    owner, recovery = PrivateKey.generate(), PrivateKey.generate()
    original = target.secrets.set

    def fail(name: str, value: str) -> None:
        original(name, value)
        if value == owner.seed_text():
            raise RuntimeError(keys.recovery_code + recovery.recovery_code())

    monkeypatch.setattr(target.secrets, "set", fail)
    with pytest.raises(SecretStoreError) as caught:
        recover_owner(target.service, parse_recovery_code(keys.recovery_code), owner, recovery)
    assert dump(target.root / "runtime.sqlite3") == before
    assert target.secrets.values == old_secrets
    text = "".join(traceback.format_exception(caught.value))
    assert keys.recovery_code not in text and recovery.recovery_code() not in text


def test_multiple_rotations_reach_offline_nodes_and_old_codes_stop_working(tmp_path: Path) -> None:
    apps: dict[str, FastAPI] = {}
    a, keys = recoverable_computer(tmp_path / "a", 1, apps)
    b = computer(tmp_path / "b", 2, apps, a)
    c = computer(tmp_path / "c", 3, apps, a)
    b.service.receive(a.service.message(), "加入后的名单")
    first_owner, first_recovery = PrivateKey.generate(), PrivateKey.generate()
    next_owner, next_recovery = PrivateKey.generate(), PrivateKey.generate()
    recover_owner(a.service, parse_recovery_code(keys.recovery_code), first_owner, first_recovery)
    b.service.receive(a.service.message(), "首次恢复")
    recover_owner(a.service, first_recovery, next_owner, next_recovery)
    b.service.receive(a.service.message(), "第二次恢复")
    c.service.receive(a.service.message(), "错过两次恢复")
    assert len(c.service.message().rotations) == 2
    assert c.service.roster().owner_public_key == next_owner.public_key
    assert a.secrets.values[OWNER_KEY_NAME] == next_owner.seed_text()
    for old in (parse_recovery_code(keys.recovery_code), first_recovery):
        before = dump(a.root / "runtime.sqlite3")
        with pytest.raises(IdentityError, match="恢复码无效"):
            recover_owner(a.service, old, PrivateKey.generate(), PrivateKey.generate())
        assert dump(a.root / "runtime.sqlite3") == before
    for node in (a, b, c):
        database = dump(node.root / "runtime.sqlite3")
        for secret in (
            keys.recovery_code,
            first_recovery.recovery_code(),
            next_recovery.recovery_code(),
        ):
            assert secret not in database
    assert SQLiteTrustStore.read_roster(a.root / "runtime.sqlite3") == a.service.roster()


def test_offline_computer_can_pull_rotation_chain_using_its_old_roster(tmp_path: Path) -> None:
    apps: dict[str, FastAPI] = {}
    a, keys = recoverable_computer(tmp_path / "a", 1, apps)
    b = computer(tmp_path / "b", 2, apps, a)
    local = a.service.roster().device(a.service.node_id)
    assert local is not None
    owner, recovery = PrivateKey.generate(), PrivateKey.generate()
    recover_owner(a.service, parse_recovery_code(keys.recovery_code), owner, recovery)
    asyncio.run(b.service.sync(local))
    assert b.service.roster().owner_public_key == owner.public_key
    assert b.service.active()
