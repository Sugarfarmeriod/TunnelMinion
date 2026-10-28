"""朋友名单不能占用别人电脑的节点 ID：不能冒充另一个朋友，也不能挤掉本机的旧式配对。"""

from __future__ import annotations

from pathlib import Path
from uuid import uuid4

import pytest
from fastapi import FastAPI
from tests.trust.test_friends import pair, token
from tests.trust.test_own_devices import NOW, Computer, computer

from tunnelminion.domain.identifiers import NodeId
from tunnelminion.domain.trust import PassScope, RequestPassClaims, SignaturePurpose
from tunnelminion.gateway.security import GatewayAuthenticationKind, GatewayPeerPolicy
from tunnelminion.trust.contracts import IdentityError
from tunnelminion.trust.friends import FriendsService
from tunnelminion.trust.keys import PrivateKey
from tunnelminion.trust.signatures import VerificationError, seal

LEGACY_NODE = NodeId("node_" + "9" * 32)
LEGACY_TOKEN = "tmn_" + "x" * 40
LEGACY_HOST = "10.20.0.9"


def impostor(owner: Computer, node_id: NodeId, key: PrivateKey):
    """朋友用自己的机主密钥签一份名单，里面多一台用别人节点 ID、自己地址的电脑。"""
    roster = owner.service.roster()
    fake = roster.devices[0].model_copy(
        update={"node_id": node_id, "device_public_key": key.public_key, "host": owner.host}
    )
    return seal(
        SignaturePurpose.OWNER_ROSTER,
        roster.model_copy(
            update={"version": roster.version + 1, "devices": (*roster.devices, fake)}
        ),
        owner.service.owner_key(),
    )


def forged_pass(key: PrivateKey, issuer: NodeId, audience: NodeId, version: int) -> str:
    now = int(NOW.timestamp())
    return key.request_pass(
        RequestPassClaims(
            iss=issuer,
            aud=audience,
            scope=PassScope.TOOL_GATEWAY,
            iat=now,
            exp=now + 60,
            jti=uuid4().hex,
            owner_fingerprint="sha256:" + "0" * 64,
            roster_version=version,
        )
    )


def test_friend_cannot_take_another_friends_node_id(tmp_path: Path) -> None:
    apps: dict[str, FastAPI] = {}
    a = computer(tmp_path / "a", 1, apps)
    f = computer(tmp_path / "f", 3, apps)
    g = computer(tmp_path / "g", 4, apps)
    pair(a, f)
    pair(a, g)
    key = PrivateKey.generate()
    with pytest.raises(VerificationError, match="冲突"):
        a.service.store.accept(impostor(f, g.service.node_id, key), "朋友名单更新")
    forged = forged_pass(key, g.service.node_id, a.service.node_id, f.service.roster().version + 1)
    assert a.policy.authenticate(f"Bearer {forged}", source_host=f.host) is None
    real = a.policy.authenticate(f"Bearer {token(g, a)}", source_host=g.host)
    assert real is not None and real.authentication_kind is GatewayAuthenticationKind.FRIEND_DEVICE
    view = next(peer for peer in a.config.view().peers if peer.node_id == g.service.node_id)
    assert view.host == g.host


def test_pairing_rejects_roster_that_reuses_existing_node_id(tmp_path: Path) -> None:
    apps: dict[str, FastAPI] = {}
    a = computer(tmp_path / "a", 1, apps)
    g = computer(tmp_path / "g", 4, apps)
    h = computer(tmp_path / "h", 5, apps)
    pair(a, g)
    # H 在自己的名单里塞进 G 的节点 ID，然后来配对。
    h.service.store.accept(impostor(h, g.service.node_id, PrivateKey.generate()), "本机更新")
    with pytest.raises(IdentityError):
        pair(a, h)
    assert len(FriendsService(a.service).devices.trust_list().people) == 1


def test_friend_roster_cannot_shadow_legacy_pairing(tmp_path: Path) -> None:
    apps: dict[str, FastAPI] = {}
    a = computer(tmp_path / "a", 1, apps)
    f = computer(tmp_path / "f", 3, apps)
    pair(a, f)
    a.policy.upsert_static_peer(
        GatewayPeerPolicy.from_token(
            LEGACY_NODE, LEGACY_TOKEN, ("get_wireguard_status",), source_host=LEGACY_HOST
        )
    )
    assert a.policy.authenticate(f"Bearer {LEGACY_TOKEN}", source_host=LEGACY_HOST) is not None
    key = PrivateKey.generate()
    a.service.store.accept(impostor(f, LEGACY_NODE, key), "朋友名单更新")
    # 旧式配对照常可用；朋友冒用这个节点 ID 签的通行证不认。
    legacy = a.policy.authenticate(f"Bearer {LEGACY_TOKEN}", source_host=LEGACY_HOST)
    assert legacy is not None and legacy.authentication_kind is GatewayAuthenticationKind.STATIC
    forged = forged_pass(key, LEGACY_NODE, a.service.node_id, f.service.roster().version + 1)
    assert a.policy.authenticate(f"Bearer {forged}", source_host=f.host) is None
    # 移除这个朋友以后，旧式配对也不会被连带作废。
    FriendsService(a.service).remove(f.service.roster().owner_fingerprint)
    assert a.policy.authenticate(f"Bearer {LEGACY_TOKEN}", source_host=LEGACY_HOST) is not None


def test_rename_friend_overrides_self_reported_name(tmp_path: Path) -> None:
    apps: dict[str, FastAPI] = {}
    a = computer(tmp_path / "a", 1, apps)
    f = computer(tmp_path / "f", 3, apps)
    pair(a, f)
    friends = FriendsService(a.service)
    fingerprint = f.service.roster().owner_fingerprint
    version = a.service.trust_list().version
    friends.rename(fingerprint, "大学同学")
    assert friends.resolve("大学同学").owner_fingerprint == fingerprint
    assert a.service.trust_list().version == version + 1


def test_own_device_history_ignores_friend_rosters(tmp_path: Path) -> None:
    apps: dict[str, FastAPI] = {}
    a = computer(tmp_path / "a", 1, apps)
    b = computer(tmp_path / "b", 2, apps, a)
    f = computer(tmp_path / "f", 3, apps)
    pair(a, f)
    assert a.service.store.was_own_device(b.service.node_id)
    assert not a.service.store.was_own_device(f.service.node_id)
