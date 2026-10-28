"""朋友名单不能占用别人电脑的节点 ID：不能冒充另一个朋友，也不能挤掉本机的旧式配对。"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from uuid import uuid4

import pytest
from fastapi import FastAPI
from tests.trust.test_friends import pair, token
from tests.trust.test_own_devices import NOW, Computer, computer

from tunnelminion.domain.identifiers import NodeId
from tunnelminion.domain.trust import PassScope, RequestPassClaims, SignaturePurpose
from tunnelminion.gateway.configuration import (
    FileGatewayConfigurationRepository,
    GatewayConfigurationService,
    GatewayPeerConfig,
    GatewayPeerInput,
)
from tunnelminion.gateway.security import GatewayAuthenticationKind, GatewayPeerPolicy
from tunnelminion.memory.sqlite import SQLiteStores
from tunnelminion.trust.contracts import IdentityError
from tunnelminion.trust.devices import OwnDevicesService
from tunnelminion.trust.friend_cli import friend_command
from tunnelminion.trust.friends import FriendsService
from tunnelminion.trust.keys import PrivateKey
from tunnelminion.trust.passes import TrustSyncRequired
from tunnelminion.trust.signatures import seal

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
    # 名单照收（否则 F 抢先占号就能冻结 G 以后的名单更新），但撞号的电脑两边都不认。
    a.service.store.accept(impostor(f, g.service.node_id, key), "朋友名单更新")
    audits = SQLiteStores.open(a.root / "runtime.sqlite3").trust.audits()
    assert "编号冲突" in audits[-1].reason
    forged = forged_pass(key, g.service.node_id, a.service.node_id, f.service.roster().version + 1)
    # 冒用者和 G 本人都认不出来，只会被要求先同步名单。
    with pytest.raises(TrustSyncRequired):
        a.policy.authenticate(f"Bearer {forged}", source_host=f.host)
    with pytest.raises(TrustSyncRequired):
        a.policy.authenticate(f"Bearer {token(g, a)}", source_host=g.host)
    assert all(peer.node_id != g.service.node_id for peer in a.config.view().peers)
    # G 之后发来的新版本名单照常能收下。
    roster = g.service.roster()
    a.service.store.accept(
        seal(
            SignaturePurpose.OWNER_ROSTER,
            roster.model_copy(update={"version": roster.version + 1}),
            g.service.owner_key(),
        ),
        "朋友名单更新",
    )
    assert (
        next(
            other
            for _, other in a.service.friends()
            if other.owner_fingerprint == roster.owner_fingerprint
        ).version
        == roster.version + 1
    )


def test_pairing_rejects_roster_that_reuses_my_computers_node_id(tmp_path: Path) -> None:
    apps: dict[str, FastAPI] = {}
    a = computer(tmp_path / "a", 1, apps)
    h = computer(tmp_path / "h", 5, apps)
    # H 在自己的名单里塞进 A 的节点 ID，然后来配对。
    h.service.store.accept(impostor(h, a.service.node_id, PrivateKey.generate()), "本机更新")
    with pytest.raises(IdentityError):
        pair(a, h)
    assert a.service.trust_list().people == ()


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


def test_outbound_keeps_legacy_address_when_friend_reuses_its_node_id(tmp_path: Path) -> None:
    apps: dict[str, FastAPI] = {}
    a = computer(tmp_path / "a", 1, apps)
    f = computer(tmp_path / "f", 3, apps)
    pair(a, f)
    a.config.provision_peer(
        GatewayPeerInput(
            peer=GatewayPeerConfig(
                node_id=LEGACY_NODE,
                host=LEGACY_HOST,
                allowed_tools=frozenset({"get_node_summary"}),
            ),
            token=LEGACY_TOKEN,
        )
    )
    a.service.store.accept(impostor(f, LEGACY_NODE, PrivateKey.generate()), "朋友名单更新")
    view = next(peer for peer in a.config.view().peers if peer.node_id == LEGACY_NODE)
    assert view.host == LEGACY_HOST
    assert a.config.relationship(LEGACY_NODE) == "legacy"
    endpoint, credential = a.config.resolve_service_peer(LEGACY_NODE)
    assert LEGACY_HOST in endpoint and credential == LEGACY_TOKEN


def test_relationship_without_gateway_configuration(tmp_path: Path) -> None:
    apps: dict[str, FastAPI] = {}
    a = computer(tmp_path / "a", 1, apps)
    f = computer(tmp_path / "f", 3, apps)
    pair(a, f)
    bare = GatewayConfigurationService(
        FileGatewayConfigurationRepository(tmp_path / "none.json"),
        a.secrets,
        owner_devices=a.service,
    )
    assert bare.relationship(f.service.node_id) == "friend"


def test_friend_list_marks_conflicting_computers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    apps: dict[str, FastAPI] = {}
    a = computer(tmp_path / "a", 1, apps)
    f = computer(tmp_path / "f", 3, apps)
    g = computer(tmp_path / "g", 4, apps)
    pair(a, f)
    pair(a, g)
    a.service.store.accept(impostor(f, g.service.node_id, PrivateKey.generate()), "朋友名单更新")

    def local_devices(_root: Path) -> OwnDevicesService:
        return a.service

    monkeypatch.setattr("tunnelminion.trust.friend_cli.load_devices", local_devices)
    monkeypatch.setattr("tunnelminion.trust.friend_cli.default_data_dir", lambda: a.root)
    assert friend_command(["friend", "list"]) == 0
    assert f"{g.service.node_id}：和其他朋友的电脑编号冲突，暂不认" in capsys.readouterr().out
    assert friend_command(["friend", "list", "--json"]) == 0
    listed = json.loads(capsys.readouterr().out)
    assert all(str(g.service.node_id) in item["conflicting_devices"] for item in listed)


def test_old_friend_history_table_is_rebuilt_from_saved_rosters(tmp_path: Path) -> None:
    apps: dict[str, FastAPI] = {}
    a = computer(tmp_path / "a", 1, apps)
    f = computer(tmp_path / "f", 3, apps)
    pair(a, f)
    database = a.root / "runtime.sqlite3"
    with sqlite3.connect(database) as connection:
        connection.executescript(
            """
            DROP TABLE friend_device_history;
            CREATE TABLE friend_device_history (node_id TEXT PRIMARY KEY);
            """
        )
    store = SQLiteStores.open(database).trust
    assert store.was_friend_device(f.service.node_id, f.host)
    # 再打开一次不会重复迁移。
    assert SQLiteStores.open(database).trust.was_friend_device(f.service.node_id, f.host)
