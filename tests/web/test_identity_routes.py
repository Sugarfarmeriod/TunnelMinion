"""本机网页上的机主身份、加入、朋友配对与管理接口。"""

from __future__ import annotations

import asyncio
import logging
import socket
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Protocol, cast

import httpx
import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
from tests.trust.test_identity import MemorySecrets
from tests.trust.test_own_devices import Computer, Mesh, computer

from tunnelminion.domain.identifiers import NodeId
from tunnelminion.domain.tools import Platform
from tunnelminion.domain.trust import JoinCode, JoinCodeKind
from tunnelminion.gateway.api import create_gateway_router
from tunnelminion.gateway.audit import InMemoryGatewaySecurityAuditSink
from tunnelminion.gateway.configuration import (
    FileGatewayConfigurationRepository,
    GatewayConfigurationService,
    GatewayPeerConfig,
    GatewayPeerInput,
    gateway_secret_store,
)
from tunnelminion.gateway.names import load_node_name
from tunnelminion.gateway.security import GatewayBindConfig
from tunnelminion.memory.sqlite import SQLiteStores
from tunnelminion.model.secrets import SecretStoreApprovalPendingError, SecretStoreError
from tunnelminion.tools.audit import InMemoryAuditSink
from tunnelminion.tools.registry import ToolRegistry
from tunnelminion.tools.runtime import ToolRuntime
from tunnelminion.trust.cli import owner_command
from tunnelminion.trust.devices import OwnDevicesService
from tunnelminion.trust.friends import FriendsService
from tunnelminion.trust.join import join_owner
from tunnelminion.trust.local import address_candidates, plan_setup
from tunnelminion.trust.signatures import VerificationError
from tunnelminion.web.identity import PendingSetups, create_identity_router
from tunnelminion.web.request_guard import install_local_request_guard

LOCAL = NodeId("node_" + "9" * 32)
HOST = "10.20.0.9"
LEGACY = NodeId("node_" + "8" * 32)
TOKEN = "tmn_" + "x" * 40


class Client(Protocol):
    """补齐 TestClient 的严格类型。"""

    def get(self, url: str) -> httpx.Response: ...

    def post(
        self, url: str, *, json: object = None, headers: dict[str, str] | None = None
    ) -> httpx.Response: ...

    def put(self, url: str, *, json: object = None) -> httpx.Response: ...

    def patch(self, url: str, *, json: object = None) -> httpx.Response: ...

    def delete(self, url: str) -> httpx.Response: ...


@pytest.fixture(autouse=True)
def memory_keyring(monkeypatch: pytest.MonkeyPatch) -> MemorySecrets:
    """默认钥匙串后端只读写测试内存。"""
    secrets = MemorySecrets()

    def get(_service: str, name: str) -> str | None:
        return secrets.get(name)

    def set_secret(_service: str, name: str, value: str) -> None:
        secrets.set(name, value)

    def delete(_service: str, name: str) -> None:
        secrets.delete(name)

    monkeypatch.setattr("keyring.get_password", get)
    monkeypatch.setattr("keyring.set_password", set_secret)
    monkeypatch.setattr("keyring.delete_password", delete)
    return secrets


def route_to(address: str) -> Callable[[str, int], str]:
    def detect(_host: str, _port: int) -> str:
        return address

    return detect


@pytest.fixture(autouse=True)
def interfaces(monkeypatch: pytest.MonkeyPatch) -> None:
    """网卡列表固定为一个可用私有地址加几种不能用的地址。"""
    entries = {
        "wg0": [
            SimpleNamespace(family=socket.AF_INET, address=HOST),
            SimpleNamespace(family=socket.AF_INET6, address="fd00::9"),
        ],
        "lo": [
            SimpleNamespace(family=socket.AF_INET, address="127.0.0.1"),
            SimpleNamespace(family=socket.AF_INET6, address="fe80::1%lo"),
            SimpleNamespace(family=-1, address="00:11:22:33:44:55"),
        ],
        "eth0": [SimpleNamespace(family=socket.AF_INET, address="8.8.8.8")],
    }
    monkeypatch.setattr("tunnelminion.trust.local.psutil.net_if_addrs", lambda: entries)
    monkeypatch.setattr("tunnelminion.trust.local.detect_local_host", route_to(HOST))


class Web:
    def __init__(
        self,
        root: Path,
        apps: dict[str, FastAPI],
        *,
        preview: bool = False,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.root = root
        root.mkdir(parents=True, exist_ok=True)
        (root / "node-id").write_text(str(LOCAL), encoding="utf-8")
        self.mesh = Mesh(HOST, apps)
        app = FastAPI()
        install_local_request_guard(app, read_only_preview=preview)
        app.include_router(
            create_identity_router(root, LOCAL, Platform.WINDOWS, transport=self.mesh, clock=clock)
        )
        self.client = cast(Client, TestClient(app, base_url="http://127.0.0.1"))

    def setup(self, **body: object) -> dict[str, Any]:
        started = self.client.post("/api/identity/setup", json=body)
        assert started.status_code == 200, started.text
        assert started.headers["cache-control"] == "no-store"
        return cast(dict[str, Any], started.json())

    def create(self, **body: object) -> dict[str, Any]:
        started = self.setup(**body)
        confirmed = self.client.post(
            f"/api/identity/setup/{started['setup_id']}:confirm",
            json={"recovery_code": started["recovery_code"].replace("-", " ").lower()},
        )
        assert confirmed.status_code == 200, confirmed.text
        return cast(dict[str, Any], confirmed.json())

    def overview(self) -> dict[str, Any]:
        return cast(dict[str, Any], self.client.get("/api/identity").json())

    def devices(self) -> OwnDevicesService:
        return OwnDevicesService(
            LOCAL,
            SQLiteStores.open(self.root / "runtime.sqlite3").trust,
            gateway_secret_store(self.root),
            transport=self.mesh,
        )


def live(item: Computer) -> Computer:
    """邀请方用真实时间，加入方签的证明才在有效期内。"""
    item.service.clock = lambda: datetime.now(UTC)
    return item


def detail(response: httpx.Response) -> tuple[int, str]:
    return response.status_code, cast(dict[str, Any], response.json())["detail"]["code"]


@pytest.fixture
def apps() -> dict[str, FastAPI]:
    return {}


def test_first_computer_shows_code_once_and_writes_nothing_until_confirmed(
    tmp_path: Path, memory_keyring: MemorySecrets, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    web = Web(tmp_path / "web", {})
    empty = web.overview()
    assert empty["initialized"] is False and empty["bind"] is None
    assert empty["address_candidates"] == [HOST, "fd00::9"]
    assert empty["local_display_name"] == load_node_name(
        web.root, Platform.WINDOWS, persist_default=False
    )
    assert detail(web.client.post("/api/identity/setup", json={})) == (400, "identity_error")
    assert detail(web.client.post("/api/identity/setup", json={"host": "127.0.0.1"}))[0] == 400
    started = web.setup(host=HOST, port=8790, display_name="书房电脑")
    code = started["recovery_code"]
    assert memory_keyring.values == {}
    assert not (web.root / "runtime.sqlite3").exists()
    url = f"/api/identity/setup/{started['setup_id']}:confirm"
    assert detail(web.client.post(url, json={"recovery_code": "WRONG"})) == (
        400,
        "recovery_code_mismatch",
    )
    assert memory_keyring.values == {}
    confirmed = web.client.post(url, json={"recovery_code": code})
    assert confirmed.status_code == 200
    view = confirmed.json()
    assert view["initialized"] and view["has_owner_key"] and not view["removed"]
    assert view["bind"] == {"host": HOST, "port": 8790}
    assert view["devices"][0]["display_name"] == "书房电脑" and view["devices"][0]["is_local"]
    assert load_node_name(web.root, Platform.WINDOWS) == "书房电脑"
    # 确认过的编号立即作废，同一个恢复码不能再用。
    assert detail(web.client.post(url, json={"recovery_code": code})) == (410, "setup_expired")
    assert detail(web.client.post("/api/identity/setup", json={"host": HOST}))[0] == 409
    leaked = (
        confirmed.text
        + web.client.get("/api/identity").text
        + caplog.text
        + (web.root / "runtime.sqlite3").read_bytes().decode("latin-1")
    )
    assert code not in leaked
    assert all(value not in leaked for value in memory_keyring.values.values())


def test_pending_setup_expires_is_replaced_and_can_be_cancelled(tmp_path: Path) -> None:
    web = Web(tmp_path / "web", {})
    first = web.setup(host=HOST)
    second = web.setup(host=HOST)
    stale = web.client.post(
        f"/api/identity/setup/{first['setup_id']}:confirm",
        json={"recovery_code": first["recovery_code"]},
    )
    assert detail(stale) == (410, "setup_expired")
    assert web.client.delete(f"/api/identity/setup/{first['setup_id']}").status_code == 204
    assert web.client.delete(f"/api/identity/setup/{second['setup_id']}").status_code == 204
    cancelled = web.client.post(
        f"/api/identity/setup/{second['setup_id']}:confirm",
        json={"recovery_code": second["recovery_code"]},
    )
    assert detail(cancelled) == (410, "setup_expired")
    moments = [datetime(2026, 10, 29, tzinfo=UTC)]
    pending = PendingSetups(lambda: moments[0])
    store = MemorySecrets()
    started = pending.start(
        plan_setup(tmp_path / "other", store, store, host=HOST, port=None, display_name=None)
    )
    assert started.recovery_code not in repr(started)
    moments[0] += timedelta(minutes=11)
    with pytest.raises(HTTPException) as failure:
        pending.take(started.setup_id, started.recovery_code)
    assert failure.value.status_code == 410
    with pytest.raises(HTTPException):
        pending.take(started.setup_id, started.recovery_code)


def test_existing_gateway_configuration_wins(tmp_path: Path) -> None:
    web = Web(tmp_path / "web", {})
    GatewayConfigurationService(
        FileGatewayConfigurationRepository(web.root / "gateway.json"),
        gateway_secret_store(web.root),
    ).configure_local(GatewayBindConfig(host="10.20.0.7", port=8791))
    view = web.create(host="10.20.0.5", port=9000)
    assert view["bind"] == {"host": "10.20.0.7", "port": 8791}
    assert view["devices"][0]["host"] == "10.20.0.7"


def test_owner_join_from_the_web(tmp_path: Path, apps: dict[str, FastAPI]) -> None:
    owner = live(computer(tmp_path / "a", 1, apps))
    web = Web(tmp_path / "web", apps)
    code = owner.service.invite().encode()
    inspected = web.client.post("/api/identity/codes:inspect", json={"code": code})
    assert inspected.status_code == 200
    body = inspected.json()
    assert body["kind"] == "owner" and body["inviter_host"] == owner.host
    assert body["suggested_host"] == HOST and body["suggested_port"] == 8787
    assert not body["bind_locked"] and not body["expired"]
    assert JoinCode.decode(code, JoinCodeKind.OWNER).token not in inspected.text
    friend_code = FriendsService(owner.service).invite().encode()
    assert detail(web.client.post("/api/identity/owner:join", json={"code": friend_code})) == (
        400,
        "invalid_code",
    )
    assert detail(web.client.post("/api/identity/owner:join", json={"code": "tmo1_broken"})) == (
        400,
        "invalid_code",
    )
    joined = web.client.post(
        "/api/identity/owner:join", json={"code": code, "host": HOST, "port": 8788}
    )
    assert joined.status_code == 200, joined.text
    view = joined.json()
    assert view["initialized"] and not view["has_owner_key"]
    assert {device["node_id"] for device in view["devices"]} == {
        str(owner.service.node_id),
        str(LOCAL),
    }
    assert view["bind"] == {"host": HOST, "port": 8788}
    # 不能重复加入；用过的码不能再用。
    assert detail(web.client.post("/api/identity/owner:join", json={"code": code}))[0] == 409
    # 没有机主密钥的电脑不能邀请电脑，也不能邀请朋友。
    assert detail(web.client.post("/api/identity/owner:invite")) == (400, "identity_error")
    assert detail(web.client.post("/api/identity/friends:invite", json={})) == (
        400,
        "identity_error",
    )
    legacy = f"/api/identity/legacy-peers/{owner.service.node_id}/proxy-approval"
    assert detail(web.client.put(legacy, json={"allowed": True})) == (404, "peer_not_found")


def test_owner_join_reports_unreachable_inviter(tmp_path: Path, apps: dict[str, FastAPI]) -> None:
    owner = live(computer(tmp_path / "a", 1, apps))
    web = Web(tmp_path / "web", apps)
    web.mesh.offline.add(owner.host)
    response = web.client.post(
        "/api/identity/owner:join", json={"code": owner.service.invite().encode()}
    )
    assert response.status_code == 400
    assert response.json()["detail"]["message"] == "连不上邀请方的电脑"
    assert not (web.root / "gateway.json").exists()


def test_friend_flow_creates_identity_then_pairs(tmp_path: Path, apps: dict[str, FastAPI]) -> None:
    owner = live(computer(tmp_path / "a", 1, apps))
    web = Web(tmp_path / "web", apps)
    code = FriendsService(owner.service).invite("小明").encode()
    inspected = web.client.post("/api/identity/codes:inspect", json={"code": code}).json()
    assert inspected["kind"] == "friend"
    assert detail(web.client.post("/api/identity/friends:join", json={"code": code})) == (
        409,
        "not_initialized",
    )
    web.create(host=inspected["suggested_host"], port=8789)
    owner_code = owner.service.invite().encode()
    assert detail(web.client.post("/api/identity/friends:join", json={"code": owner_code})) == (
        400,
        "invalid_code",
    )
    paired = web.client.post(
        "/api/identity/friends:join", json={"code": code, "display_name": "小林"}
    )
    assert paired.status_code == 200, paired.text
    friends = paired.json()["friends"]
    assert [friend["display_name"] for friend in friends] == ["小明"]
    assert friends[0]["devices"][0]["node_id"] == str(owner.service.node_id)
    assert [item.display_name for item in owner.service.trusted_people()] == ["小林"]
    again = web.client.post("/api/identity/friends:join", json={"code": code})
    assert again.status_code == 400


def test_owner_manages_devices_friends_and_legacy_peers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, apps: dict[str, FastAPI]
) -> None:
    web = Web(tmp_path / "web", apps)
    web.create(host=HOST)
    local = web.devices()
    local.clock = lambda: datetime.now(UTC)
    issued = web.client.post("/api/identity/owner:invite")
    assert issued.status_code == 200 and issued.headers["cache-control"] == "no-store"
    assert issued.json()["code"].startswith("tmo1_")
    # 把网页这台电脑当成机主，另一台电脑加入。
    host_app = FastAPI()
    config = GatewayConfigurationService(
        FileGatewayConfigurationRepository(web.root / "gateway.json"),
        local.secrets,
        owner_devices=local,
    )
    registry = ToolRegistry()
    host_app.include_router(
        create_gateway_router(
            LOCAL,
            Platform.WINDOWS,
            registry,
            ToolRuntime(registry, Platform.WINDOWS, InMemoryAuditSink()),
            config.build_security_policy(),
            InMemoryGatewaySecurityAuditSink(),
            owner_devices=local,
        )
    )
    apps[HOST] = host_app
    member = computer(tmp_path / "b", 2, apps, uninitialized=True)

    def member_secrets(_root: Path) -> MemorySecrets:
        return member.secrets

    with monkeypatch.context() as scoped:
        scoped.setattr("tunnelminion.trust.join.gateway_secret_store", member_secrets)
        asyncio.run(
            join_owner(
                JoinCode.decode(issued.json()["code"], JoinCodeKind.OWNER),
                member.root,
                host_override=member.host,
                transport=member.mesh,
            )
        )
    view = web.overview()
    member_id = next(item["node_id"] for item in view["devices"] if not item["is_local"])
    assert view["devices"][1]["permissions"] == {
        "allow_delegation": True,
        "allow_model_borrowing": True,
        "allow_proxy_repair_approval": True,
    }
    url = f"/api/identity/devices/{member_id}/permissions"
    closed = web.client.put(url, json={"allow_proxy_repair_approval": False})
    assert closed.status_code == 200
    permissions = next(
        item["permissions"] for item in closed.json()["devices"] if item["node_id"] == member_id
    )
    assert permissions["allow_proxy_repair_approval"] is False
    assert permissions["allow_delegation"] is True
    reopened = web.client.put(url, json={"allow_proxy_repair_approval": True})
    assert detail(reopened) == (400, "identity_error")
    assert detail(web.client.put(f"/api/identity/devices/{LOCAL}/permissions", json={}))[0] == 404
    assert detail(web.client.put("/api/identity/devices/bad/permissions", json={}))[0] == 404
    assert detail(web.client.put(f"/api/identity/devices/{LEGACY}/permissions", json={}))[0] == 404

    # 朋友：配对、改名、改借模型、移除；推送不到的电脑写进结果。
    friend = live(computer(tmp_path / "f", 3, apps))
    friend_code = FriendsService(friend.service).invite("阿强").encode()
    assert (
        web.client.post("/api/identity/friends:join", json={"code": friend_code}).status_code == 200
    )
    fingerprint = web.overview()["friends"][0]["owner_fingerprint"]
    apps.pop(member.host)
    renamed = web.client.patch(
        f"/api/identity/friends/{fingerprint}", json={"display_name": "强哥"}
    )
    assert renamed.status_code == 200
    assert renamed.json()["unreached"] == [load_node_name(member.root, Platform.WINDOWS)]
    assert web.overview()["friends"][0]["display_name"] == "强哥"
    borrowing = web.client.put(
        f"/api/identity/friends/{fingerprint}/permissions", json={"allow_model_borrowing": True}
    )
    assert borrowing.status_code == 200
    assert web.overview()["friends"][0]["allow_model_borrowing"] is True
    assert (
        detail(web.client.patch("/api/identity/friends/unknown", json={"display_name": "x"}))[0]
        == 400
    )
    assert (
        detail(
            web.client.put(
                "/api/identity/friends/unknown/permissions", json={"allow_model_borrowing": False}
            )
        )[0]
        == 400
    )
    assert web.client.delete(f"/api/identity/friends/{fingerprint}").status_code == 200
    assert web.overview()["friends"] == []
    assert detail(web.client.delete("/api/identity/friends/unknown"))[0] == 400

    # 移除我的电脑；不能移除本机。
    removed = web.client.delete(f"/api/identity/devices/{member_id}")
    assert removed.status_code == 200 and removed.json()["unreached"] == [member_id]
    assert len(web.overview()["devices"]) == 1
    assert detail(web.client.delete(f"/api/identity/devices/{LOCAL}")) == (400, "identity_error")
    assert detail(web.client.delete("/api/identity/devices/bad"))[0] == 404

    # 邀请朋友时生成配对码。
    invited = web.client.post("/api/identity/friends:invite", json={"display_name": "我"})
    assert invited.status_code == 200 and invited.json()["code"].startswith("tmf1_")


def test_legacy_peer_proxy_approval_can_be_toggled(tmp_path: Path) -> None:
    web = Web(tmp_path / "web", {})
    service = GatewayConfigurationService(
        FileGatewayConfigurationRepository(web.root / "gateway.json"),
        gateway_secret_store(web.root),
    )
    service.configure_local(GatewayBindConfig(host=HOST))
    service.provision_peer(
        GatewayPeerInput(
            peer=GatewayPeerConfig(
                node_id=LEGACY,
                host="10.20.0.8",
                display_name="旧电脑",
                allowed_tools=frozenset({"get_node_summary"}),
            ),
            token=TOKEN,
        )
    )
    view = web.overview()
    assert view["legacy_peers"][0]["display_name"] == "旧电脑"
    assert view["legacy_peers"][0]["allow_proxy_repair_approval"] is False
    url = f"/api/identity/legacy-peers/{LEGACY}/proxy-approval"
    opened = web.client.put(url, json={"allowed": True})
    assert opened.json()["legacy_peers"][0]["allow_proxy_repair_approval"] is True
    closed = web.client.put(url, json={"allowed": False})
    assert closed.json()["legacy_peers"][0]["allow_proxy_repair_approval"] is False
    missing = f"/api/identity/legacy-peers/node_{'7' * 32}/proxy-approval"
    assert detail(web.client.put(missing, json={"allowed": True})) == (404, "peer_not_found")
    assert (
        detail(
            web.client.put("/api/identity/legacy-peers/x/proxy-approval", json={"allowed": True})
        )[0]
        == 404
    )


def test_errors_map_to_plain_messages(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, apps: dict[str, FastAPI]
) -> None:
    web = Web(tmp_path / "web", apps)
    assert detail(web.client.post("/api/identity/owner:invite")) == (409, "not_initialized")
    assert detail(web.client.post("/api/identity/codes:inspect", json={"code": "hello"})) == (
        400,
        "invalid_code",
    )

    def broken(*_arguments: object) -> None:
        raise SecretStoreError("钥匙串坏了")

    monkeypatch.setattr("tunnelminion.trust.local.ensure_no_identity_keys", broken)
    assert detail(web.client.post("/api/identity/setup", json={"host": HOST})) == (
        500,
        "secret_store_unavailable",
    )

    def waiting(*_arguments: object) -> None:
        raise SecretStoreApprovalPendingError

    monkeypatch.setattr("tunnelminion.trust.local.ensure_no_identity_keys", waiting)
    response = web.client.post("/api/identity/setup", json={"host": HOST})
    assert detail(response) == (503, "keychain_approval_pending")
    assert "始终允许" in response.json()["detail"]["message"]


def test_inspect_without_route_and_with_locked_bind(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, apps: dict[str, FastAPI]
) -> None:
    owner = computer(tmp_path / "a", 1, apps)
    web = Web(tmp_path / "web", apps, clock=lambda: datetime(2027, 1, 1, tzinfo=UTC))
    code = owner.service.invite().encode()

    def no_route(*_arguments: object) -> str:
        raise OSError("没有路由")

    monkeypatch.setattr("tunnelminion.trust.local.detect_local_host", no_route)
    body = web.client.post("/api/identity/codes:inspect", json={"code": code}).json()
    assert body["suggested_host"] is None and body["expired"] is True
    monkeypatch.setattr("tunnelminion.trust.local.detect_local_host", route_to("127.0.0.1"))
    body = web.client.post("/api/identity/codes:inspect", json={"code": code}).json()
    assert body["suggested_host"] is None
    web.create(host=HOST, port=8795)
    body = web.client.post("/api/identity/codes:inspect", json={"code": code}).json()
    assert body["bind_locked"] and body["suggested_port"] == 8795


def test_guard_rejects_cross_site_and_preview(tmp_path: Path) -> None:
    web = Web(tmp_path / "web", {})
    cross = web.client.post(
        "/api/identity/setup",
        json={"host": HOST},
        headers={"Origin": "http://evil.example", "Sec-Fetch-Site": "cross-site"},
    )
    assert detail(cross) == (403, "cross_site_request")
    preview = Web(tmp_path / "preview", {}, preview=True)
    assert detail(preview.client.post("/api/identity/setup", json={"host": HOST})) == (
        403,
        "read_only_preview",
    )
    assert preview.client.get("/api/identity").status_code == 200


def test_address_candidates_sort_ipv4_first() -> None:
    assert address_candidates() == (HOST, "fd00::9")


def test_overview_reports_secret_store_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    web = Web(tmp_path / "web", {})
    web.create(host=HOST)

    def broken(*_arguments: object) -> None:
        raise SecretStoreError("钥匙串坏了") from OSError("User interaction is not allowed")

    monkeypatch.setattr("tunnelminion.trust.service.load_private_key", broken)
    response = web.client.get("/api/identity")
    assert detail(response) == (500, "secret_store_unavailable")
    # 页面上告诉主人怎么办，底层原因只进本机日志。
    assert "ssh" in response.json()["detail"]["message"]
    assert "User interaction is not allowed" not in response.text
    assert "User interaction is not allowed" in caplog.text


def test_confirm_after_identity_appeared_elsewhere(tmp_path: Path) -> None:
    web = Web(tmp_path / "web", {})
    started = web.setup(host=HOST)
    other = Web(tmp_path / "web", {})
    other.create(host=HOST)
    late = web.client.post(
        f"/api/identity/setup/{started['setup_id']}:confirm",
        json={"recovery_code": started["recovery_code"]},
    )
    assert detail(late) == (409, "already_initialized")


def test_friend_pairing_verification_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, apps: dict[str, FastAPI]
) -> None:
    owner = live(computer(tmp_path / "a", 1, apps))
    web = Web(tmp_path / "web", apps)
    web.create(host=HOST)

    async def forged(*_arguments: object) -> None:
        raise VerificationError("朋友身份与电脑名单不符")

    monkeypatch.setattr("tunnelminion.trust.friends.FriendsService.join", forged)
    code = FriendsService(owner.service).invite().encode()
    response = web.client.post("/api/identity/friends:join", json={"code": code})
    assert detail(response) == (400, "verification_failed")


def test_cli_still_reports_invalid_quota(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    web = Web(tmp_path / "web", {})
    web.create(host=HOST)
    arguments = ["owner", "device-permissions", str(LEGACY), "--data-dir", str(web.root)]
    assert owner_command([*arguments, "--daily-quota", "0"]) == 2
    assert "本机身份配置无效" in capsys.readouterr().out
