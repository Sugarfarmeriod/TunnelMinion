"""名单里的平台默认名换成各台电脑自己的本机名：谁能触发、能改成什么、不能改什么。

这类检查拦住"同一个主人的几台电脑在名单里同名"：几台电脑按旧平台默认名加入后，经过一轮同步，
名单里不再有平台默认名、也没有重名，主人起的名字保持不变。
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI
from tests.trust.test_identity import MemorySecrets
from tests.trust.test_own_devices import NOW, Computer, Mesh, request_for

from tunnelminion.domain.identifiers import NodeId
from tunnelminion.domain.invites import is_platform_display_name, platform_display_name
from tunnelminion.domain.tools import Platform
from tunnelminion.domain.trust import OwnerRoster, PassScope
from tunnelminion.gateway.api import (
    _startup_push,  # pyright: ignore[reportPrivateUsage]
    create_gateway_router,
)
from tunnelminion.gateway.audit import InMemoryGatewaySecurityAuditSink
from tunnelminion.gateway.configuration import (
    FileGatewayConfigurationRepository,
    GatewayConfigurationService,
)
from tunnelminion.gateway.names import save_node_name
from tunnelminion.gateway.security import GatewayBindConfig
from tunnelminion.memory.sqlite import SQLiteStores
from tunnelminion.tools.audit import InMemoryAuditSink
from tunnelminion.tools.registry import ToolRegistry
from tunnelminion.tools.runtime import ToolRuntime
from tunnelminion.trust.contracts import TrustSyncMessage, TrustSyncRequest
from tunnelminion.trust.devices import OwnDevicesService, distinct_display_name
from tunnelminion.trust.keys import InitializationKeys, PrivateKey
from tunnelminion.trust.passes import issue_pass
from tunnelminion.trust.service import OwnerIdentityService

WINDOWS = platform_display_name(Platform.WINDOWS)
MAC = platform_display_name(Platform.MACOS)


def machine(
    root: Path,
    index: int,
    apps: dict[str, FastAPI],
    *,
    roster_name: str,
    local_name: str | None,
    master: Computer | None = None,
) -> Computer:
    """一台内存网关电脑：`roster_name` 是名单里登记的名字，`local_name` 是它自己的本机名。"""
    root.mkdir(parents=True)
    node_id = NodeId("node_" + str(index) * 32)
    host = f"10.20.0.{index}"
    (root / "node-id").write_text(str(node_id), encoding="utf-8")
    secrets = MemorySecrets()
    store = SQLiteStores.open(root / "runtime.sqlite3").trust
    mesh = Mesh(host, apps)
    service = OwnDevicesService(
        node_id,
        store,
        secrets,
        transport=mesh,
        clock=lambda: NOW,
        local_name=(lambda: local_name) if local_name is not None else None,
    )
    if master is None:
        keys = InitializationKeys.generate()
        key = keys.device
        OwnerIdentityService(store, secrets).init(
            node_id, GatewayBindConfig(host=host), roster_name, keys, Platform.MACOS
        )
    else:
        key = PrivateKey.generate()
        code = master.service.invite()
        request = request_for(code, node_id, key, host).model_copy(
            update={"display_name": roster_name}
        )
        service.install_join(code, master.service.accept_join(code.token, request, host), key)
    config = GatewayConfigurationService(
        FileGatewayConfigurationRepository(root / "gateway.json"), secrets, owner_devices=service
    )
    config.configure_local(GatewayBindConfig(host=host))
    policy = config.build_security_policy()
    registry = ToolRegistry()
    app = FastAPI()
    app.include_router(
        create_gateway_router(
            node_id,
            Platform.WINDOWS,
            registry,
            ToolRuntime(registry, Platform.WINDOWS, InMemoryAuditSink()),
            policy,
            InMemoryGatewaySecurityAuditSink(),
            owner_devices=service,
        )
    )
    apps[host] = app
    return Computer(root, service, secrets, key, host, mesh, config, policy)


def names(roster: OwnerRoster) -> dict[str, str]:
    return {str(device.node_id): device.display_name for device in roster.devices}


def assert_distinct_named(roster: OwnerRoster) -> None:
    """名单里没有平台默认名，也没有不分大小写的重名。"""
    shown = [device.display_name for device in roster.devices]
    assert not [name for name in shown if is_platform_display_name(name)], shown
    assert len({name.casefold() for name in shown}) == len(shown), shown


@pytest.mark.parametrize("signer_first", [True, False])
@pytest.mark.parametrize(
    ("desk", "laptop", "expected"),
    [
        ("书房电脑", "客厅笔记本", {"书房电脑", "客厅笔记本"}),
        # 两台系统电脑名相同：先报上来的用原名，后报的加编号。
        ("书房电脑", "书房电脑", {"书房电脑", "书房电脑 (2)"}),
        # 和主人起的名字只差大小写也算重名，主人起的名字不让。
        ("nas", "客厅笔记本", {"nas (2)", "客厅笔记本"}),
    ],
)
def test_one_sync_round_leaves_no_default_or_duplicate_names(
    tmp_path: Path, signer_first: bool, desk: str, laptop: str, expected: set[str]
) -> None:
    apps: dict[str, FastAPI] = {}
    mac = machine(tmp_path / "mac", 1, apps, roster_name=MAC, local_name="工作 Mac")
    windows = machine(tmp_path / "desk", 2, apps, roster_name=WINDOWS, local_name=desk, master=mac)
    notebook = machine(
        tmp_path / "laptop", 3, apps, roster_name=WINDOWS, local_name=laptop, master=mac
    )
    nas = machine(tmp_path / "nas", 4, apps, roster_name="NAS", local_name="nas-box", master=mac)
    everyone = (mac, windows, notebook, nas)
    order = everyone if signer_first else (*everyone[1:], mac)

    async def scenario() -> None:
        for item in order:
            await _startup_push(item.service)

    asyncio.run(scenario())
    final = mac.service.roster()
    assert_distinct_named(final)
    shown = names(final)
    assert shown[str(mac.service.node_id)] == "工作 Mac"
    assert shown[str(nas.service.node_id)] == "NAS"
    assert {shown[str(windows.service.node_id)], shown[str(notebook.service.node_id)]} == expected
    for item in everyone:
        assert item.service.roster() == final
        assert {peer.display_name for peer in item.config.view().peers} == set(
            names(final).values()
        ) - {names(final)[str(item.service.node_id)]}


def test_signer_without_default_name_asks_devices_to_report(tmp_path: Path) -> None:
    """持有机主密钥的电脑后更新、自己的名字也不用换时，其他电脑回头同步一次报上本机名。"""
    apps: dict[str, FastAPI] = {}
    mac = machine(tmp_path / "mac", 1, apps, roster_name="工作 Mac", local_name="工作 Mac")
    desk = machine(
        tmp_path / "desk", 2, apps, roster_name=WINDOWS, local_name="书房电脑", master=mac
    )
    version = mac.service.roster().version

    async def scenario() -> None:
        desk.mesh.offline.add(mac.host)
        await _startup_push(desk.service)
        assert mac.service.roster().version == version
        desk.mesh.offline.clear()
        await _startup_push(mac.service)

    asyncio.run(scenario())
    assert names(desk.service.roster())[str(desk.service.node_id)] == "书房电脑"
    assert mac.service.roster().version == version + 1
    assert "平台默认名" in SQLiteStores.open(mac.root / "runtime.sqlite3").trust.audits()[-1].reason


def test_devices_without_signer_do_not_bounce_requests(tmp_path: Path) -> None:
    """两台都没有机主密钥的电脑互相同步时不改名，也不会互相回头同步个没完。"""
    apps: dict[str, FastAPI] = {}
    mac = machine(tmp_path / "mac", 1, apps, roster_name="工作 Mac", local_name=None)
    desk = machine(
        tmp_path / "desk", 2, apps, roster_name=WINDOWS, local_name="书房电脑", master=mac
    )
    note = machine(
        tmp_path / "note", 3, apps, roster_name=WINDOWS, local_name="客厅笔记本", master=mac
    )
    apps.pop(mac.host)

    async def scenario() -> None:
        await desk.service.sync(note.service.roster().device(note.service.node_id))  # type: ignore[arg-type]

    asyncio.run(scenario())
    assert desk.mesh.paths == ["/v1/trust:sync"]
    assert note.mesh.paths == []
    assert names(desk.service.roster())[str(note.service.node_id)] == WINDOWS


def test_only_authenticated_own_device_can_rename_only_itself(tmp_path: Path) -> None:
    apps: dict[str, FastAPI] = {}
    mac = machine(tmp_path / "mac", 1, apps, roster_name="工作 Mac", local_name="工作 Mac")
    desk = machine(tmp_path / "desk", 2, apps, roster_name=WINDOWS, local_name=None, master=mac)
    note = machine(tmp_path / "note", 3, apps, roster_name=WINDOWS, local_name=None, master=mac)
    version = mac.service.roster().version

    async def post(source: str, body: TrustSyncRequest, token: str | None) -> int:
        headers = {"Authorization": f"Bearer {token}"} if token is not None else {}
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(apps[mac.host], client=(source, 1234)),
            base_url=f"http://{mac.host}",
        ) as client:
            response = await client.post(
                "/v1/trust:sync", content=body.model_dump_json(), headers=headers
            )
        return response.status_code

    message = desk.service.message()

    async def scenario() -> None:
        # 不带通行证、只出示名单：照常回名单，但报来的名字不采纳。
        unauthenticated = TrustSyncRequest(**dict(message), display_name="书房电脑")
        assert await post(desk.host, unauthenticated, None) == 200
        assert mac.service.roster().version == version
        # 带通行证：只改认证出来的这台电脑自己那一条。
        token = issue_pass(desk.service, mac.service.node_id, PassScope.TRUST_SYNC)
        assert (
            await post(desk.host, TrustSyncRequest(**dict(message), display_name="书房电脑"), token)
            == 200
        )

    asyncio.run(scenario())
    renamed = names(mac.service.roster())
    assert renamed[str(desk.service.node_id)] == "书房电脑"
    assert renamed[str(note.service.node_id)] == WINDOWS
    assert mac.service.roster().version == version + 1


def test_adopt_name_keeps_owner_names_and_rejects_bad_names(tmp_path: Path) -> None:
    apps: dict[str, FastAPI] = {}
    mac = machine(tmp_path / "mac", 1, apps, roster_name="工作 Mac", local_name=None)
    desk = machine(tmp_path / "desk", 2, apps, roster_name=WINDOWS, local_name=None, master=mac)
    named = machine(tmp_path / "nas", 3, apps, roster_name="NAS", local_name=None, master=mac)
    owner = mac.service
    version = owner.roster().version
    # 主人或加入时起的名字一律不动。
    assert not owner.adopt_name(named.service.node_id, "nas-box")
    assert not owner.adopt_name(mac.service.node_id, "别的名字")
    # 不在名单上的电脑、不合法的名字、平台默认名都不采纳。
    assert not owner.adopt_name(NodeId.new(), "书房电脑")
    for bad in ("", "  ", "第一行\n第二行", "名" * 41, MAC, "电脑"):
        assert not owner.adopt_name(desk.service.node_id, bad)
    # 没有机主密钥的电脑签不了名单。
    assert not desk.service.signs_roster()
    assert not desk.service.adopt_name(desk.service.node_id, "书房电脑")
    assert owner.roster().version == version
    assert owner.signs_roster()
    assert owner.adopt_name(desk.service.node_id, "书房电脑")
    assert not owner.adopt_name(desk.service.node_id, "又一个名字")
    assert owner.roster().version == version + 1


def test_unreported_name_only_for_default_entry_with_better_local_name(tmp_path: Path) -> None:
    apps: dict[str, FastAPI] = {}
    mac = machine(tmp_path / "mac", 1, apps, roster_name="工作 Mac", local_name="工作 Mac")
    desk = machine(tmp_path / "desk", 2, apps, roster_name=WINDOWS, local_name=WINDOWS, master=mac)
    silent = machine(tmp_path / "note", 3, apps, roster_name=WINDOWS, local_name=None, master=mac)
    # 本机名取不到系统电脑名、自己也是平台默认名时，不报名字，名单保持原样。
    assert mac.service.unreported_name() is None
    assert desk.service.unreported_name() is None
    assert silent.service.unreported_name() is None
    assert not mac.service.adopt_local_name()
    # 本机已被移出名单时也不报名字。
    removed = OwnDevicesService(
        NodeId.new(), desk.service.store, desk.secrets, local_name=lambda: "书房电脑"
    )
    assert removed.unreported_name() is None


def test_distinct_display_name_numbers_and_keeps_length() -> None:
    assert distinct_display_name("书房电脑", ("客厅笔记本",)) == "书房电脑"
    assert distinct_display_name("书房电脑", ("书房电脑", "书房电脑 (2)")) == "书房电脑 (3)"
    long = "长" * 40
    numbered = distinct_display_name(long, (long,))
    assert numbered == "长" * 36 + " (2)" and len(numbered) == 40


def test_old_peers_ignore_new_sync_fields() -> None:
    """旧版本按 `TrustSyncMessage` 解析请求，多出来的字段被忽略；旧请求在新版本里也照常解析。"""
    request = TrustSyncRequest(display_name="书房电脑", roster_signer=True)
    assert TrustSyncMessage.model_validate_json(request.model_dump_json()) == TrustSyncMessage()
    old = TrustSyncRequest.model_validate_json(TrustSyncMessage().model_dump_json())
    assert old.display_name is None and not old.roster_signer


def test_file_configuration_reads_local_name_for_roster(tmp_path: Path) -> None:
    apps: dict[str, FastAPI] = {}
    mac = machine(tmp_path / "mac", 1, apps, roster_name="工作 Mac", local_name=None)
    save_node_name(mac.root, "工作 Mac")
    owner = GatewayConfigurationService(
        FileGatewayConfigurationRepository(mac.root / "gateway.json"), mac.secrets
    ).owner_devices
    assert owner is not None and owner.local_name is not None
    assert owner.local_name() == "工作 Mac"
