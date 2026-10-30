"""电脑显示名的本机配置、命令校验和双向配对。"""

from __future__ import annotations

import asyncio
import socket
from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI
from tests.gateway.test_configuration import MemorySecrets

from tunnelminion import cli
from tunnelminion.agent import join as joining
from tunnelminion.agent.invites import InMemoryInviteStore, InviteService
from tunnelminion.domain.identifiers import NodeId
from tunnelminion.domain.invites import (
    InviteAcceptance,
    InviteAccepted,
    InviteCode,
    InvitePermissions,
)
from tunnelminion.domain.tools import Platform
from tunnelminion.gateway.api import create_gateway_router
from tunnelminion.gateway.audit import InMemoryGatewaySecurityAuditSink
from tunnelminion.gateway.client import accept_invite
from tunnelminion.gateway.configuration import (
    FileGatewayConfigurationRepository,
    GatewayConfigurationService,
    GatewayPeerConfig,
    GatewayPeerInput,
    gateway_token_name,
)
from tunnelminion.gateway.names import load_node_name, save_node_name
from tunnelminion.gateway.security import GatewayBindConfig, GatewaySecurityPolicy
from tunnelminion.tools.audit import InMemoryAuditSink
from tunnelminion.tools.registry import ToolRegistry
from tunnelminion.tools.runtime import ToolRuntime

INVITER = NodeId("node_" + "a" * 32)
JOINER = NodeId("node_" + "b" * 32)
TOKEN = "tmn_" + "fake-name-token-" * 4


def configuration(root: Path, secrets: MemorySecrets) -> GatewayConfigurationService:
    value = GatewayConfigurationService(
        FileGatewayConfigurationRepository(root / "gateway.json"), secrets
    )
    value.configure_local(GatewayBindConfig(host="192.0.2.1"))
    return value


@pytest.mark.parametrize(
    ("platform", "expected"),
    [(Platform.WINDOWS, "Windows 电脑"), (Platform.MACOS, "Mac"), (Platform.LINUX, "Linux 电脑")],
)
def test_names_default_to_system_name_and_persist(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, platform: Platform, expected: str
) -> None:
    monkeypatch.setattr(socket, "gethostname", lambda: "Study-PC.local")
    assert load_node_name(tmp_path, platform, persist_default=False) == "Study-PC"
    assert not (tmp_path / "node-name.json").exists()
    assert load_node_name(tmp_path, platform) == "Study-PC"
    monkeypatch.setattr(socket, "gethostname", lambda: "Other")
    assert load_node_name(tmp_path, Platform.LINUX) == "Study-PC"
    assert save_node_name(tmp_path, "测试电脑") == "测试电脑"
    assert load_node_name(tmp_path, platform) == "测试电脑"
    # 旧版本保存的平台默认名不算用户起的名字，换成系统电脑名
    save_node_name(tmp_path, expected)
    assert load_node_name(tmp_path, platform) == "Other"
    assert load_node_name(tmp_path, platform, persist_default=False) == "Other"


@pytest.mark.parametrize("hostname", ["", "x" * 41, "a	b"])
def test_names_fall_back_to_platform_when_system_name_is_unusable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, hostname: str
) -> None:
    monkeypatch.setattr(socket, "gethostname", lambda: hostname)
    assert load_node_name(tmp_path, Platform.WINDOWS) == "Windows 电脑"


def test_names_fall_back_to_platform_when_system_name_is_unreadable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def broken() -> str:
        raise OSError("no hostname")

    monkeypatch.setattr(socket, "gethostname", broken)
    assert load_node_name(tmp_path, Platform.MACOS) == "Mac"


@pytest.mark.parametrize("command", ["node-name", "peer-rename"])
@pytest.mark.parametrize(
    "name", ["", " " * 5, "x" * 41, "a\nb", "a\tb", "a\0b", "a\x7fb", "a\u202eb"]
)
def test_name_commands_reject_invalid_plain_text_without_changing_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, command: str, name: str
) -> None:
    secrets = MemorySecrets()
    value = configuration(tmp_path, secrets)
    value.provision_peer(
        GatewayPeerInput(
            peer=GatewayPeerConfig(
                node_id=JOINER, host="192.0.2.2", allowed_tools=frozenset({"get_node_summary"})
            ),
            token=TOKEN,
        )
    )

    def secret_store(_root: Path) -> MemorySecrets:
        return secrets

    monkeypatch.setattr("tunnelminion.gateway.configuration.gateway_secret_store", secret_store)
    before = (tmp_path / "gateway.json").read_bytes()
    arguments = [command, *([str(JOINER)] if command == "peer-rename" else []), name]
    assert cli.main([*arguments, "--data-dir", str(tmp_path)]) == 2
    assert not (tmp_path / "node-name.json").exists()
    assert (tmp_path / "gateway.json").read_bytes() == before
    assert secrets.get(gateway_token_name(JOINER)) == TOKEN


def test_cli_rename_is_local_and_old_configs_without_names_load(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    secrets = MemorySecrets()
    value = configuration(tmp_path, secrets)
    value.provision_peer(
        GatewayPeerInput(
            peer=GatewayPeerConfig(
                node_id=JOINER,
                host="192.0.2.2",
                platform=Platform.MACOS,
                allowed_tools=frozenset({"get_node_summary"}),
            ),
            token=TOKEN,
        )
    )
    path = tmp_path / "gateway.json"
    path.write_text(
        path.read_text(encoding="utf-8").replace('"display_name": null,', ""), encoding="utf-8"
    )
    assert value.view().peers[0].display_name is None

    def secret_store(_root: Path) -> MemorySecrets:
        return secrets

    monkeypatch.setattr("tunnelminion.gateway.configuration.gateway_secret_store", secret_store)
    monkeypatch.setattr("tunnelminion.app.default_data_dir", lambda: tmp_path)
    assert cli.main(["node-name", "x"]) == 0
    assert load_node_name(tmp_path, Platform.WINDOWS) == "x"
    assert cli.main(["node-name", "名" * 40]) == 0
    assert cli.main(["peer-rename", str(JOINER), "本机起的名字"]) == 0
    assert value.view().peers[0].display_name == "本机起的名字"
    assert value.view().peers[0].host == "192.0.2.2"
    assert secrets.get(gateway_token_name(JOINER)) == TOKEN
    assert cli.main(["peer-rename", str(INVITER), "找不到"]) == 2
    assert cli.main(["peer-rename", "invalid", "找不到"]) == 2
    assert (
        cli.main(["peer-rename", str(JOINER), "找不到", "--data-dir", str(tmp_path / "empty")]) == 2
    )
    with pytest.raises(KeyError):
        value.resolve_service_peer(INVITER)
    assert value.resolve_service_peer(JOINER) == ("http://192.0.2.2:8787", TOKEN)
    secrets.delete(gateway_token_name(JOINER))
    with pytest.raises(RuntimeError):
        value.resolve_service_peer(JOINER)


def test_join_round_trip_exchanges_both_display_names(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    inviter_root, joiner_root = tmp_path / "inviter", tmp_path / "joiner"
    inviter_secrets, joiner_secrets = MemorySecrets(), MemorySecrets()
    inviter = configuration(inviter_root, inviter_secrets)
    save_node_name(inviter_root, "邀请方")
    save_node_name(joiner_root, "加入方")
    (joiner_root / "node-id").write_text(str(JOINER), encoding="utf-8")
    issuer = InviteService(
        INVITER,
        Platform.MACOS,
        inviter,
        InMemoryInviteStore(),
        display_name=lambda: load_node_name(inviter_root, Platform.MACOS),
    )
    code = issuer.create(InvitePermissions(allow_delegation=True))
    registry = ToolRegistry()
    app = FastAPI()
    app.include_router(
        create_gateway_router(
            INVITER,
            Platform.MACOS,
            registry,
            ToolRuntime(registry, Platform.MACOS, InMemoryAuditSink()),
            GatewaySecurityPolicy([]),
            InMemoryGatewaySecurityAuditSink(),
            invite_service=issuer,
        )
    )

    async def handshake(code: InviteCode, acceptance: InviteAcceptance) -> InviteAccepted:
        assert acceptance.display_name == "加入方"
        return await accept_invite(
            code,
            acceptance,
            transport=httpx.ASGITransport(app, client=("192.0.2.2", 1234)),
        )

    monkeypatch.setattr(joining, "accept_invite", handshake)

    def secret_store(_root: Path) -> MemorySecrets:
        return joiner_secrets

    monkeypatch.setattr(joining, "gateway_secret_store", secret_store)
    monkeypatch.setattr(joining.sys, "platform", "linux")
    accepted = asyncio.run(
        joining.join(
            code,
            data_dir=joiner_root,
            host_override="192.0.2.2",
            use_borrowed_model=False,
        )
    )
    joined = GatewayConfigurationService(
        FileGatewayConfigurationRepository(joiner_root / "gateway.json"), joiner_secrets
    )
    assert accepted.inviter_display_name == "邀请方"
    assert inviter.view().peers[0].display_name == "加入方"
    assert inviter.view().peers[0].platform is Platform.LINUX
    assert joined.view().peers[0].display_name == "邀请方"
    assert joined.view().peers[0].node_id == INVITER


def test_invite_fields_accept_old_payloads_and_reject_invalid_names() -> None:
    acceptance = InviteAcceptance(
        node_id=JOINER, platform=Platform.MACOS, host="192.0.2.2", port=8787
    )
    assert acceptance.display_name is None
    assert (
        InviteAccepted(
            inviter_node_id=INVITER, permissions=InvitePermissions()
        ).inviter_display_name
        is None
    )
    with pytest.raises(ValueError):
        InviteAcceptance.model_validate({**acceptance.model_dump(), "display_name": "bad\rname"})


def test_invite_cli_persists_linux_default_name(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(cli.sys, "platform", "linux")
    # 取不到系统电脑名时，按发出邀请的平台保存默认名
    monkeypatch.setattr(socket, "gethostname", lambda: "")
    assert (
        cli.main(
            [
                "invite",
                "--data-dir",
                str(tmp_path),
                "--bind-host",
                "192.0.2.1",
                "--secret-store",
                "restricted-file",
            ]
        )
        == 0
    )
    code = InviteCode.decode(capsys.readouterr().out.splitlines()[1])
    assert code.platform is Platform.LINUX
    assert load_node_name(tmp_path, Platform.WINDOWS) == "Linux 电脑"
