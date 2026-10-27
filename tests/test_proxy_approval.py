"""代批准的授权方向、默认关闭、命令行配置和双平台配对。"""

from __future__ import annotations

import asyncio
import io
import json
from pathlib import Path

import httpx
import pytest
from pydantic import ValidationError
from tests.gateway.test_configuration import MemorySecrets
from tests.gateway.test_invites import ACCEPTANCE, JOINER
from tests.test_invite_join import CODE
from tests.test_peer_names import configuration
from tests.web.test_peers import peer

from tunnelminion import cli
from tunnelminion.agent import join as joining
from tunnelminion.app import build_windows_gateway_application
from tunnelminion.domain.identifiers import NodeId
from tunnelminion.domain.invites import (
    InviteAcceptance,
    InviteAccepted,
    InviteCode,
    InvitePermissions,
)
from tunnelminion.gateway.configuration import (
    FileGatewayConfigurationRepository,
    GatewayConfigurationService,
    GatewayPeerInput,
    gateway_secret_store,
)
from tunnelminion.macos_app import build_macos_gateway_application


def test_local_switch_preserves_every_other_field_and_running_policy(tmp_path: Path) -> None:
    secrets = MemorySecrets()
    service = configuration(tmp_path, secrets)
    service.provision_peer(GatewayPeerInput(peer=peer(JOINER), token=CODE.token))
    other = NodeId.new()
    service.provision_peer(GatewayPeerInput(peer=peer(other, "另一台"), token="tmn_" + "z" * 40))
    repository = FileGatewayConfigurationRepository(tmp_path / "gateway.json")
    raw = json.loads((tmp_path / "gateway.json").read_text(encoding="utf-8"))
    for item in raw["peers"]:
        item.pop("allow_proxy_repair_approval")
    (tmp_path / "gateway.json").write_text(json.dumps(raw), encoding="utf-8")
    before = repository.load()
    assert before is not None
    assert not service.view().peers[0].allow_proxy_repair_approval
    assert service.peer_display_name(JOINER) == "Mac"
    assert service.peer_display_name(NodeId.new()) == "电脑"
    policy = service.build_security_policy()
    saved_secrets = dict(secrets.values)
    for allowed in (True, False):
        changed = service.set_proxy_repair_approval(JOINER, allowed)
        current = repository.load()
        assert current is not None
        assert current.peers[0].allow_proxy_repair_approval is allowed
        assert changed.peers[0].allow_proxy_repair_approval is allowed
        assert current.peers[0].model_dump(exclude={"allow_proxy_repair_approval"}) == before.peers[
            0
        ].model_dump(exclude={"allow_proxy_repair_approval"})
        assert current.peers[1] == before.peers[1]
        assert current.bind == before.bind and current.limits == before.limits
        running = policy.authenticate(f"Bearer {CODE.token}")
        restarted = service.build_security_policy().authenticate(f"Bearer {CODE.token}")
        assert running is not None and not running.allow_proxy_repair_approval
        assert restarted is not None and restarted.allow_proxy_repair_approval is allowed
        assert secrets.values == saved_secrets
    with pytest.raises(KeyError, match="gateway_peer_not_found"):
        service.set_proxy_repair_approval(NodeId.new(), True)
    empty = GatewayConfigurationService(
        FileGatewayConfigurationRepository(tmp_path / "missing.json"), secrets
    )
    with pytest.raises(KeyError, match="gateway_peer_not_found"):
        empty.set_proxy_repair_approval(JOINER, True)


def test_peer_proxy_approval_cli_text_and_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    secrets = MemorySecrets()
    service = configuration(tmp_path, secrets)
    service.provision_peer(GatewayPeerInput(peer=peer(JOINER, "书房电脑"), token=CODE.token))

    def secret_store(_root: Path) -> MemorySecrets:
        return secrets

    monkeypatch.setattr("tunnelminion.gateway.configuration.gateway_secret_store", secret_store)
    monkeypatch.setattr("tunnelminion.app.default_data_dir", lambda: tmp_path)
    for state, word in (("on", "允许"), ("off", "关闭")):
        assert cli.main(["peer-proxy-approval", str(JOINER), state]) == 0
        assert (
            capsys.readouterr().out
            == f"已{word} 书房电脑 替这台电脑批准修复。重启 TunnelMinion 后生效。\n"
        )
    for node_id, root, message in (
        (str(NodeId.new()), tmp_path, "尚未配置这个对端"),
        (str(JOINER), tmp_path / "empty", "尚未配置这个对端"),
        ("invalid", tmp_path, "电脑编号无效"),
    ):
        assert cli.main(["peer-proxy-approval", node_id, "on", "--data-dir", str(root)]) == 2
        assert capsys.readouterr().out.strip() == message
    with pytest.raises(SystemExit) as caught:
        cli.main(["peer-proxy-approval", str(JOINER), "unknown"])
    assert caught.value.code == 2


@pytest.mark.parametrize("enabled", [False, True])
def test_gateway_configure_flag_defaults_off(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, enabled: bool
) -> None:
    monkeypatch.setattr(cli.sys, "stdin", io.StringIO(CODE.token))
    args = [
        "gateway-configure",
        "--data-dir",
        str(tmp_path),
        "--bind-host",
        "192.0.2.1",
        "--peer-node-id",
        str(JOINER),
        "--peer-host",
        "192.0.2.2",
        "--peer-platform",
        "macos",
        "--secret-store",
        "restricted-file",
    ]
    if enabled:
        args.append("--allow-proxy-approval")
    assert cli.main(args) == 0
    service = GatewayConfigurationService(
        FileGatewayConfigurationRepository(tmp_path / "gateway.json"),
        gateway_secret_store(tmp_path),
    )
    assert service.view().peers[0].allow_proxy_repair_approval is enabled
    running = service.build_security_policy().authenticate(f"Bearer {CODE.token}")
    assert running is not None and running.allow_proxy_repair_approval is enabled


@pytest.mark.parametrize("platform", ["windows", "macos"])
@pytest.mark.parametrize("enabled", [False, True])
def test_invite_cli_permissions_reach_config_and_running_gateway(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], platform: str, enabled: bool
) -> None:
    args = [
        "invite",
        "--data-dir",
        str(tmp_path),
        "--bind-host",
        "192.0.2.1",
        "--secret-store",
        "restricted-file",
    ]
    if enabled:
        args.append("--allow-proxy-approval")
    assert cli.main(args) == 0
    output = capsys.readouterr().out
    code = InviteCode.decode(output.splitlines()[1])
    assert code.permissions.allow_proxy_repair_approval is enabled
    assert (
        "对方可以在它的地图上替这台电脑批准修复；每次动手前，这台电脑仍会再核对一次。" in output
    ) is enabled
    bundle = (
        build_windows_gateway_application(tmp_path)
        if platform == "windows"
        else build_macos_gateway_application(tmp_path)
    )

    async def scenario() -> None:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(bundle.app, client=(ACCEPTANCE.host, 1234)),
            base_url="http://127.0.0.1",
        ) as client:
            headers = {"Authorization": f"Bearer {code.token}"}
            before = (tmp_path / "gateway.json").read_bytes()
            for injected in (
                {**ACCEPTANCE.model_dump(mode="json"), "allow_proxy_repair_approval": True},
                {
                    **ACCEPTANCE.model_dump(mode="json"),
                    "permissions": {"allow_proxy_repair_approval": True},
                },
            ):
                with pytest.raises(ValidationError):
                    InviteAcceptance.model_validate(injected)
                rejected = await client.post("/v1/invites:accept", headers=headers, json=injected)
                assert rejected.status_code == 401
                assert (tmp_path / "gateway.json").read_bytes() == before
            accepted = await client.post(
                "/v1/invites:accept", headers=headers, json=ACCEPTANCE.model_dump(mode="json")
            )
            assert accepted.status_code == 200
            assert (
                accepted.json()["permissions"].get("allow_proxy_repair_approval", False) is enabled
            )
            # 已启用修复服务且运行中的权限已更新，获准对端能走到编号检查。
            response = await client.get("/v1/repairs/invalid", headers=headers)
            assert response.status_code == (404 if enabled else 403)
            assert response.json()["error"]["code"] == (
                "repair_not_found" if enabled else "repair_approval_not_allowed"
            )
            config = (tmp_path / "gateway.json").read_bytes()
            for path in (
                "/v1/peers",
                f"/v1/peers/{JOINER}/proxy-approval",
                "/v1/gateway/configuration",
            ):
                assert (
                    await client.post(
                        path, headers=headers, json={"allow_proxy_repair_approval": True}
                    )
                ).status_code == 404
            assert (tmp_path / "gateway.json").read_bytes() == config
        service = GatewayConfigurationService(
            FileGatewayConfigurationRepository(tmp_path / "gateway.json"),
            gateway_secret_store(tmp_path),
        )
        assert service.view().peers[0].allow_proxy_repair_approval is enabled

    asyncio.run(scenario())


@pytest.mark.parametrize("enabled", [False, True])
def test_join_reports_permission_without_granting_it_back(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    enabled: bool,
) -> None:
    secrets = MemorySecrets()
    permissions = InvitePermissions(allow_proxy_repair_approval=enabled)
    accepted = InviteAccepted(inviter_node_id=CODE.node_id, permissions=permissions)

    async def accept(_code: InviteCode, _acceptance: InviteAcceptance) -> InviteAccepted:
        return accepted

    monkeypatch.setattr(joining, "accept_invite", accept)

    def secret_store(_root: Path) -> MemorySecrets:
        return secrets

    monkeypatch.setattr(joining, "gateway_secret_store", secret_store)
    asyncio.run(joining.join(CODE, data_dir=tmp_path, host_override="192.0.2.2"))
    output = capsys.readouterr().out
    assert ("- 可以在你的地图上替对方批准修复" in output) is enabled
    config = FileGatewayConfigurationRepository(tmp_path / "gateway.json").load()
    assert config is not None and not config.peers[0].allow_proxy_repair_approval
    assert ("allow_proxy_repair_approval" in permissions.model_dump()) is enabled
    assert ("allow_proxy_repair_approval" in accepted.model_dump_json()) is enabled
