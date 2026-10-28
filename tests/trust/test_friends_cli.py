"""朋友命令的权限、同步提示与旧式配对逐条确认。"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest
from fastapi import FastAPI
from tests.trust.test_friends import pair
from tests.trust.test_identity import MemorySecrets
from tests.trust.test_own_devices import Computer, computer

from tunnelminion.cli import main
from tunnelminion.domain.trust import FriendPermissions, JoinCode, JoinCodeKind
from tunnelminion.gateway.configuration import (
    FileGatewayConfigurationRepository,
    GatewayConfiguration,
    GatewayPeerConfig,
    GatewayPeerInput,
    gateway_token_name,
)
from tunnelminion.gateway.security import GatewayBindConfig
from tunnelminion.model.secrets import SecretStoreError
from tunnelminion.trust.contracts import IdentityError
from tunnelminion.trust.devices import OwnDevicesService
from tunnelminion.trust.friend_cli import friend_command, load_devices, peers_command


def patch_secrets(monkeypatch: pytest.MonkeyPatch, a: Computer) -> None:
    def backend(_root: Path) -> MemorySecrets:
        return a.secrets

    monkeypatch.setattr("tunnelminion.trust.friend_cli.gateway_secret_store", backend)


def test_load_local_identity_does_not_initialize_missing_data(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(IdentityError, match="尚未初始化"):
        load_devices(tmp_path / "missing")
    assert not (tmp_path / "missing").exists()
    a = computer(tmp_path / "a", 1, {})
    patch_secrets(monkeypatch, a)
    assert load_devices(a.root).roster() == a.service.roster()


def test_friend_commands_pair_list_update_restrict_and_remove(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    apps: dict[str, FastAPI] = {}
    a = computer(tmp_path / "a", 1, apps)
    b = computer(tmp_path / "b", 2, apps, a)
    f = computer(tmp_path / "f", 3, apps)
    computers = {item.root: item for item in (a, b, f)}

    def local_devices(root: Path) -> OwnDevicesService:
        return computers[root].service

    monkeypatch.setattr("tunnelminion.trust.friend_cli.load_devices", local_devices)
    monkeypatch.setattr("tunnelminion.trust.friend_cli.default_data_dir", lambda: a.root)
    assert main(["friend", "invite", "--display-name", "小明"]) == 0
    code = JoinCode.decode(capsys.readouterr().out.strip(), JoinCodeKind.FRIEND)
    assert (
        main(["friend", "join", code.encode(), "--data-dir", str(f.root), "--display-name", "小林"])
        == 0
    )
    assert main(["friend", "list", "--json"]) == 0
    output = capsys.readouterr().out
    assert "小林" in output and '"relationship": "friend"' in output
    assert code.token not in output
    assert main(["friend", "list"]) == 0
    assert "可提问=是" in capsys.readouterr().out
    assert main(["friend", "restrict", "小林", "--data-dir", str(b.root), "--no-delegation"]) == 0
    assert (
        main(["friend", "permissions", "小林", "--data-dir", str(b.root), "--no-delegation"]) == 2
    )
    assert (
        main(["friend", "permissions", "小林", "--allow-model-borrowing", "--daily-quota", "100"])
        == 0
    )
    assert b.service.trust_list().people[0].permissions.allow_model_borrowing
    assert main(["friend", "restrict", "小林", "--no-model-borrowing", "--daily-quota", "50"]) == 0
    assert main(["friend", "restrict", "小林", "--no-delegation"]) == 0
    assert main(["friend", "restrict", "小林", "--allow-model-borrowing"]) == 2
    assert "只能关闭或调小" in capsys.readouterr().out
    assert main(["friend", "permissions", "小林", "--no-model-borrowing", "--no-delegation"]) == 0
    assert not b.service.trust_list().people[0].permissions.allow_delegation
    a.mesh.offline.add(b.host)
    assert main(["friend", "remove", "小林"]) == 0
    assert "下次接触时会同步" in capsys.readouterr().out
    assert not a.service.trust_list().people


def test_friend_cli_default_name_json_and_invalid_arguments(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    a = computer(tmp_path / "a", 1, {})
    f = computer(tmp_path / "f", 3, {})
    pair(a, f)

    def local_devices(_root: Path) -> OwnDevicesService:
        return a.service

    monkeypatch.setattr("tunnelminion.trust.friend_cli.load_devices", local_devices)
    monkeypatch.setattr("tunnelminion.trust.friend_cli.default_data_dir", lambda: a.root)
    assert friend_command(["friend", "list", "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data[0]["permissions"] == FriendPermissions().model_dump()
    assert friend_command(["friend", "permissions", "小林", "--daily-quota", "0"]) == 2
    assert "朋友配置无效" in capsys.readouterr().out
    assert friend_command(["friend", "join", "tmf1_损坏"]) == 2
    assert "损坏" in capsys.readouterr().out
    assert friend_command(["friend", "remove", "不认识的人"]) == 2
    assert "朋友不存在" in capsys.readouterr().out
    a.config.delete()
    assert friend_command(["friend", "list", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)[0]["devices"][0]["relationship"] == "friend"
    with sqlite3.connect(a.root / "runtime.sqlite3") as connection:
        connection.execute("DELETE FROM friend_rosters")
    assert friend_command(["friend", "list", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)[0]["devices"] == []


def provision(a: Computer, target: Computer) -> None:
    a.config.provision_peer(
        GatewayPeerInput(
            peer=GatewayPeerConfig(
                node_id=target.service.node_id,
                host=target.host,
                display_name="旧电脑",
                allowed_tools=frozenset({"get_node_summary"}),
            ),
            token="tmn_" + str(target.service.node_id)[5:] + "a" * 8,
        )
    )


@pytest.mark.parametrize("confirmation", ["", "n", "yes", "是", "eof", "interrupt"])
def test_migration_deletes_only_the_individually_confirmed_own_peer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    confirmation: str,
) -> None:
    apps: dict[str, FastAPI] = {}
    a = computer(tmp_path / "a", 1, apps)
    b = computer(tmp_path / "b", 2, apps, a)
    f = computer(tmp_path / "f", 3, apps)
    provision(a, b)
    provision(a, f)
    patch_secrets(monkeypatch, a)

    def answer(prompt: str) -> str:
        assert "旧令牌和旧配置" in prompt
        if confirmation == "eof":
            raise EOFError
        if confirmation == "interrupt":
            raise KeyboardInterrupt
        return confirmation

    before = (a.root / "gateway.json").read_bytes()
    result = peers_command(["peers", "migrate", "--data-dir", str(a.root)], input_fn=answer)
    assert result == (2 if confirmation in ("eof", "interrupt") else 0)
    repository = FileGatewayConfigurationRepository(a.root / "gateway.json")
    config = repository.load()
    assert config is not None
    accepted = confirmation in ("yes", "是")
    assert (a.secrets.get(gateway_token_name(b.service.node_id)) is None) == accepted
    assert (len(config.peers) == 1) == accepted
    assert a.secrets.get(gateway_token_name(f.service.node_id)) is not None
    if not accepted:
        assert (a.root / "gateway.json").read_bytes() == before
    elif result == 0:
        assert "friend invite" in capsys.readouterr().out


def test_migration_without_identity_keeps_legacy_and_handles_empty_or_invalid_config(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    root = tmp_path / "empty"
    monkeypatch.setattr("tunnelminion.trust.friend_cli.default_data_dir", lambda: root)
    assert main(["peers", "migrate"]) == 0
    assert "没有旧式配对" in capsys.readouterr().out
    a = computer(tmp_path / "a", 1, {})
    f = computer(tmp_path / "f", 3, {})
    patch_secrets(monkeypatch, a)
    provision(a, f)
    root.mkdir()
    repository = FileGatewayConfigurationRepository(root / "gateway.json")
    config = FileGatewayConfigurationRepository(a.root / "gateway.json").load()
    assert config is not None
    repository.save(config)
    assert main(["peers", "migrate"]) == 0
    assert "friend invite" in capsys.readouterr().out
    assert repository.load() == config
    repository.save(GatewayConfiguration(bind=GatewayBindConfig(host="10.20.0.1")))
    assert main(["peers", "migrate"]) == 0
    (root / "gateway.json").write_text("invalid", encoding="utf-8")
    assert main(["peers", "migrate"]) == 2


def test_migration_default_input_and_secret_failure_are_reported(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    apps: dict[str, FastAPI] = {}
    a = computer(tmp_path / "a", 1, apps)
    b = computer(tmp_path / "b", 2, apps, a)
    provision(a, b)
    patch_secrets(monkeypatch, a)

    def answer(_prompt: str) -> str:
        return "y"

    monkeypatch.setattr("builtins.input", answer)
    assert peers_command(["peers", "migrate", "--data-dir", str(a.root)]) == 0

    def unavailable(_root: Path) -> Computer:
        raise SecretStoreError("秘密存储不可用")

    monkeypatch.setattr("tunnelminion.trust.friend_cli.load_devices", unavailable)
    assert friend_command(["friend", "list", "--data-dir", str(a.root)]) == 2
    provision(a, b)
    assert peers_command(["peers", "migrate", "--data-dir", str(a.root)]) == 2


def test_friend_cli_rename(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    a = computer(tmp_path / "a", 1, {})
    f = computer(tmp_path / "f", 3, {})
    pair(a, f)

    def local_devices(_root: Path) -> OwnDevicesService:
        return a.service

    monkeypatch.setattr("tunnelminion.trust.friend_cli.load_devices", local_devices)
    monkeypatch.setattr("tunnelminion.trust.friend_cli.default_data_dir", lambda: a.root)
    assert friend_command(["friend", "rename", "小林", "大学同学"]) == 0
    assert "已修改朋友的显示名" in capsys.readouterr().out
    assert a.service.trust_list().people[0].display_name == "大学同学"
