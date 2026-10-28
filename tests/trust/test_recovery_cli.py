"""交互恢复和重置的确认边界、秘密隔离与本机数据保留。"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI
from tests.test_owner_cli import confirmation
from tests.trust.test_friends import pair
from tests.trust.test_identity import MemorySecrets
from tests.trust.test_own_devices import Computer, computer
from tests.trust.test_recovery import dump, recoverable_computer

from tunnelminion import cli
from tunnelminion.domain.identifiers import NodeId
from tunnelminion.memory.sqlite import SQLiteStores
from tunnelminion.model.secrets import SecretStore, SecretStoreError
from tunnelminion.trust.cli import owner_command
from tunnelminion.trust.contracts import TrustStore
from tunnelminion.trust.devices import OwnDevicesService
from tunnelminion.trust.keys import DEVICE_KEY_NAME, OWNER_KEY_NAME, PrivateKey, parse_recovery_code
from tunnelminion.trust.service import OwnerIdentityService


def files(root: Path) -> dict[str, bytes]:
    return {
        str(path.relative_to(root)): path.read_bytes() for path in root.rglob("*") if path.is_file()
    }


def use_secrets(monkeypatch: pytest.MonkeyPatch, local: Computer) -> None:
    def backend(root: Path) -> MemorySecrets:
        return local.secrets

    monkeypatch.setattr("tunnelminion.trust.cli.gateway_secret_store", backend)
    monkeypatch.setattr("tunnelminion.trust.join.gateway_secret_store", backend)


@pytest.mark.parametrize(
    "fault", ["short", "checksum", "other", "confirmation", "eof", "interrupt"]
)
def test_failed_recovery_never_writes_or_echoes_code(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
    fault: str,
) -> None:
    a, keys = recoverable_computer(tmp_path / "a", 1, {})
    code = keys.recovery_code
    if fault == "short":
        code = code[:-1]
    elif fault == "checksum":
        code = code[:-1] + ("1" if code[-1] != "1" else "0")
    elif fault == "other":
        code = PrivateKey.generate().recovery_code()
    before, private = files(a.root), dict(a.secrets.values)
    shown: list[str] = []

    def answer(prompt: str) -> str:
        if "前 4 个字符" not in prompt:
            return code
        if fault == "eof":
            raise EOFError
        if fault == "interrupt":
            raise KeyboardInterrupt
        shown.append(capsys.readouterr().out.splitlines()[-1])
        return "错误确认"

    use_secrets(monkeypatch, a)
    assert owner_command(["owner", "recover", "--data-dir", str(a.root)], input_fn=answer) == 2
    output = capsys.readouterr().out
    if fault in ("short", "checksum", "other"):
        assert output == "恢复码无效\n"
    assert code not in output + caplog.text
    assert all(new_code not in output + caplog.text for new_code in shown)
    assert files(a.root) == before and a.secrets.values == private


@pytest.mark.parametrize("injected", [False, True])
def test_recover_command_uses_interactive_input_and_pushes_removals(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
    injected: bool,
) -> None:
    apps: dict[str, FastAPI] = {}
    a, keys = recoverable_computer(tmp_path / "a", 1, apps)
    b = computer(tmp_path / "b", 2, apps, a)
    c = computer(tmp_path / "c", 3, apps, a)
    d = computer(tmp_path / "d", 4, apps, a)
    old_key = a.secrets.values[OWNER_KEY_NAME]
    shown: list[str] = []

    def answer(prompt: str) -> str:
        if "前 4 个字符" in prompt:
            return confirmation(capsys, shown)
        return keys.recovery_code

    def devices(node_id: NodeId, store: TrustStore, secrets: SecretStore) -> OwnDevicesService:
        assert (
            node_id == a.service.node_id
            and store.owner_fingerprint() == a.service.roster().owner_fingerprint
        )
        return a.service

    monkeypatch.setattr("tunnelminion.trust.cli.OwnDevicesService", devices)
    monkeypatch.setattr("tunnelminion.trust.cli.default_data_dir", lambda: a.root)
    use_secrets(monkeypatch, a)
    monkeypatch.setattr("tunnelminion.trust.cli.getpass.getpass", answer)
    monkeypatch.setattr("builtins.input", answer)
    options = [
        "owner",
        "recover",
        "--remove",
        str(b.service.node_id),
        "--remove",
        str(c.service.node_id),
    ]
    assert owner_command(options, input_fn=answer if injected else None) == 0
    assert "旧恢复码已作废" in capsys.readouterr().out
    assert a.secrets.values[OWNER_KEY_NAME] != old_key
    assert a.secrets.values[DEVICE_KEY_NAME] == keys.device.seed_text()
    assert a.service.roster().recovery_fingerprint != keys.recovery_fingerprint
    assert (
        parse_recovery_code(shown[0]).public_key
        != parse_recovery_code(keys.recovery_code).public_key
    )
    assert a.service.roster().device(b.service.node_id) is None
    assert a.service.roster().device(c.service.node_id) is None
    assert d.service.roster() == a.service.roster()
    assert all(
        code not in dump(a.root / "runtime.sqlite3") + caplog.text
        for code in (keys.recovery_code, *shown)
    )


def test_recovery_code_cannot_be_passed_on_command_line(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit):
        cli.main(["owner", "recover", "--recovery-code", "secret"])
    assert "unrecognized arguments" in capsys.readouterr().err


@pytest.mark.parametrize("action", ["init", "join"])
@pytest.mark.parametrize("answer", ["取消", "eof", "interrupt"])
def test_reset_without_confirmation_keeps_all_identity_and_other_files(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    action: str,
    answer: str,
) -> None:
    a, _ = recoverable_computer(tmp_path / "a", 1, {})
    before, private = files(a.root), dict(a.secrets.values)

    def respond(prompt: str) -> str:
        assert "重置" in prompt
        if answer == "eof":
            raise EOFError
        if answer == "interrupt":
            raise KeyboardInterrupt
        return answer

    use_secrets(monkeypatch, a)
    options = ["owner", action]
    if action == "join":
        options.append("无效加入码")
    assert owner_command([*options, "--reset", "--data-dir", str(a.root)], input_fn=respond) == 2
    assert files(a.root) == before and a.secrets.values == private


def test_init_reset_replaces_identity_keeps_audit_legacy_secrets_and_other_data(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    apps: dict[str, FastAPI] = {}
    a, _ = recoverable_computer(tmp_path / "a", 1, apps)
    f = computer(tmp_path / "f", 3, apps)
    pair(a, f)
    store = SQLiteStores.open(a.root / "runtime.sqlite3").trust
    before = store.audits()
    old_owner = a.service.roster().owner_fingerprint
    old_device = a.secrets.values[DEVICE_KEY_NAME]
    a.secrets.set("gateway-legacy-peer", "保留旧令牌")
    a.secrets.set("model-token", "保留模型密钥")
    extra = a.root / "keep.txt"
    extra.write_text("保留运行数据", encoding="utf-8")
    shown: list[str] = []

    def respond(prompt: str) -> str:
        return "重置" if "重置" in prompt else confirmation(capsys, shown)

    use_secrets(monkeypatch, a)
    assert (
        owner_command(["owner", "init", "--reset", "--data-dir", str(a.root)], input_fn=respond)
        == 0
    )
    assert a.service.store.owner_fingerprint() != old_owner
    assert a.secrets.values[DEVICE_KEY_NAME] != old_device
    assert store.audits()[: len(before)] == before
    assert store.audits()[len(before)].action == "reset"
    assert not a.service.trust_list().people and not a.service.store.friend_rosters()
    assert a.secrets.values["gateway-legacy-peer"] == "保留旧令牌"
    assert a.secrets.values["model-token"] == "保留模型密钥"
    assert extra.read_text(encoding="utf-8") == "保留运行数据"


def test_join_reset_joins_new_owner_with_new_device_key_and_retains_audit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    apps: dict[str, FastAPI] = {}
    a, _ = recoverable_computer(tmp_path / "a", 1, apps)
    f = computer(tmp_path / "f", 3, apps)
    store = SQLiteStores.open(a.root / "runtime.sqlite3").trust
    before = store.audits()
    old_device = a.secrets.values[DEVICE_KEY_NAME]
    f.service.clock = lambda: datetime.now(UTC)
    code = f.service.invite()
    use_secrets(monkeypatch, a)

    def transport(**kwargs: object) -> httpx.AsyncBaseTransport:
        return a.mesh

    monkeypatch.setattr(httpx, "AsyncHTTPTransport", transport)
    assert (
        owner_command(
            ["owner", "join", code.encode(), "--reset", "--data-dir", str(a.root)],
            input_fn=lambda prompt: "重置",
        )
        == 0
    )
    assert a.service.roster().owner_fingerprint == f.service.roster().owner_fingerprint
    assert a.secrets.values[DEVICE_KEY_NAME] != old_device
    assert OWNER_KEY_NAME not in a.secrets.values
    assert store.audits()[: len(before)] == before


def test_reset_secret_failure_rolls_back_database_and_keys(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    a, _ = recoverable_computer(tmp_path / "a", 1, {})
    before, private = dump(a.root / "runtime.sqlite3"), dict(a.secrets.values)
    original = a.secrets.delete

    def fail(name: str) -> None:
        original(name)
        if name == DEVICE_KEY_NAME:
            raise RuntimeError("删除失败")

    monkeypatch.setattr(a.secrets, "delete", fail)
    with pytest.raises(SecretStoreError):
        OwnerIdentityService(a.service.store, a.secrets).reset()
    assert dump(a.root / "runtime.sqlite3") == before and a.secrets.values == private


def test_recover_requires_initialized_identity(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root = tmp_path / "empty"
    root.mkdir()
    assert owner_command(["owner", "recover", "--data-dir", str(root)]) == 2
    assert "本机身份尚未初始化" in capsys.readouterr().out


def test_recover_reports_computers_it_could_not_reach(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    apps: dict[str, FastAPI] = {}
    a, keys = recoverable_computer(tmp_path / "a", 1, apps)
    b = computer(tmp_path / "b", 2, apps, a)
    a.mesh.offline.add(b.host)
    shown: list[str] = []

    def answer(prompt: str) -> str:
        if "前 4 个字符" in prompt:
            return confirmation(capsys, shown)
        return keys.recovery_code

    def devices(node_id: NodeId, store: TrustStore, secrets: SecretStore) -> OwnDevicesService:
        return a.service

    monkeypatch.setattr("tunnelminion.trust.cli.OwnDevicesService", devices)
    use_secrets(monkeypatch, a)
    assert owner_command(["owner", "recover", "--data-dir", str(a.root)], input_fn=answer) == 0
    assert f"这次没推到 {b.service.node_id}" in capsys.readouterr().out
