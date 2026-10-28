"""机主命令只在确认后持久化，输出只含公开身份信息。"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest
from tests.trust.test_identity import MemorySecrets

from tunnelminion import cli
from tunnelminion.app import load_or_create_node_id
from tunnelminion.domain.tools import Platform
from tunnelminion.gateway.configuration import (
    FileGatewayConfigurationRepository,
    GatewayConfiguration,
    GatewaySecretStoreKind,
    configure_gateway_secret_store,
    gateway_secret_store,
)
from tunnelminion.gateway.names import save_node_name
from tunnelminion.gateway.security import GatewayBindConfig
from tunnelminion.memory.sqlite import SQLiteStores, SQLiteTrustStore
from tunnelminion.model.secrets import RestrictedFileSecretStore
from tunnelminion.trust.cli import owner_command
from tunnelminion.trust.contracts import IdentityStatus
from tunnelminion.trust.keys import DEVICE_KEY_NAME, OWNER_KEY_NAME, InitializationKeys
from tunnelminion.trust.service import OwnerIdentityService


@pytest.fixture(autouse=True)
def memory_keyring(monkeypatch: pytest.MonkeyPatch) -> MemorySecrets:
    """包括默认后端在内，所有钥匙串调用都只读写测试内存。"""
    secrets = MemorySecrets()

    def get(service: str, name: str) -> str | None:
        return secrets.get(name)

    def set_secret(service: str, name: str, value: str) -> None:
        secrets.set(name, value)

    def delete(service: str, name: str) -> None:
        secrets.delete(name)

    monkeypatch.setattr("keyring.get_password", get)
    monkeypatch.setattr("keyring.set_password", set_secret)
    monkeypatch.setattr("keyring.delete_password", delete)
    return secrets


def confirmation(capsys: pytest.CaptureFixture[str], shown: list[str]) -> str:
    text = capsys.readouterr().out
    assert text.count("恢复码（只显示这一次") == 1
    code = text.splitlines()[-1]
    shown.append(code)
    return code[:4].lower()


@pytest.mark.parametrize("backend", [None, "keyring", "restricted-file"])
@pytest.mark.parametrize("platform", ["win32", "darwin", "linux"])
def test_init_and_status_never_repeat_recovery_code_or_private_keys(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    memory_keyring: MemorySecrets,
    backend: str | None,
    platform: str,
) -> None:
    root = tmp_path / "identity"
    monkeypatch.setattr("tunnelminion.trust.cli.sys.platform", platform)
    shown: list[str] = []

    def confirm(prompt: str) -> str:
        assert not root.exists() and memory_keyring.values == {}
        assert "前 4 个字符" in prompt
        return confirmation(capsys, shown)

    arguments = ["owner", "init", "--data-dir", str(root), "--bind-host", "10.0.0.1"]
    if backend is not None:
        arguments += ["--secret-store", backend]
    assert owner_command(arguments, input_fn=confirm) == 0
    completed = capsys.readouterr().out
    store = gateway_secret_store(root)
    service = OwnerIdentityService(SQLiteStores.open(root / "runtime.sqlite3").trust, store)
    status = service.status()
    expected_platform = {
        "win32": Platform.WINDOWS,
        "darwin": Platform.MACOS,
        "linux": Platform.LINUX,
    }[platform]
    assert status.devices[0].platform is expected_platform
    assert status.devices[0].node_id == load_or_create_node_id(root / "node-id")
    assert status.has_owner_key and status.roster_version == status.trust_list_version == 1
    assert (root / "gateway-secret-store").exists() == (backend is not None)
    assert isinstance(store, RestrictedFileSecretStore) == (backend == "restricted-file")
    assert cli.main(["owner", "status", "--data-dir", str(root)]) == 0
    readable = capsys.readouterr().out
    assert "本机持有机主密钥：是" in readable
    assert status.devices[0].display_name in readable
    assert cli.main(["owner", "status", "--data-dir", str(root), "--json"]) == 0
    structured = capsys.readouterr().out
    assert IdentityStatus.model_validate_json(structured) == status
    for secret in (store.get(OWNER_KEY_NAME), store.get(DEVICE_KEY_NAME), *shown):
        assert secret is not None
        assert secret not in completed + readable + structured
    assert shown[0].encode() not in (root / "runtime.sqlite3").read_bytes()


@pytest.mark.parametrize("existing_database", [False, True])
def test_wrong_confirmation_writes_nothing_even_with_an_older_database(
    tmp_path: Path,
    memory_keyring: MemorySecrets,
    capsys: pytest.CaptureFixture[str],
    existing_database: bool,
) -> None:
    root = tmp_path / "identity"
    if existing_database:
        root.mkdir()
        with sqlite3.connect(root / "runtime.sqlite3") as connection:
            connection.execute("CREATE TABLE existing_data (value TEXT)")
            connection.execute("INSERT INTO existing_data VALUES ('保留')")
    before = {item.name: item.read_bytes() for item in root.iterdir()} if root.exists() else {}
    assert (
        owner_command(
            [
                "owner",
                "init",
                "--data-dir",
                str(root),
                "--bind-host",
                "10.0.0.1",
                "--secret-store",
                "restricted-file",
            ],
            input_fn=lambda prompt: "XXXX",
        )
        == 2
    )
    assert "确认不符，未保存身份或密钥" in capsys.readouterr().out
    assert memory_keyring.values == {}
    after = {item.name: item.read_bytes() for item in root.iterdir()} if root.exists() else {}
    assert before == after and root.exists() == existing_database


@pytest.mark.parametrize("failure", [EOFError, KeyboardInterrupt])
def test_cancelled_input_does_not_create_files_or_secrets(
    tmp_path: Path,
    failure: type[BaseException],
    memory_keyring: MemorySecrets,
    capsys: pytest.CaptureFixture[str],
) -> None:
    root = tmp_path / "identity"

    def cancel(prompt: str) -> str:
        raise failure

    assert (
        owner_command(
            ["owner", "init", "--data-dir", str(root), "--bind-host", "10.0.0.1"], input_fn=cancel
        )
        == 2
    )
    assert "已取消" in capsys.readouterr().out
    assert not root.exists() and not memory_keyring.values


def test_existing_gateway_bind_and_node_id_take_priority(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    repository = FileGatewayConfigurationRepository(tmp_path / "gateway.json")
    config = GatewayConfiguration(bind=GatewayBindConfig(host="10.0.0.2", port=9999))
    repository.save(config)
    save_node_name(tmp_path, "已有名字")
    node = load_or_create_node_id(tmp_path / "node-id")
    shown: list[str] = []
    assert (
        owner_command(
            [
                "owner",
                "init",
                "--data-dir",
                str(tmp_path),
                "--bind-host",
                "10.0.0.3",
                "--bind-port",
                "9000",
            ],
            input_fn=lambda prompt: confirmation(capsys, shown),
        )
        == 0
    )
    status = OwnerIdentityService(
        SQLiteStores.open(tmp_path / "runtime.sqlite3").trust, gateway_secret_store(tmp_path)
    ).status()
    assert status.devices[0].host == "10.0.0.2" and status.devices[0].port == 9999
    assert status.devices[0].node_id == node and status.devices[0].display_name == "已有名字"
    assert repository.load() == config


def test_custom_name_and_port_and_default_input_are_supported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    shown: list[str] = []
    monkeypatch.setattr("tunnelminion.trust.cli.default_data_dir", lambda: tmp_path)

    def confirm(prompt: str) -> str:
        return confirmation(capsys, shown)

    monkeypatch.setattr("builtins.input", confirm)
    assert (
        cli.main(
            [
                "owner",
                "init",
                "--bind-host",
                "10.0.0.1",
                "--bind-port",
                "9000",
                "--display-name",
                "书房电脑",
            ]
        )
        == 0
    )
    status = OwnerIdentityService(
        SQLiteStores.open(tmp_path / "runtime.sqlite3").trust, gateway_secret_store(tmp_path)
    ).status()
    assert status.devices[0].display_name == "书房电脑" and status.devices[0].port == 9000
    assert not (tmp_path / "gateway.json").exists()


def test_configured_file_backend_works_when_keyring_is_unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def fail(*args: object) -> None:
        pytest.fail("受限文件后端不得访问系统钥匙串")

    monkeypatch.setattr("keyring.get_password", fail)
    configure_gateway_secret_store(tmp_path, GatewaySecretStoreKind.RESTRICTED_FILE)
    shown: list[str] = []
    assert (
        owner_command(
            ["owner", "init", "--data-dir", str(tmp_path), "--bind-host", "10.0.0.1"],
            input_fn=lambda prompt: confirmation(capsys, shown),
        )
        == 0
    )


@pytest.mark.parametrize("as_json", [False, True])
def test_uninitialized_status_is_read_only(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], as_json: bool
) -> None:
    root = tmp_path / "identity"
    options = ["--json"] if as_json else []
    assert cli.main(["owner", "status", "--data-dir", str(root), *options]) == 0
    captured = capsys.readouterr()
    if as_json:
        assert json.loads(captured.out) == IdentityStatus().model_dump(mode="json")
    else:
        assert captured.out == "本机身份尚未初始化\n"
    assert not root.exists() and not captured.err


@pytest.mark.parametrize(
    "options",
    [
        [],
        ["--bind-host", "0.0.0.0"],
        ["--bind-host", "127.0.0.1"],
        ["--bind-host", "10.0.0.1", "--bind-port", "80"],
        ["--bind-host", "10.0.0.1", "--display-name", ""],
        ["--bind-host", "10.0.0.1", "--display-name", "坏\n名字"],
    ],
)
def test_invalid_configuration_is_rejected_before_key_generation(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], options: list[str]
) -> None:
    root = tmp_path / "identity"
    assert (
        owner_command(
            ["owner", "init", "--data-dir", str(root), *options],
            input_fn=lambda prompt: pytest.fail("不得确认"),
        )
        == 2
    )
    assert "恢复码" not in capsys.readouterr().out
    assert not root.exists()


def test_duplicate_init_does_not_show_a_new_recovery_code_or_change_backend(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    keys = InitializationKeys.generate()
    OwnerIdentityService(
        SQLiteStores.open(tmp_path / "runtime.sqlite3").trust, gateway_secret_store(tmp_path)
    ).init(
        load_or_create_node_id(tmp_path / "node-id"),
        GatewayBindConfig(host="10.0.0.1"),
        "测试电脑",
        keys,
    )
    assert (
        owner_command(
            ["owner", "init", "--data-dir", str(tmp_path), "--secret-store", "restricted-file"],
            input_fn=lambda prompt: pytest.fail("不得重复确认"),
        )
        == 2
    )
    assert capsys.readouterr().out == "本机身份已经初始化，不能重复初始化\n"
    assert not (tmp_path / "gateway-secret-store").exists()


def test_status_reports_a_missing_owner_key_without_secrets(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], memory_keyring: MemorySecrets
) -> None:
    OwnerIdentityService(
        SQLiteStores.open(tmp_path / "runtime.sqlite3").trust, memory_keyring
    ).init(
        load_or_create_node_id(tmp_path / "node-id"),
        GatewayBindConfig(host="10.0.0.1"),
        "测试电脑",
        InitializationKeys.generate(),
    )
    memory_keyring.delete(OWNER_KEY_NAME)
    assert cli.main(["owner", "status", "--data-dir", str(tmp_path)]) == 0
    assert "本机持有机主密钥：否" in capsys.readouterr().out


def test_read_only_precheck_recognizes_empty_identity_table(tmp_path: Path) -> None:
    path = tmp_path / "runtime.sqlite3"
    SQLiteStores.open(path)
    before = path.read_bytes()
    assert not SQLiteTrustStore.is_initialized(path)
    assert path.read_bytes() == before
