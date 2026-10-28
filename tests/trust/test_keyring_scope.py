"""每个数据目录用自己的钥匙串条目；旧版本共用条目里的身份密钥只在指纹对得上时迁过来。"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
from keyring.errors import KeyringError, PasswordDeleteError

from tunnelminion.domain.identifiers import NodeId
from tunnelminion.domain.trust import key_fingerprint
from tunnelminion.gateway.configuration import (
    gateway_keyring_store,
    gateway_token_name,
    load_or_create_node_id,
)
from tunnelminion.gateway.security import GatewayBindConfig
from tunnelminion.memory.sqlite import SQLiteStores
from tunnelminion.model.secrets import (
    KEYRING_SERVICE_NAME,
    KeyringSecretStore,
    SecretStore,
    SecretStoreError,
)
from tunnelminion.trust.backup import KEY_BACKUP_NAME, IdentityState, KeyBackup, read_backup
from tunnelminion.trust.contracts import AlreadyInitializedError, TrustStore
from tunnelminion.trust.keys import (
    DEVICE_KEY_NAME,
    OWNER_KEY_NAME,
    InitializationKeys,
    PrivateKey,
)
from tunnelminion.trust.service import OwnerIdentityService

LEGACY = KEYRING_SERVICE_NAME
PEER = NodeId("node_" + "b" * 32)


class FakeKeyring:
    """按（服务名, 条目名）保存，和真实钥匙串一样区分服务名。"""

    def __init__(self) -> None:
        self.values: dict[tuple[str, str], str] = {}
        self.fail_set: set[str] = set()
        self.fail_delete: set[str] = set()

    def get(self, service: str, name: str) -> str | None:
        return self.values.get((service, name))

    def set(self, service: str, name: str, value: str) -> None:
        if name in self.fail_set:
            raise KeyringError("unavailable")
        self.values[(service, name)] = value

    def delete(self, service: str, name: str) -> None:
        if name in self.fail_delete:
            raise KeyringError("unavailable")
        if (service, name) not in self.values:
            raise PasswordDeleteError(name)
        del self.values[(service, name)]

    def services(self) -> set[str]:
        return {service for service, _ in self.values}


@pytest.fixture
def keyring(monkeypatch: pytest.MonkeyPatch) -> FakeKeyring:
    fake = FakeKeyring()
    monkeypatch.setattr("keyring.get_password", fake.get)
    monkeypatch.setattr("keyring.set_password", fake.set)
    monkeypatch.setattr("keyring.delete_password", fake.delete)
    return fake


def initialize(root: Path, secrets: SecretStore) -> OwnerIdentityService:
    service = OwnerIdentityService(SQLiteStores.open(root / "runtime.sqlite3").trust, secrets)
    service.init(
        load_or_create_node_id(root / "node-id"),
        GatewayBindConfig(host="10.0.0.1"),
        "测试电脑",
        InitializationKeys.generate(),
    )
    return service


def legacy_identity(root: Path) -> tuple[OwnerIdentityService, dict[str, str]]:
    """更早版本：身份密钥写在不带节点编号的共用服务名下。"""
    initialize(root, KeyringSecretStore())
    legacy = KeyringSecretStore()
    keys = {name: legacy.get(name) for name in (OWNER_KEY_NAME, DEVICE_KEY_NAME)}
    assert all(value is not None for value in keys.values())
    service = OwnerIdentityService(
        SQLiteStores.open(root / "runtime.sqlite3").trust, gateway_keyring_store(root)
    )
    return service, {name: value for name, value in keys.items() if value is not None}


def test_two_data_dirs_on_one_computer_keep_separate_identities(
    tmp_path: Path, keyring: FakeKeyring
) -> None:
    first = initialize(tmp_path / "a", gateway_keyring_store(tmp_path / "a"))
    # 旧行为：所有数据目录共用一组条目，第二个数据目录会因“本机已有身份密钥”失败。
    second = initialize(tmp_path / "b", gateway_keyring_store(tmp_path / "b"))
    assert first.status().has_owner_key and second.status().has_owner_key
    assert first.status().owner_fingerprint != second.status().owner_fingerprint
    node_a = (tmp_path / "a" / "node-id").read_text(encoding="utf-8")
    node_b = (tmp_path / "b" / "node-id").read_text(encoding="utf-8")
    assert keyring.services() == {f"{LEGACY}/{node_a}", f"{LEGACY}/{node_b}"}


def test_store_without_node_id_reads_nothing_and_creates_it_on_first_write(
    tmp_path: Path, keyring: FakeKeyring
) -> None:
    root = tmp_path / "new"
    store = gateway_keyring_store(root)
    keyring.values[(LEGACY, gateway_token_name(PEER))] = "tmn_" + "x" * 40
    assert store.get(gateway_token_name(PEER)) is None
    store.delete("anything")
    assert not root.exists()
    store.set("value", "secret")
    node_id = (root / "node-id").read_text(encoding="utf-8")
    assert keyring.values[(f"{LEGACY}/{node_id}", "value")] == "secret"
    assert store.get("value") == "secret"
    store.delete("value")
    assert store.get("value") is None


def test_peer_tokens_from_the_shared_service_are_copied_and_left_in_place(
    tmp_path: Path, keyring: FakeKeyring
) -> None:
    root = tmp_path / "old"
    node_id = load_or_create_node_id(root / "node-id")
    name = gateway_token_name(PEER)
    token = "tmn_" + "x" * 40
    keyring.values[(LEGACY, name)] = token
    keyring.fail_set.add(name)
    store = gateway_keyring_store(root)
    # 复制失败也不影响这次读取，下次再复制。
    assert store.get(name) == token
    assert (f"{LEGACY}/{node_id}", name) not in keyring.values
    keyring.fail_set.clear()
    assert store.get(name) == token
    assert keyring.values[(f"{LEGACY}/{node_id}", name)] == token
    # 别的数据目录可能也在用旧条目，所以保留。
    assert keyring.values[(LEGACY, name)] == token


def test_legacy_identity_keys_move_to_the_data_dir_entries_when_fingerprints_match(
    tmp_path: Path, keyring: FakeKeyring
) -> None:
    root = tmp_path / "old"
    service, keys = legacy_identity(root)
    status = service.status()
    assert status.has_owner_key
    node_id = (root / "node-id").read_text(encoding="utf-8")
    scoped = KeyringSecretStore(f"{LEGACY}/{node_id}")
    assert {name: scoped.get(name) for name in keys} == keys
    assert all((LEGACY, name) not in keyring.values for name in keys)
    # 迁完以后新的数据目录可以建立自己的身份。
    assert initialize(tmp_path / "fresh", gateway_keyring_store(tmp_path / "fresh")).status()
    assert service.status() == status


def test_mismatched_legacy_keys_are_neither_used_nor_touched(
    tmp_path: Path, keyring: FakeKeyring
) -> None:
    root = tmp_path / "old"
    service, _ = legacy_identity(root)
    foreign = {
        OWNER_KEY_NAME: PrivateKey.generate().seed_text(),
        DEVICE_KEY_NAME: PrivateKey.generate().seed_text(),
    }
    for name, value in foreign.items():
        keyring.values[(LEGACY, name)] = value
    keyring.values[(LEGACY, KEY_BACKUP_NAME)] = "corrupt"
    assert not service.status().has_owner_key
    assert {name: keyring.values[(LEGACY, name)] for name in foreign} == foreign
    assert keyring.values[(LEGACY, KEY_BACKUP_NAME)] == "corrupt"
    node_id = (root / "node-id").read_text(encoding="utf-8")
    assert f"{LEGACY}/{node_id}" not in keyring.services()
    # 没有身份的新数据目录也不会把它们当成“本机已有身份密钥”。
    assert initialize(tmp_path / "fresh", gateway_keyring_store(tmp_path / "fresh")).status()


def test_migration_is_safe_to_retry_after_a_failed_write_or_delete(
    tmp_path: Path, keyring: FakeKeyring
) -> None:
    root = tmp_path / "old"
    service, keys = legacy_identity(root)
    keyring.fail_set.add(DEVICE_KEY_NAME)
    with pytest.raises(SecretStoreError, match="旧条目已保留"):
        service.status()
    # 机主密钥已经迁好；电脑密钥写失败，旧条目还在。
    assert (LEGACY, OWNER_KEY_NAME) not in keyring.values
    assert keyring.values[(LEGACY, DEVICE_KEY_NAME)] == keys[DEVICE_KEY_NAME]
    keyring.fail_set.clear()
    keyring.fail_delete.add(DEVICE_KEY_NAME)
    assert service.status().has_owner_key
    # 旧条目删不掉只留一份多余的副本，不影响使用，也不会再迁一次。
    assert keyring.values[(LEGACY, DEVICE_KEY_NAME)] == keys[DEVICE_KEY_NAME]
    keyring.fail_delete.clear()
    assert service.status().has_owner_key


def test_scoped_owner_key_that_does_not_match_is_left_alone(
    tmp_path: Path, keyring: FakeKeyring
) -> None:
    root = tmp_path / "old"
    service, keys = legacy_identity(root)
    stray = PrivateKey.generate().seed_text()
    gateway_keyring_store(root).set(OWNER_KEY_NAME, stray)
    assert not service.status().has_owner_key
    assert gateway_keyring_store(root).get(OWNER_KEY_NAME) == stray
    assert keyring.values[(LEGACY, OWNER_KEY_NAME)] == keys[OWNER_KEY_NAME]


def test_legacy_backup_of_this_identity_moves_and_is_settled(
    tmp_path: Path, keyring: FakeKeyring
) -> None:
    root = tmp_path / "old"
    service, keys = legacy_identity(root)
    owner = PrivateKey.from_seed_text(keys[OWNER_KEY_NAME])
    state = IdentityState(owner_fingerprint=key_fingerprint(owner.public_key))
    backup = KeyBackup(
        created_at=datetime.now(UTC),
        before=IdentityState(owner_fingerprint="0" * 64),
        after=state.model_copy(
            update={
                "device_public_key": PrivateKey.from_seed_text(keys[DEVICE_KEY_NAME]).public_key
            }
        ),
        keys={},
    )
    keyring.values[(LEGACY, KEY_BACKUP_NAME)] = backup.model_dump_json()
    assert service.status().has_owner_key
    assert (LEGACY, KEY_BACKUP_NAME) not in keyring.values
    # 数据库已经是换之后的身份，迁过来的备份随即被清掉。
    assert read_backup(gateway_keyring_store(root)) is None


def test_leftover_keys_explain_which_keys_and_what_to_do(
    tmp_path: Path, keyring: FakeKeyring
) -> None:
    root = tmp_path / "half"
    gateway_keyring_store(root).set(DEVICE_KEY_NAME, PrivateKey.generate().seed_text())
    with pytest.raises(AlreadyInitializedError) as caught:
        initialize(root, gateway_keyring_store(root))
    message = str(caught.value)
    assert "电脑密钥" in message and "机主密钥" not in message
    assert "runtime.sqlite3" in message and "owner init --reset" in message


def test_foreign_or_unreadable_legacy_entries_never_block_a_matching_migration(
    tmp_path: Path, keyring: FakeKeyring
) -> None:
    root = tmp_path / "old"
    service, keys = legacy_identity(root)
    foreign = KeyBackup(
        created_at=datetime.now(UTC),
        before=IdentityState(owner_fingerprint="1" * 64),
        after=IdentityState(owner_fingerprint="2" * 64),
        keys={},
    ).model_dump_json()
    keyring.values[(LEGACY, KEY_BACKUP_NAME)] = foreign
    keyring.values[(LEGACY, DEVICE_KEY_NAME)] = "not-a-key"
    status = service.status()
    # 机主密钥对得上照常迁移；坏掉的电脑密钥和别人的备份原样保留。
    assert status.has_owner_key
    assert keyring.values[(LEGACY, KEY_BACKUP_NAME)] == foreign
    assert keyring.values[(LEGACY, DEVICE_KEY_NAME)] == "not-a-key"
    assert gateway_keyring_store(root).get(DEVICE_KEY_NAME) is None
    assert gateway_keyring_store(root).get(OWNER_KEY_NAME) == keys[OWNER_KEY_NAME]


def test_backup_migration_retries_and_keeps_an_existing_data_dir_backup(
    tmp_path: Path, keyring: FakeKeyring
) -> None:
    root = tmp_path / "old"
    service, keys = legacy_identity(root)
    owner = key_fingerprint(PrivateKey.from_seed_text(keys[OWNER_KEY_NAME]).public_key)
    device = PrivateKey.from_seed_text(keys[DEVICE_KEY_NAME]).public_key
    current = IdentityState(owner_fingerprint=owner, device_public_key=device)
    backup = KeyBackup(
        created_at=datetime.now(UTC),
        before=IdentityState(owner_fingerprint="0" * 64),
        after=current,
        keys={},
    )
    keyring.values[(LEGACY, KEY_BACKUP_NAME)] = backup.model_dump_json()
    keyring.fail_set.add(KEY_BACKUP_NAME)
    with pytest.raises(SecretStoreError, match="身份密钥备份"):
        service.status()
    assert (LEGACY, KEY_BACKUP_NAME) in keyring.values
    keyring.fail_set.clear()
    # 这个数据目录已经有一份备份时不覆盖它，只删掉多余的旧条目。
    own = backup.model_copy(update={"created_at": datetime(2026, 1, 1, tzinfo=UTC)})
    gateway_keyring_store(root).set(KEY_BACKUP_NAME, own.model_dump_json())
    assert service.status().has_owner_key
    assert (LEGACY, KEY_BACKUP_NAME) not in keyring.values


def test_removed_device_without_a_certificate_only_adopts_the_owner_key(
    tmp_path: Path, keyring: FakeKeyring, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "old"
    service, keys = legacy_identity(root)

    def without_certificate(store: TrustStore) -> IdentityState:
        return IdentityState(owner_fingerprint=store.owner_fingerprint())

    monkeypatch.setattr("tunnelminion.trust.backup.identity_state", without_certificate)
    service.status()
    assert gateway_keyring_store(root).get(OWNER_KEY_NAME) == keys[OWNER_KEY_NAME]
    assert keyring.values[(LEGACY, DEVICE_KEY_NAME)] == keys[DEVICE_KEY_NAME]


def test_already_copied_key_only_removes_the_legacy_entry(
    tmp_path: Path, keyring: FakeKeyring
) -> None:
    """上次写好新条目后没来得及删旧条目：这次只删旧条目。"""
    root = tmp_path / "old"
    service, keys = legacy_identity(root)
    gateway_keyring_store(root).set(OWNER_KEY_NAME, keys[OWNER_KEY_NAME])
    assert service.status().has_owner_key
    assert all((LEGACY, name) not in keyring.values for name in keys)
