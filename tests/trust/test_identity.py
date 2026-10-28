"""身份底座的签名边界、恢复码、存储原子性与秘密隔离。"""

from __future__ import annotations

import base64
import sqlite3
import traceback
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path
from threading import Barrier

import pytest
from pydantic import JsonValue

from tunnelminion.domain.identifiers import NodeId
from tunnelminion.domain.trust import (
    SignaturePurpose,
    TrustedPerson,
    TrustList,
    key_fingerprint,
)
from tunnelminion.gateway.security import GatewayBindConfig
from tunnelminion.memory.sqlite import SQLiteStores
from tunnelminion.model.secrets import SecretStoreError
from tunnelminion.trust.contracts import (
    AlreadyInitializedError,
    IdentityError,
    IdentityStatus,
    VersionRejectedError,
)
from tunnelminion.trust.keys import (
    DEVICE_KEY_NAME,
    OWNER_KEY_NAME,
    InitializationKeys,
    PrivateKey,
    RecoveryCodeError,
    delete_private_key,
    load_private_key,
    parse_recovery_code,
    save_private_key,
)
from tunnelminion.trust.service import OwnerIdentityService
from tunnelminion.trust.signatures import (
    VerificationError,
    seal,
    verify,
    verify_device_certificate,
    verify_owner_roster,
    verify_trust_list,
)

NOW = datetime(2026, 10, 28, tzinfo=UTC)
BIND = GatewayBindConfig(host="10.0.0.1")


class MemorySecrets:
    """仅在测试内存中读写，不访问系统钥匙串。"""

    def __init__(self) -> None:
        self.values: dict[str, str] = {}

    def get(self, name: str) -> str | None:
        return self.values.get(name)

    def set(self, name: str, value: str) -> None:
        self.values[name] = value

    def delete(self, name: str) -> None:
        self.values.pop(name, None)


def initialized(
    path: Path,
) -> tuple[OwnerIdentityService, MemorySecrets, InitializationKeys, IdentityStatus]:
    secrets = MemorySecrets()
    keys = InitializationKeys.generate()
    service = OwnerIdentityService(SQLiteStores.open(path).trust, secrets)
    status = service.init(NodeId.new(), BIND, "测试电脑", keys)
    return service, secrets, keys, status


def test_keys_round_trip_and_hide_secrets() -> None:
    secrets = MemorySecrets()
    key = PrivateKey.generate()
    assert load_private_key(secrets, OWNER_KEY_NAME) is None
    save_private_key(secrets, OWNER_KEY_NAME, key)
    text = secrets.values[OWNER_KEY_NAME]
    assert len(base64.urlsafe_b64decode(text + "=")) == 32
    loaded = load_private_key(secrets, OWNER_KEY_NAME)
    assert loaded is not None and loaded.public_key == key.public_key
    assert loaded.sign(b"test") == key.sign(b"test")
    assert text not in repr(key) and "Ed25519PrivateKey" not in repr(key)
    delete_private_key(secrets, OWNER_KEY_NAME)
    assert secrets.values == {}


@pytest.mark.parametrize("value", ["非 base64 秘密", "!" * 43, "AA", ""])
def test_invalid_stored_keys_never_appear_in_errors(value: str) -> None:
    secrets = MemorySecrets()
    secrets.values[OWNER_KEY_NAME] = value
    with pytest.raises(SecretStoreError, match="无法读取本机身份密钥") as caught:
        load_private_key(secrets, OWNER_KEY_NAME)
    if value:
        assert value not in "".join(traceback.format_exception(caught.value))


@pytest.mark.parametrize("operation", ["get", "set", "delete"])
def test_secret_backend_errors_hide_the_original_exception(
    operation: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    secrets = MemorySecrets()
    key = PrivateKey.generate()
    code = key.recovery_code()

    def fail(*args: object) -> None:
        raise RuntimeError(f"{key.seed_text()} {code} {args}")

    monkeypatch.setattr(secrets, operation, fail)
    with pytest.raises(SecretStoreError) as caught:
        if operation == "get":
            load_private_key(secrets, OWNER_KEY_NAME)
        elif operation == "set":
            save_private_key(secrets, OWNER_KEY_NAME, key)
        else:
            delete_private_key(secrets, OWNER_KEY_NAME)
    text = "".join(traceback.format_exception(caught.value))
    assert key.seed_text() not in text and code not in text


def test_recovery_code_round_trip_and_typing_tolerance() -> None:
    keys = InitializationKeys.generate()
    recovered = parse_recovery_code(keys.recovery_code)
    assert key_fingerprint(recovered.public_key) == keys.recovery_fingerprint
    for text in (
        keys.recovery_code.lower(),
        " \n" + keys.recovery_code.replace("-", " \t") + "\n",
        keys.recovery_code.replace("-", ""),
    ):
        assert parse_recovery_code(text).seed_text() == recovered.seed_text()
    zero = MemorySecrets()
    zero.set(OWNER_KEY_NAME, base64.urlsafe_b64encode(bytes(32)).decode())
    key = load_private_key(zero, OWNER_KEY_NAME)
    assert key is not None
    assert parse_recovery_code(key.recovery_code().replace("0", "o")).public_key == key.public_key
    assert keys.recovery_code not in repr(keys)
    assert keys.owner.seed_text() not in repr(keys) and keys.device.seed_text() not in repr(keys)


@pytest.mark.parametrize("kind", ["short", "character", "checksum", "overflow"])
def test_recovery_code_rejects_damage_without_echoing_it(kind: str) -> None:
    code = PrivateKey.generate().recovery_code().replace("-", "")
    damaged = {
        "short": code[:-1],
        "character": "!" + code[1:],
        "checksum": code[:-1] + ("0" if code[-1] != "0" else "1"),
        "overflow": "Z" + code[1:],
    }[kind]
    with pytest.raises(RecoveryCodeError, match="恢复码无效或校验失败") as caught:
        parse_recovery_code(damaged)
    assert damaged not in "".join(traceback.format_exception(caught.value))


def test_signature_preserves_and_verifies_unknown_fields(tmp_path: Path) -> None:
    _, _, keys, status = initialized(tmp_path / "runtime.sqlite3")
    store = SQLiteStores.open(tmp_path / "runtime.sqlite3").trust
    original = store.load(SignaturePurpose.OWNER_ROSTER)
    assert original is not None and status.owner_fingerprint is not None
    data: dict[str, JsonValue] = {**original.payload, "future": {"字段": [1, True]}}
    signed = seal(SignaturePurpose.OWNER_ROSTER, data, keys.owner)
    verified = verify_owner_roster(signed, status.owner_fingerprint)
    assert verified.version == 1
    assert "future" not in verified.signed_payload()
    modified = signed.model_copy(update={"payload": {**data, "future": "篡改"}})
    with pytest.raises(VerificationError, match=r"^身份签名验证失败$"):
        verify_owner_roster(modified, status.owner_fingerprint)


@pytest.mark.parametrize(
    "kind",
    ["purpose", "signer", "signature", "payload", "public_key", "fingerprint", "missing_key"],
)
def test_roster_rejects_invalid_signatures_and_owner(tmp_path: Path, kind: str) -> None:
    path = tmp_path / "runtime.sqlite3"
    _, _, keys, status = initialized(path)
    envelope = SQLiteStores.open(path).trust.load(SignaturePurpose.OWNER_ROSTER)
    assert envelope is not None and status.owner_fingerprint is not None
    other = PrivateKey.generate()
    fingerprint = status.owner_fingerprint
    if kind == "purpose":
        envelope = envelope.model_copy(update={"purpose": SignaturePurpose.TRUST_LIST})
    elif kind == "signer":
        envelope = envelope.model_copy(
            update={"signer_fingerprint": key_fingerprint(other.public_key)}
        )
    elif kind == "signature":
        envelope = seal(SignaturePurpose.OWNER_ROSTER, envelope.payload, other).model_copy(
            update={"signer_fingerprint": fingerprint}
        )
    elif kind == "payload":
        envelope = seal(
            SignaturePurpose.OWNER_ROSTER, {"owner_public_key": keys.owner.public_key}, keys.owner
        )
    elif kind == "public_key":
        envelope = envelope.model_copy(update={"payload": {"owner_public_key": "invalid"}})
    elif kind == "fingerprint":
        fingerprint = key_fingerprint(other.public_key)
    else:
        envelope = envelope.model_copy(update={"payload": {}})
    with pytest.raises(VerificationError, match=r"^身份签名验证失败$"):
        verify_owner_roster(envelope, fingerprint)


@pytest.mark.parametrize("kind", [SignaturePurpose.TRUST_LIST, SignaturePurpose.DEVICE_CERTIFICATE])
@pytest.mark.parametrize("mismatch", ["signer", "pinned_owner", "payload_owner", "purpose"])
def test_certificates_and_people_lists_use_the_same_trust_anchor(
    tmp_path: Path, kind: SignaturePurpose, mismatch: str
) -> None:
    path = tmp_path / "runtime.sqlite3"
    _, _, keys, status = initialized(path)
    envelope = SQLiteStores.open(path).trust.load(kind)
    assert envelope is not None and status.owner_fingerprint is not None
    owner = status.owner_fingerprint
    other = PrivateKey.generate()
    if mismatch == "signer":
        envelope = seal(kind, envelope.payload, other)
    elif mismatch == "pinned_owner":
        owner = key_fingerprint(other.public_key)
    elif mismatch == "payload_owner":
        envelope = seal(
            kind,
            {**envelope.payload, "owner_fingerprint": key_fingerprint(other.public_key)},
            keys.owner,
        )
    else:
        envelope = envelope.model_copy(update={"purpose": SignaturePurpose.JOIN_PROOF})
    with pytest.raises(VerificationError, match=r"^身份签名验证失败$"):
        if kind is SignaturePurpose.TRUST_LIST:
            verify_trust_list(envelope, keys.owner.public_key, owner)
        else:
            verify_device_certificate(envelope, keys.owner.public_key, owner)


def test_generic_verification_hides_invalid_public_key() -> None:
    key = PrivateKey.generate()
    envelope = seal(SignaturePurpose.TRUST_LIST, {}, key)
    with pytest.raises(VerificationError, match=r"^身份签名验证失败$"):
        verify(envelope, SignaturePurpose.TRUST_LIST, "invalid", TrustList)


def test_initialization_persists_only_public_documents_and_two_private_keys(tmp_path: Path) -> None:
    path = tmp_path / "runtime.sqlite3"
    service, secrets, keys, status = initialized(path)
    store = SQLiteStores.open(path).trust
    assert service.status() == status
    assert status.owner_fingerprint == key_fingerprint(keys.owner.public_key)
    assert status.owner_fingerprint is not None
    assert status.has_owner_key and status.roster_version == status.trust_list_version == 1
    assert len(status.devices) == 1 and status.devices[0].display_name == "测试电脑"
    assert set(secrets.values) == {OWNER_KEY_NAME, DEVICE_KEY_NAME}
    assert parse_recovery_code(keys.recovery_code).seed_text() not in secrets.values.values()
    roster = store.load(SignaturePurpose.OWNER_ROSTER)
    people = store.load(SignaturePurpose.TRUST_LIST)
    certificate = store.load(SignaturePurpose.DEVICE_CERTIFICATE)
    assert roster is not None and people is not None and certificate is not None
    assert (
        verify_owner_roster(roster, status.owner_fingerprint).recovery_fingerprint
        == keys.recovery_fingerprint
    )
    assert verify_trust_list(people, keys.owner.public_key, status.owner_fingerprint).people == ()
    cert = verify_device_certificate(certificate, keys.owner.public_key, status.owner_fingerprint)
    assert cert.node_id == status.devices[0].node_id
    assert cert.device_public_key == keys.device.public_key
    assert [audit.version for audit in store.audits()] == [1, 1]
    assert store.audits()[0].subjects == (str(cert.node_id),)
    assert store.audits()[1].subjects == ()
    for audit in store.audits():
        assert audit.action == "accept" and audit.signer_fingerprint == status.owner_fingerprint
        assert audit.reason == "本机初始化" and audit.occurred_at.tzinfo is not None
    with sqlite3.connect(path) as connection:
        dump = "\n".join(connection.iterdump())
        assert connection.execute(
            "SELECT COUNT(*) FROM trust_documents WHERE version=1"
        ).fetchone() == (3,)
    files = b"".join(item.read_bytes() for item in tmp_path.iterdir() if item.is_file())
    for secret in (
        keys.owner.seed_text(),
        keys.device.seed_text(),
        keys.recovery_code,
        parse_recovery_code(keys.recovery_code).seed_text(),
    ):
        assert secret not in dump and secret not in repr(status) and secret.encode() not in files


def test_repeat_initialization_does_not_overwrite_keys_or_audit(tmp_path: Path) -> None:
    path = tmp_path / "runtime.sqlite3"
    service, secrets, _, status = initialized(path)
    saved = dict(secrets.values)
    with pytest.raises(AlreadyInitializedError):
        service.init(NodeId.new(), BIND, "另一台", InitializationKeys.generate())
    assert secrets.values == saved and service.status() == status
    assert len(SQLiteStores.open(path).trust.audits()) == 2


@pytest.mark.parametrize("name", [OWNER_KEY_NAME, DEVICE_KEY_NAME])
def test_existing_keys_block_initialization(name: str, tmp_path: Path) -> None:
    secrets = MemorySecrets()
    save_private_key(secrets, name, PrivateKey.generate())
    saved = dict(secrets.values)
    with pytest.raises(AlreadyInitializedError):
        OwnerIdentityService(
            SQLiteStores.open(tmp_path / "runtime.sqlite3").trust, secrets
        ).ensure_uninitialized()
    assert secrets.values == saved


def test_empty_and_incomplete_identity_status(tmp_path: Path) -> None:
    path = tmp_path / "runtime.sqlite3"
    store = SQLiteStores.open(path).trust
    assert OwnerIdentityService(store, MemorySecrets()).status() == IdentityStatus()
    assert store.load(SignaturePurpose.OWNER_ROSTER) is None and store.audits() == ()
    service, _, _, _ = initialized(path)
    with sqlite3.connect(path) as connection:
        connection.execute(
            "DELETE FROM trust_documents WHERE kind=?", (SignaturePurpose.TRUST_LIST.value,)
        )
    with pytest.raises(IdentityError, match="记录不完整"):
        service.status()


@pytest.mark.parametrize("missing", [False, True])
def test_status_reports_whether_the_owner_key_belongs_to_this_identity(
    tmp_path: Path, missing: bool
) -> None:
    service, secrets, _, _ = initialized(tmp_path / "runtime.sqlite3")
    if missing:
        secrets.delete(OWNER_KEY_NAME)
    else:
        save_private_key(secrets, OWNER_KEY_NAME, PrivateKey.generate())
    assert not service.status().has_owner_key


@pytest.mark.parametrize("failed_name", [OWNER_KEY_NAME, DEVICE_KEY_NAME])
def test_secret_write_failure_rolls_back_identity_and_audits(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failed_name: str
) -> None:
    secrets = MemorySecrets()
    keys = InitializationKeys.generate()
    original = secrets.set

    def fail(name: str, value: str) -> None:
        original(name, value)
        if name == failed_name:
            raise RuntimeError(value + keys.recovery_code)

    monkeypatch.setattr(secrets, "set", fail)
    store = SQLiteStores.open(tmp_path / "runtime.sqlite3").trust
    with pytest.raises(SecretStoreError) as caught:
        OwnerIdentityService(store, secrets).init(NodeId.new(), BIND, "测试电脑", keys)
    assert not secrets.values and store.owner_fingerprint() is None
    assert store.audits() == () and store.load(SignaturePurpose.OWNER_ROSTER) is None
    assert keys.recovery_code not in "".join(traceback.format_exception(caught.value))


@pytest.mark.parametrize("kind", [SignaturePurpose.OWNER_ROSTER, SignaturePurpose.TRUST_LIST])
def test_accept_versions_and_audit_removed_subjects(tmp_path: Path, kind: SignaturePurpose) -> None:
    path = tmp_path / "runtime.sqlite3"
    _, _, keys, status = initialized(path)
    store = SQLiteStores.open(path).trust
    original = store.load(kind)
    assert original is not None
    subjects: tuple[str, ...]
    new_subject: str
    if kind is SignaturePurpose.OWNER_ROSTER:
        first = verify_owner_roster(original, key_fingerprint(keys.owner.public_key))
        added = first.devices[0].model_copy(
            update={"node_id": NodeId.new(), "device_public_key": PrivateKey.generate().public_key}
        )
        second = first.model_copy(update={"version": 2, "devices": (*first.devices, added)})
        third = first.model_copy(update={"version": 3})
        subjects = tuple(sorted(str(item.node_id) for item in second.devices))
        new_subject = str(added.node_id)
    else:
        person = TrustedPerson(
            owner_public_key=PrivateKey.generate().public_key,
            recovery_fingerprint=keys.recovery_fingerprint,
            display_name="测试朋友",
            added_at=NOW,
        )
        first = TrustList.model_validate(original.payload)
        second = first.model_copy(update={"version": 2, "people": (person,)})
        third = first.model_copy(update={"version": 3})
        subjects = (person.owner_fingerprint,)
        new_subject = person.owner_fingerprint
    for payload in (second, third):
        envelope = seal(kind, payload, keys.owner)
        store.accept(envelope, "本机名单更新")
        assert store.load(kind) == envelope
    for payload in (first, second, third):
        with pytest.raises(VersionRejectedError):
            store.accept(seal(kind, payload, keys.owner), "拒绝旧版本")
    audits = store.audits()
    assert len(audits) == 4 and audits[-1].subjects == subjects
    assert [item.version for item in audits if item.kind is kind] == [1, 2, 3]
    assert all(item.reason != "拒绝旧版本" for item in audits)
    assert store.owner_fingerprint() == status.owner_fingerprint
    changed = [item for item in audits if item.kind is kind]
    assert changed[1].reason == f"本机名单更新；新增 {new_subject}"
    assert changed[2].reason == f"本机名单更新；移除 {new_subject}"
    assert "新增" not in changed[0].reason + changed[2].reason


@pytest.mark.parametrize("kind", [SignaturePurpose.OWNER_ROSTER, SignaturePurpose.TRUST_LIST])
def test_two_concurrent_writers_keep_the_larger_version(
    tmp_path: Path, kind: SignaturePurpose
) -> None:
    path = tmp_path / "runtime.sqlite3"
    _, _, keys, _ = initialized(path)
    stores = (SQLiteStores.open(path).trust, SQLiteStores.open(path).trust)
    original = stores[0].load(kind)
    assert original is not None
    barrier = Barrier(2)

    def write(version: int) -> bool:
        envelope = seal(kind, {**original.payload, "version": version}, keys.owner)
        barrier.wait(timeout=5)
        try:
            stores[version - 2].accept(envelope, "并发更新")
            return True
        except VersionRejectedError:
            return False

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(write, (2, 3)))
    assert results[1]
    final = stores[0].load(kind)
    assert final is not None and final.payload["version"] == 3
    versions = [audit.version for audit in stores[0].audits() if audit.kind is kind]
    assert versions == sorted(set(versions)) and versions[-1] == 3


def test_accept_requires_initialized_identity_and_a_supported_purpose(tmp_path: Path) -> None:
    keys = InitializationKeys.generate()
    envelope = seal(SignaturePurpose.TRUST_LIST, {}, keys.owner)
    path = tmp_path / "runtime.sqlite3"
    store = SQLiteStores.open(path).trust
    with pytest.raises(IdentityError, match="尚未初始化"):
        store.accept(envelope, "测试")
    initialized(path)
    with pytest.raises(VerificationError):
        store.accept(seal(SignaturePurpose.JOIN_PROOF, {}, keys.owner), "测试")
    with sqlite3.connect(path) as connection:
        connection.execute(
            "DELETE FROM trust_documents WHERE kind=?", (SignaturePurpose.OWNER_ROSTER.value,)
        )
    with pytest.raises(IdentityError, match="记录不完整"):
        store.accept(envelope, "测试")


def test_store_initialization_checks_certificate_and_prevents_duplicate_writes(
    tmp_path: Path,
) -> None:
    path = tmp_path / "runtime.sqlite3"
    _, _, keys, status = initialized(path)
    store = SQLiteStores.open(path).trust
    roster = store.load(SignaturePurpose.OWNER_ROSTER)
    people = store.load(SignaturePurpose.TRUST_LIST)
    certificate = store.load(SignaturePurpose.DEVICE_CERTIFICATE)
    assert roster is not None and people is not None and certificate is not None
    assert status.owner_fingerprint is not None
    for change in (
        {"node_id": str(NodeId.new())},
        {"device_public_key": PrivateKey.generate().public_key},
    ):
        invalid = seal(
            SignaturePurpose.DEVICE_CERTIFICATE, {**certificate.payload, **change}, keys.owner
        )
        with pytest.raises(VerificationError):
            store.initialize(
                status.owner_fingerprint, roster, people, invalid, lambda: pytest.fail("不得写密钥")
            )
    with pytest.raises(AlreadyInitializedError):
        store.initialize(
            status.owner_fingerprint, roster, people, certificate, lambda: pytest.fail("不得写密钥")
        )


def test_accept_restores_a_missing_list_with_valid_signature(tmp_path: Path) -> None:
    path = tmp_path / "runtime.sqlite3"
    _, _, keys, _ = initialized(path)
    store = SQLiteStores.open(path).trust
    people = store.load(SignaturePurpose.TRUST_LIST)
    assert people is not None
    with sqlite3.connect(path) as connection:
        connection.execute(
            "DELETE FROM trust_documents WHERE kind=?", (SignaturePurpose.TRUST_LIST.value,)
        )
    store.accept(
        seal(SignaturePurpose.TRUST_LIST, {**people.payload, "version": 2}, keys.owner), "补齐名单"
    )
    assert store.load(SignaturePurpose.TRUST_LIST) is not None


def test_invalid_updates_leave_documents_and_audit_untouched(tmp_path: Path) -> None:
    path = tmp_path / "runtime.sqlite3"
    _, _, _, status = initialized(path)
    store = SQLiteStores.open(path).trust
    original = store.load(SignaturePurpose.OWNER_ROSTER)
    assert original is not None
    for kind in (SignaturePurpose.OWNER_ROSTER, SignaturePurpose.TRUST_LIST):
        document = store.load(kind)
        assert document is not None
        with pytest.raises(VerificationError):
            store.accept(
                seal(kind, {**document.payload, "version": 9}, PrivateKey.generate()), "伪造"
            )
    assert store.load(SignaturePurpose.OWNER_ROSTER) == original
    assert store.owner_fingerprint() == status.owner_fingerprint
    assert len(store.audits()) == 2
