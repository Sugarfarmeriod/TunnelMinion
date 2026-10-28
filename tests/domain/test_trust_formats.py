"""机主身份公共数据格式：签名字节、用途隔离、名单校验、通行证约束与加入码。"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

from tunnelminion.domain.identifiers import NodeId
from tunnelminion.domain.trust import (
    DeviceEntry,
    InvalidJoinCodeError,
    JoinCode,
    JoinCodeKind,
    OwnerRoster,
    OwnerRotation,
    PassScope,
    RequestPassClaims,
    SignaturePurpose,
    SignedEnvelope,
    TrustedPerson,
    TrustList,
    canonical_json,
    decode_public_key,
    decode_signature,
    encode_public_key,
    encode_signature,
    key_fingerprint,
    signing_bytes,
)

NOW = datetime(2026, 10, 28, tzinfo=UTC)


def public_text(key: Ed25519PrivateKey) -> str:
    raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return encode_public_key(raw)


def device(node: NodeId, key: Ed25519PrivateKey) -> DeviceEntry:
    return DeviceEntry(
        node_id=node,
        display_name="电脑",
        device_public_key=public_text(key),
        host="10.0.0.2",
        port=8787,
        added_at=NOW,
    )


def roster(owner: Ed25519PrivateKey, recovery: Ed25519PrivateKey, version: int = 1) -> OwnerRoster:
    return OwnerRoster(
        owner_public_key=public_text(owner),
        recovery_fingerprint=key_fingerprint(public_text(recovery)),
        version=version,
        issued_at=NOW,
        devices=(device(NodeId.new(), Ed25519PrivateKey.generate()),),
    )


def seal(purpose: SignaturePurpose, payload: OwnerRoster, key: Ed25519PrivateKey) -> SignedEnvelope:
    data = payload.signed_payload()
    return SignedEnvelope(
        purpose=purpose,
        signer_fingerprint=key_fingerprint(public_text(key)),
        payload=data,
        signature=encode_signature(key.sign(signing_bytes(purpose, data))),
    )


def test_canonical_json_is_order_independent() -> None:
    assert canonical_json({"b": 1, "a": "机"}) == canonical_json({"a": "机", "b": 1})
    assert canonical_json({"a": 1}) == b'{"a":1}'


def test_envelope_round_trip_verifies_and_parses() -> None:
    owner, recovery = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    original = roster(owner, recovery)
    envelope = SignedEnvelope.model_validate_json(
        seal(SignaturePurpose.OWNER_ROSTER, original, owner).model_dump_json()
    )

    owner.public_key().verify(decode_signature(envelope.signature), envelope.signing_bytes())
    assert envelope.parse(OwnerRoster, SignaturePurpose.OWNER_ROSTER) == original
    assert envelope.signer_fingerprint == original.owner_fingerprint


def test_signature_does_not_transfer_between_purposes() -> None:
    owner, recovery = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    envelope = seal(SignaturePurpose.OWNER_ROSTER, roster(owner, recovery), owner)
    moved = envelope.model_copy(update={"purpose": SignaturePurpose.TRUST_LIST})

    with pytest.raises(Exception):  # noqa: B017 - cryptography 抛 InvalidSignature
        owner.public_key().verify(decode_signature(moved.signature), moved.signing_bytes())
    with pytest.raises(ValueError, match="用途不符"):
        envelope.parse(OwnerRoster, SignaturePurpose.TRUST_LIST)


def test_unknown_payload_fields_are_signed_and_ignored() -> None:
    owner, recovery = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    data = {**roster(owner, recovery).signed_payload(), "future_field": "x"}
    sig = owner.sign(signing_bytes(SignaturePurpose.OWNER_ROSTER, data))
    envelope = SignedEnvelope(
        purpose=SignaturePurpose.OWNER_ROSTER,
        signer_fingerprint=key_fingerprint(public_text(owner)),
        payload=data,
        signature=encode_signature(sig),
    )

    owner.public_key().verify(decode_signature(envelope.signature), envelope.signing_bytes())
    assert envelope.parse(OwnerRoster, SignaturePurpose.OWNER_ROSTER).version == 1


def test_roster_rejects_duplicate_devices() -> None:
    owner, recovery = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    entry = device(NodeId.new(), Ed25519PrivateKey.generate())
    base = roster(owner, recovery)
    with pytest.raises(ValidationError, match="节点 ID 不得重复"):
        OwnerRoster.model_validate(
            {**base.signed_payload(), "devices": [entry.model_dump(mode="json")] * 2}
        )


def test_trust_list_rejects_self_and_duplicates() -> None:
    me, friend = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    person = TrustedPerson(
        owner_public_key=public_text(friend),
        recovery_fingerprint=key_fingerprint(public_text(Ed25519PrivateKey.generate())),
        display_name="朋友",
        added_at=NOW,
    )
    assert person.permissions.allow_delegation is True
    assert person.permissions.allow_model_borrowing is False
    mine = key_fingerprint(public_text(me))
    assert TrustList(owner_fingerprint=mine, version=1, issued_at=NOW, people=(person,)).people
    with pytest.raises(ValidationError, match="两次"):
        TrustList(owner_fingerprint=mine, version=1, issued_at=NOW, people=(person, person))
    with pytest.raises(ValidationError, match="机主自己"):
        TrustList(
            owner_fingerprint=person.owner_fingerprint, version=1, issued_at=NOW, people=(person,)
        )


def test_rotation_requires_new_keys() -> None:
    old, recovery = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    with pytest.raises(ValidationError, match="新机主密钥"):
        OwnerRotation(
            previous_owner_fingerprint=key_fingerprint(public_text(old)),
            recovery_public_key=public_text(recovery),
            new_owner_public_key=public_text(old),
            new_recovery_fingerprint=key_fingerprint(public_text(Ed25519PrivateKey.generate())),
            issued_at=NOW,
        )


def pass_claims(**changes: object) -> dict[str, object]:
    base: dict[str, object] = {
        "iss": str(NodeId.new()),
        "aud": str(NodeId.new()),
        "scope": PassScope.TOOL_GATEWAY,
        "iat": 1000,
        "exp": 1060,
        "jti": "0" * 32,
        "owner_fingerprint": "sha256:" + "a" * 64,
        "roster_version": 3,
    }
    return {**base, **changes}


def test_request_pass_bounds() -> None:
    assert RequestPassClaims.model_validate(pass_claims()).purpose is SignaturePurpose.REQUEST_PASS
    for changes, message in (
        ({"exp": 1061}, "有效期"),
        ({"exp": 1000}, "有效期"),
        ({"jti": "short"}, "编号"),
        ({"purpose": SignaturePurpose.OWNER_ROSTER}, "用途不符"),
    ):
        with pytest.raises(ValidationError, match=message):
            RequestPassClaims.model_validate(pass_claims(**changes))
    node = str(NodeId.new())
    with pytest.raises(ValidationError, match="自己"):
        RequestPassClaims.model_validate(pass_claims(iss=node, aud=node))


def test_join_code_round_trip_and_kind_check() -> None:
    code = JoinCode(
        kind=JoinCodeKind.OWNER,
        inviter_node_id=NodeId.new(),
        owner_fingerprint="sha256:" + "b" * 64,
        host="10.0.0.1",
        port=8787,
        token="t" * 40,
        expires_at=NOW,
    )
    text = code.encode()
    assert text.startswith("tmo1_")
    assert JoinCode.decode(f"  {text}\n", JoinCodeKind.OWNER) == code
    with pytest.raises(InvalidJoinCodeError):
        JoinCode.decode(text, JoinCodeKind.FRIEND)
    with pytest.raises(InvalidJoinCodeError):
        JoinCode.decode("tmo1_!!!", JoinCodeKind.OWNER)
    assert "t" * 40 not in repr(code)


def test_key_and_signature_text_validation() -> None:
    with pytest.raises(ValueError, match="32 字节"):
        encode_public_key(b"x")
    with pytest.raises(ValueError, match="64 字节"):
        encode_signature(b"x")
    with pytest.raises(ValueError, match="32 字节"):
        decode_public_key("AAAA")
    with pytest.raises(ValueError, match="base64url"):
        decode_public_key("A")
    with pytest.raises(ValueError, match="64 字节"):
        decode_signature("AAAA")
    with pytest.raises(ValidationError, match="指纹"):
        TrustList(owner_fingerprint="sha256:XYZ", version=1, issued_at=NOW)


def test_roster_rejects_shared_device_key_and_finds_devices() -> None:
    owner, recovery, shared = (Ed25519PrivateKey.generate() for _ in range(3))
    first, second = device(NodeId.new(), shared), device(NodeId.new(), shared)
    base = roster(owner, recovery)
    with pytest.raises(ValidationError, match="公钥不得重复"):
        OwnerRoster.model_validate(
            {
                **base.signed_payload(),
                "devices": [first.model_dump(mode="json"), second.model_dump(mode="json")],
            }
        )
    known = base.devices[0]
    assert base.device(known.node_id) == known
    assert base.device(NodeId.new()) is None


def test_rotation_requires_new_recovery_key_and_accepts_valid() -> None:
    old, recovery, new = (Ed25519PrivateKey.generate() for _ in range(3))
    common = {
        "previous_owner_fingerprint": key_fingerprint(public_text(old)),
        "recovery_public_key": public_text(recovery),
        "new_owner_public_key": public_text(new),
        "issued_at": NOW,
    }
    with pytest.raises(ValidationError, match="新恢复密钥"):
        OwnerRotation.model_validate(
            {**common, "new_recovery_fingerprint": key_fingerprint(public_text(recovery))}
        )
    rotation = OwnerRotation.model_validate(
        {
            **common,
            "new_recovery_fingerprint": key_fingerprint(public_text(Ed25519PrivateKey.generate())),
        }
    )
    assert rotation.new_owner_public_key == public_text(new)


def test_join_code_rejects_mismatched_kind_inside_prefix() -> None:
    code = JoinCode(
        kind=JoinCodeKind.FRIEND,
        inviter_node_id=NodeId.new(),
        owner_fingerprint="sha256:" + "c" * 64,
        host="10.0.0.1",
        port=8787,
        token="t" * 40,
        expires_at=NOW,
    )
    forged = "tmo1_" + code.encode().removeprefix("tmf1_")
    with pytest.raises(InvalidJoinCodeError, match="对应"):
        JoinCode.decode(forged, JoinCodeKind.OWNER)
