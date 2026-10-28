"""先核对签名及本机信任锚，再解析名单和证书。"""

from __future__ import annotations

from typing import TypeVar

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import BaseModel, JsonValue

from tunnelminion.domain.trust import (
    DeviceCertificate,
    OwnerRoster,
    SignaturePurpose,
    SignedEnvelope,
    TrustList,
    decode_public_key,
    decode_signature,
    encode_signature,
    key_fingerprint,
    signing_bytes,
)
from tunnelminion.trust.keys import PrivateKey

_ModelT = TypeVar("_ModelT", bound=BaseModel)


class VerificationError(ValueError):
    """所有签名、用途、信任锚和载荷验证失败使用同一错误。"""


def seal(
    purpose: SignaturePurpose, payload: BaseModel | dict[str, JsonValue], private_key: PrivateKey
) -> SignedEnvelope:
    """按用途签名，返回可跨电脑传输的信封。"""
    data = payload.model_dump(mode="json") if isinstance(payload, BaseModel) else payload
    return SignedEnvelope(
        purpose=purpose,
        signer_fingerprint=key_fingerprint(private_key.public_key),
        payload=data,
        signature=encode_signature(private_key.sign(signing_bytes(purpose, data))),
    )


def verify(
    envelope: SignedEnvelope,
    purpose: SignaturePurpose,
    public_key: str,
    model: type[_ModelT],
) -> _ModelT:
    """保留原始载荷的未知字段参与验签，成功后才按模型读取。"""
    try:
        if envelope.purpose is not purpose or envelope.signer_fingerprint != key_fingerprint(
            public_key
        ):
            raise ValueError
        Ed25519PublicKey.from_public_bytes(decode_public_key(public_key)).verify(
            decode_signature(envelope.signature), envelope.signing_bytes()
        )
        return model.model_validate(envelope.payload)
    except (ValueError, TypeError, InvalidSignature):
        raise VerificationError("身份签名验证失败") from None


def verify_owner_roster(envelope: SignedEnvelope, owner_fingerprint: str) -> OwnerRoster:
    """名单必须由名单里写明的机主公钥签名，且该公钥指纹等于本机记住的机主指纹。"""
    try:
        public_key = envelope.payload.get("owner_public_key")
        if not isinstance(public_key, str) or key_fingerprint(public_key) != owner_fingerprint:
            raise ValueError
        return verify(envelope, SignaturePurpose.OWNER_ROSTER, public_key, OwnerRoster)
    except ValueError:
        raise VerificationError("身份签名验证失败") from None


def _verify_owner_payload(
    envelope: SignedEnvelope,
    purpose: SignaturePurpose,
    public_key: str,
    owner_fingerprint: str,
    model: type[_ModelT],
) -> _ModelT:
    try:
        payload = verify(envelope, purpose, public_key, model)
        if (
            key_fingerprint(public_key) != owner_fingerprint
            or envelope.payload.get("owner_fingerprint") != owner_fingerprint
        ):
            raise ValueError
        return payload
    except ValueError:
        raise VerificationError("身份签名验证失败") from None


def verify_trust_list(
    envelope: SignedEnvelope, owner_public_key: str, owner_fingerprint: str
) -> TrustList:
    """验证"我信任的人"名单由本机机主签名。"""
    return _verify_owner_payload(
        envelope, SignaturePurpose.TRUST_LIST, owner_public_key, owner_fingerprint, TrustList
    )


def verify_device_certificate(
    envelope: SignedEnvelope, owner_public_key: str, owner_fingerprint: str
) -> DeviceCertificate:
    """验证电脑证书由本机机主签名。"""
    return _verify_owner_payload(
        envelope,
        SignaturePurpose.DEVICE_CERTIFICATE,
        owner_public_key,
        owner_fingerprint,
        DeviceCertificate,
    )
