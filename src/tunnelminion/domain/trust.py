"""机主身份的公共数据格式：密钥指纹、签名信封、证书、两份名单、换密钥声明、通行证和加入码。

这里只定义格式与签名字节的拼法，不做签名、不碰钥匙串和数据库。所有跨电脑传输、需要签名的
内容都放在 `SignedEnvelope` 里：签名覆盖"固定前缀 + 用途 + 规范化 JSON"，用途不同的签名不能
互相冒用。验签时用收到的原始 `payload` 字典重算签名字节，再按模型解析；模型忽略不认识的字段，
所以新版本加字段后旧版本仍能验签和读取。
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from collections.abc import Mapping
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Annotated, Self, TypeVar

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    JsonValue,
    ValidationError,
    model_validator,
)

from tunnelminion.domain.identifiers import NodeId
from tunnelminion.domain.invites import DisplayName
from tunnelminion.domain.model_borrowing import DEFAULT_DAILY_TOKEN_QUOTA
from tunnelminion.domain.tools import Platform

# 签名字节的固定前缀，避免 TunnelMinion 的签名被其他程序的格式误认。
SIGNATURE_DOMAIN = b"tunnelminion-trust-v1\x00"
# Ed25519 公钥的原始字节长度。
ED25519_PUBLIC_KEY_BYTES = 32
# Ed25519 签名的原始字节长度。
ED25519_SIGNATURE_BYTES = 64
# 通行证的最长有效期。
REQUEST_PASS_MAX_LIFETIME = timedelta(seconds=60)
# 验证通行证签发时间时容许的时钟误差。
REQUEST_PASS_CLOCK_LEEWAY = timedelta(seconds=5)
# 通行证 JWT 头里的 typ，用来和其他 JWT 区分。
REQUEST_PASS_TYPE = "tm-pass+jwt"
# 通行证使用的签名算法。
REQUEST_PASS_ALGORITHM = "EdDSA"
# 加入"我的电脑"的加入码前缀。
OWNER_JOIN_CODE_PREFIX = "tmo1_"
# 朋友按人配对的配对码前缀。
FRIEND_JOIN_CODE_PREFIX = "tmf1_"
# 加入码与配对码的有效期，与邀请码一致。
JOIN_CODE_LIFETIME = timedelta(hours=24)

_FINGERPRINT = re.compile(r"^sha256:[0-9a-f]{64}$")
_PASS_ID = re.compile(r"^[0-9a-f]{32}$")


class SignaturePurpose(StrEnum):
    """签名用途；验签时必须与预期用途一致。"""

    # 机主密钥签：某台电脑属于这个机主。
    DEVICE_CERTIFICATE = "tm-device-cert"
    # 机主密钥签："我的电脑"名单。
    OWNER_ROSTER = "tm-roster"
    # 机主密钥签："我信任的人"名单。
    TRUST_LIST = "tm-trust-list"
    # 恢复密钥签：换成新的机主密钥。
    OWNER_ROTATION = "tm-owner-rotate"
    # 电脑密钥签：加入时证明私钥在自己手里。
    JOIN_PROOF = "tm-join-proof"
    # 电脑密钥签：发给另一台电脑的短期通行证。
    REQUEST_PASS = "tm-request"


class PassScope(StrEnum):
    """通行证只对一种接口有效。"""

    TOOL_GATEWAY = "tool-gateway"
    OPERATION_GATEWAY = "operation-gateway"
    TRUST_SYNC = "trust-sync"


def _b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def _b64url_decode(value: str) -> bytes:
    try:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (binascii.Error, ValueError) as exc:
        raise ValueError("不是有效的 base64url 文本") from exc


def _validate_public_key(value: str) -> str:
    if len(_b64url_decode(value)) != ED25519_PUBLIC_KEY_BYTES:
        raise ValueError("Ed25519 公钥必须是 32 字节")
    return value


def _validate_signature(value: str) -> str:
    if len(_b64url_decode(value)) != ED25519_SIGNATURE_BYTES:
        raise ValueError("Ed25519 签名必须是 64 字节")
    return value


def _validate_fingerprint(value: str) -> str:
    if not _FINGERPRINT.fullmatch(value):
        raise ValueError("密钥指纹必须符合 sha256:<64 位小写十六进制字符>")
    return value


# 原始 32 字节 Ed25519 公钥的 base64url 文本（无填充）。
PublicKeyText = Annotated[
    str, Field(min_length=43, max_length=44), AfterValidator(_validate_public_key)
]
# 原始 64 字节 Ed25519 签名的 base64url 文本（无填充）。
SignatureText = Annotated[
    str, Field(min_length=86, max_length=88), AfterValidator(_validate_signature)
]
# 公钥指纹：sha256: 加上原始公钥字节的 SHA-256 十六进制。
Fingerprint = Annotated[str, AfterValidator(_validate_fingerprint)]


def encode_public_key(raw: bytes) -> str:
    """把原始公钥字节编码成格式里使用的文本。"""
    if len(raw) != ED25519_PUBLIC_KEY_BYTES:
        raise ValueError("Ed25519 公钥必须是 32 字节")
    return _b64url_encode(raw)


def decode_public_key(value: str) -> bytes:
    """把格式里的公钥文本还原成原始字节。"""
    return _b64url_decode(_validate_public_key(value))


def encode_signature(raw: bytes) -> str:
    """把原始签名字节编码成格式里使用的文本。"""
    if len(raw) != ED25519_SIGNATURE_BYTES:
        raise ValueError("Ed25519 签名必须是 64 字节")
    return _b64url_encode(raw)


def decode_signature(value: str) -> bytes:
    """把格式里的签名文本还原成原始字节。"""
    return _b64url_decode(_validate_signature(value))


def key_fingerprint(public_key: str) -> str:
    """计算公钥指纹；只依赖原始公钥字节。"""
    return "sha256:" + hashlib.sha256(decode_public_key(public_key)).hexdigest()


def canonical_json(payload: Mapping[str, JsonValue]) -> bytes:
    """规范化 JSON：键排序、无多余空白、UTF-8；同一内容在任何电脑上得到同样的字节。"""
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode()


def signing_bytes(purpose: SignaturePurpose, payload: Mapping[str, JsonValue]) -> bytes:
    """签名覆盖的全部字节：固定前缀、用途、规范化 JSON。"""
    return SIGNATURE_DOMAIN + purpose.value.encode() + b"\x00" + canonical_json(payload)


class _Payload(BaseModel):
    """被签名的内容；忽略不认识的字段，给新版本留出加字段的余地。"""

    model_config = ConfigDict(extra="ignore", frozen=True)

    def signed_payload(self) -> dict[str, JsonValue]:
        """签名时使用的字典；只含 JSON 原生类型。"""
        return self.model_dump(mode="json")


_PayloadT = TypeVar("_PayloadT", bound=_Payload)


class SignedEnvelope(BaseModel):
    """跨电脑传输的签名信封。

    `payload` 保留收到时的原始字典，验签用它重算签名字节，再由 `parse` 解析成具体模型。
    """

    model_config = ConfigDict(extra="ignore", frozen=True)

    purpose: SignaturePurpose
    signer_fingerprint: Fingerprint
    payload: dict[str, JsonValue]
    signature: SignatureText

    def signing_bytes(self) -> bytes:
        """重算这份信封应当被签名的字节。"""
        return signing_bytes(self.purpose, self.payload)

    def parse(self, model: type[_PayloadT], purpose: SignaturePurpose) -> _PayloadT:
        """按预期用途解析内容；用途不符直接拒绝。验签由调用方先完成。"""
        if self.purpose is not purpose:
            raise ValueError("签名用途不符")
        return model.model_validate(self.payload)


class DeviceEntry(BaseModel):
    """名单里的一台电脑。"""

    model_config = ConfigDict(extra="ignore", frozen=True)

    node_id: NodeId
    display_name: DisplayName
    platform: Platform | None = None
    device_public_key: PublicKeyText
    host: str
    port: int = Field(ge=1024, le=65535)
    added_at: datetime


class DeviceCertificate(_Payload):
    """机主密钥签发的电脑证书，用途 `tm-device-cert`。"""

    owner_fingerprint: Fingerprint
    node_id: NodeId
    device_public_key: PublicKeyText
    issued_at: datetime


class OwnerRoster(_Payload):
    """ "我的电脑"名单，用途 `tm-roster`，由机主密钥签名。

    `owner_public_key` 是当前机主公钥，`recovery_fingerprint` 是恢复密钥的指纹；
    版本号每次加电脑、删电脑或换机主密钥都加一，只接受比本机更大的版本。
    """

    owner_public_key: PublicKeyText
    recovery_fingerprint: Fingerprint
    version: int = Field(ge=1)
    issued_at: datetime
    devices: tuple[DeviceEntry, ...] = Field(min_length=1)

    @property
    def owner_fingerprint(self) -> str:
        """当前机主公钥的指纹。"""
        return key_fingerprint(self.owner_public_key)

    @model_validator(mode="after")
    def _unique_devices(self) -> Self:
        if len({str(item.node_id) for item in self.devices}) != len(self.devices):
            raise ValueError("名单里的节点 ID 不得重复")
        if len({item.device_public_key for item in self.devices}) != len(self.devices):
            raise ValueError("名单里的电脑公钥不得重复")
        return self

    def device(self, node_id: NodeId) -> DeviceEntry | None:
        """按节点 ID 找名单里的电脑。"""
        return next((item for item in self.devices if item.node_id == node_id), None)


class FriendPermissions(BaseModel):
    """机主给某个朋友的默认权限；每台电脑只能在本机进一步收紧。"""

    model_config = ConfigDict(extra="ignore", frozen=True)

    allow_delegation: bool = True
    allow_model_borrowing: bool = False
    daily_quota: int = Field(default=DEFAULT_DAILY_TOKEN_QUOTA, ge=1, le=100_000_000)


class TrustedPerson(BaseModel):
    """ "我信任的人"名单里的一个朋友，以他的机主公钥为准。"""

    model_config = ConfigDict(extra="ignore", frozen=True)

    owner_public_key: PublicKeyText
    recovery_fingerprint: Fingerprint
    display_name: DisplayName
    added_at: datetime
    permissions: FriendPermissions = Field(default_factory=FriendPermissions)

    @property
    def owner_fingerprint(self) -> str:
        """这个朋友的机主公钥指纹。"""
        return key_fingerprint(self.owner_public_key)


class TrustList(_Payload):
    """ "我信任的人"名单，用途 `tm-trust-list`，由机主密钥签名，版本规则同 `OwnerRoster`。"""

    owner_fingerprint: Fingerprint
    version: int = Field(ge=1)
    issued_at: datetime
    people: tuple[TrustedPerson, ...] = ()

    @model_validator(mode="after")
    def _unique_people(self) -> Self:
        prints = [item.owner_fingerprint for item in self.people]
        if len(set(prints)) != len(prints):
            raise ValueError("同一个朋友不得出现两次")
        if self.owner_fingerprint in prints:
            raise ValueError("名单里不能包含机主自己")
        return self


class OwnerRotation(_Payload):
    """换机主密钥声明，用途 `tm-owner-rotate`，由恢复密钥签名。

    验证方核对 `recovery_public_key` 的指纹等于旧名单里的 `recovery_fingerprint`。
    换密钥时同时换一把新的恢复密钥，旧恢复码随之作废。
    """

    previous_owner_fingerprint: Fingerprint
    recovery_public_key: PublicKeyText
    new_owner_public_key: PublicKeyText
    new_recovery_fingerprint: Fingerprint
    issued_at: datetime

    @model_validator(mode="after")
    def _keys_change(self) -> Self:
        if key_fingerprint(self.new_owner_public_key) == self.previous_owner_fingerprint:
            raise ValueError("新机主密钥必须和旧的不同")
        if key_fingerprint(self.recovery_public_key) == self.new_recovery_fingerprint:
            raise ValueError("新恢复密钥必须和旧的不同")
        return self


class JoinProof(_Payload):
    """加入方用新生成的电脑密钥签的应答，用途 `tm-join-proof`。

    `token_digest` 是加入码令牌的 SHA-256 十六进制，把这份应答绑在这一次加入上。
    """

    token_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    inviter_node_id: NodeId
    node_id: NodeId
    device_public_key: PublicKeyText
    issued_at: datetime


class RequestPassClaims(BaseModel):
    """通行证（EdDSA JWT）的声明，由请求方的电脑密钥签名。

    JWT 头为 `{"alg": "EdDSA", "typ": "tm-pass+jwt"}`，通过 `Authorization: Bearer <JWT>` 发送。
    `aud` 是接收方的节点 ID，`scope` 是接口类别；有效期不超过 60 秒，`jti` 在有效期内只能用一次。
    `owner_fingerprint` 与 `roster_version` 只用于提示接收方"我手上的名单可能更新"，接收方
    判断身份只看本机名单，不采信这两个字段。
    """

    model_config = ConfigDict(extra="ignore", frozen=True)

    iss: NodeId
    aud: NodeId
    purpose: SignaturePurpose = SignaturePurpose.REQUEST_PASS
    scope: PassScope
    iat: int = Field(ge=0)
    exp: int = Field(ge=0)
    jti: str
    owner_fingerprint: Fingerprint
    roster_version: int = Field(ge=1)

    @model_validator(mode="after")
    def _bounded(self) -> Self:
        if self.purpose is not SignaturePurpose.REQUEST_PASS:
            raise ValueError("通行证用途不符")
        if not _PASS_ID.fullmatch(self.jti):
            raise ValueError("通行证编号必须是 32 位小写十六进制字符")
        if self.iss == self.aud:
            raise ValueError("通行证不能发给自己")
        lifetime = self.exp - self.iat
        if lifetime <= 0 or lifetime > REQUEST_PASS_MAX_LIFETIME.total_seconds():
            raise ValueError("通行证有效期必须在 1 到 60 秒之间")
        return self


class InvalidJoinCodeError(ValueError):
    """粘贴的内容不是有效的加入码或配对码。"""


class JoinCodeKind(StrEnum):
    """加入码的种类：加入"我的电脑"，或者和朋友按人配对。"""

    OWNER = "owner"
    FRIEND = "friend"


_JOIN_PREFIX = {
    JoinCodeKind.OWNER: OWNER_JOIN_CODE_PREFIX,
    JoinCodeKind.FRIEND: FRIEND_JOIN_CODE_PREFIX,
}


class JoinCode(BaseModel):
    """加入码或配对码里的全部内容。

    令牌只能用一次，签发方只保存它的摘要；`owner_fingerprint` 让加入方确认对方是对的机主。
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: JoinCodeKind
    inviter_node_id: NodeId
    owner_fingerprint: Fingerprint
    host: str
    port: int = Field(ge=1024, le=65535)
    token: str = Field(min_length=36, max_length=512, repr=False)
    expires_at: datetime

    def encode(self) -> str:
        """编码成可以复制粘贴的一行文字。"""
        raw = self.model_dump_json().encode()
        return _JOIN_PREFIX[self.kind] + _b64url_encode(raw)

    @classmethod
    def decode(cls, value: str, kind: JoinCodeKind) -> JoinCode:
        """按预期种类解析；前缀不符、内容损坏或种类不一致都拒绝。"""
        text = value.strip()
        prefix = _JOIN_PREFIX[kind]
        if not text.startswith(prefix):
            raise InvalidJoinCodeError("这不是对应的 TunnelMinion 加入码")
        try:
            code = cls.model_validate_json(_b64url_decode(text.removeprefix(prefix)))
        except (ValueError, ValidationError) as exc:
            raise InvalidJoinCodeError("加入码不完整或已损坏") from exc
        if code.kind is not kind:
            raise InvalidJoinCodeError("这不是对应的 TunnelMinion 加入码")
        return code
