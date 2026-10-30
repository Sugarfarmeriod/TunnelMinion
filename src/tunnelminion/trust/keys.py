"""身份密钥只经秘密存储读写，恢复密钥只交付为恢复码。"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tunnelminion.domain.trust import (
    REQUEST_PASS_ALGORITHM,
    REQUEST_PASS_TYPE,
    RequestPassClaims,
    encode_public_key,
    key_fingerprint,
)
from tunnelminion.model.secrets import (
    SecretStore,
    SecretStoreApprovalPendingError,
    SecretStoreError,
)

OWNER_KEY_NAME = "trust-owner-key"
DEVICE_KEY_NAME = "trust-device-key"
IDENTITY_KEY_NAMES = (OWNER_KEY_NAME, DEVICE_KEY_NAME)
_DIGITS = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
_CHECK_DIGITS = _DIGITS + "*~$=U"


@dataclass(frozen=True)
class PrivateKey:
    """隐藏私钥对象；日志和容器的 repr 不会展开密钥。"""

    _key: Ed25519PrivateKey = field(repr=False)

    @classmethod
    def generate(cls) -> PrivateKey:
        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def from_seed_text(cls, text: str) -> PrivateKey:
        """`seed_text` 的逆操作；格式不对时抛 ValueError。"""
        seed = base64.b64decode(text + "=" * (-len(text) % 4), altchars=b"-_", validate=True)
        return cls(Ed25519PrivateKey.from_private_bytes(seed))

    @property
    def public_key(self) -> str:
        return encode_public_key(self._key.public_key().public_bytes_raw())

    def sign(self, data: bytes) -> bytes:
        return self._key.sign(data)

    def request_pass(self, claims: RequestPassClaims) -> str:
        """直接用内存私钥签通行证，不导出种子。"""
        return jwt.encode(
            claims.model_dump(mode="json"),
            self._key,
            algorithm=REQUEST_PASS_ALGORITHM,
            headers={"typ": REQUEST_PASS_TYPE},
        )

    def seed_text(self) -> str:
        """仅供秘密存储使用的原始 32 字节种子。"""
        return base64.urlsafe_b64encode(self._key.private_bytes_raw()).decode().rstrip("=")

    def recovery_code(self) -> str:
        """Crockford Base32：52 位种子、模 37 校验位，每四位分组。"""
        value = int.from_bytes(self._key.private_bytes_raw(), "big")
        digits = "".join(_DIGITS[(value >> shift) & 31] for shift in range(255, -1, -5))
        text = digits + _CHECK_DIGITS[value % 37]
        return "-".join(text[index : index + 4] for index in range(0, len(text), 4))


def load_private_key(store: SecretStore, name: str) -> PrivateKey | None:
    """损坏的秘密和后端错误都不进入异常链。"""
    try:
        text = store.get(name)
        return PrivateKey.from_seed_text(text) if text is not None else None
    except SecretStoreApprovalPendingError:
        raise
    except Exception:
        raise SecretStoreError("无法读取本机身份密钥") from None


def save_private_key(store: SecretStore, name: str, key: PrivateKey) -> None:
    try:
        store.set(name, key.seed_text())
    except Exception:
        raise SecretStoreError("无法保存本机身份密钥") from None


def delete_private_key(store: SecretStore, name: str) -> None:
    try:
        store.delete(name)
    except Exception:
        raise SecretStoreError("无法清理未完成的本机身份密钥") from None


class RecoveryCodeError(ValueError):
    """恢复码不完整、字符无效或校验失败。"""


def parse_recovery_code(code: str) -> PrivateKey:
    """忽略大小写和分隔符，也接受 Crockford 的易混字符。"""
    text = "".join(char for char in code.upper() if char != "-" and not char.isspace())
    text = text.translate(str.maketrans("OIL", "011"))
    try:
        if len(text) != 53:
            raise ValueError
        value = 0
        for char in text[:-1]:
            value = value * 32 + _DIGITS.index(char)
        if value >= 1 << 256 or text[-1] != _CHECK_DIGITS[value % 37]:
            raise ValueError
        return PrivateKey(Ed25519PrivateKey.from_private_bytes(value.to_bytes(32, "big")))
    except ValueError:
        raise RecoveryCodeError("恢复码无效或校验失败") from None


@dataclass(frozen=True)
class InitializationKeys:
    """确认前只放在内存里的初始化材料，恢复私钥不留在对象里。"""

    owner: PrivateKey = field(repr=False)
    device: PrivateKey = field(repr=False)
    recovery_code: str = field(repr=False)
    recovery_fingerprint: str

    @classmethod
    def generate(cls) -> InitializationKeys:
        recovery = PrivateKey.generate()
        return cls(
            PrivateKey.generate(),
            PrivateKey.generate(),
            recovery.recovery_code(),
            key_fingerprint(recovery.public_key),
        )
