"""Coordinator 的 Ed25519 签名身份、短期 assertion 与离线验签。"""

from __future__ import annotations

import base64
import hashlib
import secrets
from collections.abc import Callable, Collection
from datetime import UTC, datetime, timedelta
from typing import cast

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from tunnelminion.coordinator.contracts import (
    ASSERTION_ALGORITHM,
    ASSERTION_AUDIENCES,
    ASSERTION_TTL_SECONDS,
    COORDINATOR_PROTOCOL,
    AccessAssertionRequest,
    AccessAssertionResponse,
    CoordinatorErrorCode,
    NodeStatus,
    SigningKeyMetadata,
    VerificationKeySet,
    VerificationKeyView,
    VerifiedAssertion,
)
from tunnelminion.coordinator.registry import (
    CoordinatorRegistryService,
    RegistryError,
    SQLiteCoordinatorStore,
)
from tunnelminion.domain.identifiers import NetworkId, NodeId
from tunnelminion.model.secrets import SecretStore

ASSERTION_ISSUER = "tunnelminion-coordinator"
SIGNING_KEY_REFERENCE_PREFIX = "coordinator-signing:"


class AssertionVerificationError(ValueError):
    """不暴露令牌正文或密钥材料的 assertion 验证错误。"""


class SigningKeyService:
    """将私钥保存在秘密后端，只把公钥与轮换元数据写入 SQLite。"""

    def __init__(
        self,
        store: SQLiteCoordinatorStore,
        secret_store: SecretStore,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._store = store
        self._secrets = secret_store
        self._clock = clock or (lambda: datetime.now(UTC))

    def rotate(self, *, overlap_seconds: int = ASSERTION_TTL_SECONDS) -> SigningKeyMetadata:
        """生成新密钥，并让旧活动 key 在有界窗口内继续可验证。"""
        if overlap_seconds < ASSERTION_TTL_SECONDS:
            raise ValueError("签名 key 重叠窗口不能短于 assertion TTL")
        now = self._now()
        for metadata in self._store.list_signing_keys():
            if (
                metadata.destroyed_at is None
                and metadata.activates_at <= now
                and metadata.retires_at is None
            ):
                self._store.put_signing_key(
                    metadata.model_copy(
                        update={"retires_at": now + timedelta(seconds=overlap_seconds)}
                    )
                )

        private_key = Ed25519PrivateKey.generate()
        private_raw = private_key.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
        public_raw = private_key.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        key_id = f"key-{secrets.token_hex(8)}"
        reference = f"{SIGNING_KEY_REFERENCE_PREFIX}{key_id}"
        metadata = SigningKeyMetadata(
            key_id=key_id,
            private_key_reference=reference,
            public_key=_b64url(public_raw),
            fingerprint=hashlib.sha256(public_raw).hexdigest(),
            activates_at=now,
        )
        self._secrets.set(reference, _b64url(private_raw))
        try:
            self._store.put_signing_key(metadata)
        except Exception:
            self._secrets.delete(reference)
            raise
        return metadata

    def active_signer(self) -> tuple[SigningKeyMetadata, Ed25519PrivateKey]:
        """返回当前签名 key；缺失秘密时安全失败。"""
        now = self._now()
        candidates = [
            key
            for key in self._store.list_signing_keys()
            if key.destroyed_at is None and key.activates_at <= now and key.retires_at is None
        ]
        if not candidates:
            raise RuntimeError("没有可用的 Coordinator 签名 key")
        metadata = max(candidates, key=lambda key: (key.activates_at, key.key_id))
        encoded = self._secrets.get(metadata.private_key_reference)
        if encoded is None:
            raise RuntimeError("Coordinator 签名 key 的秘密材料不可用")
        try:
            private_key = Ed25519PrivateKey.from_private_bytes(_b64url_decode(encoded))
        except (ValueError, TypeError) as exc:
            raise RuntimeError("Coordinator 签名 key 的秘密材料无效") from exc
        return metadata, private_key

    def verification_keys(self) -> VerificationKeySet:
        """发布仍在验证窗口内的公钥和固定指纹。"""
        now = self._now()
        keys = tuple(
            VerificationKeyView(
                key_id=key.key_id,
                public_key=key.public_key,
                fingerprint=key.fingerprint,
                activates_at=key.activates_at,
                retires_at=key.retires_at,
            )
            for key in self._store.list_signing_keys()
            if key.destroyed_at is None
            and key.activates_at <= now
            and (key.retires_at is None or key.retires_at > now)
        )
        if not keys:
            raise RuntimeError("没有可发布的 Coordinator 验证 key")
        return VerificationKeySet(generated_at=now, keys=keys)

    def destroy_retired(self) -> int:
        """删除已过验证窗口的私钥，并保留不可逆销毁元数据。"""
        now = self._now()
        destroyed = 0
        for metadata in self._store.list_signing_keys():
            if (
                metadata.destroyed_at is None
                and metadata.retires_at is not None
                and metadata.retires_at <= now
            ):
                self._secrets.delete(metadata.private_key_reference)
                self._store.put_signing_key(metadata.model_copy(update={"destroyed_at": now}))
                destroyed += 1
        return destroyed

    def _now(self) -> datetime:
        return _utc_now(self._clock())


class AssertionService:
    """认证 refresh 凭据后签发仅用于指定 audience 的短期身份声明。"""

    def __init__(
        self,
        registry: CoordinatorRegistryService,
        keys: SigningKeyService,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._registry = registry
        self._keys = keys
        self._clock = clock or (lambda: datetime.now(UTC))

    def issue(self, request: AccessAssertionRequest) -> AccessAssertionResponse:
        node = self._registry.authenticate_refresh(request.authentication)
        if node.status is not NodeStatus.ONLINE:
            raise RegistryError(
                CoordinatorErrorCode.FORBIDDEN,
                "只有在线节点可以申请 access assertion",
            )
        now = _utc_now(self._clock())
        expires_at = now + timedelta(seconds=ASSERTION_TTL_SECONDS)
        metadata, private_key = self._keys.active_signer()
        claims = {
            "iss": ASSERTION_ISSUER,
            "sub": str(node.identity.node_id),
            "node": str(node.identity.node_id),
            "net": str(node.identity.network_id),
            "aud": request.audience,
            "iat": int(now.timestamp()),
            "nbf": int(now.timestamp()),
            "exp": int(expires_at.timestamp()),
            "jti": secrets.token_hex(16),
            "pv": COORDINATOR_PROTOCOL.major,
        }
        assertion = jwt.encode(
            claims,
            private_key,
            algorithm=ASSERTION_ALGORITHM,
            headers={"kid": metadata.key_id, "typ": "JWT"},
        )
        return AccessAssertionResponse(
            assertion=assertion,
            key_id=metadata.key_id,
            expires_at=expires_at,
        )

    def verification_keys(self) -> VerificationKeySet:
        """向 Agent/Gateway 发布当前验证窗口。"""
        return self._keys.verification_keys()


class OfflineAssertionVerifier:
    """使用固定公钥指纹离线验证 assertion，不跟随令牌提供的远程 key。"""

    def __init__(
        self,
        key_set: VerificationKeySet,
        pinned_fingerprints: Collection[str],
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._keys = {key.key_id: key for key in key_set.keys}
        self._pins = frozenset(pinned_fingerprints)
        self._clock = clock or (lambda: datetime.now(UTC))

    def verify(
        self,
        assertion: str,
        *,
        audience: str,
        network_id: NetworkId,
        node_id: NodeId | None = None,
    ) -> VerifiedAssertion:
        if audience not in ASSERTION_AUDIENCES:
            raise AssertionVerificationError("未知 assertion audience")
        try:
            header = jwt.get_unverified_header(assertion)
        except jwt.PyJWTError as exc:
            raise AssertionVerificationError("assertion 格式无效") from exc
        if header.get("alg") != ASSERTION_ALGORITHM or header.get("typ") != "JWT":
            raise AssertionVerificationError("assertion 算法或类型无效")
        key_id = header.get("kid")
        if not isinstance(key_id, str) or key_id not in self._keys:
            raise AssertionVerificationError("assertion key ID 未知")
        key = self._keys[key_id]
        if key.fingerprint not in self._pins:
            raise AssertionVerificationError("assertion key 指纹未固定")
        now = _utc_now(self._clock())
        if key.activates_at > now or (key.retires_at is not None and key.retires_at <= now):
            raise AssertionVerificationError("assertion key 不在验证窗口")
        try:
            public_key = Ed25519PublicKey.from_public_bytes(_b64url_decode(key.public_key))
            raw_claims = jwt.decode(
                assertion,
                public_key,
                algorithms=[ASSERTION_ALGORITHM],
                audience=audience,
                issuer=ASSERTION_ISSUER,
                options={
                    "require": [
                        "iss",
                        "sub",
                        "node",
                        "net",
                        "aud",
                        "iat",
                        "nbf",
                        "exp",
                        "jti",
                        "pv",
                    ],
                    "verify_exp": False,
                    "verify_iat": False,
                    "verify_nbf": False,
                },
            )
        except (jwt.PyJWTError, ValueError, TypeError) as exc:
            raise AssertionVerificationError("assertion 签名或声明无效") from exc
        claims = cast(dict[str, object], raw_claims)
        try:
            issued = _claim_time(claims["iat"])
            not_before = _claim_time(claims["nbf"])
            expires = _claim_time(claims["exp"])
            network_value = claims["net"]
            node_value = claims["node"]
            subject = claims["sub"]
            jti = claims["jti"]
            protocol_major = claims["pv"]
            if (
                not isinstance(network_value, str)
                or not isinstance(node_value, str)
                or not isinstance(subject, str)
                or not isinstance(jti, str)
                or isinstance(protocol_major, bool)
                or not isinstance(protocol_major, int)
            ):
                raise TypeError("绑定声明类型无效")
            claim_network = NetworkId(network_value)
            claim_node = NodeId(node_value)
        except (KeyError, TypeError, ValueError) as exc:
            raise AssertionVerificationError("assertion 声明类型无效") from exc
        if (
            subject != str(claim_node)
            or claim_network != network_id
            or (node_id is not None and claim_node != node_id)
            or protocol_major != COORDINATOR_PROTOCOL.major
            or len(jti) != 32
            or any(character not in "0123456789abcdef" for character in jti)
            or not_before != issued
            or expires - issued != timedelta(seconds=ASSERTION_TTL_SECONDS)
            or issued > now
            or expires <= now
        ):
            raise AssertionVerificationError("assertion 绑定或时间边界无效")
        return VerifiedAssertion(
            network_id=claim_network,
            node_id=claim_node,
            audience=audience,
            key_id=key_id,
            jti=jti,
            protocol_major=protocol_major,
            issued_at=issued,
            expires_at=expires,
        )


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _claim_time(value: object) -> datetime:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError("时间声明必须是整数")
    return datetime.fromtimestamp(value, UTC)


def _utc_now(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise ValueError("Coordinator 时钟必须包含时区")
    return value.astimezone(UTC)
