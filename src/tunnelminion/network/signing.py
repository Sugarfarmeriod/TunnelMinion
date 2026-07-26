"""受管网络 desired config 的共享域分离验签规则。"""

from __future__ import annotations

import base64
import hashlib
import json
from collections.abc import Collection
from datetime import UTC, datetime, timedelta

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from tunnelminion.coordinator.contracts import VerificationKeyView
from tunnelminion.domain.identifiers import NetworkId, NodeId
from tunnelminion.network.contracts import DesiredNetworkConfig, SignedDesiredConfig

DESIRED_CONFIG_DOMAIN = b"TunnelMinion desired config v1\x00"


class DesiredConfigVerificationError(ValueError):
    """签名配置离线验证失败，不回显配置或签名正文。"""


def desired_config_payload(
    config: DesiredNetworkConfig,
    issued_at: datetime,
    expires_at: datetime,
) -> bytes:
    """生成同时绑定配置与有效期的稳定域分离 payload。"""
    body = {
        "config": config.model_dump(mode="json"),
        "issued_at": issued_at.isoformat(),
        "expires_at": expires_at.isoformat(),
    }
    encoded = json.dumps(
        body,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return DESIRED_CONFIG_DOMAIN + encoded


def verify_signed_desired_config(
    envelope: SignedDesiredConfig,
    verification_keys: Collection[VerificationKeyView],
    pinned_fingerprints: Collection[str],
    *,
    network_id: NetworkId,
    target_node_id: NodeId,
    parent_revision: int,
    now: datetime | None = None,
) -> DesiredNetworkConfig:
    """使用固定指纹、目标和父修订绑定离线验签。"""
    current = now or datetime.now(UTC)
    if current.tzinfo is None:
        current = current.replace(tzinfo=UTC)
    config = envelope.config
    if envelope.expires_at <= current or envelope.issued_at > current + timedelta(seconds=5):
        raise DesiredConfigVerificationError("签名配置不在有效时间窗口")
    if (
        config.network_id != network_id
        or config.target_node_id != target_node_id
        or config.parent_revision != parent_revision
    ):
        raise DesiredConfigVerificationError("签名配置目标或父 revision 不匹配")
    key = next((item for item in verification_keys if item.key_id == envelope.key_id), None)
    if key is None:
        raise DesiredConfigVerificationError("签名配置使用未知 key")
    if key.activates_at > current or (key.retires_at is not None and key.retires_at <= current):
        raise DesiredConfigVerificationError("签名 key 不在验证窗口")
    expected_fingerprint = f"sha256:{key.fingerprint}"
    if envelope.key_fingerprint != expected_fingerprint or envelope.key_fingerprint not in set(
        pinned_fingerprints
    ):
        raise DesiredConfigVerificationError("签名 key 指纹未固定")
    try:
        public_raw = _b64url_decode(key.public_key)
        if f"sha256:{hashlib.sha256(public_raw).hexdigest()}" != expected_fingerprint:
            raise DesiredConfigVerificationError("签名公钥与指纹不一致")
        Ed25519PublicKey.from_public_bytes(public_raw).verify(
            _b64url_decode(envelope.signature),
            desired_config_payload(config, envelope.issued_at, envelope.expires_at),
        )
    except (InvalidSignature, ValueError, TypeError) as exc:
        if isinstance(exc, DesiredConfigVerificationError):
            raise
        raise DesiredConfigVerificationError("签名配置验签失败") from exc
    return config


def _b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
