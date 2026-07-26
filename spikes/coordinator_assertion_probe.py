"""隔离验证 PyJWT Ed25519 assertion 的字段和失败关闭规则。"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

ALGORITHM = "EdDSA"
ISSUER = "tunnelminion-coordinator"
TTL_SECONDS = 120
REQUIRED_CLAIMS = ("iss", "sub", "net", "aud", "iat", "nbf", "exp", "jti", "pv")


class AssertionRejected(ValueError):
    """断言未通过固定算法、密钥或声明验证。"""


def issue_assertion(
    private_key: Ed25519PrivateKey,
    *,
    key_id: str,
    network_id: str,
    node_id: str,
    audience: str,
    now: datetime | None = None,
) -> str:
    """生成仅用于 spike 的短期标准 EdDSA JWT。"""
    issued_at = now or datetime.now(UTC)
    claims = {
        "iss": ISSUER,
        "sub": node_id,
        "net": network_id,
        "aud": audience,
        "iat": issued_at,
        "nbf": issued_at,
        "exp": issued_at + timedelta(seconds=TTL_SECONDS),
        "jti": uuid4().hex,
        "pv": 1,
    }
    return jwt.encode(
        claims,
        private_key,
        algorithm=ALGORITHM,
        headers={"kid": key_id, "typ": "JWT"},
    )


def verify_assertion(
    token: str,
    *,
    trusted_keys: dict[str, Ed25519PublicKey],
    expected_network_id: str,
    expected_audience: str,
) -> dict[str, Any]:
    """只使用本机固定公钥和硬编码算法验证 assertion。"""
    try:
        header = jwt.get_unverified_header(token)
    except jwt.PyJWTError as exc:
        raise AssertionRejected("malformed") from exc
    if header.get("alg") != ALGORITHM or header.get("typ") != "JWT":
        raise AssertionRejected("algorithm_or_type_rejected")
    key_id = header.get("kid")
    if not isinstance(key_id, str) or key_id not in trusted_keys:
        raise AssertionRejected("unknown_key_id")
    try:
        claims = jwt.decode(
            token,
            trusted_keys[key_id],
            algorithms=[ALGORITHM],
            audience=expected_audience,
            issuer=ISSUER,
            options={"require": list(REQUIRED_CLAIMS)},
        )
    except jwt.PyJWTError as exc:
        raise AssertionRejected(type(exc).__name__) from exc
    if claims["net"] != expected_network_id:
        raise AssertionRejected("network_mismatch")
    if claims["pv"] != 1:
        raise AssertionRejected("protocol_mismatch")
    if not isinstance(claims["sub"], str) or not claims["sub"].startswith("node_"):
        raise AssertionRejected("node_malformed")
    if not isinstance(claims["jti"], str) or len(claims["jti"]) != 32:
        raise AssertionRejected("jti_malformed")
    if claims["exp"] - claims["iat"] != TTL_SECONDS:
        raise AssertionRejected("ttl_mismatch")
    return claims
