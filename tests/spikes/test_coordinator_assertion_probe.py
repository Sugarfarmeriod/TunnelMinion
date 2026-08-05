"""标准 Ed25519 JWT spike 的成功与失败关闭矩阵。"""

from datetime import UTC, datetime, timedelta

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from spikes.coordinator_assertion_probe import (
    ALGORITHM,
    ISSUER,
    TTL_SECONDS,
    AssertionRejected,
    issue_assertion,
    verify_assertion,
)

NETWORK = "network_0123456789abcdef0123456789abcdef"
NODE = "node_0123456789abcdef0123456789abcdef"
KEY_ID = "coord-signing-2026-07"


def token_and_keys() -> tuple[str, Ed25519PrivateKey]:
    private_key = Ed25519PrivateKey.generate()
    token = issue_assertion(
        private_key,
        key_id=KEY_ID,
        network_id=NETWORK,
        node_id=NODE,
        audience="tool-gateway",
        now=datetime.now(UTC),
    )
    return token, private_key


def verify(token: str, private_key: Ed25519PrivateKey) -> dict[str, object]:
    return verify_assertion(
        token,
        trusted_keys={KEY_ID: private_key.public_key()},
        expected_network_id=NETWORK,
        expected_audience="tool-gateway",
    )


def test_standard_eddsa_assertion_has_fixed_header_claims_and_ttl() -> None:
    token, private_key = token_and_keys()
    claims = verify(token, private_key)
    header = jwt.get_unverified_header(token)

    assert header == {"alg": ALGORITHM, "kid": KEY_ID, "typ": "JWT"}
    assert claims["iss"] == ISSUER
    assert claims["sub"] == NODE
    assert claims["net"] == NETWORK
    assert claims["aud"] == "tool-gateway"
    assert claims["pv"] == 1
    assert isinstance(claims["exp"], int)
    assert isinstance(claims["iat"], int)
    assert claims["exp"] - claims["iat"] == TTL_SECONDS


@pytest.mark.parametrize(
    ("change", "expected"),
    [
        ({"aud": "operation-gateway"}, "InvalidAudienceError"),
        ({"net": "network_ffffffffffffffffffffffffffffffff"}, "network_mismatch"),
        ({"pv": 2}, "protocol_mismatch"),
        ({"sub": "invalid"}, "node_malformed"),
        ({"jti": "short"}, "jti_malformed"),
        ({"exp_seconds": 121}, "ttl_mismatch"),
    ],
)
def test_claim_rejection_rules(change: dict[str, object], expected: str) -> None:
    private_key = Ed25519PrivateKey.generate()
    now = datetime.now(UTC)
    claims: dict[str, object] = {
        "iss": ISSUER,
        "sub": NODE,
        "net": NETWORK,
        "aud": "tool-gateway",
        "iat": now,
        "nbf": now,
        "exp": now + timedelta(seconds=TTL_SECONDS),
        "jti": "a" * 32,
        "pv": 1,
    }
    exp_seconds = change.get("exp_seconds")
    if isinstance(exp_seconds, int):
        claims["exp"] = now + timedelta(seconds=exp_seconds)
    else:
        claims.update(change)
    token = jwt.encode(
        claims,
        private_key,
        algorithm=ALGORITHM,
        headers={"kid": KEY_ID, "typ": "JWT"},
    )

    with pytest.raises(AssertionRejected, match=expected):
        verify(token, private_key)


def test_expiry_unknown_key_algorithm_tampering_and_malformed_token_fail_closed() -> None:
    expired_key = Ed25519PrivateKey.generate()
    expired = issue_assertion(
        expired_key,
        key_id=KEY_ID,
        network_id=NETWORK,
        node_id=NODE,
        audience="tool-gateway",
        now=datetime.now(UTC) - timedelta(minutes=5),
    )
    with pytest.raises(AssertionRejected, match="ExpiredSignatureError"):
        verify(expired, expired_key)

    token, private_key = token_and_keys()
    with pytest.raises(AssertionRejected, match="unknown_key_id"):
        verify_assertion(
            token,
            trusted_keys={},
            expected_network_id=NETWORK,
            expected_audience="tool-gateway",
        )

    symmetric = jwt.encode(
        {"value": "irrelevant"},
        "a" * 32,
        algorithm="HS256",
        headers={"kid": KEY_ID, "typ": "JWT"},
    )
    with pytest.raises(AssertionRejected, match="algorithm_or_type_rejected"):
        verify(symmetric, private_key)

    header, payload, signature = token.split(".")
    tampered = ".".join((header, payload[:-1] + ("A" if payload[-1] != "A" else "B"), signature))
    with pytest.raises(AssertionRejected, match="InvalidSignatureError"):
        verify(tampered, private_key)

    with pytest.raises(AssertionRejected, match="malformed"):
        verify("not-a-jwt", private_key)
