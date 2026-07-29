"""根据两端公钥报告生成短期签名 A/B 验收配置，不保存签名私钥。"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import BaseModel, ConfigDict

from tunnelminion.coordinator.contracts import VerificationKeyView
from tunnelminion.domain.identifiers import NetworkId, NodeId
from tunnelminion.network.contracts import (
    ApprovedRouteOverlap,
    CandidateSource,
    DesiredNetworkConfig,
    EndpointCandidate,
    PeerConfiguration,
    ProviderKind,
    SignedDesiredConfig,
)
from tunnelminion.network.signing import desired_config_payload


class PublicIdentityReport(BaseModel):
    """签名配置所需的最小公钥身份报告。"""

    model_config = ConfigDict(extra="ignore", frozen=True)

    network_id: NetworkId
    node_id: NodeId
    public_key: str
    network_writes_performed: bool


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def _load_identity(path: Path) -> PublicIdentityReport:
    value = PublicIdentityReport.model_validate_json(path.read_text(encoding="utf-8"))
    if value.network_writes_performed is not False:
        raise ValueError("身份报告未证明零网络写入")
    return value


def _sign(
    config: DesiredNetworkConfig,
    private: Ed25519PrivateKey,
    *,
    key_id: str,
    fingerprint: str,
    issued_at: datetime,
    expires_at: datetime,
) -> SignedDesiredConfig:
    return SignedDesiredConfig(
        config=config,
        key_id=key_id,
        key_fingerprint=f"sha256:{fingerprint}",
        issued_at=issued_at,
        expires_at=expires_at,
        signature=_b64url(private.sign(desired_config_payload(config, issued_at, expires_at))),
    )


def prepare(
    *,
    a_identity_path: Path,
    b_identity_path: Path,
    output_directory: Path,
    windows_route_fingerprint: str,
    macos_route_fingerprint: str,
) -> tuple[Path, Path, Path]:
    a = _load_identity(a_identity_path)
    b = _load_identity(b_identity_path)
    if a.network_id != b.network_id:
        raise ValueError("A/B 身份不属于同一验收 network")
    now = datetime.now(UTC)
    expires = now + timedelta(hours=2)
    candidate = EndpointCandidate(
        host="10.77.0.1",
        port=18889,
        source=CandidateSource.ADMIN_EXPLICIT,
        observed_at=now,
        expires_at=expires,
    )
    windows = DesiredNetworkConfig(
        network_id=a.network_id,
        target_node_id=a.node_id,
        provider=ProviderKind.WINDOWS,
        revision=1,
        parent_revision=0,
        interface_name="tmn-accept-a",
        address="10.253.0.2/32",
        peers=(
            PeerConfiguration(
                node_id=b.node_id,
                public_key=b.public_key,
                allowed_host_routes=("10.253.0.1/32",),
                candidates=(candidate,),
                persistent_keepalive_seconds=25,
            ),
        ),
        allowed_route_overlaps=(
            ApprovedRouteOverlap(
                route="10.128.0.0/9",
                observation_fingerprint=windows_route_fingerprint,
            ),
        ),
    )
    macos = DesiredNetworkConfig(
        network_id=b.network_id,
        target_node_id=b.node_id,
        provider=ProviderKind.MACOS,
        revision=1,
        parent_revision=0,
        interface_name="tmn-accept-b",
        address="10.253.0.1/32",
        listen_port=18889,
        peers=(
            PeerConfiguration(
                node_id=a.node_id,
                public_key=a.public_key,
                allowed_host_routes=("10.253.0.2/32",),
            ),
        ),
        allowed_route_overlaps=(
            ApprovedRouteOverlap(
                route="10.128.0.0/9",
                observation_fingerprint=macos_route_fingerprint,
            ),
        ),
    )
    private = Ed25519PrivateKey.generate()
    public_raw = private.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    fingerprint = hashlib.sha256(public_raw).hexdigest()
    key_id = "acceptance-20260729"
    verification = VerificationKeyView(
        key_id=key_id,
        public_key=_b64url(public_raw),
        fingerprint=fingerprint,
        activates_at=now - timedelta(seconds=1),
    )
    output_directory.mkdir(parents=True, exist_ok=True)
    a_path = output_directory / "a-envelope.json"
    b_path = output_directory / "b-envelope.json"
    key_path = output_directory / "verification-key.json"
    a_path.write_text(
        _sign(
            windows,
            private,
            key_id=key_id,
            fingerprint=fingerprint,
            issued_at=now,
            expires_at=expires,
        ).model_dump_json(indent=2)
        + "\n",
        encoding="utf-8",
    )
    b_path.write_text(
        _sign(
            macos,
            private,
            key_id=key_id,
            fingerprint=fingerprint,
            issued_at=now,
            expires_at=expires,
        ).model_dump_json(indent=2)
        + "\n",
        encoding="utf-8",
    )
    key_path.write_text(verification.model_dump_json(indent=2) + "\n", encoding="utf-8")
    return a_path, b_path, key_path


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--a-identity", type=Path, required=True)
    parser.add_argument("--b-identity", type=Path, required=True)
    parser.add_argument("--output-directory", type=Path, required=True)
    parser.add_argument("--windows-route-fingerprint", required=True)
    parser.add_argument("--macos-route-fingerprint", required=True)
    args = parser.parse_args(argv)
    paths = prepare(
        a_identity_path=args.a_identity,
        b_identity_path=args.b_identity,
        output_directory=args.output_directory,
        windows_route_fingerprint=args.windows_route_fingerprint,
        macos_route_fingerprint=args.macos_route_fingerprint,
    )
    print(json.dumps({"outputs": [str(path.resolve()) for path in paths]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
