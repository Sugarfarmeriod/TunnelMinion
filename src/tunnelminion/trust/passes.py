"""电脑通行证只以接收方本机名单为信任来源。"""

from __future__ import annotations

from threading import Lock
from uuid import uuid4

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from tunnelminion.domain.identifiers import NodeId
from tunnelminion.domain.trust import (
    REQUEST_PASS_ALGORITHM,
    REQUEST_PASS_CLOCK_LEEWAY,
    REQUEST_PASS_MAX_LIFETIME,
    REQUEST_PASS_TYPE,
    PassScope,
    RequestPassClaims,
    decode_public_key,
)
from tunnelminion.gateway.configuration import DEFAULT_GATEWAY_TOOLS
from tunnelminion.gateway.security import GatewayAuthenticationKind, GatewayPeerPolicy
from tunnelminion.trust.contracts import IdentityError
from tunnelminion.trust.devices import OwnDevicesService
from tunnelminion.trust.keys import DEVICE_KEY_NAME, load_private_key


class TrustSyncRequired(IdentityError):
    """本机名单不能确认请求方，先交换签名名单再重试。"""


def issue_pass(service: OwnDevicesService, target: NodeId, scope: PassScope) -> str:
    roster = service.roster()
    local = roster.device(service.node_id)
    key = load_private_key(service.secrets, DEVICE_KEY_NAME)
    if (
        not service.active()
        or local is None
        or key is None
        or local.device_public_key != key.public_key
        or roster.device(target) is None
    ):
        raise IdentityError("本机已被移出我的电脑，不能使用通行证")
    now = int(service.clock().timestamp())
    claims = RequestPassClaims(
        iss=service.node_id,
        aud=target,
        scope=scope,
        iat=now,
        exp=now + int(REQUEST_PASS_MAX_LIFETIME.total_seconds()),
        jti=uuid4().hex,
        owner_fingerprint=roster.owner_fingerprint,
        roster_version=roster.version,
    )
    return key.request_pass(claims)


class RequestPassVerifier:
    """单机有效期内的编号缓存和验签；不信请求自称的机主。"""

    def __init__(self, service: OwnDevicesService) -> None:
        self.service = service
        self._used: dict[tuple[str, str], float] = {}
        self._lock = Lock()

    def authenticate(
        self, credential: str, scope: str, source_host: str | None
    ) -> GatewayPeerPolicy | None:
        try:
            if jwt.get_unverified_header(credential).get("typ") != REQUEST_PASS_TYPE:
                return None
            unverified = jwt.decode(credential, options={"verify_signature": False})
            issuer = NodeId(unverified["iss"])
            roster = self.service.roster()
            device = roster.device(issuer)
            if device is None:
                raise TrustSyncRequired("需要同步名单")
            claims = RequestPassClaims.model_validate(
                jwt.decode(
                    credential,
                    Ed25519PublicKey.from_public_bytes(decode_public_key(device.device_public_key)),
                    algorithms=[REQUEST_PASS_ALGORITHM],
                    audience=str(self.service.node_id),
                    options={"verify_iat": False, "verify_exp": False},
                )
            )
            now = self.service.clock().timestamp()
            leeway = REQUEST_PASS_CLOCK_LEEWAY.total_seconds()
            if (
                claims.scope.value != scope
                or claims.iat > now + leeway
                or claims.exp <= now - leeway
                or source_host != device.host
                or not self.service.active()
            ):
                return None
            if claims.roster_version != roster.version:
                raise TrustSyncRequired("需要同步名单")
            with self._lock:
                self._used = {key: expiry for key, expiry in self._used.items() if expiry > now}
                identifier = (str(issuer), claims.jti)
                if identifier in self._used:
                    return None
                self._used[identifier] = claims.exp + leeway
            permissions = self.service.store.device_permissions(issuer)
            return GatewayPeerPolicy(
                node_id=issuer,
                token_digest=b"",
                allowed_tools=frozenset(DEFAULT_GATEWAY_TOOLS),
                source_host=device.host,
                authentication_kind=GatewayAuthenticationKind.OWNER_DEVICE,
                **permissions.model_dump(),
            )
        except TrustSyncRequired:
            raise
        except (ValueError, KeyError, TypeError, jwt.PyJWTError):
            return None
