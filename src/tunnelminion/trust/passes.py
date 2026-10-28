"""电脑通行证只以接收方本机名单为信任来源。"""

from __future__ import annotations

from dataclasses import replace
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
from tunnelminion.gateway.security import (
    GatewayAuthenticationKind,
    GatewayPeerPolicy,
    identity_permissions,
)
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
        or service.known_device(target) is None
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

    def friend_peer(self, issuer: NodeId) -> GatewayPeerPolicy | None:
        """一个节点 ID 只能属于一个朋友；出现在多份朋友名单里时谁都不认。"""
        matches = [
            (friend, device)
            for friend, roster in self.service.friends()
            if (device := roster.device(issuer)) is not None
        ]
        if len(matches) == 1:
            friend, device = matches[0]
            local = self.service.store.friend_permissions(friend.owner_fingerprint)
            return identity_permissions(
                GatewayPeerPolicy(
                    node_id=issuer,
                    token_digest=b"",
                    allowed_tools=frozenset(),
                    source_host=device.host,
                    authentication_kind=GatewayAuthenticationKind.FRIEND_DEVICE,
                    allow_delegation=friend.permissions.allow_delegation and local.allow_delegation,
                    allow_model_borrowing=friend.permissions.allow_model_borrowing
                    and local.allow_model_borrowing,
                    daily_quota=min(friend.permissions.daily_quota, local.daily_quota),
                )
            )
        return None

    def static_peer(
        self, peer: GatewayPeerPolicy, source_host: str | None
    ) -> GatewayPeerPolicy | None:
        """旧令牌命中名单上的电脑时，权限不超过名单身份；已移出的电脑旧令牌一律作废。"""
        if self.service.roster().device(peer.node_id) is not None:
            limits = self.service.store.device_permissions(peer.node_id)
            return replace(
                peer,
                allow_delegation=peer.allow_delegation and limits.allow_delegation,
                allow_model_borrowing=peer.allow_model_borrowing and limits.allow_model_borrowing,
                allow_proxy_repair_approval=peer.allow_proxy_repair_approval
                and limits.allow_proxy_repair_approval,
                daily_quota=min(peer.daily_quota, limits.daily_quota),
            )
        friend = self.friend_peer(peer.node_id)
        # 朋友名单里的地址和旧式配对登记的地址不同，说明是别人占用了这个节点 ID，按旧式配对处理。
        if friend is not None and friend.source_host == peer.source_host:
            if not self.service.active() or source_host != friend.source_host:
                return None
            return identity_permissions(friend, peer)
        if self.service.store.was_friend_device(
            peer.node_id, peer.source_host
        ) or self.service.store.was_own_device(peer.node_id):
            return None
        return peer

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
            friend = self.friend_peer(issuer) if device is None else None
            if device is None and friend is not None:
                roster = next(
                    roster for _, roster in self.service.friends() if roster.device(issuer)
                )
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
            if claims.roster_version != roster.version and scope != PassScope.TRUST_SYNC.value:
                raise TrustSyncRequired("需要同步名单")
            with self._lock:
                self._used = {key: expiry for key, expiry in self._used.items() if expiry > now}
                identifier = (str(issuer), claims.jti)
                if identifier in self._used:
                    return None
                self._used[identifier] = claims.exp + leeway
            if friend is not None:
                return friend
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
