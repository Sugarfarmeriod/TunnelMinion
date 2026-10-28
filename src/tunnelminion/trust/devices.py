"""我的电脑的加入、移除、权限和点对点名单交换。"""

from __future__ import annotations

import asyncio
import hashlib
import logging
from collections.abc import Callable, Iterable
from contextlib import suppress
from datetime import UTC, datetime
from threading import Lock

import httpx

from tunnelminion.domain.identifiers import NodeId
from tunnelminion.domain.trust import (
    JOIN_CODE_LIFETIME,
    JOIN_PROOF_MAX_AGE,
    DeviceCertificate,
    DeviceEntry,
    JoinCode,
    JoinCodeKind,
    JoinProof,
    OwnerRoster,
    PassScope,
    SignaturePurpose,
    TrustedPerson,
    TrustList,
    key_fingerprint,
)
from tunnelminion.gateway.configuration import generate_gateway_token
from tunnelminion.gateway.credentials import GatewayCredentials
from tunnelminion.gateway.security import GatewayBindConfig
from tunnelminion.model.secrets import SecretStore
from tunnelminion.trust.backup import IdentityState, settle_key_backup
from tunnelminion.trust.contracts import (
    DevicePermissions,
    IdentityError,
    OwnerJoinRequest,
    OwnerJoinResponse,
    TrustStore,
    TrustSyncMessage,
    VersionRejectedError,
)
from tunnelminion.trust.keys import (
    DEVICE_KEY_NAME,
    IDENTITY_KEY_NAMES,
    OWNER_KEY_NAME,
    PrivateKey,
    delete_private_key,
    load_private_key,
)
from tunnelminion.trust.service import IdentityKeySwap, OwnerIdentityService
from tunnelminion.trust.signatures import (
    VerificationError,
    seal,
    verify,
    verify_device_certificate,
    verify_owner_roster,
    verify_trust_list,
)

logger = logging.getLogger(__name__)
INVALID_INVITE = "邀请码无效、已过期或已被使用"


class OwnDevicesService:
    """机主密钥只用于名单和证书，网络请求只用本机电脑密钥。"""

    def __init__(
        self,
        node_id: NodeId,
        store: TrustStore,
        secrets: SecretStore,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.node_id = node_id
        self.store = store
        self.secrets = secrets
        self.transport = transport
        self.clock = clock or (lambda: datetime.now(UTC))
        self.changes = Lock()

    def roster(self) -> OwnerRoster:
        owner = self.store.owner_fingerprint()
        envelope = self.store.load(SignaturePurpose.OWNER_ROSTER)
        if owner is None or envelope is None:
            raise IdentityError("本机身份尚未初始化")
        return verify_owner_roster(envelope, owner)

    def active(self) -> bool:
        return self.store.load(SignaturePurpose.DEVICE_CERTIFICATE) is not None

    def trust_list(self) -> TrustList:
        roster = self.roster()
        envelope = self.store.load(SignaturePurpose.TRUST_LIST)
        if envelope is None:
            raise IdentityError("本机身份记录不完整")
        return verify_trust_list(envelope, roster.owner_public_key, roster.owner_fingerprint)

    def friends(self) -> tuple[tuple[TrustedPerson, OwnerRoster], ...]:
        """朋友的电脑名单；本机已把撞号编号判给别的朋友时，去掉这份名单里的同号电脑。"""
        claimed = self.claimed_friends()
        owners = self.store.friend_node_owners()
        if not owners:
            return claimed
        holders = {friend.owner_fingerprint: roster for friend, roster in claimed}

        def kept(fingerprint: str, device: DeviceEntry) -> bool:
            owner = owners.get(str(device.node_id))
            return (
                owner is None
                or owner == fingerprint
                or owner not in holders
                or holders[owner].device(device.node_id) is None
            )

        return tuple(
            (
                friend,
                roster.model_copy(
                    update={
                        "devices": tuple(
                            device
                            for device in roster.devices
                            if kept(friend.owner_fingerprint, device)
                        )
                    }
                ),
            )
            for friend, roster in claimed
        )

    def claimed_friends(self) -> tuple[tuple[TrustedPerson, OwnerRoster], ...]:
        """朋友各自签名的电脑名单原样，包括本机已判给别的朋友的撞号电脑。"""
        people = {item.owner_fingerprint: item for item in self.trusted_people()}
        return tuple(
            (
                people[envelope.signer_fingerprint],
                verify_owner_roster(envelope, envelope.signer_fingerprint),
            )
            for envelope in self.store.friend_rosters()
            if envelope.signer_fingerprint in people
        )

    def trusted_people(self) -> tuple[TrustedPerson, ...]:
        return tuple(self.store.resolve_friend(item) for item in self.trust_list().people)

    def known_device(self, node_id: NodeId) -> DeviceEntry | None:
        return self.roster().device(node_id) or next(
            (
                device
                for _, roster in self.friends()
                if (device := roster.device(node_id)) is not None
            ),
            None,
        )

    def identity_key(self, name: str) -> PrivateKey | None:
        """先处理上次换密钥中断留下的备份，再读取本机身份密钥。"""
        settle_key_backup(self.store, self.secrets)
        return load_private_key(self.secrets, name)

    def owner_key(self) -> PrivateKey:
        key = self.identity_key(OWNER_KEY_NAME)
        if key is None or key_fingerprint(key.public_key) != self.roster().owner_fingerprint:
            raise IdentityError("只能在持有机主密钥的电脑上操作")
        return key

    def invite(self) -> JoinCode:
        self.owner_key()
        roster = self.roster()
        local = roster.device(self.node_id)
        if local is None:
            raise IdentityError("本机已被移出我的电脑")
        code = JoinCode(
            kind=JoinCodeKind.OWNER,
            inviter_node_id=self.node_id,
            owner_fingerprint=roster.owner_fingerprint,
            host=local.host,
            port=local.port,
            token=generate_gateway_token(),
            expires_at=self.clock() + JOIN_CODE_LIFETIME,
        )
        self.store.create_invite(hashlib.sha256(code.token.encode()).digest(), code.expires_at)
        return code

    def accept_join(
        self, token: str, request: OwnerJoinRequest, source_host: str
    ) -> OwnerJoinResponse:
        """先验证地址和持钥证明，再消费令牌；并发报到串行更新名单。"""
        try:
            if request.host != source_host or request.node_id == self.node_id:
                raise ValueError
            GatewayBindConfig(host=request.host, port=request.port)
            proof = verify(
                request.proof, SignaturePurpose.JOIN_PROOF, request.device_public_key, JoinProof
            )
            digest = hashlib.sha256(token.encode()).digest()
            if (
                proof.token_digest != digest.hex()
                or proof.inviter_node_id != self.node_id
                or proof.node_id != request.node_id
                or proof.device_public_key != request.device_public_key
                or proof.host != request.host
                or proof.port != request.port
                or abs(self.clock() - proof.issued_at) > JOIN_PROOF_MAX_AGE
            ):
                raise ValueError
            with self.changes:
                key = self.owner_key()
                roster = self.roster()
                now = self.clock()
                device = DeviceEntry(**request.model_dump(exclude={"proof"}), added_at=now)
                updated = OwnerRoster(
                    **roster.model_dump(exclude={"devices", "version", "issued_at"}),
                    devices=(*roster.devices, device),
                    version=roster.version + 1,
                    issued_at=now,
                )
                if not self.store.consume_invite(digest, device.node_id, now):
                    raise ValueError
                self.store.accept(
                    seal(SignaturePurpose.OWNER_ROSTER, updated, key),
                    f"本机 {self.node_id} 接纳电脑 {device.node_id}",
                )
                message = self.message()
                assert message.roster is not None and message.trust_list is not None
                return OwnerJoinResponse(
                    certificate=seal(
                        SignaturePurpose.DEVICE_CERTIFICATE,
                        DeviceCertificate(
                            owner_fingerprint=roster.owner_fingerprint,
                            node_id=device.node_id,
                            device_public_key=device.device_public_key,
                            issued_at=now,
                        ),
                        key,
                    ),
                    roster=message.roster,
                    trust_list=message.trust_list,
                    rotations=message.rotations,
                )
        except (ValueError, IdentityError):
            raise IdentityError(INVALID_INVITE) from None

    def install_join(
        self,
        code: JoinCode,
        response: OwnerJoinResponse,
        key: PrivateKey,
        *,
        replace: bool = False,
        previous_secrets: SecretStore | None = None,
    ) -> None:
        """核对邀请中的机主和本机公钥后，才把电脑私钥写入秘密存储。

        `replace` 为真时，在同一个事务里替换掉本机旧身份；失败时旧身份和旧密钥原样保留。
        """
        if not replace:
            OwnerIdentityService(self.store, self.secrets).ensure_uninitialized()
        roster = verify_owner_roster(response.roster, code.owner_fingerprint)
        verify_trust_list(response.trust_list, roster.owner_public_key, code.owner_fingerprint)
        certificate = verify_device_certificate(
            response.certificate, roster.owner_public_key, code.owner_fingerprint
        )
        local = roster.device(self.node_id)
        if (
            local is None
            or local.device_public_key != key.public_key
            or certificate.node_id != self.node_id
            or certificate.device_public_key != key.public_key
            or roster.device(code.inviter_node_id) is None
        ):
            raise VerificationError("加入响应中的本机身份不符")
        swap = IdentityKeySwap(
            self.store,
            self.secrets,
            {DEVICE_KEY_NAME: key},
            IdentityState(
                owner_fingerprint=code.owner_fingerprint, device_public_key=key.public_key
            ),
            replaced=IDENTITY_KEY_NAMES if replace else (),
            previous_secrets=previous_secrets,
        )
        try:
            self.store.initialize(
                code.owner_fingerprint,
                response.roster,
                response.trust_list,
                response.certificate,
                swap.persist,
                response.rotations,
                replace=replace,
            )
        except Exception:
            swap.rollback()
            raise
        swap.commit()

    def remove(self, node_id: NodeId) -> tuple[DeviceEntry, ...]:
        """返回变更前的推送对象，包含被移除的电脑。"""
        with self.changes:
            key = self.owner_key()
            roster = self.roster()
            if node_id == self.node_id:
                raise IdentityError("不能移除本机")
            if roster.device(node_id) is None:
                raise IdentityError("我的电脑名单里没有这个节点")
            updated = OwnerRoster(
                **roster.model_dump(exclude={"devices", "version", "issued_at"}),
                devices=tuple(item for item in roster.devices if item.node_id != node_id),
                version=roster.version + 1,
                issued_at=self.clock(),
            )
            self.store.accept(
                seal(SignaturePurpose.OWNER_ROSTER, updated, key),
                f"本机 {self.node_id} 移除电脑 {node_id}",
            )
            return roster.devices

    def restrict(self, node_id: NodeId, permissions: DevicePermissions) -> None:
        if self.roster().device(node_id) is None or node_id == self.node_id:
            raise IdentityError("请指定名单上的其他电脑")
        self.store.restrict_device(node_id, permissions)

    def message(self, *, include_private: bool = True) -> TrustSyncMessage:
        friend_rosters = self.store.friend_rosters() if include_private else ()
        return TrustSyncMessage(
            roster=self.store.load(SignaturePurpose.OWNER_ROSTER),
            trust_list=self.store.load(SignaturePurpose.TRUST_LIST) if include_private else None,
            friend_rosters=friend_rosters,
            rotations=self.store.rotations(self.roster().owner_fingerprint),
            friend_rotations={
                item.signer_fingerprint: chain
                for item in friend_rosters
                if (chain := self.store.rotations(item.signer_fingerprint))
            },
        )

    def receive(self, message: TrustSyncMessage, source: str) -> TrustSyncMessage:
        reason = f"从 {source} 同步名单"
        if message.rotations:
            if message.roster is None:
                raise VerificationError("身份签名验证失败")
            self.store.rotate(message.rotations, message.roster, message.trust_list, reason)
            self._drop_retired_owner_key()
        for envelope in (message.roster, message.trust_list):
            if envelope is not None:
                with suppress(VersionRejectedError):
                    self.store.accept(envelope, reason)
        for envelope in message.friend_rosters:
            if chain := message.friend_rotations.get(envelope.signer_fingerprint):
                self.store.rotate(chain, envelope, None, reason)
            with suppress(VersionRejectedError):
                self.store.accept(envelope, reason)
        return self.message()

    def _drop_retired_owner_key(self) -> None:
        """机主换了密钥以后，钥匙串里残留的旧机主密钥已经没用，删掉免得泄露。"""
        key = load_private_key(self.secrets, OWNER_KEY_NAME)
        if key is not None and key_fingerprint(key.public_key) != self.roster().owner_fingerprint:
            delete_private_key(self.secrets, OWNER_KEY_NAME)

    async def sync(self, device: DeviceEntry) -> None:
        """我的电脑带通行证交换完整名单；朋友之间只交换各自电脑名单。"""
        from tunnelminion.trust.passes import issue_pass

        bind = GatewayBindConfig(host=device.host, port=device.port)
        local = self.roster().device(self.node_id)
        mine = self.roster().device(device.node_id) is not None
        transport = self.transport or httpx.AsyncHTTPTransport(
            local_address=local.host if local is not None else None
        )
        try:
            headers = {"Content-Type": "application/json"}
            if (
                local is not None
                and self.active()
                and self.known_device(device.node_id) is not None
            ):
                headers["Authorization"] = (
                    f"Bearer {issue_pass(self, device.node_id, PassScope.TRUST_SYNC)}"
                )
            async with httpx.AsyncClient(
                base_url=httpx.URL(scheme="http", host=bind.host, port=bind.port),
                transport=transport,
                timeout=5,
                trust_env=False,
            ) as client:
                response = await client.post(
                    "/v1/trust:sync",
                    content=self.message(include_private=mine).model_dump_json(),
                    headers=headers,
                )
            if not response.is_success or len(response.content) > 512_000:
                raise ValueError
            self.receive(
                TrustSyncMessage.model_validate_json(response.content), str(device.node_id)
            )
        except (httpx.HTTPError, ValueError):
            raise IdentityError("名单同步失败") from None

    async def push(self, devices: Iterable[DeviceEntry] | None = None) -> tuple[NodeId, ...]:
        """同时通知所有电脑，不在线的各自等到超时，总共只等一次超时；返回没推到的电脑。"""
        targets = [
            device
            for device in (
                (
                    *self.roster().devices,
                    *(device for _, roster in self.friends() for device in roster.devices),
                )
                if devices is None
                else devices
            )
            if device.node_id != self.node_id
        ]

        async def reached(device: DeviceEntry) -> bool:
            try:
                await self.sync(device)
            except IdentityError:
                logger.warning("名单同步失败：节点 %s", device.node_id)
                return False
            return True

        results = await asyncio.gather(*(reached(device) for device in targets))
        return tuple(device.node_id for device, ok in zip(targets, results, strict=True) if not ok)

    def credentials(self, device: DeviceEntry) -> GatewayCredentials:
        from tunnelminion.trust.passes import issue_pass

        local = self.roster().device(self.node_id)
        return GatewayCredentials(
            lambda scope: issue_pass(self, device.node_id, scope),
            lambda: self.sync(device),
            local.host if local is not None else None,
        )
