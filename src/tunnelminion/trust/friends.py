"""按机主配对、修改朋友权限，并保存对方签名的电脑名单。"""

from __future__ import annotations

import asyncio
import hashlib

import httpx

from tunnelminion.domain.identifiers import NodeId
from tunnelminion.domain.trust import (
    JOIN_CODE_LIFETIME,
    FriendPermissions,
    JoinCode,
    JoinCodeKind,
    OwnerRoster,
    SignaturePurpose,
    TrustedPerson,
    key_fingerprint,
)
from tunnelminion.gateway.configuration import generate_gateway_token
from tunnelminion.gateway.security import GatewayBindConfig
from tunnelminion.trust.contracts import FriendPairing, IdentityError
from tunnelminion.trust.devices import INVALID_INVITE, OwnDevicesService
from tunnelminion.trust.signatures import (
    VerificationError,
    roster_conflicts,
    seal,
    verify_owner_roster,
)


def _label(friend: TrustedPerson) -> str:
    return f"{friend.display_name}（{friend.owner_fingerprint}）"


class FriendsService:
    """只在持有本机机主密钥时修改我信任的人。"""

    def __init__(self, devices: OwnDevicesService) -> None:
        self.devices = devices

    def pairing(self, display_name: str | None = None) -> FriendPairing:
        self.devices.owner_key()
        roster = self.devices.roster()
        local = roster.device(self.devices.node_id)
        if local is None or not self.devices.active():
            raise IdentityError("本机已被移出我的电脑")
        envelope = self.devices.message().roster
        assert envelope is not None
        return FriendPairing(
            owner_public_key=roster.owner_public_key,
            recovery_fingerprint=roster.recovery_fingerprint,
            display_name=display_name
            if display_name is not None
            else f"机主 {roster.owner_fingerprint.removeprefix('sha256:')[:8]}",
            roster=envelope,
        )

    def invite(self, display_name: str | None = None) -> JoinCode:
        pairing = self.pairing(display_name)
        roster = self.devices.roster()
        local = roster.device(self.devices.node_id)
        assert local is not None
        code = JoinCode(
            kind=JoinCodeKind.FRIEND,
            inviter_node_id=self.devices.node_id,
            owner_fingerprint=roster.owner_fingerprint,
            host=local.host,
            port=local.port,
            token=generate_gateway_token(),
            expires_at=self.devices.clock() + JOIN_CODE_LIFETIME,
        )
        self.devices.store.create_friend_invite(
            hashlib.sha256(code.token.encode()).digest(), code.expires_at, pairing.display_name
        )
        return code

    def _verify_pairing(self, pairing: FriendPairing) -> OwnerRoster:
        roster = verify_owner_roster(pairing.roster, key_fingerprint(pairing.owner_public_key))
        if (
            roster.owner_public_key != pairing.owner_public_key
            or roster.recovery_fingerprint != pairing.recovery_fingerprint
            or roster.owner_fingerprint == self.devices.roster().owner_fingerprint
        ):
            raise VerificationError("朋友身份与电脑名单不符")
        for device in roster.devices:
            GatewayBindConfig(host=device.host, port=device.port)
        if roster_conflicts(roster, (self.devices.roster(),)):
            raise VerificationError("朋友名单里的电脑与已有电脑冲突")
        return roster

    def _save_pairing(self, pairing: FriendPairing) -> None:
        roster = self._verify_pairing(pairing)
        trust = self.devices.trust_list()
        if any(
            item.owner_fingerprint == roster.owner_fingerprint
            for item in self.devices.trusted_people()
        ):
            raise IdentityError("已经和这个朋友配对")
        updated = trust.model_copy(
            update={
                "version": trust.version + 1,
                "issued_at": self.devices.clock(),
                "people": (
                    *self.devices.trusted_people(),
                    TrustedPerson(
                        owner_public_key=pairing.owner_public_key,
                        recovery_fingerprint=pairing.recovery_fingerprint,
                        display_name=pairing.display_name,
                        added_at=self.devices.clock(),
                    ),
                ),
            }
        )
        self.devices.store.accept(
            seal(SignaturePurpose.TRUST_LIST, updated, self.devices.owner_key()), "接纳朋友"
        )
        self.devices.store.accept(pairing.roster, "保存朋友的电脑名单")

    def accept_pair(self, token: str, pairing: FriendPairing, source_host: str) -> FriendPairing:
        try:
            with self.devices.changes:
                self.devices.owner_key()
                roster = self._verify_pairing(pairing)
                source = next(
                    (device for device in roster.devices if device.host == source_host), None
                )
                if source is None or any(
                    item.owner_fingerprint == roster.owner_fingerprint
                    for item in self.devices.trusted_people()
                ):
                    raise ValueError
                display_name = self.devices.store.consume_friend_invite(
                    hashlib.sha256(token.encode()).digest(), source.node_id, self.devices.clock()
                )
                if display_name is None:
                    raise ValueError
                response = self.pairing(display_name)
                self._save_pairing(pairing)
                return response
        except ValueError:
            raise IdentityError(INVALID_INVITE) from None

    def install_pair(self, code: JoinCode, pairing: FriendPairing) -> None:
        with self.devices.changes:
            self.devices.owner_key()
            roster = self._verify_pairing(pairing)
            inviter = roster.device(code.inviter_node_id)
            if (
                roster.owner_fingerprint != code.owner_fingerprint
                or inviter is None
                or inviter.host != code.host
                or inviter.port != code.port
            ):
                raise VerificationError("配对响应与配对码中的机主身份不符")
            self._save_pairing(pairing)

    async def join(self, code: JoinCode, display_name: str | None = None) -> None:
        request = self.pairing(display_name)
        if (
            code.kind is not JoinCodeKind.FRIEND
            or code.expires_at.tzinfo is None
            or code.expires_at <= self.devices.clock()
        ):
            raise IdentityError("配对码无效或已过期，请重新生成")
        bind = GatewayBindConfig(host=code.host, port=code.port)
        local = self.devices.roster().device(self.devices.node_id)
        assert local is not None
        try:
            async with httpx.AsyncClient(
                base_url=httpx.URL(scheme="http", host=bind.host, port=bind.port),
                transport=self.devices.transport
                or httpx.AsyncHTTPTransport(local_address=local.host),
                timeout=15,
                trust_env=False,
            ) as client:
                response = await client.post(
                    "/v1/friends:pair",
                    content=request.model_dump_json(),
                    headers={
                        "Authorization": f"Bearer {code.token}",
                        "Content-Type": "application/json",
                    },
                )
            if response.status_code == 429:
                raise IdentityError("请求太频繁，请一分钟后再试")
            if response.status_code != 200:
                raise IdentityError(INVALID_INVITE)
            if len(response.content) > 512_000:
                raise ValueError
            pairing = FriendPairing.model_validate_json(response.content)
        except httpx.HTTPError:
            raise IdentityError("连不上邀请方的电脑") from None
        except ValueError as exc:
            if isinstance(exc, IdentityError):
                raise
            raise IdentityError("配对响应格式无效") from None
        # 写钥匙串可能要等主人点授权框，放到线程里，网页不会因此卡住。
        await asyncio.to_thread(self.install_pair, code, pairing)
        await self.devices.push()

    def resolve(self, value: str) -> TrustedPerson:
        matches = [
            item
            for item in self.devices.trusted_people()
            if value in (item.owner_fingerprint, item.display_name)
        ]
        if len(matches) != 1:
            raise IdentityError("朋友不存在或显示名重复，请使用完整朋友指纹")
        return matches[0]

    def resolve_conflict(self, node_id: NodeId, value: str) -> tuple[TrustedPerson, ...]:
        """撞号时由本机指定这个节点编号归哪个朋友，返回不再认这台电脑的其他朋友。

        只在本机生效，不改任何人的签名名单；被判给的朋友以后不再声称这个编号时，判定自然失效。
        """
        with self.devices.changes:
            winner = self.resolve(value)
            claimants = [
                friend
                for friend, roster in self.devices.claimed_friends()
                if roster.device(node_id) is not None
            ]
            if all(item.owner_fingerprint != winner.owner_fingerprint for item in claimants):
                raise IdentityError("这个朋友的名单里没有这台电脑")
            others = tuple(
                item for item in claimants if item.owner_fingerprint != winner.owner_fingerprint
            )
            if not others:
                raise IdentityError("这个节点编号没有和其他朋友冲突")
            self.devices.store.assign_friend_node(
                node_id,
                winner.owner_fingerprint,
                tuple(item.owner_fingerprint for item in others),
                f"本机手动处理编号冲突：{node_id} 归 {_label(winner)}，不再认 "
                + "、".join(_label(item) for item in others)
                + " 名单里的同号电脑",
            )
            return others

    def remove(self, value: str) -> None:
        with self.devices.changes:
            key = self.devices.owner_key()
            friend = self.resolve(value)
            trust = self.devices.trust_list()
            updated = trust.model_copy(
                update={
                    "version": trust.version + 1,
                    "issued_at": self.devices.clock(),
                    "people": tuple(
                        item for item in self.devices.trusted_people() if item != friend
                    ),
                }
            )
            self.devices.store.accept(seal(SignaturePurpose.TRUST_LIST, updated, key), "移除朋友")

    def permissions(self, value: str, permissions: FriendPermissions) -> None:
        with self.devices.changes:
            key = self.devices.owner_key()
            friend = self.resolve(value)
            trust = self.devices.trust_list()
            updated = trust.model_copy(
                update={
                    "version": trust.version + 1,
                    "issued_at": self.devices.clock(),
                    "people": tuple(
                        item.model_copy(update={"permissions": permissions})
                        if item == friend
                        else item
                        for item in self.devices.trusted_people()
                    ),
                }
            )
            self.devices.store.accept(
                seal(SignaturePurpose.TRUST_LIST, updated, key), "修改朋友权限"
            )

    def rename(self, value: str, display_name: str) -> None:
        """在本机给朋友改一个显示名，不沿用对方自己报上来的名字。"""
        with self.devices.changes:
            key = self.devices.owner_key()
            friend = self.resolve(value)
            trust = self.devices.trust_list()
            updated = trust.model_copy(
                update={
                    "version": trust.version + 1,
                    "issued_at": self.devices.clock(),
                    "people": tuple(
                        TrustedPerson.model_validate(
                            {**item.model_dump(), "display_name": display_name}
                        )
                        if item == friend
                        else item
                        for item in trust.people
                    ),
                }
            )
            self.devices.store.accept(
                seal(SignaturePurpose.TRUST_LIST, updated, key), "修改朋友显示名"
            )

    def restrict(self, value: str, permissions: FriendPermissions) -> None:
        friend = self.resolve(value)
        if permissions.daily_quota > friend.permissions.daily_quota or any(
            permissions.model_dump()[name] and not friend.permissions.model_dump()[name]
            for name in ("allow_delegation", "allow_model_borrowing")
        ):
            raise IdentityError("朋友权限只能关闭或调小")
        self.devices.store.restrict_friend(friend.owner_fingerprint, permissions)
