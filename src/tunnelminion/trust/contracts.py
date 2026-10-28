"""本机身份存储接口与不含秘密的状态、审计记录。"""

from collections.abc import Callable
from datetime import datetime
from typing import Protocol

from pydantic import BaseModel, ConfigDict, Field

from tunnelminion.domain.identifiers import NodeId
from tunnelminion.domain.invites import DisplayName
from tunnelminion.domain.model_borrowing import DEFAULT_DAILY_TOKEN_QUOTA
from tunnelminion.domain.tools import Platform
from tunnelminion.domain.trust import (
    DeviceEntry,
    Fingerprint,
    FriendPermissions,
    PublicKeyText,
    SignaturePurpose,
    SignedEnvelope,
)


class IdentityError(ValueError):
    """本机身份操作无法完成。"""


class AlreadyInitializedError(IdentityError):
    """已有身份或身份密钥，不得覆盖。"""


class VersionRejectedError(IdentityError):
    """名单版本没有严格增加。"""


class IdentityStatus(BaseModel):
    """`owner status` 展示的本机身份，不含任何私钥。"""

    model_config = ConfigDict(frozen=True)

    owner_fingerprint: str | None = None
    has_owner_key: bool = False
    roster_version: int | None = None
    trust_list_version: int | None = None
    devices: tuple[DeviceEntry, ...] = ()
    removed: bool = False


class DevicePermissions(BaseModel):
    """本机对我的电脑设置的权限上限，只能进一步收紧。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    allow_delegation: bool = True
    allow_model_borrowing: bool = True
    allow_proxy_repair_approval: bool = True
    daily_quota: int = Field(default=DEFAULT_DAILY_TOKEN_QUOTA, ge=1, le=DEFAULT_DAILY_TOKEN_QUOTA)


class OwnerJoinRequest(BaseModel):
    """新电脑报到资料和持有电脑私钥的证明。"""

    node_id: NodeId
    platform: Platform
    display_name: DisplayName
    host: str
    port: int = Field(ge=1024, le=65535)
    device_public_key: str
    proof: SignedEnvelope


class TrustSyncMessage(BaseModel):
    """可独立验签和比较版本的本机与朋友名单。"""

    roster: SignedEnvelope | None = None
    trust_list: SignedEnvelope | None = None
    friend_rosters: tuple[SignedEnvelope, ...] = ()


class FriendPairing(BaseModel):
    """配对双方只交换公开身份和各自签名的电脑名单。"""

    owner_public_key: PublicKeyText
    recovery_fingerprint: Fingerprint
    display_name: DisplayName
    roster: SignedEnvelope


class OwnerJoinResponse(BaseModel):
    """加入成功后交给新电脑验证的机主签名材料。"""

    certificate: SignedEnvelope
    roster: SignedEnvelope
    trust_list: SignedEnvelope


class TrustAudit(BaseModel):
    """一次名单变化的审计记录，不含秘密。"""

    model_config = ConfigDict(frozen=True)

    action: str = "accept"
    kind: SignaturePurpose
    version: int
    signer_fingerprint: str
    subjects: tuple[str, ...]
    reason: str
    occurred_at: datetime


class TrustStore(Protocol):
    """本机信任锚、已接受名单和证书的存储。"""

    def owner_fingerprint(self) -> str | None: ...

    def load(self, kind: SignaturePurpose) -> SignedEnvelope | None: ...

    def initialize(
        self,
        owner_fingerprint: str,
        roster: SignedEnvelope,
        trust_list: SignedEnvelope,
        certificate: SignedEnvelope,
        persist_keys: Callable[[], None],
    ) -> None: ...

    def accept(self, envelope: SignedEnvelope, reason: str) -> None: ...

    def create_invite(self, digest: bytes, expires_at: datetime) -> None: ...

    def consume_invite(self, digest: bytes, node_id: NodeId, now: datetime) -> bool: ...

    def device_permissions(self, node_id: NodeId) -> DevicePermissions: ...

    def restrict_device(self, node_id: NodeId, permissions: DevicePermissions) -> None: ...

    def friend_rosters(self) -> tuple[SignedEnvelope, ...]: ...

    def friend_permissions(self, owner_fingerprint: str) -> FriendPermissions: ...

    def restrict_friend(self, owner_fingerprint: str, permissions: FriendPermissions) -> None: ...

    def create_friend_invite(
        self, digest: bytes, expires_at: datetime, display_name: str
    ) -> None: ...

    def consume_friend_invite(
        self, digest: bytes, node_id: NodeId, now: datetime
    ) -> str | None: ...

    def was_own_device(self, node_id: NodeId) -> bool: ...

    def was_friend_device(self, node_id: NodeId, host: str | None) -> bool: ...
