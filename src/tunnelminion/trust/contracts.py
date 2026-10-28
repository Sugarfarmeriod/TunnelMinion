"""本机身份存储接口与不含秘密的状态、审计记录。"""

from collections.abc import Callable
from datetime import datetime
from typing import Protocol

from pydantic import BaseModel, ConfigDict

from tunnelminion.domain.trust import DeviceEntry, SignaturePurpose, SignedEnvelope


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
