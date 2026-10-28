"""本机初始化和状态查询，不启动网关或连接其他电脑。"""

from __future__ import annotations

from datetime import UTC, datetime

from tunnelminion.domain.identifiers import NodeId
from tunnelminion.domain.tools import Platform
from tunnelminion.domain.trust import (
    DeviceCertificate,
    DeviceEntry,
    OwnerRoster,
    SignaturePurpose,
    TrustList,
    key_fingerprint,
)
from tunnelminion.gateway.security import GatewayBindConfig
from tunnelminion.model.secrets import SecretStore
from tunnelminion.trust.contracts import (
    AlreadyInitializedError,
    IdentityError,
    IdentityStatus,
    TrustStore,
)
from tunnelminion.trust.keys import (
    DEVICE_KEY_NAME,
    OWNER_KEY_NAME,
    InitializationKeys,
    delete_private_key,
    load_private_key,
    save_private_key,
)
from tunnelminion.trust.signatures import seal, verify_owner_roster, verify_trust_list


def ensure_no_identity_keys(secrets: SecretStore) -> None:
    """钥匙串里已有身份密钥时拒绝初始化，避免覆盖。"""
    for name in (OWNER_KEY_NAME, DEVICE_KEY_NAME):
        if load_private_key(secrets, name) is not None:
            raise AlreadyInitializedError("本机已有身份密钥，不能重复初始化")


class OwnerIdentityService:
    """初始化本机机主身份并查询状态。"""

    def __init__(self, store: TrustStore, secrets: SecretStore) -> None:
        self._store = store
        self._secrets = secrets

    def ensure_uninitialized(self) -> None:
        if self._store.owner_fingerprint() is not None:
            raise AlreadyInitializedError("本机身份已经初始化，不能重复初始化")
        ensure_no_identity_keys(self._secrets)

    def init(
        self,
        node_id: NodeId,
        bind: GatewayBindConfig,
        display_name: str,
        keys: InitializationKeys,
        platform: Platform | None = None,
    ) -> IdentityStatus:
        """生成版本 1 的两份名单和本机证书；密钥在同一事务内写入钥匙串，失败时一并清理。"""
        self.ensure_uninitialized()
        now = datetime.now(UTC)
        owner_fingerprint = key_fingerprint(keys.owner.public_key)
        roster = OwnerRoster(
            owner_public_key=keys.owner.public_key,
            recovery_fingerprint=keys.recovery_fingerprint,
            version=1,
            issued_at=now,
            devices=(
                DeviceEntry(
                    node_id=node_id,
                    display_name=display_name,
                    platform=platform,
                    device_public_key=keys.device.public_key,
                    host=bind.host,
                    port=bind.port,
                    added_at=now,
                ),
            ),
        )
        trust_list = TrustList(owner_fingerprint=owner_fingerprint, version=1, issued_at=now)
        certificate = DeviceCertificate(
            owner_fingerprint=owner_fingerprint,
            node_id=node_id,
            device_public_key=keys.device.public_key,
            issued_at=now,
        )
        written: list[str] = []

        def persist_keys() -> None:
            ensure_no_identity_keys(self._secrets)
            for name, key in ((OWNER_KEY_NAME, keys.owner), (DEVICE_KEY_NAME, keys.device)):
                written.append(name)
                save_private_key(self._secrets, name, key)

        try:
            self._store.initialize(
                owner_fingerprint,
                seal(SignaturePurpose.OWNER_ROSTER, roster, keys.owner),
                seal(SignaturePurpose.TRUST_LIST, trust_list, keys.owner),
                seal(SignaturePurpose.DEVICE_CERTIFICATE, certificate, keys.owner),
                persist_keys,
            )
        except Exception:
            for name in reversed(written):
                delete_private_key(self._secrets, name)
            raise
        return self.status()

    def status(self) -> IdentityStatus:
        """读取并重新验签本机名单，返回不含私钥的状态。"""
        owner = self._store.owner_fingerprint()
        if owner is None:
            return IdentityStatus()
        roster_envelope = self._store.load(SignaturePurpose.OWNER_ROSTER)
        trust_envelope = self._store.load(SignaturePurpose.TRUST_LIST)
        if roster_envelope is None or trust_envelope is None:
            raise IdentityError("本机身份记录不完整")
        roster = verify_owner_roster(roster_envelope, owner)
        trust_list = verify_trust_list(trust_envelope, roster.owner_public_key, owner)
        key = load_private_key(self._secrets, OWNER_KEY_NAME)
        return IdentityStatus(
            owner_fingerprint=owner,
            has_owner_key=key is not None and key_fingerprint(key.public_key) == owner,
            roster_version=roster.version,
            trust_list_version=trust_list.version,
            devices=roster.devices,
        )
