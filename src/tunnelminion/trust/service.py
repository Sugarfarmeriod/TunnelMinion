"""本机初始化和状态查询，不启动网关或连接其他电脑。"""

from __future__ import annotations

from collections.abc import Mapping
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
from tunnelminion.trust.backup import (
    BACKUP_KEPT,
    IdentityState,
    discard_backup,
    identity_state,
    new_backup,
    read_backup,
    restore_keys,
    settle_key_backup,
    write_backup,
)
from tunnelminion.trust.contracts import (
    AlreadyInitializedError,
    IdentityError,
    IdentityStatus,
    TrustStore,
)
from tunnelminion.trust.keys import (
    DEVICE_KEY_NAME,
    IDENTITY_KEY_NAMES,
    OWNER_KEY_NAME,
    InitializationKeys,
    PrivateKey,
    delete_private_key,
    load_private_key,
    save_private_key,
)
from tunnelminion.trust.signatures import seal, verify_owner_roster, verify_trust_list


def ensure_no_identity_keys(secrets: SecretStore) -> None:
    """钥匙串里已有身份密钥时拒绝初始化，避免覆盖。"""
    for name in IDENTITY_KEY_NAMES:
        if load_private_key(secrets, name) is not None:
            raise AlreadyInitializedError("本机已有身份密钥，不能重复初始化")


class IdentityKeySwap:
    """把本机身份密钥换成新的；数据库事务提交前留一份旧密钥备份，失败时逐把恢复。

    `replaced` 列出要换掉的旧密钥（可能在另一个秘密后端 `previous_secrets` 里），为空时要求本机
    原本没有身份密钥。`after` 是事务提交后数据库里应有的身份，中断后据此判断事务是否已经生效。
    `persist` 在数据库事务内调用；事务成功后调用 `commit` 删掉备份，失败时调用 `rollback`。
    """

    def __init__(
        self,
        store: TrustStore,
        secrets: SecretStore,
        keys: Mapping[str, PrivateKey],
        after: IdentityState,
        *,
        replaced: tuple[str, ...] = (),
        previous_secrets: SecretStore | None = None,
    ) -> None:
        self._store = store
        self._secrets = secrets
        self._keys = dict(keys)
        self._after = after
        self._previous_secrets = previous_secrets or secrets
        settle_key_backup(store, self._previous_secrets)
        self._previous = {name: load_private_key(self._previous_secrets, name) for name in replaced}
        self._touched = False
        self._backed_up = False

    def persist(self) -> None:
        if not self._previous:
            ensure_no_identity_keys(self._secrets)
        else:
            if read_backup(self._previous_secrets) is not None:
                raise IdentityError("上次换身份密钥留下的备份还没处理完，请稍后重试")
            write_backup(
                self._previous_secrets,
                new_backup(identity_state(self._store), self._after, self._previous),
            )
            self._backed_up = True
        self._touched = True
        for name in self._previous:
            delete_private_key(self._previous_secrets, name)
        for name, key in self._keys.items():
            save_private_key(self._secrets, name, key)

    def commit(self) -> None:
        if self._backed_up:
            discard_backup(self._previous_secrets)
            self._backed_up = False

    def rollback(self) -> None:
        """每把密钥单独恢复；有没恢复的就保留备份并统一报错。"""
        if not self._touched:
            return
        restore_keys(
            self._previous_secrets,
            self._previous,
            written=self._secrets,
            written_names=self._keys,
            note=BACKUP_KEPT if self._backed_up else "",
        )
        self.commit()


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
        *,
        replace: bool = False,
        previous_secrets: SecretStore | None = None,
    ) -> IdentityStatus:
        """生成版本 1 的两份名单和本机证书；密钥在同一事务内写入钥匙串，失败时一并清理。

        `replace` 为真时，在同一个事务里替换掉本机旧身份；失败时旧身份和旧密钥原样保留。
        """
        if not replace:
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
        swap = IdentityKeySwap(
            self._store,
            self._secrets,
            {OWNER_KEY_NAME: keys.owner, DEVICE_KEY_NAME: keys.device},
            IdentityState(
                owner_fingerprint=owner_fingerprint, device_public_key=keys.device.public_key
            ),
            replaced=IDENTITY_KEY_NAMES if replace else (),
            previous_secrets=previous_secrets,
        )
        try:
            self._store.initialize(
                owner_fingerprint,
                seal(SignaturePurpose.OWNER_ROSTER, roster, keys.owner),
                seal(SignaturePurpose.TRUST_LIST, trust_list, keys.owner),
                seal(SignaturePurpose.DEVICE_CERTIFICATE, certificate, keys.owner),
                swap.persist,
                replace=replace,
            )
        except Exception:
            swap.rollback()
            raise
        swap.commit()
        return self.status()

    def status(self) -> IdentityStatus:
        """读取并重新验签本机名单，返回不含私钥的状态。"""
        settle_key_backup(self._store, self._secrets)
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
            removed=self._store.load(SignaturePurpose.DEVICE_CERTIFICATE) is None,
        )

    def reset(self) -> None:
        """清除两把身份密钥；数据库或钥匙串失败时保留原身份。"""
        swap = IdentityKeySwap(
            self._store, self._secrets, {}, IdentityState(), replaced=IDENTITY_KEY_NAMES
        )
        try:
            self._store.reset(swap.persist)
        except Exception:
            swap.rollback()
            raise
        swap.commit()
