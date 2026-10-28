"""换身份密钥时的旧密钥备份：事务提交前留底，中断后按数据库里的身份还原或清理。

钥匙串和数据库无法放进同一个事务。换密钥时先把旧密钥连同时间戳、换之前和换之后的身份写进
一条备份，再改钥匙串，数据库事务提交后才删备份。进程在两者之间被杀或断电时，下次读取身份会
看到这条备份：数据库仍是换之前的身份就把旧密钥写回去；已经是换之后的身份就删掉备份；两者都
对不上时保留备份并报错，交给人核对。
"""

from __future__ import annotations

import logging
from collections.abc import Iterable, Mapping
from datetime import UTC, datetime

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from tunnelminion.domain.trust import SignaturePurpose
from tunnelminion.model.secrets import SecretStore, SecretStoreError
from tunnelminion.trust.contracts import IdentityError, TrustStore
from tunnelminion.trust.keys import DEVICE_KEY_NAME, OWNER_KEY_NAME, PrivateKey

logger = logging.getLogger(__name__)

KEY_BACKUP_NAME = "trust-key-backup"
_LABELS = {OWNER_KEY_NAME: "机主密钥", DEVICE_KEY_NAME: "电脑密钥"}
BACKUP_KEPT = "；旧密钥备份已保留，下次读取身份时会再次尝试还原"


class IdentityState(BaseModel):
    """数据库里决定身份密钥是否匹配的两项：机主指纹和本机证书里的电脑公钥。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    owner_fingerprint: str | None = None
    device_public_key: str | None = None


class KeyBackup(BaseModel):
    """一次换密钥留下的旧密钥；值为空表示换之前没有这把密钥。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    created_at: datetime
    before: IdentityState
    after: IdentityState
    keys: dict[str, str | None] = Field(repr=False)


def identity_state(store: TrustStore) -> IdentityState:
    owner = store.owner_fingerprint()
    if owner is None:
        return IdentityState()
    certificate = store.load(SignaturePurpose.DEVICE_CERTIFICATE)
    device = certificate.payload.get("device_public_key") if certificate is not None else None
    return IdentityState(
        owner_fingerprint=owner, device_public_key=device if isinstance(device, str) else None
    )


def key_labels(names: Iterable[str]) -> str:
    return "、".join(_LABELS.get(name, name) for name in names)


def read_backup(secrets: SecretStore) -> KeyBackup | None:
    try:
        text = secrets.get(KEY_BACKUP_NAME)
        return KeyBackup.model_validate_json(text) if text is not None else None
    except (ValidationError, ValueError):
        raise SecretStoreError("身份密钥备份已损坏，已保留原样，请人工核对") from None
    except Exception:
        raise SecretStoreError("无法读取身份密钥备份") from None


def write_backup(secrets: SecretStore, backup: KeyBackup) -> None:
    try:
        secrets.set(KEY_BACKUP_NAME, backup.model_dump_json())
    except Exception:
        raise SecretStoreError("无法保存身份密钥备份，未改动身份密钥") from None


def discard_backup(secrets: SecretStore) -> None:
    """换密钥已经生效，备份只是多余的旧密钥；删不掉时下次读取身份会再清理。"""
    try:
        secrets.delete(KEY_BACKUP_NAME)
    except Exception:
        logger.warning("没能删除身份密钥备份，下次读取身份时会再清理")


def restore_keys(
    secrets: SecretStore,
    keys: Mapping[str, PrivateKey | None],
    *,
    written: SecretStore | None = None,
    written_names: Iterable[str] = (),
    note: str = "",
) -> None:
    """逐把写回旧密钥，一把失败不影响其他；全部做完后统一报出没处理好的密钥。

    `keys` 里值为空表示换之前没有这把密钥，要删掉。`written` 是新密钥所在的秘密存储（可能和旧密钥
    不是同一个后端），`written_names` 里的新密钥在旧密钥没有覆盖它们时删掉。
    """
    target = written or secrets
    names = tuple(written_names)
    failed: list[str] = []
    for name in dict.fromkeys((*keys, *names)):
        key = keys.get(name)
        try:
            if key is not None:
                secrets.set(name, key.seed_text())
            if name in names and (key is None or target is not secrets):
                target.delete(name)
            elif key is None:
                secrets.delete(name)
        except Exception:
            failed.append(name)
    if failed:
        raise SecretStoreError(f"身份密钥没有全部还原：{key_labels(failed)}没能恢复原样{note}")


def settle_key_backup(store: TrustStore, secrets: SecretStore) -> None:
    """读取身份前处理上次换密钥中断留下的备份；没有备份时只多一次秘密存储读取。"""
    if read_backup(secrets) is None:
        return
    # 拿数据库写锁再判断，避免把另一个进程正在进行（尚未提交）的换密钥当成中断。
    store.exclusive(lambda: _settle(store, secrets))


def _settle(store: TrustStore, secrets: SecretStore) -> None:
    backup = read_backup(secrets)
    if backup is None:
        return
    state = identity_state(store)
    if state == backup.after:
        discard_backup(secrets)
        return
    if state.owner_fingerprint != backup.before.owner_fingerprint:
        raise IdentityError(
            f"秘密存储里有一份 {backup.created_at:%Y-%m-%d %H:%M:%S} 换身份密钥时留下的旧密钥"
            "备份，但和本机数据库里的身份对不上；备份已保留，请先核对本机身份"
        )
    try:
        keys = {
            name: PrivateKey.from_seed_text(seed) if seed is not None else None
            for name, seed in backup.keys.items()
        }
    except ValueError:
        raise SecretStoreError("身份密钥备份已损坏，已保留原样，请人工核对") from None
    restore_keys(secrets, keys, note=BACKUP_KEPT)
    discard_backup(secrets)
    logger.warning("上次换身份密钥没有完成，已用 %s 的备份还原旧密钥", backup.created_at)


def new_backup(
    before: IdentityState, after: IdentityState, keys: Mapping[str, PrivateKey | None]
) -> KeyBackup:
    return KeyBackup(
        created_at=datetime.now(UTC),
        before=before,
        after=after,
        keys={name: key.seed_text() if key is not None else None for name, key in keys.items()},
    )
