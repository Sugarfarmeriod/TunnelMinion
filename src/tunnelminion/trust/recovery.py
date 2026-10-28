"""恢复密钥仅在内存中签换钥匙声明，不写入任何秘密存储。"""

from __future__ import annotations

from tunnelminion.domain.identifiers import NodeId
from tunnelminion.domain.trust import (
    DeviceEntry,
    OwnerRoster,
    OwnerRotation,
    SignaturePurpose,
    key_fingerprint,
)
from tunnelminion.trust.contracts import IdentityError, OwnerRotationStep
from tunnelminion.trust.devices import OwnDevicesService
from tunnelminion.trust.keys import (
    DEVICE_KEY_NAME,
    OWNER_KEY_NAME,
    PrivateKey,
    RecoveryCodeError,
    delete_private_key,
    load_private_key,
    parse_recovery_code,
    save_private_key,
)
from tunnelminion.trust.signatures import seal


def recovery_key(roster: OwnerRoster, code: str) -> PrivateKey:
    """损坏、校验失败和属于其他机主的恢复码统一拒绝，不回显输入。"""
    try:
        key = parse_recovery_code(code)
    except RecoveryCodeError:
        raise IdentityError("恢复码无效") from None
    if key_fingerprint(key.public_key) != roster.recovery_fingerprint:
        raise IdentityError("恢复码无效")
    return key


def check_recovery_devices(
    roster: OwnerRoster, node_id: NodeId, remove: tuple[NodeId, ...]
) -> None:
    if roster.device(node_id) is None:
        raise IdentityError("只能在我的电脑名单上的电脑恢复")
    if node_id in remove:
        raise IdentityError("不能移除本机")
    if any(roster.device(item) is None for item in remove):
        raise IdentityError("我的电脑名单里没有这个节点")


def recover_owner(
    service: OwnDevicesService,
    old_recovery: PrivateKey,
    new_owner: PrivateKey,
    new_recovery: PrivateKey,
    remove: tuple[NodeId, ...] = (),
) -> tuple[DeviceEntry, ...]:
    """确认新恢复码后才调用；换信任锚与保存新机主密钥共用写事务。"""
    with service.changes:
        roster = service.roster()
        if key_fingerprint(old_recovery.public_key) != roster.recovery_fingerprint:
            raise IdentityError("恢复码无效")
        check_recovery_devices(roster, service.node_id, remove)
        local = roster.device(service.node_id)
        device_key = load_private_key(service.secrets, DEVICE_KEY_NAME)
        if (
            not service.active()
            or device_key is None
            or local is None
            or local.device_public_key != device_key.public_key
        ):
            raise IdentityError("本机电脑身份无效，不能恢复")
        now = service.clock()
        updated = roster.model_copy(
            update={
                "owner_public_key": new_owner.public_key,
                "recovery_fingerprint": key_fingerprint(new_recovery.public_key),
                "version": roster.version + 1,
                "issued_at": now,
                "devices": tuple(item for item in roster.devices if item.node_id not in remove),
            }
        )
        people = service.trust_list()
        people = people.model_copy(
            update={
                "owner_fingerprint": updated.owner_fingerprint,
                "version": people.version + 1,
                "issued_at": now,
                "people": service.trusted_people(),
            }
        )
        step = OwnerRotationStep(
            rotation=seal(
                SignaturePurpose.OWNER_ROTATION,
                OwnerRotation(
                    previous_owner_fingerprint=roster.owner_fingerprint,
                    recovery_public_key=old_recovery.public_key,
                    new_owner_public_key=new_owner.public_key,
                    new_recovery_fingerprint=updated.recovery_fingerprint,
                    issued_at=now,
                ),
                old_recovery,
            ),
            roster=seal(SignaturePurpose.OWNER_ROSTER, updated, new_owner),
        )
        targets = (
            *updated.devices,
            *(item for _, friend_roster in service.friends() for item in friend_roster.devices),
        )
        previous_key = load_private_key(service.secrets, OWNER_KEY_NAME)
        written = False

        def persist() -> None:
            nonlocal written
            written = True
            if previous_key is not None:
                delete_private_key(service.secrets, OWNER_KEY_NAME)
            save_private_key(service.secrets, OWNER_KEY_NAME, new_owner)

        try:
            service.store.rotate(
                (step,),
                step.roster,
                seal(SignaturePurpose.TRUST_LIST, people, new_owner),
                f"本机 {service.node_id} 使用恢复码更换机主密钥",
                persist,
            )
        except Exception:
            if written:
                if previous_key is None:
                    delete_private_key(service.secrets, OWNER_KEY_NAME)
                else:
                    save_private_key(service.secrets, OWNER_KEY_NAME, previous_key)
            raise
        return targets
