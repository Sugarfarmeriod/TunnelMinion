"""用纯数据 fixture 比较 Windows 与 macOS 的 Provider 生命周期语义。"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from enum import StrEnum


class Platform(StrEnum):
    """首轮受管 Provider 平台。"""

    WINDOWS = "windows"
    MACOS = "macos"


class Action(StrEnum):
    """生命周期 spike 覆盖的变化。"""

    CREATE = "create"
    REPLACE = "replace"
    STOP = "stop"
    DELETE = "delete"


@dataclass(frozen=True)
class LifecycleSemantics:
    """不含秘密和动态命令的固定生命周期描述。"""

    platform: Platform
    action: Action
    fixed_steps: tuple[str, ...]
    verification: tuple[str, ...]
    rollback: tuple[str, ...]
    permission: str
    atomic: bool
    notes: tuple[str, ...] = ()


@dataclass(frozen=True)
class RecoveryDecision:
    """根据回执与实时所有权决定是否可以自动恢复。"""

    state: str
    rollback_steps: tuple[str, ...]
    reason: str


def windows_semantics(action: Action) -> LifecycleSemantics:
    """返回 Windows 官方 tunnel service 的预期语义。"""
    values = {
        Action.CREATE: LifecycleSemantics(
            platform=Platform.WINDOWS,
            action=action,
            fixed_steps=(
                "write_acl_restricted_revision_config",
                "install_revision_tunnel_service",
                "wait_service_running",
            ),
            verification=("read_service", "read_adapter", "read_address", "read_host_routes"),
            rollback=("uninstall_owned_tunnel_service", "delete_owned_revision_config"),
            permission="administrator_or_local_system",
            atomic=False,
            notes=("manager_may_convert_conf_to_dpapi",),
        ),
        Action.REPLACE: LifecycleSemantics(
            platform=Platform.WINDOWS,
            action=action,
            fixed_steps=(
                "stop_owned_tunnel_service",
                "uninstall_owned_tunnel_service",
                "install_new_revision_tunnel_service",
                "wait_service_running",
            ),
            verification=("read_service", "read_adapter", "read_peer", "read_host_routes"),
            rollback=(
                "uninstall_failed_revision",
                "install_parent_revision_tunnel_service",
                "verify_parent_revision",
            ),
            permission="administrator_or_local_system",
            atomic=False,
            notes=("service_and_route_replacement_has_no_cross_step_atomicity",),
        ),
        Action.STOP: LifecycleSemantics(
            platform=Platform.WINDOWS,
            action=action,
            fixed_steps=("stop_owned_tunnel_service",),
            verification=("read_service_stopped", "read_adapter_absent"),
            rollback=("start_owned_tunnel_service", "verify_parent_revision"),
            permission="administrator_or_local_system",
            atomic=False,
        ),
        Action.DELETE: LifecycleSemantics(
            platform=Platform.WINDOWS,
            action=action,
            fixed_steps=(
                "uninstall_owned_tunnel_service",
                "delete_owned_revision_config",
                "delete_owned_secret_reference",
            ),
            verification=("read_service_absent", "read_adapter_absent", "read_secret_absent"),
            rollback=(),
            permission="administrator_or_local_system",
            atomic=False,
            notes=("delete_requires_double_ownership_evidence",),
        ),
    }
    return values[action]


def macos_semantics(action: Action) -> LifecycleSemantics:
    """返回 macOS wireguard-go/wg-quick 的预期语义。"""
    values = {
        Action.CREATE: LifecycleSemantics(
            platform=Platform.MACOS,
            action=action,
            fixed_steps=(
                "write_mode_0600_revision_config_without_hooks",
                "wg_quick_up_managed_config",
                "record_kernel_assigned_utun_name",
            ),
            verification=("read_utun", "read_address", "read_peer", "read_host_routes"),
            rollback=("wg_quick_down_owned_config", "delete_owned_revision_config"),
            permission="network_administrator_without_interactive_sudo",
            atomic=False,
            notes=("fixed_absolute_tool_paths", "wg_tun_name_file_records_actual_utun"),
        ),
        Action.REPLACE: LifecycleSemantics(
            platform=Platform.MACOS,
            action=action,
            fixed_steps=(
                "wg_syncconf_peer_delta",
                "reconcile_owned_addresses",
                "reconcile_owned_host_routes",
            ),
            verification=("read_utun", "read_address", "read_peer", "read_host_routes"),
            rollback=("wg_syncconf_parent", "restore_parent_addresses", "restore_parent_routes"),
            permission="network_administrator_without_interactive_sudo",
            atomic=False,
            notes=("syncconf_does_not_manage_wg_quick_addresses_or_routes",),
        ),
        Action.STOP: LifecycleSemantics(
            platform=Platform.MACOS,
            action=action,
            fixed_steps=("wg_quick_down_owned_config",),
            verification=("read_utun_absent", "read_owned_routes_absent"),
            rollback=("wg_quick_up_parent_config", "verify_parent_revision"),
            permission="network_administrator_without_interactive_sudo",
            atomic=False,
        ),
        Action.DELETE: LifecycleSemantics(
            platform=Platform.MACOS,
            action=action,
            fixed_steps=(
                "wg_quick_down_owned_config",
                "delete_owned_revision_config",
                "delete_owned_secret_reference",
            ),
            verification=("read_utun_absent", "read_owned_routes_absent", "read_secret_absent"),
            rollback=(),
            permission="network_administrator_without_interactive_sudo",
            atomic=False,
            notes=("delete_requires_double_ownership_evidence",),
        ),
    }
    return values[action]


def decide_recovery(
    semantics: LifecycleSemantics,
    *,
    confirmed_step_count: int,
    ownership_matches: bool,
) -> RecoveryDecision:
    """只根据已确认回执回滚；所有权变化时停止自动清理。"""
    if confirmed_step_count < 0 or confirmed_step_count > len(semantics.fixed_steps):
        raise ValueError("confirmed_step_count 超出固定步骤范围")
    if not ownership_matches:
        return RecoveryDecision(
            state="manual_intervention",
            rollback_steps=(),
            reason="ownership_conflict",
        )
    if confirmed_step_count == 0:
        return RecoveryDecision(
            state="unchanged",
            rollback_steps=(),
            reason="no_confirmed_write",
        )
    return RecoveryDecision(
        state="rolling_back",
        rollback_steps=semantics.rollback,
        reason="confirmed_partial_success",
    )


def build_report() -> dict[str, object]:
    """构建可提交的无秘密 spike 报告。"""
    matrix = [
        asdict(builder(action))
        for builder in (windows_semantics, macos_semantics)
        for action in Action
    ]
    failure_cases = {
        "response_lost_after_create": asdict(
            decide_recovery(
                windows_semantics(Action.CREATE),
                confirmed_step_count=3,
                ownership_matches=True,
            )
        ),
        "peer_step_failed": asdict(
            decide_recovery(
                macos_semantics(Action.REPLACE),
                confirmed_step_count=1,
                ownership_matches=True,
            )
        ),
        "resource_replaced_externally": asdict(
            decide_recovery(
                windows_semantics(Action.DELETE),
                confirmed_step_count=1,
                ownership_matches=False,
            )
        ),
    }
    return {
        "schema_version": "managed-connectivity-lifecycle-spike.v1",
        "mode": "fake_no_system_writes",
        "matrix": matrix,
        "failure_cases": failure_cases,
        "conclusion": {
            "cross_platform_atomic_replace": False,
            "command_exit_is_verification": False,
            "rollback_uses_confirmed_receipts_only": True,
            "ownership_conflict_stops_cleanup": True,
        },
    }


def main() -> None:
    """向标准输出写入确定性 JSON，供评估报告生成。"""
    print(json.dumps(build_report(), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
