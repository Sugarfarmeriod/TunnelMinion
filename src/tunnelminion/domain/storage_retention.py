"""每张 SQLite 表的清理规则登记。

常驻程序每轮都可能写库，表只增不减时数据库会一直变大。新增一张表时必须在这里登记它属于哪一类、
为什么不会无限变大；`tests/architecture/test_storage_retention.py` 扫描源码里的全部建表语句，
没有登记、登记了不存在的表、或清理函数找不到时都会失败。
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum


class TableGrowth(StrEnum):
    """表的行数怎样随时间变化。"""

    # 每个现存对象（服务、设备、网络、节点等）一行，覆盖写；对象移除时删行，行数跟着对象数走。
    PER_OBJECT = "per_object"
    # 随时间增长，由 `cleanup` 指向的函数按保留规则自动删除。
    PRUNED = "pruned"
    # 目前没有自动清理；写清增长来源，作为待办跟踪。事件观察、巡检这类每轮都写的库不允许用这一类。
    GROWING = "growing"


@dataclass(frozen=True)
class TableRetention:
    """一张表的增长方式、规则说明和自动清理入口（`模块:类.方法`）。"""

    growth: TableGrowth
    rule: str
    cleanup: str | None = None


def _object(rule: str) -> TableRetention:
    return TableRetention(TableGrowth.PER_OBJECT, rule)


def _pruned(rule: str, cleanup: str) -> TableRetention:
    return TableRetention(TableGrowth.PRUNED, rule, cleanup)


def _growing(rule: str) -> TableRetention:
    return TableRetention(TableGrowth.GROWING, rule)


_INCIDENT_PRUNE = "tunnelminion.incident.storage:SQLiteIncidentStore.prune_batch"
_OPERATION = "每个操作一行或几行，随主人发起的操作增长；目前不自动清理"

SQLITE_TABLE_RETENTION: Mapping[str, TableRetention] = {
    # incidents.sqlite3：后台观察每轮都写。
    "incident_snapshots": _pruned(
        "只留最新一份和最近 50 条事件、正在调查的事件引用的快照", _INCIDENT_PRUNE
    ),
    "incidents": _pruned(
        "按最后观察时间保留 30 天、最多 500 条，调查进行中的不删", _INCIDENT_PRUNE
    ),
    "incident_threads": _pruned("随事件一起删除", _INCIDENT_PRUNE),
    "incident_store_meta": _object("少量固定键，清理完成后撤掉"),
    # patrol.sqlite3：巡检每轮都写。
    "patrol_services": _object("每个被巡检的服务一行，服务移除时删除"),
    "patrol_investigations": _pruned(
        "每天一行计数，只留最近 7 天",
        "tunnelminion.patrol.storage:SQLitePatrolStore.take_investigation",
    ),
    # runtime.sqlite3：对话、修复、信任与好友。
    "checkpoints": _growing("每次对话运行一行，主人删除对话时删除"),
    "tool_artifacts": _growing("工具产出的大结果，每个一行，随对话增长"),
    "long_term_memories": _object("主人确认保存的长期记忆，主人删除时删除"),
    "delegations": _growing("每次授权委托一行，随主人操作增长"),
    "service_marks": _object("每个被主人标记的服务一行，取消标记时删除"),
    "launch_records": _object("每个启动过的脚本或程序一行，移除服务时删除"),
    "model_usage": _growing("每台借用模型的电脑每天一行计数"),
    "repairs": _growing("每次修复一行，随修复次数增长"),
    "requester_operations": _growing(_OPERATION),
    "operations": _growing(_OPERATION),
    "operation_authorizations": _growing(_OPERATION),
    "operation_leases": _growing(_OPERATION),
    "operation_resources": _growing(_OPERATION),
    "operation_verifications": _growing(_OPERATION),
    "operation_cleanups": _growing(_OPERATION),
    "operation_transitions": _growing(_OPERATION),
    "operation_preauthorizations": _growing("每条预授权一行，随主人授权增长"),
    "trust_identity": _object("本机身份，只有一行"),
    "trust_documents": _object("每类信任文档一行，覆盖写"),
    "trust_audit": _growing("信任变更审计，每次加人、换钥、撤销一行"),
    "trust_rotations": _growing("每次换钥一行"),
    "gateway_invites": _growing("每张邀请码一行"),
    "owner_invites": _growing("每张邀请码一行，重置信任时清空"),
    "friend_invites": _growing("每张邀请码一行，重置信任时清空"),
    "device_permissions": _object("每台自己的电脑一行"),
    "friend_rosters": _object("每位好友一行，删除好友时删除"),
    "friend_permissions": _object("每位好友一行，删除好友时删除"),
    "friend_node_owners": _object("每台好友电脑一行"),
    "friend_device_history": _object("每台见过的好友电脑一行，只插不改"),
    "own_device_history": _object("每台见过的自己的电脑一行，只插不改"),
    # 组网相关的本机库。
    "managed_network_sync": _object("每个网络里的每台电脑一行，覆盖写"),
    "managed_network_resources": _object("每个网络里的每台电脑一行，撤下时删除"),
    "windows_network_operations": _growing("每次组网改动一行，随组网操作增长"),
    "network_governance": _growing("每次组网配置修订一行"),
    "network_path_status": _growing("每次组网配置修订一行"),
    "network_authorization_grants": _growing("每次组网授权一行"),
    "network_apply_claims": _growing("每次组网修订一行"),
    # coordinator 库。
    "schema_metadata": _object("库版本，只有一行"),
    "networks": _object("每个网络一行"),
    "enrollment_tokens": _growing("每张入网令牌一行"),
    "nodes": _object("每台入网电脑一行"),
    "refresh_credentials": _growing("每次换发凭据一行，旧的标记撤销"),
    "signing_keys": _object("每把签名密钥一行"),
    "revocations": _growing("每次撤销一行"),
    "revisions": _object("每个网络一行"),
    "coordinator_audit": _growing("coordinator 审计，每次变更一行；电脑同步快照也记一行，待补清理"),
    "registration_idempotency": _growing("每次入网请求一行"),
    "snapshot_heads": _object("每台电脑每类快照一行，覆盖写"),
    "snapshot_receipts": _growing("每次收到电脑同步的快照一行，随同步次数增长，待补清理"),
    "capability_directory": _object("每台电脑每个能力一行"),
    "service_directory": _object("每台电脑每个服务一行"),
    "network_address_pools": _object("每个网络一行"),
    "network_address_leases": _object("每台电脑一行"),
    "network_public_keys": _object("每台电脑一行"),
    "network_endpoint_candidates": _object("每台电脑的候选地址，整组替换"),
    "network_relay_roles": _object("每台电脑一行"),
    "network_sagas": _growing("每次组网变更一行"),
    "network_desired_configs": _growing("每次组网变更一行"),
    "network_acknowledgements": _growing("每次组网变更回执一行"),
}
