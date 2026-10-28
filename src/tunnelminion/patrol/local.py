"""用本机真实的网页探测和存储组装巡检；Windows 与 macOS 应用共用。"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from tunnelminion.domain.identifiers import NodeId
from tunnelminion.incident.contracts import IncidentEventType, SnapshotDiffEvent
from tunnelminion.patrol.service import PatrolConversations, PatrolRepairs, PatrolService
from tunnelminion.patrol.storage import SQLitePatrolStore
from tunnelminion.repair.contracts import LaunchRecordStore
from tunnelminion.repair.processes import SocketLocalVerifier
from tunnelminion.web.service_map import LocalServiceMap


def build_local_patrol(
    *,
    root: Path,
    node_id: NodeId,
    services: Callable[[], LocalServiceMap],
    conversations: PatrolConversations,
    repairs: PatrolRepairs,
    launch_records: LaunchRecordStore,
) -> PatrolService:
    return PatrolService(
        node_id,
        SQLitePatrolStore(root / "patrol.sqlite3"),
        services,
        SocketLocalVerifier().web_status,
        conversations,
        repairs,
        lambda key: launch_records.get(key) is not None,
    )


def patrol_covers(node_id: NodeId) -> Callable[[SnapshotDiffEvent], bool]:
    """本机服务消失或不可达由巡检调查，观察循环只记录事件。"""
    covered = {IncidentEventType.SERVICE_REMOVED, IncidentEventType.REMOTE_UNREACHABLE}
    return lambda event: event.target_node_id == node_id and event.event_type in covered
