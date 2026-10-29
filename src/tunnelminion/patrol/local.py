"""用本机真实的网页探测和存储组装巡检；Windows 与 macOS 应用共用。"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from tunnelminion.domain.identifiers import NodeId
from tunnelminion.gateway.contracts import PeerServicePatrol
from tunnelminion.incident.contracts import IncidentEventType, SnapshotDiffEvent
from tunnelminion.patrol.contracts import REASON_TEXT, PatrolStatus
from tunnelminion.patrol.service import PatrolConversations, PatrolRepairs, PatrolService
from tunnelminion.patrol.storage import SQLitePatrolStore
from tunnelminion.repair.contracts import LaunchRecordStore, WindowsServiceRuntime
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
    windows_services: WindowsServiceRuntime | None = None,
) -> PatrolService:
    verifier = SocketLocalVerifier()
    return PatrolService(
        node_id,
        patrol_store(root),
        services,
        verifier.web_status,
        conversations,
        repairs,
        launch_records.get,
        talks_first=verifier.talks_first,
        windows_services=windows_services,
    )


def patrol_store(root: Path) -> SQLitePatrolStore:
    """本机应用和 Gateway 读同一份巡检记录；第一次写入时才建库。"""
    return SQLitePatrolStore(root / "patrol.sqlite3")


def peer_patrol_reports(store: SQLitePatrolStore) -> dict[str, PeerServicePatrol]:
    """给别的电脑看的巡检摘要：只有确认挂了的服务，不含对话、修复编号和暂停原因。"""
    return {
        record.key: PeerServicePatrol(
            status=record.status.value,
            reason=record.reason.value if record.reason is not None else None,
            reason_text=REASON_TEXT[record.reason] if record.reason is not None else None,
            confirmed_at=record.confirmed_at,
            auto_repair=record.auto_repair_enabled and not record.auto_repair_paused,
        )
        for record in store.list_all()
        if record.status is PatrolStatus.DOWN
    }


def patrol_covers(node_id: NodeId) -> Callable[[SnapshotDiffEvent], bool]:
    """本机服务消失或不可达由巡检调查，观察循环只记录事件。"""
    covered = {IncidentEventType.SERVICE_REMOVED, IncidentEventType.REMOTE_UNREACHABLE}
    return lambda event: event.target_node_id == node_id and event.event_type in covered
