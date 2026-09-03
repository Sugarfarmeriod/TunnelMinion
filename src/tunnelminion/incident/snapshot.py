"""从现有总览组装规范化快照并确定性识别六类变化。"""

from __future__ import annotations

import hashlib
import json
from typing import TYPE_CHECKING

from tunnelminion.domain.identifiers import NodeId, SnapshotId
from tunnelminion.incident.contracts import (
    IncidentEventType,
    NormalizedSnapshot,
    SnapshotDiffEvent,
    SnapshotFreshness,
    SnapshotNode,
    SnapshotNodeState,
    SnapshotObjectKind,
    SnapshotService,
    SnapshotServiceState,
    SnapshotSource,
)

if TYPE_CHECKING:
    from tunnelminion.web.overview import ResourceOverview


def assemble_overview_snapshot(overview: ResourceOverview, *, revision: int) -> NormalizedSnapshot:
    """删除显示名、地址和原始正文，只保留比较所需字段。"""
    nodes = tuple(
        SnapshotNode(
            node_id=item.node_id,
            state=SnapshotNodeState(item.state.value),
            source=_source(item.source.value),
            freshness=_freshness(item.freshness.value),
            evidence_at=item.evidence_at,
        )
        for item in sorted(overview.nodes.items, key=lambda value: str(value.node_id))
    )
    services = tuple(
        SnapshotService(
            service_id=item.service_id,
            node_id=item.node_id,
            state=SnapshotServiceState(item.state.value),
            source=_source(item.source.value),
            freshness=_freshness(item.freshness.value),
            evidence_at=item.evidence_at,
            protocol=item.protocol,
            port=item.port,
            accessibility=item.accessibility,
            lifecycle=item.lifecycle,
        )
        for item in sorted(overview.services.items, key=lambda value: str(value.service_id))
    )
    canonical = json.dumps(
        {
            "observed_at": overview.generated_at.isoformat(),
            "revision": revision,
            "nodes": [item.model_dump(mode="json") for item in nodes],
            "services": [item.model_dump(mode="json") for item in services],
        },
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    )
    snapshot_id = SnapshotId(f"snapshot_{hashlib.sha256(canonical.encode()).hexdigest()[:32]}")
    return NormalizedSnapshot(
        snapshot_id=snapshot_id,
        observed_at=overview.generated_at,
        revision=revision,
        nodes=nodes,
        services=services,
    )


class SnapshotDiffDetector:
    """使用确认次数抑制短暂抖动；从不调用模型。"""

    def __init__(self, confirmations_required: int = 2) -> None:
        if not 1 <= confirmations_required <= 10:
            raise ValueError("确认次数必须位于 1 到 10")
        self._confirmations_required = confirmations_required
        self._pending: dict[str, int] = {}
        self._confirmed: set[str] = set()

    @property
    def has_pending(self) -> bool:
        """返回是否存在尚未达到确认窗口的变化。"""
        return bool(self._pending)

    def compare(
        self,
        baseline: NormalizedSnapshot,
        current: NormalizedSnapshot,
    ) -> tuple[SnapshotDiffEvent, ...]:
        """只有变化连续达到确认窗口时才输出 incident 事件。"""
        candidates = self._candidates(baseline, current)
        current_keys = {item.dedup_key for item in candidates}
        self._pending = {key: count for key, count in self._pending.items() if key in current_keys}
        self._confirmed.intersection_update(current_keys)
        confirmed: list[SnapshotDiffEvent] = []
        for event in candidates:
            count = self._pending.get(event.dedup_key, 0) + 1
            self._pending[event.dedup_key] = count
            if count >= self._confirmations_required and event.dedup_key not in self._confirmed:
                self._confirmed.add(event.dedup_key)
                confirmed.append(event)
        return tuple(confirmed)

    def _candidates(
        self,
        baseline: NormalizedSnapshot,
        current: NormalizedSnapshot,
    ) -> tuple[SnapshotDiffEvent, ...]:
        values: list[SnapshotDiffEvent] = []
        before_nodes = {str(item.node_id): item for item in baseline.nodes}
        after_nodes = {str(item.node_id): item for item in current.nodes}
        before_services = {str(item.service_id): item for item in baseline.services}
        after_services = {str(item.service_id): item for item in current.services}

        for object_id in sorted(after_services.keys() - before_services.keys()):
            item = after_services[object_id]
            values.append(
                self._event(
                    IncidentEventType.SERVICE_ADDED,
                    SnapshotObjectKind.SERVICE,
                    object_id,
                    item.node_id,
                    baseline,
                    current,
                    item.source,
                    None,
                    item.state.value,
                )
            )
        for object_id in sorted(before_services.keys() - after_services.keys()):
            item = before_services[object_id]
            values.append(
                self._event(
                    IncidentEventType.SERVICE_REMOVED,
                    SnapshotObjectKind.SERVICE,
                    object_id,
                    item.node_id,
                    baseline,
                    current,
                    item.source,
                    item.state.value,
                    None,
                )
            )
        for object_id in sorted(before_nodes.keys() & after_nodes.keys()):
            before = before_nodes[object_id]
            after = after_nodes[object_id]
            if (
                before.state is not SnapshotNodeState.OFFLINE
                and after.state is SnapshotNodeState.OFFLINE
            ):
                values.append(
                    self._event(
                        IncidentEventType.NODE_OFFLINE,
                        SnapshotObjectKind.NODE,
                        object_id,
                        after.node_id,
                        baseline,
                        current,
                        after.source,
                        before.state.value,
                        after.state.value,
                    )
                )
            if _became_stale(before.freshness, after.freshness):
                values.append(
                    self._event(
                        IncidentEventType.STATE_STALE,
                        SnapshotObjectKind.NODE,
                        object_id,
                        after.node_id,
                        baseline,
                        current,
                        after.source,
                        before.freshness.value,
                        after.freshness.value,
                    )
                )
        for object_id in sorted(before_services.keys() & after_services.keys()):
            before = before_services[object_id]
            after = after_services[object_id]
            if _became_stale(before.freshness, after.freshness):
                values.append(
                    self._event(
                        IncidentEventType.STATE_STALE,
                        SnapshotObjectKind.SERVICE,
                        object_id,
                        after.node_id,
                        baseline,
                        current,
                        after.source,
                        before.freshness.value,
                        after.freshness.value,
                    )
                )
            if str(before.accessibility) != "loopback" and str(after.accessibility) == "loopback":
                values.append(
                    self._event(
                        IncidentEventType.LOCAL_ONLY,
                        SnapshotObjectKind.SERVICE,
                        object_id,
                        after.node_id,
                        baseline,
                        current,
                        after.source,
                        str(before.accessibility) if before.accessibility is not None else None,
                        "loopback",
                    )
                )
            if (
                before.state is not SnapshotServiceState.UNAVAILABLE
                and after.state is SnapshotServiceState.UNAVAILABLE
            ):
                values.append(
                    self._event(
                        IncidentEventType.REMOTE_UNREACHABLE,
                        SnapshotObjectKind.SERVICE,
                        object_id,
                        after.node_id,
                        baseline,
                        current,
                        after.source,
                        before.state.value,
                        after.state.value,
                    )
                )
        return tuple(values)

    @staticmethod
    def _event(
        event_type: IncidentEventType,
        object_kind: SnapshotObjectKind,
        object_id: str,
        target_node_id: NodeId,
        baseline: NormalizedSnapshot,
        current: NormalizedSnapshot,
        source: SnapshotSource,
        before_state: str | None,
        after_state: str | None,
    ) -> SnapshotDiffEvent:
        canonical = (
            f"{object_kind.value}:{object_id}:{event_type.value}:{baseline.revision}"
        ).encode()
        return SnapshotDiffEvent(
            event_type=event_type,
            object_kind=object_kind,
            object_id=object_id,
            target_node_id=target_node_id,
            baseline_snapshot_id=baseline.snapshot_id,
            current_snapshot_id=current.snapshot_id,
            baseline_revision=baseline.revision,
            current_revision=current.revision,
            observed_at=current.observed_at,
            source=source,
            before_state=before_state,
            after_state=after_state,
            dedup_key=f"sha256:{hashlib.sha256(canonical).hexdigest()}",
        )


def _source(value: str) -> SnapshotSource:
    try:
        return SnapshotSource(value)
    except ValueError:
        return SnapshotSource.UNKNOWN


def _freshness(value: str) -> SnapshotFreshness:
    try:
        return SnapshotFreshness(value)
    except ValueError:
        return SnapshotFreshness.UNKNOWN


def _became_stale(before: SnapshotFreshness, after: SnapshotFreshness) -> bool:
    stale = {SnapshotFreshness.STALE, SnapshotFreshness.EXPIRED}
    return before not in stale and after in stale
