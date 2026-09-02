"""确定性 incident 观察、调查与持久化边界。"""

from tunnelminion.incident.contracts import (
    EvidenceReference,
    HypothesisStatus,
    Incident,
    IncidentEventType,
    IncidentHypothesis,
    IncidentReport,
    IncidentStatus,
    InvestigationStopReason,
    NormalizedSnapshot,
    PublicTraceEntry,
    SnapshotDiffEvent,
    SnapshotFreshness,
    SnapshotNode,
    SnapshotNodeState,
    SnapshotObjectKind,
    SnapshotService,
    SnapshotServiceState,
    SnapshotSource,
)
from tunnelminion.incident.snapshot import SnapshotDiffDetector, assemble_overview_snapshot
from tunnelminion.incident.storage import SQLiteIncidentStore

__all__ = [
    "EvidenceReference",
    "HypothesisStatus",
    "Incident",
    "IncidentEventType",
    "IncidentHypothesis",
    "IncidentReport",
    "IncidentStatus",
    "InvestigationStopReason",
    "NormalizedSnapshot",
    "PublicTraceEntry",
    "SQLiteIncidentStore",
    "SnapshotDiffDetector",
    "SnapshotDiffEvent",
    "SnapshotFreshness",
    "SnapshotNode",
    "SnapshotNodeState",
    "SnapshotObjectKind",
    "SnapshotService",
    "SnapshotServiceState",
    "SnapshotSource",
    "assemble_overview_snapshot",
]
