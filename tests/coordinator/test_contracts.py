"""Coordinator v1 协议模型与拒绝边界测试。"""

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from tunnelminion.coordinator.contracts import (
    ASSERTION_ALGORITHM,
    ASSERTION_AUDIENCES,
    ASSERTION_TTL_SECONDS,
    COORDINATOR_PROTOCOL,
    CapabilityAvailability,
    CapabilitySnapshot,
    CapabilitySummary,
    CoordinatorAuditAction,
    CoordinatorAuditRecord,
    CoordinatorAuditResult,
    CoordinatorError,
    CoordinatorErrorCode,
    CoordinatorErrorResponse,
    DirectoryFreshness,
    DirectoryNodeSummary,
    DirectoryPage,
    DirectoryQuery,
    GatewayEndpoint,
    HeartbeatRequest,
    HeartbeatResponse,
    NodeIdentity,
    NodeStatus,
    ServiceAccessibility,
    ServiceLifecycle,
    ServiceProtocol,
    ServiceSnapshot,
    ServiceSummary,
    SnapshotKind,
    SnapshotReceipt,
)
from tunnelminion.domain.identifiers import (
    CoordinatorAuditId,
    NetworkId,
    NodeId,
    ServiceId,
    SnapshotId,
)
from tunnelminion.domain.tools import Platform, RiskLevel
from tunnelminion.domain.versioning import ProtocolVersion

NOW = datetime(2026, 7, 26, 8, 0, tzinfo=UTC)
NETWORK = NetworkId("network_0123456789abcdef0123456789abcdef")
NODE = NodeId("node_0123456789abcdef0123456789abcdef")
SNAPSHOT = SnapshotId("snapshot_0123456789abcdef0123456789abcdef")
SERVICE = ServiceId("service_0123456789abcdef0123456789abcdef")
AUDIT = CoordinatorAuditId("coordaudit_0123456789abcdef0123456789abcdef")


def identity() -> NodeIdentity:
    return NodeIdentity(
        network_id=NETWORK,
        node_id=NODE,
        display_name="HomeMac",
        platform=Platform.MACOS,
        gateway_endpoint=GatewayEndpoint(host="10.77.0.1"),
    )


def capability() -> CapabilitySummary:
    return CapabilitySummary(
        name="get_node_summary",
        version=ProtocolVersion(major=1, minor=0),
        platform=Platform.MACOS,
        risk_level=RiskLevel.READ_ONLY,
        availability=CapabilityAvailability.AVAILABLE,
        schema_hash="a" * 64,
    )


def service() -> ServiceSummary:
    return ServiceSummary(
        service_id=SERVICE,
        protocol=ServiceProtocol.HTTP,
        host="127.0.0.1",
        port=8082,
        accessibility=ServiceAccessibility.LOOPBACK,
        source="list_network_listeners",
        confidence=1,
        observed_at=NOW,
    )


def test_protocol_constants_and_private_gateway_endpoint() -> None:
    assert ProtocolVersion(major=1, minor=0) == COORDINATOR_PROTOCOL
    assert ASSERTION_ALGORITHM == "EdDSA"
    assert ASSERTION_TTL_SECONDS == 120
    assert {
        "coordinator-agent",
        "tool-gateway",
        "operation-gateway",
    } == ASSERTION_AUDIENCES
    assert identity().gateway_endpoint.port == 8787

    for host in ("127.0.0.1", "0.0.0.0", "224.0.0.1", "8.8.8.8"):
        with pytest.raises(ValidationError):
            GatewayEndpoint(host=host)


def test_heartbeat_snapshot_receipt_and_directory_contracts() -> None:
    request = HeartbeatRequest(
        network_id=NETWORK,
        node_id=NODE,
        sent_at=NOW,
    )
    response = HeartbeatResponse(
        received_at=NOW,
        node_status=NodeStatus.ONLINE,
        server_revision=2,
    )
    receipt = SnapshotReceipt(
        snapshot_id=SNAPSHOT,
        sequence=1,
        server_revision=2,
        received_at=NOW,
    )
    summary = DirectoryNodeSummary(
        identity=identity(),
        status=NodeStatus.ONLINE,
        freshness=DirectoryFreshness.FRESH,
        last_received_at=NOW,
        capability_count=1,
        service_count=1,
        server_revision=2,
    )
    query = DirectoryQuery(network_id=NETWORK)
    page = DirectoryPage(
        server_revision=2,
        generated_at=NOW,
        nodes=(summary,),
    )

    assert request.last_server_revision == 0
    assert response.protocol == COORDINATOR_PROTOCOL
    assert receipt.duplicate is False
    assert query.page_size == 50
    assert page.nodes == (summary,)


def test_complete_capability_and_service_snapshots_are_typed_and_bounded() -> None:
    capability_snapshot = CapabilitySnapshot(
        network_id=NETWORK,
        node_id=NODE,
        snapshot_id=SNAPSHOT,
        sequence=1,
        idempotency_key=f"snapkey_{'b' * 64}",
        generated_at=NOW,
        capabilities=(capability(),),
    )
    service_snapshot = ServiceSnapshot(
        network_id=NETWORK,
        node_id=NODE,
        snapshot_id=SNAPSHOT,
        sequence=2,
        idempotency_key=f"snapkey_{'c' * 64}",
        generated_at=NOW,
        services=(service(),),
    )

    assert capability_snapshot.kind is SnapshotKind.CAPABILITY
    assert service_snapshot.services[0].lifecycle is ServiceLifecycle.ACTIVE

    with pytest.raises(ValidationError, match="capability"):
        CapabilitySnapshot.model_validate(
            capability_snapshot.model_dump() | {"kind": SnapshotKind.SERVICE}
        )
    with pytest.raises(ValidationError, match="service"):
        ServiceSnapshot.model_validate(
            service_snapshot.model_dump() | {"kind": SnapshotKind.CAPABILITY}
        )


def test_error_and_audit_contracts_are_minimal_and_strict() -> None:
    error = CoordinatorError(
        code=CoordinatorErrorCode.VERSION_INCOMPATIBLE,
        message="协议主版本不兼容",
    )
    response = CoordinatorErrorResponse(error=error)
    audit = CoordinatorAuditRecord(
        audit_id=AUDIT,
        network_id=NETWORK,
        node_id=NODE,
        server_revision=3,
        action=CoordinatorAuditAction.NODE_REVOKED,
        result=CoordinatorAuditResult.SUCCEEDED,
        occurred_at=NOW,
    )

    assert response.error.retryable is False
    assert audit.item_count == 0
    with pytest.raises(ValidationError):
        CoordinatorError.model_validate(
            {"code": "forbidden", "message": "拒绝", "authorization": "不可出现"}
        )
