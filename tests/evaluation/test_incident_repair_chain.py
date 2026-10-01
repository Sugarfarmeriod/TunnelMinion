"""TCP 服务观察、Incident 调查到受控操作提交的隔离纵切。"""

# pyright: reportPrivateUsage=false

from __future__ import annotations

from pathlib import Path

import pytest
from tests.agent.test_service_observation import FakeAdapter, collection
from tests.incident.test_investigation import NODE, NOW, _remote_runtime
from tests.operation.test_requester import (
    FakeDiagnosticAgent,
    FakeGatewayClient,
    _candidate,
    _input,
    _remote,
    _service,
)

from tunnelminion.agent.managed_node import ServiceObservationConfig
from tunnelminion.agent.service_observation import DeterministicServiceObserver
from tunnelminion.coordinator.contracts import ServiceAccessibility, ServiceProtocol
from tunnelminion.incident.contracts import IncidentStatus, NormalizedSnapshot
from tunnelminion.incident.snapshot import SnapshotDiffDetector, assemble_overview_snapshot
from tunnelminion.operation.contracts import OperationPlan, OperationStatus
from tunnelminion.platforms.windows.models import NetworkListener
from tunnelminion.web.overview import (
    KnownServiceOverview,
    KnownServicesOverview,
    KnownServiceState,
    OverviewFreshness,
    OverviewService,
    OverviewSource,
)


@pytest.mark.anyio
async def test_tcp_observation_investigation_submits_bound_incident_operation(
    tmp_path: Path,
) -> None:
    observer = DeterministicServiceObserver(
        NODE,
        ServiceObservationConfig(interval_seconds=5, timeout_seconds=1),
        FakeAdapter(
            collection(
                NetworkListener(
                    protocol="tcp",
                    address="127.0.0.1",
                    port=43123,
                    pid=4242,
                    process_name="fixture-http",
                )
            )
        ),
        FakeAdapter(collection()),
        FakeAdapter(collection()),
        clock=lambda: NOW,
    )
    observed = (await observer.observe()).services[0]
    assert observed.protocol is ServiceProtocol.TCP
    assert observed.accessibility is ServiceAccessibility.LOOPBACK

    investigator, incident_store, *_ = _remote_runtime(tmp_path, "success")

    def snapshot(
        accessibility: ServiceAccessibility,
        revision: int,
    ) -> NormalizedSnapshot:
        overview = OverviewService(
            services=lambda: KnownServicesOverview(
                source=OverviewSource.COORDINATOR_DIRECTORY,
                evidence_at=observed.observed_at,
                freshness=OverviewFreshness.FRESH,
                items=(
                    KnownServiceOverview(
                        service_id=observed.service_id,
                        node_id=NODE,
                        protocol=observed.protocol,
                        port=observed.port,
                        accessibility=accessibility,
                        state=KnownServiceState.AVAILABLE,
                        source=OverviewSource.COORDINATOR_DIRECTORY,
                        evidence_at=observed.observed_at,
                        freshness=OverviewFreshness.FRESH,
                    ),
                ),
            ),
            clock=lambda: NOW,
        ).view()
        return assemble_overview_snapshot(overview, revision=revision)

    baseline = snapshot(ServiceAccessibility.NETWORK, 1)
    current = snapshot(observed.accessibility, 2)
    incident_store.put_snapshot(baseline)
    incident_store.put_snapshot(current)
    event = SnapshotDiffDetector(confirmations_required=1).compare(baseline, current)[0]
    incident = await investigator.run(incident_store.record_event(event))
    assert incident.status is IncidentStatus.CONFIRMED

    agent = FakeDiagnosticAgent(_candidate)
    client = FakeGatewayClient()
    requester, stores, _configuration, _local, remote = _service(
        tmp_path / "requester",
        agent,
        client,
        incident_store=incident_store,
        remote_node_id=NODE,
    )
    payload = _input(remote).model_copy(
        update={"source_incident_id": incident.incident_id, "service_port": observed.port}
    )

    def accept(operation_plan: OperationPlan) -> None:
        assert operation_plan.source_incident_id == incident.incident_id
        assert operation_plan.service.service_id == str(observed.service_id)
        client.submit_result = _remote(
            operation_plan,
            OperationStatus.AWAITING_AUTHORIZATION,
        )

    client.before_submit = accept
    created = await requester.create_operation(payload)

    restored = stores.requester_operations.get(created.plan.operation_id)
    assert restored is not None
    assert restored.plan.service.service_id == str(observed.service_id)
    assert client.submit_calls == 1
