"""TCP 服务观察、Incident 调查到受控操作提交的隔离纵切。"""

# pyright: reportPrivateUsage=false

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

import httpx
import pytest
from tests.agent.test_service_observation import FakeAdapter, collection
from tests.incident.test_investigation import NODE, NOW, _remote_runtime
from tests.operation.test_requester import (
    FakeCallbackRuntime,
    FakeDiagnosticAgent,
    FakeGatewayClient,
    _candidate,
    _input,
    _service,
)
from tests.operation.test_workflow import MemorySecretStore
from tests.tools.test_registry import definition

from tunnelminion.agent.managed_node import ServiceObservationConfig
from tunnelminion.agent.service_observation import DeterministicServiceObserver
from tunnelminion.coordinator.contracts import ServiceAccessibility, ServiceProtocol
from tunnelminion.domain.tools import RiskLevel
from tunnelminion.gateway.contracts import (
    GATEWAY_PROTOCOL,
    RemoteOperationResult,
    RequesterVerificationCallback,
)
from tunnelminion.gateway.operations import CallbackRequesterVerifier, TargetOperationGatewayService
from tunnelminion.incident.contracts import (
    IncidentStatus,
    InvestigationStepStatus,
    NormalizedSnapshot,
)
from tunnelminion.incident.skills import SERVICE_LOCAL_ONLY
from tunnelminion.incident.snapshot import SnapshotDiffDetector, assemble_overview_snapshot
from tunnelminion.memory.sqlite import SQLiteStores
from tunnelminion.operation.contracts import (
    OperationPlan,
    OperationRecord,
    OperationStatus,
    OperationSummary,
)
from tunnelminion.operation.fakes import (
    FakeRequesterVerifier,
    FakeServiceEvidenceProvider,
    FakeSharingAdapter,
)
from tunnelminion.operation.policy import AuthorizationService, OperationPolicy
from tunnelminion.operation.requester import RequesterExecutionInput
from tunnelminion.operation.workflow import OperationWorkflow, operation_token_name
from tunnelminion.platforms.windows.models import NetworkListener
from tunnelminion.tools.fakes import FakeToolAdapter
from tunnelminion.tools.registry import ToolRegistry
from tunnelminion.web.operations import ApproveInput, OperationControlService
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
    print("隔离模拟演示：模型/网络/共享资源为测试替身")
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
    assert incident.investigation is not None
    completed_steps = {
        step.step_id
        for step in incident.investigation.steps
        if step.status is InvestigationStepStatus.SUCCEEDED
    }
    covered_requirements = {
        requirement
        for step in SERVICE_LOCAL_ONLY.steps
        if step.step_id in completed_steps
        for requirement in step.requirement_ids
    }
    assert len(covered_requirements) == len(SERVICE_LOCAL_ONLY.requirements)
    print(f"阶段 1/6 事件 ID（dedup_key）：{event.dedup_key} → Incident {incident.incident_id}")
    print(
        "阶段 2/6 Skill 证据完整："
        f"{SERVICE_LOCAL_ONLY.skill_id}@{SERVICE_LOCAL_ONLY.version} "
        f"{len(covered_requirements)}/{len(SERVICE_LOCAL_ONLY.requirements)}"
    )

    agent = FakeDiagnosticAgent(_candidate)
    client = FakeGatewayClient()
    callback_runtime = FakeCallbackRuntime()
    operation_now = datetime.now(UTC)
    requester, stores, _configuration, _local, remote = _service(
        tmp_path / "requester",
        agent,
        client,
        callback_runtime=callback_runtime,
        clock=lambda: operation_now,
        incident_store=incident_store,
        remote_node_id=NODE,
        verification_transport=httpx.MockTransport(lambda _request: httpx.Response(204)),
    )
    payload = _input(remote).model_copy(
        update={"source_incident_id": incident.incident_id, "service_port": observed.port}
    )

    target_stores = SQLiteStores.open(tmp_path / "target.sqlite3")
    registry = ToolRegistry()
    registry.register(
        definition("share_local_http_service", RiskLevel.REQUIRES_APPROVAL),
        FakeToolAdapter(),
    )
    authorization = AuthorizationService(
        target_stores.operations,
        target_stores.preauthorizations,
        OperationPolicy(registry, target_stores.preauthorizations),
    )
    adapter = FakeSharingAdapter()
    secrets = MemorySecretStore()
    target: TargetOperationGatewayService | None = None
    workflow: OperationWorkflow | None = None

    def result(record: OperationRecord) -> RemoteOperationResult:
        summary = OperationSummary.from_record(record)
        return RemoteOperationResult(
            protocol=GATEWAY_PROTOCOL,
            execution_node_id=remote,
            summary=summary,
        )

    def accept(operation_plan: OperationPlan) -> None:
        nonlocal target, workflow
        assert operation_plan.source_incident_id == incident.incident_id
        assert operation_plan.service.service_id == str(observed.service_id)
        workflow = OperationWorkflow(
            target_stores.operations,
            secrets,
            FakeServiceEvidenceProvider(operation_plan.service),
            adapter,
            FakeRequesterVerifier(operation_plan.request_node_id),
        )
        target = TargetOperationGatewayService(
            target_stores.operations,
            authorization,
            workflow,
        )
        client.submit_result = result(target.submit(operation_plan, at=operation_now))

    client.before_submit = accept
    created = await requester.create_operation(payload)

    restored = stores.requester_operations.get(created.plan.operation_id)
    assert restored is not None
    assert restored.plan.service.service_id == str(observed.service_id)
    assert client.submit_calls == 1
    assert target is not None and workflow is not None
    target_service = cast(TargetOperationGatewayService, target)
    assert created.remote_summary is not None
    assert created.remote_summary.status is OperationStatus.AWAITING_AUTHORIZATION
    print(
        "阶段 3/6 候选计划已提交："
        f"operation_id={created.plan.operation_id}，状态=awaiting_authorization"
    )

    target_record = target_service.get(created.plan.operation_id)
    assert target_record is not None
    client.get_result = result(target_record)
    blocked = await requester.execute_operation(
        created.plan.operation_id,
        RequesterExecutionInput(confirmed=True),
    )
    assert blocked.error_code == "operation_not_authorized"
    assert adapter.create_calls == 0
    assert adapter.active_resources == {}
    print("阶段 4/6 批准前无写：create_calls=0，自有资源=0")

    control = OperationControlService(
        node_id=remote,
        operations=target_stores.operations,
        preauthorizations=target_stores.preauthorizations,
        authorization=authorization,
        lifecycle=workflow,
        clock=lambda: operation_now,
    )
    approved = control.approve(
        created.plan.operation_id,
        ApproveInput(
            operator="target-local-user",
            expires_at=operation_now + timedelta(minutes=1),
        ),
    )
    assert approved.status is OperationStatus.AUTHORIZED
    authorized_record = target_service.get(created.plan.operation_id)
    assert authorized_record is not None
    client.get_result = result(authorized_record)

    async def execute(
        operation_plan: OperationPlan,
        callback: RequesterVerificationCallback,
    ) -> None:
        assert callback_runtime.app is not None
        verifier = CallbackRequesterVerifier(
            callback,
            transport=httpx.ASGITransport(app=callback_runtime.app),
        )
        executed = await target_service.execute(
            operation_id=operation_plan.operation_id,
            plan_version=operation_plan.plan_version,
            idempotency_key=operation_plan.idempotency_key,
            request_node_id=operation_plan.request_node_id,
            target_node_id=operation_plan.target_node_id,
            thread_id=operation_plan.thread_id,
            run_id=operation_plan.run_id,
            tool_run_ids=operation_plan.tool_run_ids,
            at=operation_now,
            verifier=verifier,
        )
        client.execute_result = result(executed)

    client.on_execute = execute
    executed = await requester.execute_operation(
        created.plan.operation_id,
        RequesterExecutionInput(confirmed=True),
    )
    assert executed.remote_summary is not None
    assert executed.remote_summary.status is OperationStatus.SUCCEEDED
    succeeded = target_service.get(created.plan.operation_id)
    assert succeeded is not None and succeeded.lease is not None
    assert succeeded.verifications[0].result.value == "passed"
    assert adapter.create_calls == 1
    print("阶段 5/6 目标批准后执行成功：请求端独立验证=passed，自有资源=1")

    expired = await workflow.expire_due(at=succeeded.lease.expires_at)
    assert expired[0].plan.operation_id == created.plan.operation_id
    assert expired[0].status is OperationStatus.EXPIRED
    assert adapter.active_resources == {}
    assert operation_token_name(created.plan.operation_id) not in secrets.values
    client.get_result = result(expired[0])
    refreshed = await requester.refresh_operation(created.plan.operation_id)
    assert refreshed.remote_summary is not None
    assert refreshed.remote_summary.status is OperationStatus.EXPIRED
    print(
        "阶段 6/6 租约到期清理完成：请求端状态=expired，同一 operation_id，自有资源=0，临时凭据=0"
    )
