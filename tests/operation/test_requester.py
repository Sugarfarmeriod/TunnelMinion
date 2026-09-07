"""请求端产品操作编排的确定性测试。"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from datetime import timedelta
from pathlib import Path

import pytest
from tests.operation.factories import NOW, plan

from tunnelminion.agent.diagnostics import CrossNodeAgentAnswer
from tunnelminion.agent.planning import CandidatePlanIntent
from tunnelminion.domain.errors import ErrorCode
from tunnelminion.domain.identifiers import NodeId, OperationId, ThreadId
from tunnelminion.domain.versioning import ProtocolVersion
from tunnelminion.gateway.client import RemoteGatewayError
from tunnelminion.gateway.configuration import (
    FileGatewayConfigurationRepository,
    GatewayConfigurationService,
    GatewayPeerConfig,
    GatewayPeerInput,
    generate_gateway_token,
)
from tunnelminion.gateway.contracts import (
    GATEWAY_PROTOCOL,
    RemoteOperationResult,
    RequesterVerificationCallback,
)
from tunnelminion.gateway.security import GatewayBindConfig
from tunnelminion.memory.sqlite import SQLiteStores
from tunnelminion.model.contracts import (
    CancellationToken,
    ProviderError,
    ProviderErrorCode,
)
from tunnelminion.operation.contracts import (
    AccessScope,
    OperationPlan,
    OperationRecord,
    OperationStatus,
    OperationSummary,
    compute_idempotency_key,
    transition_operation,
)
from tunnelminion.operation.requester import RequesterOperationInput
from tunnelminion.operation.requester_service import (
    RequesterOperationFailure,
    RequesterOperationService,
)
from tunnelminion.tools.contracts import ToolCallContext, ToolCancellationToken


class MemorySecrets:
    def __init__(self) -> None:
        self.values: dict[str, str] = {}

    def get(self, name: str) -> str | None:
        return self.values.get(name)

    def set(self, name: str, value: str) -> None:
        self.values[name] = value

    def delete(self, name: str) -> None:
        self.values.pop(name, None)


class FakeDiagnosticAgent:
    def __init__(
        self,
        builder: Callable[[ToolCallContext, str, int, int, int], OperationPlan] | None,
        *,
        error_code: str | None = None,
    ) -> None:
        self._builder = builder
        self._error_code = error_code
        self.calls: list[tuple[str, int]] = []

    async def answer(
        self,
        question: str,
        context: ToolCallContext,
        target_host: str,
        *,
        port: int | None = None,
        plan_intent: CandidatePlanIntent | None = None,
        tool_cancellation: ToolCancellationToken | None = None,
        model_cancellation: CancellationToken | None = None,
    ) -> CrossNodeAgentAnswer:
        del question, tool_cancellation, model_cancellation
        assert port is not None
        assert plan_intent is not None
        service_port = plan_intent.service_port
        bind_port = plan_intent.bind_port
        duration = plan_intent.duration_seconds
        self.calls.append((target_host, port))
        candidate = (
            self._builder(context, target_host, service_port, bind_port, duration)
            if self._builder is not None
            else None
        )
        return CrossNodeAgentAnswer(
            answer="fixture",
            candidate_plan=candidate,
            plan_error_code=self._error_code,
        )


class FakeGatewayClient:
    def __init__(self) -> None:
        self.submit_result: RemoteOperationResult | RemoteGatewayError | None = None
        self.get_result: RemoteOperationResult | RemoteGatewayError | None = None
        self.submit_calls = 0
        self.get_calls = 0
        self.before_submit: Callable[[OperationPlan], None] | None = None
        self.cancel_submit = False

    async def submit_operation(self, plan: OperationPlan) -> RemoteOperationResult:
        self.submit_calls += 1
        if self.before_submit is not None:
            self.before_submit(plan)
        if self.cancel_submit:
            raise asyncio.CancelledError
        if isinstance(self.submit_result, RemoteGatewayError):
            raise self.submit_result
        assert self.submit_result is not None
        return self.submit_result

    async def get_operation(self, operation_id: OperationId) -> RemoteOperationResult:
        del operation_id
        self.get_calls += 1
        if isinstance(self.get_result, RemoteGatewayError):
            raise self.get_result
        assert self.get_result is not None
        return self.get_result

    async def execute_operation(
        self,
        plan: OperationPlan,
        *,
        verification_callback: RequesterVerificationCallback | None = None,
    ) -> RemoteOperationResult:
        del plan, verification_callback
        raise AssertionError("本组测试不应执行远端操作")


def _candidate(
    context: ToolCallContext,
    target_host: str,
    service_port: int,
    bind_port: int,
    duration_seconds: int,
) -> OperationPlan:
    base = plan()
    scope = AccessScope(
        allowed_peer_id=context.caller_node_id,
        bind_host=target_host,
        bind_port=bind_port,
        duration_seconds=duration_seconds,
    )
    values = {
        **base.model_dump(),
        "request_node_id": context.caller_node_id,
        "target_node_id": context.execution_node_id,
        "thread_id": context.thread_id,
        "run_id": context.run_id,
        "service": base.service.model_copy(update={"port": service_port}),
        "access_scope": scope,
        "idempotency_key": compute_idempotency_key(
            request_node_id=context.caller_node_id,
            target_node_id=context.execution_node_id,
            tool_name=base.tool_name,
            plan_version=base.plan_version,
            service_fingerprint=base.service.fingerprint,
            access_scope=scope,
        ),
    }
    return OperationPlan.model_validate(values)


def _remote(operation_plan: OperationPlan, status: OperationStatus) -> RemoteOperationResult:
    record = OperationRecord.planned(operation_plan)
    if status is not OperationStatus.PLANNED:
        record = transition_operation(
            record,
            status,
            reason="fixture",
            occurred_at=NOW + timedelta(seconds=1),
        )
    return RemoteOperationResult(
        protocol=GATEWAY_PROTOCOL,
        execution_node_id=operation_plan.target_node_id,
        summary=OperationSummary.from_record(record),
    )


def _service(
    tmp_path: Path,
    agent: FakeDiagnosticAgent,
    client: FakeGatewayClient,
    *,
    factory_error: ProviderError | None = None,
) -> tuple[
    RequesterOperationService,
    SQLiteStores,
    GatewayConfigurationService,
    NodeId,
    NodeId,
]:
    local = NodeId.new()
    remote = NodeId.new()
    repository = FileGatewayConfigurationRepository(tmp_path / "gateway.json")
    configuration = GatewayConfigurationService(repository, MemorySecrets())
    configuration.configure_local(GatewayBindConfig(host="10.77.0.2"))
    configuration.provision_peer(
        GatewayPeerInput(
            peer=GatewayPeerConfig(
                node_id=remote,
                host="10.77.0.1",
                allowed_tools=frozenset(
                    {
                        "get_node_summary",
                        "list_network_listeners",
                        "get_process_summary",
                        "list_docker_services",
                    }
                ),
                allowed_operations=frozenset({"share_local_http_service"}),
            ),
            token=generate_gateway_token(),
        )
    )
    stores = SQLiteStores.open(tmp_path / "runtime.sqlite3")

    def create_agent(_peer: object) -> FakeDiagnosticAgent:
        if factory_error is not None:
            raise factory_error
        return agent

    service = RequesterOperationService(
        node_id=local,
        store=stores.requester_operations,
        configuration=configuration,
        diagnostic_agent_factory=create_agent,
        gateway_client_factory=lambda _peer: client,
        clock=lambda: NOW + timedelta(seconds=2),
    )
    return service, stores, configuration, local, remote


def _input(remote: NodeId) -> RequesterOperationInput:
    return RequesterOperationInput(
        target_node_id=remote,
        service_port=8080,
        bind_port=18_881,
        duration_seconds=300,
        confirmed=True,
    )


@pytest.mark.anyio
async def test_create_persists_before_single_submit_and_accepts_remote_summary(
    tmp_path: Path,
) -> None:
    agent = FakeDiagnosticAgent(_candidate)
    client = FakeGatewayClient()
    service, stores, _configuration, _local, remote = _service(tmp_path, agent, client)

    def before_submit(operation_plan: OperationPlan) -> None:
        assert stores.requester_operations.get(operation_plan.operation_id) is not None
        client.submit_result = _remote(operation_plan, OperationStatus.AWAITING_AUTHORIZATION)

    client.before_submit = before_submit
    created = await service.create_operation(_input(remote))

    assert client.submit_calls == 1
    assert agent.calls == [("10.77.0.1", 8080)]
    assert created.remote_summary is not None
    assert created.remote_summary.status is OperationStatus.AWAITING_AUTHORIZATION
    assert created.error_code is None
    assert tuple(item.node_id for item in service.eligible_peers()) == (remote,)
    assert service.list_operations() == (created,)
    assert service.get_operation(created.plan.operation_id) == created


@pytest.mark.anyio
async def test_unavailable_plan_does_not_touch_existing_target_operation(tmp_path: Path) -> None:
    agent = FakeDiagnosticAgent(None, error_code="model_not_found")
    client = FakeGatewayClient()
    service, stores, _configuration, _local, remote = _service(tmp_path, agent, client)
    existing = OperationRecord.planned(plan())
    stores.operations.put(existing)

    with pytest.raises(RequesterOperationFailure, match="model_not_found"):
        await service.create_operation(_input(remote))

    assert stores.operations.get(existing.plan.operation_id) == existing
    assert stores.requester_operations.list_all() == ()
    assert client.submit_calls == 0

    unavailable, _, _, _, second_remote = _service(
        tmp_path / "provider-unavailable",
        agent,
        client,
        factory_error=ProviderError(ProviderErrorCode.MODEL_NOT_FOUND, "safe"),
    )
    with pytest.raises(RequesterOperationFailure, match="model_not_found"):
        await unavailable.create_operation(_input(second_remote))

    with pytest.raises(RequesterOperationFailure, match="explicit_intent_required"):
        await service.create_operation(_input(remote).model_copy(update={"confirmed": False}))
    with pytest.raises(RequesterOperationFailure, match="gateway_operation_peer_unavailable"):
        await service.create_operation(_input(NodeId.new()))


@pytest.mark.anyio
async def test_unknown_submit_is_only_refreshed_and_never_replayed(tmp_path: Path) -> None:
    agent = FakeDiagnosticAgent(_candidate)
    client = FakeGatewayClient()
    client.submit_result = RemoteGatewayError(ErrorCode.REMOTE_TIMEOUT, "safe")
    service, stores, _configuration, _local, remote = _service(tmp_path, agent, client)

    created = await service.create_operation(_input(remote))
    assert created.submission_result_unknown is True
    assert created.error_code == ErrorCode.REMOTE_TIMEOUT.value

    client.get_result = _remote(created.plan, OperationStatus.AWAITING_AUTHORIZATION)
    refreshed = await service.refresh_operation(created.plan.operation_id)
    assert refreshed.submission_result_unknown is False
    assert refreshed.error_code is None
    assert client.submit_calls == 1
    assert client.get_calls == 1
    assert stores.requester_operations.get(created.plan.operation_id) == refreshed


@pytest.mark.anyio
async def test_known_submit_failure_and_bad_remote_summary_are_persisted(tmp_path: Path) -> None:
    agent = FakeDiagnosticAgent(_candidate)
    client = FakeGatewayClient()
    client.submit_result = RemoteGatewayError(ErrorCode.FORBIDDEN, "safe")
    service, _stores, _configuration, _local, remote = _service(tmp_path, agent, client)
    failed = await service.create_operation(_input(remote))
    assert failed.error_code == ErrorCode.FORBIDDEN.value
    assert failed.submission_result_unknown is False

    bad = _remote(failed.plan, OperationStatus.AWAITING_AUTHORIZATION)
    bad = bad.model_copy(
        update={
            "summary": bad.summary.model_copy(
                update={"bind_port": failed.plan.access_scope.bind_port + 1}
            )
        }
    )
    client.get_result = bad
    refreshed = await service.refresh_operation(failed.plan.operation_id)
    assert refreshed.error_code == "remote_integrity_error"
    assert refreshed.remote_summary is None

    wrong_node = _remote(failed.plan, OperationStatus.AWAITING_AUTHORIZATION).model_copy(
        update={"execution_node_id": NodeId.new()}
    )
    client.get_result = wrong_node
    assert (await service.refresh_operation(failed.plan.operation_id)).error_code == (
        "remote_integrity_error"
    )
    wrong_protocol = _remote(failed.plan, OperationStatus.AWAITING_AUTHORIZATION).model_copy(
        update={"protocol": ProtocolVersion(major=2, minor=0)}
    )
    client.get_result = wrong_protocol
    assert (await service.refresh_operation(failed.plan.operation_id)).error_code == (
        "remote_integrity_error"
    )


@pytest.mark.anyio
async def test_cancelled_submit_is_persisted_as_unknown_before_propagation(tmp_path: Path) -> None:
    agent = FakeDiagnosticAgent(_candidate)
    client = FakeGatewayClient()
    client.cancel_submit = True
    service, stores, _configuration, _local, remote = _service(tmp_path, agent, client)

    with pytest.raises(asyncio.CancelledError):
        await service.create_operation(_input(remote))

    saved = stores.requester_operations.list_all()[0]
    assert saved.submission_result_unknown is True
    assert saved.error_code == "submission_result_unknown"


@pytest.mark.anyio
async def test_plan_identity_and_refresh_failures_never_trigger_a_second_write(
    tmp_path: Path,
) -> None:
    def mismatched(
        context: ToolCallContext,
        target_host: str,
        service_port: int,
        bind_port: int,
        duration_seconds: int,
    ) -> OperationPlan:
        return _candidate(
            context,
            target_host,
            service_port,
            bind_port,
            duration_seconds,
        ).model_copy(update={"thread_id": ThreadId.new()})

    bad_agent = FakeDiagnosticAgent(mismatched)
    bad_client = FakeGatewayClient()
    bad_service, bad_stores, _, _, bad_remote = _service(
        tmp_path / "bad-plan", bad_agent, bad_client
    )
    with pytest.raises(RequesterOperationFailure, match="candidate_plan_mismatch"):
        await bad_service.create_operation(_input(bad_remote))
    assert bad_stores.requester_operations.list_all() == ()
    assert bad_client.submit_calls == 0

    agent = FakeDiagnosticAgent(_candidate)
    client = FakeGatewayClient()
    service, _stores, configuration, _, remote = _service(tmp_path / "refresh", agent, client)
    client.submit_result = RemoteGatewayError(ErrorCode.FORBIDDEN, "safe")
    created = await service.create_operation(_input(remote))
    client.get_result = RemoteGatewayError(ErrorCode.NODE_UNREACHABLE, "safe")
    failed_query = await service.refresh_operation(created.plan.operation_id)
    assert failed_query.error_code == ErrorCode.NODE_UNREACHABLE.value
    assert client.submit_calls == 1

    configuration.delete()
    unavailable = await service.refresh_operation(created.plan.operation_id)
    assert unavailable.error_code == "gateway_operation_peer_unavailable"
    assert client.submit_calls == 1
    with pytest.raises(KeyError, match="requester_operation_not_found"):
        service.get_operation(OperationId.new())
