"""请求端产品操作编排的确定性测试。"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from datetime import datetime, timedelta
from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI
from tests.operation.factories import NOW, plan

from tunnelminion.agent.diagnostics import CrossNodeAgentAnswer
from tunnelminion.agent.planning import CandidatePlanIntent
from tunnelminion.domain.errors import ErrorCode
from tunnelminion.domain.identifiers import LeaseId, NodeId, OperationId, ThreadId
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
    RemoteVerificationRequest,
    RemoteVerificationResult,
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
    LeaseRecord,
    OperationPlan,
    OperationRecord,
    OperationStatus,
    OperationSummary,
    compute_idempotency_key,
    transition_operation,
)
from tunnelminion.operation.http_sharing import HTTPProxyLimits, StopResult
from tunnelminion.operation.requester import RequesterExecutionInput, RequesterOperationInput
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
        self.execute_result: RemoteOperationResult | RemoteGatewayError | None = None
        self.submit_calls = 0
        self.get_calls = 0
        self.execute_calls = 0
        self.before_submit: Callable[[OperationPlan], None] | None = None
        self.on_get: Callable[[], None] | None = None
        self.on_execute: (
            Callable[[OperationPlan, RequesterVerificationCallback], Awaitable[None]] | None
        ) = None
        self.cancel_submit = False
        self.cancel_execute = False

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
        if self.on_get is not None:
            self.on_get()
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
        self.execute_calls += 1
        assert verification_callback is not None
        if self.on_execute is not None:
            await self.on_execute(plan, verification_callback)
        if self.cancel_execute:
            raise asyncio.CancelledError
        if isinstance(self.execute_result, RemoteGatewayError):
            raise self.execute_result
        assert self.execute_result is not None
        return self.execute_result


class FakeCallbackRuntime:
    def __init__(self, *, fail_start: bool = False) -> None:
        self.fail_start = fail_start
        self.app: FastAPI | None = None
        self.starts = 0
        self.stops = 0

    def start(
        self,
        app: FastAPI,
        *,
        host: str,
        port: int,
        owner_fingerprint: str,
        expires_at: datetime,
        graceful_shutdown_seconds: float,
    ) -> int:
        del host, port, owner_fingerprint, expires_at, graceful_shutdown_seconds
        self.starts += 1
        if self.fail_start:
            raise OSError("fixture")
        self.app = app
        return 123

    def stop(
        self,
        *,
        host: str,
        port: int,
        owner_fingerprint: str,
    ) -> StopResult:
        del host, port, owner_fingerprint
        self.stops += 1
        return StopResult.STOPPED


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


def _remote(
    operation_plan: OperationPlan,
    status: OperationStatus,
    *,
    absolute_expires_at: datetime | None = None,
) -> RemoteOperationResult:
    record = OperationRecord.planned(operation_plan)
    paths = {
        OperationStatus.PLANNED: (),
        OperationStatus.AWAITING_AUTHORIZATION: (OperationStatus.AWAITING_AUTHORIZATION,),
        OperationStatus.AUTHORIZED: (OperationStatus.AUTHORIZED,),
        OperationStatus.SUCCEEDED: (
            OperationStatus.AUTHORIZED,
            OperationStatus.EXECUTING,
            OperationStatus.VERIFYING,
            OperationStatus.SUCCEEDED,
        ),
        OperationStatus.ROLLED_BACK: (
            OperationStatus.AUTHORIZED,
            OperationStatus.EXECUTING,
            OperationStatus.ROLLING_BACK,
            OperationStatus.ROLLED_BACK,
        ),
    }
    for index, next_status in enumerate(paths[status], start=1):
        record = transition_operation(
            record,
            next_status,
            reason="fixture",
            occurred_at=NOW + timedelta(seconds=index),
        )
    return RemoteOperationResult(
        protocol=GATEWAY_PROTOCOL,
        execution_node_id=operation_plan.target_node_id,
        summary=OperationSummary.from_record(record).model_copy(
            update={"absolute_expires_at": absolute_expires_at}
        ),
    )


def _service(
    tmp_path: Path,
    agent: FakeDiagnosticAgent,
    client: FakeGatewayClient,
    *,
    factory_error: ProviderError | None = None,
    callback_runtime: FakeCallbackRuntime | None = None,
    clock: Callable[[], datetime] | None = None,
    verification_transport: httpx.AsyncBaseTransport | None = None,
    access_transport: httpx.AsyncBaseTransport | None = None,
    proxy_limits: HTTPProxyLimits | None = None,
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
    runtime = callback_runtime or FakeCallbackRuntime()

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
        callback_runtime=runtime,
        clock=clock or (lambda: NOW + timedelta(seconds=2)),
        verification_transport=verification_transport,
        access_transport=access_transport,
        proxy_limits=proxy_limits,
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


async def _post_callback(
    runtime: FakeCallbackRuntime,
    callback: RequesterVerificationCallback,
    request: RemoteVerificationRequest,
    *,
    token: str | None = None,
) -> httpx.Response:
    assert runtime.app is not None
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=runtime.app),
        base_url=callback.endpoint,
    ) as client:
        return await client.post(
            "/v1/operations:verify-callback",
            content=request.model_dump_json(),
            headers={
                "Authorization": f"Bearer {token or callback.token}",
                "Content-Type": "application/json",
            },
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

    secret = f"tmn_share_{'s' * 43}"
    untrusted = _remote(failed.plan, OperationStatus.AWAITING_AUTHORIZATION)
    client.get_result = untrusted.model_copy(
        update={
            "summary": untrusted.summary.model_copy(
                update={"authorization_basis": f"Authorization: Bearer {secret}"}
            )
        }
    )
    sanitized = await service.refresh_operation(failed.plan.operation_id)
    assert sanitized.remote_summary is not None
    assert sanitized.remote_summary.authorization_basis == "[REDACTED]"
    assert secret.encode() not in (tmp_path / "runtime.sqlite3").read_bytes()


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


@pytest.mark.anyio
async def test_authorized_execute_captures_memory_token_and_proxies_get_head(
    tmp_path: Path,
) -> None:
    now = [NOW + timedelta(seconds=10)]
    runtime = FakeCallbackRuntime()
    upstream_requests: list[httpx.Request] = []
    upstream_mode = ["ok"]

    def verification_handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["X-TunnelMinion-Share-Token"].startswith("tmn_share_")
        return httpx.Response(204)

    def access_handler(request: httpx.Request) -> httpx.Response:
        upstream_requests.append(request)
        if upstream_mode[0] == "timeout":
            raise httpx.ReadTimeout("fixture", request=request)
        if upstream_mode[0] == "offline":
            raise httpx.ConnectError("fixture", request=request)
        content = b"0123456789" if upstream_mode[0] == "large" else b"ok"
        return httpx.Response(200, content=content, headers={"content-type": "text/plain"})

    agent = FakeDiagnosticAgent(_candidate)
    client = FakeGatewayClient()
    service, stores, configuration, local, remote = _service(
        tmp_path,
        agent,
        client,
        callback_runtime=runtime,
        clock=lambda: now[0],
        verification_transport=httpx.MockTransport(verification_handler),
        access_transport=httpx.MockTransport(access_handler),
        proxy_limits=HTTPProxyLimits(max_response_bytes=8),
    )

    def before_submit(operation_plan: OperationPlan) -> None:
        client.submit_result = _remote(operation_plan, OperationStatus.AUTHORIZED)

    client.before_submit = before_submit
    created = await service.create_operation(_input(remote))
    client.get_result = _remote(created.plan, OperationStatus.AUTHORIZED)
    lease = LeaseRecord(
        lease_id=LeaseId.new(),
        operation_id=created.plan.operation_id,
        starts_at=now[0],
        expires_at=now[0] + timedelta(seconds=300),
    )
    access_token = f"tmn_share_{'a' * 43}"

    async def callback(plan: OperationPlan, value: RequesterVerificationCallback) -> None:
        request = RemoteVerificationRequest(plan=plan, lease=lease, access_token=access_token)
        assert (await _post_callback(runtime, value, request, token="wrong")).status_code == 401
        wrong_plan = plan.model_copy(update={"expected_change": "tampered"})
        assert (
            await _post_callback(
                runtime,
                value,
                request.model_copy(update={"plan": wrong_plan}),
            )
        ).status_code == 403
        wrong_lease = lease.model_copy(update={"operation_id": OperationId.new()})
        assert (
            await _post_callback(
                runtime,
                value,
                request.model_copy(update={"lease": wrong_lease}),
            )
        ).status_code == 403
        accepted = await _post_callback(runtime, value, request)
        assert (
            RemoteVerificationResult.model_validate_json(accepted.content).verification.result.value
            == "passed"
        )
        duplicate = await _post_callback(runtime, value, request)
        assert (
            RemoteVerificationResult.model_validate_json(
                duplicate.content
            ).verification.result.value
            == "failed"
        )
        client.execute_result = _remote(
            plan,
            OperationStatus.SUCCEEDED,
            absolute_expires_at=lease.expires_at,
        )
        client.get_result = client.execute_result

    client.on_execute = callback
    executed = await service.execute_operation(
        created.plan.operation_id,
        RequesterExecutionInput(confirmed=True),
    )
    assert executed.remote_summary is not None
    assert executed.remote_summary.status is OperationStatus.SUCCEEDED
    assert client.execute_calls == 1
    assert runtime.starts == runtime.stops == 1
    assert service.access_expires_at(created.plan.operation_id) == lease.expires_at

    response = await service.access_operation(
        created.plan.operation_id,
        method="GET",
        path="assets/app.css",
        query="v=1",
    )
    assert response.status_code == 200
    assert response.content == b"ok"
    assert response.content_type == "text/plain"
    assert str(upstream_requests[-1].url) == "http://10.77.0.1:18881/assets/app.css?v=1"
    assert upstream_requests[-1].headers["X-TunnelMinion-Share-Token"] == access_token
    assert access_token not in str(upstream_requests[-1].url)
    assert access_token not in repr(response)
    assert (
        await service.access_operation(created.plan.operation_id, method="HEAD", path="")
    ).status_code == 200
    assert access_token.encode() not in (tmp_path / "runtime.sqlite3").read_bytes()

    restarted = RequesterOperationService(
        node_id=local,
        store=stores.requester_operations,
        configuration=configuration,
        diagnostic_agent_factory=lambda _peer: agent,
        gateway_client_factory=lambda _peer: client,
        callback_runtime=FakeCallbackRuntime(),
        clock=lambda: now[0],
        verification_transport=httpx.MockTransport(verification_handler),
        access_transport=httpx.MockTransport(access_handler),
    )
    assert restarted.access_expires_at(created.plan.operation_id) is None
    with pytest.raises(RequesterOperationFailure, match="access_method_not_allowed"):
        await service.access_operation(created.plan.operation_id, method="POST", path="")

    upstream_mode[0] = "large"
    with pytest.raises(RequesterOperationFailure, match="access_response_too_large"):
        await service.access_operation(created.plan.operation_id, method="GET", path="")
    upstream_mode[0] = "timeout"
    with pytest.raises(RequesterOperationFailure, match="access_upstream_timeout"):
        await service.access_operation(created.plan.operation_id, method="GET", path="")
    upstream_mode[0] = "offline"
    with pytest.raises(RequesterOperationFailure, match="access_upstream_unavailable"):
        await service.access_operation(created.plan.operation_id, method="GET", path="")

    client.get_result = _remote(created.plan, OperationStatus.ROLLED_BACK)
    request_count = len(upstream_requests)
    with pytest.raises(RequesterOperationFailure, match="access_session_unavailable"):
        await service.access_operation(created.plan.operation_id, method="GET", path="")
    assert len(upstream_requests) == request_count
    assert service.access_expires_at(created.plan.operation_id) is None

    now[0] = lease.expires_at
    assert service.access_expires_at(created.plan.operation_id) is None
    with pytest.raises(RequesterOperationFailure, match="access_session_unavailable"):
        await service.access_operation(created.plan.operation_id, method="GET", path="")


@pytest.mark.anyio
async def test_execute_bind_unknown_and_authorization_fail_closed(tmp_path: Path) -> None:
    agent = FakeDiagnosticAgent(_candidate)
    client = FakeGatewayClient()
    runtime = FakeCallbackRuntime(fail_start=True)
    service, _stores, configuration, _local, remote = _service(
        tmp_path / "bind", agent, client, callback_runtime=runtime
    )
    client.before_submit = lambda operation_plan: setattr(
        client, "submit_result", _remote(operation_plan, OperationStatus.AUTHORIZED)
    )
    created = await service.create_operation(_input(remote))
    client.get_result = _remote(created.plan, OperationStatus.AUTHORIZED)
    bind_failed = await service.execute_operation(
        created.plan.operation_id,
        RequesterExecutionInput(confirmed=True),
    )
    assert bind_failed.error_code == "callback_bind_failed"
    assert client.execute_calls == 0
    assert runtime.starts == 1
    assert runtime.stops == 0

    client.on_get = configuration.delete
    unavailable = await service.execute_operation(
        created.plan.operation_id,
        RequesterExecutionInput(confirmed=True),
    )
    assert unavailable.error_code == "gateway_operation_peer_unavailable"
    assert client.execute_calls == 0

    with pytest.raises(RequesterOperationFailure, match="explicit_execution_required"):
        await service.execute_operation(
            created.plan.operation_id,
            RequesterExecutionInput(confirmed=False),
        )

    working_runtime = FakeCallbackRuntime()
    unknown_service, _, _, _, second_remote = _service(
        tmp_path / "unknown", agent, client, callback_runtime=working_runtime
    )
    second = await unknown_service.create_operation(_input(second_remote))
    client.get_result = _remote(second.plan, OperationStatus.AUTHORIZED)
    client.execute_result = RemoteGatewayError(ErrorCode.REMOTE_TIMEOUT, "safe")
    unknown = await unknown_service.execute_operation(
        second.plan.operation_id,
        RequesterExecutionInput(confirmed=True),
    )
    assert unknown.execution_result_unknown is True
    assert client.execute_calls == 1
    queried = await unknown_service.execute_operation(
        second.plan.operation_id,
        RequesterExecutionInput(confirmed=True),
    )
    assert queried.execution_result_unknown is False
    assert queried.remote_summary is not None
    assert queried.remote_summary.status is OperationStatus.AUTHORIZED
    assert client.execute_calls == 1

    cancelled_client = FakeGatewayClient()
    cancelled_runtime = FakeCallbackRuntime()
    cancelled_service, cancelled_stores, _, _, cancelled_remote = _service(
        tmp_path / "cancelled",
        agent,
        cancelled_client,
        callback_runtime=cancelled_runtime,
    )
    cancelled_client.before_submit = lambda plan: setattr(
        cancelled_client, "submit_result", _remote(plan, OperationStatus.AUTHORIZED)
    )
    cancelled = await cancelled_service.create_operation(_input(cancelled_remote))
    cancelled_client.get_result = _remote(cancelled.plan, OperationStatus.AUTHORIZED)
    cancelled_client.cancel_execute = True
    with pytest.raises(asyncio.CancelledError):
        await cancelled_service.execute_operation(
            cancelled.plan.operation_id,
            RequesterExecutionInput(confirmed=True),
        )
    saved = cancelled_stores.requester_operations.get(cancelled.plan.operation_id)
    assert saved is not None and saved.execution_result_unknown is True
    assert cancelled_runtime.starts == cancelled_runtime.stops == 1

    waiting_client = FakeGatewayClient()
    waiting_service, _, _, _, third_remote = _service(tmp_path / "waiting-2", agent, waiting_client)
    waiting_client.before_submit = lambda operation_plan: setattr(
        waiting_client,
        "submit_result",
        _remote(operation_plan, OperationStatus.AWAITING_AUTHORIZATION),
    )
    waiting = await waiting_service.create_operation(_input(third_remote))
    waiting_client.get_result = _remote(waiting.plan, OperationStatus.AWAITING_AUTHORIZATION)
    not_authorized = await waiting_service.execute_operation(
        waiting.plan.operation_id,
        RequesterExecutionInput(confirmed=True),
    )
    assert not_authorized.error_code == "operation_not_authorized"
    assert waiting_client.execute_calls == 0


@pytest.mark.anyio
@pytest.mark.parametrize("case", ["unhealthy", "oversized", "revoked", "expiry_mismatch"])
async def test_invalid_or_mismatched_verification_never_creates_access_session(
    tmp_path: Path,
    case: str,
) -> None:
    runtime = FakeCallbackRuntime()
    agent = FakeDiagnosticAgent(_candidate)
    client = FakeGatewayClient()

    def unhealthy(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(503 if case == "unhealthy" else 204)

    service, _stores, _configuration, _local, remote = _service(
        tmp_path,
        agent,
        client,
        callback_runtime=runtime,
        verification_transport=httpx.MockTransport(unhealthy),
    )
    client.before_submit = lambda operation_plan: setattr(
        client, "submit_result", _remote(operation_plan, OperationStatus.AUTHORIZED)
    )
    created = await service.create_operation(_input(remote))
    client.get_result = _remote(created.plan, OperationStatus.AUTHORIZED)
    lease = LeaseRecord(
        lease_id=LeaseId.new(),
        operation_id=created.plan.operation_id,
        starts_at=NOW,
        expires_at=NOW + timedelta(seconds=301 if case == "oversized" else 300),
        revoked_at=NOW + timedelta(seconds=1) if case == "revoked" else None,
    )

    async def callback(plan: OperationPlan, value: RequesterVerificationCallback) -> None:
        response = await _post_callback(
            runtime,
            value,
            RemoteVerificationRequest(
                plan=plan,
                lease=lease,
                access_token=f"tmn_share_{'b' * 43}",
            ),
        )
        verification = RemoteVerificationResult.model_validate_json(response.content).verification
        assert verification.result.value == ("passed" if case == "expiry_mismatch" else "failed")
        client.execute_result = _remote(
            plan,
            (
                OperationStatus.SUCCEEDED
                if case == "expiry_mismatch"
                else OperationStatus.ROLLED_BACK
            ),
            absolute_expires_at=(
                lease.expires_at - timedelta(seconds=1) if case == "expiry_mismatch" else None
            ),
        )

    client.on_execute = callback
    rolled_back = await service.execute_operation(
        created.plan.operation_id,
        RequesterExecutionInput(confirmed=True),
    )
    assert rolled_back.remote_summary is not None
    assert rolled_back.remote_summary.status is (
        OperationStatus.SUCCEEDED if case == "expiry_mismatch" else OperationStatus.ROLLED_BACK
    )
    assert service.access_expires_at(created.plan.operation_id) is None
