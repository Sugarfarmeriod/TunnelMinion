"""L2 操作注册边界与执行前 HTTP 服务复核测试。"""

from __future__ import annotations

import asyncio
from collections.abc import Coroutine
from pathlib import Path
from typing import Any, TypeVar

import httpx
import pytest
from tests.operation.factories import plan

from tunnelminion.domain.identifiers import RunId, ThreadId
from tunnelminion.domain.tools import Platform
from tunnelminion.memory.sqlite import SQLiteStores
from tunnelminion.operation.contracts import (
    OperationLevel,
    OperationPlan,
    OperationRecord,
    compute_idempotency_key,
    compute_service_fingerprint,
)
from tunnelminion.operation.definitions import (
    SAFE_HTTP_SHARING_OPERATION,
    register_safe_http_sharing_operation,
)
from tunnelminion.operation.evidence import HTTPServiceProbeEvidenceProvider
from tunnelminion.platforms.windows.models import NetworkListener
from tunnelminion.tools.audit import InMemoryAuditSink
from tunnelminion.tools.contracts import (
    ToolCallContext,
    ToolCancellationToken,
    ToolExecutionRequest,
)
from tunnelminion.tools.registry import ToolRegistry
from tunnelminion.tools.runtime import ToolRuntime

T = TypeVar("T")


def run(value: Coroutine[Any, Any, T]) -> T:
    return asyncio.run(value)


def test_safe_operation_is_l2_and_cannot_use_normal_tool_runtime() -> None:
    registry = ToolRegistry()
    definition = register_safe_http_sharing_operation(registry)
    entry = registry.lookup(SAFE_HTTP_SHARING_OPERATION)

    assert entry is not None
    assert entry.operation_level is OperationLevel.L2
    assert definition not in registry.model_tools(Platform.MACOS)
    runtime = ToolRuntime(registry, Platform.MACOS, InMemoryAuditSink())
    operation_plan = plan()
    result = run(
        runtime.execute(
            ToolExecutionRequest(
                context=ToolCallContext(
                    thread_id=ThreadId.new(),
                    run_id=RunId.new(),
                    caller_node_id=operation_plan.request_node_id,
                    execution_node_id=operation_plan.target_node_id,
                ),
                tool_name=SAFE_HTTP_SHARING_OPERATION,
            )
        )
    )
    assert result.status.value == "failed"
    assert result.error is not None
    assert result.error.code.value == "forbidden"
    with pytest.raises(Exception, match="操作协议"):
        run(entry.adapter.execute({}, ToolCancellationToken()))


def test_http_evidence_provider_revalidates_only_submitted_loopback_service(
    tmp_path: Path,
) -> None:
    stores = SQLiteStores.open(tmp_path / "runtime.sqlite3")
    operation_plan = plan()
    stores.operations.put(OperationRecord.planned(operation_plan))

    async def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.host == "127.0.0.1"
        assert request.url.port == 8080
        return httpx.Response(200, text="ok")

    provider = HTTPServiceProbeEvidenceProvider(
        stores.operations,
        transport=httpx.MockTransport(handler),
    )
    current = run(provider.read(operation_plan.service.service_id))

    assert current is not None
    assert current.fingerprint == operation_plan.service.fingerprint
    assert current.observed_at >= operation_plan.service.observed_at
    assert run(provider.read("missing")) is None


@pytest.mark.parametrize("timeout", [0, 31])
def test_http_evidence_provider_rejects_invalid_timeout(
    tmp_path: Path,
    timeout: float,
) -> None:
    stores = SQLiteStores.open(tmp_path / "runtime.sqlite3")
    with pytest.raises(ValueError, match="超时"):
        HTTPServiceProbeEvidenceProvider(stores.operations, timeout_seconds=timeout)


def test_http_evidence_provider_fails_closed_for_invalid_or_unhealthy_endpoint(
    tmp_path: Path,
) -> None:
    stores = SQLiteStores.open(tmp_path / "runtime.sqlite3")
    invalid = plan().model_copy(
        update={"service": plan().service.model_copy(update={"host": "10.77.0.1"})}
    )
    stores.operations.put(OperationRecord.planned(invalid))
    provider = HTTPServiceProbeEvidenceProvider(stores.operations)
    assert run(provider.read(invalid.service.service_id)) is None

    invalid_host = plan().model_copy(
        update={
            "service": plan().service.model_copy(
                update={
                    "service_id": "http:invalid-host:8080:fixture",
                    "host": "invalid-host",
                }
            )
        }
    )
    stores.operations.put(OperationRecord.planned(invalid_host))
    assert run(provider.read(invalid_host.service.service_id)) is None

    stores = SQLiteStores.open(tmp_path / "unhealthy.sqlite3")
    operation_plan = plan()
    stores.operations.put(OperationRecord.planned(operation_plan))

    async def unhealthy(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(503)

    unavailable = HTTPServiceProbeEvidenceProvider(
        stores.operations,
        transport=httpx.MockTransport(unhealthy),
    )
    assert run(unavailable.read(operation_plan.service.service_id)) is None

    async def failed(_request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("offline")

    disconnected = HTTPServiceProbeEvidenceProvider(
        stores.operations,
        transport=httpx.MockTransport(failed),
    )
    assert run(disconnected.read(operation_plan.service.service_id)) is None


def test_http_evidence_provider_rechecks_listener_identity(tmp_path: Path) -> None:
    stores = SQLiteStores.open(tmp_path / "identity.sqlite3")
    operation_plan = plan()
    listener = NetworkListener(
        protocol="tcp",
        address="127.0.0.1",
        port=8080,
        pid=123,
        process_name="fixture",
    )
    fingerprint = compute_service_fingerprint(
        node_id=operation_plan.target_node_id,
        protocol=listener.protocol,
        address=listener.address,
        port=listener.port,
        process_pid=listener.pid,
        process_name=listener.process_name,
    )
    service = operation_plan.service.model_copy(update={"fingerprint": fingerprint})
    operation_plan = OperationPlan.model_validate(
        {
            **operation_plan.model_dump(),
            "service": service,
            "idempotency_key": compute_idempotency_key(
                request_node_id=operation_plan.request_node_id,
                target_node_id=operation_plan.target_node_id,
                tool_name=operation_plan.tool_name,
                plan_version=operation_plan.plan_version,
                service_fingerprint=fingerprint,
                access_scope=operation_plan.access_scope,
            ),
        }
    )
    stores.operations.put(OperationRecord.planned(operation_plan))

    class Reader:
        values: tuple[NetworkListener, ...] = (listener,)

        def listeners(self) -> tuple[NetworkListener, ...]:
            return self.values

    async def healthy(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200)

    reader = Reader()
    provider = HTTPServiceProbeEvidenceProvider(
        stores.operations,
        identity_reader=reader,
        transport=httpx.MockTransport(healthy),
    )
    assert run(provider.read(operation_plan.service.service_id)) is not None

    reader.values = (listener.model_copy(update={"pid": 456, "process_name": "replacement"}),)
    assert run(provider.read(operation_plan.service.service_id)) is None
    reader.values = ()
    assert run(provider.read(operation_plan.service.service_id)) is None
    reader.values = (listener, listener)
    assert run(provider.read(operation_plan.service.service_id)) is None

    class DeniedReader:
        def listeners(self) -> tuple[NetworkListener, ...]:
            raise PermissionError

    denied = HTTPServiceProbeEvidenceProvider(
        stores.operations,
        identity_reader=DeniedReader(),
        transport=httpx.MockTransport(healthy),
    )
    assert run(denied.read(operation_plan.service.service_id)) is None
