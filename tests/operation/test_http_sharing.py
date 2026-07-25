"""有界 HTTP 共享代理、资源所有权和状态护栏测试。"""

from __future__ import annotations

import socket
import threading
import time
from collections.abc import AsyncIterator, Callable
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from fastapi import FastAPI, Request
from tests.operation.factories import NOW, plan

import tunnelminion.operation.http_sharing as http_sharing
from tunnelminion.domain.identifiers import LeaseId, OperationId
from tunnelminion.operation.contracts import (
    AccessScope,
    CleanupResult,
    LeaseRecord,
    OperationPlan,
    ServiceEvidence,
    compute_idempotency_key,
)
from tunnelminion.operation.http_sharing import (
    SHARE_TOKEN_HEADER,
    HTTPProxyLimits,
    HTTPSharingAdapter,
    HTTPSharingConfig,
    ProxyRuntime,
    StopResult,
    UvicornProxyRuntime,
    create_bounded_proxy_app,
    validate_http_sharing_plan,
)
from tunnelminion.tools.state_guard import (
    PlatformStateSnapshot,
    ReadOnlyStateGuard,
)

TOKEN = "t" * 43


def _config(**updates: object) -> HTTPSharingConfig:
    operation_plan = plan()
    values: dict[str, object] = {
        "wireguard_addresses": frozenset({"10.77.0.1"}),
        "allowed_peer_addresses": {str(operation_plan.request_node_id): frozenset({"10.77.0.2"})},
        "minimum_port": 18880,
        "maximum_port": 18899,
        "maximum_duration_seconds": 600,
        "limits": HTTPProxyLimits(
            max_concurrent_requests=2,
            max_request_bytes=16,
            max_response_bytes=32,
            request_timeout_seconds=1,
            graceful_shutdown_seconds=1,
        ),
    }
    values.update(updates)
    return HTTPSharingConfig.model_validate(values)


def _plan_with(
    source: OperationPlan,
    *,
    scope: AccessScope | None = None,
    service: ServiceEvidence | None = None,
) -> OperationPlan:
    selected_scope = scope or source.access_scope
    selected_service = service or source.service
    return OperationPlan.model_validate(
        {
            **source.model_dump(),
            "access_scope": selected_scope,
            "service": selected_service,
            "idempotency_key": compute_idempotency_key(
                request_node_id=source.request_node_id,
                target_node_id=source.target_node_id,
                tool_name=source.tool_name,
                plan_version=source.plan_version,
                service_fingerprint=selected_service.fingerprint,
                access_scope=selected_scope,
            ),
        }
    )


def _sharing_setup() -> tuple[OperationPlan, HTTPSharingConfig, LeaseRecord]:
    operation_plan = plan()
    config = _config(
        allowed_peer_addresses={str(operation_plan.request_node_id): frozenset({"10.77.0.2"})}
    )
    lease = LeaseRecord(
        lease_id=LeaseId.new(),
        operation_id=operation_plan.operation_id,
        starts_at=NOW,
        expires_at=NOW + timedelta(minutes=5),
    )
    return operation_plan, config, lease


@pytest.mark.anyio
async def test_proxy_enforces_peer_token_expiry_and_request_budgets() -> None:
    upstream = FastAPI()

    @upstream.api_route("/{path:path}", methods=["GET", "POST"])
    async def echo(path: str, request: Request) -> dict[str, object]:
        return {
            "path": path,
            "body": (await request.body()).decode(),
            "token_forwarded": SHARE_TOKEN_HEADER.lower() in request.headers,
        }

    _ = echo
    limits = HTTPProxyLimits(
        max_concurrent_requests=1,
        max_request_bytes=16,
        max_response_bytes=128,
        request_timeout_seconds=1,
        graceful_shutdown_seconds=1,
    )
    upstream_transport = httpx.ASGITransport(app=upstream)
    app = create_bounded_proxy_app(
        upstream_url="http://upstream",
        access_token=TOKEN,
        allowed_client_addresses=frozenset({"10.77.0.2"}),
        expires_at=NOW + timedelta(minutes=1),
        limits=limits,
        transport=upstream_transport,
        now=lambda: NOW,
    )
    allowed_transport = httpx.ASGITransport(app=app, client=("10.77.0.2", 1234))
    async with httpx.AsyncClient(transport=allowed_transport, base_url="http://proxy") as client:
        denied = await client.get("/denied")
        accepted = await client.post(
            "/accepted",
            headers={SHARE_TOKEN_HEADER: TOKEN},
            content=b"hello",
        )
        too_large = await client.post(
            "/large",
            headers={SHARE_TOKEN_HEADER: TOKEN},
            content=b"x" * 17,
        )
        invalid_length = await client.post(
            "/invalid-length",
            headers={SHARE_TOKEN_HEADER: TOKEN, "content-length": "not-a-number"},
            content=b"x",
        )

        async def body_stream() -> AsyncIterator[bytes]:
            yield b"x" * 17

        streamed_too_large = await client.post(
            "/stream-large",
            headers={SHARE_TOKEN_HEADER: TOKEN},
            content=body_stream(),
        )
        health = await client.get(
            "/__tunnelminion_health",
            headers={SHARE_TOKEN_HEADER: TOKEN},
        )
    assert denied.status_code == 401
    assert accepted.status_code == 200
    assert accepted.json() == {
        "path": "accepted",
        "body": "hello",
        "token_forwarded": False,
    }
    assert too_large.status_code == 413
    assert invalid_length.status_code == 400
    assert streamed_too_large.status_code == 413
    assert health.status_code == 204

    forbidden_transport = httpx.ASGITransport(app=app, client=("10.77.0.3", 1234))
    async with httpx.AsyncClient(transport=forbidden_transport, base_url="http://proxy") as client:
        forbidden = await client.get("/", headers={SHARE_TOKEN_HEADER: TOKEN})
    assert forbidden.status_code == 403

    expired_app = create_bounded_proxy_app(
        upstream_url="http://upstream",
        access_token=TOKEN,
        allowed_client_addresses=frozenset({"10.77.0.2"}),
        expires_at=NOW,
        limits=limits,
        transport=upstream_transport,
        now=lambda: NOW,
    )
    expired_transport = httpx.ASGITransport(
        app=expired_app,
        client=("10.77.0.2", 1234),
    )
    async with httpx.AsyncClient(transport=expired_transport, base_url="http://proxy") as client:
        expired = await client.get("/", headers={SHARE_TOKEN_HEADER: TOKEN})
    assert expired.status_code == 410


@pytest.mark.anyio
async def test_proxy_maps_upstream_timeout_failure_and_response_budget() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/timeout":
            raise httpx.ReadTimeout("injected")
        if request.url.path == "/unavailable":
            raise httpx.ConnectError("injected")
        return httpx.Response(200, content=b"x" * 33)

    app = create_bounded_proxy_app(
        upstream_url="http://upstream",
        access_token=TOKEN,
        allowed_client_addresses=frozenset({"10.77.0.2"}),
        expires_at=NOW + timedelta(minutes=1),
        limits=HTTPProxyLimits(
            max_concurrent_requests=1,
            max_request_bytes=16,
            max_response_bytes=32,
            request_timeout_seconds=1,
            graceful_shutdown_seconds=1,
        ),
        transport=httpx.MockTransport(handler),
        now=lambda: NOW,
    )
    transport = httpx.ASGITransport(app=app, client=("10.77.0.2", 1234))
    async with httpx.AsyncClient(transport=transport, base_url="http://proxy") as client:
        timeout = await client.get("/timeout", headers={SHARE_TOKEN_HEADER: TOKEN})
        unavailable = await client.get("/unavailable", headers={SHARE_TOKEN_HEADER: TOKEN})
        oversized = await client.get("/large", headers={SHARE_TOKEN_HEADER: TOKEN})
    assert timeout.status_code == 504
    assert unavailable.status_code == 502
    assert oversized.status_code == 502


INVALID_PLAN_CASES: list[
    tuple[Callable[[OperationPlan], OperationPlan], dict[str, object], str]
] = [
    (
        lambda item: _plan_with(
            item,
            scope=item.access_scope.model_copy(update={"bind_host": "0.0.0.0"}),
        ),
        {},
        "WireGuard 私网",
    ),
    (
        lambda item: _plan_with(
            item,
            scope=item.access_scope.model_copy(update={"bind_host": "8.8.8.8"}),
        ),
        {},
        "WireGuard 私网",
    ),
    (
        lambda item: _plan_with(
            item,
            scope=item.access_scope.model_copy(update={"bind_host": "10.77.0.9"}),
        ),
        {},
        "允许",
    ),
    (
        lambda item: item,
        {"minimum_port": 18900, "maximum_port": 18899},
        "范围无效",
    ),
    (
        lambda item: _plan_with(
            item,
            scope=item.access_scope.model_copy(update={"bind_port": 19000}),
        ),
        {},
        "超出",
    ),
    (
        lambda item: _plan_with(
            item,
            scope=item.access_scope.model_copy(update={"duration_seconds": 601}),
        ),
        {},
        "持续时间",
    ),
    (
        lambda item: _plan_with(
            item,
            service=item.service.model_copy(update={"host": "10.77.0.8"}),
        ),
        {},
        "环回",
    ),
    (
        lambda item: _plan_with(
            item,
            service=item.service.model_copy(update={"scheme": "https"}),
        ),
        {},
        "明文环回 HTTP",
    ),
]


@pytest.mark.parametrize(
    ("mutate", "config_updates", "message"),
    INVALID_PLAN_CASES,
)
def test_plan_validation_rejects_non_wireguard_or_unsupported_scope(
    mutate: Callable[[OperationPlan], OperationPlan],
    config_updates: dict[str, object],
    message: str,
) -> None:
    operation_plan, config, _ = _sharing_setup()
    changed = mutate(operation_plan)
    config = config.model_copy(update=config_updates)
    with pytest.raises(ValueError, match=message):
        validate_http_sharing_plan(changed, config)


def test_plan_validation_requires_configured_private_peer_address() -> None:
    operation_plan, config, _ = _sharing_setup()
    with pytest.raises(ValueError, match="没有配置"):
        validate_http_sharing_plan(
            operation_plan,
            config.model_copy(update={"allowed_peer_addresses": {}}),
        )
    with pytest.raises(ValueError, match="来源"):
        validate_http_sharing_plan(
            operation_plan,
            config.model_copy(
                update={
                    "allowed_peer_addresses": {
                        str(operation_plan.request_node_id): frozenset({"127.0.0.1"})
                    }
                }
            ),
        )


class FakeProxyRuntime(ProxyRuntime):
    """记录适配器生命周期调用的假代理运行时。"""

    def __init__(
        self,
        *,
        stop_result: StopResult = StopResult.STOPPED,
        start_error: Exception | None = None,
    ) -> None:
        self.stop_result = stop_result
        self.start_error = start_error
        self.starts: list[dict[str, object]] = []
        self.stops: list[dict[str, object]] = []

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
        del app
        if self.start_error is not None:
            raise self.start_error
        self.starts.append(
            {
                "host": host,
                "port": port,
                "fingerprint": owner_fingerprint,
                "expires_at": expires_at,
                "grace": graceful_shutdown_seconds,
            }
        )
        return 4321

    def stop(
        self,
        *,
        host: str,
        port: int,
        owner_fingerprint: str,
    ) -> StopResult:
        self.stops.append({"host": host, "port": port, "fingerprint": owner_fingerprint})
        return self.stop_result


@pytest.mark.anyio
async def test_adapter_creates_owned_resource_and_classifies_cleanup() -> None:
    operation_plan, config, lease = _sharing_setup()
    runtime = FakeProxyRuntime()
    adapter = HTTPSharingAdapter(config, runtime)
    execution = await adapter.create(operation_plan, lease, TOKEN)
    assert execution.error is None
    assert execution.resources[0].process_id == 4321
    assert runtime.starts[0]["host"] == "10.77.0.1"
    assert TOKEN not in execution.model_dump_json()

    cleaned = await adapter.cleanup(
        operation_plan.operation_id,
        execution.resources,
        at=NOW + timedelta(seconds=1),
    )
    assert cleaned.result is CleanupResult.SUCCEEDED
    assert "forced_or_scheduled" in cleaned.reason

    empty = await adapter.cleanup(operation_plan.operation_id, (), at=NOW)
    assert empty.result is CleanupResult.SUCCEEDED

    missing_runtime = FakeProxyRuntime(stop_result=StopResult.ALREADY_MISSING)
    missing = await HTTPSharingAdapter(config, missing_runtime).cleanup(
        operation_plan.operation_id,
        execution.resources,
        at=lease.expires_at,
    )
    assert missing.result is CleanupResult.SUCCEEDED
    assert "normal_expiry" in missing.reason


@pytest.mark.anyio
async def test_adapter_never_stops_unknown_resource_and_surfaces_failure() -> None:
    operation_plan, config, lease = _sharing_setup()
    execution = await HTTPSharingAdapter(config, FakeProxyRuntime()).create(
        operation_plan,
        lease,
        TOKEN,
    )
    resource = execution.resources[0]

    foreign = resource.model_copy(update={"operation_id": OperationId.new()})
    mismatch = await HTTPSharingAdapter(config, FakeProxyRuntime()).cleanup(
        operation_plan.operation_id,
        (foreign,),
        at=NOW,
    )
    assert mismatch.result is CleanupResult.OWNERSHIP_MISMATCH

    for stop_result, expected in (
        (StopResult.OWNERSHIP_MISMATCH, CleanupResult.OWNERSHIP_MISMATCH),
        (StopResult.FAILED, CleanupResult.FAILED),
    ):
        result = await HTTPSharingAdapter(
            config,
            FakeProxyRuntime(stop_result=stop_result),
        ).cleanup(operation_plan.operation_id, (resource,), at=NOW)
        assert result.result is expected
        assert result.manual_action is not None


@pytest.mark.anyio
async def test_adapter_rejects_invalid_lease_token_and_port_conflict() -> None:
    operation_plan, config, lease = _sharing_setup()
    invalid_cases = (
        (
            lease.model_copy(update={"operation_id": OperationId.new()}),
            TOKEN,
            FakeProxyRuntime(),
        ),
        (lease, "short", FakeProxyRuntime()),
        (lease, TOKEN, FakeProxyRuntime(start_error=OSError("occupied"))),
        (lease, TOKEN, FakeProxyRuntime(start_error=RuntimeError("failed"))),
    )
    for invalid_lease, token, runtime in invalid_cases:
        result = await HTTPSharingAdapter(config, runtime).create(
            operation_plan,
            invalid_lease,
            token,
        )
        assert result.error is not None
        assert result.resources == ()


class StableSnapshotProvider:
    """证明适配器不接触用户网络、服务、容器和配置摘要。"""

    async def capture(self) -> PlatformStateSnapshot:
        return PlatformStateSnapshot(
            wireguard_digest="wg-stable",
            routes_digest="routes-stable",
            containers_digest="docker-stable",
            services_digest="services-stable",
        )


@pytest.mark.anyio
async def test_adapter_lifecycle_preserves_external_platform_state() -> None:
    operation_plan, config, lease = _sharing_setup()
    runtime = FakeProxyRuntime()
    adapter = HTTPSharingAdapter(config, runtime)
    async with ReadOnlyStateGuard(StableSnapshotProvider()):
        execution = await adapter.create(operation_plan, lease, TOKEN)
        await adapter.cleanup(operation_plan.operation_id, execution.resources, at=NOW)


def _free_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def test_uvicorn_runtime_starts_checks_ownership_stops_and_auto_expires() -> None:
    runtime = UvicornProxyRuntime()
    app = FastAPI()

    @app.get("/")
    async def ready() -> dict[str, bool]:
        return {"ready": True}

    _ = ready
    port = _free_loopback_port()
    fingerprint = f"sha256:{'5' * 64}"
    process_id = runtime.start(
        app,
        host="127.0.0.1",
        port=port,
        owner_fingerprint=fingerprint,
        expires_at=datetime_now_plus(milliseconds=3_600_000),
        graceful_shutdown_seconds=1,
    )
    assert process_id > 0
    with pytest.raises(OSError, match="占用"):
        runtime.start(
            app,
            host="127.0.0.1",
            port=port,
            owner_fingerprint=fingerprint,
            expires_at=datetime_now_plus(milliseconds=3_600_000),
            graceful_shutdown_seconds=1,
        )
    assert (
        runtime.stop(
            host="127.0.0.1",
            port=port,
            owner_fingerprint=f"sha256:{'6' * 64}",
        )
        is StopResult.OWNERSHIP_MISMATCH
    )
    assert (
        runtime.stop(host="127.0.0.1", port=port, owner_fingerprint=fingerprint)
        is StopResult.STOPPED
    )
    assert (
        runtime.stop(host="127.0.0.1", port=port, owner_fingerprint=fingerprint)
        is StopResult.ALREADY_MISSING
    )

    expiring_port = _free_loopback_port()
    runtime.start(
        app,
        host="127.0.0.1",
        port=expiring_port,
        owner_fingerprint=fingerprint,
        expires_at=datetime_now_plus(milliseconds=500),
        graceful_shutdown_seconds=1,
    )
    time.sleep(0.8)
    deadline = time.monotonic() + 3
    result = StopResult.FAILED
    while time.monotonic() < deadline:
        result = runtime.stop(
            host="127.0.0.1",
            port=expiring_port,
            owner_fingerprint=fingerprint,
        )
        if result is StopResult.ALREADY_MISSING:
            break
        time.sleep(0.05)
    assert result is StopResult.ALREADY_MISSING


def test_uvicorn_runtime_treats_foreign_listener_as_ownership_mismatch() -> None:
    runtime = UvicornProxyRuntime()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        port = int(listener.getsockname()[1])
        assert (
            runtime.stop(
                host="127.0.0.1",
                port=port,
                owner_fingerprint=f"sha256:{'7' * 64}",
            )
            is StopResult.OWNERSHIP_MISMATCH
        )


def test_uvicorn_runtime_surfaces_startup_and_drain_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    dead_thread = threading.Thread()
    wait_for_listener = http_sharing._wait_for_listener  # pyright: ignore[reportPrivateUsage]
    assert not wait_for_listener("127.0.0.1", _free_loopback_port(), dead_thread)

    def never_ready(
        _host: str,
        _port: int,
        _thread: threading.Thread,
        _server: object | None = None,
    ) -> bool:
        return False

    runtime = UvicornProxyRuntime()
    app = FastAPI()
    port = _free_loopback_port()
    fingerprint = f"sha256:{'8' * 64}"
    monkeypatch.setattr(http_sharing, "_wait_for_listener", never_ready)
    with pytest.raises(RuntimeError, match="未能启动"):
        runtime.start(
            app,
            host="127.0.0.1",
            port=port,
            owner_fingerprint=fingerprint,
            expires_at=datetime_now_plus(milliseconds=3_600_000),
            graceful_shutdown_seconds=1,
        )

    monkeypatch.undo()
    port = _free_loopback_port()
    runtime.start(
        app,
        host="127.0.0.1",
        port=port,
        owner_fingerprint=fingerprint,
        expires_at=datetime_now_plus(milliseconds=3_600_000),
        graceful_shutdown_seconds=1,
    )
    handle = runtime._handles[("127.0.0.1", port)]  # pyright: ignore[reportPrivateUsage]
    original_is_alive = handle.thread.is_alive
    monkeypatch.setattr(handle.thread, "is_alive", lambda: True)
    assert (
        runtime.stop(
            host="127.0.0.1",
            port=port,
            owner_fingerprint=fingerprint,
        )
        is StopResult.FAILED
    )
    monkeypatch.setattr(handle.thread, "is_alive", original_is_alive)
    handle.thread.join(timeout=2)


def datetime_now_plus(*, milliseconds: int) -> datetime:
    return datetime.now(UTC) + timedelta(milliseconds=milliseconds)
