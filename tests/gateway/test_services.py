"""服务清单的认证、筛选、隐私和固定对端读取。"""

from __future__ import annotations

import asyncio
import os
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from fastapi import FastAPI
from tests.agent.test_service_observation import FakeAdapter, collection

from tunnelminion.agent.managed_node import ServiceObservationConfig
from tunnelminion.agent.service_marks import InMemoryServiceMarkStore, ServiceMark
from tunnelminion.agent.service_observation import DeterministicServiceObserver
from tunnelminion.domain.errors import ErrorCode
from tunnelminion.domain.identifiers import NodeId
from tunnelminion.domain.tools import Platform
from tunnelminion.gateway.api import create_gateway_router
from tunnelminion.gateway.audit import InMemoryGatewaySecurityAuditSink
from tunnelminion.gateway.client import FixedGatewayClient, RemoteGatewayError
from tunnelminion.gateway.contracts import GatewayErrorCode, GatewayErrorResponse, GatewayServices
from tunnelminion.gateway.security import GatewayLimits, GatewayPeerPolicy, GatewaySecurityPolicy
from tunnelminion.gateway.services import GatewayServiceReader
from tunnelminion.platforms.process_origin import ProcessOrigin
from tunnelminion.platforms.windows.models import NetworkListener, ProcessInfo
from tunnelminion.tools.audit import InMemoryAuditSink
from tunnelminion.tools.registry import ToolRegistry
from tunnelminion.tools.runtime import ToolRuntime

LOCAL = NodeId("node_" + "a" * 32)
REMOTE = NodeId("node_" + "b" * 32)
TOKEN = "tmn_" + "fake-services-token-" * 3


def services() -> GatewayServices:
    return GatewayServices(node_id=REMOTE, display_name="测试电脑", observed_at=datetime.now(UTC))


def reader() -> tuple[GatewayServiceReader, FakeAdapter, InMemoryServiceMarkStore]:
    listeners = FakeAdapter(
        collection(
            NetworkListener(
                protocol="tcp",
                address="192.0.2.123",
                port=8081,
                pid=101,
                process_name="python",
                python_entrypoint="app.py",
                origin=ProcessOrigin.TERMINAL,
                has_web_page=True,
                web_title="示例服务",
            ),
            NetworkListener(
                protocol="tcp",
                address="127.0.0.1",
                port=8081,
                pid=101,
                process_name="python",
                python_entrypoint="app.py",
                origin=ProcessOrigin.TERMINAL,
                has_web_page=True,
            ),
            NetworkListener(
                protocol="tcp",
                address="0.0.0.0",
                port=8082,
                pid=102,
                process_name="review-only-marker",
                origin=ProcessOrigin.APP_SERVICE,
            ),
            NetworkListener(
                protocol="tcp",
                address="127.0.0.1",
                port=8083,
                pid=103,
                process_name="hidden-only-marker",
                origin=ProcessOrigin.TERMINAL,
            ),
            NetworkListener(
                protocol="tcp",
                address="127.0.0.1",
                port=8084,
                pid=104,
                process_name="mine-service",
                origin=ProcessOrigin.DESKTOP_APP,
            ),
            NetworkListener(
                protocol="tcp",
                address="127.0.0.1",
                port=8085,
                pid=os.getpid(),
                process_name="self-only-marker",
                origin=ProcessOrigin.TERMINAL,
            ),
        )
    )
    processes = FakeAdapter(
        collection(
            ProcessInfo(pid=101, name="python", status="/private/UNIQUE-PROCESS-PATH"),
            ProcessInfo(pid=102, name="review-only-marker", status="UNIQUE-COMMAND --secret"),
        )
    )
    marks = InMemoryServiceMarkStore()
    marks.set("program:hidden-only-marker@8083", ServiceMark.HIDDEN)
    marks.set("program:mine-service@8084", ServiceMark.MINE)
    observer = DeterministicServiceObserver(
        REMOTE,
        ServiceObservationConfig(),
        listeners,
        processes,
        FakeAdapter(collection()),
        marks=marks.all,
    )
    return GatewayServiceReader(REMOTE, lambda: "测试电脑", observer, marks), listeners, marks


def gateway(
    service_reader: Callable[[], Awaitable[GatewayServices]] | None,
    *,
    allowed: bool = True,
    limits: GatewayLimits | None = None,
) -> tuple[FastAPI, InMemoryGatewaySecurityAuditSink]:
    registry = ToolRegistry()
    policy = GatewaySecurityPolicy(
        [
            GatewayPeerPolicy.from_token(
                LOCAL, TOKEN, ("get_node_summary",), allow_delegation=allowed
            )
        ],
        limits,
    )
    audit = InMemoryGatewaySecurityAuditSink()
    app = FastAPI()
    app.include_router(
        create_gateway_router(
            REMOTE,
            Platform.WINDOWS,
            registry,
            ToolRuntime(registry, Platform.WINDOWS, InMemoryAuditSink()),
            policy,
            audit,
            service_reader=service_reader,
        )
    )
    return app, audit


def test_services_only_exports_show_and_mine_without_raw_details() -> None:
    service_reader, listeners, marks = reader()

    async def scenario() -> None:
        app, _ = gateway(service_reader)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app), base_url="http://127.0.0.1"
        ) as client:
            response = await client.get(
                "/v1/services", headers={"Authorization": f"Bearer {TOKEN}"}
            )
            assert response.status_code == 200
            value = GatewayServices.model_validate_json(response.content)
            entries = {entry.key: entry for entry in value.services}
            assert set(entries) == {"program:mine-service@8084", "python:app.py@8081"}
            python = entries["python:app.py@8081"]
            assert python.ports[0].port == 8081
            assert len(python.ports) == 1
            assert python.web_title == "示例服务"
            assert python.state == "running"
            assert all(entry["state"] == "running" for entry in response.json()["services"])
            assert entries["program:mine-service@8084"].mark is ServiceMark.MINE
            for marker in (
                "192.0.2.123",
                "127.0.0.1",
                "0.0.0.0",
                "address",
                "endpoints",
                "pid",
                "UNIQUE-PROCESS-PATH",
                "UNIQUE-COMMAND",
                "review-only-marker",
                "hidden-only-marker",
                "self-only-marker",
            ):
                assert marker not in response.text
            marks.set("python:app.py@8081", ServiceMark.HIDDEN)
            assert len((await service_reader()).services) == 1
            assert len(listeners.calls) == 1

    asyncio.run(scenario())


def test_services_exports_stopped_mine_with_default_running_for_older_peers() -> None:
    service_reader, _, marks = reader()
    marks.set("docker:photos", ServiceMark.MINE)

    async def scenario() -> None:
        app, _ = gateway(service_reader)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app), base_url="http://127.0.0.1"
        ) as client:
            response = await client.get(
                "/v1/services", headers={"Authorization": f"Bearer {TOKEN}"}
            )
        entries = {entry["key"]: entry for entry in response.json()["services"]}
        assert entries["docker:photos"]["state"] == "stopped"
        legacy = GatewayServices.model_validate(
            {
                **response.json(),
                "services": [
                    {
                        key: value
                        for key, value in entries["docker:photos"].items()
                        if key != "state"
                    }
                ],
            }
        )
        assert legacy.services[0].state == "running"

    asyncio.run(scenario())


@pytest.mark.parametrize(
    ("token", "allowed", "status", "code"),
    [
        (None, True, 401, GatewayErrorCode.UNAUTHENTICATED),
        ("unknown-peer-token-" * 3, True, 401, GatewayErrorCode.UNAUTHENTICATED),
        (TOKEN, False, 403, GatewayErrorCode.DELEGATION_NOT_ALLOWED),
    ],
)
def test_services_rejects_before_observation(
    token: str | None, allowed: bool, status: int, code: GatewayErrorCode
) -> None:
    async def fail() -> GatewayServices:
        raise AssertionError("未授权不能观察服务")

    async def scenario() -> None:
        app, audit = gateway(fail, allowed=allowed)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app), base_url="http://127.0.0.1"
        ) as client:
            response = await client.get(
                "/v1/services", headers={"Authorization": f"Bearer {token}"} if token else {}
            )
        assert response.status_code == status
        assert GatewayErrorResponse.model_validate_json(response.content).error.code is code
        assert audit.records[-1].error_code is code

    asyncio.run(scenario())


def test_services_rate_limit_and_response_budget() -> None:
    async def read() -> GatewayServices:
        return services()

    async def scenario() -> None:
        app, _ = gateway(read, limits=GatewayLimits(requests_per_minute=1))
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app),
            base_url="http://127.0.0.1",
            headers={"Authorization": f"Bearer {TOKEN}"},
        ) as client:
            assert (await client.get("/v1/services")).status_code == 200
            response = await client.get("/v1/services")
            assert response.status_code == 429
            assert (
                GatewayErrorResponse.model_validate_json(response.content).error.code
                is GatewayErrorCode.RATE_LIMITED
            )

    asyncio.run(scenario())


@pytest.mark.parametrize("mode", ["missing", "failed", "timeout", "large"])
def test_services_unavailable_or_over_budget(mode: str) -> None:
    async def read() -> GatewayServices:
        if mode == "failed":
            raise RuntimeError("private-error-marker")
        if mode == "timeout":
            await asyncio.Event().wait()
        return services().model_copy(update={"display_name": "x" * 600})

    async def scenario() -> None:
        app, _ = gateway(
            None if mode == "missing" else read,
            limits=GatewayLimits(max_timeout_seconds=0.01, max_response_bytes=512),
        )
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app), base_url="http://127.0.0.1"
        ) as client:
            response = await client.get(
                "/v1/services", headers={"Authorization": f"Bearer {TOKEN}"}
            )
        assert response.status_code == (413 if mode == "large" else 503)
        assert "private-error-marker" not in response.text

    asyncio.run(scenario())


def test_reader_refreshes_expired_snapshot_without_overlapping_observations() -> None:
    async def scenario() -> None:
        service_reader, listeners, _ = reader()
        first, second = await asyncio.gather(service_reader(), service_reader())
        assert first == second and len(listeners.calls) == 1
        future = datetime.now(UTC) + timedelta(minutes=1)
        service_reader._observer._clock = lambda: future  # pyright: ignore[reportPrivateUsage]
        first_snapshot = service_reader._observer.last_snapshot  # pyright: ignore[reportPrivateUsage]
        assert first_snapshot is not None
        service_reader._observer._last_snapshot = first_snapshot.model_copy(  # pyright: ignore[reportPrivateUsage]
            update={"observed_at": datetime.now(UTC) - timedelta(minutes=1)}
        )
        assert (await service_reader()).observed_at == future
        assert len(listeners.calls) == 2

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "mode", ["ok", "timeout", "connect", "invalid", "identity", "denied", "large"]
)
def test_fixed_client_service_response_validation(mode: str) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/v1/services"
        assert request.headers["Authorization"] == f"Bearer {TOKEN}"
        assert request.extensions["timeout"] == {"connect": 10, "read": 10, "write": 10, "pool": 10}
        if mode == "timeout":
            raise httpx.ReadTimeout("fake", request=request)
        if mode == "connect":
            raise httpx.ConnectError("fake", request=request)
        if mode == "denied":
            return httpx.Response(
                403, json={"error": {"code": "delegation_not_allowed", "message": "未允许"}}
            )
        value = services()
        if mode == "identity":
            value = value.model_copy(update={"node_id": LOCAL})
        body = (
            "invalid"
            if mode == "invalid"
            else "x" * 600
            if mode == "large"
            else value.model_dump_json()
        )
        return httpx.Response(200, content=body)

    client = FixedGatewayClient(
        "http://127.0.0.1",
        TOKEN,
        LOCAL,
        REMOTE,
        InMemoryAuditSink(),
        transport=httpx.MockTransport(handler),
        max_response_bytes=512,
    )
    if mode == "ok":
        assert asyncio.run(client.get_services()).node_id == REMOTE
    else:
        with pytest.raises(RemoteGatewayError) as caught:
            asyncio.run(client.get_services())
        assert (
            caught.value.code
            is {
                "timeout": ErrorCode.REMOTE_TIMEOUT,
                "connect": ErrorCode.NODE_UNREACHABLE,
                "invalid": ErrorCode.INTERNAL,
                "identity": ErrorCode.FORBIDDEN,
                "denied": ErrorCode.FORBIDDEN,
                "large": ErrorCode.RESULT_TOO_LARGE,
            }[mode]
        )
