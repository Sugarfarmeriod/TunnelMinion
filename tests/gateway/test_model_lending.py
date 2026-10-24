"""模型提供方的认证、配额、并发、取消与用量隐私。"""

from __future__ import annotations

import asyncio
from datetime import date, timedelta
from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI

from tunnelminion.agent.model_lending import (
    InMemoryModelUsageStore,
    ModelLendingService,
    ModelUsageStore,
)
from tunnelminion.domain.identifiers import NodeId
from tunnelminion.domain.model_borrowing import (
    BorrowedMessage,
    BorrowedModelCall,
    BorrowedModelResult,
    ModelUsageRecord,
)
from tunnelminion.domain.tools import Platform
from tunnelminion.gateway.api import create_gateway_router
from tunnelminion.gateway.audit import InMemoryGatewaySecurityAuditSink
from tunnelminion.gateway.contracts import GatewayErrorCode, GatewayErrorResponse
from tunnelminion.gateway.security import GatewayLimits, GatewayPeerPolicy, GatewaySecurityPolicy
from tunnelminion.memory.sqlite import SQLiteStores
from tunnelminion.model.contracts import (
    CancellationToken,
    ModelCapabilities,
    ModelMessage,
    ModelRequest,
    ModelResponse,
    ModelUsage,
    ProviderError,
    ProviderErrorCode,
    ToolCall,
    ToolDefinition,
)
from tunnelminion.tools.audit import InMemoryAuditSink
from tunnelminion.tools.registry import ToolRegistry
from tunnelminion.tools.runtime import ToolRuntime

PEER = NodeId("node_" + "a" * 32)
PROVIDER = NodeId("node_" + "b" * 32)
OTHER = NodeId("node_" + "c" * 32)
TOKEN = "tmn_" + "d" * 40
OTHER_TOKEN = "tmn_" + "e" * 40
TODAY = date(2026, 10, 25)
AUTH = {"Authorization": f"Bearer {TOKEN}"}
URL = "/v1/model:complete"


class StubProvider:
    def __init__(
        self,
        response: ModelResponse | None = None,
        *,
        error: ProviderError | None = None,
        block: bool = False,
    ) -> None:
        self.response = response or ModelResponse(
            content="模型回复", usage=ModelUsage(total_tokens=17)
        )
        self.error = error
        self.requests: list[ModelRequest] = []
        self.cancellations: list[CancellationToken | None] = []
        self.started: asyncio.Queue[None] = asyncio.Queue()
        self.release = asyncio.Event()
        if not block:
            self.release.set()

    @property
    def capabilities(self) -> ModelCapabilities:
        return ModelCapabilities(tool_calls=True, structured_output=True)

    async def complete(
        self, request: ModelRequest, cancellation: CancellationToken | None = None
    ) -> ModelResponse:
        self.requests.append(request)
        self.cancellations.append(cancellation)
        self.started.put_nowait(None)
        await self.release.wait()
        if self.error is not None:
            raise self.error
        return self.response


def peer(
    node_id: NodeId = PEER,
    *,
    token: str = TOKEN,
    allow: bool = True,
    quota: int = 200_000,
) -> GatewayPeerPolicy:
    return GatewayPeerPolicy.from_token(
        node_id,
        token,
        ("get_node_summary",),
        allow_model_borrowing=allow,
        daily_quota=quota,
    )


def call(caller: NodeId = PEER, content: str = "请计算这一轮") -> BorrowedModelCall:
    return BorrowedModelCall(
        caller_node_id=caller, messages=(BorrowedMessage(role="user", content=content),)
    )


def gateway(
    service: ModelLendingService | None,
    *,
    peers: tuple[GatewayPeerPolicy, ...] | None = None,
    limits: GatewayLimits | None = None,
    audit: InMemoryGatewaySecurityAuditSink | None = None,
) -> FastAPI:
    registry = ToolRegistry()
    app = FastAPI()
    app.include_router(
        create_gateway_router(
            PROVIDER,
            Platform.MACOS,
            registry,
            ToolRuntime(registry, Platform.MACOS, InMemoryAuditSink()),
            GatewaySecurityPolicy(peers or (peer(),), limits),
            audit or InMemoryGatewaySecurityAuditSink(),
            model_lending_service=service,
        )
    )
    return app


def error(response: httpx.Response, status: int, code: GatewayErrorCode) -> GatewayErrorResponse:
    assert response.status_code == status
    body = GatewayErrorResponse.model_validate_json(response.content)
    assert body.error.code is code
    return body


@pytest.mark.parametrize(
    ("authorization", "with_service", "allow", "caller", "status", "code"),
    [
        (None, False, False, OTHER, 401, GatewayErrorCode.UNAUTHENTICATED),
        ("wrong-token", True, True, PEER, 401, GatewayErrorCode.UNAUTHENTICATED),
        (TOKEN, False, False, OTHER, 503, GatewayErrorCode.MODEL_BORROWING_UNAVAILABLE),
        (TOKEN, True, False, OTHER, 403, GatewayErrorCode.MODEL_BORROWING_NOT_ALLOWED),
        (TOKEN, True, True, OTHER, 403, GatewayErrorCode.FORBIDDEN),
    ],
)
def test_gateway_checks_auth_service_permission_and_caller_in_order(
    authorization: str | None,
    with_service: bool,
    allow: bool,
    caller: NodeId,
    status: int,
    code: GatewayErrorCode,
) -> None:
    provider = StubProvider()
    store = InMemoryModelUsageStore()
    service = ModelLendingService(PROVIDER, lambda: provider, store)
    audit = InMemoryGatewaySecurityAuditSink()
    app = gateway(service if with_service else None, peers=(peer(allow=allow),), audit=audit)

    async def scenario() -> None:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://gateway"
        ) as client:
            response = await client.post(
                URL,
                json=call(caller).model_dump(mode="json"),
                headers={}
                if authorization is None
                else {"Authorization": f"Bearer {authorization}"},
            )
        error(response, status, code)

    asyncio.run(scenario())
    assert not provider.requests and not store.list()
    assert audit.records[0].action == "model_complete"
    assert audit.records[0].error_code is code


@pytest.mark.parametrize(
    ("usage", "tokens"),
    [
        (ModelUsage(input_tokens=1, output_tokens=2, total_tokens=50), 50),
        (ModelUsage(input_tokens=7, output_tokens=8), 15),
        (ModelUsage(), 0),
        (ModelUsage(input_tokens=7, output_tokens=8, total_tokens=0), 0),
        (ModelUsage(input_tokens=8), 8),
        (ModelUsage(output_tokens=4), 4),
    ],
)
def test_success_preserves_the_wire_contract_and_records_usage(
    usage: ModelUsage, tokens: int
) -> None:
    tool_call = ToolCall(call_id="call_1", name="get_node_summary", arguments={})
    original = ModelRequest(
        messages=(
            ModelMessage(role="system", content="检查节点"),
            ModelMessage(role="user", content="查看状态"),
            ModelMessage(
                role="assistant", content="", reasoning_content="工具推理", tool_calls=(tool_call,)
            ),
            ModelMessage(
                role="tool", content="在线", tool_call_id="call_1", name="get_node_summary"
            ),
        ),
        tools=(ToolDefinition(name="get_node_summary", description="节点状态", input_schema={}),),
        require_tool_call=True,
        response_schema={"type": "object"},
    )
    request = BorrowedModelCall.from_request(PEER, original)
    provider = StubProvider(
        ModelResponse(
            content="已完成",
            reasoning_content="返回推理",
            tool_calls=(tool_call,),
            structured_output={"status": "ok"},
            usage=usage,
        )
    )
    store = InMemoryModelUsageStore()
    app = gateway(ModelLendingService(PROVIDER, lambda: provider, store))

    async def scenario() -> None:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://gateway"
        ) as client:
            response = await client.post(URL, json=request.model_dump(mode="json"), headers=AUTH)
        assert response.status_code == 200
        result = BorrowedModelResult.model_validate_json(response.content)
        assert result.provider_node_id == PROVIDER
        assert result.to_response() == provider.response

    asyncio.run(scenario())
    assert provider.requests == [original]
    assert store.get(PEER, date.today()) == ModelUsageRecord(
        peer_node_id=PEER, day=date.today(), calls=1, tokens=tokens
    )


def test_invalid_tool_message_is_rejected_without_echoing_content_or_calling_the_provider(
    caplog: pytest.LogCaptureFixture,
) -> None:
    marker = "private-validation-marker"
    provider = StubProvider()
    store = InMemoryModelUsageStore()
    app = gateway(ModelLendingService(PROVIDER, lambda: provider, store))
    request = BorrowedModelCall(
        caller_node_id=PEER, messages=(BorrowedMessage(role="tool", content=marker),)
    )

    async def scenario() -> None:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://gateway"
        ) as client:
            response = await client.post(URL, json=request.model_dump(mode="json"), headers=AUTH)
        error(response, 422, GatewayErrorCode.MODEL_CALL_FAILED)
        assert marker not in response.text

    asyncio.run(scenario())
    assert not provider.requests and not store.list()
    assert marker not in caplog.text


@pytest.mark.parametrize("used", [20, 21])
def test_quota_rejects_without_counting_and_recovers_on_the_next_local_day(used: int) -> None:
    current_day = [TODAY]
    store = InMemoryModelUsageStore()
    store.add(PEER, TODAY, 2, used)
    provider = StubProvider(ModelResponse(content="完成", usage=ModelUsage(total_tokens=20)))
    service = ModelLendingService(PROVIDER, lambda: provider, store, clock=lambda: current_day[0])
    app = gateway(service, peers=(peer(quota=20),))

    async def scenario() -> None:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://gateway"
        ) as client:
            payload = call().model_dump(mode="json")
            error(
                await client.post(URL, json=payload, headers=AUTH),
                429,
                GatewayErrorCode.MODEL_QUOTA_EXCEEDED,
            )
            assert not provider.requests
            current_day[0] += timedelta(days=1)
            assert (await client.post(URL, json=payload, headers=AUTH)).status_code == 200
            error(
                await client.post(URL, json=payload, headers=AUTH),
                429,
                GatewayErrorCode.MODEL_QUOTA_EXCEEDED,
            )

    asyncio.run(scenario())
    assert store.get(PEER, TODAY).calls == 2
    assert store.get(PEER, current_day[0]).calls == 1


def test_two_calls_run_per_peer_and_the_third_is_rejected_without_queueing() -> None:
    async def scenario() -> None:
        store = InMemoryModelUsageStore()
        provider = StubProvider(block=True)
        service = ModelLendingService(PROVIDER, lambda: provider, store, clock=lambda: TODAY)
        app = gateway(service, peers=(peer(), peer(OTHER, token=OTHER_TOKEN)))
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://gateway"
        ) as client:
            payload = call().model_dump(mode="json")
            first = asyncio.create_task(client.post(URL, json=payload, headers=AUTH))
            second = asyncio.create_task(client.post(URL, json=payload, headers=AUTH))
            await asyncio.wait_for(provider.started.get(), timeout=1)
            await asyncio.wait_for(provider.started.get(), timeout=1)
            error(
                await client.post(URL, json=payload, headers=AUTH), 429, GatewayErrorCode.MODEL_BUSY
            )
            assert len(provider.requests) == 2 and not store.list()
            other = asyncio.create_task(
                client.post(
                    URL,
                    json=call(OTHER).model_dump(mode="json"),
                    headers={"Authorization": f"Bearer {OTHER_TOKEN}"},
                )
            )
            await asyncio.wait_for(provider.started.get(), timeout=1)
            provider.release.set()
            assert all(
                response.status_code == 200
                for response in await asyncio.gather(first, second, other)
            )
            assert (await client.post(URL, json=payload, headers=AUTH)).status_code == 200
        assert store.get(PEER, TODAY).calls == 3
        assert store.get(OTHER, TODAY).calls == 1

    asyncio.run(scenario())


def test_provider_creation_failure_is_unavailable_and_counts_a_failed_call() -> None:
    def unavailable() -> StubProvider:
        raise ProviderError(
            ProviderErrorCode.MODEL_NOT_FOUND, "secret-key upstream-body", retryable=True
        )

    store = InMemoryModelUsageStore()
    app = gateway(ModelLendingService(PROVIDER, unavailable, store, clock=lambda: TODAY))

    async def scenario() -> None:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://gateway"
        ) as client:
            for _ in range(3):
                response = await client.post(URL, json=call().model_dump(mode="json"), headers=AUTH)
                body = error(response, 503, GatewayErrorCode.MODEL_BORROWING_UNAVAILABLE)
                assert body.error.message == "model_not_found"
                assert "secret-key" not in response.text and "upstream-body" not in response.text

    asyncio.run(scenario())
    assert store.get(PEER, TODAY) == ModelUsageRecord(
        peer_node_id=PEER, day=TODAY, calls=3, tokens=0
    )


@pytest.mark.parametrize("retryable", [False, True])
def test_provider_failure_returns_only_its_code_and_records_no_tokens(retryable: bool) -> None:
    provider = StubProvider(
        error=ProviderError(
            ProviderErrorCode.AUTHENTICATION_FAILED, "secret-key upstream-body", retryable=retryable
        )
    )
    store = InMemoryModelUsageStore()
    app = gateway(ModelLendingService(PROVIDER, lambda: provider, store, clock=lambda: TODAY))

    async def scenario() -> None:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://gateway"
        ) as client:
            response = await client.post(URL, json=call().model_dump(mode="json"), headers=AUTH)
        body = error(response, 502, GatewayErrorCode.MODEL_CALL_FAILED)
        assert body.error.message == "authentication_failed"
        assert body.error.retryable is retryable
        assert "secret-key" not in response.text and "upstream-body" not in response.text

    asyncio.run(scenario())
    assert store.get(PEER, TODAY).calls == 1 and store.get(PEER, TODAY).tokens == 0


def test_timeout_cancels_the_token_counts_the_failure_and_releases_the_slot(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("tunnelminion.agent.model_lending.MAX_MODEL_CALL_SECONDS", 0.01)

    async def scenario() -> None:
        provider = StubProvider(block=True)
        store = InMemoryModelUsageStore()
        app = gateway(ModelLendingService(PROVIDER, lambda: provider, store, clock=lambda: TODAY))
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://gateway"
        ) as client:
            response = await client.post(URL, json=call().model_dump(mode="json"), headers=AUTH)
            assert error(response, 504, GatewayErrorCode.MODEL_CALL_FAILED).error.retryable
            cancellation = provider.cancellations[0]
            assert cancellation is not None and cancellation.cancelled
            assert store.get(PEER, TODAY).calls == 1 and store.get(PEER, TODAY).tokens == 0
            provider.release.set()
            assert (
                await client.post(URL, json=call().model_dump(mode="json"), headers=AUTH)
            ).status_code == 200
        assert store.get(PEER, TODAY).calls == 2 and store.get(PEER, TODAY).tokens == 17

    asyncio.run(scenario())


def test_request_cancellation_propagates_and_a_call_spanning_midnight_uses_its_start_day() -> None:
    async def scenario() -> None:
        current_day = [TODAY]
        store = InMemoryModelUsageStore()
        provider = StubProvider(block=True)
        service = ModelLendingService(
            PROVIDER, lambda: provider, store, clock=lambda: current_day[0]
        )
        task = asyncio.create_task(service.complete(peer(), call()))
        await asyncio.wait_for(provider.started.get(), timeout=1)
        current_day[0] += timedelta(days=1)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        cancellation = provider.cancellations[0]
        assert cancellation is not None and cancellation.cancelled
        assert store.get(PEER, TODAY).calls == 1 and store.get(PEER, TODAY).tokens == 0
        provider.release.set()
        await service.complete(peer(), call())
        assert store.get(PEER, current_day[0]).tokens == 17

    asyncio.run(scenario())


def test_realistic_300kb_body_is_accepted_and_gateway_rate_limiting_still_applies() -> None:
    provider = StubProvider()
    store = InMemoryModelUsageStore()
    app = gateway(
        ModelLendingService(PROVIDER, lambda: provider, store),
        limits=GatewayLimits(requests_per_minute=1),
    )
    request = BorrowedModelCall(
        caller_node_id=PEER,
        messages=tuple(BorrowedMessage(role="user", content="x" * 1500) for _ in range(200)),
    )
    assert len(request.model_dump_json().encode()) > 300_000

    async def scenario() -> None:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://gateway"
        ) as client:
            payload = request.model_dump(mode="json")
            assert (await client.post(URL, json=payload, headers=AUTH)).status_code == 200
            error(
                await client.post(URL, json=payload, headers=AUTH),
                429,
                GatewayErrorCode.RATE_LIMITED,
            )

    asyncio.run(scenario())
    assert len(provider.requests) == 1


@pytest.mark.parametrize("sqlite", [False, True])
def test_usage_stores_accumulate_and_isolate_peers_and_days(tmp_path: Path, sqlite: bool) -> None:
    path = tmp_path / "runtime.sqlite3"
    store: ModelUsageStore = (
        SQLiteStores.open(path).model_usage if sqlite else InMemoryModelUsageStore()
    )
    tomorrow = TODAY + timedelta(days=1)
    assert store.get(PEER, TODAY) == ModelUsageRecord(
        peer_node_id=PEER, day=TODAY, calls=0, tokens=0
    )
    assert not store.list() and not store.list(TODAY)
    store.add(PEER, TODAY, 1, 10)
    store.add(PEER, TODAY, 2, 20)
    store.add(PEER, tomorrow, 1, 5)
    store.add(OTHER, TODAY, 1, 7)
    if sqlite:
        store = SQLiteStores.open(path).model_usage
    expected = ModelUsageRecord(peer_node_id=PEER, day=TODAY, calls=3, tokens=30)
    assert store.get(PEER, TODAY) == expected
    assert store.list() == (
        expected,
        ModelUsageRecord(peer_node_id=PEER, day=tomorrow, calls=1, tokens=5),
        ModelUsageRecord(peer_node_id=OTHER, day=TODAY, calls=1, tokens=7),
    )
    assert store.list(tomorrow) == (store.get(PEER, tomorrow),)
    assert len(store.list(TODAY)) == 2


def test_sqlite_and_audit_never_store_messages_tools_or_model_output(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    marker = "PRIVATE-MODEL-LENDING-71b0ff0d"
    path = tmp_path / "runtime.sqlite3"
    store = SQLiteStores.open(path).model_usage
    request = call(content=marker).model_copy(
        update={
            "tools": (
                ToolDefinition(name="private_tool", description=marker + "-tool", input_schema={}),
            )
        }
    )
    provider = StubProvider(ModelResponse(content=marker + "-output", reasoning_content=marker))
    audit = InMemoryGatewaySecurityAuditSink()
    app = gateway(ModelLendingService(PROVIDER, lambda: provider, store), audit=audit)

    async def scenario() -> None:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://gateway"
        ) as client:
            assert (
                await client.post(URL, json=request.model_dump(mode="json"), headers=AUTH)
            ).status_code == 200

    asyncio.run(scenario())
    assert store.get(PEER, date.today()).calls == 1
    for file in tmp_path.glob("runtime.sqlite3*"):
        assert marker.encode() not in file.read_bytes()
    assert marker not in caplog.text
    assert marker not in "".join(record.model_dump_json() for record in audit.records)
