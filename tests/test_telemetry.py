"""追踪开关、隐私、导出和跨节点父子关系。"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Generator
from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from opentelemetry import trace
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import ReadableSpan, TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor, SimpleSpanProcessor, SpanExporter
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from opentelemetry.trace import StatusCode
from opentelemetry.util._once import Once
from tests.agent.test_context_runtime import _request  # pyright: ignore[reportPrivateUsage]
from tests.agent.test_langchain_agent import ScriptedProvider, build_agent, context, definition
from tests.gateway.test_model_lending import TOKEN, StubProvider, gateway
from tests.tools.test_runtime import build_runtime, request

from tunnelminion import telemetry
from tunnelminion.agent.context_runtime import ContextModelRuntime
from tunnelminion.agent.delegation import DelegationService
from tunnelminion.agent.delegation_tool import DelegateToNodeAdapter, delegate_tool_definition
from tunnelminion.agent.langchain_model import TunnelMinionChatModel
from tunnelminion.agent.model_lending import InMemoryModelUsageStore, ModelLendingService
from tunnelminion.agent.runtime import LangChainReadOnlyAgent
from tunnelminion.domain.delegation import DELEGATE_TOOL_NAME
from tunnelminion.domain.identifiers import NodeId
from tunnelminion.domain.tools import Platform
from tunnelminion.gateway.api import create_gateway_router
from tunnelminion.gateway.audit import InMemoryGatewaySecurityAuditSink
from tunnelminion.gateway.client import FixedGatewayClient
from tunnelminion.gateway.configuration import GatewayPeerConfig
from tunnelminion.gateway.security import GatewayPeerPolicy, GatewaySecurityPolicy
from tunnelminion.memory.sqlite import SQLiteStores
from tunnelminion.model.contracts import (
    CancellationToken,
    ModelRequest,
    ModelResponse,
    ModelUsage,
    ProviderError,
    ProviderErrorCode,
    ToolCall,
)
from tunnelminion.model.openai_compatible import OpenAICompatibleConfig, OpenAICompatibleProvider
from tunnelminion.model.remote import RemoteModelProvider
from tunnelminion.tools.audit import InMemoryAuditSink
from tunnelminion.tools.fakes import FakeToolAdapter
from tunnelminion.tools.registry import ToolRegistry
from tunnelminion.tools.runtime import ToolRuntime

A = NodeId("node_" + "a" * 32)
B = NodeId("node_" + "b" * 32)
MARKER = "private-message-argument-output-secret-file-marker"


@pytest.fixture(autouse=True)
def isolated_tracing(monkeypatch: pytest.MonkeyPatch) -> Generator[None]:
    monkeypatch.delenv("TUNNELMINION_TRACE", raising=False)
    monkeypatch.delenv("TUNNELMINION_TRACE_FILE", raising=False)
    monkeypatch.setattr(trace, "_TRACER_PROVIDER", None)
    monkeypatch.setattr(trace, "_TRACER_PROVIDER_SET_ONCE", Once())
    monkeypatch.setattr(telemetry, "_provider", None)
    yield
    provider = trace.get_tracer_provider()
    if isinstance(provider, TracerProvider):
        provider.shutdown()


@pytest.fixture
def spans() -> InMemorySpanExporter:
    exporter = InMemorySpanExporter()
    provider = TracerProvider(
        resource=Resource.create({"service.name": "tunnelminion"}), shutdown_on_exit=False
    )
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    trace.set_tracer_provider(provider)
    return exporter


@pytest.mark.parametrize("mode", [None, "off"])
def test_off_keeps_noop_provider_and_agent_behavior(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mode: str | None
) -> None:
    if mode is not None:
        monkeypatch.setenv("TUNNELMINION_TRACE", mode)
    assert telemetry.configure_tracing(tmp_path, A, Platform.WINDOWS) is None
    with telemetry.span("off") as current:
        result = asyncio.run(build_agent()[0].run(MARKER, context(), ("probe_service",)))
        assert not current.is_recording()
        assert telemetry.inject_headers() == {}
    assert result.model_rounds == 2 and result.tool_calls == 1
    assert not isinstance(trace.get_tracer_provider(), TracerProvider)
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("mode", ["console", "file", "otlp"])
def test_exporter_selection_and_single_configuration(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    mode: str,
) -> None:
    exporters: list[SpanExporter] = []

    def processor(exporter: SpanExporter) -> BatchSpanProcessor:
        exporters.append(exporter)
        return BatchSpanProcessor(exporter)

    monkeypatch.setattr(telemetry, "BatchSpanProcessor", processor)
    monkeypatch.setenv("TUNNELMINION_TRACE", mode)
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:4318")
    provider = telemetry.configure_tracing(tmp_path, A, Platform.WINDOWS)
    assert provider is not None
    assert telemetry.configure_tracing(tmp_path, B, Platform.MACOS) is provider
    assert len(exporters) == 1
    assert provider.resource.attributes["service.name"] == "tunnelminion"
    assert provider.resource.attributes["tunnelminion.node_id"] == str(A)
    assert provider.resource.attributes["tunnelminion.platform"] == "windows"
    if mode == "otlp":
        assert isinstance(exporters[0], telemetry.OTLPSpanExporter)
        assert exporters[0]._endpoint == "http://127.0.0.1:4318/v1/traces"  # pyright: ignore[reportPrivateUsage]
    else:
        with telemetry.span("selected"):
            pass
        assert provider.force_flush()
        if mode == "console":
            assert isinstance(exporters[0], telemetry.ConsoleSpanExporter)
            output = capsys.readouterr()
            assert '"name": "selected"' in output.err and output.out == ""
        else:
            assert isinstance(exporters[0], telemetry.JsonLinesSpanExporter)
            assert json.loads((tmp_path / "traces.jsonl").read_text())["name"] == "selected"


def test_unknown_exporter_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TUNNELMINION_TRACE", "unknown")
    with pytest.raises(ValueError, match="TUNNELMINION_TRACE"):
        telemetry.configure_tracing(tmp_path, A, Platform.WINDOWS)


def test_file_export_has_ids_parent_timing_status_and_safe_attributes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "custom" / "spans.jsonl"
    monkeypatch.setenv("TUNNELMINION_TRACE", "file")
    monkeypatch.setenv("TUNNELMINION_TRACE_FILE", str(path))
    provider = telemetry.configure_tracing(tmp_path, B, Platform.MACOS)
    assert provider is not None
    with (
        telemetry.span("root"),
        pytest.raises(RuntimeError),
        telemetry.span("child", {"safe": True}),
    ):
        raise RuntimeError(MARKER)
    assert provider.force_flush()
    child, root = [json.loads(line) for line in path.read_text().splitlines()]
    assert child["trace_id"] == root["trace_id"] and len(root["trace_id"]) == 32
    assert child["parent_span_id"] == root["span_id"] and len(root["span_id"]) == 16
    assert root["parent_span_id"] is None
    assert root["start_ns"] <= child["start_ns"] <= child["end_ns"] <= root["end_ns"]
    assert child["attributes"] == {"safe": True, "status": "error"}
    assert child["status"] == "ERROR" and root["status"] == "OK"
    assert root["resource"] == {
        "service.name": "tunnelminion",
        "tunnelminion.node_id": str(B),
        "tunnelminion.platform": "macos",
    }
    assert MARKER not in path.read_text()


@pytest.mark.parametrize("enabled", [False, True])
@pytest.mark.parametrize("existing", [False, True])
def test_lifespan_configures_at_startup_and_flushes_on_shutdown(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, enabled: bool, existing: bool
) -> None:
    if enabled:
        monkeypatch.setenv("TUNNELMINION_TRACE", "file")
    original = FastAPI().router.lifespan_context if existing else None
    app = FastAPI(lifespan=telemetry.tracing_lifespan(tmp_path, A, Platform.WINDOWS, original))
    with TestClient(app), telemetry.span("lifespan"):
        pass
    path = tmp_path / "traces.jsonl"
    assert path.exists() is enabled
    if enabled:
        assert json.loads(path.read_text())["name"] == "lifespan"


def test_model_attributes_tokens_and_exception_privacy(spans: InMemorySpanExporter) -> None:
    provider = StubProvider(
        ModelResponse(
            content=MARKER, usage=ModelUsage(input_tokens=11, output_tokens=3, total_tokens=14)
        )
    )
    invocation = asyncio.run(
        ContextModelRuntime(
            provider, provider_name="test-provider", model_name="test-model"
        ).invoke(_request(current_intent=MARKER))
    )
    assert invocation.response.content == MARKER
    recorded = spans.get_finished_spans()
    assert len(recorded) == 1 and recorded[0].name == "model.call"
    assert recorded[0].attributes == {
        "model.provider": "test-provider",
        "model.name": "test-model",
        "model.input_tokens": 11,
        "model.output_tokens": 3,
        "model.total_tokens": 14,
        "status": "success",
    }
    failed_provider = StubProvider(error=ProviderError(ProviderErrorCode.INVALID_RESPONSE, MARKER))
    with pytest.raises(ProviderError):
        asyncio.run(ContextModelRuntime(failed_provider).invoke(_request()))
    failed = spans.get_finished_spans()[-1]
    assert failed.status.status_code is StatusCode.ERROR and failed.events == ()
    assert all(MARKER not in item.to_json() for item in spans.get_finished_spans())
    named = OpenAICompatibleProvider(
        OpenAICompatibleConfig(endpoint="http://127.0.0.1", model="qwen")
    )
    assert telemetry.model_attributes(named)["model.name"] == "qwen"


@pytest.mark.parametrize("max_bytes, status", [(1024, "success"), (10, "partial")])
def test_tool_attributes_exclude_arguments_and_outputs(
    spans: InMemorySpanExporter, max_bytes: int, status: str
) -> None:
    runtime, _ = build_runtime(FakeToolAdapter(), max_bytes=max_bytes)
    tool_request = request(port=8082, note=MARKER, api_token=MARKER)
    result = asyncio.run(runtime.execute(tool_request))
    current = spans.get_finished_spans()[0]
    attributes = current.attributes
    assert attributes is not None
    assert attributes["tool.name"] == "probe_service" and attributes["status"] == status
    assert attributes["tool.execution_node"] == str(tool_request.context.execution_node_id)
    assert attributes["tool.truncated"] is result.truncated
    assert float(str(attributes["tool.duration_ms"])) >= 0
    assert all(MARKER not in item.to_json() for item in spans.get_finished_spans())


class DelegatingProvider(ScriptedProvider):
    async def complete(
        self, request: ModelRequest, cancellation: CancellationToken | None = None
    ) -> ModelResponse:
        self.requests.append(request)
        if len(self.requests) == 1:
            return ModelResponse(
                tool_calls=(
                    ToolCall(
                        call_id="delegate-1",
                        name=DELEGATE_TOOL_NAME,
                        arguments={"node_id": str(B), "question": MARKER},
                    ),
                )
            )
        return ModelResponse(content="已收到对方的结论")


def test_delegation_keeps_one_trace_after_submission_returns(
    tmp_path: Path, spans: InMemorySpanExporter
) -> None:
    headers: list[httpx.Headers] = []

    class Transport(httpx.ASGITransport):
        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            headers.append(request.headers)
            return await super().handle_async_request(request)

    async def scenario() -> None:
        release = asyncio.Event()

        class DeferredProvider(ScriptedProvider):
            async def complete(
                self, request: ModelRequest, cancellation: CancellationToken | None = None
            ) -> ModelResponse:
                await release.wait()
                return await super().complete(request, cancellation)

        registry_b = ToolRegistry()
        registry_b.register(
            definition().model_copy(update={"platforms": frozenset({Platform.MACOS})}),
            FakeToolAdapter(),
        )
        runtime_b = ToolRuntime(registry_b, Platform.MACOS, InMemoryAuditSink())
        agent_b = LangChainReadOnlyAgent(
            TunnelMinionChatModel(provider=DeferredProvider()),
            registry_b,
            runtime_b,
            Platform.MACOS,
        )
        stores = SQLiteStores.open(tmp_path / "runtime.sqlite3")
        service = DelegationService(
            B, stores.delegations, lambda: agent_b, lambda: ("probe_service",)
        )
        app = FastAPI()
        app.include_router(
            create_gateway_router(
                B,
                Platform.MACOS,
                registry_b,
                runtime_b,
                GatewaySecurityPolicy(
                    [
                        GatewayPeerPolicy.from_token(
                            A, TOKEN, ("probe_service",), allow_delegation=True
                        )
                    ]
                ),
                InMemoryGatewaySecurityAuditSink(),
                delegation_service=service,
            )
        )
        client = FixedGatewayClient(
            "http://127.0.0.1:8787", TOKEN, A, B, InMemoryAuditSink(), transport=Transport(app=app)
        )

        async def poll(_: float) -> None:
            release.set()
            await asyncio.sleep(0.01)

        registry_a = ToolRegistry()
        registry_a.register(definition(), FakeToolAdapter())
        registry_a.register(
            delegate_tool_definition(
                [
                    GatewayPeerConfig(
                        node_id=B, host="127.0.0.1", allowed_tools=frozenset({"probe_service"})
                    )
                ],
                Platform.WINDOWS,
            ),
            DelegateToNodeAdapter(lambda _: client, sleep=poll),
        )
        agent_a = LangChainReadOnlyAgent(
            TunnelMinionChatModel(provider=DelegatingProvider()),
            registry_a,
            ToolRuntime(registry_a, Platform.WINDOWS, InMemoryAuditSink()),
            Platform.WINDOWS,
        )
        incoming = telemetry.extract_context(
            {"traceparent": "00-" + "1" * 32 + "-" + "2" * 16 + "-01", "tracestate": "test=opaque"}
        )
        with telemetry.span("question", parent=incoming):
            local_context = context().model_copy(
                update={"caller_node_id": A, "execution_node_id": A}
            )
            result = await agent_a.run(MARKER, local_context, ("probe_service",))
            assert result.tool_calls == 1

    asyncio.run(scenario())
    recorded = spans.get_finished_spans()
    assert len({item.context.trace_id for item in recorded if item.context is not None}) == 1
    agents = [item for item in recorded if item.name == "agent.run"]
    assert len(agents) == 2
    for item in agents:
        attributes = item.attributes
        assert attributes is not None
        assert attributes["agent.rounds"] == 2 and attributes["agent.tool_calls"] == 1
        assert attributes["agent.stop_reason"] == "completed"
        assert str(attributes["agent.run_id"]).startswith("run_")
    delegated = next(
        item
        for item in agents
        if item.attributes and item.attributes["tunnelminion.platform"] == "macos"
    )
    by_id = {item.context.span_id: item for item in recorded if item.context is not None}
    chain: list[ReadableSpan] = []
    current = delegated
    while current.parent is not None and current.parent.span_id in by_id:
        current = by_id[current.parent.span_id]
        chain.append(current)
    assert [item.name for item in chain] == [
        "gateway.server.submit_delegation",
        "gateway.client.submit_delegation",
        "tool.call",
        "agent.run",
        "question",
    ]
    assert chain[0].parent is not None and chain[0].parent.is_remote
    assert chain[2].attributes and chain[2].attributes["tool.name"] == DELEGATE_TOOL_NAME
    assert len([item for item in recorded if item.name == "model.call"]) == 4
    assert any(item.name == "gateway.client.delegation_status" for item in recorded)
    assert all(
        "traceparent" in item and item.get("tracestate") == "test=opaque" for item in headers
    )
    assert all(MARKER not in item.to_json() for item in recorded)


def test_borrowed_model_spans_include_both_boundaries_and_usage(
    spans: InMemorySpanExporter,
) -> None:
    stub = StubProvider(ModelResponse(content=MARKER, usage=ModelUsage(total_tokens=17)))
    service = ModelLendingService(B, lambda: stub, InMemoryModelUsageStore())
    client = FixedGatewayClient(
        "http://127.0.0.1:8787",
        TOKEN,
        A,
        B,
        InMemoryAuditSink(),
        transport=httpx.ASGITransport(app=gateway(service)),
    )
    result = asyncio.run(ContextModelRuntime(RemoteModelProvider(client, A)).invoke(_request()))
    assert result.response.content == MARKER
    recorded = spans.get_finished_spans()
    models = [item for item in recorded if item.name == "model.call"]
    assert len(models) == 3
    assert all(item.attributes and item.attributes["model.total_tokens"] == 17 for item in models)
    assert len({item.context.trace_id for item in recorded if item.context is not None}) == 1
    assert all(MARKER not in item.to_json() for item in recorded)
