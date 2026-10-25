"""可选的调用追踪，只记录运行元数据。"""

from __future__ import annotations

import json
import os
import sys
from collections.abc import AsyncGenerator, Generator, Mapping, Sequence
from contextlib import asynccontextmanager, contextmanager
from pathlib import Path

from fastapi import FastAPI
from opentelemetry import trace
from opentelemetry.context import Context
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import ReadableSpan, TracerProvider
from opentelemetry.sdk.trace.export import (
    BatchSpanProcessor,
    ConsoleSpanExporter,
    SpanExporter,
    SpanExportResult,
)
from opentelemetry.trace import Span, SpanKind, StatusCode
from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator
from opentelemetry.util.types import AttributeValue
from starlette.types import Lifespan

from tunnelminion.domain.identifiers import NodeId
from tunnelminion.domain.tools import Platform
from tunnelminion.model.contracts import ModelUsage

_provider: TracerProvider | None = None
_propagator = TraceContextTextMapPropagator()


class JsonLinesSpanExporter(SpanExporter):
    """每行追加一个已结束的 span。"""

    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self._stream = path.open("a", encoding="utf-8")

    def export(self, spans: Sequence[ReadableSpan]) -> SpanExportResult:
        for span in spans:
            context = span.get_span_context()
            assert context is not None
            self._stream.write(
                json.dumps(
                    {
                        "trace_id": f"{context.trace_id:032x}",
                        "span_id": f"{context.span_id:016x}",
                        "parent_span_id": f"{span.parent.span_id:016x}" if span.parent else None,
                        "name": span.name,
                        "start_ns": span.start_time,
                        "end_ns": span.end_time,
                        "attributes": dict(span.attributes or {}),
                        "status": span.status.status_code.name,
                        "resource": {
                            key: value
                            for key, value in span.resource.attributes.items()
                            if key
                            in {"service.name", "tunnelminion.node_id", "tunnelminion.platform"}
                        },
                    },
                    ensure_ascii=False,
                )
                + "\n"
            )
        self._stream.flush()
        return SpanExportResult.SUCCESS

    def shutdown(self) -> None:
        self._stream.close()


def configure_tracing(data_dir: Path, node_id: NodeId, platform: Platform) -> TracerProvider | None:
    """每个进程只在显式启用时安装 SDK；SDK 在退出时排空批处理队列。"""
    global _provider
    mode = os.environ.get("TUNNELMINION_TRACE", "off").lower()
    if mode == "off":
        return None
    if _provider is not None:
        return _provider
    exporter: SpanExporter
    if mode == "console":
        exporter = ConsoleSpanExporter(out=sys.stderr)
    elif mode == "file":
        exporter = JsonLinesSpanExporter(
            Path(os.environ.get("TUNNELMINION_TRACE_FILE", data_dir / "traces.jsonl"))
        )
    elif mode == "otlp":
        exporter = OTLPSpanExporter()
    else:
        raise ValueError("TUNNELMINION_TRACE 必须为 off、console、file 或 otlp")
    provider = TracerProvider(
        resource=Resource.create(
            {
                "service.name": "tunnelminion",
                "tunnelminion.node_id": str(node_id),
                "tunnelminion.platform": platform.value,
            }
        )
    )
    provider.add_span_processor(BatchSpanProcessor(exporter))
    trace.set_tracer_provider(provider)
    _provider = provider
    return provider


def tracing_lifespan(
    data_dir: Path,
    node_id: NodeId,
    platform: Platform,
    existing: Lifespan[FastAPI] | None = None,
) -> Lifespan[FastAPI]:
    """在应用和 runtime-child 的共同启动入口配置并刷新追踪。"""

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncGenerator[None]:
        provider = configure_tracing(data_dir, node_id, platform)
        try:
            if existing is None:
                yield
            else:
                async with existing(app):
                    yield
        finally:
            if provider is not None:
                provider.force_flush()

    return lifespan


@contextmanager
def span(
    name: str,
    attributes: Mapping[str, AttributeValue] | None = None,
    *,
    parent: Context | None = None,
    kind: SpanKind = SpanKind.INTERNAL,
) -> Generator[Span]:
    """禁用异常正文和堆栈采集，避免泄漏消息、参数与路径。"""
    with trace.get_tracer("tunnelminion").start_as_current_span(
        name,
        context=parent,
        kind=kind,
        attributes=attributes,
        record_exception=False,
        set_status_on_exception=False,
    ) as current:
        try:
            yield current
        except BaseException:
            set_status(current, "error")
            raise
        else:
            if isinstance(current, ReadableSpan) and current.status.status_code is StatusCode.UNSET:
                set_status(current, "success")


def set_status(current: Span, status: str) -> None:
    """只使用稳定状态，不记录错误消息。"""
    current.set_attribute("status", status)
    current.set_status(StatusCode.OK if status in {"success", "completed"} else StatusCode.ERROR)


def record_usage(current: Span, usage: ModelUsage) -> None:
    """未知用量不写入属性。"""
    for name in ("input_tokens", "output_tokens", "total_tokens"):
        value: int | None = getattr(usage, name)
        if value is not None:
            current.set_attribute(f"model.{name}", value)


def model_attributes(
    provider: object,
    provider_name: str = "configured-provider",
    model_name: str = "configured-model",
) -> dict[str, AttributeValue]:
    return {
        "model.provider": type(provider).__name__
        if provider_name == "configured-provider"
        else provider_name,
        "model.name": getattr(provider, "model_name", model_name),
    }


def inject_headers() -> dict[str, str]:
    headers: dict[str, str] = {}
    _propagator.inject(headers)
    return headers


def extract_context(headers: Mapping[str, str]) -> Context:
    return _propagator.extract(headers)
