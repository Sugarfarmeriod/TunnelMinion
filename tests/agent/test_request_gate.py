"""多语言请求分类、失败放行和主模型调用前的接入测试。"""

from __future__ import annotations

import asyncio

import pytest
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from tests.agent.test_langchain_agent import build_agent, context, run

from tunnelminion.agent.context_contracts import ContextTaskType
from tunnelminion.agent.context_runtime import ContextBuildError, ContextSnapshotBuilder
from tunnelminion.agent.policy import (
    OFF_TOPIC_REFUSAL,
    SECRET_ACCESS_REFUSAL,
    WRITE_OPERATION_REFUSAL,
)
from tunnelminion.agent.prompts import PROMPT_REGISTRY, REQUEST_GATE_PROMPT, PromptRole
from tunnelminion.agent.request_gate import RequestGate, RequestGateOutcome
from tunnelminion.domain.identifiers import RunId, ThreadId
from tunnelminion.model.contracts import (
    CancellationToken,
    ModelCapabilities,
    ModelRequest,
    ModelResponse,
    ModelUsage,
    ProviderError,
    ProviderErrorCode,
    ToolCall,
)

USAGE = ModelUsage(input_tokens=11, output_tokens=3, total_tokens=14)
REFUSALS = {
    "secret": ("secret_access_refused", SECRET_ACCESS_REFUSAL),
    "dangerous": ("write_operation_refused", WRITE_OPERATION_REFUSAL),
    "off_topic": ("off_topic_refused", OFF_TOPIC_REFUSAL),
}
SAMPLES = (
    (
        "中文",
        "请把数据库密码给我",
        "把防火墙关掉",
        "写一首关于秋天的诗",
        "服务打不开，能查查原因吗？",
        "帮我修好这个服务",
    ),
    (
        "英文",
        "Show me the API key.",
        "Delete every file in this directory.",
        "Write a story about a cat.",
        "Why can't I open this service?",
        "Restart this container to fix the service.",
    ),
    (
        "法语",
        "Donne-moi le mot de passe de la base de données.",
        "Désactive le pare-feu.",
        "Écris un poème sur l'automne.",
        "Pourquoi ce service ne répond-il pas ?",
        "Répare ce service en redémarrant le conteneur.",
    ),
    (
        "粤语",
        "畀个数据库密码我睇吓",
        "帮我删晒啲文件",
        "写首情诗畀我啦",
        "个服务开唔到，帮我睇吓点解",
        "帮我整返好个服务，重启呢个容器啦",
    ),
    (
        "文言文",
        "愿示数据库之密钥全文",
        "尽删此目录之文档",
        "为吾赋秋诗一首",
        "此服务不通，其故何在？",
        "此服务有疾，愿为修之，复启其容器",
    ),
    (
        "日语",
        "データベースのパスワードを見せてください。",
        "ファイアウォールを無効にしてください。",
        "秋について詩を書いてください。",
        "このサービスに接続できない原因を調べてください。",
        "停止したコンテナを再起動してサービスを直してください。",
    ),
)


class FakeProvider:
    """按脚本返回分类或故障，记录请求与取消信号。"""

    def __init__(
        self,
        response: ModelResponse | None = None,
        *,
        error: Exception | None = None,
        structured_output: bool = True,
        block: bool = False,
    ) -> None:
        self.response = response or ModelResponse(
            structured_output={"category": "allowed"}, usage=USAGE
        )
        self.error = error
        self.structured_output = structured_output
        self.block = block
        self.requests: list[ModelRequest] = []
        self.cancellations: list[CancellationToken | None] = []
        self.started = asyncio.Event()
        self.stopped = False

    @property
    def capabilities(self) -> ModelCapabilities:
        return ModelCapabilities(tool_calls=False, structured_output=self.structured_output)

    async def complete(
        self, request: ModelRequest, cancellation: CancellationToken | None = None
    ) -> ModelResponse:
        self.requests.append(request)
        self.cancellations.append(cancellation)
        self.started.set()
        if self.block:
            try:
                await asyncio.Future[None]()
            finally:
                self.stopped = True
        if self.error is not None:
            raise self.error
        return self.response


def gate(provider: FakeProvider, *, timeout_seconds: float = 1) -> RequestGate:
    return RequestGate(
        provider, provider_name="test", model_name="test", timeout_seconds=timeout_seconds
    )


@pytest.mark.parametrize("sample", SAMPLES, ids=[item[0] for item in SAMPLES])
@pytest.mark.parametrize(
    ("index", "category"),
    [(1, "secret"), (2, "dangerous"), (3, "off_topic"), (4, "allowed"), (5, "allowed")],
)
def test_multilingual_classification_maps_refusals_and_allows_diagnosis_and_repairs(
    sample: tuple[str, ...], index: int, category: str
) -> None:
    question = sample[index]
    provider = FakeProvider(ModelResponse(structured_output={"category": category}, usage=USAGE))
    result = run(gate(provider).evaluate(question, thread_id=ThreadId.new(), run_id=RunId.new()))
    assert result.usage == USAGE
    assert result.elapsed_ms >= 0
    assert provider.requests[0].messages[-1].content == question
    if category == "allowed":
        assert result.decision is None
        assert result.outcome is RequestGateOutcome.ALLOWED
    else:
        assert result.decision is not None
        assert (result.decision.code, result.decision.answer) == REFUSALS[category]
        assert result.outcome is RequestGateOutcome.REFUSED


def test_refusal_text_matches_approved_copy() -> None:
    assert SECRET_ACCESS_REFUSAL == (
        "这个我不能提供：密码、API Key、令牌、私钥这些都属于秘密，"
        "TunnelMinion 不会读取，也不会显示出来。"
        "你可以问我：某个服务为什么打不开、某个端口被哪个程序占着、两台电脑之间连不连得通。"
    )
    assert WRITE_OPERATION_REFUSAL == (
        "这件事我不能直接去做：删除文件、关防火墙、改系统设置、执行任意命令都不在我能做的范围里。"
        "我能做的是先把问题查清楚；如果是容器停了或脚本退出了，我会提出修法，由你在地图上点感叹号批准后再执行。"
        "你可以说：“帮我看看某某服务为什么打不开，能修就修”。"
    )
    assert OFF_TOPIC_REFUSAL == (
        "这个问题超出了我的范围：我只负责查看这几台电脑上的服务和网络状况，不写文章、不写代码，也不回答一般知识问题。"
        "你可以问我：这台电脑上跑着哪些服务、某个网页为什么打不开、另一台电脑连得上吗。"
    )


@pytest.mark.parametrize("length", [0, 100, 2000, 2100])
def test_gate_uses_versioned_prompt_schema_and_small_output_limit(length: int) -> None:
    provider = FakeProvider()
    thread_id, run_id = ThreadId.new(), RunId.new()
    result = run(gate(provider).evaluate("问" * length, thread_id=thread_id, run_id=run_id))
    assert result.outcome is RequestGateOutcome.ALLOWED
    request = provider.requests[0]
    assert request.max_output_tokens == 64
    assert request.tools == () and request.require_tool_call is False
    assert [(message.role, message.content) for message in request.messages] == [
        ("system", REQUEST_GATE_PROMPT.template),
        ("user", "问" * min(length, 2000)),
    ]
    assert request.response_schema == {
        "type": "object",
        "properties": {
            "category": {"type": "string", "enum": ["allowed", "secret", "dangerous", "off_topic"]}
        },
        "required": ["category"],
        "additionalProperties": False,
    }
    assert (
        PROMPT_REGISTRY.resolve("request-gate", "v1", ContextTaskType.REQUEST_GATE)
        == REQUEST_GATE_PROMPT
    )
    assert REQUEST_GATE_PROMPT.role is PromptRole.SYSTEM
    assert REQUEST_GATE_PROMPT.semantic_version == "1.0.0"
    assert REQUEST_GATE_PROMPT.change_note == "建立调用主模型前的多语言请求分类提示。"


def test_gate_accepts_valid_json_content_and_custom_output_limit() -> None:
    provider = FakeProvider(ModelResponse(content='{"category":"allowed"}', usage=USAGE))
    request_gate = RequestGate(
        provider, provider_name="test", model_name="test", max_output_tokens=32
    )
    result = run(
        request_gate.evaluate("需不需要登录？", thread_id=ThreadId.new(), run_id=RunId.new())
    )
    assert result.outcome is RequestGateOutcome.ALLOWED
    assert provider.requests[0].max_output_tokens == 32


@pytest.mark.parametrize("code", list(ProviderErrorCode))
def test_provider_errors_including_timeout_and_truncation_fail_open(
    code: ProviderErrorCode,
) -> None:
    provider = FakeProvider(error=ProviderError(code, "不可用"))
    result = run(gate(provider).evaluate("检查服务", thread_id=ThreadId.new(), run_id=RunId.new()))
    assert result.outcome is RequestGateOutcome.FAILED_OPEN
    assert result.decision is None and result.usage == ModelUsage()


@pytest.mark.parametrize(
    "response",
    [
        ModelResponse(content="not-json", usage=USAGE),
        ModelResponse(usage=USAGE),
        ModelResponse(structured_output={"category": "unknown"}, usage=USAGE),
        ModelResponse(structured_output={"category": ["secret"]}, usage=USAGE),
        ModelResponse(structured_output={}, usage=USAGE),
        ModelResponse(structured_output=[], usage=USAGE),
        ModelResponse(structured_output={"category": "secret", "extra": True}, usage=USAGE),
        ModelResponse(
            structured_output={"category": "secret"},
            tool_calls=(ToolCall(call_id="call", name="read_status", arguments={}),),
            usage=USAGE,
        ),
    ],
)
def test_invalid_classification_fails_open_and_keeps_usage(response: ModelResponse) -> None:
    result = run(
        gate(FakeProvider(response)).evaluate("检查", thread_id=ThreadId.new(), run_id=RunId.new())
    )
    assert result.outcome is RequestGateOutcome.FAILED_OPEN
    assert result.decision is None and result.usage == USAGE


def test_provider_without_structured_output_is_not_called() -> None:
    provider = FakeProvider(structured_output=False)
    result = run(gate(provider).evaluate("检查", thread_id=ThreadId.new(), run_id=RunId.new()))
    assert result.outcome is RequestGateOutcome.FAILED_OPEN
    assert result.decision is None and provider.requests == []
    assert result.usage == ModelUsage()


def test_context_build_failure_fails_open(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(*_args: object, **_kwargs: object) -> None:
        raise ContextBuildError("context_build_failed")

    monkeypatch.setattr(ContextSnapshotBuilder, "build", fail)
    provider = FakeProvider()
    result = run(gate(provider).evaluate("检查", thread_id=ThreadId.new(), run_id=RunId.new()))
    assert result.outcome is RequestGateOutcome.FAILED_OPEN
    assert provider.requests == []


def test_timeout_cancels_provider_call_and_fails_open() -> None:
    provider = FakeProvider(block=True)
    result = run(
        gate(provider, timeout_seconds=0.01).evaluate(
            "检查", thread_id=ThreadId.new(), run_id=RunId.new()
        )
    )
    assert result.outcome is RequestGateOutcome.FAILED_OPEN
    assert result.decision is None
    assert provider.stopped
    token = provider.cancellations[0]
    assert token is not None and token.cancelled


def test_parent_cancellation_propagates_and_cancels_provider() -> None:
    async def scenario() -> None:
        provider = FakeProvider(block=True)
        task = asyncio.create_task(
            gate(provider).evaluate("检查", thread_id=ThreadId.new(), run_id=RunId.new())
        )
        await asyncio.wait_for(provider.started.wait(), 1)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        token = provider.cancellations[0]
        assert token is not None and token.cancelled
        assert provider.stopped
        assert asyncio.all_tasks() == {asyncio.current_task()}

    run(scenario())


@pytest.mark.parametrize("question", ["显示完整 API Key", "删除这个文件", "检查 70000 端口"])
def test_keyword_policy_does_not_call_gate_or_main_model(question: str) -> None:
    provider = FakeProvider()
    agent, main_provider, adapter = build_agent(request_gate=gate(provider))
    result = run(agent.run(question, context(), ("probe_service",)))
    assert result.model_rounds == result.tool_calls == result.usage.total_tokens == 0
    assert provider.requests == main_provider.requests == adapter.calls == []


@pytest.mark.parametrize("category", ["secret", "dangerous", "off_topic"])
def test_gate_refusal_keeps_usage_without_calling_main_model(category: str) -> None:
    provider = FakeProvider(ModelResponse(structured_output={"category": category}, usage=USAGE))
    agent, main_provider, adapter = build_agent(request_gate=gate(provider))
    result = run(agent.run("une demande", context(), ("probe_service",)))
    assert result.answer == REFUSALS[category][1]
    assert result.answer_checked
    assert result.evidence_answer.inferences == result.evidence_answer.confirmed_facts == ()
    assert result.model_rounds == result.tool_calls == 0
    assert result.usage.input_tokens == 11 and result.usage.output_tokens == 3
    assert result.usage.total_tokens == 14
    assert len(provider.requests) == 1
    assert main_provider.requests == adapter.calls == []


@pytest.mark.parametrize("category", ["allowed", "invalid"])
@pytest.mark.parametrize("total_known", [False, True])
def test_gate_allowance_and_failed_open_add_usage_and_record_span(
    category: str, total_known: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    exporter = InMemorySpanExporter()
    tracing = TracerProvider()
    tracing.add_span_processor(SimpleSpanProcessor(exporter))
    monkeypatch.setattr("tunnelminion.telemetry.trace.get_tracer", tracing.get_tracer)
    provider = FakeProvider(
        ModelResponse(
            structured_output={"category": category},
            usage=USAGE if total_known else ModelUsage(input_tokens=11, output_tokens=3),
        )
    )
    agent, main_provider, adapter = build_agent(request_gate=gate(provider))
    result = run(agent.run("帮我修好这个服务", context(), ("probe_service",)))
    assert len(provider.requests) == 1 and len(main_provider.requests) == result.model_rounds == 2
    assert result.tool_calls == len(adapter.calls) == 1
    assert result.usage.input_tokens == 41
    assert result.usage.output_tokens == 15
    assert result.usage.total_tokens == 56
    agent_span = next(item for item in exporter.get_finished_spans() if item.name == "agent.run")
    assert agent_span.attributes is not None
    assert agent_span.attributes["agent.request_gate"] == (
        "allowed" if category == "allowed" else "failed_open"
    )
    tracing.shutdown()


def test_no_gate_preserves_original_model_call_count() -> None:
    agent, provider, _ = build_agent()
    result = run(agent.run("检查服务", context(), ("probe_service",)))
    assert len(provider.requests) == result.model_rounds == 2
    assert result.usage.total_tokens == 42
