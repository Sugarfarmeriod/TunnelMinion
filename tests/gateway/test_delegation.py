"""委派：B 端有边界的本机调查、记录、网关接口、客户端和 A 端委派工具。"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable, Coroutine
from pathlib import Path
from typing import Any, Protocol, TypeVar, cast

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from tests.agent.test_langchain_agent import ScriptedProvider, build_agent

from tunnelminion.agent.context_contracts import HistoryContext
from tunnelminion.agent.delegation import DelegationService, summarize
from tunnelminion.agent.delegation_tool import (
    DelegateToNodeAdapter,
    delegate_tool_definition,
    register_delegate_tool,
)
from tunnelminion.agent.runtime import (
    AgentCancellationToken,
    AgentRunLimits,
    AgentToolEvent,
    CheckedAgentTurnResult,
    ServiceCheckTarget,
    TaskAgent,
)
from tunnelminion.agent.task_progress import TaskProgress
from tunnelminion.domain.delegation import (
    DELEGATE_TOOL_NAME,
    MAX_MODEL_ROUNDS,
    MAX_SECONDS,
    MAX_TOOL_CALLS,
    DelegationBusyError,
    DelegationErrorCode,
    DelegationRecord,
    DelegationRequest,
    DelegationStatus,
)
from tunnelminion.domain.errors import ErrorCode
from tunnelminion.domain.identifiers import DelegationId, NodeId
from tunnelminion.domain.tools import Platform
from tunnelminion.gateway import create_gateway_router
from tunnelminion.gateway.audit import InMemoryGatewaySecurityAuditSink
from tunnelminion.gateway.client import FixedGatewayClient, RemoteGatewayError
from tunnelminion.gateway.configuration import (
    FileGatewayConfigurationRepository,
    GatewayConfigurationService,
    GatewayPeerConfig,
    GatewayPeerInput,
)
from tunnelminion.gateway.security import (
    GatewayBindConfig,
    GatewayPeerPolicy,
    GatewaySecurityPolicy,
)
from tunnelminion.memory.contracts import LongTermMemory
from tunnelminion.memory.sqlite import SQLiteStores
from tunnelminion.model.contracts import ProviderError, ProviderErrorCode
from tunnelminion.tools.audit import InMemoryAuditSink
from tunnelminion.tools.contracts import ToolAdapterError, ToolCallContext, ToolCancellationToken
from tunnelminion.tools.registry import ToolRegistry
from tunnelminion.tools.runtime import ToolRuntime

T = TypeVar("T")
TOKEN = "delegation-test-token-that-is-at-least-32-characters"
B = NodeId("node_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
A = NodeId("node_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
OTHER = NodeId("node_cccccccccccccccccccccccccccccccc")


def run(coroutine: Coroutine[Any, Any, T]) -> T:
    return asyncio.run(coroutine)


def stores(tmp_path: Path) -> SQLiteStores:
    return SQLiteStores.open(tmp_path / "runtime.sqlite3")


def real_agent() -> TaskAgent:
    """真实 Agent 循环 + 脚本模型：先调一次本机工具，再给出结论。"""
    return build_agent(ScriptedProvider())[0]


class FailingAgent:
    """按配置抛出异常的 Agent。"""

    def __init__(self, error: BaseException) -> None:
        self.error = error

    @property
    def supports_remote(self) -> bool:
        return False

    async def run(self, *args: object, **kwargs: object) -> CheckedAgentTurnResult:
        raise self.error


class WaitingAgent:
    """一直等到被取消，然后用真实 Agent 的结果格式返回。"""

    def __init__(self) -> None:
        self.started = asyncio.Event()
        self.question = ""
        self.tool_names: tuple[str, ...] = ()
        self.limits: AgentRunLimits | None = None
        self.context: ToolCallContext | None = None

    @property
    def supports_remote(self) -> bool:
        return False

    async def run(
        self,
        question: str,
        context: ToolCallContext,
        tool_names: tuple[str, ...],
        limits: AgentRunLimits | None = None,
        cancellation: AgentCancellationToken | None = None,
        tool_event_sink: Callable[[AgentToolEvent], None] | None = None,
        history_context: HistoryContext | None = None,
        memories: tuple[LongTermMemory, ...] = (),
        target: ServiceCheckTarget | None = None,
        progress: TaskProgress | None = None,
        progress_sink: Callable[[TaskProgress], None] | None = None,
    ) -> CheckedAgentTurnResult:
        self.question, self.tool_names, self.limits, self.context = (
            question,
            tool_names,
            limits,
            context,
        )
        self.started.set()
        assert cancellation is not None
        await cancellation.wait()
        return await real_agent().run("8082 服务是否存在？", context, ("probe_service",))


def service(
    tmp_path: Path, factory: Callable[[], TaskAgent] = real_agent
) -> tuple[DelegationService, SQLiteStores]:
    store = stores(tmp_path)
    return (
        DelegationService(
            B, store.delegations, factory, lambda: ("probe_service", DELEGATE_TOOL_NAME)
        ),
        store,
    )


# ---------- B 端服务 ----------


def test_delegation_runs_a_bounded_local_investigation_and_keeps_only_a_summary(
    tmp_path: Path,
) -> None:
    async def scenario() -> DelegationRecord:
        value, _ = service(tmp_path)
        record = value.submit(DelegationRequest(caller_node_id=A, question="8082 服务是否存在？"))
        assert record.status is DelegationStatus.RUNNING and record.executing_node_id == B
        await value.wait(record.delegation_id)
        finished = value.get(record.delegation_id, A)
        assert finished is not None
        return finished

    finished = run(scenario())
    assert finished.status is DelegationStatus.COMPLETED and finished.finished_at is not None
    assert finished.result is not None
    assert finished.result.summary.startswith("已确认服务状态")
    assert finished.result.evidence[0].tool_name == "probe_service"
    assert finished.result.tool_calls == 1 and finished.result.stop_reason == "completed"
    assert len(finished.result.confirmed_facts) == 1
    # 只回传摘要，不带工具原始输出。
    assert "port" not in finished.result.model_dump_json()


def test_delegated_run_uses_only_local_tools_and_fixed_limits(tmp_path: Path) -> None:
    agent = WaitingAgent()

    async def scenario() -> DelegationRecord | None:
        value, _ = service(tmp_path, lambda: agent)
        record = value.submit(
            DelegationRequest(
                caller_node_id=A, question="相册为什么打不开？", service_key="docker:gimp"
            )
        )
        await agent.started.wait()
        # 同一台电脑同时只能有一个委派在跑。
        with pytest.raises(DelegationBusyError):
            value.submit(DelegationRequest(caller_node_id=A, question="再问一个"))
        cancelled = await value.cancel(record.delegation_id, A)
        assert cancelled is not None and cancelled.status is DelegationStatus.CANCELLED
        return value.get(record.delegation_id, A)

    final = run(scenario())
    assert final is not None and final.status is DelegationStatus.CANCELLED
    assert agent.tool_names == ("probe_service",)
    assert agent.limits == AgentRunLimits(
        max_model_rounds=MAX_MODEL_ROUNDS,
        max_tool_calls=MAX_TOOL_CALLS,
        timeout_seconds=MAX_SECONDS,
    )
    assert "docker:gimp" in agent.question
    assert agent.context is not None
    assert agent.context.caller_node_id == agent.context.execution_node_id == B


@pytest.mark.parametrize(
    ("error", "code"),
    [
        (
            ProviderError(ProviderErrorCode.MODEL_NOT_FOUND, "未配置"),
            DelegationErrorCode.MODEL_UNAVAILABLE,
        ),
        (TimeoutError(), DelegationErrorCode.TIMEOUT),
        (RuntimeError("坏了"), DelegationErrorCode.FAILED),
    ],
)
def test_failures_are_recorded_with_a_reason(
    tmp_path: Path, error: BaseException, code: DelegationErrorCode
) -> None:
    async def scenario() -> DelegationRecord | None:
        value, _ = service(tmp_path, lambda: FailingAgent(error))
        record = value.submit(DelegationRequest(caller_node_id=A, question="查一下"))
        await value.wait(record.delegation_id)
        return value.get(record.delegation_id, A)

    record = run(scenario())
    assert record is not None and record.status is DelegationStatus.FAILED
    assert record.error_code is code and record.result is None


def test_model_missing_at_agent_creation_counts_as_model_unavailable(tmp_path: Path) -> None:
    def no_model() -> TaskAgent:
        raise ProviderError(ProviderErrorCode.MODEL_NOT_FOUND, "未配置")

    async def scenario() -> DelegationRecord | None:
        value, _ = service(tmp_path, no_model)
        record = value.submit(DelegationRequest(caller_node_id=A, question="查一下"))
        await value.wait(record.delegation_id)
        return value.get(record.delegation_id, A)

    record = run(scenario())
    assert record is not None and record.error_code is DelegationErrorCode.MODEL_UNAVAILABLE


def test_records_are_private_to_their_caller_and_survive_restart(tmp_path: Path) -> None:
    async def scenario() -> DelegationId:
        value, _ = service(tmp_path)
        record = value.submit(DelegationRequest(caller_node_id=A, question="8082 服务是否存在？"))
        await value.wait(record.delegation_id)
        assert value.get(record.delegation_id, OTHER) is None
        assert await value.cancel(record.delegation_id, OTHER) is None
        # 已结束的委派取消时原样返回。
        done = await value.cancel(record.delegation_id, A)
        assert done is not None and done.status is DelegationStatus.COMPLETED
        await value.wait(DelegationId.new())
        return record.delegation_id

    identifier = run(scenario())
    reopened, store = service(tmp_path)
    assert reopened.get(identifier, A) is not None
    assert [item.delegation_id for item in store.delegations.recent()] == [identifier]


def test_running_records_left_by_a_crash_are_marked_failed(tmp_path: Path) -> None:
    store = stores(tmp_path)

    async def scenario() -> tuple[DelegationRecord | None, DelegationRecord | None]:
        first = DelegationService(B, store.delegations, real_agent, lambda: ("probe_service",))
        orphan = first.submit(DelegationRequest(caller_node_id=A, question="8082 服务是否存在？"))
        first_task = asyncio.all_tasks() - {asyncio.current_task()}
        for task in first_task:
            task.cancel()
        await asyncio.gather(*first_task, return_exceptions=True)
        # 新进程启动时，上次没跑完的委派已经没有执行者了。
        store.delegations.put(orphan)
        second = DelegationService(B, store.delegations, real_agent, lambda: ("probe_service",))
        recovered = second.get(orphan.delegation_id, A)
        # 记录还在 RUNNING 但没有执行任务时，取消直接把它标为已取消。
        stuck = orphan.model_copy(update={"delegation_id": DelegationId.new()})
        store.delegations.put(stuck)
        return recovered, await second.cancel(stuck.delegation_id, A)

    recovered, stuck = run(scenario())
    assert recovered is not None and recovered.status is DelegationStatus.FAILED
    assert recovered.error_code is DelegationErrorCode.FAILED
    assert stuck is not None and stuck.status is DelegationStatus.CANCELLED


def test_summary_is_bounded() -> None:
    async def scenario() -> CheckedAgentTurnResult:
        node = NodeId.new()
        context = ToolCallContext.model_validate(
            {
                "thread_id": "thread_" + "1" * 32,
                "run_id": "run_" + "2" * 32,
                "caller_node_id": str(node),
                "execution_node_id": str(node),
            }
        )
        return await real_agent().run("8082 服务是否存在？", context, ("probe_service",))

    result = run(scenario())
    long = result.model_copy(
        update={
            "evidence_answer": result.evidence_answer.model_copy(
                update={"summary": "长" * 5000, "unknowns": tuple(str(i) for i in range(30))}
            )
        }
    )
    summary = summarize(long)
    assert len(summary.summary) == 4000 and len(summary.unknowns) == 20


# ---------- 网关接口与客户端 ----------


class Api(Protocol):
    def get(self, url: str, *, headers: dict[str, str] | None = None) -> httpx.Response: ...

    def post(
        self, url: str, *, json: object, headers: dict[str, str] | None = None
    ) -> httpx.Response: ...

    def delete(self, url: str, *, headers: dict[str, str] | None = None) -> httpx.Response: ...


AUTH = {"Authorization": f"Bearer {TOKEN}"}


def gateway_app(
    tmp_path: Path,
    *,
    allow: bool = True,
    with_service: bool = True,
    factory: Callable[[], TaskAgent] = real_agent,
) -> FastAPI:
    registry = ToolRegistry()
    runtime = ToolRuntime(registry, Platform.MACOS, InMemoryAuditSink())
    policy = GatewaySecurityPolicy(
        [GatewayPeerPolicy.from_token(A, TOKEN, ["probe_service"], allow_delegation=allow)]
    )
    delegation = (
        DelegationService(B, stores(tmp_path).delegations, factory, lambda: ("probe_service",))
        if with_service
        else None
    )
    app = FastAPI()
    app.include_router(
        create_gateway_router(
            B,
            Platform.MACOS,
            registry,
            runtime,
            policy,
            InMemoryGatewaySecurityAuditSink(),
            delegation_service=delegation,
        )
    )
    return app


def code(response: httpx.Response) -> object:
    return cast(dict[str, dict[str, object]], response.json())["error"]["code"]


def wait_until_done(api: Api, identifier: str) -> dict[str, object]:
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        body = cast(
            dict[str, object], api.get(f"/v1/delegations/{identifier}", headers=AUTH).json()
        )
        if body["status"] != "running":
            return body
        time.sleep(0.02)
    raise AssertionError("委派没有结束")


def test_gateway_accepts_reports_and_cancels_delegations(tmp_path: Path) -> None:
    payload = {"caller_node_id": str(A), "question": "8082 服务是否存在？"}
    with TestClient(gateway_app(tmp_path)) as raw:
        api = cast(Api, raw)
        accepted = api.post("/v1/delegations", json=payload, headers=AUTH)
        assert accepted.status_code == 202
        identifier = accepted.json()["delegation_id"]
        done = wait_until_done(api, identifier)
        assert done["status"] == "completed" and done["executing_node_id"] == str(B)
        assert api.delete(f"/v1/delegations/{identifier}", headers=AUTH).json()["status"] == (
            "completed"
        )
        assert code(api.get("/v1/delegations/not-an-id", headers=AUTH)) == "delegation_not_found"
        missing = f"/v1/delegations/{DelegationId.new()}"
        assert api.get(missing, headers=AUTH).status_code == 404
        assert api.delete(missing, headers=AUTH).status_code == 404
        assert code(api.delete("/v1/delegations/bad", headers=AUTH)) == "delegation_not_found"
        forged = {"caller_node_id": str(OTHER), "question": "冒充别人"}
        assert code(api.post("/v1/delegations", json=forged, headers=AUTH)) == "forbidden"
        assert api.post("/v1/delegations", json=payload).status_code == 401
        assert api.delete(f"/v1/delegations/{identifier}").status_code == 401


def test_gateway_reports_busy_disabled_and_unavailable(tmp_path: Path) -> None:
    agent = WaitingAgent()
    payload = {"caller_node_id": str(A), "question": "查一下"}
    with TestClient(gateway_app(tmp_path, factory=lambda: agent)) as raw:
        api = cast(Api, raw)
        first = api.post("/v1/delegations", json=payload, headers=AUTH).json()["delegation_id"]
        busy = api.post("/v1/delegations", json=payload, headers=AUTH)
        assert busy.status_code == 409 and code(busy) == "delegation_busy"
        assert api.delete(f"/v1/delegations/{first}", headers=AUTH).json()["status"] == "cancelled"
    with TestClient(gateway_app(tmp_path / "off", allow=False)) as raw:
        denied = cast(Api, raw).post("/v1/delegations", json=payload, headers=AUTH)
        assert denied.status_code == 403 and code(denied) == "delegation_not_allowed"
    with TestClient(gateway_app(tmp_path / "none", with_service=False)) as raw:
        off = cast(Api, raw).get(f"/v1/delegations/{DelegationId.new()}", headers=AUTH)
        assert off.status_code == 503 and code(off) == "delegation_unavailable"


def client_for(app: FastAPI, *, local: NodeId = A, remote: NodeId = B) -> FixedGatewayClient:
    return FixedGatewayClient(
        "http://10.77.0.1:8787",
        TOKEN,
        local,
        remote,
        InMemoryAuditSink(),
        transport=httpx.ASGITransport(app=app),
    )


def test_client_submits_reads_and_cancels(tmp_path: Path) -> None:
    agent = WaitingAgent()
    app = gateway_app(tmp_path, factory=lambda: agent)

    async def scenario() -> tuple[DelegationRecord, DelegationRecord, DelegationRecord]:
        client = client_for(app)
        submitted = await client.submit_delegation("查一下", "program:gost@805")
        await agent.started.wait()
        current = await client.get_delegation(submitted.delegation_id)
        cancelled = await client.cancel_delegation(submitted.delegation_id)
        return submitted, current, cancelled

    submitted, current, cancelled = run(scenario())
    assert submitted.service_key == "program:gost@805"
    assert current.status is DelegationStatus.RUNNING
    assert cancelled.status is DelegationStatus.CANCELLED


def test_client_rejects_wrong_identity_errors_and_bad_responses(tmp_path: Path) -> None:
    app = gateway_app(tmp_path, allow=False)

    async def denied() -> None:
        await client_for(app).submit_delegation("查一下")

    with pytest.raises(RemoteGatewayError) as forbidden:
        run(denied())
    assert forbidden.value.code is ErrorCode.FORBIDDEN

    record = DelegationRecord(
        delegation_id=DelegationId.new(),
        caller_node_id=A,
        executing_node_id=OTHER,
        question="q",
        status=DelegationStatus.RUNNING,
        created_at="2026-10-23T00:00:00Z",  # type: ignore[arg-type]
    )

    def respond(body: bytes, status: int = 200) -> Callable[[httpx.Request], httpx.Response]:
        return lambda request: httpx.Response(status, content=body)

    cases: list[tuple[Callable[[httpx.Request], httpx.Response], ErrorCode]] = [
        (respond(record.model_dump_json().encode()), ErrorCode.FORBIDDEN),
        (respond(b"not json"), ErrorCode.INTERNAL),
    ]

    def timeout(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("slow", request=request)

    def offline(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("down", request=request)

    cases += [(timeout, ErrorCode.REMOTE_TIMEOUT), (offline, ErrorCode.NODE_UNREACHABLE)]
    for handler, expected in cases:
        client = FixedGatewayClient(
            "http://10.77.0.1:8787",
            TOKEN,
            A,
            B,
            InMemoryAuditSink(),
            transport=httpx.MockTransport(handler),
        )
        with pytest.raises(RemoteGatewayError) as raised:
            run(client.get_delegation(record.delegation_id))
        assert raised.value.code is expected


# ---------- A 端委派工具 ----------


class FakeClient:
    """按脚本返回状态的对端。"""

    def __init__(
        self, statuses: list[DelegationStatus], *, error: RemoteGatewayError | None = None
    ) -> None:
        self.statuses = statuses
        self.error = error
        self.calls: list[str] = []
        self.base = DelegationRecord(
            delegation_id=DelegationId.new(),
            caller_node_id=A,
            executing_node_id=B,
            question="q",
            status=DelegationStatus.RUNNING,
            created_at="2026-10-23T00:00:00Z",  # type: ignore[arg-type]
        )

    def _next(self, name: str) -> DelegationRecord:
        self.calls.append(name)
        if self.error is not None:
            raise self.error
        status = self.statuses.pop(0) if self.statuses else DelegationStatus.RUNNING
        return self.base.model_copy(update={"status": status})

    async def submit_delegation(
        self, question: str, service_key: str | None = None
    ) -> DelegationRecord:
        self.calls.append(f"submit:{question}:{service_key}")
        return self._next("first")

    async def get_delegation(self, delegation_id: DelegationId) -> DelegationRecord:
        return self._next("get")

    async def cancel_delegation(self, delegation_id: DelegationId) -> DelegationRecord:
        self.calls.append("cancel")
        return self.base.model_copy(update={"status": DelegationStatus.CANCELLED})


def adapter(
    client: FakeClient, *, clock: Callable[[], float] | None = None
) -> DelegateToNodeAdapter:
    async def no_sleep(_: float) -> None:
        return None

    def lookup(node_id: NodeId) -> FakeClient:
        if node_id != B:
            raise KeyError("unknown")
        return client

    return DelegateToNodeAdapter(lookup, sleep=no_sleep, clock=clock or (lambda: 0.0))


def test_tool_waits_for_the_answer(tmp_path: Path) -> None:
    client = FakeClient(
        [DelegationStatus.RUNNING, DelegationStatus.RUNNING, DelegationStatus.COMPLETED]
    )
    output = run(
        adapter(client).execute(
            {"node_id": str(B), "question": "相册打不开", "service_key": "docker:gimp"},
            ToolCancellationToken(),
        )
    )
    assert cast(dict[str, object], output)["status"] == "completed"
    assert cast(dict[str, object], output)["answered_by"] == str(B)
    assert client.calls[0] == "submit:相册打不开:docker:gimp"
    assert client.calls.count("get") == 2


def test_tool_cancels_on_local_cancellation_and_on_deadline() -> None:
    cancelled = ToolCancellationToken()
    cancelled.cancel()
    client = FakeClient([DelegationStatus.RUNNING])
    output = run(adapter(client).execute({"node_id": str(B), "question": "q"}, cancelled))
    assert cast(dict[str, object], output)["status"] == "cancelled" and "cancel" in client.calls

    ticks = iter([0.0, 1000.0])
    late = FakeClient([DelegationStatus.RUNNING])
    with pytest.raises(ToolAdapterError) as timed_out:
        run(
            adapter(late, clock=lambda: next(ticks)).execute(
                {"node_id": str(B), "question": "q"}, ToolCancellationToken()
            )
        )
    assert timed_out.value.error.code is ErrorCode.REMOTE_TIMEOUT and "cancel" in late.calls


@pytest.mark.parametrize("node", ["not-a-node", str(OTHER)])
def test_tool_rejects_unknown_computers(node: str) -> None:
    with pytest.raises(ToolAdapterError) as raised:
        run(
            adapter(FakeClient([])).execute(
                {"node_id": node, "question": "q"}, ToolCancellationToken()
            )
        )
    assert raised.value.error.code is ErrorCode.INVALID_ARGUMENT


def test_tool_passes_through_remote_errors() -> None:
    client = FakeClient([], error=RemoteGatewayError(ErrorCode.FORBIDDEN, "不允许"))
    with pytest.raises(ToolAdapterError) as raised:
        run(adapter(client).execute({"node_id": str(B), "question": "q"}, ToolCancellationToken()))
    assert raised.value.error.code is ErrorCode.FORBIDDEN


def test_tool_definition_lists_the_computers_it_can_ask() -> None:
    peer = GatewayPeerConfig(
        node_id=B, platform=Platform.MACOS, host="10.77.0.1", allowed_tools=frozenset({"x"})
    )
    unknown = peer.model_copy(update={"node_id": OTHER, "platform": None})
    definition = delegate_tool_definition([peer, unknown], Platform.WINDOWS)
    assert definition.name == DELEGATE_TOOL_NAME
    assert str(B) in definition.description and "macOS 电脑（Mac）" in definition.description
    assert "Windows 电脑" in definition.description
    assert "未知平台的电脑" in definition.description
    assert definition.platforms == frozenset({Platform.WINDOWS})


class MemorySecrets:
    def __init__(self) -> None:
        self.values: dict[str, str] = {}

    def get(self, name: str) -> str | None:
        return self.values.get(name)

    def set(self, name: str, value: str) -> None:
        self.values[name] = value

    def delete(self, name: str) -> None:
        self.values.pop(name, None)


STORED_TOKEN = "tmn_" + "d" * 40


def configuration(
    tmp_path: Path, secrets: MemorySecrets | None = None
) -> GatewayConfigurationService:
    return GatewayConfigurationService(
        FileGatewayConfigurationRepository(tmp_path / "gateway.json"), secrets or MemorySecrets()
    )


def with_peer(service: GatewayConfigurationService) -> GatewayConfigurationService:
    service.configure_local(GatewayBindConfig(host="10.77.0.5"))
    service.provision_peer(
        GatewayPeerInput(
            peer=GatewayPeerConfig(
                node_id=B, platform=Platform.MACOS, host="10.77.0.1", allowed_tools=frozenset({"x"})
            ),
            token=STORED_TOKEN,
        )
    )
    return service


def test_tool_is_registered_only_when_peers_are_configured(tmp_path: Path) -> None:
    registry = ToolRegistry()
    empty = configuration(tmp_path / "empty")
    assert not register_delegate_tool(registry, Platform.WINDOWS, empty, A, InMemoryAuditSink())
    bound_only = configuration(tmp_path / "bound")
    bound_only.configure_local(GatewayBindConfig(host="10.77.0.5"))
    assert not register_delegate_tool(
        registry, Platform.WINDOWS, bound_only, A, InMemoryAuditSink()
    )
    configured = with_peer(configuration(tmp_path / "peers"))
    assert register_delegate_tool(registry, Platform.WINDOWS, configured, A, InMemoryAuditSink())
    assert registry.lookup(DELEGATE_TOOL_NAME) is not None
    peer = configured.resolve_delegation_peer(B)
    assert peer.endpoint == "http://10.77.0.1:8787" and peer.allowed_tools == ()
    assert peer.token == STORED_TOKEN
    with pytest.raises(KeyError):
        configured.resolve_delegation_peer(OTHER)


def test_registered_tool_reaches_the_peer_through_the_gateway_client(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[tuple[str, str]] = []

    class Recording:
        def __init__(self, endpoint: str, token: str, *args: object) -> None:
            seen.append((endpoint, token))

        async def submit_delegation(
            self, question: str, service_key: str | None = None
        ) -> DelegationRecord:
            raise RemoteGatewayError(ErrorCode.NODE_UNREACHABLE, "离线")

    monkeypatch.setattr("tunnelminion.agent.delegation_tool.FixedGatewayClient", Recording)
    registry = ToolRegistry()
    register_delegate_tool(
        registry, Platform.WINDOWS, with_peer(configuration(tmp_path)), A, InMemoryAuditSink()
    )
    entry = registry.lookup(DELEGATE_TOOL_NAME)
    assert entry is not None
    with pytest.raises(ToolAdapterError) as raised:
        run(entry.adapter.execute({"node_id": str(B), "question": "q"}, ToolCancellationToken()))
    assert raised.value.error.code is ErrorCode.NODE_UNREACHABLE
    assert seen == [("http://10.77.0.1:8787", STORED_TOKEN)]


def test_delegation_peer_without_stored_token_is_reported(tmp_path: Path) -> None:
    secrets = MemorySecrets()
    configured = with_peer(configuration(tmp_path, secrets))
    secrets.values.clear()
    with pytest.raises(RuntimeError):
        configured.resolve_delegation_peer(B)
