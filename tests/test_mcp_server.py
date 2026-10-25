"""MCP 会话、只读边界与命令行接线测试。"""

from __future__ import annotations

import asyncio
import json
import os
from contextlib import nullcontext
from dataclasses import dataclass
from importlib.metadata import version
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import anyio
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from mcp import ClientSession
from mcp.server.lowlevel import Server
from mcp.shared.memory import (
    create_client_server_memory_streams,
    create_connected_server_and_client_session,
)
from mcp.types import CallToolResult, TextContent
from pydantic import JsonValue
from tests.agent.test_service_observation import FakeAdapter, collection
from tests.tools.test_registry import definition
from tests.web.test_service_map import ApiClient

from tunnelminion import cli, macos_app, mcp_server
from tunnelminion.agent.service_marks import ServiceMark
from tunnelminion.agent.service_observation import (
    DeterministicServiceObserver,
    ServiceObservationSnapshot,
)
from tunnelminion.domain.errors import ErrorCode
from tunnelminion.domain.identifiers import NodeId
from tunnelminion.domain.tools import Platform, RiskLevel
from tunnelminion.memory.sqlite import SQLiteStores
from tunnelminion.platforms.process_origin import ProcessOrigin
from tunnelminion.platforms.windows.definitions import windows_tool_definitions
from tunnelminion.platforms.windows.models import NetworkListener
from tunnelminion.tools.audit import InMemoryAuditSink
from tunnelminion.tools.fakes import FakeToolAdapter, FakeToolBehavior
from tunnelminion.tools.registry import ToolRegistry
from tunnelminion.tools.runtime import ToolRuntime
from tunnelminion.web.service_map import create_service_map_router

EXPECTED_TOOLS = {
    "get_wireguard_status",
    "list_network_listeners",
    "get_process_summary",
    "list_docker_services",
    "probe_service_reachability",
    "get_node_summary",
    "list_local_services",
}
DENIED_TOOLS = {
    "delegate_to_node",
    "propose_repair",
    "repair_restart_containers",
    "repair_relaunch_python",
}
RISK_TOOLS = {
    "advice_tool": RiskLevel.ADVISORY,
    "approval_tool": RiskLevel.REQUIRES_APPROVAL,
    "sensitive_tool": RiskLevel.SENSITIVE,
    "forbidden_tool": RiskLevel.FORBIDDEN,
}


@dataclass
class Harness:
    server: Server
    node: SimpleNamespace
    registry: ToolRegistry
    audit: InMemoryAuditSink
    adapters: dict[str, FakeToolAdapter]
    listeners: FakeAdapter
    stores: SQLiteStores


def harness(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, platform: Platform = Platform.WINDOWS
) -> Harness:
    registry = ToolRegistry()
    adapters: dict[str, FakeToolAdapter] = {}
    for tool in windows_tool_definitions():
        adapters[tool.name] = FakeToolAdapter()
        registry.register(
            tool.model_copy(
                update={
                    "platforms": frozenset({platform}),
                    "timeout_seconds": 0.05,
                    "max_result_bytes": 1024,
                }
            ),
            adapters[tool.name],
        )
    for name, risk in {**dict.fromkeys(DENIED_TOOLS, RiskLevel.READ_ONLY), **RISK_TOOLS}.items():
        adapters[name] = FakeToolAdapter()
        registry.register(definition(name, risk, platforms=frozenset({platform})), adapters[name])
    registry.register(
        definition("other_platform", platforms=frozenset({Platform.LINUX})), FakeToolAdapter()
    )
    audit = InMemoryAuditSink()
    stores = SQLiteStores.open(tmp_path / "runtime.sqlite3")
    listeners = FakeAdapter(
        collection(
            NetworkListener(
                protocol="tcp",
                address="127.0.0.1",
                port=8080,
                pid=100,
                process_name="python",
                python_entrypoint="app.py",
                origin=ProcessOrigin.TERMINAL,
            ),
            NetworkListener(
                protocol="tcp",
                address="127.0.0.1",
                port=8765,
                pid=os.getpid(),
                process_name="python",
                origin=ProcessOrigin.TERMINAL,
            ),
        )
    )
    node = SimpleNamespace(
        root=tmp_path,
        node_id=NodeId.new(),
        tool_registry=registry,
        tool_runtime=ToolRuntime(registry, platform, audit),
        listeners=listeners,
        processes=FakeAdapter(collection()),
        docker=FakeAdapter(collection()),
        stores=stores,
    )

    def builder(data_dir: Path | None) -> SimpleNamespace:
        assert data_dir == tmp_path
        return node

    monkeypatch.setattr(mcp_server, "build_windows_node", builder)
    monkeypatch.setattr(macos_app, "_build_macos_node", builder)
    with monkeypatch.context() as patch:
        patch.setattr(
            mcp_server.sys, "platform", "darwin" if platform is Platform.MACOS else "win32"
        )
        server = mcp_server.build_mcp_server(tmp_path)
    return Harness(server, node, registry, audit, adapters, listeners, stores)


def payload(result: CallToolResult) -> JsonValue:
    assert len(result.content) == 1
    content = result.content[0]
    assert isinstance(content, TextContent)
    return cast(JsonValue, json.loads(content.text))


@pytest.mark.parametrize("platform", [Platform.WINDOWS, Platform.MACOS])
def test_initialize_list_and_call(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, platform: Platform
) -> None:
    h = harness(tmp_path, monkeypatch, platform)

    async def scenario() -> None:
        async with create_connected_server_and_client_session(h.server) as client:
            info = await client.initialize()
            assert info.serverInfo.name == "tunnelminion"
            assert info.serverInfo.version == version("tunnelminion")
            assert info.capabilities.tools is not None
            tools = (await client.list_tools()).tools
            assert {tool.name for tool in tools} == EXPECTED_TOOLS
            for tool in tools:
                entry = h.registry.lookup(tool.name)
                assert entry is not None
                assert tool.description == entry.definition.description
                assert tool.inputSchema == entry.definition.input_schema
            result = await client.call_tool("get_node_summary")
            assert not result.isError
            assert payload(result) == {"ok": True, "arguments": {}}
            assert len(h.audit.records) == 1
            record = h.audit.records[0]
            assert record.tool_name == "get_node_summary"
            assert record.caller_node_id == record.execution_node_id == h.node.node_id

    asyncio.run(scenario())


@pytest.mark.parametrize("leak_risks", [False, True])
def test_only_allowed_tools_are_listed_and_callable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, leak_risks: bool
) -> None:
    if leak_risks:
        monkeypatch.setattr(ToolRegistry, "model_tools", ToolRegistry.capabilities)
    h = harness(tmp_path, monkeypatch)

    async def scenario() -> None:
        async with create_connected_server_and_client_session(h.server) as client:
            for name in DENIED_TOOLS | RISK_TOOLS.keys() | {"other_platform", "unknown_tool"}:
                result = await client.call_tool(name, {})
                assert result.isError
                assert payload(result) == {"code": "tool_not_found", "message": "工具未开放"}
            assert {tool.name for tool in (await client.list_tools()).tools} == EXPECTED_TOOLS
        assert not h.audit.records
        assert all(not adapter.calls for adapter in h.adapters.values())

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "arguments",
    [{}, {"host": "127.0.0.1", "port": 0}, {"host": "127.0.0.1", "port": "8080"}],
)
def test_invalid_arguments_use_runtime_validation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, arguments: dict[str, JsonValue]
) -> None:
    h = harness(tmp_path, monkeypatch)

    async def scenario() -> None:
        async with create_connected_server_and_client_session(h.server) as client:
            result = await client.call_tool("probe_service_reachability", arguments)
            assert result.isError
            assert payload(result) == {
                "code": "invalid_argument",
                "message": "工具参数不符合 schema",
            }
        assert not h.adapters["probe_service_reachability"].calls
        assert h.audit.records[0].error_code is ErrorCode.INVALID_ARGUMENT

    asyncio.run(scenario())


@pytest.mark.parametrize(
    ("behavior", "code"),
    [
        (FakeToolBehavior.ADAPTER_ERROR, ErrorCode.INVALID_ARGUMENT),
        (FakeToolBehavior.PLATFORM_UNSUPPORTED, ErrorCode.OPERATION_NOT_SUPPORTED),
        (FakeToolBehavior.SLOW, ErrorCode.TIMEOUT),
        (FakeToolBehavior.LARGE_RESULT, ErrorCode.RESULT_TOO_LARGE),
    ],
)
def test_runtime_failures_and_budgets_become_tool_errors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    behavior: FakeToolBehavior,
    code: ErrorCode,
) -> None:
    h = harness(tmp_path, monkeypatch)
    h.adapters["get_node_summary"].behavior = behavior

    async def scenario() -> None:
        async with create_connected_server_and_client_session(h.server) as client:
            result = await client.call_tool("get_node_summary", {})
            assert result.isError
            error = payload(result)
            assert isinstance(error, dict)
            assert error["code"] == code.value
            assert set(error) == {"code", "message"}
        assert h.audit.records[0].error_code is code

    asyncio.run(scenario())


@pytest.mark.parametrize("failure_site", ["adapter", "audit"])
def test_unexpected_failure_never_exposes_exception_text(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure_site: str
) -> None:
    h = harness(tmp_path, monkeypatch)

    def fail(*_args: object) -> None:
        raise RuntimeError("private exception secret")

    async def fail_adapter(*_args: object) -> JsonValue:
        fail()

    if failure_site == "audit":
        monkeypatch.setattr(h.audit, "append", fail)
    else:
        monkeypatch.setattr(h.adapters["get_node_summary"], "execute", fail_adapter)

    async def scenario() -> None:
        async with create_connected_server_and_client_session(h.server) as client:
            result = await client.call_tool("get_node_summary", {})
            assert result.isError
            assert payload(result) == {"code": "internal", "message": "工具执行失败"}

    asyncio.run(scenario())


def test_local_services_matches_api_and_reuses_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    snapshots: list[ServiceObservationSnapshot] = []
    observe = DeterministicServiceObserver.observe

    async def record_snapshot(observer: DeterministicServiceObserver) -> ServiceObservationSnapshot:
        snapshot = await observe(observer)
        snapshots.append(snapshot)
        return snapshot

    monkeypatch.setattr(DeterministicServiceObserver, "observe", record_snapshot)
    h = harness(tmp_path, monkeypatch)

    async def scenario() -> None:
        async with create_connected_server_and_client_session(h.server) as client:
            invalid = await client.call_tool("list_local_services", {"extra": True})
            assert invalid.isError
            assert not snapshots
            first = await client.call_tool("list_local_services")
            assert not first.isError
            data = payload(first)
            assert isinstance(data, dict)
            services = data["services"]
            assert isinstance(services, list) and len(services) == 1
            service = services[0]
            assert isinstance(service, dict)
            key = service["key"]
            assert isinstance(key, str)
            h.stores.service_marks.set(key, ServiceMark.HIDDEN)
            second = await client.call_tool("list_local_services")
            assert not second.isError
            assert len(snapshots) == len(h.listeners.calls) == 1
            app = FastAPI()
            app.include_router(
                create_service_map_router(
                    h.node.node_id, h.stores.service_marks, lambda: snapshots[0], lambda _: None
                )
            )
            with TestClient(app) as api:
                response = cast(ApiClient, api).get("/api/services/local")
            assert response.status_code == 200
            assert payload(second) == response.json()
            assert response.json()["services"][0]["mark"] == "hidden"
            assert [record.tool_name for record in h.audit.records] == ["list_local_services"] * 3

    asyncio.run(scenario())


def test_stdio_runner_uses_sdk_transport(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    h = harness(tmp_path, monkeypatch)

    def build(data_dir: Path | None) -> Server:
        assert data_dir == tmp_path
        return h.server

    monkeypatch.setattr(mcp_server, "build_mcp_server", build)

    async def scenario() -> None:
        async with create_client_server_memory_streams() as (client_streams, server_streams):
            monkeypatch.setattr(mcp_server, "stdio_server", lambda: nullcontext(server_streams))
            async with anyio.create_task_group() as tasks:
                tasks.start_soon(mcp_server.run_mcp_server, tmp_path)
                async with ClientSession(*client_streams) as client:
                    await client.initialize()
                    result = await client.call_tool("get_node_summary")
                    assert not result.isError
                tasks.cancel_scope.cancel()

    asyncio.run(scenario())


@pytest.mark.parametrize("explicit_path", [False, True])
def test_cli_wiring(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    explicit_path: bool,
) -> None:
    paths: list[Path | None] = []

    async def run(data_dir: Path | None = None) -> None:
        paths.append(data_dir)

    monkeypatch.setattr(mcp_server, "run_mcp_server", run)
    args = ["mcp", "--data-dir", str(tmp_path)] if explicit_path else ["mcp"]
    assert cli.main(args) == 0
    assert paths == [tmp_path if explicit_path else None]
    assert capsys.readouterr().out == ""


def test_cli_help_is_chinese(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        cli.main(["mcp", "--help"])
    assert exc.value.code == 0
    assert "以 MCP（stdio）方式开放本机只读诊断工具" in capsys.readouterr().out
