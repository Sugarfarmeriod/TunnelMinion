"""委派在两个应用里的接入：Windows 网关、后台启动入口、Agent 自动提供委派工具。"""

from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from tests.agent.test_langchain_agent import ScriptedProvider, context, definition

from tunnelminion import cli
from tunnelminion.agent.langchain_model import TunnelMinionChatModel
from tunnelminion.agent.runtime import LangChainReadOnlyAgent
from tunnelminion.app import build_windows_gateway_application, build_windows_node
from tunnelminion.domain.delegation import DELEGATE_TOOL_NAME
from tunnelminion.domain.identifiers import NodeId
from tunnelminion.domain.tools import Platform
from tunnelminion.gateway.configuration import (
    FileGatewayConfigurationRepository,
    GatewayConfigurationService,
    GatewayPeerConfig,
    GatewayPeerInput,
    GatewaySecretStoreKind,
    configure_gateway_secret_store,
)
from tunnelminion.gateway.security import GatewayBindConfig
from tunnelminion.model.contracts import ProviderError
from tunnelminion.tools.audit import InMemoryAuditSink
from tunnelminion.tools.fakes import FakeToolAdapter
from tunnelminion.tools.registry import ToolRegistry
from tunnelminion.tools.runtime import ToolRuntime

PEER = NodeId("node_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
TOKEN = "tmn_" + "e" * 40


def configure(root: Path, *, allow_delegation: bool) -> None:
    service = GatewayConfigurationService(
        FileGatewayConfigurationRepository(root / "gateway.json"),
        configure_gateway_secret_store(root, GatewaySecretStoreKind.RESTRICTED_FILE),
    )
    service.configure_local(GatewayBindConfig(host="10.77.0.5"))
    service.provision_peer(
        GatewayPeerInput(
            peer=GatewayPeerConfig(
                node_id=PEER,
                platform=Platform.MACOS,
                host="10.77.0.1",
                allowed_tools=frozenset({"list_network_listeners"}),
                allow_delegation=allow_delegation,
            ),
            token=TOKEN,
        )
    )


def test_windows_gateway_handles_delegation_only_when_a_peer_is_allowed(tmp_path: Path) -> None:
    with pytest.raises(RuntimeError):
        build_windows_gateway_application(tmp_path / "unconfigured")
    configure(tmp_path / "closed", allow_delegation=False)
    closed = build_windows_gateway_application(tmp_path / "closed")
    assert closed.delegation_service is None
    assert closed.bind == GatewayBindConfig(host="10.77.0.5")
    configure(tmp_path / "open", allow_delegation=True)
    opened = build_windows_gateway_application(tmp_path / "open")
    assert opened.delegation_service is not None
    assert opened.gateway_service.view().peers[0].allow_delegation


def test_windows_node_agent_needs_a_configured_model(tmp_path: Path) -> None:
    node = build_windows_node(tmp_path)
    assert DELEGATE_TOOL_NAME not in {
        item.name for item in node.tool_registry.model_tools(Platform.WINDOWS)
    }
    with pytest.raises(ProviderError):
        node.create_read_only_agent()


def test_windows_node_agent_uses_only_local_tools(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    node = build_windows_node(tmp_path)

    def provider(_self: object) -> ScriptedProvider:
        return ScriptedProvider()

    monkeypatch.setattr(type(node.model_service), "create_provider", provider)
    agent = node.create_read_only_agent()
    assert isinstance(agent, LangChainReadOnlyAgent) and not agent.supports_remote


def test_background_gateway_component_starts_the_windows_gateway(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[dict[str, object]] = []
    gateway_app = FastAPI()

    def run(application: FastAPI, **kwargs: object) -> None:
        calls.append({"application": application, **kwargs})

    def build(data_dir: Path) -> SimpleNamespace:
        assert data_dir == tmp_path
        return SimpleNamespace(app=gateway_app, bind=SimpleNamespace(host="10.77.0.5", port=8787))

    monkeypatch.setattr("uvicorn.run", run)
    monkeypatch.setattr("tunnelminion.app.build_windows_gateway_application", build)
    monkeypatch.setattr(cli.sys, "platform", "win32")
    assert (
        cli.main(
            [
                "runtime-child",
                "--runtime-component=gateway",
                "--runtime-instance-id=00000000-0000-0000-0000-000000000001",
                "--data-dir",
                str(tmp_path),
                "--local-port",
                "8125",
                "--runtime-log-file",
                str(tmp_path / "gateway.log"),
            ]
        )
        == 0
    )
    assert calls[-1]["application"] is gateway_app
    assert (calls[-1]["host"], calls[-1]["port"]) == ("10.77.0.5", 8787)


def agent_with_delegate_tool() -> tuple[LangChainReadOnlyAgent, ScriptedProvider]:
    provider = ScriptedProvider()
    registry = ToolRegistry()
    registry.register(definition(), FakeToolAdapter())
    registry.register(definition(DELEGATE_TOOL_NAME), FakeToolAdapter())
    runtime = ToolRuntime(registry, Platform.WINDOWS, InMemoryAuditSink())
    agent = LangChainReadOnlyAgent(
        TunnelMinionChatModel(provider=provider), registry, runtime, Platform.WINDOWS
    )
    return agent, provider


def test_local_runs_always_offer_the_delegate_tool_once() -> None:
    agent, provider = agent_with_delegate_tool()
    asyncio.run(agent.run("Mac 上的相册怎么了？", context(), ("probe_service",)))
    assert [tool.name for tool in provider.requests[0].tools] == [
        "probe_service",
        DELEGATE_TOOL_NAME,
    ]

    agent, provider = agent_with_delegate_tool()
    asyncio.run(agent.run("Mac 上的相册怎么了？", context(), ("probe_service", DELEGATE_TOOL_NAME)))
    assert [tool.name for tool in provider.requests[0].tools] == [
        "probe_service",
        DELEGATE_TOOL_NAME,
    ]
