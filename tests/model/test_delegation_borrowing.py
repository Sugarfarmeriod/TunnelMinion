"""处理委派时借委派方的模型：只借同一机主的电脑，借不到时不给提供方。"""

from __future__ import annotations

import asyncio
from dataclasses import replace
from pathlib import Path

import httpx
import pytest

from tunnelminion.domain.identifiers import NodeId
from tunnelminion.domain.model_borrowing import BorrowedModelResult
from tunnelminion.domain.tools import Platform
from tunnelminion.gateway.configuration import GatewayToolPeer
from tunnelminion.gateway.contracts import DELEGATION_MODEL_PURPOSE, MODEL_PURPOSE_HEADER
from tunnelminion.model.contracts import ModelMessage, ModelProvider, ModelRequest
from tunnelminion.model.delegation_borrowing import caller_model_provider_factory
from tunnelminion.model.remote import RemoteModelProvider
from tunnelminion.tools.audit import InMemoryAuditSink

LOCAL = NodeId("node_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
CALLER = NodeId("node_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
TOKEN = "tmn_" + "d" * 40


class FakeGateway:
    def __init__(self, relationship: str, error: Exception | None = None) -> None:
        self.kind = relationship
        self.error = error
        self.resolved: list[NodeId] = []

    def relationship(self, node_id: NodeId) -> str:
        return self.kind

    def resolve_model_peer(self, node_id: NodeId) -> GatewayToolPeer:
        self.resolved.append(node_id)
        if self.error is not None:
            raise self.error
        return GatewayToolPeer(
            node_id=node_id,
            platform=Platform.WINDOWS,
            endpoint="http://10.77.0.3:8787",
            allowed_tools=(),
            token=TOKEN,
        )


@pytest.mark.parametrize("relationship", ["friend", "legacy"])
def test_only_the_owners_own_computers_are_borrowed_from(relationship: str) -> None:
    gateway = FakeGateway(relationship)
    factory = caller_model_provider_factory(gateway, LOCAL, InMemoryAuditSink())
    assert factory(CALLER) is None
    assert gateway.resolved == []


@pytest.mark.parametrize("error", [KeyError("missing"), RuntimeError("没有凭据")])
def test_an_unresolvable_caller_gives_no_provider(error: Exception) -> None:
    factory = caller_model_provider_factory(FakeGateway("mine", error), LOCAL, InMemoryAuditSink())
    assert factory(CALLER) is None


def test_the_callers_model_is_asked_with_the_delegation_purpose(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    factory = caller_model_provider_factory(FakeGateway("mine"), LOCAL, InMemoryAuditSink())
    provider = factory(CALLER)
    assert isinstance(provider, RemoteModelProvider)
    seen: list[str | None] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.headers.get(MODEL_PURPOSE_HEADER))
        return httpx.Response(
            200,
            content=BorrowedModelResult(provider_node_id=CALLER, content="好").model_dump_json(),
        )

    client = provider._client  # pyright: ignore[reportPrivateUsage]
    monkeypatch.setattr(client, "_transport", httpx.MockTransport(handler))
    request = ModelRequest(messages=(ModelMessage(role="user", content="这是什么程序？"),))
    response = asyncio.run(provider.complete(request))
    assert response.content == "好"
    assert seen == [DELEGATION_MODEL_PURPOSE]


def test_nodes_use_the_given_provider_for_delegation_agents(tmp_path: Path) -> None:
    """两种平台的节点：借到了就用借来的提供方建 Agent，借不到就不建。"""
    from tunnelminion import app as windows_app
    from tunnelminion import macos_app

    borrowed: list[NodeId] = []

    def lend(caller: NodeId) -> ModelProvider | None:
        borrowed.append(caller)
        if caller != CALLER:
            return None
        return caller_model_provider_factory(FakeGateway("mine"), LOCAL, InMemoryAuditSink())(
            caller
        )

    windows = replace(windows_app.build_windows_node(tmp_path / "w"), caller_model_provider=lend)
    mac = replace(
        macos_app._build_macos_node(tmp_path / "m"),  # pyright: ignore[reportPrivateUsage]
        caller_model_provider=lend,
    )
    windows_agent = windows_app._caller_agent  # pyright: ignore[reportPrivateUsage]
    mac_agent = macos_app._caller_agent  # pyright: ignore[reportPrivateUsage]
    assert windows_agent(windows, LOCAL) is None
    assert windows_agent(windows, CALLER) is not None
    assert mac_agent(mac, LOCAL) is None
    assert mac_agent(mac, CALLER) is not None
    assert borrowed == [LOCAL, CALLER, LOCAL, CALLER]
    # 默认的节点（没有网关配置）借不到任何电脑的模型。
    assert windows_app.build_windows_node(tmp_path / "w2").caller_model_provider(CALLER) is None
