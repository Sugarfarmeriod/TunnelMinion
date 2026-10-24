"""两种节点入口与借用命令的接线测试。"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import httpx
import pytest
from tests.test_delegation_apps import PEER, TOKEN, configure

from tunnelminion import cli
from tunnelminion.app import build_windows_node
from tunnelminion.domain.identifiers import NodeId
from tunnelminion.domain.model_borrowing import BorrowedModelCall, BorrowedModelResult
from tunnelminion.gateway.client import FixedGatewayClient
from tunnelminion.macos_app import build_macos_local_application
from tunnelminion.model.configuration import FileModelConfigurationRepository
from tunnelminion.model.contracts import ModelMessage, ModelRequest, ModelUsage, ToolCall
from tunnelminion.model.remote import RemoteModelProvider
from tunnelminion.tools.audit import AuditSink

ClientArguments = tuple[str, str, NodeId, NodeId, AuditSink]


@pytest.fixture
def mock_gateway(monkeypatch: pytest.MonkeyPatch) -> list[ClientArguments]:
    seen: list[ClientArguments] = []

    class RecordingClient(FixedGatewayClient):
        def __init__(
            self,
            endpoint: str,
            token: str,
            local_node_id: NodeId,
            remote_node_id: NodeId,
            audit_sink: AuditSink,
            *,
            max_response_bytes: int = 512_000,
            transport: httpx.AsyncBaseTransport | None = None,
        ) -> None:
            seen.append((endpoint, token, local_node_id, remote_node_id, audit_sink))
            assert transport is None

            def handler(request: httpx.Request) -> httpx.Response:
                assert str(request.url) == f"{endpoint}/v1/model:complete"
                assert request.headers["Authorization"] == f"Bearer {token}"
                call = BorrowedModelCall.model_validate_json(request.content)
                assert call.caller_node_id == local_node_id
                result = BorrowedModelResult(
                    provider_node_id=remote_node_id,
                    content="结果",
                    reasoning_content="推理记录",
                    tool_calls=(
                        ToolCall(
                            call_id="validation",
                            name=call.tools[0].name,
                            arguments={"status": "ok"},
                        ),
                    )
                    if call.tools
                    else (),
                    structured_output={"status": "ok"} if call.response_schema else None,
                    usage=ModelUsage(total_tokens=20),
                )
                return httpx.Response(200, content=result.model_dump_json())

            super().__init__(
                endpoint,
                token,
                local_node_id,
                remote_node_id,
                audit_sink,
                max_response_bytes=max_response_bytes,
                transport=httpx.MockTransport(handler),
            )

    monkeypatch.setattr("tunnelminion.app.FixedGatewayClient", RecordingClient)
    monkeypatch.setattr("tunnelminion.macos_app.FixedGatewayClient", RecordingClient)
    return seen


@pytest.mark.parametrize("platform", ["win32", "darwin"])
def test_node_builders_resolve_borrowed_peer_with_node_identity_and_audit(
    tmp_path: Path, platform: str, mock_gateway: list[ClientArguments]
) -> None:
    configure(tmp_path, allow_delegation=False)
    node = (
        build_macos_local_application(tmp_path).node
        if platform == "darwin"
        else build_windows_node(tmp_path)
    )
    view = asyncio.run(node.model_service.borrow(PEER))
    assert view.status == "available" and view.borrowed_from == PEER
    provider = node.model_service.create_provider()
    assert isinstance(provider, RemoteModelProvider)
    reply = asyncio.run(
        provider.complete(ModelRequest(messages=(ModelMessage(role="user", content="问题"),)))
    )
    assert reply.content == "结果" and reply.reasoning_content == "推理记录"
    assert reply.usage.total_tokens == 20
    assert len(mock_gateway) == 2
    for endpoint, token, local, remote, audit in mock_gateway:
        assert (endpoint, token, local, remote) == (
            "http://10.77.0.1:8787",
            TOKEN,
            node.node_id,
            PEER,
        )
        assert audit is node.audit_sink


@pytest.mark.parametrize("platform", ["win32", "darwin"])
@pytest.mark.parametrize("explicit_data_dir", [False, True])
def test_model_borrow_cli_prints_view_and_persists_without_api_key(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    platform: str,
    explicit_data_dir: bool,
    mock_gateway: list[ClientArguments],
) -> None:
    configure(tmp_path, allow_delegation=False)
    monkeypatch.setattr(cli.sys, "platform", platform)
    monkeypatch.setattr("tunnelminion.app.default_data_dir", lambda: tmp_path)
    monkeypatch.setattr("tunnelminion.macos_app.default_data_dir", lambda: tmp_path)
    values = ["model-borrow", "--from", str(PEER)]
    if explicit_data_dir:
        values.extend(["--data-dir", str(tmp_path)])
    assert cli.main(values) == 0
    view = json.loads(capsys.readouterr().out)
    assert view["borrowed_from"] == str(PEER)
    assert view["status"] == "available" and not view["api_key_configured"]
    assert view["endpoint"] is None and view["model"] is None
    repository = FileModelConfigurationRepository(tmp_path / "model.json")
    borrowed = repository.load_borrowed()
    assert borrowed is not None and borrowed.peer_node_id == PEER
    assert repository.load() is None
    assert len(mock_gateway) == 1
    assert TOKEN not in json.dumps(view)
