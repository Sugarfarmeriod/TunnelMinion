"""macOS Tool Gateway 真实组装与私网暴露边界测试。"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Protocol, cast

import httpx
import pytest
from fastapi.testclient import TestClient
from keyring.errors import KeyringError
from pydantic import JsonValue

from tunnelminion.domain.identifiers import NodeId, RunId, ThreadId
from tunnelminion.gateway.configuration import (
    FileGatewayConfigurationRepository,
    GatewayConfiguration,
    GatewayPeerConfig,
    gateway_token_name,
)
from tunnelminion.gateway.security import GatewayBindConfig
from tunnelminion.macos_app import (
    build_macos_gateway_application,
    build_macos_local_application,
    create_macos_app,
)
from tunnelminion.model.configuration import ModelConfigurationService
from tunnelminion.platforms.windows.system import CommandResult
from tunnelminion.tools.contracts import ToolCallContext, ToolExecutionRequest

TOKEN = "tmn_gateway-test-token-with-more-than-32-characters"


class ApiClient(Protocol):
    """屏蔽 TestClient 当前缺失的严格类型标注。"""

    def get(self, url: str, *, headers: dict[str, str]) -> httpx.Response: ...

    def post(self, url: str, *, json: object | None = None) -> httpx.Response: ...


def write_gateway_config(path: Path, caller: NodeId) -> None:
    """写入不含 token 的 B 节点网关配置。"""
    FileGatewayConfigurationRepository(path / "gateway.json").save(
        GatewayConfiguration(
            bind=GatewayBindConfig(host="10.77.0.1", port=8787),
            peers=(
                GatewayPeerConfig(
                    node_id=caller,
                    host="10.77.0.2",
                    allowed_tools=frozenset(
                        {
                            "get_node_summary",
                            "get_wireguard_status",
                            "list_network_listeners",
                            "get_process_summary",
                            "list_docker_services",
                            "probe_service_reachability",
                        }
                    ),
                ),
            ),
        )
    )


def test_macos_gateway_requires_configuration_for_explicit_and_default_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """未配置 WireGuard 地址和 peer 时绝不退回通配监听。"""
    with pytest.raises(RuntimeError, match="尚未配置"):
        build_macos_gateway_application(tmp_path / "explicit")
    monkeypatch.setattr("tunnelminion.macos_app.default_data_dir", lambda: tmp_path / "default")
    with pytest.raises(RuntimeError, match="尚未配置"):
        build_macos_gateway_application()


def test_macos_gateway_exposes_only_authenticated_v1_tools(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """B 网关不挂载本地页面，并在无模型配置时保持工具能力可用。"""
    root = tmp_path / "mac"
    caller = NodeId.new()
    write_gateway_config(root, caller)

    def get_password(_service: str, name: str) -> str | None:
        return TOKEN if name == gateway_token_name(caller) else None

    async def no_interfaces(
        _self: object, command: tuple[str, ...], timeout_seconds: float
    ) -> CommandResult:
        del timeout_seconds
        assert command[-1] == "interfaces"
        return CommandResult(returncode=0, stdout="", stderr="")

    monkeypatch.setattr("keyring.get_password", get_password)
    monkeypatch.setattr(
        "tunnelminion.platforms.windows.system.SubprocessCommandRunner.run",
        no_interfaces,
    )
    bundle = build_macos_gateway_application(root)
    assert bundle.bind.host == "10.77.0.1"
    assert bundle.bind.port == 8787
    assert bundle.app.docs_url is None
    assert bundle.app.openapi_url is None

    client = cast(ApiClient, TestClient(bundle.app))
    for local_path in ("/docs", "/resources", "/api/model-config"):
        assert client.get(local_path, headers={}).status_code == 404
    capabilities = client.get("/v1/capabilities", headers={"Authorization": f"Bearer {TOKEN}"})
    assert capabilities.status_code == 200
    body = cast(dict[str, JsonValue], capabilities.json())
    assert body["platform"] == "macos"
    assert len(cast(list[object], body["tools"])) == 6

    context = ToolCallContext(
        thread_id=ThreadId.new(),
        run_id=RunId.new(),
        caller_node_id=caller,
        execution_node_id=bundle.node_id,
    )
    summary = asyncio.run(
        bundle.tool_runtime.execute(
            ToolExecutionRequest(context=context, tool_name="get_node_summary")
        )
    )
    assert cast(dict[str, JsonValue], summary.output)["model_status"] == "unconfigured"

    def keyring_failure(_service: str, name: str) -> str | None:
        if name == gateway_token_name(caller):
            return TOKEN
        raise KeyringError("unavailable")

    monkeypatch.setattr("keyring.get_password", keyring_failure)
    degraded = asyncio.run(
        bundle.tool_runtime.execute(
            ToolExecutionRequest(context=context, tool_name="get_node_summary")
        )
    )
    assert cast(dict[str, JsonValue], degraded.output)["model_status"] == "unconfigured"


def test_macos_local_resources_degrade_without_model(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """B 未配置模型时资源页和只读工具可用，只有 AI 运行入口拒绝。"""

    def no_password(_service: str, _name: str) -> None:
        return None

    monkeypatch.setattr("keyring.get_password", no_password)

    async def no_interfaces(
        _self: object, command: tuple[str, ...], timeout_seconds: float
    ) -> CommandResult:
        del timeout_seconds
        assert command[-1] == "interfaces"
        return CommandResult(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(
        "tunnelminion.platforms.windows.system.SubprocessCommandRunner.run",
        no_interfaces,
    )
    bundle = build_macos_local_application(tmp_path / "local")
    client = cast(ApiClient, TestClient(bundle.app))

    assert client.get("/resources", headers={}).status_code == 200
    summary = client.get("/api/resources/node-summary", headers={})
    assert summary.status_code == 200
    assert cast(dict[str, object], summary.json())["status"] == "success"
    model = client.get("/api/model-config", headers={})
    assert cast(dict[str, object], model.json())["status"] == "unconfigured"
    unavailable = client.post("/api/ai/runs/availability")
    assert unavailable.status_code == 503
    thread = cast(dict[str, object], client.post("/api/threads").json())
    run = client.post(
        f"/api/threads/{thread['thread_id']}/runs",
        json={"question": "检查本机状态", "tool_names": ["get_node_summary"]},
    )
    assert run.status_code == 503

    def opaque_provider(_self: ModelConfigurationService) -> object:
        return object()

    monkeypatch.setattr(ModelConfigurationService, "create_provider", opaque_provider)
    assert bundle.create_read_only_agent()

    monkeypatch.setattr("tunnelminion.macos_app.default_data_dir", lambda: tmp_path / "factory")
    assert create_macos_app().title == "TunnelMinion"
