"""macOS Tool Gateway 真实组装与私网暴露边界测试。"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Protocol, cast

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from keyring.errors import KeyringError
from pydantic import JsonValue
from tests.operation.factories import plan

from tunnelminion.domain.identifiers import LeaseId, NodeId, RunId, ThreadId
from tunnelminion.gateway.configuration import (
    FileGatewayConfigurationRepository,
    GatewayConfiguration,
    GatewayPeerConfig,
    gateway_token_name,
)
from tunnelminion.gateway.security import GatewayBindConfig
from tunnelminion.macos_app import (
    SafeSharingGatewaySettings,
    _CallbackRequiredVerifier,  # pyright: ignore[reportPrivateUsage]
    _gateway_lifespan,  # pyright: ignore[reportPrivateUsage]
    build_macos_gateway_application,
    build_macos_local_application,
    create_macos_app,
)
from tunnelminion.model.configuration import ModelConfigurationService
from tunnelminion.operation.contracts import (
    LeaseRecord,
    VerificationResult,
)
from tunnelminion.operation.workflow import OperationWorkflow
from tunnelminion.platforms.windows.system import CommandResult
from tunnelminion.tools.contracts import ToolCallContext, ToolExecutionRequest

TOKEN = "tmn_gateway-test-token-with-more-than-32-characters"


class ApiClient(Protocol):
    """屏蔽 TestClient 当前缺失的严格类型标注。"""

    def get(self, url: str, *, headers: dict[str, str]) -> httpx.Response: ...

    def post(
        self,
        url: str,
        *,
        json: object | None = None,
        headers: dict[str, str] | None = None,
    ) -> httpx.Response: ...


def write_gateway_config(
    path: Path,
    caller: NodeId,
    *,
    allowed_operations: frozenset[str] = frozenset(),
) -> None:
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
                    allowed_operations=allowed_operations,
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

    client = cast(ApiClient, TestClient(bundle.app, base_url="http://127.0.0.1"))
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


def test_macos_gateway_enables_safe_sharing_only_with_explicit_peer_scope(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "safe-sharing"
    caller = NodeId.new()
    write_gateway_config(
        root,
        caller,
        allowed_operations=frozenset({"share_local_http_service"}),
    )

    def get_password(_service: str, name: str) -> str | None:
        return TOKEN if name == gateway_token_name(caller) else None

    monkeypatch.setattr("keyring.get_password", get_password)
    bundle = build_macos_gateway_application(
        root,
        safe_sharing=SafeSharingGatewaySettings(bind_port_override=18_883),
    )

    assert bundle.bind.port == 18_883
    assert bundle.operation_service is not None
    assert bundle.operation_workflow is not None
    with TestClient(bundle.app, base_url="http://127.0.0.1") as raw_client:
        client = cast(ApiClient, raw_client)
        response = client.get(
            "/v1/capabilities",
            headers={"Authorization": f"Bearer {TOKEN}"},
        )
    assert response.status_code == 200
    assert response.json()["operations"] == ["share_local_http_service"]


def test_macos_gateway_refuses_safe_sharing_without_allowed_operation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "no-operation"
    caller = NodeId.new()
    write_gateway_config(root, caller)

    def get_password(_service: str, name: str) -> str | None:
        return TOKEN if name == gateway_token_name(caller) else None

    monkeypatch.setattr("keyring.get_password", get_password)

    with pytest.raises(RuntimeError, match="没有 peer"):
        build_macos_gateway_application(root, safe_sharing=SafeSharingGatewaySettings())

    with pytest.raises(ValueError, match="下限"):
        SafeSharingGatewaySettings(minimum_port=18_899, maximum_port=18_880)


def test_gateway_fallback_verifier_and_lifespan_are_fail_closed() -> None:
    operation_plan = plan()
    now = datetime.now(UTC)
    lease = LeaseRecord(
        lease_id=LeaseId.new(),
        operation_id=operation_plan.operation_id,
        starts_at=now,
        expires_at=now + timedelta(seconds=60),
    )
    verification = asyncio.run(_CallbackRequiredVerifier().verify(operation_plan, lease, "secret"))
    assert verification.result is VerificationResult.REQUESTER_OFFLINE
    assert verification.verifier_node_id == operation_plan.request_node_id

    class Workflow:
        def __init__(self) -> None:
            self.recovered = 0
            self.expired = 0

        async def recover_unfinished(self, *, at: datetime) -> tuple[object, ...]:
            assert at.tzinfo is not None
            self.recovered += 1
            return ()

        async def expire_due(self, *, at: datetime) -> tuple[object, ...]:
            assert at.tzinfo is not None
            self.expired += 1
            return ()

    workflow = Workflow()

    async def exercise_lifespan() -> None:
        lifespan = _gateway_lifespan(cast(OperationWorkflow, workflow), 0)
        async with lifespan(FastAPI()):
            await asyncio.sleep(0.01)

    asyncio.run(exercise_lifespan())
    assert workflow.recovered == 1
    assert workflow.expired >= 1


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
    client = cast(ApiClient, TestClient(bundle.app, base_url="http://127.0.0.1"))

    paths = set(bundle.app.openapi()["paths"])
    for original, legacy in (
        ("/chat", "/legacy/chat"),
        ("/resources", "/legacy/resources"),
        ("/operations", "/legacy/operations"),
        ("/memories", "/legacy/memories"),
    ):
        assert original in paths
        assert legacy in paths
    assert "/" in paths
    assert client.get("/resources", headers={}).status_code == 200
    summary = client.get("/api/resources/node-summary", headers={})
    assert summary.status_code == 200
    assert cast(dict[str, object], summary.json())["status"] == "success"
    managed = client.get("/api/resources/managed-node", headers={})
    managed_body = cast(dict[str, object], managed.json())
    enrollment = cast(dict[str, object], managed_body["enrollment"])
    assert enrollment["state"] == "unconfigured"
    assert bundle.managed_node.runtime is None
    overview = client.get("/api/resources/overview", headers={})
    overview_body = cast(dict[str, object], overview.json())
    assert overview.status_code == 200
    assert cast(dict[str, object], overview_body["local"])["platform"] == "macos"
    assert cast(dict[str, object], overview_body["coordinator"])["state"] == "unconfigured"
    diagnostics = client.get("/api/diagnostics/export", headers={})
    diagnostics_body = cast(dict[str, object], diagnostics.json())
    assert diagnostics.status_code == 200
    assert diagnostics.headers["cache-control"] == "no-store"
    diagnostics_overview = cast(dict[str, object], diagnostics_body["overview"])
    diagnostics_runtime = cast(dict[str, object], diagnostics_overview["runtime"])
    assert diagnostics_runtime["platform"] == "macos"
    assert [
        cast(dict[str, object], item)["status"]
        for item in cast(list[object], diagnostics_body["optional_sources"])
    ] == ["unavailable", "unavailable"]
    model = client.get("/api/model-config", headers={})
    assert cast(dict[str, object], model.json())["status"] == "unconfigured"
    cross_site = client.post(
        "/api/threads",
        headers={
            "Origin": "https://attacker.example",
            "Sec-Fetch-Site": "cross-site",
        },
    )
    assert cross_site.status_code == 403
    assert cross_site.json()["detail"]["code"] == "cross_site_request"
    assert client.get("/resources", headers={"Host": "attacker.example"}).status_code == 403
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
