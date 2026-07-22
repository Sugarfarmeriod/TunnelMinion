"""网关能力发现、版本协商、认证和结构化远端错误测试。"""

from __future__ import annotations

from typing import Protocol, cast

import httpx
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import JsonValue
from tests.tools.test_registry import definition

from tunnelminion.domain.identifiers import NodeId, RunId, ThreadId, ToolRunId
from tunnelminion.domain.tools import Platform, RiskLevel
from tunnelminion.gateway import create_gateway_router
from tunnelminion.gateway.audit import InMemoryGatewaySecurityAuditSink
from tunnelminion.gateway.security import (
    GatewayLimits,
    GatewayPeerPolicy,
    GatewaySecurityPolicy,
)
from tunnelminion.tools.audit import InMemoryAuditSink
from tunnelminion.tools.fakes import FakeToolAdapter
from tunnelminion.tools.registry import ToolRegistry
from tunnelminion.tools.runtime import ToolRuntime

TOKEN = "gateway-test-token-that-is-at-least-32-characters"


class ApiClient(Protocol):
    """屏蔽 TestClient 当前缺失的严格类型标注。"""

    def get(
        self,
        url: str,
        *,
        params: dict[str, int] | None = None,
        headers: dict[str, str] | None = None,
    ) -> httpx.Response: ...

    def post(
        self, url: str, *, json: object, headers: dict[str, str] | None = None
    ) -> httpx.Response: ...


def auth() -> dict[str, str]:
    """返回测试 peer 的独立应用层认证头。"""
    return {"Authorization": f"Bearer {TOKEN}"}


def build_client(
    limits: GatewayLimits | None = None,
) -> tuple[
    ApiClient,
    NodeId,
    NodeId,
    ToolRegistry,
    InMemoryAuditSink,
    InMemoryGatewaySecurityAuditSink,
]:
    """组装包含多种策略条目的 Windows 测试网关。"""
    node_id = NodeId.new()
    caller_node_id = NodeId.new()
    registry = ToolRegistry()
    registry.register(definition("read_status"), FakeToolAdapter())
    registry.register(
        definition("mac_status", platforms=frozenset({Platform.MACOS})),
        FakeToolAdapter(),
    )
    registry.register(definition("restart_service", RiskLevel.REQUIRES_APPROVAL), FakeToolAdapter())
    registry.register(definition("read_other"), FakeToolAdapter())
    audit = InMemoryAuditSink()
    security_audit = InMemoryGatewaySecurityAuditSink()
    runtime = ToolRuntime(registry, Platform.WINDOWS, audit)
    policy = GatewaySecurityPolicy(
        [GatewayPeerPolicy.from_token(caller_node_id, TOKEN, ["read_status"])], limits
    )
    app = FastAPI()
    app.include_router(
        create_gateway_router(node_id, Platform.WINDOWS, registry, runtime, policy, security_audit)
    )
    return (
        cast(ApiClient, TestClient(app)),
        node_id,
        caller_node_id,
        registry,
        audit,
        security_audit,
    )


def call_payload(
    caller: NodeId,
    *,
    protocol_major: int = 1,
    tool_major: int = 1,
    arguments: dict[str, JsonValue] | None = None,
) -> tuple[dict[str, object], RunId, ToolRunId]:
    """创建携带全套关联标识符的远端调用。"""
    run_id = RunId.new()
    tool_run_id = ToolRunId.new()
    return (
        {
            "protocol": {"major": protocol_major, "minor": 0},
            "tool_version": {"major": tool_major, "minor": 0},
            "thread_id": str(ThreadId.new()),
            "run_id": str(run_id),
            "tool_run_id": str(tool_run_id),
            "caller_node_id": str(caller),
            "arguments": arguments or {},
            "timeout_seconds": 2,
        },
        run_id,
        tool_run_id,
    )


def error_code(response: httpx.Response) -> object:
    """读取结构化网关错误码。"""
    return cast(dict[str, object], cast(dict[str, object], response.json())["error"])["code"]


def test_capabilities_negotiate_protocol_and_only_expose_allowed_tools() -> None:
    """能力清单协商版本，并同时应用平台、风险和 peer 允许列表。"""
    client, node_id, _caller, _registry, _audit, security_audit = build_client()
    response = client.get(
        "/v1/capabilities",
        params={"protocol_major": 1, "protocol_minor": 7},
        headers=auth(),
    )

    assert response.status_code == 200
    body = cast(dict[str, object], response.json())
    assert body["protocol"] == {"major": 1, "minor": 0}
    assert body["node_id"] == str(node_id)
    tools = cast(list[dict[str, object]], body["tools"])
    assert [item["name"] for item in tools] == ["read_status"]

    incompatible = client.get(
        "/v1/capabilities",
        params={"protocol_major": 2, "protocol_minor": 0},
        headers=auth(),
    )
    assert incompatible.status_code == 409
    assert error_code(incompatible) == "protocol_version_unsupported"
    assert security_audit.records[-1].action == "capabilities"


def test_exact_tool_call_propagates_ids_and_returns_runtime_result() -> None:
    """远端请求指定的 run/tool run ID 原样进入执行结果和审计。"""
    client, execution_node, caller, _registry, audit, _security_audit = build_client()
    payload, _run_id, tool_run_id = call_payload(caller, arguments={"unexpected": "value"})
    invalid = client.post("/v1/tools/read_status:call", json=payload, headers=auth())
    invalid_body = cast(dict[str, object], invalid.json())
    assert invalid.status_code == 200
    assert invalid_body["status"] == "failed"
    assert cast(dict[str, object], invalid_body["error"])["code"] == "invalid_argument"
    assert invalid_body["tool_run_id"] == str(tool_run_id)

    valid_payload, valid_run_id, valid_tool_run_id = call_payload(caller)
    response = client.post("/v1/tools/read_status:call", json=valid_payload, headers=auth())

    assert response.status_code == 200
    body = cast(dict[str, object], response.json())
    assert body["execution_node_id"] == str(execution_node)
    assert body["run_id"] == str(valid_run_id)
    assert body["tool_run_id"] == str(valid_tool_run_id)
    assert body["status"] == "success"
    assert cast(dict[str, object], body["output"])["ok"] is True
    assert audit.records[-1].run_id == valid_run_id
    assert audit.records[-1].tool_run_id == valid_tool_run_id
    assert audit.records[-1].caller_node_id == caller


def test_call_rejects_protocol_tool_version_and_non_exposed_tools() -> None:
    """协议、工具版本或允许列表不匹配时不进入 Tool Runtime。"""
    client, _node_id, caller, _registry, audit, security_audit = build_client()

    protocol_payload, _, _ = call_payload(caller, protocol_major=2)
    protocol = client.post("/v1/tools/read_status:call", json=protocol_payload, headers=auth())
    assert protocol.status_code == 409
    assert error_code(protocol) == "protocol_version_unsupported"

    version_payload, _, _ = call_payload(caller, tool_major=2)
    version = client.post("/v1/tools/read_status:call", json=version_payload, headers=auth())
    assert version.status_code == 409
    assert error_code(version) == "tool_version_unsupported"

    for name in ("invented_tool", "mac_status", "restart_service"):
        payload, _, _ = call_payload(caller)
        rejected = client.post(f"/v1/tools/{name}:call", json=payload, headers=auth())
        assert rejected.status_code == 404
        assert error_code(rejected) == "tool_not_found"
    payload, _, _ = call_payload(caller)
    forbidden = client.post("/v1/tools/read_other:call", json=payload, headers=auth())
    assert forbidden.status_code == 403
    assert error_code(forbidden) == "forbidden"
    assert audit.records == []
    assert {item.error_code.value for item in security_audit.records} == {
        "protocol_version_unsupported",
        "tool_version_unsupported",
        "tool_not_found",
        "forbidden",
    }


def test_gateway_rejects_bad_identity_and_applies_rate_limit() -> None:
    """缺失令牌、caller 冒充和超额请求均在工具执行前拒绝。"""
    client, _node_id, caller, _registry, audit, security_audit = build_client(
        GatewayLimits(requests_per_minute=1)
    )
    assert client.get("/v1/capabilities").status_code == 401
    assert (
        client.get("/v1/capabilities", headers={"Authorization": "Basic wrong"}).status_code == 401
    )

    impersonated, _, _ = call_payload(NodeId.new())
    forbidden = client.post("/v1/tools/read_status:call", json=impersonated, headers=auth())
    assert forbidden.status_code == 403
    assert error_code(forbidden) == "forbidden"

    payload, _, _ = call_payload(caller)
    limited = client.post("/v1/tools/read_status:call", json=payload, headers=auth())
    assert limited.status_code == 429
    assert error_code(limited) == "rate_limited"
    assert audit.records == []
    serialized = " ".join(item.model_dump_json() for item in security_audit.records)
    assert TOKEN not in serialized
    assert "Authorization" not in serialized
    assert [item.error_code.value for item in security_audit.records] == [
        "unauthenticated",
        "unauthenticated",
        "forbidden",
        "rate_limited",
    ]
    assert security_audit.records[-1].peer_node_id == caller
