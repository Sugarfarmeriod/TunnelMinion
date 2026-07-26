"""Windows 资源 API 与最小只读资源页面。"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from enum import StrEnum
from typing import Annotated, cast

from fastapi import APIRouter, Body
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, ConfigDict, JsonValue

from tunnelminion.agent.coordinator import (
    CoordinatorCache,
    CoordinatorSyncStatus,
    SyncPhase,
)
from tunnelminion.coordinator.contracts import (
    DirectoryFreshness,
    NodeStatus,
)
from tunnelminion.domain.identifiers import NodeId, RunId, ThreadId
from tunnelminion.tools.contracts import ToolCallContext, ToolExecutionRequest
from tunnelminion.tools.runtime import ToolRuntime

_RESOURCE_PAGE = """<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><title>TunnelMinion 资源</title>
<style>body{font-family:system-ui;max-width:1100px;margin:2rem auto;padding:0 1rem}
section{border:1px solid #ddd;border-radius:8px;padding:1rem;margin:1rem 0}
pre{overflow:auto}</style>
</head><body><h1>TunnelMinion 本机资源</h1>
<p>这些数据来自确定性只读工具，即使模型不可用也能刷新。</p>
<button onclick="refreshAll()">刷新</button><div id="content"></div>
<script>
const paths=['node-summary','wireguard','listeners','processes','docker','coordinator'];
async function refreshAll(){const root=document.getElementById('content');root.innerHTML='';
for(const name of paths){let data;
try{const r=await fetch('/api/resources/'+name);data=await r.json();}
catch(error){data={status:'unavailable',error:String(error)}}
const s=document.createElement('section');s.innerHTML='<h2>'+name+'</h2><pre></pre>';
s.querySelector('pre').textContent=JSON.stringify(data,null,2);root.appendChild(s);}}
refreshAll();</script></body></html>"""


class CoordinatorResourceState(StrEnum):
    """面板明确区分实时、陈旧与 managed 认证过期。"""

    UNCONFIGURED = "unconfigured"
    CONNECTING = "connecting"
    READY = "ready"
    STALE = "stale"
    OFFLINE = "offline"
    INCOMPATIBLE = "incompatible"
    MANAGED_AUTH_EXPIRED = "managed-auth-expired"


class CoordinatorResourceView(BaseModel):
    """不含任何可重放凭据的 Coordinator 资源摘要。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    configured: bool
    state: CoordinatorResourceState
    directory_may_be_stale: bool
    last_success_at: datetime | None = None
    server_revision: int = 0
    last_error_code: str | None = None
    phase: SyncPhase | None = None
    nodes: tuple[dict[str, JsonValue], ...] = ()


def create_resource_router(
    runtime: ToolRuntime,
    node_id: NodeId,
    *,
    coordinator_status: Callable[[], CoordinatorSyncStatus] | None = None,
    coordinator_cache: CoordinatorCache | None = None,
    clock: Callable[[], datetime] | None = None,
) -> APIRouter:
    """创建不依赖模型 Provider 的本机资源路由。"""
    router = APIRouter()

    async def call_tool(
        name: str, arguments: dict[str, JsonValue] | None = None
    ) -> dict[str, object]:
        result = await runtime.execute(
            ToolExecutionRequest(
                context=ToolCallContext(
                    thread_id=ThreadId.new(),
                    run_id=RunId.new(),
                    caller_node_id=node_id,
                    execution_node_id=node_id,
                ),
                tool_name=name,
                arguments=arguments or {},
            )
        )
        return result.model_dump(mode="json")

    async def wireguard() -> dict[str, object]:
        return await call_tool("get_wireguard_status")

    async def listeners() -> dict[str, object]:
        return await call_tool("list_network_listeners")

    async def processes(limit: int = 50) -> dict[str, object]:
        return await call_tool("get_process_summary", {"limit": limit})

    async def docker() -> dict[str, object]:
        return await call_tool("list_docker_services")

    async def node_summary() -> dict[str, object]:
        return await call_tool("get_node_summary")

    async def coordinator() -> CoordinatorResourceView:
        return coordinator_resource_view(
            coordinator_status() if coordinator_status is not None else None,
            coordinator_cache,
            now=(clock or (lambda: datetime.now(UTC)))(),
        )

    async def probe(
        payload: Annotated[dict[str, JsonValue], Body()],
    ) -> dict[str, object]:
        return await call_tool("probe_service_reachability", payload)

    def page() -> HTMLResponse:
        return HTMLResponse(
            _RESOURCE_PAGE,
            headers={
                "Content-Security-Policy": (
                    "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; "
                    "connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
                ),
                "Cache-Control": "no-store",
                "X-Content-Type-Options": "nosniff",
            },
        )

    router.add_api_route("/api/resources/wireguard", wireguard, methods=["GET"])
    router.add_api_route("/api/resources/listeners", listeners, methods=["GET"])
    router.add_api_route("/api/resources/processes", processes, methods=["GET"])
    router.add_api_route("/api/resources/docker", docker, methods=["GET"])
    router.add_api_route("/api/resources/node-summary", node_summary, methods=["GET"])
    router.add_api_route(
        "/api/resources/coordinator",
        coordinator,
        methods=["GET"],
        response_model=CoordinatorResourceView,
    )
    router.add_api_route("/api/resources/probe", probe, methods=["POST"])
    router.add_api_route("/resources", page, methods=["GET"], response_class=HTMLResponse)
    return router


def coordinator_resource_view(
    status: CoordinatorSyncStatus | None,
    cache: CoordinatorCache | None,
    *,
    now: datetime,
) -> CoordinatorResourceView:
    """把同步器和缓存压缩为显式状态，不把缓存伪装成实时目录。"""
    if now.tzinfo is None:
        raise ValueError("Coordinator 资源面板时钟必须包含时区")
    if status is None or cache is None:
        return CoordinatorResourceView(
            configured=False,
            state=CoordinatorResourceState.UNCONFIGURED,
            directory_may_be_stale=True,
        )
    view = cache.read()
    if view is None:
        return CoordinatorResourceView(
            configured=True,
            state=CoordinatorResourceState.CONNECTING,
            directory_may_be_stale=True,
            last_success_at=status.last_success_at,
            server_revision=status.server_revision,
            last_error_code=status.last_error_code,
            phase=status.phase,
        )
    current = now.astimezone(UTC)
    if not view.is_fresh(current):
        state = CoordinatorResourceState.MANAGED_AUTH_EXPIRED
    elif any(item.status is NodeStatus.INCOMPATIBLE for item in view.nodes):
        state = CoordinatorResourceState.INCOMPATIBLE
    elif view.nodes and all(
        item.status in {NodeStatus.OFFLINE, NodeStatus.REVOKED} for item in view.nodes
    ):
        state = CoordinatorResourceState.OFFLINE
    elif any(
        item.status is NodeStatus.STALE or item.freshness is not DirectoryFreshness.FRESH
        for item in view.nodes
    ):
        state = CoordinatorResourceState.STALE
    else:
        state = CoordinatorResourceState.READY
    nodes = tuple(
        cast(
            dict[str, JsonValue],
            {
                "node_id": str(item.identity.node_id),
                "display_name": item.identity.display_name,
                "platform": item.identity.platform.value,
                "status": item.status.value,
                "freshness": item.freshness.value,
                "protocol": item.identity.protocol.model_dump(mode="json"),
                "gateway_endpoint": item.identity.gateway_endpoint.model_dump(mode="json"),
                "server_revision": item.server_revision,
                "capabilities": [
                    capability.model_dump(mode="json") for capability in item.capabilities
                ],
                "services": [service.model_dump(mode="json") for service in item.services],
            },
        )
        for item in view.nodes
    )
    return CoordinatorResourceView(
        configured=True,
        state=state,
        directory_may_be_stale=state is not CoordinatorResourceState.READY,
        last_success_at=status.last_success_at,
        server_revision=max(
            (status.server_revision, *(item.server_revision for item in view.nodes))
        ),
        last_error_code=status.last_error_code,
        phase=status.phase,
        nodes=nodes,
    )
