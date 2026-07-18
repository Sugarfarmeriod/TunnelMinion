"""Windows 资源 API 与最小只读资源页面。"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Body
from fastapi.responses import HTMLResponse
from pydantic import JsonValue

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
const paths=['node-summary','wireguard','listeners','processes','docker'];
async function refreshAll(){const root=document.getElementById('content');root.innerHTML='';
for(const name of paths){const r=await fetch('/api/resources/'+name);const data=await r.json();
const s=document.createElement('section');s.innerHTML='<h2>'+name+'</h2><pre></pre>';
s.querySelector('pre').textContent=JSON.stringify(data,null,2);root.appendChild(s);}}
refreshAll();</script></body></html>"""


def create_resource_router(runtime: ToolRuntime, node_id: NodeId) -> APIRouter:
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

    async def probe(
        payload: Annotated[dict[str, JsonValue], Body()],
    ) -> dict[str, object]:
        return await call_tool("probe_service_reachability", payload)

    def page() -> HTMLResponse:
        return HTMLResponse(_RESOURCE_PAGE)

    router.add_api_route("/api/resources/wireguard", wireguard, methods=["GET"])
    router.add_api_route("/api/resources/listeners", listeners, methods=["GET"])
    router.add_api_route("/api/resources/processes", processes, methods=["GET"])
    router.add_api_route("/api/resources/docker", docker, methods=["GET"])
    router.add_api_route("/api/resources/node-summary", node_summary, methods=["GET"])
    router.add_api_route("/api/resources/probe", probe, methods=["POST"])
    router.add_api_route("/resources", page, methods=["GET"], response_class=HTMLResponse)
    return router
