"""长期记忆查看、确认、修正和删除 API/UI。"""

# ruff: noqa: E501

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query, status
from fastapi.responses import HTMLResponse, Response
from pydantic import BaseModel, ConfigDict, Field

from tunnelminion.domain.identifiers import MemoryId, NodeId
from tunnelminion.memory.contracts import MemoryNamespace
from tunnelminion.memory.service import (
    LongTermMemoryService,
    MemoryCandidate,
    MemoryWriteRejected,
)

_MEMORY_PAGE = """<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">
<title>TunnelMinion 长期记忆</title><style>body{font-family:system-ui;max-width:1000px;margin:2rem auto;padding:0 1rem}input,button{font:inherit;margin:.25rem}.memory{border:1px solid #ddd;border-radius:8px;padding:.8rem;margin:.6rem 0}code{word-break:break-all}</style></head><body>
<h1>长期记忆</h1><p>这里只显示用户明确确认过的稳定事实和偏好。实时状态请重新运行工具获取。</p>
<label>用户 <input id="user" value="local-user"></label><label>网络 <input id="network" value="home"></label><label>节点 ID <input id="node" placeholder="node_..."></label>
<button onclick="loadMemories()">查看</button><button onclick="clearScope()">清空此作用域</button><div id="items"></div>
<script>async function api(path,options){const r=await fetch(path,options);if(!r.ok)throw new Error(await r.text());return r.status===204?null:r.json()}
function query(){return new URLSearchParams({user:document.getElementById('user').value,network:document.getElementById('network').value,node_id:document.getElementById('node').value})}
async function loadMemories(){const values=await api('/api/memories?'+query());const root=document.getElementById('items');root.innerHTML='';for(const m of values){const box=document.createElement('div');box.className='memory';const text=document.createElement('input');text.value=m.content;text.size=70;const source=document.createElement('input');source.value=m.source;source.size=35;const save=document.createElement('button');save.textContent='保存修正';save.onclick=async()=>{await api('/api/memories/'+m.memory_id,{method:'PUT',headers:{'content-type':'application/json'},body:JSON.stringify({content:text.value,source:source.value})});loadMemories()};const remove=document.createElement('button');remove.textContent='删除';remove.onclick=async()=>{await api('/api/memories/'+m.memory_id,{method:'DELETE'});loadMemories()};box.append(document.createTextNode(m.kind+' · '+m.updated_at+' '),text,source,save,remove);root.appendChild(box)}}
async function clearScope(){await api('/api/memories/scope?'+query(),{method:'DELETE'});loadMemories()}</script></body></html>"""


class ReviseMemoryInput(BaseModel):
    """用户确认的一次记忆修正。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    content: str = Field(min_length=1, max_length=20_000)
    source: str = Field(min_length=1, max_length=2_000)


def create_memory_router(service: LongTermMemoryService) -> APIRouter:
    """创建只由本机应用挂载的长期记忆路由。"""
    router = APIRouter()

    def namespace(user: str, network: str, node_id: str) -> MemoryNamespace:
        try:
            return MemoryNamespace(user=user, network=network, node_id=NodeId(node_id))
        except ValueError as exc:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "记忆作用域无效") from exc

    def memory_id(value: str) -> MemoryId:
        try:
            return MemoryId(value)
        except ValueError as exc:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "记忆不存在") from exc

    def memory_page() -> HTMLResponse:
        return HTMLResponse(_MEMORY_PAGE)

    def list_memories(
        user: str = Query(min_length=1, max_length=128),
        network: str = Query(min_length=1, max_length=128),
        node_id: str = Query(min_length=1),
    ) -> list[dict[str, object]]:
        scope = namespace(user, network, node_id)
        return [item.model_dump(mode="json") for item in service.list(scope)]

    def confirm_memory(payload: MemoryCandidate) -> dict[str, object]:
        try:
            return service.save_confirmed(payload).model_dump(mode="json")
        except MemoryWriteRejected as exc:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, exc.code) from exc

    def revise_memory(value: str, payload: ReviseMemoryInput) -> dict[str, object]:
        try:
            return service.revise(memory_id(value), payload.content, payload.source).model_dump(
                mode="json"
            )
        except MemoryWriteRejected as exc:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, exc.code) from exc
        except KeyError as exc:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "记忆不存在") from exc

    def delete_memory(value: str) -> Response:
        try:
            service.delete(memory_id(value))
        except KeyError as exc:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "记忆不存在") from exc
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    def clear_scope(
        user: str = Query(min_length=1, max_length=128),
        network: str = Query(min_length=1, max_length=128),
        node_id: str = Query(min_length=1),
    ) -> Response:
        service.clear(namespace(user, network, node_id))
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    router.add_api_route("/memories", memory_page, methods=["GET"], response_class=HTMLResponse)
    router.add_api_route("/api/memories", list_memories, methods=["GET"])
    router.add_api_route("/api/memories/confirm", confirm_memory, methods=["POST"])
    router.add_api_route("/api/memories/scope", clear_scope, methods=["DELETE"])
    router.add_api_route("/api/memories/{value}", revise_memory, methods=["PUT"])
    router.add_api_route("/api/memories/{value}", delete_memory, methods=["DELETE"])
    return router
