"""本机聊天 thread/run API 与 SSE 公开事件流。"""

# ruff: noqa: E501

from __future__ import annotations

from collections.abc import AsyncIterator

from fastapi import APIRouter, HTTPException, Query, status
from fastapi.responses import HTMLResponse, Response, StreamingResponse

from tunnelminion.agent.conversation import InMemoryConversationService, StartRunInput
from tunnelminion.domain.identifiers import RunId, ThreadId
from tunnelminion.model.contracts import ProviderError

_CHAT_PAGE = """<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">
<title>TunnelMinion 聊天</title><style>
body{font-family:system-ui;margin:0;display:grid;grid-template-columns:260px 1fr;height:100vh}
aside{border-right:1px solid #ddd;padding:1rem;overflow:auto}main{padding:1.5rem;overflow:auto}
button,select,textarea{font:inherit;margin:.25rem}textarea{width:min(760px,95%);height:90px}
.message,.event{border:1px solid #ddd;border-radius:8px;padding:.7rem;margin:.5rem 0;white-space:pre-wrap}
</style></head><body><aside><h2>线程</h2><button onclick="newThread()">新建</button>
<button onclick="deleteThread()">删除</button><div id="threads"></div></aside><main>
<h1>TunnelMinion 只读诊断</h1><div id="messages"></div><textarea id="question"
placeholder="例如：本机 WireGuard 和模型状态如何？"></textarea><br><label>本次允许工具：
<select id="tool"><option>get_node_summary</option><option>get_wireguard_status</option>
<option>list_network_listeners</option><option>get_process_summary</option>
<option>list_docker_services</option><option>probe_service_reachability</option></select></label>
<button onclick="send()">发送</button><button onclick="cancelRun()">取消运行</button>
<div id="events"></div><script>
let currentThread=null,currentRun=null;
async function api(path,options){const r=await fetch(path,options);if(!r.ok)throw new Error(await r.text());return r.status===204?null:r.json()}
async function refresh(){const ts=await api('/api/threads');const root=document.getElementById('threads');root.innerHTML='';
for(const t of ts){const b=document.createElement('button');b.textContent=t.thread_id+' ('+t.message_count+')';
b.onclick=()=>openThread(t.thread_id);root.appendChild(b);root.appendChild(document.createElement('br'));}
if(!currentThread&&ts.length)await openThread(ts[0].thread_id)}
async function newThread(){const t=await api('/api/threads',{method:'POST'});await refresh();await openThread(t.thread_id)}
async function openThread(id){currentThread=id;const d=await api('/api/threads/'+id);const root=document.getElementById('messages');root.innerHTML='';
for(const m of d.messages){const e=document.createElement('div');e.className='message';e.textContent=m.role+': '+m.content;root.appendChild(e)}}
async function send(){if(!currentThread)await newThread();const q=document.getElementById('question').value;
const tool=document.getElementById('tool').value;const r=await api('/api/threads/'+currentThread+'/runs',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({question:q,tool_names:[tool]})});currentRun=r.run_id;
const es=new EventSource('/api/runs/'+currentRun+'/events');es.onmessage=()=>{};for(const name of ['goal','tool','finished','failed'])es.addEventListener(name,e=>{const d=JSON.parse(e.data);const line=document.createElement('div');line.className='event';line.textContent=name+': '+JSON.stringify(d);document.getElementById('events').appendChild(line);if(name==='finished'||name==='failed'){es.close();openThread(currentThread);refresh()}})}
async function cancelRun(){if(currentRun)await api('/api/runs/'+currentRun+'/cancel',{method:'POST'})}
async function deleteThread(){if(currentThread){await api('/api/threads/'+currentThread,{method:'DELETE'});currentThread=null;document.getElementById('messages').innerHTML='';await refresh()}}
refresh();</script></main></body></html>"""


def create_conversation_router(service: InMemoryConversationService) -> APIRouter:
    """创建只由环回绑定应用挂载的对话路由。"""
    router = APIRouter()

    def thread_id(value: str) -> ThreadId:
        try:
            return ThreadId(value)
        except ValueError as exc:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "线程不存在") from exc

    def run_id(value: str) -> RunId:
        try:
            return RunId(value)
        except ValueError as exc:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "运行不存在") from exc

    def not_found(exc: KeyError) -> HTTPException:
        message = "线程不存在" if exc.args == ("thread_not_found",) else "运行不存在"
        return HTTPException(status.HTTP_404_NOT_FOUND, message)

    async def create_thread() -> dict[str, object]:
        return service.create_thread().model_dump(mode="json")

    async def list_threads() -> list[dict[str, object]]:
        return [item.model_dump(mode="json") for item in service.list_threads()]

    async def get_thread(value: str) -> dict[str, object]:
        try:
            return service.get_thread(thread_id(value)).model_dump(mode="json")
        except KeyError as exc:
            raise not_found(exc) from exc

    async def delete_thread(value: str) -> Response:
        try:
            service.delete_thread(thread_id(value))
        except KeyError as exc:
            raise not_found(exc) from exc
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    def chat_page() -> HTMLResponse:
        return HTMLResponse(_CHAT_PAGE)

    async def start_run(value: str, payload: StartRunInput) -> dict[str, object]:
        try:
            view = await service.start_run(thread_id(value), payload)
        except KeyError as exc:
            raise not_found(exc) from exc
        except ProviderError as exc:
            raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, str(exc)) from exc
        return view.model_dump(mode="json")

    async def get_run(value: str) -> dict[str, object]:
        try:
            return service.get_run(run_id(value)).model_dump(mode="json")
        except KeyError as exc:
            raise not_found(exc) from exc

    async def cancel_run(value: str) -> dict[str, object]:
        try:
            return service.cancel_run(run_id(value)).model_dump(mode="json")
        except KeyError as exc:
            raise not_found(exc) from exc

    async def events(value: str, after: int = Query(default=0, ge=0)) -> StreamingResponse:
        identifier = run_id(value)

        async def body() -> AsyncIterator[str]:
            try:
                async for event in service.stream_events(identifier, after):
                    yield (
                        f"id: {event.sequence}\n"
                        f"event: {event.event_type.value}\n"
                        f"data: {event.model_dump_json()}\n\n"
                    )
            except KeyError:
                return

        try:
            service.get_run(identifier)
        except KeyError as exc:
            raise not_found(exc) from exc
        return StreamingResponse(body(), media_type="text/event-stream")

    router.add_api_route("/api/threads", create_thread, methods=["POST"])
    router.add_api_route("/api/threads", list_threads, methods=["GET"])
    router.add_api_route("/api/threads/{value}", get_thread, methods=["GET"])
    router.add_api_route("/api/threads/{value}", delete_thread, methods=["DELETE"])
    router.add_api_route("/api/threads/{value}/runs", start_run, methods=["POST"])
    router.add_api_route("/api/runs/{value}", get_run, methods=["GET"])
    router.add_api_route("/api/runs/{value}/cancel", cancel_run, methods=["POST"])
    router.add_api_route("/api/runs/{value}/events", events, methods=["GET"])
    router.add_api_route("/chat", chat_page, methods=["GET"], response_class=HTMLResponse)
    return router
