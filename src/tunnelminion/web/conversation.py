"""本机聊天 thread/run API 与 SSE 公开事件流。"""

# ruff: noqa: E501

from __future__ import annotations

import json
from collections.abc import AsyncIterator, Callable

from fastapi import APIRouter, HTTPException, Query, status
from fastapi.responses import HTMLResponse, Response, StreamingResponse
from pydantic import BaseModel, ConfigDict, Field

from tunnelminion.agent.conversation import (
    InMemoryConversationService,
    StartRunInput,
    ThreadContext,
)
from tunnelminion.agent.runtime import ServiceCheckTarget
from tunnelminion.domain.identifiers import RunId, ServiceId, ThreadId
from tunnelminion.model.contracts import ProviderError
from tunnelminion.web.overview import OverviewFreshness, OverviewService
from tunnelminion.web.service_map import LocalServiceMap

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
async function api(path,options={}){const method=(options.method||'GET').toUpperCase();const headers=new Headers(options.headers||{});if(!['GET','HEAD','OPTIONS','TRACE'].includes(method))headers.set('X-TunnelMinion-Request','same-origin');const r=await fetch(path,{...options,headers});if(!r.ok)throw new Error(await r.text());return r.status===204?null:r.json()}
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


class StartProgramRunInput(StartRunInput):
    """工作台专用的所选程序身份，不改变既有对话请求契约。"""

    service_id: ServiceId | None = None


class ResumeRunInput(BaseModel):
    """继续未完任务时可补充问题，工具与对象仍由原任务和当前清单界定。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    question: str | None = Field(default=None, min_length=1, max_length=20_000)


def create_conversation_router(
    service: InMemoryConversationService,
    overview: OverviewService | None = None,
    local_services: Callable[[], LocalServiceMap] | None = None,
) -> APIRouter:
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

    async def get_program_thread(value: str) -> dict[str, object]:
        identifier = thread_id(value)
        try:
            detail = service.get_thread(identifier).model_dump(mode="json")
            selected = service.get_thread_service_id(identifier)
            return {**detail, "service_id": str(selected) if selected is not None else None}
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
        return await begin_run(value, payload)

    async def start_program_run(value: str, payload: StartProgramRunInput) -> dict[str, object]:
        target = current_target(payload.service_id) if payload.service_id is not None else None
        return await begin_run(value, payload, target)

    async def about_context(
        identifier: ThreadId, payload: StartRunInput
    ) -> tuple[ThreadContext | None, str | None]:
        saved = service.get_thread(identifier).context
        about = payload.about or saved
        if about is None:
            return None, None
        if about.node_id != str(service.node_id):
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "目前只能询问这台电脑")
        if saved is not None and (
            saved.node_id != about.node_id or saved.service_key != about.service_key
        ):
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "请为另一个对象新建对话")
        details: dict[str, object] = {"node_id": about.node_id}
        name = None
        if about.service_key is not None:
            # 与首页同一份已观察清单，不重新扫描电脑。
            local = local_services() if local_services is not None else None
            selected = (
                next(
                    (
                        item
                        for item in local.services
                        if item.key == about.service_key and item.tier != "hidden"
                    ),
                    None,
                )
                if local is not None
                else None
            )
            if selected is None:
                raise HTTPException(
                    status.HTTP_422_UNPROCESSABLE_CONTENT, "服务不在当前可见清单中，请刷新后重试"
                )
            name = selected.name
            details.update(
                service_name=name,
                kind=selected.kind,
                service_key=selected.key,
                ports=[f"{item.protocol}/{item.port}" for item in selected.endpoints],
            )
        context = saved or ThreadContext(
            node_id=about.node_id, service_key=about.service_key, service_name=name
        )
        return context, "关于：" + json.dumps(details, ensure_ascii=False, separators=(",", ":"))

    def current_target(service_id: ServiceId) -> ServiceCheckTarget:
        items = overview.view_for_programs().services.items if overview is not None else ()
        selected = next((item for item in items if item.service_id == service_id), None)
        if (
            selected is None
            or selected.protocol is None
            or selected.port is None
            or selected.freshness not in {OverviewFreshness.LIVE, OverviewFreshness.FRESH}
        ):
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_CONTENT, "程序记录不可核对，请刷新后重试"
            )
        return ServiceCheckTarget(
            service_id=selected.service_id,
            node_id=selected.node_id,
            protocol=selected.protocol,
            port=selected.port,
            application_kind=selected.application.kind
            if selected.application is not None
            else None,
            display_name=(
                selected.application.name
                if selected.application is not None
                else selected.display_name or "所选程序"
            ),
        )

    async def resume_run(value: str, payload: ResumeRunInput | None = None) -> dict[str, object]:
        try:
            identifier = run_id(value)
            saved_target = service.get_resume_target(identifier)
            target = current_target(saved_target.service_id) if saved_target is not None else None
            result = await service.resume_run(
                identifier,
                question=payload.question if payload is not None else None,
                target=target,
            )
            return result.model_dump(mode="json")
        except KeyError as exc:
            raise not_found(exc) from exc
        except ProviderError as exc:
            raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "模型调查当前不可用") from exc
        except ValueError as exc:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_CONTENT, "当前任务不能继续，请核对对象和任务状态"
            ) from exc

    async def begin_run(
        value: str,
        payload: StartRunInput,
        target: ServiceCheckTarget | None = None,
    ) -> dict[str, object]:
        try:
            identifier = thread_id(value)
            context, context_line = await about_context(identifier, payload)
            view = await service.start_run(
                identifier, payload, target, context=context, context_line=context_line
            )
        except KeyError as exc:
            raise not_found(exc) from exc
        except ProviderError as exc:
            raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_CONTENT, "当前工具不能核对所选程序"
            ) from exc
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
    router.add_api_route(
        "/api/ui/threads/{value}", get_program_thread, methods=["GET"], include_in_schema=False
    )
    router.add_api_route("/api/threads/{value}", delete_thread, methods=["DELETE"])
    router.add_api_route("/api/threads/{value}/runs", start_run, methods=["POST"])
    router.add_api_route(
        "/api/ui/threads/{value}/runs", start_program_run, methods=["POST"], include_in_schema=False
    )
    router.add_api_route("/api/runs/{value}", get_run, methods=["GET"])
    router.add_api_route("/api/runs/{value}/cancel", cancel_run, methods=["POST"])
    router.add_api_route(
        "/api/ui/runs/{value}/resume", resume_run, methods=["POST"], include_in_schema=False
    )
    router.add_api_route("/api/runs/{value}/events", events, methods=["GET"])
    router.add_api_route("/chat", chat_page, methods=["GET"], response_class=HTMLResponse)
    router.add_api_route(
        "/legacy/chat",
        chat_page,
        methods=["GET"],
        response_class=HTMLResponse,
    )
    return router
