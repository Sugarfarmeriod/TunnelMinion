"""Overview incident 列表、详情与有界上下文追问。"""

from __future__ import annotations

import json

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field

from tunnelminion.agent.conversation import (
    InMemoryConversationService,
    RunView,
    StartRunInput,
)
from tunnelminion.domain.identifiers import IncidentId, ThreadId
from tunnelminion.incident.contracts import Incident, IncidentEventType
from tunnelminion.incident.investigation import READ_ONLY_INVESTIGATION_TOOLS
from tunnelminion.incident.storage import SQLiteIncidentStore
from tunnelminion.model.contracts import ProviderError
from tunnelminion.web.overview import (
    IncidentOverviewItem,
    IncidentSeverity,
    IncidentsOverview,
    OverviewFreshness,
    OverviewSource,
)

_SEVERITIES = {
    IncidentEventType.SERVICE_ADDED: IncidentSeverity.INFO,
    IncidentEventType.STATE_STALE: IncidentSeverity.WARNING,
    IncidentEventType.LOCAL_ONLY: IncidentSeverity.WARNING,
    IncidentEventType.SERVICE_REMOVED: IncidentSeverity.CRITICAL,
    IncidentEventType.NODE_OFFLINE: IncidentSeverity.CRITICAL,
    IncidentEventType.REMOTE_UNREACHABLE: IncidentSeverity.CRITICAL,
}
_FALLBACK_QUESTIONS = {
    IncidentEventType.SERVICE_ADDED: "这个新增服务来自哪个进程或 Docker 容器？",
    IncidentEventType.SERVICE_REMOVED: "服务消失前后，进程和监听端口发生了什么变化？",
    IncidentEventType.NODE_OFFLINE: "节点离线时 WireGuard 和本机网络状态有什么证据？",
    IncidentEventType.STATE_STALE: "哪些状态已经陈旧，还需要刷新什么只读证据？",
    IncidentEventType.LOCAL_ONLY: "为什么这个服务只能从本机访问？",
    IncidentEventType.REMOTE_UNREACHABLE: "远端不可达发生在监听、隧道还是服务探测哪一层？",
}


class IncidentDetail(BaseModel):
    """详情保留公开调查合同和独立的 conversation 绑定。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    incident: Incident
    suggested_questions: tuple[str, ...] = Field(max_length=3)
    thread_id: ThreadId | None = None


class IncidentFollowUpInput(BaseModel):
    """小型上下文追问不接受调用方自选工具。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    question: str = Field(min_length=1, max_length=2_000)


def incidents_overview(store: SQLiteIncidentStore) -> IncidentsOverview:
    """把同一 incident 存储投影为 Overview section。"""
    incidents = store.list_recent(limit=50)
    return IncidentsOverview(
        source=OverviewSource.LOCAL_OBSERVATION,
        evidence_at=max((item.last_observed_at for item in incidents), default=None),
        freshness=(OverviewFreshness.LIVE if incidents else OverviewFreshness.NOT_APPLICABLE),
        items=tuple(
            IncidentOverviewItem(
                incident_id=item.incident_id,
                event_type=item.event.event_type,
                object_kind=item.event.object_kind,
                object_id=item.event.object_id,
                severity=_SEVERITIES[item.event.event_type],
                status=item.status,
                first_observed_at=item.created_at,
                last_observed_at=item.last_observed_at,
                conclusion=item.report.conclusion if item.report is not None else None,
            )
            for item in incidents
        ),
    )


def suggested_questions(incident: Incident) -> tuple[str, ...]:
    """优先追问证据缺口；无报告时使用固定事件模板。"""
    values = [
        f"关于“{item}”，还缺少什么只读证据？"
        for item in (incident.report.unknowns if incident.report is not None else ())[:2]
    ]
    values.append(_FALLBACK_QUESTIONS[incident.event.event_type])
    return tuple(dict.fromkeys(values))[:3]


def create_incident_router(
    store: SQLiteIncidentStore,
    conversations: InMemoryConversationService,
) -> APIRouter:
    """创建本机只读详情与显式追问路由。"""
    router = APIRouter()

    def get_incident(value: str) -> Incident:
        try:
            incident_id = IncidentId(value)
        except ValueError as exc:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Incident 不存在") from exc
        incident = store.get(incident_id)
        if incident is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Incident 不存在")
        return incident

    def detail(value: str) -> IncidentDetail:
        incident = get_incident(value)
        return IncidentDetail(
            incident=incident,
            suggested_questions=suggested_questions(incident),
            thread_id=store.thread_for(incident.incident_id),
        )

    async def follow_up(value: str, payload: IncidentFollowUpInput) -> RunView:
        incident = get_incident(value)
        thread_id = store.thread_for(incident.incident_id)
        if thread_id is None:
            thread_id = conversations.create_thread().thread_id
            store.bind_thread(incident.incident_id, thread_id)
        context = json.dumps(
            {
                "event": incident.event.model_dump(mode="json"),
                "hypotheses": [item.model_dump(mode="json") for item in incident.hypotheses],
                "report": (
                    incident.report.model_dump(mode="json") if incident.report is not None else None
                ),
            },
            ensure_ascii=False,
            separators=(",", ":"),
        )
        try:
            return await conversations.start_incident_run(
                thread_id,
                StartRunInput(
                    question=payload.question,
                    tool_names=READ_ONLY_INVESTIGATION_TOOLS,
                ),
                context[:12_000],
            )
        except ProviderError as exc:
            raise HTTPException(
                status.HTTP_503_SERVICE_UNAVAILABLE,
                "模型调查当前不可用",
            ) from exc

    router.add_api_route(
        "/api/incidents/{value}",
        detail,
        methods=["GET"],
        response_model=IncidentDetail,
    )
    router.add_api_route(
        "/api/incidents/{value}/follow-up",
        follow_up,
        methods=["POST"],
        response_model=RunView,
    )
    return router
