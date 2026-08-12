"""目标节点本地操作授权与生命周期控制页面。"""

# ruff: noqa: E501

from __future__ import annotations

import re
from collections.abc import Callable
from datetime import UTC, datetime
from enum import StrEnum
from typing import Protocol

from fastapi import APIRouter, HTTPException, status
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, ConfigDict, Field, model_validator

from tunnelminion.domain.identifiers import AuthorizationId, NodeId, OperationId, ResourceId
from tunnelminion.operation.contracts import (
    CleanupRecord,
    CleanupResult,
    OperationRecord,
    OperationStatus,
    OperationStore,
    OperationSummary,
    Preauthorization,
    PreauthorizationStore,
    ResourceOwnership,
    VerificationRecord,
    VerificationResult,
)
from tunnelminion.operation.policy import AuthorizationService

_SENSITIVE_TEXT = re.compile(
    r"(?i)authorization\s*[:=]\s*(?:bearer\s+)?\S+"
    r"|x-tunnelminion-share-token\s*[:=]\s*\S+"
    r"|bearer\s+\S+"
    r"|tmn_(?:share|gateway)_[A-Za-z0-9_-]+"
)


def _safe_text(value: str) -> str:
    """过滤可能混入远端说明字段的常见认证材料。"""
    return _SENSITIVE_TEXT.sub("[REDACTED]", value)


class OperationLifecycle(Protocol):
    """由实际持有临时资源的进程实现的生命周期动作。"""

    async def revoke(self, operation_id: OperationId, *, at: datetime) -> OperationRecord: ...


class OperationAction(StrEnum):
    """详情页可按当前服务端事实提交的状态变更动作。"""

    APPROVE = "approve"
    REJECT = "reject"
    CANCEL = "cancel"
    REVOKE = "revoke"


class OwnedResourceView(BaseModel):
    """可向本机用户展示的自有资源；省略进程号和所有权指纹。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    resource_id: ResourceId
    kind: str
    bind_host: str
    bind_port: int
    created_at: datetime

    @classmethod
    def from_record(cls, resource: ResourceOwnership) -> OwnedResourceView:
        return cls(
            resource_id=resource.resource_id,
            kind=_safe_text(resource.kind),
            bind_host=_safe_text(resource.bind_host),
            bind_port=resource.bind_port,
            created_at=resource.created_at,
        )


class VerificationSummaryView(BaseModel):
    """请求节点沿真实路径产生的脱敏验证摘要。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    verifier_node_id: NodeId
    result: VerificationResult
    status_code: int | None
    evidence_summary: str
    verified_at: datetime

    @classmethod
    def from_record(cls, verification: VerificationRecord) -> VerificationSummaryView:
        return cls(
            verifier_node_id=verification.verifier_node_id,
            result=verification.result,
            status_code=verification.status_code,
            evidence_summary=_safe_text(verification.evidence_summary),
            verified_at=verification.verified_at,
        )


class CleanupRecordView(BaseModel):
    """资源清理结果；人工动作由详情顶层单独表达。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    result: CleanupResult
    reason: str
    completed_at: datetime

    @classmethod
    def from_record(cls, cleanup: CleanupRecord) -> CleanupRecordView:
        return cls(
            result=cleanup.result,
            reason=_safe_text(cleanup.reason),
            completed_at=cleanup.completed_at,
        )


_BASE_ALLOWED_ACTIONS: dict[OperationStatus, tuple[OperationAction, ...]] = {
    OperationStatus.PLANNED: (OperationAction.CANCEL,),
    OperationStatus.AWAITING_AUTHORIZATION: (
        OperationAction.APPROVE,
        OperationAction.REJECT,
        OperationAction.CANCEL,
    ),
    OperationStatus.AUTHORIZED: (OperationAction.CANCEL,),
}


def _allowed_actions(
    state: OperationStatus,
    *,
    revoke_available: bool,
) -> tuple[OperationAction, ...]:
    """按当前状态和实际装配能力返回动作提示；最终裁决仍在写端点。"""
    if state is OperationStatus.SUCCEEDED and revoke_available:
        return (OperationAction.REVOKE,)
    return _BASE_ALLOWED_ACTIONS.get(state, ())


def _safe_summary(record: OperationRecord) -> OperationSummary:
    """在详情边界再次过滤摘要中的自由文本。"""
    summary = OperationSummary.from_record(record)
    authorization_basis = (
        _safe_text(summary.authorization_basis) if summary.authorization_basis is not None else None
    )
    error = (
        summary.error.model_copy(update={"message": _safe_text(summary.error.message)})
        if summary.error is not None
        else None
    )
    return summary.model_copy(update={"authorization_basis": authorization_basis, "error": error})


class OperationDetailView(BaseModel):
    """本地页面需要的完整计划视图，不包含访问凭据和远端正文。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    summary: OperationSummary
    state: OperationStatus
    allowed_actions: tuple[OperationAction, ...]
    service_id: str
    service_endpoint: str
    service_process_or_container: str
    service_fingerprint: str
    expected_change: str
    risk_summary: str
    verification_method: str
    rollback_method: str
    duration_seconds: int
    created_at: datetime
    owned_resources: tuple[OwnedResourceView, ...]
    verification_summaries: tuple[VerificationSummaryView, ...]
    cleanup_record: CleanupRecordView | None
    manual_action: str | None
    transitions: tuple[dict[str, str], ...]

    @classmethod
    def from_record(
        cls,
        record: OperationRecord,
        *,
        revoke_available: bool = False,
    ) -> OperationDetailView:
        plan = record.plan
        return cls(
            summary=_safe_summary(record),
            state=record.status,
            allowed_actions=_allowed_actions(
                record.status,
                revoke_available=revoke_available,
            ),
            service_id=_safe_text(plan.service.service_id),
            service_endpoint=f"{plan.service.scheme}://{plan.service.host}:{plan.service.port}",
            service_process_or_container=_safe_text(plan.service.process_or_container),
            service_fingerprint=plan.service.fingerprint,
            expected_change=_safe_text(plan.expected_change),
            risk_summary=_safe_text(plan.risk_summary),
            verification_method=_safe_text(plan.verification_method),
            rollback_method=_safe_text(plan.rollback_method),
            duration_seconds=plan.access_scope.duration_seconds,
            created_at=plan.created_at,
            owned_resources=tuple(OwnedResourceView.from_record(item) for item in record.resources),
            verification_summaries=tuple(
                VerificationSummaryView.from_record(item) for item in record.verifications
            ),
            cleanup_record=(
                CleanupRecordView.from_record(record.cleanup)
                if record.cleanup is not None
                else None
            ),
            manual_action=(
                _safe_text(record.cleanup.manual_action)
                if record.cleanup is not None and record.cleanup.manual_action is not None
                else None
            ),
            transitions=tuple(
                {
                    "from_status": (
                        item.from_status.value if item.from_status is not None else "none"
                    ),
                    "to_status": item.to_status.value,
                    "reason": _safe_text(item.reason),
                    "occurred_at": item.occurred_at.isoformat(),
                }
                for item in record.transitions
            ),
        )


class ApproveInput(BaseModel):
    """逐次批准所需的本地操作者和绝对过期时间。"""

    model_config = ConfigDict(extra="forbid")

    operator: str = Field(min_length=1, max_length=256)
    expires_at: datetime


class DecisionInput(BaseModel):
    """拒绝或取消时记录的本地理由。"""

    model_config = ConfigDict(extra="forbid")

    operator: str = Field(default="target-local-user", min_length=1, max_length=256)
    reason: str = Field(min_length=1, max_length=2_000)


class PreauthorizationInput(BaseModel):
    """要求逐项确认全部授权维度的本地预授权输入。"""

    model_config = ConfigDict(extra="forbid")

    request_peer_id: NodeId
    tool_name: str = Field(min_length=1, max_length=128)
    service_ids: frozenset[str] = Field(min_length=1)
    service_fingerprints: frozenset[str] = Field(min_length=1)
    minimum_port: int = Field(ge=1024, le=65535)
    maximum_port: int = Field(ge=1024, le=65535)
    maximum_duration_seconds: int = Field(ge=1, le=86_400)
    valid_from: datetime
    valid_until: datetime
    created_by: str = Field(min_length=1, max_length=256)
    confirm_peer: bool
    confirm_tool: bool
    confirm_service: bool
    confirm_port: bool
    confirm_duration: bool
    confirm_validity: bool

    @model_validator(mode="after")
    def require_individual_confirmations(self) -> PreauthorizationInput:
        confirmations = (
            self.confirm_peer,
            self.confirm_tool,
            self.confirm_service,
            self.confirm_port,
            self.confirm_duration,
            self.confirm_validity,
        )
        if not all(confirmations):
            raise ValueError("必须分别确认 peer、工具、服务、端口、持续时间和有效期")
        return self


class OperationControlService:
    """仅供环回本地页面调用的确定性授权控制面。"""

    def __init__(
        self,
        *,
        node_id: NodeId,
        operations: OperationStore,
        preauthorizations: PreauthorizationStore,
        authorization: AuthorizationService,
        lifecycle: OperationLifecycle | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.node_id = node_id
        self.operations = operations
        self.preauthorizations = preauthorizations
        self.authorization = authorization
        self.lifecycle = lifecycle
        self.clock = clock or (lambda: datetime.now(UTC))

    def list_operations(self) -> tuple[OperationSummary, ...]:
        return self.operations.list_summaries()

    def get_operation(self, operation_id: OperationId) -> OperationDetailView:
        record = self.operations.get(operation_id)
        if record is None:
            raise KeyError("operation_not_found")
        return OperationDetailView.from_record(
            record,
            revoke_available=self.lifecycle is not None,
        )

    def approve(self, operation_id: OperationId, payload: ApproveInput) -> OperationSummary:
        now = self.clock()
        if payload.expires_at <= now:
            raise ValueError("批准过期时间必须晚于当前时间")
        current = self.operations.get(operation_id)
        if (
            current is not None
            and current.status is OperationStatus.AUTHORIZED
            and current.authorization is not None
        ):
            return OperationSummary.from_record(current)
        record = self.authorization.approve_once(
            operation_id,
            operator=payload.operator,
            decided_at=now,
            expires_at=payload.expires_at,
            local_control=True,
        )
        return OperationSummary.from_record(record)

    def reject(self, operation_id: OperationId, payload: DecisionInput) -> OperationSummary:
        record = self.authorization.reject_once(
            operation_id,
            operator=payload.operator,
            reason=payload.reason,
            decided_at=self.clock(),
            local_control=True,
        )
        return OperationSummary.from_record(record)

    def cancel(self, operation_id: OperationId, payload: DecisionInput) -> OperationSummary:
        record = self.authorization.cancel(
            operation_id,
            reason=payload.reason,
            cancelled_at=self.clock(),
            local_control=True,
        )
        return OperationSummary.from_record(record)

    async def revoke(self, operation_id: OperationId) -> OperationSummary:
        if self.lifecycle is None:
            raise RuntimeError("持有临时资源的生命周期执行器当前不可用")
        record = await self.lifecycle.revoke(operation_id, at=self.clock())
        return OperationSummary.from_record(record)

    def create_preauthorization(self, payload: PreauthorizationInput) -> Preauthorization:
        authorization = Preauthorization(
            authorization_id=AuthorizationId.new(),
            target_node_id=self.node_id,
            request_peer_id=payload.request_peer_id,
            tool_name=payload.tool_name,
            service_ids=payload.service_ids,
            service_fingerprints=payload.service_fingerprints,
            minimum_port=payload.minimum_port,
            maximum_port=payload.maximum_port,
            maximum_duration_seconds=payload.maximum_duration_seconds,
            created_by=payload.created_by,
            valid_from=payload.valid_from,
            valid_until=payload.valid_until,
        )
        return self.authorization.create_preauthorization(
            authorization,
            local_control=True,
        )

    def revoke_preauthorization(self, authorization_id: AuthorizationId) -> Preauthorization:
        current = self.preauthorizations.get(authorization_id)
        if current is None:
            raise KeyError("preauthorization_not_found")
        if current.revoked_at is not None:
            return current
        return self.authorization.revoke_preauthorization(
            authorization_id,
            revoked_at=self.clock(),
            local_control=True,
        )


_OPERATIONS_PAGE = """<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><title>TunnelMinion 操作</title>
<style>
body{font-family:system-ui;max-width:1180px;margin:2rem auto;padding:0 1rem;color:#17202a}
header,.row{display:flex;gap:.75rem;align-items:center;flex-wrap:wrap}
.notice{background:#fff4d6;border:1px solid #e3b341;padding:.8rem;border-radius:8px}
.card{border:1px solid #d0d7de;border-radius:10px;padding:1rem;margin:1rem 0}
.grid{display:grid;grid-template-columns:minmax(9rem,13rem) 1fr;gap:.4rem 1rem}
.label{font-weight:650}.state{font-weight:700}.danger{color:#b42318}
button,input,textarea{font:inherit}button{padding:.35rem .7rem}
pre{white-space:pre-wrap;overflow-wrap:anywhere}
</style></head><body>
<header><h1>操作与授权</h1><button id="refresh">刷新</button></header>
<p class="notice">最终授权权属于当前目标节点的本地用户。模型、请求节点和聊天文本都不能代替你批准。</p>
<section><h2>操作</h2><div id="operations"></div></section>
<section><h2>预授权</h2>
<p>创建预授权必须分别确认 peer、工具、服务、端口、持续时间和有效期。</p>
<form id="grant-form" class="card">
<div class="grid">
<label>请求 peer</label><input name="request_peer_id" required>
<label>工具</label><input name="tool_name" value="share_local_http_service" required>
<label>服务 ID</label><input name="service_id" required>
<label>服务指纹</label><input name="service_fingerprint" required>
<label>最小端口</label><input name="minimum_port" type="number" min="1024" max="65535" required>
<label>最大端口</label><input name="maximum_port" type="number" min="1024" max="65535" required>
<label>最长持续秒数</label><input name="maximum_duration_seconds" type="number" min="1" max="86400" required>
<label>生效时间</label><input name="valid_from" type="datetime-local" required>
<label>失效时间</label><input name="valid_until" type="datetime-local" required>
</div>
<div>
<label><input name="confirm_peer" type="checkbox">我确认 peer</label>
<label><input name="confirm_tool" type="checkbox">我确认工具</label>
<label><input name="confirm_service" type="checkbox">我确认服务与指纹</label>
<label><input name="confirm_port" type="checkbox">我确认端口范围</label>
<label><input name="confirm_duration" type="checkbox">我确认最长持续时间</label>
<label><input name="confirm_validity" type="checkbox">我确认授权有效期</label>
</div>
<button type="submit">创建预授权</button>
</form>
<div id="preauthorizations"></div></section>
<script>
const api=async(path,options={})=>{const method=(options.method||'GET').toUpperCase();const headers=new Headers(options.headers||{});if(!['GET','HEAD','OPTIONS','TRACE'].includes(method))headers.set('X-TunnelMinion-Request','same-origin');const r=await fetch(path,{...options,headers});if(!r.ok)throw new Error(await r.text());return r.status===204?null:r.json()};
const text=(tag,value,cls)=>{const e=document.createElement(tag);if(cls)e.className=cls;e.textContent=String(value??'—');return e};
const stateText={executing:'正在创建入口，尚未成功',verifying:'入口已创建，正在等待请求节点验证',succeeded:'请求节点验证通过',rolling_back:'正在回滚',rolled_back:'已回滚',expiring:'正在到期清理',expired:'已到期并清理',cleanup_failed:'清理失败，需要人工处理'};
const add=(grid,label,value)=>{grid.append(text('div',label,'label'),text('div',value))};
async function decide(id,action,body){await api('/api/operations/'+id+'/'+action,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(body)});await refresh()}
async function showOperation(summary){const d=await api('/api/operations/'+summary.operation_id);const card=text('article','');card.className='card';
card.append(text('h3',d.service_id+' · '+summary.operation_id));const grid=text('div','');grid.className='grid';
add(grid,'状态',stateText[summary.status]||summary.status);add(grid,'目标节点',summary.target_node_id);add(grid,'请求节点',summary.request_node_id);
add(grid,'证据',d.service_endpoint+' · '+d.service_process_or_container+' · '+d.service_fingerprint);add(grid,'等级','L'+summary.level);
add(grid,'风险',d.risk_summary);add(grid,'预期变化',d.expected_change);add(grid,'访问入口',summary.bind_host+':'+summary.bind_port);
add(grid,'持续时间',d.duration_seconds+' 秒');add(grid,'验证',d.verification_method);add(grid,'回滚',d.rollback_method);
if(summary.absolute_expires_at)add(grid,'绝对到期',summary.absolute_expires_at);if(summary.error)add(grid,'错误',summary.error.code+': '+summary.error.message);
card.append(grid);const controls=text('div','');controls.className='row';
if(summary.status==='awaiting_authorization'){const approve=text('button','批准一次');approve.onclick=()=>{const expires=prompt('输入批准绝对过期时间（ISO 8601）');if(expires)decide(summary.operation_id,'approve',{operator:'target-local-user',expires_at:expires})};
const reject=text('button','拒绝');reject.onclick=()=>decide(summary.operation_id,'reject',{operator:'target-local-user',reason:'目标节点本地用户拒绝'});controls.append(approve,reject)}
if(['planned','awaiting_authorization','authorized'].includes(summary.status)){const cancel=text('button','取消');cancel.onclick=()=>decide(summary.operation_id,'cancel',{operator:'target-local-user',reason:'目标节点本地用户取消'});controls.append(cancel)}
if(summary.status==='succeeded'){const revoke=text('button','主动撤销');revoke.onclick=()=>decide(summary.operation_id,'revoke',{});controls.append(revoke)}
card.append(controls);return card}
async function refresh(){const operations=await api('/api/operations');const root=document.getElementById('operations');root.replaceChildren();
for(const item of operations)root.append(await showOperation(item));if(!operations.length)root.append(text('p','当前没有操作记录。'));
const grants=await api('/api/preauthorizations');const grantsRoot=document.getElementById('preauthorizations');grantsRoot.replaceChildren();
for(const grant of grants){const card=text('article','');card.className='card';card.append(text('pre',JSON.stringify(grant,null,2)));if(!grant.revoked_at){const revoke=text('button','撤销预授权');revoke.onclick=async()=>{await api('/api/preauthorizations/'+grant.authorization_id+'/revoke',{method:'POST'});await refresh()};card.append(revoke)}grantsRoot.append(card)}
if(!grants.length)grantsRoot.append(text('p','当前没有预授权。'))}
document.getElementById('refresh').onclick=refresh;refresh();
document.getElementById('grant-form').onsubmit=async event=>{event.preventDefault();const form=new FormData(event.target);
const checked=name=>form.get(name)==='on';const body={request_peer_id:form.get('request_peer_id'),tool_name:form.get('tool_name'),
service_ids:[form.get('service_id')],service_fingerprints:[form.get('service_fingerprint')],
minimum_port:Number(form.get('minimum_port')),maximum_port:Number(form.get('maximum_port')),
maximum_duration_seconds:Number(form.get('maximum_duration_seconds')),valid_from:new Date(form.get('valid_from')).toISOString(),
valid_until:new Date(form.get('valid_until')).toISOString(),created_by:'target-local-user',confirm_peer:checked('confirm_peer'),
confirm_tool:checked('confirm_tool'),confirm_service:checked('confirm_service'),confirm_port:checked('confirm_port'),
confirm_duration:checked('confirm_duration'),confirm_validity:checked('confirm_validity')};
await api('/api/preauthorizations',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(body)});event.target.reset();await refresh()};
</script></body></html>"""


def create_operation_router(service: OperationControlService) -> APIRouter:
    """创建只应由环回绑定应用挂载的操作控制路由。"""
    router = APIRouter()

    def operation_id(value: str) -> OperationId:
        try:
            return OperationId(value)
        except ValueError as exc:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "操作不存在") from exc

    def authorization_id(value: str) -> AuthorizationId:
        try:
            return AuthorizationId(value)
        except ValueError as exc:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "预授权不存在") from exc

    def translate(exc: Exception) -> HTTPException:
        if isinstance(exc, HTTPException):
            return exc
        if isinstance(exc, KeyError):
            return HTTPException(status.HTTP_404_NOT_FOUND, "记录不存在")
        if isinstance(exc, RuntimeError):
            return HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, str(exc))
        return HTTPException(status.HTTP_409_CONFLICT, str(exc))

    def list_operations() -> tuple[OperationSummary, ...]:
        return service.list_operations()

    def get_operation(value: str) -> OperationDetailView:
        try:
            return service.get_operation(operation_id(value))
        except Exception as exc:
            raise translate(exc) from exc

    def approve(value: str, payload: ApproveInput) -> OperationSummary:
        try:
            return service.approve(operation_id(value), payload)
        except Exception as exc:
            raise translate(exc) from exc

    def reject(value: str, payload: DecisionInput) -> OperationSummary:
        try:
            return service.reject(operation_id(value), payload)
        except Exception as exc:
            raise translate(exc) from exc

    def cancel(value: str, payload: DecisionInput) -> OperationSummary:
        try:
            return service.cancel(operation_id(value), payload)
        except Exception as exc:
            raise translate(exc) from exc

    async def revoke(value: str) -> OperationSummary:
        try:
            return await service.revoke(operation_id(value))
        except Exception as exc:
            raise translate(exc) from exc

    def list_preauthorizations() -> tuple[Preauthorization, ...]:
        return service.preauthorizations.list_all()

    def create_preauthorization(payload: PreauthorizationInput) -> Preauthorization:
        try:
            return service.create_preauthorization(payload)
        except Exception as exc:
            raise translate(exc) from exc

    def revoke_preauthorization(value: str) -> Preauthorization:
        try:
            return service.revoke_preauthorization(authorization_id(value))
        except Exception as exc:
            raise translate(exc) from exc

    def page() -> HTMLResponse:
        return HTMLResponse(_OPERATIONS_PAGE)

    router.add_api_route("/api/operations", list_operations, methods=["GET"])
    router.add_api_route("/api/operations/{value}", get_operation, methods=["GET"])
    router.add_api_route("/api/operations/{value}/approve", approve, methods=["POST"])
    router.add_api_route("/api/operations/{value}/reject", reject, methods=["POST"])
    router.add_api_route("/api/operations/{value}/cancel", cancel, methods=["POST"])
    router.add_api_route("/api/operations/{value}/revoke", revoke, methods=["POST"])
    router.add_api_route("/api/preauthorizations", list_preauthorizations, methods=["GET"])
    router.add_api_route("/api/preauthorizations", create_preauthorization, methods=["POST"])
    router.add_api_route(
        "/api/preauthorizations/{value}/revoke",
        revoke_preauthorization,
        methods=["POST"],
    )
    router.add_api_route("/operations", page, methods=["GET"], response_class=HTMLResponse)
    router.add_api_route(
        "/legacy/operations",
        page,
        methods=["GET"],
        response_class=HTMLResponse,
    )
    return router
