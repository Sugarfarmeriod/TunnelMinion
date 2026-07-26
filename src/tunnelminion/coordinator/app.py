"""Coordinator 独立 Agent API 与环回管理员 API 的应用边界。"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator

from tunnelminion.coordinator.contracts import (
    AccessAssertionRequest,
    AccessAssertionResponse,
    AuthenticatedCapabilitySnapshot,
    AuthenticatedDirectoryQuery,
    AuthenticatedHeartbeat,
    AuthenticatedServiceSnapshot,
    DirectoryPage,
    EnrollmentTokenCreated,
    EnrollmentTokenRequest,
    HeartbeatResponse,
    NodeRegistrationRequest,
    NodeRegistrationResponse,
    NodeRevocationRequest,
    RefreshAuthentication,
    RegisteredNodeView,
    SnapshotReceipt,
    VerificationKeySet,
)
from tunnelminion.coordinator.directory import CoordinatorDirectoryService
from tunnelminion.coordinator.identity import AssertionService
from tunnelminion.coordinator.network_control import (
    AddressPoolRequest,
    AddressPoolView,
    ManagedNetworkControlService,
    ManagedNetworkRequest,
    RelayRoleRequest,
    RelayRoleView,
)
from tunnelminion.coordinator.registry import CoordinatorRegistryService, RegistryError
from tunnelminion.domain.identifiers import NetworkId, NodeId

_ADMIN_PAGE = """<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><title>TunnelMinion Coordinator</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>body{font-family:system-ui;max-width:1100px;margin:2rem auto;padding:0 1rem}
label,button,input{font:inherit} input{padding:.45rem} button{margin:.25rem;padding:.45rem .7rem}
section{border:1px solid #ccc;border-radius:8px;padding:1rem;margin:1rem 0}
table{border-collapse:collapse;width:100%}
th,td{padding:.5rem;border-bottom:1px solid #ddd;text-align:left}
.error{color:#a00}.muted{color:#555}</style></head>
<body><h1>Coordinator 本机管理</h1>
<p class="muted">页面仅允许环回访问；凭据不会写入页面或日志。</p>
<label>Network ID <input id="network" autocomplete="off"></label>
<button id="refresh" type="button">刷新节点</button>
<button id="enroll" type="button">创建并复制一次性 token</button>
<p id="status" role="status" aria-live="polite"></p>
<section><h2>节点</h2><table><thead><tr><th>名称</th><th>平台</th><th>状态</th>
<th>最后心跳</th><th>协议</th><th>操作</th></tr></thead><tbody id="nodes"></tbody></table></section>
<script>
const network=document.getElementById('network'),statusBox=document.getElementById('status');
const nodes=document.getElementById('nodes');
function say(text,error=false){statusBox.textContent=text;statusBox.className=error?'error':'';}
async function jsonRequest(path,options){const response=await fetch(path,options);
const data=await response.json();
if(!response.ok)throw new Error(data.detail?.message||'请求失败');return data;}
async function refreshNodes(){nodes.replaceChildren();
const id=encodeURIComponent(network.value.trim());
if(!id){say('请填写 Network ID',true);return;}
try{const data=await jsonRequest('/api/v1/admin/networks/'+id+'/nodes');
for(const item of data){const row=document.createElement('tr');
for(const value of [item.identity.display_name,item.identity.platform,item.status,
item.last_received_at||'从未',item.identity.protocol.major+'.'+item.identity.protocol.minor]){
const cell=document.createElement('td');cell.textContent=String(value);row.appendChild(cell);}
const actions=document.createElement('td');const revoke=document.createElement('button');
revoke.type='button';revoke.textContent='撤销';revoke.onclick=()=>revokeNode(item.identity.node_id);
actions.appendChild(revoke);row.appendChild(actions);nodes.appendChild(row);}say('节点状态已刷新');}
catch(error){say(error.message,true);}}
async function createEnrollment(){const id=network.value.trim();
if(!id){say('请填写 Network ID',true);return;}
try{const data=await jsonRequest('/api/v1/admin/enrollments',
{method:'POST',headers:{'Content-Type':'application/json'},
body:JSON.stringify({network_id:id,expires_in_seconds:600,max_uses:1})});
await navigator.clipboard.writeText(data.token);say('一次性 token 已复制；页面不会显示或保存它。');}
catch(error){say(error.message,true);}}
async function revokeNode(nodeId){const id=encodeURIComponent(network.value.trim());
try{await jsonRequest('/api/v1/admin/networks/'+id+'/nodes/'+encodeURIComponent(nodeId)+'/revoke',
{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({reason:'local-admin'})});
await refreshNodes();}catch(error){say(error.message,true);}}
document.getElementById('refresh').onclick=refreshNodes;
document.getElementById('enroll').onclick=createEnrollment;
</script></body></html>"""


class CoordinatorAgentBindConfig(BaseModel):
    """必须显式指定的 WireGuard 私网 Agent API 监听配置。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    host: str
    port: int = Field(ge=1024, le=65535)

    @field_validator("host")
    @classmethod
    def validate_wireguard_host(cls, value: str) -> str:
        address = ipaddress.ip_address(value)
        if (
            not address.is_private
            or address.is_loopback
            or address.is_unspecified
            or address.is_multicast
        ):
            raise ValueError("Coordinator Agent API 只能绑定明确的 WireGuard 私网地址")
        return value


class CoordinatorAdminBindConfig(BaseModel):
    """默认且只允许环回地址的管理员 API 监听配置。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    host: str = "127.0.0.1"
    port: int = Field(default=8791, ge=1024, le=65535)

    @field_validator("host")
    @classmethod
    def validate_loopback_host(cls, value: str) -> str:
        if not ipaddress.ip_address(value).is_loopback:
            raise ValueError("Coordinator 管理员 API 只能绑定环回地址")
        return value


class CoordinatorApplicationConfig(BaseModel):
    """不含秘密的 Coordinator 双应用配置。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    data_path: Path
    agent_bind: CoordinatorAgentBindConfig
    admin_bind: CoordinatorAdminBindConfig = Field(default_factory=CoordinatorAdminBindConfig)


@dataclass(frozen=True)
class CoordinatorApplications:
    """由部署层分别启动的两个 FastAPI 应用。"""

    agent_app: FastAPI
    admin_app: FastAPI
    config: CoordinatorApplicationConfig


def build_coordinator_applications(
    config: CoordinatorApplicationConfig,
    *,
    registry: CoordinatorRegistryService | None = None,
    assertions: AssertionService | None = None,
    directory: CoordinatorDirectoryService | None = None,
    network_control: ManagedNetworkControlService | None = None,
) -> CoordinatorApplications:
    """建立隔离应用工厂；本函数不启动监听器。"""
    agent_app = FastAPI(
        title="TunnelMinion Coordinator Agent API",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    admin_app = FastAPI(
        title="TunnelMinion Coordinator Admin API",
        docs_url="/api/docs",
        redoc_url=None,
    )

    async def agent_health() -> dict[str, str]:
        return {"status": "available", "boundary": "agent"}

    async def admin_health() -> dict[str, str]:
        return {"status": "available", "boundary": "admin"}

    agent_app.add_api_route("/api/v1/agent/health", agent_health, methods=["GET"])
    admin_app.add_api_route("/api/v1/admin/health", admin_health, methods=["GET"])

    def admin_page() -> HTMLResponse:
        return HTMLResponse(
            _ADMIN_PAGE,
            headers={
                "Content-Security-Policy": (
                    "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; "
                    "connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
                ),
                "Cache-Control": "no-store",
                "X-Content-Type-Options": "nosniff",
            },
        )

    admin_app.add_api_route("/", admin_page, methods=["GET"], response_class=HTMLResponse)

    if registry is not None:

        async def create_enrollment(
            payload: EnrollmentTokenRequest,
        ) -> EnrollmentTokenCreated:
            try:
                return registry.create_enrollment_token(payload)
            except RegistryError as exc:
                raise _http_error(exc) from exc

        async def register_node(
            payload: NodeRegistrationRequest,
        ) -> NodeRegistrationResponse:
            try:
                return registry.register(payload)
            except RegistryError as exc:
                raise _http_error(exc) from exc

        async def rotate_own_refresh(
            payload: RefreshAuthentication,
        ) -> NodeRegistrationResponse:
            try:
                return registry.rotate_refresh(payload)
            except RegistryError as exc:
                raise _http_error(exc) from exc

        async def heartbeat(payload: AuthenticatedHeartbeat) -> HeartbeatResponse:
            try:
                return registry.heartbeat(payload.authentication, payload.heartbeat)
            except RegistryError as exc:
                raise _http_error(exc) from exc

        async def list_nodes(network_id: str) -> tuple[RegisteredNodeView, ...]:
            return registry.list_nodes(NetworkId(network_id))

        async def rotate_refresh(
            network_id: str,
            node_id: str,
        ) -> NodeRegistrationResponse:
            try:
                return registry.admin_rotate_refresh(
                    NetworkId(network_id),
                    NodeId(node_id),
                )
            except RegistryError as exc:
                raise _http_error(exc) from exc

        async def revoke_node(
            network_id: str,
            node_id: str,
            payload: NodeRevocationRequest,
        ) -> dict[str, str]:
            try:
                registry.revoke_node(
                    NetworkId(network_id),
                    NodeId(node_id),
                    reason=payload.reason,
                )
            except RegistryError as exc:
                raise _http_error(exc) from exc
            return {"status": "revoked"}

        async def restore_node(
            network_id: str,
            node_id: str,
        ) -> NodeRegistrationResponse:
            try:
                return registry.restore_node(NetworkId(network_id), NodeId(node_id))
            except RegistryError as exc:
                raise _http_error(exc) from exc

        agent_app.add_api_route(
            "/api/v1/agent/heartbeat",
            heartbeat,
            methods=["POST"],
            response_model=HeartbeatResponse,
        )
        agent_app.add_api_route(
            "/api/v1/agent/registrations",
            register_node,
            methods=["POST"],
            response_model=NodeRegistrationResponse,
        )
        agent_app.add_api_route(
            "/api/v1/agent/refresh/rotate",
            rotate_own_refresh,
            methods=["POST"],
            response_model=NodeRegistrationResponse,
        )
        admin_app.add_api_route(
            "/api/v1/admin/enrollments",
            create_enrollment,
            methods=["POST"],
            response_model=EnrollmentTokenCreated,
        )
        admin_app.add_api_route(
            "/api/v1/admin/networks/{network_id}/nodes",
            list_nodes,
            methods=["GET"],
        )
        admin_app.add_api_route(
            "/api/v1/admin/networks/{network_id}/nodes/{node_id}/rotate-refresh",
            rotate_refresh,
            methods=["POST"],
            response_model=NodeRegistrationResponse,
        )
        admin_app.add_api_route(
            "/api/v1/admin/networks/{network_id}/nodes/{node_id}/revoke",
            revoke_node,
            methods=["POST"],
        )
        admin_app.add_api_route(
            "/api/v1/admin/networks/{network_id}/nodes/{node_id}/restore",
            restore_node,
            methods=["POST"],
            response_model=NodeRegistrationResponse,
        )

    if assertions is not None:

        async def issue_assertion(
            payload: AccessAssertionRequest,
        ) -> AccessAssertionResponse:
            try:
                return assertions.issue(payload)
            except RegistryError as exc:
                raise _http_error(exc) from exc

        async def verification_keys() -> VerificationKeySet:
            return assertions.verification_keys()

        agent_app.add_api_route(
            "/api/v1/agent/assertions",
            issue_assertion,
            methods=["POST"],
            response_model=AccessAssertionResponse,
        )
        agent_app.add_api_route(
            "/api/v1/agent/verification-keys",
            verification_keys,
            methods=["GET"],
            response_model=VerificationKeySet,
        )

    if directory is not None:

        async def replace_capabilities(
            payload: AuthenticatedCapabilitySnapshot,
        ) -> SnapshotReceipt:
            try:
                return directory.replace_capabilities(
                    payload.authentication,
                    payload.snapshot,
                )
            except RegistryError as exc:
                raise _http_error(exc) from exc

        async def replace_services(
            payload: AuthenticatedServiceSnapshot,
        ) -> SnapshotReceipt:
            try:
                return directory.replace_services(
                    payload.authentication,
                    payload.snapshot,
                )
            except RegistryError as exc:
                raise _http_error(exc) from exc

        async def query_directory(payload: AuthenticatedDirectoryQuery) -> DirectoryPage:
            try:
                return directory.query(payload.authentication, payload.query)
            except RegistryError as exc:
                raise _http_error(exc) from exc

        agent_app.add_api_route(
            "/api/v1/agent/snapshots/capabilities",
            replace_capabilities,
            methods=["PUT"],
            response_model=SnapshotReceipt,
        )
        agent_app.add_api_route(
            "/api/v1/agent/snapshots/services",
            replace_services,
            methods=["PUT"],
            response_model=SnapshotReceipt,
        )
        agent_app.add_api_route(
            "/api/v1/agent/directory/query",
            query_directory,
            methods=["POST"],
            response_model=DirectoryPage,
        )

    if network_control is not None:

        async def create_managed_network(
            payload: ManagedNetworkRequest,
        ) -> ManagedNetworkRequest:
            try:
                network_control.create_network(payload.network_id)
            except RegistryError as exc:
                raise _http_error(exc) from exc
            return payload

        async def configure_address_pool(
            network_id: str,
            payload: AddressPoolRequest,
        ) -> AddressPoolView:
            try:
                return network_control.configure_address_pool(NetworkId(network_id), payload)
            except RegistryError as exc:
                raise _http_error(exc) from exc

        async def list_address_pools(network_id: str) -> tuple[AddressPoolView, ...]:
            try:
                return network_control.list_address_pools(NetworkId(network_id))
            except RegistryError as exc:
                raise _http_error(exc) from exc

        async def set_relay_role(
            network_id: str,
            node_id: str,
            payload: RelayRoleRequest,
        ) -> RelayRoleView:
            try:
                return network_control.set_relay_role(
                    NetworkId(network_id),
                    NodeId(node_id),
                    payload,
                )
            except RegistryError as exc:
                raise _http_error(exc) from exc

        admin_app.add_api_route(
            "/api/v1/admin/networks",
            create_managed_network,
            methods=["POST"],
            response_model=ManagedNetworkRequest,
        )
        admin_app.add_api_route(
            "/api/v1/admin/networks/{network_id}/address-pools",
            configure_address_pool,
            methods=["POST"],
            response_model=AddressPoolView,
        )
        admin_app.add_api_route(
            "/api/v1/admin/networks/{network_id}/address-pools",
            list_address_pools,
            methods=["GET"],
            response_model=tuple[AddressPoolView, ...],
        )
        admin_app.add_api_route(
            "/api/v1/admin/networks/{network_id}/nodes/{node_id}/relay-role",
            set_relay_role,
            methods=["PUT"],
            response_model=RelayRoleView,
        )
    return CoordinatorApplications(agent_app, admin_app, config)


def _http_error(error: RegistryError) -> HTTPException:
    status_by_code = {
        "unauthenticated": 401,
        "forbidden": 403,
        "conflict": 409,
        "version_incompatible": 426,
        "rate_limited": 429,
        "snapshot_too_large": 413,
    }
    status_code = status_by_code.get(error.code.value, 400)
    return HTTPException(
        status_code=status_code,
        detail={"code": error.code.value, "message": str(error)},
    )
