"""macOS B 节点只读 Tool Gateway 的真实依赖组装。"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from fastapi import FastAPI
from pydantic import BaseModel, ConfigDict, Field, model_validator
from starlette.types import Lifespan

from tunnelminion.agent.conversation import InMemoryConversationService
from tunnelminion.agent.delegation import DelegationService
from tunnelminion.agent.delegation_tool import register_delegate_tool
from tunnelminion.agent.invites import InviteService
from tunnelminion.agent.langchain_model import TunnelMinionChatModel
from tunnelminion.agent.managed_application import (
    ManagedNodeApplication,
    build_managed_node_application,
    managed_application_lifespan,
    managed_path_status_callback,
    managed_resource_payload_callback,
)
from tunnelminion.agent.managed_coordinator import ServiceSnapshotCache
from tunnelminion.agent.managed_node import ServiceObservationConfig
from tunnelminion.agent.model_lending import ModelLendingService
from tunnelminion.agent.remote import AgentRemoteToolPreparer, ConfiguredRemoteToolPreparer
from tunnelminion.agent.remote_service_presentation import RemoteServicePresentationObserver
from tunnelminion.agent.runtime import LangChainReadOnlyAgent
from tunnelminion.agent.service_observation import DeterministicServiceObserver
from tunnelminion.app import (
    build_requester_operation_service,
    default_data_dir,
    load_or_create_node_id,
)
from tunnelminion.domain.identifiers import NodeId
from tunnelminion.domain.tools import Platform
from tunnelminion.gateway import create_gateway_router
from tunnelminion.gateway.audit import InMemoryGatewaySecurityAuditSink
from tunnelminion.gateway.client import FixedGatewayClient
from tunnelminion.gateway.configuration import (
    FileGatewayConfigurationRepository,
    GatewayConfigurationService,
    gateway_secret_store,
)
from tunnelminion.gateway.operations import TargetOperationGatewayService
from tunnelminion.gateway.security import GatewayBindConfig
from tunnelminion.incident.investigation import ConfiguredIncidentRunner
from tunnelminion.incident.observer import (
    IncidentObservationService,
    incident_observation_lifespan,
)
from tunnelminion.incident.peer_observation import StaticPeerServiceObserver
from tunnelminion.incident.storage import SQLiteIncidentStore
from tunnelminion.incident.tasks import IncidentTaskHarness
from tunnelminion.memory.context import ArtifactContextManager
from tunnelminion.memory.service import LongTermMemoryService, MemoryContextRetriever
from tunnelminion.memory.sqlite import SQLiteStores
from tunnelminion.model.api import create_model_router
from tunnelminion.model.configuration import (
    FileModelConfigurationRepository,
    ModelConfigurationService,
)
from tunnelminion.model.remote import RemoteModelProvider
from tunnelminion.model.secrets import KeyringSecretStore
from tunnelminion.operation.contracts import (
    LeaseRecord,
    OperationPlan,
    VerificationRecord,
    VerificationResult,
)
from tunnelminion.operation.definitions import register_safe_http_sharing_operation
from tunnelminion.operation.evidence import HTTPServiceProbeEvidenceProvider
from tunnelminion.operation.http_sharing import HTTPSharingAdapter, HTTPSharingConfig
from tunnelminion.operation.policy import AuthorizationService, OperationPolicy
from tunnelminion.operation.requester_service import RequesterOperationService
from tunnelminion.operation.workflow import OperationWorkflow, RequesterVerifier
from tunnelminion.platforms.macos.adapters import (
    DockerServicesAdapter,
    MacOSNodeSummaryAdapter,
    MacOSWireGuardStatusAdapter,
    NetworkListenersAdapter,
    ProcessSummaryAdapter,
    ServiceReachabilityAdapter,
)
from tunnelminion.platforms.macos.definitions import MacOSToolAdapters, register_macos_tools
from tunnelminion.platforms.macos.managed_path import build_macos_managed_path_platform
from tunnelminion.platforms.macos.system import (
    MacOSSystemReader,
    SubprocessCommandRunner,
    default_docker_path,
    default_wg_path,
)
from tunnelminion.platforms.windows.system import SystemReader
from tunnelminion.repair.agent_tools import proposed_repairs_for_delegation
from tunnelminion.repair.definitions import register_repair_operations
from tunnelminion.repair.launch_records import LaunchRecorder
from tunnelminion.repair.local import build_node_repair_service
from tunnelminion.repair.service import RepairService
from tunnelminion.telemetry import tracing_lifespan
from tunnelminion.tools.audit import InMemoryAuditSink
from tunnelminion.tools.registry import ToolRegistry
from tunnelminion.tools.runtime import ToolRuntime
from tunnelminion.web.application_views import (
    NetworkPathViewBindings,
    build_application_view_bindings,
)
from tunnelminion.web.conversation import create_conversation_router
from tunnelminion.web.diagnostics import DiagnosticsExportService, create_diagnostics_router
from tunnelminion.web.incidents import create_incident_router, incidents_overview
from tunnelminion.web.memory import create_memory_router
from tunnelminion.web.operations import OperationControlService, create_operation_router
from tunnelminion.web.overview import create_overview_router
from tunnelminion.web.repairs import create_repair_router
from tunnelminion.web.request_guard import install_local_request_guard
from tunnelminion.web.resources import create_resource_router
from tunnelminion.web.service_map import create_service_map_router
from tunnelminion.web.spa import create_spa_router


@dataclass(frozen=True)
class MacOSNode:
    """macOS 本地面板与远端网关共享的只读节点依赖。"""

    root: Path
    node_id: NodeId
    model_service: ModelConfigurationService
    tool_runtime: ToolRuntime
    audit_sink: InMemoryAuditSink
    tool_registry: ToolRegistry
    system_reader: SystemReader
    listeners: NetworkListenersAdapter
    processes: ProcessSummaryAdapter
    docker: DockerServicesAdapter
    artifact_manager: ArtifactContextManager
    stores: SQLiteStores
    repair_service: RepairService


@dataclass(frozen=True)
class MacOSLocalApplication:
    """只应绑定环回地址的 macOS 本地面板。"""

    app: FastAPI
    node: MacOSNode
    conversation_service: InMemoryConversationService
    memory_service: LongTermMemoryService
    operation_control_service: OperationControlService
    requester_operation_service: RequesterOperationService
    managed_node: ManagedNodeApplication
    repair_service: RepairService

    def create_read_only_agent(self) -> LangChainReadOnlyAgent:
        """使用当前 macOS 模型配置创建一次本地 Agent。"""
        return _create_macos_read_only_agent(self.node)


@dataclass(frozen=True)
class MacOSGatewayApplication:
    """只包含跨节点工具端点，不挂载本地聊天、配置或资源页面。"""

    app: FastAPI
    bind: GatewayBindConfig
    node_id: NodeId
    tool_runtime: ToolRuntime
    audit_sink: InMemoryAuditSink
    security_audit_sink: InMemoryGatewaySecurityAuditSink
    tool_registry: ToolRegistry
    gateway_service: GatewayConfigurationService
    operation_service: TargetOperationGatewayService | None = None
    operation_workflow: OperationWorkflow | None = None
    delegation_service: DelegationService | None = None
    model_lending_service: ModelLendingService | None = None


class SafeSharingGatewaySettings(BaseModel):
    """显式启用 L2 HTTP 共享时的目标节点本地边界。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    minimum_port: int = Field(default=18_880, ge=1024, le=65535)
    maximum_port: int = Field(default=18_899, ge=1024, le=65535)
    maximum_duration_seconds: int = Field(default=3600, ge=1, le=86_400)
    expiry_poll_seconds: float = Field(default=1, gt=0, le=60)
    bind_port_override: int | None = Field(default=None, ge=1024, le=65535)

    @model_validator(mode="after")
    def validate_port_range(self) -> SafeSharingGatewaySettings:
        if self.minimum_port > self.maximum_port:
            raise ValueError("共享端口下限不得大于上限")
        return self


class _CallbackRequiredVerifier(RequesterVerifier):
    """没有请求节点回调时保守失败，避免由目标节点替代 A 验证。"""

    async def verify(
        self,
        plan: OperationPlan,
        lease: LeaseRecord,
        access_token: str,
    ) -> VerificationRecord:
        del lease, access_token
        return VerificationRecord(
            operation_id=plan.operation_id,
            verifier_node_id=plan.request_node_id,
            result=VerificationResult.REQUESTER_OFFLINE,
            evidence_summary="请求节点没有提供独立验证回调",
            verified_at=datetime.now(UTC),
        )


def _gateway_lifespan(
    workflow: OperationWorkflow,
    poll_seconds: float,
) -> Lifespan[FastAPI]:
    """创建恢复与绝对到期清理循环，不重放未完成写操作。"""

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
        del app
        await workflow.recover_unfinished(at=datetime.now(UTC))

        async def expire() -> None:
            while True:
                await asyncio.sleep(poll_seconds)
                await workflow.expire_due(at=datetime.now(UTC))

        task = asyncio.create_task(expire())
        try:
            yield
        finally:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)

    return lifespan


def _create_macos_read_only_agent(
    node: MacOSNode, *, remote_tools: AgentRemoteToolPreparer | None = None
) -> LangChainReadOnlyAgent:
    """把 macOS 节点依赖组合成受只读策略约束的 Agent。"""
    model = TunnelMinionChatModel(
        provider=node.model_service.create_provider(), artifact_manager=node.artifact_manager
    )
    return LangChainReadOnlyAgent(
        model, node.tool_registry, node.tool_runtime, Platform.MACOS, remote_tools=remote_tools
    )


def _build_macos_node(
    data_dir: Path | None = None,
    *,
    interface_name: str | None = None,
) -> MacOSNode:
    """组装两种 macOS 入口共用的模型状态与六个只读工具。"""
    root = default_data_dir() if data_dir is None else data_dir
    node_id = load_or_create_node_id(root / "node-id")
    secrets = KeyringSecretStore()
    audit = InMemoryAuditSink()
    gateway = GatewayConfigurationService(
        FileGatewayConfigurationRepository(root / "gateway.json"), gateway_secret_store(root)
    )

    def borrowed_provider(peer_node_id: NodeId) -> RemoteModelProvider:
        peer = gateway.resolve_model_peer(peer_node_id)
        return RemoteModelProvider(
            FixedGatewayClient(peer.endpoint, peer.token, node_id, peer.node_id, audit), node_id
        )

    model_service = ModelConfigurationService(
        FileModelConfigurationRepository(root / "model.json"),
        secrets,
        borrowed_provider_factory=borrowed_provider,
    )
    registry = ToolRegistry()
    runner = SubprocessCommandRunner()
    reader = MacOSSystemReader()
    wireguard = MacOSWireGuardStatusAdapter(
        reader,
        runner,
        default_wg_path(),
        interface_name=interface_name,
    )

    def model_status() -> str:
        return model_service.view().status

    node_summary = MacOSNodeSummaryAdapter(node_id, registry, wireguard, model_status)
    listeners = NetworkListenersAdapter(reader)
    processes = ProcessSummaryAdapter(reader)
    docker = DockerServicesAdapter(runner, default_docker_path())
    register_macos_tools(
        registry,
        MacOSToolAdapters(
            wireguard=wireguard,
            listeners=listeners,
            processes=processes,
            docker=docker,
            reachability=ServiceReachabilityAdapter(),
            node_summary=node_summary,
        ),
    )
    register_safe_http_sharing_operation(registry)
    register_repair_operations(registry)
    stores = SQLiteStores.open(root / "runtime.sqlite3")
    repair_service = build_node_repair_service(
        root=root,
        node_id=node_id,
        stores=stores,
        registry=registry,
        docker_path=default_docker_path(),
        system_reader=reader,
    )
    artifact_manager = ArtifactContextManager(stores.artifacts)
    runtime = ToolRuntime(
        registry,
        Platform.MACOS,
        audit,
        artifact_manager=artifact_manager,
    )
    return MacOSNode(
        root,
        node_id,
        model_service,
        runtime,
        audit,
        registry,
        reader,
        listeners,
        processes,
        docker,
        artifact_manager,
        stores,
        repair_service,
    )


def build_macos_local_application(
    data_dir: Path | None = None,
    *,
    interface_name: str | None = None,
    network_path: NetworkPathViewBindings | None = None,
    read_only_preview: bool = False,
) -> MacOSLocalApplication:
    """组装即使没有模型也能使用资源页的 macOS 本地应用。"""
    node = _build_macos_node(data_dir, interface_name=interface_name)
    register_delegate_tool(
        node.tool_registry,
        Platform.MACOS,
        GatewayConfigurationService(
            FileGatewayConfigurationRepository(node.root / "gateway.json"),
            gateway_secret_store(node.root),
        ),
        node.node_id,
        node.audit_sink,
    )

    stores = node.stores

    def create_agent() -> LangChainReadOnlyAgent:
        return _create_macos_read_only_agent(node, remote_tools=remote_preparer)

    conversations = InMemoryConversationService(
        node.node_id,
        create_agent,
        stores.checkpoints,
        memory_retriever=MemoryContextRetriever(stores.memories),
        read_only_preview=read_only_preview,
    )
    memories = LongTermMemoryService(stores.memories, (conversations,))
    authorization = AuthorizationService(
        stores.operations,
        stores.preauthorizations,
        OperationPolicy(node.tool_registry, stores.preauthorizations),
    )
    incident_store = SQLiteIncidentStore(node.root / "incidents.sqlite3")
    requester_operations = build_requester_operation_service(
        root=node.root,
        node_id=node.node_id,
        platform=Platform.MACOS,
        model_service=node.model_service,
        tool_runtime=node.tool_runtime,
        audit_sink=node.audit_sink,
        stores=stores,
        incident_store=incident_store,
    )
    operation_control = OperationControlService(
        node_id=node.node_id,
        operations=stores.operations,
        preauthorizations=stores.preauthorizations,
        authorization=authorization,
        requester=requester_operations,
    )
    managed = build_managed_node_application(
        node.root,
        node.node_id,
        Platform.MACOS,
        node.tool_registry,
        node.listeners,
        node.processes,
        node.docker,
        managed_path_platform_factory=build_macos_managed_path_platform,
    )
    service_cache = (
        managed.coordinator.service_cache
        if managed.coordinator is not None
        else ServiceSnapshotCache()
    )
    remote_preparer = ConfiguredRemoteToolPreparer(
        GatewayConfigurationService(
            FileGatewayConfigurationRepository(node.root / "gateway.json"),
            gateway_secret_store(node.root),
        ),
        node.node_id,
        Platform.MACOS,
        node.audit_sink,
    )
    peer_observer = StaticPeerServiceObserver.from_file(node.root, node.node_id, remote_preparer)
    if peer_observer is not None and managed.coordinator is not None:
        raise ValueError("静态对端观察不能与目录观察同时启用")
    before_snapshot = None
    remote_observer = None
    if managed.coordinator is not None and not read_only_preview:
        remote_observer = RemoteServicePresentationObserver(
            node.node_id, managed.coordinator.coordinator_cache, remote_preparer
        )
        before_snapshot = remote_observer.refresh
    if managed.coordinator is None or read_only_preview:
        local_observer = DeterministicServiceObserver(
            node.node_id,
            ServiceObservationConfig(),
            node.listeners,
            node.processes,
            node.docker,
            marks=stores.service_marks.all,
            launch_recorder=(
                None if read_only_preview else LaunchRecorder(stores.launch_records).record
            ),
        )

        async def refresh_local_services() -> None:
            service_cache.replace(await local_observer.observe())
            if peer_observer is not None and not read_only_preview:
                await peer_observer.refresh()

        before_snapshot = refresh_local_services

    current_managed_path_status = managed_path_status_callback(managed)
    views = build_application_view_bindings(
        node_id=node.node_id,
        platform=Platform.MACOS,
        model_service=node.model_service,
        managed=managed,
        network_path=network_path,
        managed_path_status=current_managed_path_status,
        incidents=lambda: incidents_overview(incident_store),
        local_services=service_cache.read,
        peer_observation=peer_observer,
        remote_service_presentations=remote_observer.presentations
        if remote_observer is not None
        else None,
    )
    incident_tasks = IncidentTaskHarness(
        conversations,
        incident_store,
        ConfiguredIncidentRunner(
            node.model_service.create_provider,
            node.tool_registry,
            node.tool_runtime,
            incident_store,
            Platform.MACOS,
            local_node_id=node.node_id,
            remote_tools=remote_preparer,
        ),
        create_agent,
        views.overview_service.view,
    )
    incident_observer = IncidentObservationService(
        views.overview_service.view,
        incident_store,
        investigator=incident_tasks,
        before_snapshot=before_snapshot,
        watched_service_id=peer_observer.service.service_id if peer_observer is not None else None,
        read_only_preview=read_only_preview,
    )
    app = FastAPI(
        title="TunnelMinion",
        docs_url="/api/docs",
        lifespan=tracing_lifespan(
            node.root,
            node.node_id,
            Platform.MACOS,
            incident_observation_lifespan(
                managed_application_lifespan(managed),
                incident_observer,
                incident_store,
            ),
        ),
    )
    install_local_request_guard(app, read_only_preview=read_only_preview)
    app.include_router(create_model_router(node.model_service))
    app.include_router(
        create_resource_router(
            node.tool_runtime,
            node.node_id,
            coordinator_status=views.resource_bindings.coordinator_status,
            coordinator_cache=views.resource_bindings.coordinator_cache,
            network_path_status=views.resource_bindings.network_path,
            managed_status=managed_resource_payload_callback(managed),
            managed_path_status=current_managed_path_status,
        )
    )
    app.include_router(create_overview_router(views.overview_service))
    app.include_router(create_incident_router(incident_store, conversations, tasks=incident_tasks))
    app.include_router(create_diagnostics_router(DiagnosticsExportService(views.overview_service)))
    app.include_router(create_conversation_router(conversations, views.overview_service))
    app.include_router(create_memory_router(memories))
    app.include_router(
        create_service_map_router(
            node.node_id, stores.service_marks, service_cache.read, service_cache.replace
        )
    )
    app.include_router(create_operation_router(operation_control))
    repair_service = node.repair_service
    app.include_router(create_repair_router(repair_service))
    app.include_router(create_spa_router(read_only_preview=read_only_preview))
    return MacOSLocalApplication(
        app,
        node,
        conversations,
        memories,
        operation_control,
        requester_operations,
        managed,
        repair_service,
    )


def create_macos_app() -> FastAPI:
    """供 macOS 本地 Uvicorn 工厂使用。"""
    bundle = build_macos_local_application()
    bundle.app.state.managed_node = bundle.managed_node
    return bundle.app


def build_macos_gateway_application(
    data_dir: Path | None = None,
    *,
    interface_name: str | None = None,
    safe_sharing: SafeSharingGatewaySettings | None = None,
) -> MacOSGatewayApplication:
    """组装 macOS 六工具和只绑定 WireGuard 地址的认证网关。"""
    node = _build_macos_node(data_dir, interface_name=interface_name)
    security_audit = InMemoryGatewaySecurityAuditSink()
    gateway_service = GatewayConfigurationService(
        FileGatewayConfigurationRepository(node.root / "gateway.json"),
        gateway_secret_store(node.root),
    )
    view = gateway_service.view()
    if not view.configured or view.bind is None:
        raise RuntimeError("尚未配置 macOS Tool Gateway WireGuard 监听地址")
    security_policy = gateway_service.build_security_policy()
    bind = GatewayBindConfig(
        host=view.bind.host,
        port=(
            safe_sharing.bind_port_override
            if safe_sharing is not None and safe_sharing.bind_port_override is not None
            else view.bind.port
        ),
    )
    operation_service: TargetOperationGatewayService | None = None
    operation_workflow: OperationWorkflow | None = None
    lifespan = None
    stores = node.stores
    delegation_service = DelegationService(
        node.node_id,
        stores.delegations,
        lambda: _create_macos_read_only_agent(node),
        lambda: tuple(item.name for item in node.tool_registry.model_tools(Platform.MACOS)),
        repair_query=lambda delegation_id: proposed_repairs_for_delegation(
            stores.repairs, delegation_id
        ),
    )
    model_lending_service = ModelLendingService(
        node.node_id, node.model_service.create_lending_provider, stores.model_usage
    )
    invite_service = InviteService(
        node.node_id, Platform.MACOS, gateway_service, stores.invites, security_policy
    )
    if safe_sharing is not None:
        operation_peers = tuple(
            peer for peer in view.peers if "share_local_http_service" in peer.allowed_operations
        )
        if not operation_peers:
            raise RuntimeError("没有 peer 被本地配置允许请求临时 HTTP 共享")
        authorization = AuthorizationService(
            stores.operations,
            stores.preauthorizations,
            OperationPolicy(node.tool_registry, stores.preauthorizations),
        )
        operation_workflow = OperationWorkflow(
            stores.operations,
            gateway_secret_store(node.root),
            HTTPServiceProbeEvidenceProvider(
                stores.operations,
                identity_reader=node.system_reader,
            ),
            HTTPSharingAdapter(
                HTTPSharingConfig(
                    wireguard_addresses=frozenset({view.bind.host}),
                    allowed_peer_addresses={
                        str(peer.node_id): frozenset({peer.host}) for peer in operation_peers
                    },
                    minimum_port=safe_sharing.minimum_port,
                    maximum_port=safe_sharing.maximum_port,
                    maximum_duration_seconds=safe_sharing.maximum_duration_seconds,
                )
            ),
            _CallbackRequiredVerifier(),
        )
        operation_service = TargetOperationGatewayService(
            stores.operations,
            authorization,
            operation_workflow,
        )
        lifespan = _gateway_lifespan(
            operation_workflow,
            safe_sharing.expiry_poll_seconds,
        )
    app = FastAPI(
        title="TunnelMinion Tool Gateway",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=tracing_lifespan(node.root, node.node_id, Platform.MACOS, lifespan),
    )
    app.include_router(
        create_gateway_router(
            node.node_id,
            Platform.MACOS,
            node.tool_registry,
            node.tool_runtime,
            security_policy,
            security_audit,
            operation_service,
            delegation_service,
            model_lending_service,
            invite_service=invite_service,
        )
    )
    return MacOSGatewayApplication(
        app=app,
        bind=bind,
        node_id=node.node_id,
        tool_runtime=node.tool_runtime,
        audit_sink=node.audit_sink,
        security_audit_sink=security_audit,
        tool_registry=node.tool_registry,
        gateway_service=gateway_service,
        operation_service=operation_service,
        operation_workflow=operation_workflow,
        delegation_service=delegation_service,
        model_lending_service=model_lending_service,
    )
