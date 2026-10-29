"""Windows MVP 的真实依赖组装与 FastAPI 应用工厂。"""

from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from fastapi import FastAPI

from tunnelminion.agent.conversation import InMemoryConversationService
from tunnelminion.agent.delegation import DelegationService
from tunnelminion.agent.delegation_tool import register_delegate_tool
from tunnelminion.agent.diagnostics import CrossNodeDiagnosticAgent, CrossNodeDiagnosticWorkflow
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
from tunnelminion.agent.remote import ConfiguredRemoteToolPreparer, RemoteCapabilityLoader
from tunnelminion.agent.remote_service_presentation import RemoteServicePresentationObserver
from tunnelminion.agent.request_gate import RequestGate
from tunnelminion.agent.runtime import LangChainReadOnlyAgent
from tunnelminion.agent.service_observation import DeterministicServiceObserver
from tunnelminion.agent.tool_selection import ToolSelectionSettings
from tunnelminion.domain.identifiers import NodeId
from tunnelminion.domain.tools import Platform
from tunnelminion.gateway.api import create_gateway_router
from tunnelminion.gateway.audit import InMemoryGatewaySecurityAuditSink
from tunnelminion.gateway.client import FixedGatewayClient
from tunnelminion.gateway.configuration import (
    FileGatewayConfigurationRepository,
    GatewayConfigurationService,
    GatewayOperationPeer,
    gateway_secret_store,
    load_or_create_node_id,
)
from tunnelminion.gateway.names import load_node_name
from tunnelminion.gateway.security import GatewayBindConfig
from tunnelminion.gateway.services import GatewayServiceReader
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
from tunnelminion.operation.definitions import register_safe_http_sharing_operation
from tunnelminion.operation.http_sharing import UvicornProxyRuntime
from tunnelminion.operation.policy import AuthorizationService, OperationPolicy
from tunnelminion.operation.requester_service import RequesterOperationService
from tunnelminion.patrol.local import (
    build_local_patrol,
    patrol_covers,
    patrol_store,
    peer_patrol_reports,
)
from tunnelminion.patrol.service import patrol_lifespan
from tunnelminion.platforms.windows.adapters import (
    DockerServicesAdapter,
    NetworkListenersAdapter,
    NodeSummaryAdapter,
    ProcessSummaryAdapter,
    ServiceReachabilityAdapter,
    WireGuardStatusAdapter,
)
from tunnelminion.platforms.windows.definitions import (
    WindowsToolAdapters,
    register_windows_tools,
)
from tunnelminion.platforms.windows.managed_path import build_windows_managed_path_platform
from tunnelminion.platforms.windows.system import (
    PsutilSystemReader,
    SubprocessCommandRunner,
    default_docker_path,
    default_wg_path,
)
from tunnelminion.repair.agent_tools import proposed_repairs_for_delegation
from tunnelminion.repair.definitions import register_repair_operations
from tunnelminion.repair.launch_records import LaunchRecorder
from tunnelminion.repair.local import build_node_repair_service
from tunnelminion.repair.service import RepairService
from tunnelminion.runtime.profile import default_runtime_data_dir
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
from tunnelminion.web.identity import create_identity_router
from tunnelminion.web.incidents import create_incident_router, incidents_overview
from tunnelminion.web.memory import create_memory_router
from tunnelminion.web.operations import OperationControlService, create_operation_router
from tunnelminion.web.overview import create_overview_router
from tunnelminion.web.patrol import create_patrol_router
from tunnelminion.web.peers import PeerServicePoller, create_peers_router, peer_services_lifespan
from tunnelminion.web.repairs import create_repair_router
from tunnelminion.web.request_guard import install_local_request_guard
from tunnelminion.web.resources import create_resource_router
from tunnelminion.web.service_map import build_local_service_map, create_service_map_router
from tunnelminion.web.spa import create_spa_router


@dataclass(frozen=True)
class WindowsApplication:
    """供启动、测试和后续持久化替换使用的运行时集合。"""

    app: FastAPI
    node_id: NodeId
    model_service: ModelConfigurationService
    tool_runtime: ToolRuntime
    audit_sink: InMemoryAuditSink
    tool_registry: ToolRegistry
    conversation_service: InMemoryConversationService
    memory_service: LongTermMemoryService
    operation_control_service: OperationControlService
    requester_operation_service: RequesterOperationService
    managed_node: ManagedNodeApplication
    artifact_manager: ArtifactContextManager
    repair_service: RepairService

    def create_read_only_agent(self) -> LangChainReadOnlyAgent:
        """使用当前模型配置创建一次可注入动态工具集的本地 Agent。"""
        provider = self.model_service.create_provider()
        model = TunnelMinionChatModel(provider=provider, artifact_manager=self.artifact_manager)
        return LangChainReadOnlyAgent(
            model,
            self.tool_registry,
            self.tool_runtime,
            Platform.WINDOWS,
            request_gate=RequestGate(
                provider, provider_name="configured-provider", model_name="configured-model"
            ),
            tool_selection=ToolSelectionSettings(max_tools=self.model_service.tool_limit()),
        )


def default_data_dir() -> Path:
    """返回当前系统账户的 TunnelMinion 数据目录。"""
    return default_runtime_data_dir()


def build_requester_operation_service(
    *,
    root: Path,
    node_id: NodeId,
    platform: Platform,
    model_service: ModelConfigurationService,
    tool_runtime: ToolRuntime,
    audit_sink: InMemoryAuditSink,
    stores: SQLiteStores,
    incident_store: SQLiteIncidentStore,
) -> RequesterOperationService:
    """用现有模型、只读工具和固定 Gateway 组装请求端主路径。"""
    configuration = GatewayConfigurationService(
        FileGatewayConfigurationRepository(root / "gateway.json"),
        gateway_secret_store(root),
    )

    def client(peer: GatewayOperationPeer) -> FixedGatewayClient:
        return FixedGatewayClient(
            peer.endpoint,
            peer.token,
            node_id,
            peer.node_id,
            audit_sink,
        )

    def diagnostic_agent(peer: GatewayOperationPeer) -> CrossNodeDiagnosticAgent:
        provider = model_service.create_provider()
        return CrossNodeDiagnosticAgent(
            CrossNodeDiagnosticWorkflow(
                RemoteCapabilityLoader(client(peer), platform, peer.node_id, peer.platform),
                tool_runtime,
                node_id,
            ),
            provider,
        )

    return RequesterOperationService(
        node_id=node_id,
        store=stores.requester_operations,
        configuration=configuration,
        diagnostic_agent_factory=diagnostic_agent,
        gateway_client_factory=client,
        callback_runtime=UvicornProxyRuntime(),
        clock=lambda: datetime.now(UTC),
        incident_store=incident_store,
    )


@dataclass(frozen=True)
class WindowsNode:
    """Windows 本地面板与网关共享的节点依赖：模型配置、只读工具和本机存储。"""

    root: Path
    node_id: NodeId
    model_service: ModelConfigurationService
    tool_registry: ToolRegistry
    tool_runtime: ToolRuntime
    audit_sink: InMemoryAuditSink
    listeners: NetworkListenersAdapter
    processes: ProcessSummaryAdapter
    docker: DockerServicesAdapter
    stores: SQLiteStores
    artifact_manager: ArtifactContextManager
    repair_service: RepairService

    def create_read_only_agent(self) -> LangChainReadOnlyAgent:
        """只用本机工具的 Agent；处理别的电脑交来的委派时使用。"""
        model = TunnelMinionChatModel(
            provider=self.model_service.create_provider(), artifact_manager=self.artifact_manager
        )
        return LangChainReadOnlyAgent(
            model,
            self.tool_registry,
            self.tool_runtime,
            Platform.WINDOWS,
            tool_selection=ToolSelectionSettings(max_tools=self.model_service.tool_limit()),
        )


def build_windows_node(data_dir: Path | None = None) -> WindowsNode:
    """组装 Windows 节点的模型配置、六个只读工具和本机存储。"""
    root = data_dir or default_data_dir()
    node_id = load_or_create_node_id(root / "node-id")
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
        KeyringSecretStore(),
        borrowed_provider_factory=borrowed_provider,
    )
    registry = ToolRegistry()
    runner = SubprocessCommandRunner()
    reader = PsutilSystemReader()
    wireguard = WireGuardStatusAdapter(reader, runner, default_wg_path())

    def model_status() -> str:
        return model_service.view().status

    node_summary = NodeSummaryAdapter(node_id, registry, wireguard, model_status)
    listeners = NetworkListenersAdapter(reader)
    processes = ProcessSummaryAdapter(reader)
    docker = DockerServicesAdapter(runner, default_docker_path())
    register_windows_tools(
        registry,
        WindowsToolAdapters(
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
        Platform.WINDOWS,
        audit,
        artifact_manager=artifact_manager,
    )
    return WindowsNode(
        root=root,
        node_id=node_id,
        model_service=model_service,
        tool_registry=registry,
        tool_runtime=runtime,
        audit_sink=audit,
        listeners=listeners,
        processes=processes,
        docker=docker,
        stores=stores,
        artifact_manager=artifact_manager,
        repair_service=repair_service,
    )


@dataclass(frozen=True)
class WindowsGatewayApplication:
    """只包含跨节点端点的 Windows 网关：只读工具调用与委派处理。"""

    app: FastAPI
    bind: GatewayBindConfig
    node_id: NodeId
    gateway_service: GatewayConfigurationService
    delegation_service: DelegationService | None = None
    model_lending_service: ModelLendingService | None = None


def build_windows_gateway_application(data_dir: Path | None = None) -> WindowsGatewayApplication:
    """组装只绑定 WireGuard 地址的认证网关，让别的电脑能把问题交给这台电脑。"""
    node = build_windows_node(data_dir)
    gateway_service = GatewayConfigurationService(
        FileGatewayConfigurationRepository(node.root / "gateway.json"),
        gateway_secret_store(node.root),
    )
    view = gateway_service.view()
    if not view.configured or view.bind is None:
        raise RuntimeError("尚未配置 Windows Tool Gateway WireGuard 监听地址")
    load_node_name(node.root, Platform.WINDOWS)
    security_policy = gateway_service.build_security_policy()
    delegation_service = DelegationService(
        node.node_id,
        node.stores.delegations,
        node.create_read_only_agent,
        lambda: tuple(item.name for item in node.tool_registry.model_tools(Platform.WINDOWS)),
        repair_query=lambda delegation_id: proposed_repairs_for_delegation(
            node.stores.repairs, delegation_id
        ),
    )
    model_lending_service = ModelLendingService(
        node.node_id, node.model_service.create_lending_provider, node.stores.model_usage
    )
    invite_service = InviteService(
        node.node_id,
        Platform.WINDOWS,
        gateway_service,
        node.stores.invites,
        security_policy,
        display_name=lambda: load_node_name(node.root, Platform.WINDOWS),
    )
    app = FastAPI(
        title="TunnelMinion Tool Gateway",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=tracing_lifespan(node.root, node.node_id, Platform.WINDOWS),
    )
    gateway_patrol = patrol_store(node.root)
    app.include_router(
        create_gateway_router(
            node.node_id,
            Platform.WINDOWS,
            node.tool_registry,
            node.tool_runtime,
            security_policy,
            InMemoryGatewaySecurityAuditSink(),
            delegation_service=delegation_service,
            model_lending_service=model_lending_service,
            invite_service=invite_service,
            repair_service=node.repair_service,
            peer_display_name=gateway_service.peer_display_name,
            owner_devices=gateway_service.owner_devices,
            service_reader=GatewayServiceReader(
                node.node_id,
                lambda: load_node_name(node.root, Platform.WINDOWS),
                DeterministicServiceObserver(
                    node.node_id,
                    ServiceObservationConfig(),
                    node.listeners,
                    node.processes,
                    node.docker,
                    marks=node.stores.service_marks.all,
                ),
                node.stores.service_marks,
                pending_repair_ids=node.repair_service.pending_repair_ids,
                patrol=lambda: peer_patrol_reports(gateway_patrol),
            ),
        )
    )
    return WindowsGatewayApplication(
        app=app,
        bind=view.bind,
        node_id=node.node_id,
        gateway_service=gateway_service,
        delegation_service=delegation_service,
        model_lending_service=model_lending_service,
    )


def build_windows_application(
    data_dir: Path | None = None,
    *,
    network_path: NetworkPathViewBindings | None = None,
    read_only_preview: bool = False,
) -> WindowsApplication:
    """组装模型配置、六个真实只读工具和本机 Web 入口。"""
    node = build_windows_node(data_dir)
    root = node.root
    register_delegate_tool(
        node.tool_registry,
        Platform.WINDOWS,
        GatewayConfigurationService(
            FileGatewayConfigurationRepository(root / "gateway.json"), gateway_secret_store(root)
        ),
        node.node_id,
        node.audit_sink,
        progress_sink=lambda context, progress: conversations.append_delegation_progress(
            context, progress
        ),
        proposed_repairs_sink=lambda peer, repairs: peer_poller.remember_repairs(peer, repairs),
    )
    node_id = node.node_id
    model_service = node.model_service
    registry = node.tool_registry
    audit = node.audit_sink
    listeners = node.listeners
    processes = node.processes
    docker = node.docker
    stores = node.stores
    artifact_manager = node.artifact_manager
    runtime = node.tool_runtime

    def create_agent() -> LangChainReadOnlyAgent:
        provider = model_service.create_provider()
        model = TunnelMinionChatModel(provider=provider, artifact_manager=artifact_manager)
        return LangChainReadOnlyAgent(
            model,
            registry,
            runtime,
            Platform.WINDOWS,
            remote_tools=remote_preparer,
            request_gate=RequestGate(
                provider, provider_name="configured-provider", model_name="configured-model"
            ),
            tool_selection=ToolSelectionSettings(max_tools=model_service.tool_limit()),
        )

    conversations = InMemoryConversationService(
        node_id,
        create_agent,
        stores.checkpoints,
        memory_retriever=MemoryContextRetriever(stores.memories),
        read_only_preview=read_only_preview,
    )
    memories = LongTermMemoryService(stores.memories, (conversations,))
    node.repair_service.set_result_handler(conversations.append_repair_result)
    authorization = AuthorizationService(
        stores.operations,
        stores.preauthorizations,
        OperationPolicy(registry, stores.preauthorizations),
    )
    incident_store = SQLiteIncidentStore(root / "incidents.sqlite3")
    requester_operations = build_requester_operation_service(
        root=root,
        node_id=node_id,
        platform=Platform.WINDOWS,
        model_service=model_service,
        tool_runtime=runtime,
        audit_sink=audit,
        stores=stores,
        incident_store=incident_store,
    )
    operation_control = OperationControlService(
        node_id=node_id,
        operations=stores.operations,
        preauthorizations=stores.preauthorizations,
        authorization=authorization,
        requester=requester_operations,
    )
    managed = build_managed_node_application(
        root,
        node_id,
        Platform.WINDOWS,
        registry,
        listeners,
        processes,
        docker,
        managed_path_platform_factory=build_windows_managed_path_platform,
        containers=node.repair_service.containers,
        launch_records=stores.launch_records,
        host=node.repair_service.host,
    )
    service_cache = (
        managed.coordinator.service_cache
        if managed.coordinator is not None
        else ServiceSnapshotCache()
    )
    remote_preparer = ConfiguredRemoteToolPreparer(
        GatewayConfigurationService(
            FileGatewayConfigurationRepository(root / "gateway.json"),
            gateway_secret_store(root),
        ),
        node_id,
        Platform.WINDOWS,
        audit,
    )
    peer_observer = StaticPeerServiceObserver.from_file(root, node_id, remote_preparer)
    if peer_observer is not None and managed.coordinator is not None:
        raise ValueError("静态对端观察不能与目录观察同时启用")
    before_snapshot = None
    remote_observer = None
    if managed.coordinator is not None and not read_only_preview:
        remote_observer = RemoteServicePresentationObserver(
            node_id, managed.coordinator.coordinator_cache, remote_preparer
        )
        before_snapshot = remote_observer.refresh
    if managed.coordinator is None or read_only_preview:
        local_observer = DeterministicServiceObserver(
            node_id,
            ServiceObservationConfig(),
            listeners,
            processes,
            docker,
            marks=stores.service_marks.all,
            containers=node.repair_service.containers,
            launch_records=stores.launch_records,
            host=node.repair_service.host,
            windows_services=node.repair_service.windows_services,
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
        node_id=node_id,
        platform=Platform.WINDOWS,
        model_service=model_service,
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
            model_service.create_provider,
            registry,
            runtime,
            incident_store,
            Platform.WINDOWS,
            local_node_id=node_id,
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
        skip_investigation=None if read_only_preview else patrol_covers(node_id),
    )
    patrol = build_local_patrol(
        root=root,
        node_id=node_id,
        services=lambda: build_local_service_map(
            node_id,
            service_cache.read(),
            stores.service_marks.all(),
            excluded_pid=os.getpid(),
            launch_records=stores.launch_records.list_all(),
        ),
        conversations=conversations,
        repairs=node.repair_service,
        launch_records=stores.launch_records,
        windows_services=node.repair_service.windows_services,
    )
    peer_poller = PeerServicePoller(
        GatewayConfigurationService(
            FileGatewayConfigurationRepository(root / "gateway.json"), gateway_secret_store(root)
        ),
        node_id,
        audit,
    )
    local_lifespan = incident_observation_lifespan(
        managed_application_lifespan(managed), incident_observer, incident_store
    )
    if not read_only_preview:
        local_lifespan = peer_services_lifespan(local_lifespan, peer_poller)
        local_lifespan = patrol_lifespan(local_lifespan, patrol)
    app = FastAPI(
        title="TunnelMinion",
        docs_url="/api/docs",
        lifespan=tracing_lifespan(
            root,
            node_id,
            Platform.WINDOWS,
            local_lifespan,
        ),
    )
    install_local_request_guard(app, read_only_preview=read_only_preview)
    app.include_router(create_model_router(model_service))
    app.include_router(
        create_resource_router(
            runtime,
            node_id,
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
    app.include_router(
        create_conversation_router(
            conversations,
            views.overview_service,
            lambda: build_local_service_map(
                node_id,
                service_cache.read(),
                stores.service_marks.all(),
                excluded_pid=os.getpid(),
                launch_records=stores.launch_records.list_all(),
            ),
            lambda value: peer_poller.services_view(
                value, views.resource_bindings.coordinator_cache
            ),
        )
    )
    app.include_router(create_memory_router(memories))
    app.include_router(create_identity_router(root, node_id, Platform.WINDOWS))
    app.include_router(
        create_peers_router(
            node_id,
            Platform.WINDOWS,
            lambda: load_node_name(root, Platform.WINDOWS),
            peer_poller,
            lambda: build_local_service_map(
                node_id, service_cache.read(), stores.service_marks.all(), excluded_pid=os.getpid()
            ),
            views.resource_bindings.coordinator_cache,
        )
    )
    app.include_router(
        create_service_map_router(
            node_id,
            stores.service_marks,
            service_cache.read,
            service_cache.replace,
            stores.launch_records,
        )
    )
    app.include_router(create_operation_router(operation_control))
    repair_service = node.repair_service
    app.include_router(create_repair_router(repair_service))
    if not read_only_preview:
        app.include_router(create_patrol_router(patrol))
    app.include_router(create_spa_router(read_only_preview=read_only_preview))
    return WindowsApplication(
        app,
        node_id,
        model_service,
        runtime,
        audit,
        registry,
        conversations,
        memories,
        operation_control,
        requester_operations,
        managed,
        artifact_manager,
        repair_service,
    )


def create_app() -> FastAPI:
    """供 Uvicorn `--factory` 使用的应用工厂。"""
    bundle = build_windows_application()
    bundle.app.state.managed_node = bundle.managed_node
    return bundle.app
