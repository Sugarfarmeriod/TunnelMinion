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
from tunnelminion.agent.langchain_model import TunnelMinionChatModel
from tunnelminion.agent.managed_application import (
    ManagedNodeApplication,
    build_managed_node_application,
    managed_application_lifespan,
)
from tunnelminion.agent.runtime import LangChainReadOnlyAgent
from tunnelminion.app import default_data_dir, load_or_create_node_id
from tunnelminion.domain.identifiers import NodeId
from tunnelminion.domain.tools import Platform
from tunnelminion.gateway import create_gateway_router
from tunnelminion.gateway.audit import InMemoryGatewaySecurityAuditSink
from tunnelminion.gateway.configuration import (
    FileGatewayConfigurationRepository,
    GatewayConfigurationService,
    gateway_secret_store,
)
from tunnelminion.gateway.operations import TargetOperationGatewayService
from tunnelminion.gateway.security import GatewayBindConfig
from tunnelminion.memory.context import ArtifactContextManager
from tunnelminion.memory.service import LongTermMemoryService, MemoryContextRetriever
from tunnelminion.memory.sqlite import SQLiteStores
from tunnelminion.model.api import create_model_router
from tunnelminion.model.configuration import (
    FileModelConfigurationRepository,
    ModelConfigurationService,
)
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
from tunnelminion.platforms.macos.system import (
    MacOSSystemReader,
    SubprocessCommandRunner,
    default_docker_path,
    default_wg_path,
)
from tunnelminion.platforms.windows.system import SystemReader
from tunnelminion.tools.audit import InMemoryAuditSink
from tunnelminion.tools.registry import ToolRegistry
from tunnelminion.tools.runtime import ToolRuntime
from tunnelminion.web.application_views import build_application_view_bindings
from tunnelminion.web.conversation import create_conversation_router
from tunnelminion.web.diagnostics import DiagnosticsExportService, create_diagnostics_router
from tunnelminion.web.memory import create_memory_router
from tunnelminion.web.operations import OperationControlService, create_operation_router
from tunnelminion.web.overview import create_overview_router
from tunnelminion.web.request_guard import install_local_request_guard
from tunnelminion.web.resources import create_resource_router
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


@dataclass(frozen=True)
class MacOSLocalApplication:
    """只应绑定环回地址的 macOS 本地面板。"""

    app: FastAPI
    node: MacOSNode
    conversation_service: InMemoryConversationService
    memory_service: LongTermMemoryService
    operation_control_service: OperationControlService
    managed_node: ManagedNodeApplication

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


def _create_macos_read_only_agent(node: MacOSNode) -> LangChainReadOnlyAgent:
    """把 macOS 节点依赖组合成受只读策略约束的 Agent。"""
    model = TunnelMinionChatModel(provider=node.model_service.create_provider())
    return LangChainReadOnlyAgent(model, node.tool_registry, node.tool_runtime, Platform.MACOS)


def _build_macos_node(
    data_dir: Path | None = None,
    *,
    interface_name: str | None = None,
) -> MacOSNode:
    """组装两种 macOS 入口共用的模型状态与六个只读工具。"""
    root = default_data_dir() if data_dir is None else data_dir
    node_id = load_or_create_node_id(root / "node-id")
    secrets = KeyringSecretStore()
    model_service = ModelConfigurationService(
        FileModelConfigurationRepository(root / "model.json"), secrets
    )
    registry = ToolRegistry()
    audit = InMemoryAuditSink()
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
    stores = SQLiteStores.open(root / "runtime.sqlite3")
    runtime = ToolRuntime(
        registry,
        Platform.MACOS,
        audit,
        artifact_manager=ArtifactContextManager(stores.artifacts),
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
    )


def build_macos_local_application(
    data_dir: Path | None = None,
    *,
    interface_name: str | None = None,
) -> MacOSLocalApplication:
    """组装即使没有模型也能使用资源页的 macOS 本地应用。"""
    node = _build_macos_node(data_dir, interface_name=interface_name)

    stores = SQLiteStores.open(node.root / "runtime.sqlite3")
    conversations = InMemoryConversationService(
        node.node_id,
        lambda: _create_macos_read_only_agent(node),
        stores.checkpoints,
        memory_retriever=MemoryContextRetriever(stores.memories),
    )
    memories = LongTermMemoryService(stores.memories, (conversations,))
    authorization = AuthorizationService(
        stores.operations,
        stores.preauthorizations,
        OperationPolicy(node.tool_registry, stores.preauthorizations),
    )
    operation_control = OperationControlService(
        node_id=node.node_id,
        operations=stores.operations,
        preauthorizations=stores.preauthorizations,
        authorization=authorization,
    )
    managed = build_managed_node_application(
        node.root,
        node.node_id,
        Platform.MACOS,
        node.tool_registry,
        node.listeners,
        node.processes,
        node.docker,
    )
    app = FastAPI(
        title="TunnelMinion",
        docs_url="/api/docs",
        lifespan=managed_application_lifespan(managed),
    )
    install_local_request_guard(app)
    views = build_application_view_bindings(
        node_id=node.node_id,
        platform=Platform.MACOS,
        model_service=node.model_service,
        managed=managed,
    )
    app.include_router(create_model_router(node.model_service))
    app.include_router(
        create_resource_router(
            node.tool_runtime,
            node.node_id,
            coordinator_status=views.resource_bindings.coordinator_status,
            coordinator_cache=views.resource_bindings.coordinator_cache,
            managed_status=managed.resource_payload,
        )
    )
    app.include_router(create_overview_router(views.overview_service))
    app.include_router(create_diagnostics_router(DiagnosticsExportService(views.overview_service)))
    app.include_router(create_conversation_router(conversations))
    app.include_router(create_memory_router(memories))
    app.include_router(create_operation_router(operation_control))
    app.include_router(create_spa_router())
    return MacOSLocalApplication(
        app,
        node,
        conversations,
        memories,
        operation_control,
        managed,
    )


def create_macos_app() -> FastAPI:
    """供 macOS 本地 Uvicorn 工厂使用。"""
    return build_macos_local_application().app


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
    if safe_sharing is not None:
        operation_peers = tuple(
            peer for peer in view.peers if "share_local_http_service" in peer.allowed_operations
        )
        if not operation_peers:
            raise RuntimeError("没有 peer 被本地配置允许请求临时 HTTP 共享")
        stores = SQLiteStores.open(node.root / "runtime.sqlite3")
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
        lifespan=lifespan,
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
    )
