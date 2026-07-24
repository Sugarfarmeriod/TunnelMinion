"""macOS B 节点只读 Tool Gateway 的真实依赖组装。"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from fastapi import FastAPI

from tunnelminion.agent.conversation import InMemoryConversationService
from tunnelminion.agent.langchain_model import TunnelMinionChatModel
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
from tunnelminion.gateway.security import GatewayBindConfig
from tunnelminion.memory.service import LongTermMemoryService
from tunnelminion.memory.sqlite import SQLiteStores
from tunnelminion.model.api import create_model_router
from tunnelminion.model.configuration import (
    FileModelConfigurationRepository,
    ModelConfigurationService,
)
from tunnelminion.model.secrets import KeyringSecretStore
from tunnelminion.operation.policy import AuthorizationService, OperationPolicy
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
    PsutilSystemReader,
    SubprocessCommandRunner,
    default_docker_path,
    default_wg_path,
)
from tunnelminion.tools.audit import InMemoryAuditSink
from tunnelminion.tools.registry import ToolRegistry
from tunnelminion.tools.runtime import ToolRuntime
from tunnelminion.web.conversation import create_conversation_router
from tunnelminion.web.memory import create_memory_router
from tunnelminion.web.operations import OperationControlService, create_operation_router
from tunnelminion.web.resources import create_resource_router


@dataclass(frozen=True)
class MacOSNode:
    """macOS 本地面板与远端网关共享的只读节点依赖。"""

    root: Path
    node_id: NodeId
    model_service: ModelConfigurationService
    tool_runtime: ToolRuntime
    audit_sink: InMemoryAuditSink
    tool_registry: ToolRegistry


@dataclass(frozen=True)
class MacOSLocalApplication:
    """只应绑定环回地址的 macOS 本地面板。"""

    app: FastAPI
    node: MacOSNode
    conversation_service: InMemoryConversationService
    memory_service: LongTermMemoryService
    operation_control_service: OperationControlService

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
    reader = PsutilSystemReader()
    wireguard = MacOSWireGuardStatusAdapter(
        reader,
        runner,
        default_wg_path(),
        interface_name=interface_name,
    )

    def model_status() -> str:
        return model_service.view().status

    node_summary = MacOSNodeSummaryAdapter(node_id, registry, wireguard, model_status)
    register_macos_tools(
        registry,
        MacOSToolAdapters(
            wireguard=wireguard,
            listeners=NetworkListenersAdapter(reader),
            processes=ProcessSummaryAdapter(reader),
            docker=DockerServicesAdapter(runner, default_docker_path()),
            reachability=ServiceReachabilityAdapter(),
            node_summary=node_summary,
        ),
    )
    runtime = ToolRuntime(registry, Platform.MACOS, audit)
    return MacOSNode(root, node_id, model_service, runtime, audit, registry)


def build_macos_local_application(
    data_dir: Path | None = None,
    *,
    interface_name: str | None = None,
) -> MacOSLocalApplication:
    """组装即使没有模型也能使用资源页的 macOS 本地应用。"""
    node = _build_macos_node(data_dir, interface_name=interface_name)

    stores = SQLiteStores.open(node.root / "runtime.sqlite3")
    conversations = InMemoryConversationService(
        node.node_id, lambda: _create_macos_read_only_agent(node), stores.checkpoints
    )
    memories = LongTermMemoryService(stores.memories)
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
    app = FastAPI(title="TunnelMinion", docs_url="/api/docs")
    app.include_router(create_model_router(node.model_service))
    app.include_router(create_resource_router(node.tool_runtime, node.node_id))
    app.include_router(create_conversation_router(conversations))
    app.include_router(create_memory_router(memories))
    app.include_router(create_operation_router(operation_control))
    return MacOSLocalApplication(app, node, conversations, memories, operation_control)


def create_macos_app() -> FastAPI:
    """供 macOS 本地 Uvicorn 工厂使用。"""
    return build_macos_local_application().app


def build_macos_gateway_application(
    data_dir: Path | None = None,
    *,
    interface_name: str | None = None,
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
    app = FastAPI(
        title="TunnelMinion Tool Gateway",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.include_router(
        create_gateway_router(
            node.node_id,
            Platform.MACOS,
            node.tool_registry,
            node.tool_runtime,
            security_policy,
            security_audit,
        )
    )
    return MacOSGatewayApplication(
        app=app,
        bind=view.bind,
        node_id=node.node_id,
        tool_runtime=node.tool_runtime,
        audit_sink=node.audit_sink,
        security_audit_sink=security_audit,
        tool_registry=node.tool_registry,
        gateway_service=gateway_service,
    )
