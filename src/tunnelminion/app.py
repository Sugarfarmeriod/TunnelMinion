"""Windows MVP 的真实依赖组装与 FastAPI 应用工厂。"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from fastapi import FastAPI

from tunnelminion.agent.conversation import InMemoryConversationService
from tunnelminion.agent.langchain_model import TunnelMinionChatModel
from tunnelminion.agent.managed_application import (
    ManagedNodeApplication,
    build_managed_node_application,
    managed_application_lifespan,
)
from tunnelminion.agent.runtime import LangChainReadOnlyAgent
from tunnelminion.domain.identifiers import NodeId
from tunnelminion.domain.tools import Platform
from tunnelminion.memory.context import ArtifactContextManager
from tunnelminion.memory.service import LongTermMemoryService, MemoryContextRetriever
from tunnelminion.memory.sqlite import SQLiteStores
from tunnelminion.model.api import create_model_router
from tunnelminion.model.configuration import (
    FileModelConfigurationRepository,
    ModelConfigurationService,
)
from tunnelminion.model.secrets import KeyringSecretStore
from tunnelminion.operation.definitions import register_safe_http_sharing_operation
from tunnelminion.operation.policy import AuthorizationService, OperationPolicy
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
from tunnelminion.platforms.windows.system import (
    PsutilSystemReader,
    SubprocessCommandRunner,
    default_docker_path,
    default_wg_path,
)
from tunnelminion.runtime.profile import default_runtime_data_dir
from tunnelminion.tools.audit import InMemoryAuditSink
from tunnelminion.tools.registry import ToolRegistry
from tunnelminion.tools.runtime import ToolRuntime
from tunnelminion.web.conversation import create_conversation_router
from tunnelminion.web.memory import create_memory_router
from tunnelminion.web.operations import OperationControlService, create_operation_router
from tunnelminion.web.resources import create_resource_router


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
    managed_node: ManagedNodeApplication

    def create_read_only_agent(self) -> LangChainReadOnlyAgent:
        """使用当前模型配置创建一次可注入动态工具集的本地 Agent。"""
        model = TunnelMinionChatModel(provider=self.model_service.create_provider())
        return LangChainReadOnlyAgent(
            model,
            self.tool_registry,
            self.tool_runtime,
            Platform.WINDOWS,
        )


def default_data_dir() -> Path:
    """返回当前系统账户的 TunnelMinion 数据目录。"""
    return default_runtime_data_dir()


def load_or_create_node_id(path: Path) -> NodeId:
    """读取稳定 Node ID，首次启动时以原子替换方式创建。"""
    if path.exists():
        return NodeId(path.read_text(encoding="utf-8").strip())
    path.parent.mkdir(parents=True, exist_ok=True)
    node_id = NodeId.new()
    temporary = path.with_suffix(f"{path.suffix}.tmp")
    temporary.write_text(str(node_id), encoding="utf-8")
    temporary.replace(path)
    return node_id


def build_windows_application(data_dir: Path | None = None) -> WindowsApplication:
    """组装模型配置、六个真实只读工具和本机 Web 入口。"""
    root = data_dir or default_data_dir()
    node_id = load_or_create_node_id(root / "node-id")
    model_service = ModelConfigurationService(
        FileModelConfigurationRepository(root / "model.json"),
        KeyringSecretStore(),
    )
    registry = ToolRegistry()
    audit = InMemoryAuditSink()
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
    stores = SQLiteStores.open(root / "runtime.sqlite3")
    runtime = ToolRuntime(
        registry,
        Platform.WINDOWS,
        audit,
        artifact_manager=ArtifactContextManager(stores.artifacts),
    )

    def create_agent() -> LangChainReadOnlyAgent:
        model = TunnelMinionChatModel(provider=model_service.create_provider())
        return LangChainReadOnlyAgent(model, registry, runtime, Platform.WINDOWS)

    conversations = InMemoryConversationService(
        node_id,
        create_agent,
        stores.checkpoints,
        memory_retriever=MemoryContextRetriever(stores.memories),
    )
    memories = LongTermMemoryService(stores.memories, (conversations,))
    authorization = AuthorizationService(
        stores.operations,
        stores.preauthorizations,
        OperationPolicy(registry, stores.preauthorizations),
    )
    operation_control = OperationControlService(
        node_id=node_id,
        operations=stores.operations,
        preauthorizations=stores.preauthorizations,
        authorization=authorization,
    )
    managed = build_managed_node_application(
        root,
        node_id,
        Platform.WINDOWS,
        registry,
        listeners,
        processes,
        docker,
    )
    app = FastAPI(
        title="TunnelMinion",
        docs_url="/api/docs",
        lifespan=managed_application_lifespan(managed),
    )
    app.include_router(create_model_router(model_service))
    app.include_router(
        create_resource_router(runtime, node_id, managed_status=managed.resource_payload)
    )
    app.include_router(create_conversation_router(conversations))
    app.include_router(create_memory_router(memories))
    app.include_router(create_operation_router(operation_control))
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
        managed,
    )


def create_app() -> FastAPI:
    """供 Uvicorn `--factory` 使用的应用工厂。"""
    return build_windows_application().app
