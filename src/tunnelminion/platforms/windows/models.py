"""Windows 只读工具返回的结构化模型。"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class Availability(StrEnum):
    """平台能力的可用程度。"""

    AVAILABLE = "available"
    DEGRADED = "degraded"
    UNAVAILABLE = "unavailable"


class InterfaceSnapshot(BaseModel):
    """Windows 网络接口的非秘密摘要。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str
    is_up: bool
    addresses: tuple[str, ...] = ()


class WireGuardPeerSummary(BaseModel):
    """不包含完整公钥或任何私钥的 peer 状态。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    public_key_summary: str
    endpoint: str | None = None
    allowed_addresses: tuple[str, ...] = ()
    latest_handshake_epoch: int | None = Field(default=None, ge=0)
    received_bytes: int | None = Field(default=None, ge=0)
    sent_bytes: int | None = Field(default=None, ge=0)


class WireGuardStatus(BaseModel):
    """WireGuard 接口、peer 与结构化降级原因。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    availability: Availability
    interface: str
    interface_up: bool
    addresses: tuple[str, ...] = ()
    peers: tuple[WireGuardPeerSummary, ...] = ()
    error_code: str | None = None
    error_message: str | None = None


class NetworkListener(BaseModel):
    """本机监听端点及可获得的进程摘要。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    protocol: str = Field(pattern="^(tcp|udp)$")
    address: str
    port: int = Field(ge=1, le=65535)
    pid: int | None = Field(default=None, ge=0)
    process_name: str | None = None


class ProcessInfo(BaseModel):
    """不含命令行、环境变量和文件内容的进程摘要。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    pid: int = Field(ge=0)
    name: str
    status: str | None = None
    memory_bytes: int | None = Field(default=None, ge=0)
    thread_count: int | None = Field(default=None, ge=0)


class DockerService(BaseModel):
    """Docker `ps` 允许返回的容器、镜像与端口字段。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    container_id: str
    name: str
    image: str
    ports: str
    status: str


class CollectionResult(BaseModel):
    """列表型平台工具的统一降级包装。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    availability: Availability
    items: tuple[dict[str, object], ...] = ()
    error_code: str | None = None
    error_message: str | None = None


class ReachabilityResult(BaseModel):
    """不读取应用正文的 TCP 连接结果。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    host: str
    port: int
    reachable: bool
    latency_ms: float | None = Field(default=None, ge=0)
    error_code: str | None = None


class NodeSummary(BaseModel):
    """供资源页和 Agent 优先读取的节点能力摘要。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    node_id: str
    platform: str
    agent_status: str
    model_status: str
    wireguard: WireGuardStatus
    available_tools: tuple[str, ...]
