"""加入邀请码并按需启用对端模型。"""

from __future__ import annotations

import socket
import sys
from datetime import UTC, datetime
from pathlib import Path

from tunnelminion.domain.identifiers import NodeId
from tunnelminion.domain.invites import (
    InvalidInviteCodeError,
    InviteAcceptance,
    InviteAccepted,
    InviteCode,
    platform_display_name,
)
from tunnelminion.domain.tools import Platform
from tunnelminion.gateway.client import FixedGatewayClient, InviteHandshakeError, accept_invite
from tunnelminion.gateway.configuration import (
    DEFAULT_GATEWAY_TOOLS,
    GATEWAY_TOKEN_PREFIX,
    FileGatewayConfigurationRepository,
    GatewayConfigurationService,
    GatewayPeerConfig,
    GatewayPeerInput,
    GatewaySecretStoreKind,
    configure_gateway_secret_store,
    gateway_secret_store,
)
from tunnelminion.gateway.names import load_node_name
from tunnelminion.gateway.security import GatewayBindConfig
from tunnelminion.model.configuration import (
    FileModelConfigurationRepository,
    ModelConfigurationService,
)
from tunnelminion.model.contracts import ProviderError
from tunnelminion.model.remote import RemoteModelProvider
from tunnelminion.model.secrets import KeyringSecretStore
from tunnelminion.runtime.profile import default_runtime_data_dir as default_data_dir
from tunnelminion.tools.audit import InMemoryAuditSink


class JoinError(ValueError):
    """可直接向用户说明的本地加入条件错误。"""


def detect_local_host(host: str, port: int) -> str:
    """读取系统到邀请方的路由源地址，不发送数据包。"""
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM) as connection:
        connection.connect((host, port))
        return str(connection.getsockname()[0])


async def join(
    code: InviteCode,
    *,
    data_dir: Path | None = None,
    host_override: str | None = None,
    bind_port: int = 8787,
    secret_store_kind: GatewaySecretStoreKind | None = None,
    use_borrowed_model: bool | None = None,
    now: datetime | None = None,
) -> InviteAccepted:
    """先完成握手再保存对端；模型自检失败仍保留配对。"""
    if code.expires_at.tzinfo is None or not code.token.startswith(GATEWAY_TOKEN_PREFIX):
        raise InvalidInviteCodeError("这不是有效的邀请码")
    if code.expires_at <= (now or datetime.now(UTC)):
        raise JoinError("邀请码已过期，请让对方重新生成")
    root = data_dir or default_data_dir()
    node_path = root / "node-id"
    node_id = (
        NodeId(node_path.read_text(encoding="utf-8").strip())
        if node_path.exists()
        else NodeId.new()
    )
    if node_id == code.node_id:
        raise JoinError("不能加入自己生成的邀请码")
    peer = GatewayPeerConfig(
        node_id=code.node_id,
        platform=code.platform,
        host=code.host,
        port=code.port,
        allowed_tools=frozenset(DEFAULT_GATEWAY_TOOLS),
    )
    peer.endpoint()
    repository = FileGatewayConfigurationRepository(root / "gateway.json")
    existing = repository.load()
    try:
        host = host_override or (
            existing.bind.host if existing is not None else detect_local_host(code.host, code.port)
        )
    except OSError as exc:
        raise InviteHandshakeError("unreachable") from exc
    reported = GatewayBindConfig(
        host=host, port=existing.bind.port if existing is not None else bind_port
    )
    if existing is None:
        GatewayConfigurationService(repository, gateway_secret_store(root)).configure_local(
            reported
        )
    local_platform = (
        Platform.MACOS
        if sys.platform == "darwin"
        else Platform.WINDOWS
        if sys.platform == "win32"
        else Platform.LINUX
    )
    acceptance = InviteAcceptance(
        node_id=node_id,
        platform=local_platform,
        display_name=load_node_name(root, local_platform, persist_default=False),
        host=reported.host,
        port=reported.port,
    )
    print(f"正在联系 {str(code.node_id)[:12]}（{code.host}:{code.port}）……", flush=True)
    accepted = await accept_invite(code, acceptance)
    load_node_name(root, local_platform)
    peer = peer.model_copy(
        update={
            "display_name": accepted.inviter_display_name or platform_display_name(code.platform)
        }
    )
    if not node_path.exists():
        temporary = node_path.with_suffix(".tmp")
        temporary.write_text(str(node_id), encoding="utf-8")
        temporary.replace(node_path)
    gateway = GatewayConfigurationService(
        repository,
        configure_gateway_secret_store(root, secret_store_kind)
        if secret_store_kind is not None
        else gateway_secret_store(root),
    )
    gateway.provision_peer(GatewayPeerInput(peer=peer, token=code.token))
    platform = "macOS" if code.platform is Platform.MACOS else "Windows"
    print(f"已加入。对方：{str(code.node_id)[:12]}，平台：{platform}", flush=True)
    if accepted.permissions.allow_delegation:
        print("- 可以把问题交给对方的 Agent 处理", flush=True)
    if accepted.permissions.allow_proxy_repair_approval:
        print("- 可以在你的地图上替对方批准修复", flush=True)
    if accepted.permissions.allow_model_borrowing:
        print(f"- 可以借用对方的模型，每天 {accepted.permissions.daily_quota} 个 token", flush=True)
    if not accepted.permissions.allow_model_borrowing or use_borrowed_model is False:
        return accepted

    def borrowed_provider(peer_node_id: NodeId) -> RemoteModelProvider:
        provider = gateway.resolve_model_peer(peer_node_id)
        return RemoteModelProvider(
            FixedGatewayClient(
                provider.endpoint, provider.token, node_id, provider.node_id, InMemoryAuditSink()
            ),
            node_id,
        )

    try:
        model_service = ModelConfigurationService(
            FileModelConfigurationRepository(root / "model.json"),
            KeyringSecretStore(),
            borrowed_provider_factory=borrowed_provider,
        )
        if use_borrowed_model is True or model_service.view().status == "unconfigured":
            print("正在切换到对方的模型并做一次自检，可能要几十秒……", flush=True)
            await model_service.borrow(code.node_id)
            print("已改用对方的模型。你在这台电脑上提的问题会发给对方的模型处理。", flush=True)
    except Exception as exc:
        reason = str(exc) if isinstance(exc, ProviderError) else "模型自检失败"
        print(
            f"没能改用对方的模型：{reason}。配对已经完成，可以稍后运行 "
            f"tunnelminion model-borrow --from {code.node_id}。",
            flush=True,
        )
    return accepted
