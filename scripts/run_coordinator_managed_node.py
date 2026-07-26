"""在隔离数据目录运行 Coordinator-managed macOS 测试 Gateway。"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

import uvicorn
from fastapi import FastAPI

from tunnelminion.agent.coordinator import (
    AgentCoordinatorSynchronizer,
    CoordinatorCache,
    CoordinatorCheckpointStore,
    CoordinatorClientConfig,
    CoordinatorEnrollmentClient,
    HttpCoordinatorTransport,
    render_capabilities,
)
from tunnelminion.coordinator.client_credentials import AgentRefreshCredentialStore
from tunnelminion.coordinator.contracts import (
    GatewayEndpoint,
    NodeIdentity,
    ServiceAccessibility,
    ServiceLifecycle,
    ServiceProtocol,
    ServiceSummary,
)
from tunnelminion.domain.identifiers import NetworkId, NodeId, ServiceId
from tunnelminion.domain.tools import Platform
from tunnelminion.gateway import create_gateway_router
from tunnelminion.gateway.audit import InMemoryGatewaySecurityAuditSink
from tunnelminion.gateway.security import GatewayManagedPeerPolicy, GatewaySecurityPolicy
from tunnelminion.macos_app import build_macos_local_application
from tunnelminion.model.secrets import RestrictedFileSecretStore

_ALLOWED_TOOLS = frozenset(
    {
        "get_node_summary",
        "get_process_summary",
        "get_wireguard_status",
        "list_docker_services",
        "list_network_listeners",
        "probe_service_reachability",
    }
)


async def _tcp_reachable(host: str, port: int) -> bool:
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=2)
    except (OSError, TimeoutError):
        return False
    writer.close()
    await writer.wait_closed()
    return True


async def run_managed_node(args: argparse.Namespace) -> None:
    """注册 B、持续同步目录并在临时允许端口提供 managed Gateway。"""
    data_dir = Path(args.data_dir)
    data_dir.mkdir(parents=True, exist_ok=True)
    (data_dir / "node-id").write_text(str(args.node_id), encoding="utf-8")
    token_path = Path(args.enrollment_token_file)
    enrollment_token = token_path.read_text(encoding="utf-8").strip()
    token_path.unlink()

    application = build_macos_local_application(data_dir)
    config = CoordinatorClientConfig(
        endpoint=args.coordinator_endpoint,
        network_id=args.network_id,
        node_id=args.node_id,
        pinned_fingerprints=frozenset({args.pinned_fingerprint}),
        sync_interval_seconds=2,
        base_backoff_seconds=1,
        max_backoff_seconds=4,
        cache_ttl_seconds=args.cache_ttl_seconds,
    )
    transport = HttpCoordinatorTransport(config)
    credentials = AgentRefreshCredentialStore(
        RestrictedFileSecretStore(data_dir / "coordinator-secrets")
    )
    identity = NodeIdentity(
        network_id=args.network_id,
        node_id=args.node_id,
        display_name="macOS B acceptance",
        platform=Platform.MACOS,
        gateway_endpoint=GatewayEndpoint(host=args.gateway_host, port=args.gateway_port),
    )
    enrollment = CoordinatorEnrollmentClient(config, transport, credentials)
    await enrollment.enroll(
        identity,
        device_identity_hash=hashlib.sha256(
            f"coordinator-ab:{args.node_id}".encode()
        ).hexdigest(),
        enrollment_token=enrollment_token,
    )
    enrollment_token = ""

    cache = CoordinatorCache()
    synchronizer = AgentCoordinatorSynchronizer(
        config,
        transport,
        credentials,
        CoordinatorCheckpointStore(data_dir / "coordinator-checkpoint.json"),
        cache,
    )
    capabilities = render_capabilities(
        application.node.tool_registry.model_tools(Platform.MACOS),
        Platform.MACOS,
    )
    model_service = ServiceSummary(
        service_id=ServiceId.new(),
        protocol=ServiceProtocol.HTTP,
        host=args.gateway_host,
        port=args.model_port,
        accessibility=ServiceAccessibility.NETWORK,
        source="acceptance-socket-probe",
        confidence=1,
        observed_at=datetime.now(UTC),
        lifecycle=(
            ServiceLifecycle.ACTIVE
            if await _tcp_reachable(args.gateway_host, args.model_port)
            else ServiceLifecycle.STOPPED
        ),
    )
    await synchronizer.sync_once(capabilities, (model_service,))
    sync_task = asyncio.create_task(
        synchronizer.run(lambda: capabilities, lambda: (model_service,))
    )

    policy = GatewaySecurityPolicy(
        [],
        managed_peers=[
            GatewayManagedPeerPolicy(args.peer_node_id, _ALLOWED_TOOLS),
        ],
        coordinator_cache=cache,
        pinned_fingerprints={args.pinned_fingerprint},
    )
    gateway = FastAPI(title="TunnelMinion Coordinator A/B managed Gateway")
    gateway.include_router(
        create_gateway_router(
            args.node_id,
            Platform.MACOS,
            application.node.tool_registry,
            application.node.tool_runtime,
            policy,
            InMemoryGatewaySecurityAuditSink(),
        )
    )
    server = uvicorn.Server(
        uvicorn.Config(
            gateway,
            host=args.gateway_host,
            port=args.gateway_port,
            log_level="warning",
            access_log=False,
        )
    )
    ready = {
        "node_id": str(args.node_id),
        "gateway": f"{args.gateway_host}:{args.gateway_port}",
        "capability_count": len(capabilities),
        "service_state": model_service.lifecycle.value,
        "token_file_removed": not token_path.exists(),
    }
    Path(args.ready_file).write_text(
        json.dumps(ready, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    try:
        await server.serve()
    finally:
        synchronizer.stop()
        await asyncio.gather(sync_task, return_exceptions=True)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--coordinator-endpoint", required=True)
    parser.add_argument("--network-id", type=NetworkId, required=True)
    parser.add_argument("--node-id", type=NodeId, required=True)
    parser.add_argument("--peer-node-id", type=NodeId, required=True)
    parser.add_argument("--pinned-fingerprint", required=True)
    parser.add_argument("--gateway-host", required=True)
    parser.add_argument("--gateway-port", type=int, default=18_888)
    parser.add_argument("--model-port", type=int, default=8082)
    parser.add_argument("--cache-ttl-seconds", type=int, default=15)
    parser.add_argument("--data-dir", type=Path, required=True)
    parser.add_argument("--enrollment-token-file", type=Path, required=True)
    parser.add_argument("--ready-file", type=Path, required=True)
    args = parser.parse_args(argv)
    if os.name == "nt":
        raise RuntimeError("managed-node 验收帮助程序只能在 macOS/Linux 隔离环境运行")
    asyncio.run(run_managed_node(args))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
