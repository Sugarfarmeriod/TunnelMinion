"""在真实 WireGuard A/B 节点运行 Coordinator 迁移与故障验收。"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import shutil
import socket
import subprocess
import tempfile
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

import httpx
import uvicorn

from tunnelminion.agent.coordinator import (
    AgentCoordinatorSynchronizer,
    CoordinatorAuthorizationView,
    CoordinatorCache,
    CoordinatorCheckpointStore,
    CoordinatorClientConfig,
    CoordinatorEnrollmentClient,
    HttpCoordinatorTransport,
    render_capabilities,
)
from tunnelminion.agent.dynamic_remote import (
    DynamicRemoteToolCoordinator,
    DynamicSelectionSink,
)
from tunnelminion.app import build_windows_application
from tunnelminion.coordinator.app import (
    CoordinatorAdminBindConfig,
    CoordinatorAgentBindConfig,
    CoordinatorApplicationConfig,
    build_coordinator_applications,
)
from tunnelminion.coordinator.client_credentials import AgentRefreshCredentialStore
from tunnelminion.coordinator.contracts import (
    AccessAssertionRequest,
    DirectoryQuery,
    EnrollmentTokenRequest,
    GatewayEndpoint,
    NodeIdentity,
    NodeRegistrationRequest,
    RefreshAuthentication,
)
from tunnelminion.coordinator.directory import CoordinatorDirectoryService
from tunnelminion.coordinator.identity import AssertionService, SigningKeyService
from tunnelminion.coordinator.registry import CoordinatorRegistryService, SQLiteCoordinatorStore
from tunnelminion.domain.identifiers import NetworkId, NodeId, RunId, ThreadId
from tunnelminion.domain.tools import Platform
from tunnelminion.model.secrets import RestrictedFileSecretStore
from tunnelminion.tools.audit import InMemoryAuditSink
from tunnelminion.tools.contracts import ToolCallContext, ToolExecutionRequest

_B_NODE_ID = NodeId("node_406913ccf29f4774a908c0435dbe8c5b")
_A_NODE_ID = NodeId("node_129841509f55473d8d9d3ca363850204")


def _run(
    command: list[str],
    *,
    cwd: Path,
    input_text: str | None = None,
    timeout: int = 180,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=cwd,
        input=input_text,
        capture_output=True,
        text=True,
        check=True,
        timeout=timeout,
    )


def _ssh(
    target: str,
    command: str,
    *,
    cwd: Path,
    input_text: str | None = None,
    timeout: int = 180,
) -> str:
    completed = _run(
        ["ssh", "-o", "BatchMode=yes", target, command],
        cwd=cwd,
        input_text=input_text,
        timeout=timeout,
    )
    return completed.stdout.strip()


async def _wait_http(url: str, expected: int = 200, timeout: float = 30) -> None:
    deadline = asyncio.get_running_loop().time() + timeout
    async with httpx.AsyncClient(timeout=2) as client:
        while asyncio.get_running_loop().time() < deadline:
            try:
                if (await client.get(url)).status_code == expected:
                    return
            except httpx.RequestError:
                pass
            await asyncio.sleep(0.5)
    raise TimeoutError(f"等待 HTTP endpoint 超时：{url}")


async def _port_open(host: str, port: int) -> bool:
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=2)
    except (OSError, TimeoutError):
        return False
    writer.close()
    await writer.wait_closed()
    return True


async def _start_server(
    app: Any,
    host: str,
    port: int,
) -> tuple[uvicorn.Server, asyncio.Task[None]]:
    server = uvicorn.Server(
        uvicorn.Config(app, host=host, port=port, log_level="warning", access_log=False)
    )
    task = asyncio.create_task(server.serve())
    await _wait_http(
        f"http://{host}:{port}/api/v1/"
        + ("agent/health" if host != "127.0.0.1" else "admin/health")
    )
    return server, task


def _snapshot_b(host: str) -> dict[str, object]:
    result: dict[str, object] = {}
    for port in (8082, 8787, *range(18_881, 18_890)):
        try:
            connection = socket.create_connection((host, port), timeout=0.6)
        except OSError:
            result[str(port)] = False
        else:
            connection.close()
            result[str(port)] = True
    return result


async def run_acceptance(args: argparse.Namespace) -> dict[str, object]:
    repo = Path(args.repo).resolve()
    output = Path(args.output).resolve()
    runtime = output.parent / ".coordinator-ab-runtime"
    if runtime.exists():
        shutil.rmtree(runtime)
    runtime.mkdir(parents=True)
    network_id = NetworkId.new()
    before = _snapshot_b(args.b_host)
    remote_root = ""
    remote_pid = ""
    agent_server: uvicorn.Server | None = None
    admin_server: uvicorn.Server | None = None
    server_tasks: list[asyncio.Task[None]] = []
    evidence: dict[str, object] = {
        "schema_version": 1,
        "acceptance": "coordinator-real-ab-migration",
        "started_at": datetime.now(UTC).isoformat(),
        "network_id": str(network_id),
        "nodes": {"a": str(_A_NODE_ID), "b": str(_B_NODE_ID)},
        "bindings": {
            "agent": f"{args.agent_host}:{args.agent_port}",
            "admin": f"127.0.0.1:{args.admin_port}",
            "temporary_b_gateway": f"{args.b_host}:{args.b_gateway_port}",
        },
        "before": before,
    }
    try:
        store = SQLiteCoordinatorStore(runtime / "coordinator.sqlite3")
        registry = CoordinatorRegistryService(store)
        registry.create_network(network_id)
        signing = SigningKeyService(
            store,
            RestrictedFileSecretStore(runtime / "signing-secrets"),
        )
        key = signing.rotate()
        assertions = AssertionService(registry, signing)
        directory = CoordinatorDirectoryService(store, registry)
        applications = build_coordinator_applications(
            CoordinatorApplicationConfig(
                data_path=store.path,
                agent_bind=CoordinatorAgentBindConfig(
                    host=args.agent_host,
                    port=args.agent_port,
                ),
                admin_bind=CoordinatorAdminBindConfig(port=args.admin_port),
            ),
            registry=registry,
            assertions=assertions,
            directory=directory,
        )
        agent_server, agent_task = await _start_server(
            applications.agent_app, args.agent_host, args.agent_port
        )
        admin_server, admin_task = await _start_server(
            applications.admin_app, "127.0.0.1", args.admin_port
        )
        server_tasks.extend((agent_task, admin_task))

        b_enrollment = registry.create_enrollment_token(
            EnrollmentTokenRequest(network_id=network_id)
        )
        remote_root = _ssh(
            args.ssh_target,
            "mktemp -d /tmp/tunnelminion-coordinator-ab.XXXXXX",
            cwd=repo,
        )
        if not remote_root.startswith("/tmp/tunnelminion-coordinator-ab."):
            raise RuntimeError("远端隔离目录不符合预期前缀")
        archive_fd, archive_name = tempfile.mkstemp(suffix=".tar.gz")
        os.close(archive_fd)
        archive = Path(archive_name)
        try:
            _run(
                ["git", "archive", "--format=tar.gz", "-o", str(archive), "HEAD"],
                cwd=repo,
            )
            _run(
                ["scp", "-q", str(archive), f"{args.ssh_target}:{remote_root}/source.tar.gz"],
                cwd=repo,
            )
        finally:
            archive.unlink(missing_ok=True)
        _ssh(
            args.ssh_target,
            (
                f"cd {remote_root} && tar -xzf source.tar.gz && "
                f"{args.remote_python} -m pip install --quiet --target .deps . && "
                "umask 077 && cat > enrollment.token"
            ),
            cwd=repo,
            input_text=b_enrollment.token,
            timeout=300,
        )
        remote_command = (
            f"cd {remote_root} && nohup env PYTHONPATH={remote_root}/src:{remote_root}/.deps "
            f"{args.remote_python} "
            "scripts/run_coordinator_managed_node.py "
            f"--coordinator-endpoint http://{args.agent_host}:{args.agent_port} "
            f"--network-id {network_id} --node-id {_B_NODE_ID} --peer-node-id {_A_NODE_ID} "
            f"--pinned-fingerprint {key.fingerprint} "
            f"--gateway-host {args.b_host} --gateway-port {args.b_gateway_port} "
            f"--data-dir {remote_root}/data --enrollment-token-file {remote_root}/enrollment.token "
            f"--ready-file {remote_root}/ready.json "
            f">{remote_root}/managed.log 2>&1 & echo $!"
        )
        remote_pid = _ssh(args.ssh_target, remote_command, cwd=repo)
        if not remote_pid.isdigit():
            raise RuntimeError("远端 managed Gateway PID 无效")
        await _wait_http(
            f"http://{args.b_host}:{args.b_gateway_port}/v1/capabilities",
            expected=401,
            timeout=90,
        )
        ready = json.loads(_ssh(args.ssh_target, f"cat {remote_root}/ready.json", cwd=repo))

        a_root = runtime / "a"
        (a_root / "node-id").parent.mkdir(parents=True, exist_ok=True)
        (a_root / "node-id").write_text(str(_A_NODE_ID), encoding="utf-8")
        a_application = build_windows_application(a_root)
        a_config = CoordinatorClientConfig(
            endpoint=f"http://{args.agent_host}:{args.agent_port}",
            network_id=network_id,
            node_id=_A_NODE_ID,
            pinned_fingerprints=frozenset({key.fingerprint}),
            sync_interval_seconds=2,
            cache_ttl_seconds=args.cache_ttl_seconds,
        )
        a_transport = HttpCoordinatorTransport(a_config)
        a_credentials = AgentRefreshCredentialStore(
            RestrictedFileSecretStore(a_root / "coordinator-secrets")
        )
        a_identity = NodeIdentity(
            network_id=network_id,
            node_id=_A_NODE_ID,
            display_name="Windows A acceptance",
            platform=Platform.WINDOWS,
            gateway_endpoint=GatewayEndpoint(host=args.agent_host, port=18_887),
        )
        a_token = registry.create_enrollment_token(EnrollmentTokenRequest(network_id=network_id))
        await CoordinatorEnrollmentClient(a_config, a_transport, a_credentials).enroll(
            a_identity,
            device_identity_hash=hashlib.sha256(
                f"coordinator-ab:{_A_NODE_ID}".encode()
            ).hexdigest(),
            enrollment_token=a_token.token,
        )
        a_cache = CoordinatorCache()
        a_sync = AgentCoordinatorSynchronizer(
            a_config,
            a_transport,
            a_credentials,
            CoordinatorCheckpointStore(a_root / "coordinator-checkpoint.json"),
            a_cache,
        )
        a_capabilities = render_capabilities(
            a_application.tool_registry.model_tools(Platform.WINDOWS),
            Platform.WINDOWS,
        )
        await a_sync.sync_once(a_capabilities, ())
        await asyncio.sleep(3)
        await a_sync.sync_once(a_capabilities, ())
        a_refresh = a_credentials.load(network_id, _A_NODE_ID)
        if a_refresh is None:
            raise RuntimeError("A 节点 refresh 凭据缺失")
        a_authentication = RefreshAuthentication(
            network_id=network_id,
            node_id=_A_NODE_ID,
            refresh_credential=a_refresh,
        )
        full_directory = await a_transport.query(
            a_authentication,
            DirectoryQuery(network_id=network_id),
        )
        a_cache.replace(
            CoordinatorAuthorizationView(
                network_id=network_id,
                generated_at=full_directory.generated_at,
                expires_at=full_directory.generated_at + timedelta(seconds=args.cache_ttl_seconds),
                nodes=full_directory.nodes,
                verification_keys=await a_transport.verification_keys(),
            )
        )
        for _ in range(15):
            ready = json.loads(_ssh(args.ssh_target, f"cat {remote_root}/ready.json", cwd=repo))
            authorization_nodes = cast(
                list[object],
                cast(dict[str, object], ready).get("authorization_nodes", []),
            )
            converged = False
            for node in authorization_nodes:
                if not isinstance(node, dict):
                    continue
                view = cast(dict[str, object], node)
                if (
                    view.get("node_id") == str(_A_NODE_ID)
                    and view.get("status") == "online"
                    and view.get("freshness") == "fresh"
                ):
                    converged = True
                    break
            if converged:
                break
            await asyncio.sleep(1)
        else:
            raise RuntimeError("B 节点授权缓存未在期限内收敛到 A")

        replay_identity = a_identity.model_copy(update={"node_id": NodeId.new()})
        replay_request = NodeRegistrationRequest(
            identity=replay_identity,
            device_identity_hash="0" * 64,
            enrollment_token=b_enrollment.token,
            idempotency_key=f"regkey_{'0' * 64}",
        )
        replay_status = 0
        async with httpx.AsyncClient(timeout=5) as client:
            replay_status = (
                await client.post(
                    f"http://{args.agent_host}:{args.agent_port}/api/v1/agent/registrations",
                    json=replay_request.model_dump(mode="json"),
                )
            ).status_code

        supported = {
            definition.name: definition.version
            for definition in a_application.tool_registry.model_tools(Platform.WINDOWS)
        }
        for definition in a_application.tool_registry.model_tools(Platform.WINDOWS):
            supported.setdefault(definition.name, definition.version)
        b_definitions = ready.get("capabilities")
        del b_definitions
        supported.update(
            {
                definition.name: definition.version
                for definition in a_application.tool_registry.model_tools(Platform.WINDOWS)
            }
        )
        # macOS 与 Windows 的六个固定只读工具使用同一协议版本；目录仍会复核目标平台。
        for name in (
            "get_node_summary",
            "list_network_listeners",
            "get_process_summary",
            "get_wireguard_status",
            "list_docker_services",
            "probe_service_reachability",
        ):
            supported[name] = next(
                item.version
                for item in a_application.tool_registry.model_tools(Platform.WINDOWS)
                if item.name == name
            )
        selections = DynamicSelectionSink()
        dynamic = DynamicRemoteToolCoordinator(
            network_id=network_id,
            local_node_id=_A_NODE_ID,
            local_platform=Platform.WINDOWS,
            cache=a_cache,
            transport=a_transport,
            credentials=a_credentials,
            audit_sink=InMemoryAuditSink(),
            selection_sink=selections,
            authorized_nodes=(_B_NODE_ID,),
            supported_tools=supported,
        )
        context = ToolCallContext(
            thread_id=ThreadId.new(),
            run_id=RunId.new(),
            caller_node_id=_A_NODE_ID,
            execution_node_id=_B_NODE_ID,
        )
        assertion = (
            await a_transport.issue_assertion(
                AccessAssertionRequest(
                    authentication=a_authentication,
                    audience="tool-gateway",
                )
            )
        ).assertion
        async with httpx.AsyncClient(timeout=5) as client:
            assertion_diagnostic = cast(
                dict[str, object],
                (
                    await client.get(
                        (
                            f"http://{args.b_host}:{args.b_gateway_port}"
                            "/acceptance/assertion-diagnostic"
                        ),
                        headers={"Authorization": f"Bearer {assertion}"},
                    )
                ).json(),
            )
        evidence["assertion_diagnostic"] = assertion_diagnostic
        if assertion_diagnostic.get("accepted") is not True:
            raise RuntimeError(
                "B 节点 assertion 离线验签失败："
                + json.dumps(assertion_diagnostic, ensure_ascii=False)
            )
        prepared = await dynamic.prepare(
            _B_NODE_ID,
            context,
            ("get_node_summary", "list_network_listeners"),
        )
        listeners = await prepared.tools.executor.execute(
            ToolExecutionRequest(
                context=context,
                tool_name="list_network_listeners",
            )
        )
        node_summary = await prepared.tools.executor.execute(
            ToolExecutionRequest(
                context=context,
                tool_name="get_node_summary",
            )
        )
        async with httpx.AsyncClient(timeout=5) as client:
            incompatible_status = (
                await client.get(
                    f"http://{args.b_host}:{args.b_gateway_port}/v1/capabilities",
                    params={"protocol_major": 2},
                    headers={"Authorization": f"Bearer {assertion}"},
                )
            ).status_code

        registry.revoke_node(network_id, _A_NODE_ID, reason="acceptance")
        await asyncio.sleep(3)
        revoked_prepare_failed = False
        try:
            await dynamic.prepare(_B_NODE_ID, context, ("get_node_summary",))
        except Exception:
            revoked_prepare_failed = True

        agent_server.should_exit = True
        admin_server.should_exit = True
        await asyncio.gather(*server_tasks)
        server_tasks.clear()
        coordinator_offline = not await _port_open(args.agent_host, args.agent_port)
        await asyncio.sleep(args.cache_ttl_seconds + 1)
        async with httpx.AsyncClient(timeout=5) as client:
            expired_status = (
                await client.get(
                    f"http://{args.b_host}:{args.b_gateway_port}/v1/capabilities",
                    headers={"Authorization": f"Bearer {assertion}"},
                )
            ).status_code

        static_report = runtime / "static-fallback.json"
        _run(
            [
                "uv",
                "run",
                "python",
                "scripts/run_ab_gateway_acceptance.py",
                "--endpoint",
                f"http://{args.b_host}:8787",
                "--local-node-id",
                str(_A_NODE_ID),
                "--remote-node-id",
                str(_B_NODE_ID),
                "--output",
                str(static_report),
            ],
            cwd=repo,
            timeout=180,
        )
        static_data = json.loads(static_report.read_text(encoding="utf-8"))
        evidence.update(
            {
                "registration_order": ["b", "a"],
                "remote_ready": ready,
                "enrollment_replay_status": replay_status,
                "managed_flow": {
                    "selected_tools": list(prepared.tools.tool_names),
                    "summary_tool_run_id": str(prepared.tools.summary_tool_run_id),
                    "listener_tool_run_id": str(listeners.tool_run_id),
                    "listener_status": listeners.status.value,
                    "node_summary_tool_run_id": str(node_summary.tool_run_id),
                    "node_summary_status": node_summary.status.value,
                    "selection": prepared.selection.model_dump(mode="json"),
                },
                "fault_matrix": {
                    "protocol_incompatible_status": incompatible_status,
                    "revoked_node_denied": revoked_prepare_failed,
                    "coordinator_offline": coordinator_offline,
                    "expired_cache_unauthenticated_status": expired_status,
                },
                "static_fallback": {
                    "endpoint": static_data["endpoint"],
                    "unauthenticated_status": static_data["unauthenticated_status"],
                    "tool_statuses": {
                        name: value["status"] for name, value in static_data["tool_results"].items()
                    },
                },
                "remote_pid": int(remote_pid),
            }
        )
    finally:
        if agent_server is not None:
            agent_server.should_exit = True
        if admin_server is not None:
            admin_server.should_exit = True
        if server_tasks:
            await asyncio.gather(*server_tasks, return_exceptions=True)
        if remote_root:
            if not remote_root.startswith("/tmp/tunnelminion-coordinator-ab."):
                raise RuntimeError("拒绝清理非隔离远端目录")
            _ssh(
                args.ssh_target,
                (
                    (f"kill {remote_pid} 2>/dev/null || true; " if remote_pid.isdigit() else "")
                    + f"rm -rf -- {remote_root}"
                ),
                cwd=repo,
            )
        after = _snapshot_b(args.b_host)
        evidence["after"] = after
        evidence["production_unchanged"] = {
            "model_8082": before.get("8082") is True and after.get("8082") is True,
            "gateway_8787": before.get("8787") is True and after.get("8787") is True,
            "temporary_18888_removed": after.get(str(args.b_gateway_port)) is False,
        }
        evidence["finished_at"] = datetime.now(UTC).isoformat()
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(
            json.dumps(evidence, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
    return evidence


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--ssh-target", required=True)
    parser.add_argument("--remote-python", default="/Users/mac/.local/bin/python3.12")
    parser.add_argument("--agent-host", default="10.77.0.2")
    parser.add_argument("--agent-port", type=int, default=8790)
    parser.add_argument("--admin-port", type=int, default=8791)
    parser.add_argument("--b-host", default="10.77.0.1")
    parser.add_argument("--b-gateway-port", type=int, default=18_888)
    parser.add_argument("--cache-ttl-seconds", type=int, default=8)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    report = asyncio.run(run_acceptance(args))
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
