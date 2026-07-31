"""用常规 Windows/macOS 入口执行受显式批准约束的真实 A/B 验收。"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import shutil
import socket
import subprocess
import sys
import tempfile
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

import httpx
import uvicorn

from tunnelminion.agent.managed_node import (
    MANAGED_NODE_CONFIG_FILE,
    FileManagedNodeConfigRepository,
    ManagedNodeConfig,
    ManagedNodeSecretStoreKind,
    ServiceObservationConfig,
)
from tunnelminion.app import build_windows_application
from tunnelminion.coordinator.app import (
    CoordinatorAdminBindConfig,
    CoordinatorAgentBindConfig,
    CoordinatorApplicationConfig,
    build_coordinator_applications,
)
from tunnelminion.coordinator.contracts import EnrollmentTokenRequest, GatewayEndpoint
from tunnelminion.coordinator.directory import CoordinatorDirectoryService
from tunnelminion.coordinator.identity import AssertionService, SigningKeyService
from tunnelminion.coordinator.network_control import ManagedNetworkControlService
from tunnelminion.coordinator.registry import CoordinatorRegistryService, SQLiteCoordinatorStore
from tunnelminion.domain.identifiers import NetworkId, NodeId
from tunnelminion.domain.tools import Platform
from tunnelminion.model.secrets import RestrictedFileSecretStore

_A_NODE_ID = NodeId("node_129841509f55473d8d9d3ca363850204")
_B_NODE_ID = NodeId("node_406913ccf29f4774a908c0435dbe8c5b")
_REMOTE_PREFIX = "/tmp/tunnelminion-managed-runtime-ab."
_LOCAL_PREFIX = "tunnelminion-managed-runtime-ab-"


def approval_manifest(args: argparse.Namespace) -> dict[str, object]:
    """返回不执行任何外部动作的精确授权面。"""
    return {
        "schema_version": "managed-node-runtime-ab-approval/v1",
        "requires_explicit_execute_flag": True,
        "ssh_target": args.ssh_target,
        "temporary_bindings": {
            "coordinator_agent": f"{args.agent_host}:{args.agent_port}",
            "coordinator_admin": f"127.0.0.1:{args.admin_port}",
            "windows_local_app": f"127.0.0.1:{args.a_local_port}",
            "macos_local_app": f"127.0.0.1:{args.b_local_port}",
        },
        "creates": (
            "A 当前账户临时目录及 restricted-file 测试凭据",
            f"B {_REMOTE_PREFIX}XXXXXX 临时目录及 restricted-file 测试凭据",
            "隔离 Coordinator network/node/enrollment/checkpoint 数据",
            "A/B 常规本地应用临时进程",
        ),
        "reads_without_body": (
            "Windows WireGuardTunnel$HomeMac 服务与 HomeMac 适配器状态",
            "Windows 10.77 路由摘要哈希",
            "macOS WireGuard 配置文件元数据、接口与 10.77 路由摘要哈希",
            "macOS Application Firewall/pf 只读输出哈希",
            "B 生产模型 8082 与 Gateway 8787 端口可达性",
        ),
        "evidence_limitations": (
            "Murus 规则正文无法由非交互仓库适配器可靠读取；报告只保存 PF 与 macOS "
            "Application Firewall 的可观察状态哈希和读取返回码",
            "验收流程不调用 Murus、pfctl 写入、socketfilterfw 写入或任何防火墙配置命令",
        ),
        "does_not_modify": (
            "HomeMac 或 B 手写 WireGuard 配置",
            "Murus、Windows/macOS 防火墙、pf、DNS 或用户 route",
            "生产 Gateway 8787、模型 8082 或现有 static peer",
            "任何 Provider/L3 网络资源或本机授权",
        ),
        "cleanup": (
            "停止 A/B 常规本地应用和隔离 Coordinator",
            "删除前缀校验后的 A/B 临时目录和测试凭据",
            "保存脱敏 JSON 报告，不保存 token、refresh、认证头或配置正文",
        ),
    }


def _run(
    command: list[str],
    *,
    cwd: Path,
    input_text: str | None = None,
    timeout: int = 300,
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
    timeout: int = 300,
) -> str:
    completed = _run(
        ["ssh", "-o", "BatchMode=yes", target, command],
        cwd=cwd,
        input_text=input_text,
        timeout=timeout,
    )
    return completed.stdout.strip()


async def _wait_json(
    url: str,
    predicate: Callable[[dict[str, object]], bool],
    *,
    timeout: float = 90,
) -> dict[str, object]:
    deadline = asyncio.get_running_loop().time() + timeout
    async with httpx.AsyncClient(timeout=3) as client:
        while asyncio.get_running_loop().time() < deadline:
            try:
                response = await client.get(url)
                if response.status_code == 200:
                    value = cast(dict[str, object], response.json())
                    if predicate(value):
                        return value
            except (httpx.RequestError, ValueError):
                pass
            await asyncio.sleep(0.5)
    raise TimeoutError(f"等待本地资源状态超时：{url}")


async def _start_server(
    app: Any,
    host: str,
    port: int,
    ready_url: str,
) -> tuple[uvicorn.Server, asyncio.Task[None]]:
    server = uvicorn.Server(
        uvicorn.Config(app, host=host, port=port, log_level="warning", access_log=False)
    )
    task = asyncio.create_task(server.serve())

    def any_json(_value: dict[str, object]) -> bool:
        return True

    await _wait_json(ready_url, any_json, timeout=30)
    return server, task


async def _stop_server(
    server: uvicorn.Server | None,
    task: asyncio.Task[None] | None,
) -> None:
    if server is not None:
        server.should_exit = True
    if task is not None:
        await asyncio.gather(task, return_exceptions=True)


def _port_open(host: str, port: int) -> bool:
    try:
        connection = socket.create_connection((host, port), timeout=1)
    except OSError:
        return False
    connection.close()
    return True


def _production_ports(host: str) -> dict[str, bool]:
    return {
        "model_8082": _port_open(host, 8082),
        "gateway_8787": _port_open(host, 8787),
    }


def preflight_failure_reasons(
    windows: dict[str, object],
    production_ports: dict[str, bool],
) -> tuple[str, ...]:
    reasons: list[str] = []
    if windows.get("service") != "Running":
        reasons.append("windows_home_mac_service_not_running")
    if windows.get("adapter") != "Up":
        reasons.append("windows_home_mac_adapter_not_up")
    if production_ports.get("model_8082") is not True:
        reasons.append("macos_model_8082_not_reachable")
    if production_ports.get("gateway_8787") is not True:
        reasons.append("macos_gateway_8787_not_reachable")
    return tuple(reasons)


def _windows_snapshot() -> dict[str, object]:
    script = (
        "$ErrorActionPreference='SilentlyContinue';"
        "$s=(Get-Service -Name 'WireGuardTunnel$HomeMac').Status.ToString();"
        "$a=(Get-NetAdapter -Name 'HomeMac').Status;"
        "$r=Get-NetRoute | Where-Object {$_.DestinationPrefix -like '10.77.*'} | "
        "Select-Object DestinationPrefix,InterfaceIndex,NextHop,RouteMetric | "
        "Sort-Object DestinationPrefix,InterfaceIndex,NextHop,RouteMetric | "
        "ConvertTo-Json -Compress;"
        "[pscustomobject]@{service=$s;adapter=$a;routes=$r}|ConvertTo-Json -Compress"
    )
    completed = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True,
        text=True,
        check=False,
        timeout=15,
    )
    value = (
        cast(dict[str, object], json.loads(completed.stdout))
        if completed.returncode == 0 and completed.stdout.strip()
        else {}
    )
    routes = str(value.pop("routes", ""))
    value["routes_sha256"] = hashlib.sha256(routes.encode()).hexdigest()
    value["snapshot_returncode"] = completed.returncode
    return value


def _macos_snapshot(target: str, remote_root: str, repo: Path) -> dict[str, object]:
    command = (
        f"cd {remote_root} && env PYTHONPATH={remote_root}/src:{remote_root}/.deps "
        f"{remote_root}/.deps/bin/python -c '"
        "import hashlib,json,subprocess;"
        "from dataclasses import asdict;"
        "from scripts.macos_invariance import snapshot;"
        "s=asdict(snapshot());"
        'fw=subprocess.run(["/usr/libexec/ApplicationFirewall/socketfilterfw",'
        '"--getglobalstate"],capture_output=True,text=True);'
        'pf=subprocess.run(["/sbin/pfctl","-sr"],capture_output=True,text=True);'
        'print(json.dumps({"wireguard_state_sha256":hashlib.sha256('
        "json.dumps(s,sort_keys=True).encode()).hexdigest(),"
        '"firewall_sha256":hashlib.sha256(fw.stdout.encode()).hexdigest(),'
        '"firewall_returncode":fw.returncode,'
        '"pf_sha256":hashlib.sha256(pf.stdout.encode()).hexdigest(),'
        '"pf_returncode":pf.returncode,'
        '"interface_count":len(s["interfaces"])}))\''
    )
    return cast(dict[str, object], json.loads(_ssh(target, command, cwd=repo)))


def _remote_json(
    target: str, remote_root: str, port: int, path: str, repo: Path
) -> dict[str, object]:
    url = f"http://127.0.0.1:{port}{path}"
    command = (
        f"cd {remote_root} && env PYTHONPATH={remote_root}/src:{remote_root}/.deps "
        f"{remote_root}/.deps/bin/python -c 'import urllib.request;"
        f'print(urllib.request.urlopen("{url}",timeout=3).read().decode())\''
    )
    return cast(dict[str, object], json.loads(_ssh(target, command, cwd=repo)))


async def _wait_remote_ready(
    target: str,
    remote_root: str,
    port: int,
    repo: Path,
    *,
    offline: bool = False,
) -> dict[str, object]:
    deadline = asyncio.get_running_loop().time() + 90
    while asyncio.get_running_loop().time() < deadline:
        try:
            value = await asyncio.to_thread(
                _remote_json,
                target,
                remote_root,
                port,
                "/api/resources/managed-node",
                repo,
            )
            enrollment = cast(dict[str, object], value.get("enrollment", {}))
            directory = cast(dict[str, object], value.get("directory", {}))
            managed_config = cast(dict[str, object], value.get("managed_config", {}))
            if offline:
                if directory.get("phase") == "backoff" and managed_config.get("phase") in {
                    "backoff",
                    "stale",
                }:
                    return value
            elif (
                enrollment.get("state") == "ready"
                and directory.get("last_success_at") is not None
                and managed_config.get("last_success_at") is not None
            ):
                return value
        except (subprocess.SubprocessError, ValueError):
            pass
        await asyncio.sleep(1)
    raise TimeoutError("等待 macOS 常规 managed node 状态超时")


def _managed_config(
    *,
    network_id: NetworkId,
    node_id: NodeId,
    platform: Platform,
    coordinator_endpoint: str,
    gateway_host: str,
    fingerprint: str,
) -> ManagedNodeConfig:
    return ManagedNodeConfig(
        coordinator_endpoint=coordinator_endpoint,
        network_id=network_id,
        node_id=node_id,
        display_name=f"{platform.value} regular-entry acceptance",
        platform=platform,
        gateway_endpoint=GatewayEndpoint(host=gateway_host, port=8787),
        pinned_fingerprints=frozenset({fingerprint}),
        secret_store=ManagedNodeSecretStoreKind.RESTRICTED_FILE,
        sync_interval_seconds=1,
        base_backoff_seconds=0.2,
        max_backoff_seconds=2,
        cache_ttl_seconds=8,
        services=ServiceObservationConfig(interval_seconds=5, timeout_seconds=3),
    )


def _public_status(value: dict[str, object]) -> dict[str, object]:
    """只保留验收需要的状态字段，拒绝把远端正文原样写入报告。"""
    enrollment = cast(dict[str, object], value.get("enrollment", {}))
    runtime = cast(dict[str, object], value.get("runtime", {}))
    directory = cast(dict[str, object], value.get("directory", {}))
    services = cast(dict[str, object], value.get("services", {}))
    managed_config = cast(dict[str, object], value.get("managed_config", {}))
    return {
        "enrollment_state": enrollment.get("state"),
        "runtime_phase": runtime.get("phase"),
        "directory_phase": directory.get("phase"),
        "directory_revision": directory.get("server_revision"),
        "service_count": services.get("service_count"),
        "managed_config_phase": managed_config.get("phase"),
        "managed_config_applied_revision": managed_config.get("applied_revision"),
        "last_known_good_revision": value.get("last_known_good_revision"),
    }


async def run_acceptance(args: argparse.Namespace) -> dict[str, object]:
    repo = Path(args.repo).resolve()
    output = Path(args.output).resolve()
    runtime = Path(tempfile.mkdtemp(prefix=_LOCAL_PREFIX))
    if not runtime.name.startswith(_LOCAL_PREFIX):
        raise RuntimeError("本地验收目录前缀无效")
    remote_root = ""
    remote_pid = ""
    agent_server: uvicorn.Server | None = None
    agent_task: asyncio.Task[None] | None = None
    admin_server: uvicorn.Server | None = None
    admin_task: asyncio.Task[None] | None = None
    local_server: uvicorn.Server | None = None
    local_task: asyncio.Task[None] | None = None
    evidence: dict[str, object] = {
        "schema_version": "managed-node-runtime-real-ab/v1",
        "started_at": datetime.now(UTC).isoformat(),
        "approval_manifest": approval_manifest(args),
    }
    try:
        preflight_windows = _windows_snapshot()
        preflight_ports = _production_ports(args.b_host)
        preflight_reasons = preflight_failure_reasons(preflight_windows, preflight_ports)
        evidence["preflight"] = {
            "windows": preflight_windows,
            "production_ports": preflight_ports,
            "passed": not preflight_reasons,
            "failure_reasons": preflight_reasons,
        }
        if preflight_reasons:
            evidence["automated_passed"] = False
            evidence["passed"] = False
            return evidence

        store = SQLiteCoordinatorStore(runtime / "coordinator.sqlite3")
        registry = CoordinatorRegistryService(store)
        network_id = NetworkId.new()
        registry.create_network(network_id)
        signing = SigningKeyService(
            store,
            RestrictedFileSecretStore(runtime / "signing-secrets"),
        )
        key = signing.rotate()
        assertions = AssertionService(registry, signing)
        directory = CoordinatorDirectoryService(store, registry)
        network_control = ManagedNetworkControlService(store, signing)
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
            network_control=network_control,
        )
        agent_server, agent_task = await _start_server(
            applications.agent_app,
            args.agent_host,
            args.agent_port,
            f"http://{args.agent_host}:{args.agent_port}/api/v1/agent/health",
        )
        admin_server, admin_task = await _start_server(
            applications.admin_app,
            "127.0.0.1",
            args.admin_port,
            f"http://127.0.0.1:{args.admin_port}/api/v1/admin/health",
        )

        remote_root = await asyncio.to_thread(
            _ssh,
            args.ssh_target,
            f"mktemp -d {_REMOTE_PREFIX}XXXXXX",
            cwd=repo,
        )
        if not remote_root.startswith(_REMOTE_PREFIX):
            raise RuntimeError("远端验收目录前缀无效")
        archive = runtime / "source.tar.gz"
        await asyncio.to_thread(
            _run,
            ["git", "archive", "--format=tar.gz", "-o", str(archive), "HEAD"],
            cwd=repo,
        )
        await asyncio.to_thread(
            _run,
            ["scp", "-q", str(archive), f"{args.ssh_target}:{remote_root}/source.tar.gz"],
            cwd=repo,
        )
        await asyncio.to_thread(
            _ssh,
            args.ssh_target,
            (
                f"cd {remote_root} && tar -xzf source.tar.gz && "
                f"{args.remote_python} -m venv .deps && "
                f"{remote_root}/.deps/bin/python -m pip install --quiet ."
            ),
            cwd=repo,
            timeout=600,
        )
        before = {
            "windows": _windows_snapshot(),
            "macos": await asyncio.to_thread(_macos_snapshot, args.ssh_target, remote_root, repo),
            "production_ports": _production_ports(args.b_host),
        }
        evidence["before"] = before

        endpoint = f"http://{args.agent_host}:{args.agent_port}"
        a_root = runtime / "a"
        a_root.mkdir()
        (a_root / "node-id").write_text(str(_A_NODE_ID), encoding="utf-8")
        a_config = _managed_config(
            network_id=network_id,
            node_id=_A_NODE_ID,
            platform=Platform.WINDOWS,
            coordinator_endpoint=endpoint,
            gateway_host=args.agent_host,
            fingerprint=key.fingerprint,
        )
        FileManagedNodeConfigRepository(a_root / MANAGED_NODE_CONFIG_FILE).save(a_config)
        b_config = _managed_config(
            network_id=network_id,
            node_id=_B_NODE_ID,
            platform=Platform.MACOS,
            coordinator_endpoint=endpoint,
            gateway_host=args.b_host,
            fingerprint=key.fingerprint,
        )
        await asyncio.to_thread(
            _ssh,
            args.ssh_target,
            (
                f"cd {remote_root} && mkdir -p data && umask 077 && "
                f"printf '%s\\n' '{_B_NODE_ID}' > data/node-id && "
                "cat > data/managed-node.json"
            ),
            cwd=repo,
            input_text=b_config.model_dump_json(indent=2),
        )

        b_token = registry.create_enrollment_token(EnrollmentTokenRequest(network_id=network_id))
        await asyncio.to_thread(
            _ssh,
            args.ssh_target,
            (
                f"cd {remote_root} && env PYTHONPATH={remote_root}/src:{remote_root}/.deps "
                f"{remote_root}/.deps/bin/python -m tunnelminion coordinator-enroll "
                f"--data-dir {remote_root}/data"
            ),
            cwd=repo,
            input_text=b_token.token,
        )
        a_token = registry.create_enrollment_token(EnrollmentTokenRequest(network_id=network_id))
        await asyncio.to_thread(
            _run,
            [
                sys.executable,
                "-m",
                "tunnelminion",
                "coordinator-enroll",
                "--data-dir",
                str(a_root),
            ],
            cwd=repo,
            input_text=a_token.token,
        )

        remote_pid = await asyncio.to_thread(
            _ssh,
            args.ssh_target,
            (
                f"cd {remote_root} && nohup env PYTHONPATH={remote_root}/src:{remote_root}/.deps "
                f"{remote_root}/.deps/bin/python -m tunnelminion --data-dir {remote_root}/data "
                f"--port {args.b_local_port} >managed-local.log 2>&1 & echo $!"
            ),
            cwd=repo,
        )
        if not remote_pid.isdigit():
            raise RuntimeError("远端常规应用 PID 无效")
        local_application = build_windows_application(a_root)
        local_server, local_task = await _start_server(
            local_application.app,
            "127.0.0.1",
            args.a_local_port,
            f"http://127.0.0.1:{args.a_local_port}/api/resources/managed-node",
        )

        def converged(value: dict[str, object]) -> bool:
            enrollment = cast(dict[str, object], value.get("enrollment", {}))
            directory_status = cast(dict[str, object], value.get("directory", {}))
            managed_config = cast(dict[str, object], value.get("managed_config", {}))
            return (
                enrollment.get("state") == "ready"
                and directory_status.get("last_success_at") is not None
                and managed_config.get("last_success_at") is not None
            )

        a_ready = await _wait_json(
            f"http://127.0.0.1:{args.a_local_port}/api/resources/managed-node",
            converged,
        )
        b_ready = await _wait_remote_ready(args.ssh_target, remote_root, args.b_local_port, repo)
        async with httpx.AsyncClient(timeout=3) as client:
            a_model = cast(
                dict[str, object],
                (await client.get(f"http://127.0.0.1:{args.a_local_port}/api/model-config")).json(),
            )
        b_model = await asyncio.to_thread(
            _remote_json,
            args.ssh_target,
            remote_root,
            args.b_local_port,
            "/api/model-config",
            repo,
        )
        evidence["converged"] = {
            "windows": _public_status(a_ready),
            "macos": _public_status(b_ready),
            "model_status": {
                "windows": a_model.get("status"),
                "macos": b_model.get("status"),
            },
        }

        await _stop_server(agent_server, agent_task)
        agent_server = None
        agent_task = None
        await _stop_server(admin_server, admin_task)
        admin_server = None
        admin_task = None

        def offline(value: dict[str, object]) -> bool:
            directory_status = cast(dict[str, object], value.get("directory", {}))
            managed_config = cast(dict[str, object], value.get("managed_config", {}))
            return directory_status.get("phase") == "backoff" and managed_config.get("phase") in {
                "backoff",
                "stale",
            }

        a_offline = await _wait_json(
            f"http://127.0.0.1:{args.a_local_port}/api/resources/managed-node",
            offline,
        )
        b_offline = await _wait_remote_ready(
            args.ssh_target,
            remote_root,
            args.b_local_port,
            repo,
            offline=True,
        )
        evidence["coordinator_offline"] = {
            "windows": _public_status(a_offline),
            "macos": _public_status(b_offline),
            "windows_local_resources_available": True,
            "macos_local_resources_available": True,
        }

        await _stop_server(local_server, local_task)
        local_server = None
        local_task = None
        await asyncio.to_thread(
            _ssh,
            args.ssh_target,
            f"kill {remote_pid} 2>/dev/null || true; sleep 2",
            cwd=repo,
        )
        remote_pid = ""
        after = {
            "windows": _windows_snapshot(),
            "macos": await asyncio.to_thread(_macos_snapshot, args.ssh_target, remote_root, repo),
            "production_ports": _production_ports(args.b_host),
        }
        evidence["after"] = after
        before_windows = cast(dict[str, object], before["windows"])
        before_macos = cast(dict[str, object], before["macos"])
        before_ports = cast(dict[str, object], before["production_ports"])
        interface_count = before_macos.get("interface_count")
        production_baseline_valid = (
            before_windows.get("service") == "Running"
            and before_windows.get("adapter") == "Up"
            and isinstance(interface_count, int)
            and interface_count > 0
            and before_ports.get("model_8082") is True
            and before_ports.get("gateway_8787") is True
        )
        automated_passed = (
            before == after
            and production_baseline_valid
            and a_model.get("status") == "unconfigured"
            and b_model.get("status") == "unconfigured"
        )
        after_macos = cast(dict[str, object], after["macos"])
        evidence["production_unchanged"] = before == after
        evidence["production_baseline_valid"] = production_baseline_valid
        evidence["murus_firewall_evidence"] = {
            "configuration_body_read": False,
            "writes_performed": False,
            "direct_pf_rules_readable": before_macos.get("pf_returncode") == 0
            and after_macos.get("pf_returncode") == 0,
            "pf_observation_unchanged": before_macos.get("pf_sha256")
            == after_macos.get("pf_sha256")
            and before_macos.get("pf_returncode") == after_macos.get("pf_returncode"),
            "application_firewall_observation_unchanged": before_macos.get("firewall_sha256")
            == after_macos.get("firewall_sha256")
            and before_macos.get("firewall_returncode") == after_macos.get("firewall_returncode"),
            "limitation": "Murus 规则正文没有非交互读取权限，不声称读取或导出了 GUI 配置",
        }
        evidence["automated_passed"] = automated_passed
        evidence["passed"] = automated_passed
    finally:
        await _stop_server(local_server, local_task)
        await _stop_server(agent_server, agent_task)
        await _stop_server(admin_server, admin_task)
        if remote_root:
            if not remote_root.startswith(_REMOTE_PREFIX):
                raise RuntimeError("拒绝清理非验收远端目录")
            cleanup = (
                f"kill {remote_pid} 2>/dev/null || true; " if remote_pid.isdigit() else ""
            ) + f"rm -rf -- {remote_root}"
            await asyncio.to_thread(_ssh, args.ssh_target, cleanup, cwd=repo)
        if runtime.name.startswith(_LOCAL_PREFIX):
            shutil.rmtree(runtime, ignore_errors=True)
        evidence["finished_at"] = datetime.now(UTC).isoformat()
        serialized = json.dumps(evidence, ensure_ascii=False, indent=2) + "\n"
        lowered = serialized.lower()
        forbidden = ("tmne_", "tmnr_", "authorization:", "bearer ", "private_key")
        if any(item in lowered for item in forbidden):
            raise RuntimeError("真实 A/B 报告包含禁止秘密字段")
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(serialized, encoding="utf-8")
    return evidence


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--ssh-target", required=True)
    parser.add_argument("--remote-python", default="/Users/mac/.local/bin/python3.12")
    parser.add_argument("--agent-host", default="10.77.0.2")
    parser.add_argument("--agent-port", type=int, default=8790)
    parser.add_argument("--admin-port", type=int, default=8791)
    parser.add_argument("--a-local-port", type=int, default=18_765)
    parser.add_argument("--b-host", default="10.77.0.1")
    parser.add_argument("--b-local-port", type=int, default=18_765)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--execute-approved", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if not args.execute_approved:
        print(json.dumps(approval_manifest(args), ensure_ascii=False, indent=2))
        return 0
    if args.output is None:
        raise SystemExit("--execute-approved 必须同时提供 --output")
    report = asyncio.run(run_acceptance(args))
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report.get("automated_passed") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
