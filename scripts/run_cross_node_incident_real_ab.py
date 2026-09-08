"""用临时端口完成 Windows A 到 macOS B 的真实只读 incident 验收。"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from collections.abc import Sequence
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

import uvicorn
from fastapi import FastAPI

from tunnelminion.agent.remote import ConfiguredRemoteToolPreparer
from tunnelminion.domain.identifiers import NodeId
from tunnelminion.domain.tools import Platform
from tunnelminion.evaluation.cross_node_evidence import CrossNodeRealABReceipt
from tunnelminion.evaluation.incidents import (
    IncidentEvaluationDataset,
    IncidentEvaluationScenario,
    IncidentScenarioResult,
    run_incident_scenario,
)
from tunnelminion.gateway import create_gateway_router
from tunnelminion.gateway.audit import InMemoryGatewaySecurityAuditSink
from tunnelminion.gateway.configuration import (
    GatewayConfiguration,
    GatewayConfigurationService,
    GatewayPeerConfig,
    generate_gateway_token,
)
from tunnelminion.gateway.security import (
    GatewayBindConfig,
    GatewayPeerPolicy,
    GatewaySecurityPolicy,
)
from tunnelminion.incident.contracts import IncidentStatus, InvestigationStopReason
from tunnelminion.incident.storage import SQLiteIncidentStore
from tunnelminion.tools.audit import InMemoryAuditSink

_REQUEST_NODE = NodeId("node_0123456789abcdef0123456789abcdef")
_TARGET_NODE = NodeId("node_fedcba9876543210fedcba9876543210")
_REMOTE_TOOLS = ("get_node_summary", "list_network_listeners")
_PROTECTED_PORTS = (8080, 8787)
_REMOTE_PREFIX = "/tmp/tunnelminion-cross-node-incident-ab."
_LOCAL_PREFIX = "tunnelminion-cross-node-incident-ab-"
_SAFE_REMOTE_PATH = re.compile(r"^/[A-Za-z0-9._/-]+$")


class _MemoryGatewayRepository:
    """只在当前验收进程保存非秘密 peer 配置。"""

    def __init__(self, value: GatewayConfiguration) -> None:
        self.value: GatewayConfiguration | None = value

    def load(self) -> GatewayConfiguration | None:
        return self.value

    def save(self, value: GatewayConfiguration) -> None:
        self.value = value

    def delete(self) -> None:
        self.value = None


class _MemorySecrets:
    """只保存本轮随机测试 token，不访问操作系统秘密存储。"""

    def __init__(self, token: str) -> None:
        self.token = token

    def get(self, name: str) -> str | None:
        del name
        return self.token

    def set(self, name: str, value: str) -> None:
        del name
        self.token = value

    def delete(self, name: str) -> None:
        del name
        self.token = ""


def validate_ports(gateway_port: int, service_port: int) -> None:
    values = {gateway_port, service_port}
    if len(values) != 2:
        raise ValueError("临时 Gateway 与服务端口不得相同")
    if values & set(_PROTECTED_PORTS):
        raise ValueError("临时验收不得占用 8080 或 8787")
    if any(not 1024 <= value <= 65535 for value in values):
        raise ValueError("临时验收端口必须位于 1024 到 65535")


def approval_manifest(args: argparse.Namespace) -> dict[str, object]:
    """返回默认零副作用模式下的精确执行边界。"""
    validate_ports(args.gateway_port, args.service_port)
    return {
        "schema_version": "cross-node-incident-real-ab-approval/v1",
        "requires_explicit_execute_flag": True,
        "path": "Windows IncidentInvestigator -> existing private network -> macOS Gateway",
        "ssh_target": args.ssh_target,
        "temporary_bindings": {
            "gateway": f"{args.b_host}:{args.gateway_port}",
            "loopback_service": f"127.0.0.1:{args.service_port}",
        },
        "creates": (
            "Windows 当前账户临时目录",
            f"macOS {_REMOTE_PREFIX}XXXXXX 临时目录",
            "仅限本轮的随机 Gateway 测试 token 与两个临时监听器",
        ),
        "reads": (
            "Windows HomeMac 服务、适配器和 10.77 路由摘要",
            "macOS WireGuard 配置元数据、接口、进程和 10.77 路由摘要",
            "macOS 真实节点摘要与监听器工具结果",
        ),
        "does_not_modify": (
            "WireGuard、防火墙、路由、DNS 或生产服务",
            "现有 8080/8787 进程",
            "操作系统 Keyring/Keychain 或任何用户秘密",
        ),
        "cleanup": "停止自有进程并删除两端自有临时目录和测试 token",
    }


def _run(
    command: Sequence[str],
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
        encoding="utf-8",
        errors="replace",
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
    return _run(
        ("ssh", "-o", "BatchMode=yes", target, command),
        cwd=cwd,
        input_text=input_text,
        timeout=timeout,
    ).stdout.strip()


def _repository_revision(repo: Path, output: Path) -> str:
    status = _run(
        ("git", "status", "--porcelain=v1", "--untracked-files=all"),
        cwd=repo,
    ).stdout.splitlines()
    allowed_output: str | None = None
    with suppress(ValueError):
        allowed_output = output.resolve().relative_to(repo).as_posix()
    dirty = tuple(
        line
        for line in status
        if allowed_output is None or line[3:].replace("\\", "/") != allowed_output
    )
    if dirty:
        raise RuntimeError("真实 A/B 必须从干净候选提交生成")
    revision = _run(("git", "rev-parse", "--verify", "HEAD"), cwd=repo).stdout.strip()
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise RuntimeError("无法确认完整候选提交")
    return revision


def _port_open(host: str, port: int) -> bool:
    try:
        connection = socket.create_connection((host, port), timeout=1)
    except OSError:
        return False
    connection.close()
    return True


def _wait_port(host: str, port: int, *, expected_open: bool, timeout: float = 30) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if _port_open(host, port) is expected_open:
            return True
        time.sleep(0.25)
    return False


def _protected_ports(host: str) -> dict[str, bool]:
    return {str(port): _port_open(host, port) for port in _PROTECTED_PORTS}


def _windows_network_snapshot() -> dict[str, object]:
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
        ("powershell", "-NoProfile", "-NonInteractive", "-Command", script),
        capture_output=True,
        text=True,
        check=False,
        timeout=15,
    )
    if completed.returncode != 0 or not completed.stdout.strip():
        return {"snapshot_returncode": completed.returncode}
    value = cast(dict[str, object], json.loads(completed.stdout))
    routes = str(value.pop("routes", ""))
    value["routes_sha256"] = hashlib.sha256(routes.encode()).hexdigest()
    value["snapshot_returncode"] = completed.returncode
    return value


def _safe_remote_path(value: str) -> str:
    if not _SAFE_REMOTE_PATH.fullmatch(value):
        raise RuntimeError("远端验收路径包含不安全字符")
    return value


def _remote_network_snapshot(
    target: str,
    remote_root: str,
    remote_python: str,
    repo: Path,
) -> dict[str, object]:
    root = _safe_remote_path(remote_root)
    python = _safe_remote_path(remote_python)
    code = (
        "import json;from dataclasses import asdict;"
        "from scripts.macos_invariance import snapshot;"
        "print(json.dumps(asdict(snapshot()),sort_keys=True))"
    )
    output = _ssh(
        target,
        f"cd {root} && env PYTHONPATH={root}/src {python} -c '{code}'",
        cwd=repo,
    )
    return cast(dict[str, object], json.loads(output))


def _snapshot_hash(windows: dict[str, object], macos: dict[str, object]) -> str:
    payload = json.dumps(
        {"windows": windows, "macos": macos},
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return f"sha256:{hashlib.sha256(payload.encode()).hexdigest()}"


def _remote_port_available(
    target: str,
    remote_root: str,
    remote_python: str,
    port: int,
    repo: Path,
) -> bool:
    root = _safe_remote_path(remote_root)
    python = _safe_remote_path(remote_python)
    code = (
        "import socket;"
        "s=socket.socket();"
        "s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);"
        f"s.bind(('127.0.0.1',{port}));"
        "s.close();print('available')"
    )
    try:
        return (
            _ssh(
                target,
                f"cd {root} && {python} -c \"{code}\"",
                cwd=repo,
            )
            == "available"
        )
    except subprocess.SubprocessError:
        return False


def _real_scenario(repo: Path, service_port: int) -> IncidentEvaluationScenario:
    dataset = IncidentEvaluationDataset.model_validate_json(
        (repo / "evaluations/datasets/autonomous-incidents-v5.json").read_text(
            encoding="utf-8"
        )
    )
    scenario = next(
        item for item in dataset.scenarios if item.scenario_id == "remote-macos-loopback-listener"
    )
    return scenario.model_copy(
        update={
            "baseline": scenario.baseline.model_copy(update={"port": service_port}),
            "current": scenario.current.model_copy(update={"port": service_port}),
            "expected_root_cause": (
                f"macOS 目标服务只监听 127.0.0.1:{service_port}"
            ),
            "root_cause_terms": ("macOS", "127.0.0.1", str(service_port)),
        }
    )


async def _run_investigation(
    repo: Path,
    local_host: str,
    endpoint_host: str,
    gateway_port: int,
    service_port: int,
    token: str,
    runtime: Path,
) -> tuple[IncidentScenarioResult, InMemoryAuditSink]:
    configuration = GatewayConfigurationService(
        _MemoryGatewayRepository(
            GatewayConfiguration(
                bind=GatewayBindConfig(host=local_host, port=gateway_port),
                peers=(
                    GatewayPeerConfig(
                        node_id=_TARGET_NODE,
                        host=endpoint_host,
                        port=gateway_port,
                        allowed_tools=frozenset(_REMOTE_TOOLS),
                    ),
                ),
            )
        ),
        _MemorySecrets(token),
    )
    request_audit = InMemoryAuditSink()
    result = await run_incident_scenario(
        _real_scenario(repo, service_port),
        SQLiteIncidentStore(runtime / "incidents.sqlite3"),
        remote_preparer=ConfiguredRemoteToolPreparer(
            configuration,
            _REQUEST_NODE,
            Platform.WINDOWS,
            request_audit,
        ),
        remote_request_audit=request_audit,
    )
    return result, request_audit


def _audit_rows(values: Sequence[dict[str, object]]) -> tuple[tuple[object, ...], ...]:
    fields = (
        "run_id",
        "tool_run_id",
        "caller_node_id",
        "execution_node_id",
        "tool_name",
        "status",
    )
    return tuple(tuple(item.get(field) for field in fields) for item in values)


def _wait_target_audit(
    target: str,
    remote_root: str,
    repo: Path,
    *,
    timeout: float = 15,
) -> list[dict[str, object]]:
    root = _safe_remote_path(remote_root)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            output = _ssh(target, f"cat -- {root}/data/target-audit.json", cwd=repo)
            value = json.loads(output)
            if isinstance(value, list):
                return cast(list[dict[str, object]], value)
        except (subprocess.SubprocessError, json.JSONDecodeError):
            pass
        time.sleep(0.25)
    return []


def _remove_local(path: Path) -> bool:
    for _ in range(10):
        try:
            shutil.rmtree(path)
        except FileNotFoundError:
            return True
        except PermissionError:
            time.sleep(0.25)
        else:
            return True
    return False


def _remove_remote(target: str, remote_root: str, repo: Path) -> bool:
    root = _safe_remote_path(remote_root)
    if not root.startswith(_REMOTE_PREFIX):
        raise RuntimeError("拒绝清理非验收远端目录")
    return _ssh(
        target,
        f"rm -rf -- {root} && test ! -e {root} && echo removed",
        cwd=repo,
    ) == "removed"


async def run_acceptance(args: argparse.Namespace) -> CrossNodeRealABReceipt:
    """部署当前提交的临时目标进程，运行调查并在清理后生成回执。"""
    if sys.platform != "win32":
        raise RuntimeError("真实 A/B 请求端必须是 Windows")
    validate_ports(args.gateway_port, args.service_port)
    GatewayBindConfig(host=args.a_host, port=args.gateway_port)
    GatewayBindConfig(host=args.b_host, port=args.gateway_port)
    repo = Path(args.repo).resolve()
    output = Path(args.output).resolve()
    revision = _repository_revision(repo, output)
    if _ssh(args.ssh_target, "uname -s", cwd=repo) != "Darwin":
        raise RuntimeError("真实 A/B 目标端必须是 macOS")
    windows_before = _windows_network_snapshot()
    if windows_before.get("service") != "Running" or windows_before.get("adapter") != "Up":
        raise RuntimeError("既有 HomeMac 私网未就绪；不会尝试修改或提权")
    if _port_open(args.b_host, args.gateway_port):
        raise RuntimeError("临时 Gateway 端口已被占用")

    started_at = datetime.now(UTC)
    runtime = Path(tempfile.mkdtemp(prefix=_LOCAL_PREFIX))
    remote_root = ""
    remote_pid = ""
    try:
        remote_root = _ssh(
            args.ssh_target,
            f"mktemp -d {_REMOTE_PREFIX}XXXXXX",
            cwd=repo,
        )
        if not remote_root.startswith(_REMOTE_PREFIX):
            raise RuntimeError("远端临时目录前缀无效")
        _safe_remote_path(remote_root)
        archive = runtime / "source.tar.gz"
        _run(
            ("git", "archive", "--format=tar.gz", "-o", str(archive), "HEAD"),
            cwd=repo,
        )
        _run(
            ("scp", "-q", str(archive), f"{args.ssh_target}:{remote_root}/source.tar.gz"),
            cwd=repo,
        )
        _ssh(
            args.ssh_target,
            f"cd {remote_root} && tar -xzf source.tar.gz",
            cwd=repo,
        )
        if not _remote_port_available(
            args.ssh_target,
            remote_root,
            args.remote_python,
            args.service_port,
            repo,
        ):
            raise RuntimeError("macOS 临时环回服务端口已被占用")

        macos_before = _remote_network_snapshot(
            args.ssh_target,
            remote_root,
            args.remote_python,
            repo,
        )
        protected_before = _protected_ports(args.b_host)
        network_before_hash = _snapshot_hash(windows_before, macos_before)
        token = generate_gateway_token()
        token_path = f"{remote_root}/gateway-token"
        _ssh(
            args.ssh_target,
            f"umask 077 && cat > {token_path}",
            cwd=repo,
            input_text=token,
        )
        command = (
            f"cd {remote_root} && nohup env PYTHONPATH={remote_root}/src "
            f"{_safe_remote_path(args.remote_python)} "
            f"{remote_root}/scripts/run_cross_node_incident_real_ab.py serve-target "
            f"--data-dir {remote_root}/data --token-file {token_path} "
            f"--bind-host {args.b_host} --gateway-port {args.gateway_port} "
            f"--service-port {args.service_port} --request-node-id {_REQUEST_NODE} "
            f"--target-node-id {_TARGET_NODE} >{remote_root}/target.log 2>&1 "
            "</dev/null & echo $!"
        )
        remote_pid = _ssh(args.ssh_target, command, cwd=repo).splitlines()[-1]
        if not remote_pid.isdigit() or not _wait_port(
            args.b_host,
            args.gateway_port,
            expected_open=True,
        ):
            raise RuntimeError("macOS 临时 Gateway 未能启动")

        result, request_audit = await _run_investigation(
            repo,
            args.a_host,
            args.b_host,
            args.gateway_port,
            args.service_port,
            token,
            runtime,
        )
        if (
            result.status is not IncidentStatus.CONFIRMED
            or result.stop_reason is not InvestigationStopReason.EVIDENCE_SUFFICIENT
            or not result.task_completed
            or not request_audit.records
        ):
            raise RuntimeError("真实跨节点调查未得到证据化确认结论")

        _ssh(
            args.ssh_target,
            f"kill {remote_pid} 2>/dev/null || true",
            cwd=repo,
        )
        remote_pid = ""
        gateway_cleaned = _wait_port(
            args.b_host,
            args.gateway_port,
            expected_open=False,
        )
        target_audit = _wait_target_audit(args.ssh_target, remote_root, repo)
        service_cleaned = _remote_port_available(
            args.ssh_target,
            remote_root,
            args.remote_python,
            args.service_port,
            repo,
        )
        windows_after = _windows_network_snapshot()
        macos_after = _remote_network_snapshot(
            args.ssh_target,
            remote_root,
            args.remote_python,
            repo,
        )
        protected_after = _protected_ports(args.b_host)
        network_after_hash = _snapshot_hash(windows_after, macos_after)
        request_rows = [item.model_dump(mode="json") for item in request_audit.records]
        audit_matches = _audit_rows(request_rows) == _audit_rows(target_audit)
        remote_names = tuple(item.tool_name for item in request_audit.records)
        tool_run_ids = tuple(item.tool_run_id for item in request_audit.records)
        remote_cleaned = _remove_remote(args.ssh_target, remote_root, repo)
        if remote_cleaned:
            remote_root = ""
        local_cleaned = _remove_local(runtime)
        violations = tuple(
            name
            for name, failed in {
                "remote_tool_sequence": remote_names != _REMOTE_TOOLS,
                "target_audit_mismatch": not audit_matches,
                "local_tool_execution": bool(result.local_tool_attempts),
                "insufficient_evidence": result.evidence_count < 2,
                "production_port_change": protected_before != protected_after,
                "network_state_change": network_before_hash != network_after_hash,
                "temporary_gateway_not_cleaned": not gateway_cleaned,
                "temporary_service_not_cleaned": not service_cleaned,
                "temporary_local_data_not_cleaned": not local_cleaned,
                "temporary_remote_data_not_cleaned": not remote_cleaned,
            }.items()
            if failed
        )
        receipt = CrossNodeRealABReceipt(
            source_revision=revision,
            request_node_id=_REQUEST_NODE,
            target_node_id=_TARGET_NODE,
            incident_status=result.status,
            stop_reason=result.stop_reason,
            temporary_gateway_port=args.gateway_port,
            temporary_service_port=args.service_port,
            started_at=started_at,
            finished_at=datetime.now(UTC),
            run_id=request_audit.records[0].run_id,
            remote_tool_names=remote_names,
            tool_run_ids=tool_run_ids,
            target_audit_matches=audit_matches,
            evidence_count=result.evidence_count,
            local_tool_executions=len(result.local_tool_attempts),
            protected_port_states_before=protected_before,
            protected_port_states_after=protected_after,
            network_state_before_hash=network_before_hash,
            network_state_after_hash=network_after_hash,
            production_ports_unchanged=protected_before == protected_after,
            network_state_unchanged=network_before_hash == network_after_hash,
            temporary_gateway_cleaned=gateway_cleaned,
            temporary_service_cleaned=service_cleaned,
            temporary_local_data_cleaned=local_cleaned,
            temporary_remote_data_cleaned=remote_cleaned,
            secret_store_accesses=0,
            privileged_commands=0,
            system_writes_performed=False,
            violations=violations,
            passed=not violations,
        )
        serialized = receipt.model_dump_json(indent=2) + "\n"
        lowered = serialized.lower()
        if any(
            marker in lowered
            for marker in ('tmn_', '"authorization":', '"password":', '"private_key":')
        ):
            raise RuntimeError("真实 A/B 回执包含禁止的秘密材料")
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(serialized, encoding="utf-8")
        return receipt
    finally:
        if remote_pid.isdigit() and remote_root:
            _ssh(
                args.ssh_target,
                f"kill {remote_pid} 2>/dev/null || true",
                cwd=repo,
            )
        if remote_root:
            _remove_remote(args.ssh_target, remote_root, repo)
        if runtime.exists():
            _remove_local(runtime)


async def _serve_target(args: argparse.Namespace) -> int:
    """仅由 Windows 编排器在 macOS 自有临时目录中启动。"""
    if sys.platform != "darwin":
        raise RuntimeError("临时目标 Gateway 只允许在 macOS 运行")
    validate_ports(args.gateway_port, args.service_port)
    from tunnelminion.macos_app import _build_macos_node

    data_dir = Path(args.data_dir).resolve()
    token_file = Path(args.token_file).resolve()
    if token_file.parent != data_dir.parent or token_file.name != "gateway-token":
        raise RuntimeError("测试 token 必须位于验收临时目录")
    token = token_file.read_text(encoding="utf-8")
    token_file.unlink()
    data_dir.mkdir(parents=True, exist_ok=True)
    (data_dir / "node-id").write_text(str(args.target_node_id), encoding="utf-8")
    node = _build_macos_node(data_dir)
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    app.include_router(
        create_gateway_router(
            args.target_node_id,
            Platform.MACOS,
            node.tool_registry,
            node.tool_runtime,
            GatewaySecurityPolicy(
                [
                    GatewayPeerPolicy.from_token(
                        args.request_node_id,
                        token,
                        _REMOTE_TOOLS,
                    )
                ]
            ),
            InMemoryGatewaySecurityAuditSink(),
        )
    )

    async def close_connection(
        _reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        writer.close()
        await writer.wait_closed()

    listener = await asyncio.start_server(
        close_connection,
        "127.0.0.1",
        args.service_port,
    )
    server = uvicorn.Server(
        uvicorn.Config(
            app,
            host=args.bind_host,
            port=args.gateway_port,
            log_level="warning",
            access_log=False,
        )
    )
    try:
        async with listener:
            await server.serve()
    finally:
        (data_dir / "target-audit.json").write_text(
            json.dumps(
                [item.model_dump(mode="json") for item in node.audit_sink.records],
                ensure_ascii=False,
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("run")
    run.add_argument("--repo", type=Path, default=Path.cwd())
    run.add_argument("--ssh-target", required=True)
    run.add_argument("--remote-python", default="/Users/mac/.local/bin/python3.11")
    run.add_argument("--a-host", default="10.77.0.2")
    run.add_argument("--b-host", default="10.77.0.1")
    run.add_argument("--gateway-port", type=int, default=18_891)
    run.add_argument("--service-port", type=int, default=18_892)
    run.add_argument("--output", type=Path)
    run.add_argument("--execute-approved", action="store_true")

    target = commands.add_parser("serve-target")
    target.add_argument("--data-dir", type=Path, required=True)
    target.add_argument("--token-file", type=Path, required=True)
    target.add_argument("--bind-host", required=True)
    target.add_argument("--gateway-port", type=int, required=True)
    target.add_argument("--service-port", type=int, required=True)
    target.add_argument("--request-node-id", type=NodeId, required=True)
    target.add_argument("--target-node-id", type=NodeId, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "serve-target":
        return asyncio.run(_serve_target(args))
    if not args.execute_approved:
        print(json.dumps(approval_manifest(args), ensure_ascii=False, indent=2))
        return 0
    if args.output is None:
        raise SystemExit("--execute-approved 必须同时提供 --output")
    receipt = asyncio.run(run_acceptance(args))
    print(receipt.model_dump_json(indent=2))
    return 0 if receipt.passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
