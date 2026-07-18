"""在真实 macOS 节点验证六个工具不会改变现有 WireGuard 状态。"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import subprocess
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import cast

from pydantic import JsonValue

from tunnelminion.domain.identifiers import RunId, ThreadId
from tunnelminion.macos_app import build_macos_local_application
from tunnelminion.platforms.macos.system import default_wg_path
from tunnelminion.tools.contracts import ToolCallContext, ToolExecutionRequest


@dataclass(frozen=True)
class MacOSWireGuardSnapshot:
    """不含私钥、配置正文和易变流量计数的状态指纹。"""

    config_metadata: tuple[str, ...]
    processes: tuple[str, ...]
    interfaces: tuple[str, ...]
    interface_state: tuple[str, ...]
    managed_routes: tuple[str, ...]


def _run(command: tuple[str, ...]) -> str:
    completed = subprocess.run(command, check=False, capture_output=True, text=True, timeout=10)
    return completed.stdout if completed.returncode == 0 else ""


def _config_metadata() -> tuple[str, ...]:
    """只比较文件身份、大小和时间，不读取可能含私钥的正文。"""
    roots = (Path("/opt/homebrew/etc/wireguard"), Path("/usr/local/etc/wireguard"))
    values: list[str] = []
    for root in roots:
        if not root.exists():
            continue
        for path in sorted(root.glob("*.conf")):
            metadata = path.stat()
            values.append(
                f"{path}:{metadata.st_size}:{metadata.st_mtime_ns}:{metadata.st_mode & 0o777:o}"
            )
    return tuple(values)


def _normalized_interface_state(interface: str) -> str:
    lines = _run(("ifconfig", interface)).splitlines()
    stable = tuple(
        line.strip()
        for line in lines
        if line.startswith(interface + ":") or line.lstrip().startswith(("inet ", "inet6 ", "mtu "))
    )
    digest = hashlib.sha256("\n".join(stable).encode()).hexdigest()
    return f"{interface}:{digest}"


def snapshot() -> MacOSWireGuardSnapshot:
    """采集足以发现配置、接口、路由或终端进程变化的安全快照。"""
    wg_path = default_wg_path()
    interfaces = tuple(_run((wg_path, "show", "interfaces")).split())
    process_rows = _run(("ps", "-axo", "pid=,comm=")).splitlines()
    processes = tuple(
        sorted(
            " ".join(row.split())
            for row in process_rows
            if "wireguard" in row.lower() or "wg-quick" in row.lower()
        )
    )
    route_rows = _run(("netstat", "-rn", "-f", "inet")).splitlines()
    managed_routes = tuple(
        sorted(
            " ".join(row.split())
            for row in route_rows
            if "10.77." in row or any(interface in row for interface in interfaces)
        )
    )
    return MacOSWireGuardSnapshot(
        config_metadata=_config_metadata(),
        processes=processes,
        interfaces=interfaces,
        interface_state=tuple(_normalized_interface_state(item) for item in interfaces),
        managed_routes=managed_routes,
    )


async def execute_all_tools(probe_host: str, probe_port: int) -> tuple[dict[str, str], ...]:
    """通过真实 macOS Runtime 依次执行完整只读工具序列。"""
    with tempfile.TemporaryDirectory(prefix="tunnelminion-invariance-") as directory:
        bundle = build_macos_local_application(Path(directory))
        context = ToolCallContext(
            thread_id=ThreadId.new(),
            run_id=RunId.new(),
            caller_node_id=bundle.node.node_id,
            execution_node_id=bundle.node.node_id,
        )
        calls: tuple[tuple[str, dict[str, JsonValue]], ...] = (
            ("get_wireguard_status", {}),
            ("list_network_listeners", {}),
            ("get_process_summary", {"limit": 50}),
            ("list_docker_services", {}),
            (
                "probe_service_reachability",
                {"host": probe_host, "port": probe_port, "timeout_seconds": 1.0},
            ),
            ("get_node_summary", {}),
        )
        results: list[dict[str, str]] = []
        for name, arguments in calls:
            result = await bundle.node.tool_runtime.execute(
                ToolExecutionRequest(
                    context=context,
                    tool_name=name,
                    arguments=arguments,
                )
            )
            results.append(
                {
                    "tool": name,
                    "tool_run_id": str(result.tool_run_id),
                    "status": result.status.value,
                    "error_code": "" if result.error is None else result.error.code.value,
                }
            )
        return tuple(results)


def main() -> int:
    """执行工具并输出可保存为真机验收证据的脱敏 JSON。"""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--probe-host", default="10.77.0.2")
    parser.add_argument("--probe-port", type=int, default=8082)
    args = parser.parse_args()
    before = snapshot()
    tools = asyncio.run(execute_all_tools(cast(str, args.probe_host), cast(int, args.probe_port)))
    after = snapshot()
    unchanged = before == after
    print(
        json.dumps(
            {
                "platform": "macos",
                "unchanged": unchanged,
                "before": asdict(before),
                "after": asdict(after),
                "tools": tools,
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0 if unchanged else 1


if __name__ == "__main__":
    raise SystemExit(main())
