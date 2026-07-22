"""通过真实 WireGuard Gateway 运行六个 macOS 只读工具并保存脱敏报告。"""

from __future__ import annotations

import argparse
import asyncio
import json
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from time import perf_counter

import httpx
from pydantic import JsonValue

from tunnelminion.domain.identifiers import NodeId, RunId, ThreadId
from tunnelminion.domain.versioning import ProtocolVersion
from tunnelminion.gateway.client import FixedGatewayClient
from tunnelminion.gateway.configuration import gateway_token_name
from tunnelminion.model.secrets import KeyringSecretStore
from tunnelminion.tools.audit import InMemoryAuditSink
from tunnelminion.tools.contracts import ToolCallContext

_VERSION = ProtocolVersion(major=1, minor=0)
_TOOL_ARGUMENTS: tuple[tuple[str, dict[str, JsonValue]], ...] = (
    ("get_wireguard_status", {}),
    ("list_network_listeners", {}),
    ("get_process_summary", {"limit": 20}),
    ("list_docker_services", {}),
    ("probe_service_reachability", {"host": "10.77.0.1", "port": 8082}),
    ("get_node_summary", {}),
)


def _summary(name: str, output: JsonValue | None) -> JsonValue:
    """只保留演示需要的计数与状态，不保存进程、端口和容器正文。"""
    if not isinstance(output, dict):
        return None
    if name in {"list_network_listeners", "get_process_summary", "list_docker_services"}:
        items = output.get("items")
        return {
            "availability": output.get("availability"),
            "item_count": len(items) if isinstance(items, list) else 0,
            "error_code": output.get("error_code"),
        }
    if name == "get_wireguard_status":
        peers = output.get("peers")
        addresses = output.get("addresses")
        return {
            "availability": output.get("availability"),
            "interface": output.get("interface"),
            "interface_up": output.get("interface_up"),
            "address_count": len(addresses) if isinstance(addresses, list) else 0,
            "peer_count": len(peers) if isinstance(peers, list) else 0,
            "error_code": output.get("error_code"),
        }
    if name == "probe_service_reachability":
        return {
            key: output.get(key)
            for key in ("host", "port", "reachable", "latency_ms", "error_code")
        }
    wireguard = output.get("wireguard")
    tools = output.get("available_tools")
    return {
        "node_id": output.get("node_id"),
        "platform": output.get("platform"),
        "agent_status": output.get("agent_status"),
        "model_status": output.get("model_status"),
        "wireguard_availability": (
            wireguard.get("availability") if isinstance(wireguard, dict) else None
        ),
        "available_tool_count": len(tools) if isinstance(tools, list) else 0,
    }


async def run_acceptance(
    endpoint: str,
    local_node_id: NodeId,
    remote_node_id: NodeId,
) -> dict[str, JsonValue]:
    """认证发现能力并逐个调用六个固定只读工具。"""
    token = KeyringSecretStore().get(gateway_token_name(remote_node_id))
    if token is None:
        raise RuntimeError("本机密钥环中没有该远端节点的 Gateway token")
    audit = InMemoryAuditSink()
    client = FixedGatewayClient(endpoint, token, local_node_id, remote_node_id, audit)
    async with httpx.AsyncClient(timeout=10) as unauthenticated:
        unauthenticated_status = (
            await unauthenticated.get(f"{endpoint}/v1/capabilities")
        ).status_code

    started_at = datetime.now(UTC)
    started = perf_counter()
    capabilities = await client.discover()
    context = ToolCallContext(
        thread_id=ThreadId.new(),
        run_id=RunId.new(),
        caller_node_id=local_node_id,
        execution_node_id=remote_node_id,
    )
    results: dict[str, JsonValue] = {}
    for name, arguments in _TOOL_ARGUMENTS:
        result = await client.call(name, _VERSION, context, arguments, 15)
        results[name] = {
            "status": result.status.value,
            "tool_run_id": str(result.tool_run_id),
            "truncated": result.truncated,
            "error_code": result.error.code.value if result.error is not None else None,
            "summary": _summary(name, result.output),
        }

    return {
        "schema_version": 1,
        "acceptance": "windows-a-to-macos-b-real-gateway",
        "started_at": started_at.isoformat(),
        "finished_at": datetime.now(UTC).isoformat(),
        "elapsed_ms": round((perf_counter() - started) * 1000, 2),
        "endpoint": endpoint,
        "local_node_id": str(local_node_id),
        "remote_node_id": str(remote_node_id),
        "unauthenticated_status": unauthenticated_status,
        "protocol": capabilities.protocol.model_dump(mode="json"),
        "platform": capabilities.platform.value,
        "capabilities": [tool.name for tool in capabilities.tools],
        "tool_results": results,
        "a_audit_records": [record.model_dump(mode="json") for record in audit.records],
        "excluded_categories": [
            "gateway_token",
            "authorization_header",
            "wireguard_private_key",
            "process_and_listener_bodies",
            "container_bodies",
        ],
    }


def main(argv: Sequence[str] | None = None) -> int:
    """解析真实 A/B 节点参数并写入脱敏 JSON。"""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--endpoint", required=True)
    parser.add_argument("--local-node-id", type=NodeId, required=True)
    parser.add_argument("--remote-node-id", type=NodeId, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    report = asyncio.run(run_acceptance(args.endpoint, args.local_node_id, args.remote_node_id))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
