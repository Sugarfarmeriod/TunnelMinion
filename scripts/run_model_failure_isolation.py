"""临时移除 A 节点模型配置，验证资源与 B 网关仍可用，并自动恢复配置。"""

from __future__ import annotations

import argparse
import asyncio
import json
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

import httpx
from pydantic import JsonValue

from tunnelminion.domain.identifiers import NodeId, RunId, ThreadId
from tunnelminion.domain.versioning import ProtocolVersion
from tunnelminion.gateway.client import FixedGatewayClient
from tunnelminion.gateway.configuration import gateway_token_name
from tunnelminion.model.secrets import KeyringSecretStore
from tunnelminion.tools.audit import InMemoryAuditSink
from tunnelminion.tools.contracts import ToolCallContext


def _object(response: httpx.Response) -> dict[str, JsonValue]:
    """读取已成功响应的 JSON 对象。"""
    response.raise_for_status()
    return cast(dict[str, JsonValue], response.json())


async def run_isolation(
    local_endpoint: str,
    remote_endpoint: str,
    local_node_id: NodeId,
    remote_node_id: NodeId,
) -> dict[str, JsonValue]:
    """执行故障注入、确定性资源检查、远端调用和配置恢复。"""
    token = KeyringSecretStore().get(gateway_token_name(remote_node_id))
    if token is None:
        raise RuntimeError("本机密钥环中没有该远端节点的 Gateway token")
    gateway_audit = InMemoryAuditSink()
    gateway = FixedGatewayClient(
        remote_endpoint,
        token,
        local_node_id,
        remote_node_id,
        gateway_audit,
    )
    async with httpx.AsyncClient(timeout=120) as client:
        original = _object(await client.get(f"{local_endpoint}/api/model-config"))
        if original.get("status") != "available":
            raise RuntimeError("A 节点模型在故障注入前不可用")
        if original.get("api_key_configured") is True:
            raise RuntimeError("脚本不会删除无法自动恢复的 API key 配置")
        endpoint = original.get("endpoint")
        model = original.get("model")
        timeout_seconds = original.get("timeout_seconds")
        if (
            not isinstance(endpoint, str)
            or not isinstance(model, str)
            or not isinstance(timeout_seconds, int | float)
        ):
            raise RuntimeError("A 节点模型配置不完整")

        deleted = False
        restored: dict[str, JsonValue] | None = None
        try:
            deletion = await client.delete(f"{local_endpoint}/api/model-config")
            deletion.raise_for_status()
            deleted = True
            degraded_model = _object(await client.get(f"{local_endpoint}/api/model-config"))
            availability = await client.post(f"{local_endpoint}/api/ai/runs/availability")
            resources = _object(await client.get(f"{local_endpoint}/api/resources/node-summary"))

            await gateway.discover()
            context = ToolCallContext(
                thread_id=ThreadId.new(),
                run_id=RunId.new(),
                caller_node_id=local_node_id,
                execution_node_id=remote_node_id,
            )
            remote = await gateway.call(
                "get_node_summary",
                ProtocolVersion(major=1, minor=0),
                context,
                {},
                15,
            )
        finally:
            if deleted:
                restored = _object(
                    await client.put(
                        f"{local_endpoint}/api/model-config",
                        json={
                            "endpoint": endpoint,
                            "model": model,
                            "timeout_seconds": timeout_seconds,
                        },
                    )
                )

        restored_availability = await client.post(f"{local_endpoint}/api/ai/runs/availability")
        remote_output = remote.output if isinstance(remote.output, dict) else {}
        resource_output = resources.get("output")
        resource_summary = resource_output if isinstance(resource_output, dict) else {}
        return {
            "schema_version": 1,
            "acceptance": "single-node-model-failure-isolation",
            "finished_at": datetime.now(UTC).isoformat(),
            "local_node_id": str(local_node_id),
            "remote_node_id": str(remote_node_id),
            "degraded_model_status": degraded_model.get("status"),
            "ai_run_status_during_failure": availability.status_code,
            "local_resource_http_status": 200,
            "local_resource_tool_status": resources.get("status"),
            "local_resource_model_status": resource_summary.get("model_status"),
            "remote_gateway_tool_status": remote.status.value,
            "remote_gateway_node_id": remote_output.get("node_id"),
            "restored_model_status": restored.get("status") if restored is not None else None,
            "ai_run_status_after_restore": restored_availability.status_code,
            "gateway_audit_records": [
                record.model_dump(mode="json") for record in gateway_audit.records
            ],
            "excluded_categories": [
                "model_api_key",
                "gateway_token",
                "authorization_header",
                "wireguard_private_key",
                "raw_resource_and_remote_tool_bodies",
            ],
        }


def main(argv: Sequence[str] | None = None) -> int:
    """解析真实节点参数并保存脱敏故障隔离报告。"""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--local-endpoint", default="http://127.0.0.1:8765")
    parser.add_argument("--remote-endpoint", required=True)
    parser.add_argument("--local-node-id", type=NodeId, required=True)
    parser.add_argument("--remote-node-id", type=NodeId, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    report = asyncio.run(
        run_isolation(
            args.local_endpoint,
            args.remote_endpoint,
            args.local_node_id,
            args.remote_node_id,
        )
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(report, ensure_ascii=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
