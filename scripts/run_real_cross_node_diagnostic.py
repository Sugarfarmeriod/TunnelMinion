"""通过真实 A/B 节点运行跨节点服务发现，并保存可复现的脱敏报告。"""

from __future__ import annotations

import argparse
import asyncio
import json
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

from pydantic import JsonValue

from tunnelminion.agent.diagnostics import CrossNodeDiagnosticAgent, CrossNodeDiagnosticWorkflow
from tunnelminion.agent.remote import RemoteCapabilityLoader
from tunnelminion.agent.services import CrossNodeServiceDiagnostic
from tunnelminion.app import build_windows_application
from tunnelminion.domain.identifiers import NodeId, RunId, ThreadId
from tunnelminion.domain.tools import Platform
from tunnelminion.gateway.client import FixedGatewayClient
from tunnelminion.gateway.configuration import gateway_token_name
from tunnelminion.model.secrets import KeyringSecretStore
from tunnelminion.tools.audit import InMemoryAuditSink
from tunnelminion.tools.contracts import ToolCallContext


def _diagnostic_summary(value: CrossNodeServiceDiagnostic) -> dict[str, JsonValue]:
    """保留服务归属、可达性与证据 ID，不保存远端原始工具正文。"""
    service = value.service
    return {
        "protocol": service.protocol,
        "address": service.address,
        "port": service.port,
        "process_name": service.process_name,
        "container_name": service.container_name,
        "image": service.image,
        "container_port": service.container_port,
        "accessibility": service.accessibility.value,
        "confidence": service.confidence.value,
        "reachability": value.reachability.value,
        "explanation": value.explanation,
        "evidence_tool_run_ids": [str(entry.tool_run_id) for entry in value.evidence],
    }


async def run_diagnostic(
    endpoint: str,
    remote_node_id: NodeId,
    target_host: str,
    question: str,
    port: int | None,
    data_dir: Path | None,
) -> dict[str, JsonValue]:
    """使用 A 的真实模型、工具和密钥环认证信息完成一次诊断。"""
    application = build_windows_application(data_dir)
    token = KeyringSecretStore().get(gateway_token_name(remote_node_id))
    if token is None:
        raise RuntimeError("本机密钥环中没有该远端节点的 Gateway token")
    gateway_audit = InMemoryAuditSink()
    client = FixedGatewayClient(
        endpoint,
        token,
        application.node_id,
        remote_node_id,
        gateway_audit,
    )
    workflow = CrossNodeDiagnosticWorkflow(
        RemoteCapabilityLoader(client, Platform.WINDOWS, remote_node_id),
        application.tool_runtime,
        application.node_id,
    )
    agent = CrossNodeDiagnosticAgent(workflow, application.model_service.create_provider())
    context = ToolCallContext(
        thread_id=ThreadId.new(),
        run_id=RunId.new(),
        caller_node_id=application.node_id,
        execution_node_id=remote_node_id,
    )
    started_at = datetime.now(UTC)
    answer = await agent.answer(question, context, target_host, port=port)
    report = answer.report
    return {
        "schema_version": 1,
        "acceptance": "windows-a-to-macos-b-cross-node-diagnostic",
        "started_at": started_at.isoformat(),
        "finished_at": datetime.now(UTC).isoformat(),
        "endpoint": endpoint,
        "target_host": target_host,
        "local_node_id": str(application.node_id),
        "remote_node_id": str(remote_node_id),
        "question": question,
        "selected_port": port,
        "answer": answer.answer,
        "model_error_code": answer.model_error_code,
        "remote_error_code": answer.remote_error_code,
        "elapsed_ms": round(answer.elapsed_ms, 2),
        "model_usage": (
            answer.model_usage.model_dump(mode="json") if answer.model_usage is not None else None
        ),
        "node_summary_tool_run_id": (
            str(report.node_summary_tool_run_id) if report is not None else None
        ),
        "unavailable_sources": (
            list(report.inventory.unavailable_sources) if report is not None else []
        ),
        "diagnostics": (
            [_diagnostic_summary(item) for item in report.diagnostics] if report is not None else []
        ),
        "a_gateway_audit_records": [
            record.model_dump(mode="json") for record in gateway_audit.records
        ],
        "excluded_categories": [
            "gateway_token",
            "authorization_header",
            "wireguard_private_key",
            "remote_listener_process_and_container_raw_bodies",
            "model_api_key",
        ],
    }


def main(argv: Sequence[str] | None = None) -> int:
    """解析真实双机参数并写入脱敏 JSON。"""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--endpoint", required=True)
    parser.add_argument("--remote-node-id", type=NodeId, required=True)
    parser.add_argument("--target-host", required=True)
    parser.add_argument("--question", required=True)
    parser.add_argument("--port", type=int)
    parser.add_argument("--data-dir", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    report = asyncio.run(
        run_diagnostic(
            args.endpoint,
            args.remote_node_id,
            args.target_host,
            args.question,
            args.port,
            args.data_dir,
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
