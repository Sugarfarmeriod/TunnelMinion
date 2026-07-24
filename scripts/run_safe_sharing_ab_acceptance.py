"""在真实 A/B 节点提交或执行临时 HTTP 共享，并输出脱敏验收证据。"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import secrets
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from time import perf_counter
from typing import cast

import httpx
import uvicorn
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import Response
from pydantic import JsonValue

from tunnelminion.agent.diagnostics import (
    CrossNodeDiagnosticAgent,
    CrossNodeDiagnosticWorkflow,
)
from tunnelminion.agent.planning import CandidateOperationPlanner, CandidatePlanIntent
from tunnelminion.agent.remote import RemoteCapabilityLoader
from tunnelminion.app import build_windows_application
from tunnelminion.domain.identifiers import NodeId, RunId, ThreadId
from tunnelminion.domain.tools import Platform
from tunnelminion.gateway.client import FixedGatewayClient
from tunnelminion.gateway.contracts import RequesterVerificationCallback
from tunnelminion.gateway.operations import (
    GatewayRequesterVerifier,
    RequesterVerificationConfig,
    create_requester_verification_router,
)
from tunnelminion.model.openai_compatible import (
    OpenAICompatibleConfig,
    OpenAICompatibleProvider,
)
from tunnelminion.operation.contracts import (
    LeaseRecord,
    OperationPlan,
    OperationStatus,
    VerificationRecord,
)
from tunnelminion.operation.workflow import RequesterVerifier
from tunnelminion.tools.audit import InMemoryAuditSink
from tunnelminion.tools.contracts import ToolCallContext

_TOKEN_ENV = "TUNNELMINION_GATEWAY_TOKEN"


def _token() -> str:
    value = os.environ.get(_TOKEN_ENV)
    if value is None or len(value) < 43:
        raise RuntimeError(f"必须通过环境变量 {_TOKEN_ENV} 提供高熵临时网关凭据")
    return value


async def _model_name(endpoint: str) -> str:
    async with httpx.AsyncClient(timeout=10, trust_env=False) as client:
        response = await client.get(f"{endpoint.rstrip('/')}/models")
        response.raise_for_status()
    body = cast(JsonValue, response.json())
    data = body.get("data") if isinstance(body, dict) else None
    if not isinstance(data, list) or not data or not isinstance(data[0], dict):
        raise RuntimeError("真实模型端点没有返回可用模型")
    model = data[0].get("id")
    if not isinstance(model, str) or not model:
        raise RuntimeError("真实模型端点缺少模型标识")
    return model


def _write_local_node_id(data_dir: Path, node_id: NodeId) -> None:
    data_dir.mkdir(parents=True, exist_ok=True)
    path = data_dir / "node-id"
    if path.exists() and path.read_text(encoding="utf-8").strip() != str(node_id):
        raise RuntimeError("验收数据目录已属于其他节点")
    path.write_text(str(node_id), encoding="utf-8")


async def submit(
    *,
    endpoint: str,
    model_endpoint: str,
    local_node_id: NodeId,
    remote_node_id: NodeId,
    local_data_dir: Path,
    service_port: int,
    bind_port: int,
    duration_seconds: int,
) -> dict[str, JsonValue]:
    """运行真实只读诊断和模型候选计划，并提交到 B 等待本地授权。"""
    _write_local_node_id(local_data_dir, local_node_id)
    application = build_windows_application(local_data_dir)
    audit = InMemoryAuditSink()
    client = FixedGatewayClient(
        endpoint,
        _token(),
        local_node_id,
        remote_node_id,
        audit,
    )
    provider_model = await _model_name(model_endpoint)
    provider = OpenAICompatibleProvider(
        OpenAICompatibleConfig(
            endpoint=model_endpoint,
            model=provider_model,
            timeout_seconds=120,
        )
    )
    workflow = CrossNodeDiagnosticWorkflow(
        RemoteCapabilityLoader(client, Platform.WINDOWS, remote_node_id),
        application.tool_runtime,
        local_node_id,
    )
    agent = CrossNodeDiagnosticAgent(
        workflow,
        provider,
        CandidateOperationPlanner(
            provider,
            provider_name="openai-compatible",
            model_name=provider_model,
        ),
    )
    context = ToolCallContext(
        thread_id=ThreadId.new(),
        run_id=RunId.new(),
        caller_node_id=local_node_id,
        execution_node_id=remote_node_id,
    )
    started = perf_counter()
    answer = await agent.answer(
        "请让 Windows A 临时访问 macOS B 的隔离 HTTP fixture。",
        context,
        "10.77.0.1",
        port=service_port,
        plan_intent=CandidatePlanIntent(
            confirmed=True,
            service_port=service_port,
            bind_host="10.77.0.1",
            bind_port=bind_port,
            duration_seconds=duration_seconds,
        ),
    )
    if answer.candidate_plan is None:
        raise RuntimeError(f"候选计划生成失败：{answer.plan_error_code}")
    remote = await client.submit_operation(answer.candidate_plan)
    diagnostic = next(
        (
            item
            for item in (answer.report.diagnostics if answer.report is not None else ())
            if item.service.port == service_port
        ),
        None,
    )
    return {
        "schema_version": 1,
        "phase": "submit",
        "recorded_at": datetime.now(UTC).isoformat(),
        "elapsed_ms": round((perf_counter() - started) * 1000, 2),
        "operation_id": str(answer.candidate_plan.operation_id),
        "status": remote.summary.status.value,
        "plan": answer.candidate_plan.model_dump(mode="json"),
        "diagnostic": (
            {
                "port": diagnostic.service.port,
                "address": diagnostic.service.address,
                "accessibility": diagnostic.service.accessibility.value,
                "reachability": diagnostic.reachability.value,
                "evidence_tool_run_ids": [str(item.tool_run_id) for item in diagnostic.evidence],
            }
            if diagnostic is not None
            else None
        ),
        "model_error_code": answer.model_error_code,
        "plan_error_code": answer.plan_error_code,
        "model_usage": (
            answer.model_usage.model_dump(mode="json") if answer.model_usage is not None else None
        ),
        "plan_trace": (
            answer.plan_trace.model_dump(mode="json") if answer.plan_trace is not None else None
        ),
        "audit_record_count": len(audit.records),
        "excluded_categories": [
            "gateway_token",
            "authorization_header",
            "temporary_share_token",
            "raw_process_and_container_bodies",
        ],
    }


class _CapturingVerifier(RequesterVerifier):
    """验证时把临时凭据只保留在 A 的进程内存中。"""

    def __init__(self, delegate: RequesterVerifier) -> None:
        self._delegate = delegate
        self.access_token: str | None = None

    async def verify(
        self,
        plan: OperationPlan,
        lease: LeaseRecord,
        access_token: str,
    ) -> VerificationRecord:
        self.access_token = access_token
        return await self._delegate.verify(plan, lease, access_token)


def _browser_bridge(plan: OperationPlan, verifier: _CapturingVerifier) -> FastAPI:
    """创建只绑定 A 环回地址的短期浏览器桥，不在 URL 中暴露凭据。"""
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    @app.get("/{path:path}")
    async def proxy(  # pyright: ignore[reportUnusedFunction]
        path: str,
        request: Request,
    ) -> Response:
        token = verifier.access_token
        if token is None:
            raise HTTPException(503, "共享凭据尚未由请求节点验证")
        suffix = f"/{path}" if path else "/"
        async with httpx.AsyncClient(timeout=5, trust_env=False) as client:
            response = await client.get(
                f"http://{plan.access_scope.bind_host}:{plan.access_scope.bind_port}{suffix}",
                params=request.query_params,
                headers={"X-TunnelMinion-Share-Token": token},
            )
        return Response(
            content=response.content,
            status_code=response.status_code,
            media_type=response.headers.get("content-type"),
        )

    return app


async def _serve(app: FastAPI, host: str, port: int) -> tuple[uvicorn.Server, asyncio.Task[None]]:
    server = uvicorn.Server(
        uvicorn.Config(app, host=host, port=port, log_level="warning", access_log=False)
    )
    task = asyncio.create_task(server.serve())
    for _ in range(100):
        if server.started:
            return server, task
        await asyncio.sleep(0.05)
    server.should_exit = True
    await task
    raise RuntimeError(f"临时验收服务未能监听 {host}:{port}")


async def execute(
    *,
    endpoint: str,
    local_node_id: NodeId,
    remote_node_id: NodeId,
    plan: OperationPlan,
    callback_port: int,
    browser_port: int,
    wait_for_expiry: bool,
) -> dict[str, JsonValue]:
    """由 A 提供验证回调，执行共享、走环回浏览器桥并可等待自动到期。"""
    client = FixedGatewayClient(
        endpoint,
        _token(),
        local_node_id,
        remote_node_id,
        InMemoryAuditSink(),
    )
    delegate = GatewayRequesterVerifier(
        RequesterVerificationConfig(
            allowed_target_addresses=frozenset({plan.access_scope.bind_host})
        )
    )
    verifier = _CapturingVerifier(delegate)
    callback_token = secrets.token_urlsafe(32)
    callback_app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    callback_app.include_router(
        create_requester_verification_router(
            local_node_id=local_node_id,
            target_node_id=remote_node_id,
            callback_token=callback_token,
            verifier=verifier,
        )
    )
    callback_server, callback_task = await _serve(callback_app, "10.77.0.2", callback_port)
    browser_server: uvicorn.Server | None = None
    browser_task: asyncio.Task[None] | None = None
    started = perf_counter()
    try:
        result = await client.execute_operation(
            plan,
            verification_callback=RequesterVerificationCallback(
                endpoint=f"http://10.77.0.2:{callback_port}",
                token=callback_token,
                timeout_seconds=10,
            ),
        )
        if result.summary.status is not OperationStatus.SUCCEEDED:
            raise RuntimeError(f"操作未成功：{result.summary.status.value}")
        browser_server, browser_task = await _serve(
            _browser_bridge(plan, verifier), "127.0.0.1", browser_port
        )
        async with httpx.AsyncClient(timeout=5, trust_env=False) as browser:
            browser_response = await browser.get(f"http://127.0.0.1:{browser_port}/")
        final = result
        if wait_for_expiry:
            deadline = asyncio.get_running_loop().time() + plan.access_scope.duration_seconds + 8
            while asyncio.get_running_loop().time() < deadline:
                final = await client.get_operation(plan.operation_id)
                if final.summary.status in {
                    OperationStatus.EXPIRED,
                    OperationStatus.CLEANUP_FAILED,
                }:
                    break
                await asyncio.sleep(0.5)
        return {
            "schema_version": 1,
            "phase": "execute",
            "recorded_at": datetime.now(UTC).isoformat(),
            "elapsed_ms": round((perf_counter() - started) * 1000, 2),
            "operation_id": str(plan.operation_id),
            "execution_status": result.summary.status.value,
            "final_status": final.summary.status.value,
            "verification_results": [item.value for item in result.summary.verification_results],
            "browser_bridge_status": browser_response.status_code,
            "browser_bridge_bytes": len(browser_response.content),
            "lease_expired": final.summary.status is OperationStatus.EXPIRED,
            "temporary_credential_retained_in_memory_only": verifier.access_token is not None,
            "excluded_categories": [
                "gateway_token",
                "callback_token",
                "temporary_share_token",
                "authorization_header",
                "browser_response_body",
            ],
        }
    finally:
        callback_server.should_exit = True
        if browser_server is not None:
            browser_server.should_exit = True
        await callback_task
        if browser_task is not None:
            await browser_task


def _write_report(path: Path, value: dict[str, JsonValue]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(value, ensure_ascii=False, indent=2))


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    submit_parser = subparsers.add_parser("submit")
    submit_parser.add_argument("--endpoint", required=True)
    submit_parser.add_argument("--model-endpoint", required=True)
    submit_parser.add_argument("--local-node-id", type=NodeId, required=True)
    submit_parser.add_argument("--remote-node-id", type=NodeId, required=True)
    submit_parser.add_argument("--local-data-dir", type=Path, required=True)
    submit_parser.add_argument("--service-port", type=int, default=18880)
    submit_parser.add_argument("--bind-port", type=int, required=True)
    submit_parser.add_argument("--duration-seconds", type=int, default=15)
    submit_parser.add_argument("--output", type=Path, required=True)

    execute_parser = subparsers.add_parser("execute")
    execute_parser.add_argument("--endpoint", required=True)
    execute_parser.add_argument("--local-node-id", type=NodeId, required=True)
    execute_parser.add_argument("--remote-node-id", type=NodeId, required=True)
    execute_parser.add_argument("--plan-report", type=Path, required=True)
    execute_parser.add_argument("--callback-port", type=int, default=18900)
    execute_parser.add_argument("--browser-port", type=int, default=18901)
    execute_parser.add_argument("--wait-for-expiry", action="store_true")
    execute_parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)

    if args.command == "submit":
        report = asyncio.run(
            submit(
                endpoint=args.endpoint,
                model_endpoint=args.model_endpoint,
                local_node_id=args.local_node_id,
                remote_node_id=args.remote_node_id,
                local_data_dir=args.local_data_dir,
                service_port=args.service_port,
                bind_port=args.bind_port,
                duration_seconds=args.duration_seconds,
            )
        )
    else:
        payload = json.loads(args.plan_report.read_text(encoding="utf-8"))
        report = asyncio.run(
            execute(
                endpoint=args.endpoint,
                local_node_id=args.local_node_id,
                remote_node_id=args.remote_node_id,
                plan=OperationPlan.model_validate(payload["plan"]),
                callback_port=args.callback_port,
                browser_port=args.browser_port,
                wait_for_expiry=args.wait_for_expiry,
            )
        )
    _write_report(args.output, report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
