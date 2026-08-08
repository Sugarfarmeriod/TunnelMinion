"""为 Playwright 启动使用隔离数据目录的真实本机 FastAPI 应用。"""

from __future__ import annotations

import argparse
import sys
from datetime import UTC, datetime
from pathlib import Path
from tempfile import TemporaryDirectory

import uvicorn
from fastapi import FastAPI

from stage_frontend import stage_frontend
from tunnelminion.app import build_windows_application
from tunnelminion.domain.identifiers import NodeId, OperationId, RunId, ThreadId, ToolRunId
from tunnelminion.macos_app import build_macos_local_application
from tunnelminion.operation.contracts import (
    AccessScope,
    OperationLevel,
    OperationPlan,
    OperationRecord,
    OperationStatus,
    ServiceEvidence,
    compute_idempotency_key,
    transition_operation,
)
from tunnelminion.web.operations import OperationControlService

E2E_OPERATION_ID = OperationId(f"operation_{'1' * 32}")


def seed_operation(service: OperationControlService, target_node_id: NodeId) -> OperationId:
    """写入一条脱敏待审批记录，供真实浏览器验收详情和确认框。"""
    now = datetime.now(UTC)
    request_node_id = NodeId(f"node_{'2' * 32}")
    access_scope = AccessScope(
        allowed_peer_id=request_node_id,
        bind_host="10.77.0.1",
        bind_port=18_881,
        duration_seconds=300,
    )
    plan = OperationPlan(
        operation_id=E2E_OPERATION_ID,
        plan_version=1,
        idempotency_key=compute_idempotency_key(
            request_node_id=request_node_id,
            target_node_id=target_node_id,
            tool_name="share_local_http_service",
            plan_version=1,
            service_fingerprint=f"sha256:{'3' * 64}",
            access_scope=access_scope,
        ),
        request_node_id=request_node_id,
        target_node_id=target_node_id,
        thread_id=ThreadId(f"thread_{'4' * 32}"),
        run_id=RunId(f"run_{'5' * 32}"),
        tool_run_ids=(ToolRunId(f"toolrun_{'6' * 32}"),),
        tool_name="share_local_http_service",
        level=OperationLevel.L2,
        service=ServiceEvidence(
            service_id="playwright-dashboard",
            scheme="http",
            host="127.0.0.1",
            port=8080,
            process_or_container="isolated-browser-fixture",
            fingerprint=f"sha256:{'3' * 64}",
            observed_at=now,
        ),
        expected_change="创建仅供指定测试节点访问的临时入口",
        access_scope=access_scope,
        risk_summary="指定测试节点可在五分钟内访问脱敏示例服务",
        verification_method="请求节点沿真实路径发起 HTTP 探测",
        rollback_method="停止自有代理并确认测试端口释放",
        created_at=now,
    )
    record = transition_operation(
        OperationRecord.planned(plan),
        OperationStatus.AWAITING_AUTHORIZATION,
        reason="等待目标节点本地用户批准",
        occurred_at=now,
    )
    service.operations.put(record)
    return E2E_OPERATION_ID


def build_application(data_dir: Path) -> FastAPI:
    """按当前验收平台装配与产品入口相同的 FastAPI 应用。"""
    if sys.platform == "darwin":
        application = build_macos_local_application(data_dir)
        seed_operation(application.operation_control_service, application.node.node_id)
        return application.app
    application = build_windows_application(data_dir)
    seed_operation(application.operation_control_service, application.node_id)
    return application.app


def main() -> int:
    """暂存生产前端并在环回地址启动隔离的验收服务器。"""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=4174)
    args = parser.parse_args()

    repository = Path(__file__).resolve().parents[1]
    stage_frontend(
        repository / "frontend" / "dist",
        repository / "build" / "frontend-dist",
    )
    with TemporaryDirectory(prefix="tunnelminion-playwright-") as temporary:
        application = build_application(Path(temporary))
        uvicorn.run(
            application,
            host=args.host,
            port=args.port,
            log_level="warning",
            access_log=False,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
