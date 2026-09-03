"""为正式运行包浏览器验收生成隔离、无秘密的本机数据。"""

from __future__ import annotations

import argparse
import asyncio
import gc
import hashlib
import json
import sqlite3
import sys
from collections.abc import Generator, Sequence
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

from pydantic import JsonValue

if __package__:
    from scripts.security_scan import scan_files
else:
    from security_scan import scan_files

import tunnelminion.app as windows_app
import tunnelminion.macos_app as macos_app
from tunnelminion.domain.identifiers import NodeId, OperationId, RunId, ThreadId, ToolRunId
from tunnelminion.evaluation.incidents import (
    IncidentEvaluationDataset,
    run_incident_scenario,
)
from tunnelminion.incident.storage import SQLiteIncidentStore
from tunnelminion.memory.contracts import MemoryKind, MemoryNamespace
from tunnelminion.memory.service import (
    LongTermMemoryService,
    MemoryCandidate,
    MemoryCandidateOrigin,
)
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

FIXTURE_SCHEMA = "local-product-package-fixture/v1"
FIXTURE_OPERATION_ID = OperationId(f"operation_{'1' * 32}")
INCIDENT_DATASET = (
    Path(__file__).resolve().parents[1]
    / "evaluations"
    / "datasets"
    / "autonomous-incidents-v1.json"
)
ALLOWED_DATA_FILES = frozenset({"incidents.sqlite3", "node-id", "runtime.sqlite3"})


class RejectingSecretStore:
    """任何密钥环访问都会让验收夹具立即失败。"""

    def get(self, name: str) -> str | None:
        raise RuntimeError(f"验收夹具禁止读取秘密：{name}")

    def set(self, name: str, value: str) -> None:
        del value
        raise RuntimeError(f"验收夹具禁止写入秘密：{name}")

    def delete(self, name: str) -> None:
        raise RuntimeError(f"验收夹具禁止删除秘密：{name}")


@contextmanager
def rejecting_product_keyrings() -> Generator[None]:
    """只在应用工厂组装期间把产品密钥环替换为拒绝实现。"""
    original_windows = windows_app.KeyringSecretStore
    original_macos = macos_app.KeyringSecretStore
    windows_app.KeyringSecretStore = RejectingSecretStore  # type: ignore[assignment]
    macos_app.KeyringSecretStore = RejectingSecretStore  # type: ignore[assignment]
    try:
        yield
    finally:
        windows_app.KeyringSecretStore = original_windows  # type: ignore[assignment]
        macos_app.KeyringSecretStore = original_macos  # type: ignore[assignment]


def seed_operation(service: OperationControlService, target_node_id: NodeId) -> OperationId:
    """写入一条脱敏待审批记录，供正式包验证详情与确认框。"""
    now = datetime.now(UTC)
    request_node_id = NodeId(f"node_{'2' * 32}")
    access_scope = AccessScope(
        allowed_peer_id=request_node_id,
        bind_host="10.77.0.1",
        bind_port=18_881,
        duration_seconds=300,
    )
    plan = OperationPlan(
        operation_id=FIXTURE_OPERATION_ID,
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
            service_id="package-acceptance-dashboard",
            scheme="http",
            host="127.0.0.1",
            port=8080,
            process_or_container="isolated-package-fixture",
            fingerprint=f"sha256:{'3' * 64}",
            observed_at=now,
        ),
        expected_change="创建仅供指定测试节点访问的临时入口",
        access_scope=access_scope,
        risk_summary="指定测试节点可在五分钟内访问脱敏示例服务",
        verification_method="请求节点沿隔离验收路径发起 HTTP 探测",
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
    return FIXTURE_OPERATION_ID


def seed_memories(service: LongTermMemoryService, node_id: NodeId) -> tuple[MemoryNamespace, ...]:
    """写入两个不同网络作用域，证明正式包不会串读或串删记忆。"""
    namespaces = (
        MemoryNamespace(user="acceptance-user", network="home", node_id=node_id),
        MemoryNamespace(user="acceptance-user", network="lab", node_id=node_id),
    )
    candidates = (
        MemoryCandidate(
            namespace=namespaces[0],
            kind=MemoryKind.PREFERENCE,
            content="总览优先显示家庭网络中的本机服务",
            source="隔离正式包验收",
            origin=MemoryCandidateOrigin.USER_STATEMENT,
            user_confirmed=True,
        ),
        MemoryCandidate(
            namespace=namespaces[1],
            kind=MemoryKind.SECURITY_CONSTRAINT,
            content="实验网络只允许只读诊断",
            source="隔离正式包验收",
            origin=MemoryCandidateOrigin.USER_STATEMENT,
            user_confirmed=True,
        ),
    )
    for candidate in candidates:
        service.save_confirmed(candidate)
    return namespaces


async def seed_incident(path: Path) -> dict[str, JsonValue]:
    """复用固定矩阵写入一个可供 Overview 展示的离线调查。"""
    dataset = IncidentEvaluationDataset.model_validate_json(
        INCIDENT_DATASET.read_text(encoding="utf-8")
    )
    scenarios = {item.scenario_id: item for item in dataset.scenarios}
    store = SQLiteIncidentStore(path)
    normal = await run_incident_scenario(scenarios["normal-refresh"], store)
    result = await run_incident_scenario(scenarios["loopback-listener"], store)
    incidents = store.list_recent()
    if normal.incident_count or normal.model_calls or len(incidents) != 1:
        raise ValueError("正式包 incident 夹具不满足零模型刷新或唯一事件约束")
    incident = incidents[0]
    if result.status is None or incident.report is None:
        raise ValueError("正式包 incident 夹具没有生成调查报告")
    return {
        "incident_id": str(incident.incident_id),
        "scenario_id": result.scenario_id,
        "provider_name": dataset.provider_name,
        "model_name": dataset.model_name,
        "status": result.status.value,
        "conclusion": result.conclusion,
        "selected_tools": list(result.selected_tools),
        "normal_refresh": {
            "scenario_id": normal.scenario_id,
            "incident_count": normal.incident_count,
            "model_calls": normal.model_calls,
        },
        "real_model_calls": 0,
    }


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _compact_sqlite_database(path: Path) -> None:
    """把短连接留下的 WAL 合回主文件，避免夹具携带瞬时旁路文件。"""
    gc.collect()
    with sqlite3.connect(path) as connection:
        connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        connection.execute("PRAGMA journal_mode=DELETE")


def _prepare_empty_data_dir(data_dir: Path, allowed_root: Path) -> Path:
    if allowed_root.is_symlink():
        raise ValueError("允许根目录不得是符号链接")
    allowed_root.mkdir(parents=True, exist_ok=True)
    if allowed_root.is_symlink():
        raise ValueError("允许根目录不得是符号链接")
    root = allowed_root.resolve(strict=True)
    if not root.is_dir():
        raise ValueError("允许根目录不是目录")
    if data_dir.is_symlink():
        raise ValueError("数据目录不得是符号链接")
    candidate = data_dir.resolve()
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise ValueError("数据目录逃出允许根目录") from exc
    if candidate.exists() and (not candidate.is_dir() or any(candidate.iterdir())):
        raise ValueError("数据目录必须不存在或为空")
    candidate.mkdir(parents=True, exist_ok=True)
    return candidate


def resolve_platform_name(value: str | None = None) -> str:
    if value is not None:
        return value
    if sys.platform == "win32":
        return "windows"
    if sys.platform == "darwin":
        return "macos"
    raise ValueError("正式包夹具只支持 Windows 或 macOS")


def prepare_fixture(data_dir: Path, allowed_root: Path, platform_name: str) -> dict[str, JsonValue]:
    """调用真实平台工厂，写入验收数据并生成无秘密摘要。"""
    root = _prepare_empty_data_dir(data_dir, allowed_root)
    with rejecting_product_keyrings():
        if platform_name == "windows":
            application = windows_app.build_windows_application(root)
            node_id = application.node_id
        elif platform_name == "macos":
            application = macos_app.build_macos_local_application(root)
            node_id = application.node.node_id
        else:
            raise ValueError("未知验收平台")
    operation_id = seed_operation(application.operation_control_service, node_id)
    namespaces = seed_memories(application.memory_service, node_id)
    incident = asyncio.run(seed_incident(root / "incidents.sqlite3"))
    _compact_sqlite_database(root / "runtime.sqlite3")
    _compact_sqlite_database(root / "incidents.sqlite3")

    entries = tuple(sorted(root.iterdir(), key=lambda path: path.name))
    if any(path.is_symlink() or not path.is_file() for path in entries):
        raise ValueError("验收数据目录只能包含普通文件")
    names = {path.name for path in entries}
    if frozenset(names) != ALLOWED_DATA_FILES:
        raise ValueError("验收数据目录出现未列入白名单的文件")
    findings = scan_files(entries, allow_placeholders=False)
    if findings:
        raise ValueError("验收数据目录秘密扫描失败")

    return {
        "schema_version": FIXTURE_SCHEMA,
        "platform": platform_name,
        "node_id": str(node_id),
        "operation_id": str(operation_id),
        "incident": incident,
        "memory_scopes": [
            {
                "user": namespace.user,
                "network": namespace.network,
                "node_id": str(namespace.node_id),
                "task_type": namespace.task_type,
                "security_scope": namespace.security_scope,
            }
            for namespace in namespaces
        ],
        "files": [
            {"path": path.name, "sha256": _sha256(path), "size": path.stat().st_size}
            for path in entries
        ],
        "contains_secrets": False,
        "security_boundary": {
            "secret_store": "rejecting",
            "network_changes": 0,
        },
    }


def main(argv: Sequence[str] | None = None) -> int:
    """解析隔离目录并保存可供浏览器作业消费的夹具回执。"""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", type=Path, required=True)
    parser.add_argument("--allowed-root", type=Path, required=True)
    parser.add_argument("--platform", choices=("windows", "macos"))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    output = args.output.resolve()
    data_dir = args.data_dir.resolve()
    if output == data_dir or data_dir in output.parents:
        parser.error("夹具回执不得写入产品数据目录")
    native_platform = resolve_platform_name()
    if args.platform is not None and args.platform != native_platform:
        parser.error("夹具平台必须与当前原生运行包平台一致")
    platform_name = resolve_platform_name(args.platform)
    report = prepare_fixture(args.data_dir, args.allowed_root, platform_name)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(report, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
