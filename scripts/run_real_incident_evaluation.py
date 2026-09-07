"""使用真实 OpenAI-compatible 模型运行隔离 incident 矩阵。"""

from __future__ import annotations

import argparse
import asyncio
import json
import subprocess
from collections.abc import Sequence
from pathlib import Path
from tempfile import TemporaryDirectory

import httpx

from tunnelminion.evaluation.incidents import (
    IncidentEvaluationDataset,
    IncidentModelServiceHealth,
    run_incident_dataset,
)
from tunnelminion.incident.storage import SQLiteIncidentStore
from tunnelminion.model.openai_compatible import (
    OpenAICompatibleConfig,
    OpenAICompatibleProvider,
)


def _repository_revision() -> str:
    """只允许在干净工作树上生成可关联到提交的正式报告。"""
    status = subprocess.run(
        ("git", "status", "--porcelain"),
        check=True,
        capture_output=True,
        text=True,
    )
    if status.stdout.strip():
        raise RuntimeError("真实 incident 评测要求干净工作树")
    revision = subprocess.run(
        ("git", "rev-parse", "HEAD"),
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    if not revision:
        raise RuntimeError("无法读取被评测代码提交")
    return revision


def _model_health(endpoint: str, expected_model: str) -> IncidentModelServiceHealth:
    """读取最小健康字段，并拒绝后台静默切换模型。"""
    response = httpx.get(endpoint, timeout=10.0)
    response.raise_for_status()
    health = IncidentModelServiceHealth.model_validate(response.json())
    if health.loaded_model != expected_model:
        raise RuntimeError("模型服务当前加载的模型与验收目标不一致")
    return health


def main(argv: Sequence[str] | None = None) -> int:
    """运行一次串行真实矩阵并保存不含凭据和 endpoint 的报告。"""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dataset", type=Path)
    parser.add_argument("--endpoint", required=True)
    parser.add_argument("--health-endpoint", required=True)
    parser.add_argument("--model", required=True)
    parser.add_argument("--provider-name", default="openai-compatible")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--timeout-seconds", type=float, default=120.0)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)

    dataset = IncidentEvaluationDataset.model_validate_json(
        args.dataset.read_text(encoding="utf-8")
    )
    health_before = _model_health(args.health_endpoint, args.model)
    provider = OpenAICompatibleProvider(
        OpenAICompatibleConfig(
            endpoint=args.endpoint,
            model=args.model,
            timeout_seconds=args.timeout_seconds,
        )
    )
    with TemporaryDirectory(prefix="tunnelminion-real-incident-eval-") as temporary:
        report = asyncio.run(
            run_incident_dataset(
                dataset,
                SQLiteIncidentStore(Path(temporary) / "incidents.sqlite3"),
                provider=provider,
                provider_name=args.provider_name,
                model_name=args.model,
                source_revision=_repository_revision(),
            )
        )
    health_after = _model_health(args.health_endpoint, args.model)
    report = report.model_copy(
        update={
            "model_service_health_before": health_before,
            "model_service_health_after": health_after,
        }
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(report.model_dump_json(indent=2) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {
                "dataset": f"{report.dataset_id}:{report.dataset_version}",
                "model": report.model_name,
                "scenario_count": report.metrics.scenario_count,
                "root_cause_success_rate": report.metrics.root_cause_success_rate,
                "tool_selection_rate": report.metrics.tool_selection_rate,
                "task_completion_rate": report.metrics.task_completion_rate,
                "safety_gate_violations": report.safety_gate_violations,
                "quality_target_violations": report.quality_target_violations,
                "ready_for_operation_stage": report.ready_for_operation_stage,
                "total_tokens": report.metrics.total_tokens,
                "output": str(args.output),
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return int(args.check and not report.ready_for_operation_stage)


if __name__ == "__main__":  # pragma: no cover - 由命令行入口调用
    raise SystemExit(main())
