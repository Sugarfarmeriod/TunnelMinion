"""在同一提交和评分器下重复运行 legacy 与 Harness + Skill incident 评测。"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from statistics import fmean
from tempfile import TemporaryDirectory
from typing import Any

from scripts.run_real_incident_evaluation import (
    _configured_api_key,  # pyright: ignore[reportPrivateUsage]
    _model_catalog_health,  # pyright: ignore[reportPrivateUsage]
    _model_health,  # pyright: ignore[reportPrivateUsage]
    _repository_revision,  # pyright: ignore[reportPrivateUsage]
)

from tunnelminion.agent.prompts import INCIDENT_INVESTIGATION_PROMPT
from tunnelminion.evaluation.incidents import (
    IncidentEvaluationDataset,
    IncidentEvaluationReport,
    incident_dataset_content_hash,
    run_incident_dataset,
)
from tunnelminion.incident.investigation import InvestigationLimits
from tunnelminion.incident.storage import SQLiteIncidentStore
from tunnelminion.model.openai_compatible import (
    OpenAICompatibleConfig,
    OpenAICompatibleProvider,
)


def _content_hash(path: Path) -> str:
    return f"sha256:{hashlib.sha256(path.read_bytes()).hexdigest()}"


def _summarize(reports: Sequence[IncidentEvaluationReport]) -> dict[str, Any]:
    metric_names = tuple(reports[0].metrics.metric_counts)
    metrics: dict[str, object] = {}
    for name in metric_names:
        counts = [report.metrics.metric_counts[name] for report in reports]
        values = [item.value for item in counts]
        metrics[name] = {
            "numerator": sum(item.numerator for item in counts),
            "denominator": sum(item.denominator for item in counts),
            "mean": fmean(values),
            "minimum": min(values),
            "maximum": max(values),
            "per_run": values,
        }
    failures = [
        {
            "run": run_index,
            "scenario_id": scenario.scenario_id,
            "failure_class": scenario.failure_class,
            "status": scenario.status,
            "stop_reason": scenario.stop_reason,
            "selected_tools": scenario.selected_tools,
            "runtime_tool_attempts": scenario.runtime_tool_attempts,
            "skill_id": scenario.skill_id,
        }
        for run_index, report in enumerate(reports, start=1)
        for scenario in report.scenarios
        if not scenario.task_completed
    ]
    return {
        "runs": len(reports),
        "metrics": metrics,
        "average_latency_ms": [report.metrics.average_latency_ms for report in reports],
        "total_tokens": [report.metrics.total_tokens for report in reports],
        "safety_gate_violations": [report.safety_gate_violations for report in reports],
        "failures": failures,
    }


async def _run_variant(
    dataset: IncidentEvaluationDataset,
    provider: OpenAICompatibleProvider,
    *,
    provider_name: str,
    model_name: str,
    source_revision: str,
    run_count: int,
    skills_enabled: bool,
) -> tuple[IncidentEvaluationReport, ...]:
    reports: list[IncidentEvaluationReport] = []
    for _ in range(run_count):
        with TemporaryDirectory(prefix="tunnelminion-incident-ab-") as temporary:
            reports.append(
                await run_incident_dataset(
                    dataset,
                    SQLiteIncidentStore(Path(temporary) / "incidents.sqlite3"),
                    provider=provider,
                    provider_name=provider_name,
                    model_name=model_name,
                    source_revision=source_revision,
                    skills_enabled=skills_enabled,
                )
            )
    return tuple(reports)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dataset", type=Path)
    parser.add_argument("--endpoint", required=True)
    parser.add_argument("--health-endpoint")
    parser.add_argument("--configured-api-key", action="store_true")
    parser.add_argument("--model", required=True)
    parser.add_argument("--provider-name", default="openai-compatible")
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--timeout-seconds", type=float, default=120.0)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.runs < 1:
        parser.error("--runs 必须大于零")
    if args.output_dir.exists():
        raise RuntimeError("A/B 输出目录已存在，不得覆盖")

    source_revision = _repository_revision()
    dataset = IncidentEvaluationDataset.model_validate_json(
        args.dataset.read_text(encoding="utf-8")
    )
    api_key = _configured_api_key(args.endpoint) if args.configured_api_key else None

    def health():
        return (
            _model_health(args.health_endpoint, args.model)
            if args.health_endpoint is not None
            else _model_catalog_health(args.endpoint, args.model, api_key)
        )

    health_before = health()
    provider = OpenAICompatibleProvider(
        OpenAICompatibleConfig(
            endpoint=args.endpoint,
            model=args.model,
            timeout_seconds=args.timeout_seconds,
        ),
        api_key,
    )
    variants = (
        ("baseline", False),
        ("candidate", True),
    )
    completed: dict[str, tuple[IncidentEvaluationReport, ...]] = {}
    for name, skills_enabled in variants:
        completed[name] = asyncio.run(
            _run_variant(
                dataset,
                provider,
                provider_name=args.provider_name,
                model_name=args.model,
                source_revision=source_revision,
                run_count=args.runs,
                skills_enabled=skills_enabled,
            )
        )
    health_after = health()

    root = Path.cwd()
    manifest = {
        "schema_version": "incident-ab-manifest/v1",
        "source_revision": source_revision,
        "dataset_id": dataset.dataset_id,
        "dataset_version": dataset.dataset_version,
        "dataset_content_hash": incident_dataset_content_hash(dataset),
        "provider_name": args.provider_name,
        "model_name": args.model,
        "prompt_version": dataset.prompt_version,
        "prompt_content_hash": INCIDENT_INVESTIGATION_PROMPT.content_hash,
        "tool_versions": dataset.tool_versions,
        "budget": InvestigationLimits().model_dump(mode="json"),
        "scorer_version": completed["candidate"][0].scorer_version,
        "scorer_content_hash": _content_hash(root / "src/tunnelminion/evaluation/incidents.py"),
        "run_count_per_variant": args.runs,
        "variant_difference": "skills_enabled: false -> true",
        "model_service_health_before": health_before.model_dump(mode="json"),
        "model_service_health_after": health_after.model_dump(mode="json"),
    }
    summaries: dict[str, dict[str, Any]] = {
        name: _summarize(reports) for name, reports in completed.items()
    }
    baseline_metrics: dict[str, Any] = summaries["baseline"]["metrics"]
    candidate_metrics: dict[str, Any] = summaries["candidate"]["metrics"]
    report: dict[str, Any] = {
        "schema_version": "incident-ab-report/v1",
        "generated_at": datetime.now(UTC).isoformat(),
        "manifest": manifest,
        "variants": summaries,
        "mean_delta_candidate_minus_baseline": {
            name: candidate_metrics[name]["mean"] - baseline_metrics[name]["mean"]
            for name in baseline_metrics
        },
    }

    args.output_dir.mkdir(parents=True)
    (args.output_dir / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    (args.output_dir / "report.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    for name, reports in completed.items():
        for index, raw_report in enumerate(reports, start=1):
            (args.output_dir / f"{name}-{index}.json").write_text(
                raw_report.model_dump_json(indent=2) + "\n", encoding="utf-8"
            )
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":  # pragma: no cover - 由命令行入口调用
    raise SystemExit(main())
