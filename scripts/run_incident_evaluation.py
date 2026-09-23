"""运行固定 incident 故障矩阵并输出版本化离线报告。"""

from __future__ import annotations

import argparse
import asyncio
import json
from collections.abc import Sequence
from pathlib import Path
from tempfile import TemporaryDirectory

from tunnelminion.evaluation.incidents import (
    IncidentEvaluationDataset,
    run_incident_dataset,
    run_incident_scenario,
)
from tunnelminion.incident.investigation import InvestigationLimits
from tunnelminion.incident.storage import SQLiteIncidentStore


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dataset", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--scenario")
    args = parser.parse_args(argv)
    dataset = IncidentEvaluationDataset.model_validate_json(
        args.dataset.read_text(encoding="utf-8")
    )
    with TemporaryDirectory(prefix="tunnelminion-incident-eval-") as temporary:
        store = SQLiteIncidentStore(Path(temporary) / "incidents.sqlite3")
        if args.scenario is None:
            result = asyncio.run(run_incident_dataset(dataset, store))
            failed = bool(result.gate_violations)
            serialized_result = result.model_dump(mode="json")
        else:
            scenario = next(
                (item for item in dataset.scenarios if item.scenario_id == args.scenario),
                None,
            )
            if scenario is None:
                parser.error(f"未知场景：{args.scenario}")
            scenario_result = asyncio.run(run_incident_scenario(scenario, store))
            result = {
                "schema_version": "incident-investigation-demo/v1",
                "input": scenario.model_dump(mode="json"),
                "budget": InvestigationLimits().model_dump(mode="json"),
                "result": scenario_result.model_dump(mode="json"),
            }
            failed = not scenario_result.task_completed
            serialized_result = result
    serialized = json.dumps(
        serialized_result,
        ensure_ascii=False,
        indent=2,
    )
    if args.output is None:
        print(serialized)
    else:
        args.output.write_text(serialized + "\n", encoding="utf-8")
    return int(args.check and failed)


if __name__ == "__main__":  # pragma: no cover - 由 console/测试入口调用
    raise SystemExit(main())
