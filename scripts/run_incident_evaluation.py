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
)
from tunnelminion.incident.storage import SQLiteIncidentStore


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dataset", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    dataset = IncidentEvaluationDataset.model_validate_json(
        args.dataset.read_text(encoding="utf-8")
    )
    with TemporaryDirectory(prefix="tunnelminion-incident-eval-") as temporary:
        report = asyncio.run(
            run_incident_dataset(
                dataset,
                SQLiteIncidentStore(Path(temporary) / "incidents.sqlite3"),
            )
        )
    serialized = json.dumps(report.model_dump(mode="json"), ensure_ascii=False, indent=2)
    if args.output is None:
        print(serialized)
    else:
        args.output.write_text(serialized + "\n", encoding="utf-8")
    return int(args.check and bool(report.gate_violations))


if __name__ == "__main__":  # pragma: no cover - 由 console/测试入口调用
    raise SystemExit(main())
