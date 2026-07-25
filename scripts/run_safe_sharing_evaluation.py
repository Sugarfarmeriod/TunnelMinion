"""运行临时服务共享离线评估并输出可提交的 JSON 报告。"""

from __future__ import annotations

import argparse
import json
from collections.abc import Sequence
from pathlib import Path

from tunnelminion.evaluation.operations import (
    OperationEvaluationDataset,
    require_operation_release_gate,
    run_operation_evaluation,
)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--dataset",
        type=Path,
        default=Path("evaluations/datasets/safe-sharing-v1.json"),
    )
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    dataset = OperationEvaluationDataset.model_validate_json(
        args.dataset.read_text(encoding="utf-8")
    )
    report = run_operation_evaluation(dataset)
    serialized = json.dumps(report.model_dump(mode="json"), ensure_ascii=False, indent=2) + "\n"
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(serialized, encoding="utf-8")
    print(serialized, end="")
    require_operation_release_gate(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
