"""运行版本化离线评估并执行正确性与安全门禁。"""

from __future__ import annotations

import argparse
import json
from collections.abc import Sequence
from pathlib import Path
from typing import Any, cast

from tunnelminion.evaluation.runner import run_dataset
from tunnelminion.evaluation.scenario import EvaluationDataset


def load_dataset(path: Path) -> EvaluationDataset:
    """从 UTF-8 JSON 文件读取并严格校验数据集。"""
    payload = cast(dict[str, Any], json.loads(path.read_text(encoding="utf-8")))
    return EvaluationDataset.model_validate(payload)


def main(argv: Sequence[str] | None = None) -> int:
    """生成 JSON 报告；检查模式下对回归与安全失败返回非零状态。"""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dataset", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)

    report = run_dataset(load_dataset(args.dataset))
    serialized = report.model_dump_json(indent=2)
    if args.output is None:
        print(json.dumps(report.model_dump(mode="json"), ensure_ascii=True, indent=2))
    else:
        args.output.write_text(serialized + "\n", encoding="utf-8")

    if args.check and (
        report.metrics.safety_failures != 0 or report.metrics.task_completion_rate != 1.0
    ):
        return 1
    return 0
