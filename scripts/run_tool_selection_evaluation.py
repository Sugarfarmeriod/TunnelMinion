"""用假模型跑按问题挑工具的固定口径评测，确认每个问题该看到的工具都看到了。"""

from __future__ import annotations

import argparse
import asyncio
from collections.abc import Sequence
from pathlib import Path

from tunnelminion.evaluation.tool_selection import load_dataset, report_json, run_offline

DEFAULT_DATASET = Path("evaluations/datasets/tool-selection-v1.json")


def main(argv: Sequence[str] | None = None) -> int:
    """运行离线评测；有任何问题没通过时返回 1。"""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    report = asyncio.run(run_offline(load_dataset(args.dataset)))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(report_json(report), encoding="utf-8")
    print(f"{report.passed}/{report.cases} 个问题通过")
    return 0 if report.passed == report.cases else 1


if __name__ == "__main__":
    raise SystemExit(main())
