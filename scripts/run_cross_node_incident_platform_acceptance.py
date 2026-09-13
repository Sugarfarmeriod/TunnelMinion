"""在当前 Windows/macOS 宿主运行隔离跨节点 incident 回执或校验双平台矩阵。"""

from __future__ import annotations

import argparse
import asyncio
import json
import subprocess
import sys
from collections.abc import Sequence
from contextlib import suppress
from pathlib import Path

from pydantic import BaseModel

from tunnelminion.domain.tools import Platform
from tunnelminion.evaluation.cross_node_evidence import (
    CrossNodePlatformMatrix,
    CrossNodePlatformReceipt,
    CrossNodeRealABReceipt,
    FinalEvaluationAttemptLedger,
    build_final_metric_freeze,
    run_platform_acceptance,
    validate_platform_matrix,
)
from tunnelminion.evaluation.incidents import (
    IncidentEvaluationDataset,
    IncidentEvaluationReport,
)


def _host_platform() -> Platform:
    if sys.platform == "win32":
        return Platform.WINDOWS
    if sys.platform == "darwin":
        return Platform.MACOS
    raise RuntimeError("平台回执只允许在 Windows 或 macOS 真机生成")


def _repository_revision(output: Path) -> str:
    root = Path(__file__).resolve().parents[1]
    status = subprocess.run(
        ("git", "status", "--porcelain=v1", "--untracked-files=all"),
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.splitlines()
    allowed_output = None
    with suppress(ValueError):
        allowed_output = output.resolve().relative_to(root.resolve()).as_posix()
    dirty = tuple(
        line
        for line in status
        if allowed_output is None or line[3:].replace("\\", "/") != allowed_output
    )
    if dirty:
        raise RuntimeError("平台回执必须从干净候选提交生成")
    revision = subprocess.run(
        ("git", "rev-parse", "--verify", "HEAD"),
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    if len(revision) != 40 or any(item not in "0123456789abcdef" for item in revision):
        raise RuntimeError("无法确认完整候选提交")
    return revision


def _write(path: Path, value: BaseModel) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value.model_dump(mode="json"), ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    run = commands.add_parser("run")
    run.add_argument("--platform", type=Platform, required=True)
    run.add_argument("--dataset", type=Path, required=True)
    run.add_argument("--output", type=Path, required=True)
    run.add_argument("--check", action="store_true")

    validate = commands.add_parser("validate")
    validate.add_argument("--windows", type=Path, required=True)
    validate.add_argument("--macos", type=Path, required=True)
    validate.add_argument("--output", type=Path, required=True)
    validate.add_argument("--check", action="store_true")

    freeze = commands.add_parser("freeze")
    freeze.add_argument("--model-report", type=Path, action="append", required=True)
    freeze.add_argument("--platform-matrix", type=Path, required=True)
    freeze.add_argument("--real-ab", type=Path, required=True)
    freeze.add_argument("--attempt-ledger", type=Path, required=True)
    freeze.add_argument("--output", type=Path, required=True)
    freeze.add_argument("--check", action="store_true")

    args = parser.parse_args(argv)
    if args.command == "run":
        if args.platform is not _host_platform():
            raise RuntimeError("声明平台与当前真实宿主不一致")
        dataset = IncidentEvaluationDataset.model_validate_json(
            args.dataset.read_text(encoding="utf-8")
        )
        receipt = asyncio.run(
            run_platform_acceptance(
                dataset,
                args.platform,
                _repository_revision(args.output),
            )
        )
        _write(args.output, receipt)
        return int(args.check and not receipt.passed)

    if args.command == "validate":
        windows = CrossNodePlatformReceipt.model_validate_json(
            args.windows.read_text(encoding="utf-8")
        )
        macos = CrossNodePlatformReceipt.model_validate_json(args.macos.read_text(encoding="utf-8"))
        matrix = validate_platform_matrix((windows, macos))
        _write(args.output, matrix)
        return int(args.check and not matrix.passed)

    reports = tuple(
        IncidentEvaluationReport.model_validate_json(path.read_text(encoding="utf-8"))
        for path in args.model_report
    )
    matrix = CrossNodePlatformMatrix.model_validate_json(
        args.platform_matrix.read_text(encoding="utf-8")
    )
    real_ab = CrossNodeRealABReceipt.model_validate_json(args.real_ab.read_text(encoding="utf-8"))
    attempt_ledger = FinalEvaluationAttemptLedger.model_validate_json(
        args.attempt_ledger.read_text(encoding="utf-8")
    )
    frozen = build_final_metric_freeze(reports, matrix, real_ab, attempt_ledger)
    _write(args.output, frozen)
    return int(args.check and not frozen.passed)


if __name__ == "__main__":
    raise SystemExit(main())
