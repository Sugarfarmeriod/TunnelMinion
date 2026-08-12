"""把仓库外构建的正式运行包干净复制到可扫描的 CI 暂存区。"""

from __future__ import annotations

import argparse
import json
import shutil
from collections.abc import Sequence
from pathlib import Path
from typing import cast


def _load_object(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"JSON 根节点必须是对象：{path}")
    return cast(dict[str, object], value)


def stage_runtime_package(
    output_root: Path,
    manifest_path: Path,
    summary_path: Path,
    destination: Path,
) -> Path:
    """根据构建摘要定位唯一包，并 clean-first 复制包与证据。"""
    summary = _load_object(summary_path)
    package_id = summary.get("package_id")
    if not isinstance(package_id, str) or not package_id:
        raise ValueError("运行包构建摘要缺少 package_id")
    root = output_root.resolve()
    package_root = (root / package_id).resolve()
    if package_root.parent != root or not package_root.is_dir():
        raise ValueError("运行包构建摘要指向无效包目录")
    if not manifest_path.is_file():
        raise ValueError("运行包构建缺少 manifest")

    target = destination.resolve()
    if target.exists():
        shutil.rmtree(target)
    target.mkdir(parents=True)
    shutil.copytree(package_root, target / "package")
    shutil.copy2(manifest_path, target / "manifest.json")
    shutil.copy2(summary_path, target / "build-summary.json")
    return target


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--summary", type=Path, required=True)
    parser.add_argument("--destination", type=Path, required=True)
    args = parser.parse_args(argv)
    staged = stage_runtime_package(
        args.output_root,
        args.manifest,
        args.summary,
        args.destination,
    )
    print(staged)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
