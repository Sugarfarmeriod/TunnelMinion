"""把刚构建的 React 产物干净地复制到唯一发布暂存目录。"""

from __future__ import annotations

import argparse
import shutil
from pathlib import Path


def stage_frontend(source: Path, destination: Path) -> tuple[Path, ...]:
    """校验并 clean-first 暂存前端文件，返回相对文件清单。"""
    source = source.resolve()
    destination = destination.resolve()
    if source == destination or source in destination.parents:
        raise ValueError("前端暂存目录不得位于构建输出内部")
    if not (source / "index.html").is_file():
        raise ValueError("前端构建缺少 index.html")
    files = tuple(sorted(path for path in source.rglob("*") if path.is_file()))
    if not files:
        raise ValueError("前端构建没有可暂存文件")
    for path in source.rglob("*"):
        if path.is_symlink():
            raise ValueError(f"前端构建不得包含符号链接：{path.relative_to(source)}")

    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(f".{destination.name}.staging")
    if temporary.exists():
        shutil.rmtree(temporary)
    shutil.copytree(source, temporary)
    if destination.exists():
        shutil.rmtree(destination)
    temporary.replace(destination)
    return tuple(path.relative_to(source) for path in files)


def main() -> int:
    """命令行入口。"""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--destination", type=Path, required=True)
    args = parser.parse_args()
    files = stage_frontend(args.source, args.destination)
    print(f"staged {len(files)} frontend files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
