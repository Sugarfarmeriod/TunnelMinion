"""干净构建唯一 React 暂存区，并生成可校验的构建回执。"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import zipfile
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import cast

from pydantic import JsonValue

try:
    from scripts.stage_frontend import stage_frontend
except ModuleNotFoundError:
    from stage_frontend import stage_frontend  # pyright: ignore[reportMissingImports]

RECEIPT_SCHEMA = "tunnelminion/frontend-dist-receipt/v1"
FRONTEND_INPUTS = (
    Path("frontend/.npmrc"),
    Path("frontend/index.html"),
    Path("frontend/package.json"),
    Path("frontend/package-lock.json"),
    Path("frontend/tsconfig.json"),
    Path("frontend/vite.config.ts"),
    Path("frontend/src"),
)
CommandRunner = Callable[[Sequence[str], Path], None]


def _npm_executable() -> str:
    return "npm.cmd" if sys.platform == "win32" else "npm"


def _run(command: Sequence[str], cwd: Path) -> None:
    subprocess.run(command, cwd=cwd, check=True)


def file_sha256(path: Path) -> str:
    """流式计算单文件 SHA-256。"""
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def tree_sha256(root: Path) -> tuple[str, int]:
    """把稳定相对路径和内容摘要一起纳入目录摘要。"""
    resolved = root.resolve()
    entries = tuple(resolved.rglob("*"))
    for path in entries:
        if path.is_symlink():
            raise ValueError("前端目录不得包含符号链接")
        if not path.is_file() and not path.is_dir():
            raise ValueError("前端目录不得包含特殊文件")
    files = tuple(
        sorted(
            (path for path in entries if path.is_file()),
            key=lambda path: path.relative_to(resolved).as_posix(),
        )
    )
    if not files:
        raise ValueError("前端目录没有可摘要文件")
    digest = hashlib.sha256()
    for path in files:
        digest.update(path.relative_to(resolved).as_posix().encode("utf-8"))
        digest.update(b"\0")
        digest.update(bytes.fromhex(file_sha256(path)))
    return digest.hexdigest(), len(files)


def frontend_source_sha256(root: Path) -> str:
    """计算会影响 React 构建结果的仓库输入摘要。"""
    digest = hashlib.sha256()
    for relative in FRONTEND_INPUTS:
        path = root / relative
        if path.is_symlink() or not path.exists():
            raise ValueError(f"前端构建输入无效：{relative.as_posix()}")
        entries = tuple(path.rglob("*")) if path.is_dir() else (path,)
        for item in entries:
            if item.is_symlink() or (not item.is_file() and not item.is_dir()):
                raise ValueError(f"前端构建输入无效：{relative.as_posix()}")
        candidates = tuple(
            sorted(
                (item for item in entries if item.is_file()),
                key=lambda item: item.relative_to(root).as_posix(),
            )
        )
        for item in candidates:
            digest.update(item.relative_to(root).as_posix().encode("utf-8"))
            digest.update(b"\0")
            digest.update(bytes.fromhex(file_sha256(item)))
    return digest.hexdigest()


def verify_frontend_dist(root: Path) -> dict[str, JsonValue]:
    """验证回执、当前输入和唯一暂存区完全一致。"""
    root = root.resolve()
    destination = root / "build/frontend-dist"
    receipt_path = root / "build/frontend-dist-receipt.json"
    if not (destination / "index.html").is_file() or not receipt_path.is_file():
        raise ValueError("缺少可信的 build/frontend-dist 或构建回执")
    raw = json.loads(receipt_path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("前端构建回执格式无效")
    receipt = cast(dict[str, JsonValue], raw)
    digest, count = tree_sha256(destination)
    expected = {
        "schema": RECEIPT_SCHEMA,
        "source_sha256": frontend_source_sha256(root),
        "npm_lock_sha256": file_sha256(root / "frontend/package-lock.json"),
        "dist_sha256": digest,
        "file_count": count,
    }
    if receipt != expected:
        raise ValueError("前端构建回执与源码、锁文件或暂存产物不匹配")
    return receipt


def verify_wheel_frontend(root: Path, wheel_path: Path) -> None:
    """证明 wheel 内的 UI 与唯一暂存区逐文件完全一致。"""
    root = root.resolve()
    staging = root / "build/frontend-dist"
    verify_frontend_dist(root)
    expected = {
        path.relative_to(staging).as_posix(): file_sha256(path)
        for path in staging.rglob("*")
        if path.is_file()
    }
    prefix = "tunnelminion/web/ui/"
    with zipfile.ZipFile(wheel_path.resolve()) as archive:
        members = {
            name.removeprefix(prefix): hashlib.sha256(archive.read(name)).hexdigest()
            for name in archive.namelist()
            if name.startswith(prefix) and not name.endswith("/")
        }
    if members != expected:
        raise ValueError("wheel 未完整收集唯一 frontend dist")


def prepare_frontend_dist(
    root: Path,
    *,
    install: bool = True,
    run: CommandRunner = _run,
) -> dict[str, JsonValue]:
    """删除旧输出后构建、暂存并写入原子回执。"""
    root = root.resolve()
    source = root / "frontend/dist"
    destination = root / "build/frontend-dist"
    receipt_path = root / "build/frontend-dist-receipt.json"
    for target in (source, destination):
        if target.exists():
            shutil.rmtree(target)
    receipt_path.unlink(missing_ok=True)
    if install:
        run((_npm_executable(), "--prefix", "frontend", "ci"), root)
    run((_npm_executable(), "--prefix", "frontend", "run", "build"), root)
    stage_frontend(source, destination)
    dist_sha256, file_count = tree_sha256(destination)
    receipt: dict[str, JsonValue] = {
        "schema": RECEIPT_SCHEMA,
        "source_sha256": frontend_source_sha256(root),
        "npm_lock_sha256": file_sha256(root / "frontend/package-lock.json"),
        "dist_sha256": dist_sha256,
        "file_count": file_count,
    }
    receipt_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = receipt_path.with_suffix(".tmp")
    temporary.write_text(
        json.dumps(receipt, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    temporary.replace(receipt_path)
    return verify_frontend_dist(root)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--skip-install", action="store_true")
    args = parser.parse_args(argv)
    receipt = prepare_frontend_dist(args.root, install=not args.skip_install)
    print(json.dumps(receipt, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
