"""把 CI 产出的两个平台运行包整理成 GitHub Release 附件，并生成 sha256 清单 `release.json`。

只用标准库，发布 job 不需要安装项目依赖。
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import re
import shutil
from collections.abc import Sequence
from pathlib import Path

RELEASE_METADATA_VERSION = "tunnelminion-release/v1"
TARGETS = ("windows-amd64", "macos-arm64")
_TAG = re.compile(r"^[A-Za-z0-9._-]{1,80}$")
_REVISION = re.compile(r"^[0-9a-f]{40}$")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _compress(source: Path, destination: Path) -> None:
    """固定 gzip 头里的时间和文件名，同一个 tar 每次压出来字节相同。"""
    with (
        source.open("rb") as raw,
        destination.open("wb") as output,
        gzip.GzipFile(filename="", mode="wb", fileobj=output, mtime=0, compresslevel=9) as stream,
    ):
        shutil.copyfileobj(raw, stream, 1024 * 1024)


def build_release_assets(
    artifacts_root: Path,
    output_dir: Path,
    *,
    tag: str,
    source_revision: str,
) -> dict[str, object]:
    """读取 `runtime-package-<平台>/runtime-package.tar`，输出压缩包和 `release.json`。"""
    if _TAG.fullmatch(tag) is None:
        raise ValueError("Release 名无效")
    if _REVISION.fullmatch(source_revision) is None:
        raise ValueError("提交号必须是 40 位小写十六进制")
    output_dir.mkdir(parents=True, exist_ok=True)
    assets: dict[str, dict[str, object]] = {}
    for target in TARGETS:
        source = artifacts_root / f"runtime-package-{target}" / "runtime-package.tar"
        if not source.is_file():
            raise FileNotFoundError(f"缺少 {target} 运行包")
        name = f"tunnelminion-{target}.tar.gz"
        destination = output_dir / name
        _compress(source, destination)
        assets[target] = {
            "name": name,
            "size": destination.stat().st_size,
            "sha256": _sha256(destination),
        }
    metadata: dict[str, object] = {
        "schema_version": RELEASE_METADATA_VERSION,
        "tag": tag,
        "source_revision": source_revision,
        "assets": assets,
    }
    (output_dir / "release.json").write_text(
        json.dumps(metadata, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return metadata


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts-root", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--source-revision", required=True)
    args = parser.parse_args(argv)
    metadata = build_release_assets(
        args.artifacts_root,
        args.output_dir,
        tag=args.tag,
        source_revision=args.source_revision,
    )
    print(json.dumps(metadata, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
