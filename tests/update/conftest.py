"""一键更新测试共用的运行包和发布源夹具。"""

from __future__ import annotations

import hashlib
import io
import json
import shutil
import sys
import tarfile
from collections.abc import Callable
from pathlib import Path

import pytest

from tunnelminion.runtime.preflight import canonical_runtime_architecture

PackageFactory = Callable[..., Path]
ArchiveFactory = Callable[[Path, Path], Path]


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build_package(
    root: Path,
    package_id: str,
    payload: bytes,
    *,
    revision: str = "a" * 40,
) -> Path:
    """在 root/package 下生成一个能通过逐文件校验的最小运行包，清单放在包内。"""
    package = root / "package"
    package.mkdir(parents=True)
    (package / "app.bin").write_bytes(payload)
    schemas = package / "schemas"
    schemas.mkdir()
    shutil.copy2(
        "schemas/runtime-package-manifest-v1.schema.json",
        schemas / "runtime-package-manifest-v1.schema.json",
    )
    files = [
        {
            "path": path.relative_to(package).as_posix(),
            "sha256": _sha256(path),
            "size": path.stat().st_size,
        }
        for path in sorted(item for item in package.rglob("*") if item.is_file())
    ]
    manifest = {
        "schema_version": "runtime-package-manifest/v1",
        "candidate": {
            "id": package_id,
            "layout": "onedir-freeze",
            "platform": sys.platform,
            "architecture": canonical_runtime_architecture(),
            "python_version": "3.11.15",
            "application_version": "0.1.0",
        },
        "build": {
            "source_revision": revision,
            "source_tree_sha256": hashlib.sha256(payload).hexdigest(),
            "lock_sha256": "b" * 64,
            "builder": "fixture",
        },
        "entrypoint": "app.bin",
        "entrypoint_args": [],
        "files": files,
        "licenses": [],
    }
    (package / "runtime-package-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    return package


def build_archive(package: Path, archive: Path) -> Path:
    """把 package/ 目录打成和 CI 发布一致的 tar.gz。"""
    archive.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive, "w:gz") as bundle:
        bundle.add(package, arcname="package")
    return archive


def tar_with(members: list[tuple[tarfile.TarInfo, bytes | None]]) -> bytes:
    """生成包含指定成员的 tar.gz 字节，用来构造恶意压缩包。"""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as bundle:
        for info, data in members:
            if data is None:
                bundle.addfile(info)
            else:
                info.size = len(data)
                bundle.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


@pytest.fixture
def package_factory() -> PackageFactory:
    return build_package


@pytest.fixture
def archive_factory() -> ArchiveFactory:
    return build_archive
