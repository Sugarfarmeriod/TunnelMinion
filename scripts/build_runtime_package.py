"""从锁定输入构建正式 TunnelMinion one-folder 运行包。"""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
from collections.abc import Sequence
from pathlib import Path
from typing import cast

from pydantic import JsonValue

try:
    from scripts.build_runtime_package_spike import (
        file_sha256,
        git_revision,
        license_inventory,
        package_files,
        source_tree_sha256,
    )
    from scripts.prepare_frontend_dist import verify_frontend_dist
except ModuleNotFoundError:
    from build_runtime_package_spike import (  # pyright: ignore[reportMissingImports]
        file_sha256,
        git_revision,
        license_inventory,
        package_files,
        source_tree_sha256,
    )
    from prepare_frontend_dist import verify_frontend_dist  # pyright: ignore[reportMissingImports]

APPLICATION_VERSION = importlib.metadata.version("tunnelminion")
MANIFEST_VERSION = "runtime-package-manifest/v2"
SOURCE_INPUTS = (
    Path("pyproject.toml"),
    Path("uv.lock"),
    Path("frontend/package.json"),
    Path("frontend/package-lock.json"),
    Path("frontend/src"),
    Path("schemas"),
    Path("src"),
    Path("scripts/build_runtime_package.py"),
    Path("scripts/prepare_frontend_dist.py"),
)
FRONTEND_DIST = Path("build/frontend-dist")
PACKAGED_FRONTEND_RELATIVE = Path("tunnelminion/web/ui")


def _source_date_epoch(revision: str) -> str:
    """把 Git 提交时间固定为可重复构建时间源。"""
    return subprocess.check_output(
        ("git", "show", "-s", "--format=%ct", revision), text=True
    ).strip()


def _run(command: Sequence[str], *, environment: dict[str, str]) -> None:
    subprocess.run(command, check=True, env=environment)


def _executable_name() -> str:
    return "tunnelminion.exe" if sys.platform == "win32" else "tunnelminion"


def _frontend_files(root: Path) -> tuple[Path, ...]:
    """验证唯一前端暂存区，拒绝缺文件、符号链接和特殊文件。"""
    resolved = root.resolve()
    if not (resolved / "index.html").is_file():
        raise ValueError("运行包构建缺少 build/frontend-dist/index.html")
    files: list[Path] = []
    for path in resolved.rglob("*"):
        if path.is_symlink():
            raise ValueError("运行包前端暂存区不得包含符号链接")
        if path.is_file():
            files.append(path)
        elif not path.is_dir():
            raise ValueError("运行包前端暂存区不得包含特殊文件")
    return tuple(sorted(files, key=lambda item: item.relative_to(resolved).as_posix()))


def _frontend_digest(root: Path) -> str:
    """按相对路径和内容生成跨平台稳定的前端产物摘要。"""
    resolved = root.resolve()
    digest = hashlib.sha256()
    for path in _frontend_files(resolved):
        digest.update(path.relative_to(resolved).as_posix().encode("utf-8"))
        digest.update(b"\0")
        digest.update(bytes.fromhex(file_sha256(path)))
    return digest.hexdigest()


def _npm_license_inventory(lock_path: Path) -> list[dict[str, JsonValue]]:
    """从固定 npm lock 生成不依赖当前平台 node_modules 的许可清单。"""
    raw = json.loads(lock_path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("npm lock 缺少完整 packages 清单")
    lock = cast(dict[str, object], raw)
    packages_value = lock.get("packages")
    if not isinstance(packages_value, dict):
        raise ValueError("npm lock 缺少完整 packages 清单")
    packages = cast(dict[str, object], packages_value)
    inventory: list[dict[str, JsonValue]] = []
    for package_path, value in packages.items():
        if not package_path or not isinstance(value, dict):
            continue
        package = cast(dict[str, object], value)
        name = package_path.rsplit("node_modules/", 1)[-1]
        version = package.get("version")
        license_name = package.get("license")
        if (
            not name
            or not isinstance(version, str)
            or not isinstance(license_name, str)
            or not license_name.strip()
            or "UNKNOWN" in license_name.upper()
        ):
            raise ValueError(f"npm 依赖 {name or package_path} 缺少已接受许可证")
        inventory.append(
            {
                "ecosystem": "npm",
                "name": name,
                "version": version,
                "license": license_name[:240],
                "source": "frontend/package-lock.json",
            }
        )
    if not inventory:
        raise ValueError("npm lock 没有依赖许可记录")
    return sorted(inventory, key=lambda item: (cast(str, item["name"]), cast(str, item["version"])))


def _python_license_inventory(work: Path) -> list[dict[str, JsonValue]]:
    """给既有 Python 许可清单补充生态和可复核来源。"""
    inventory: list[dict[str, JsonValue]] = []
    for item in license_inventory(work):
        license_name = cast(str, item["license"])
        if "UNKNOWN" in license_name.upper():
            raise ValueError(f"Python 依赖 {item['name']} 缺少已接受许可证")
        inventory.append(
            {
                "ecosystem": "python",
                "name": item["name"],
                "version": item["version"],
                "license": license_name,
                "source": "installed-python-metadata",
            }
        )
    return inventory


def _v2_package_files(root: Path, entrypoint: str) -> list[dict[str, JsonValue]]:
    """给逐文件摘要补充供 v2 交叉校验的稳定逻辑类型。"""
    frontend_prefix = f"_internal/{PACKAGED_FRONTEND_RELATIVE.as_posix()}/"
    records: list[dict[str, JsonValue]] = []
    for raw in package_files(root):
        path = cast(str, raw["path"])
        file_type = "runtime"
        if path == entrypoint:
            file_type = "entrypoint"
        elif path.startswith(frontend_prefix):
            file_type = "frontend"
        elif path.startswith("schemas/"):
            file_type = "schema"
        elif path == "THIRD_PARTY_LICENSES.json":
            file_type = "license-evidence"
        records.append({**raw, "type": file_type})
    return records


def _canonicalize_embedded_zip(path: Path) -> None:
    """固定 PyInstaller 标准库 ZIP 的成员顺序和元数据。"""
    if not path.is_file():
        return
    with zipfile.ZipFile(path, "r") as source:
        members = {name: source.read(name) for name in source.namelist()}
    temporary = path.with_suffix(".canonical.tmp")
    try:
        with zipfile.ZipFile(
            temporary,
            "w",
            compression=zipfile.ZIP_DEFLATED,
            compresslevel=9,
        ) as destination:
            for name in sorted(members):
                info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
                info.compress_type = zipfile.ZIP_DEFLATED
                info.create_system = 3
                info.external_attr = 0o100644 << 16
                destination.writestr(info, members[name])
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def build_runtime_package(
    output_root: Path,
    manifest_path: Path,
    summary_path: Path,
    *,
    source_revision: str | None = None,
) -> dict[str, JsonValue]:
    """构建版本化目录，并生成清单、许可和稳定摘要。"""
    frontend_root = FRONTEND_DIST.resolve()
    frontend_files = _frontend_files(frontend_root)
    frontend_digest = _frontend_digest(frontend_root)
    frontend_receipt = verify_frontend_dist(Path.cwd())
    if frontend_receipt.get("dist_sha256") != frontend_digest or frontend_receipt.get(
        "file_count"
    ) != len(frontend_files):
        raise ValueError("运行包构建拒绝陈旧或不一致的 frontend dist")
    revision = git_revision(source_revision)
    source_digest = source_tree_sha256(SOURCE_INPUTS)
    python_lock_sha256 = file_sha256(Path("uv.lock"))
    npm_lock_sha256 = file_sha256(Path("frontend/package-lock.json"))
    version_label = re.sub(r"[^a-z0-9-]", "-", APPLICATION_VERSION.lower())
    package_id = (
        f"tunnelminion-{version_label}-{sys.platform}-"
        f"{platform.machine().lower()}-{source_digest[:12]}-{frontend_digest[:12]}"
    )
    package_root = output_root / package_id
    if package_root.exists():
        shutil.rmtree(package_root)
    output_root.mkdir(parents=True, exist_ok=True)
    environment = dict(os.environ)
    environment["SOURCE_DATE_EPOCH"] = _source_date_epoch(revision)
    work_parent = Path("build/runtime-package").resolve()
    work_parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="production-", dir=work_parent) as temporary:
        work = Path(temporary)
        dist = work / "dist"
        _run(
            (
                sys.executable,
                "-m",
                "PyInstaller",
                "--noconfirm",
                "--clean",
                "--onedir",
                "--contents-directory",
                "_internal",
                "--name",
                "tunnelminion",
                "--distpath",
                str(dist),
                "--workpath",
                str(work / "build"),
                "--specpath",
                str(work / "spec"),
                "--paths",
                "src",
                "--copy-metadata",
                "tunnelminion",
                "--copy-metadata",
                "keyring",
                "--add-data",
                f"{frontend_root}:{PACKAGED_FRONTEND_RELATIVE.as_posix()}",
                "src/tunnelminion/__main__.py",
            ),
            environment=environment,
        )
        licenses = [
            *_python_license_inventory(work),
            *_npm_license_inventory(Path("frontend/package-lock.json")),
        ]
        built = dist / "tunnelminion"
        packaged_frontend = built / "_internal" / PACKAGED_FRONTEND_RELATIVE
        if _frontend_digest(packaged_frontend) != frontend_digest or len(
            _frontend_files(packaged_frontend)
        ) != len(frontend_files):
            raise ValueError("PyInstaller 未完整收集唯一 frontend dist")
        shutil.copytree(built, package_root, copy_function=shutil.copy2)
    _canonicalize_embedded_zip(package_root / "_internal" / "base_library.zip")

    schema_dir = package_root / "schemas"
    schema_dir.mkdir()
    for schema in (
        "runtime-package-manifest-v1.schema.json",
        "runtime-package-manifest-v2.schema.json",
        "runtime-profile-v1.schema.json",
    ):
        shutil.copy2(Path("schemas") / schema, schema_dir / schema)

    license_path = package_root / "THIRD_PARTY_LICENSES.json"
    license_path.write_text(
        json.dumps(licenses, ensure_ascii=False, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    entrypoint = _executable_name()
    files = _v2_package_files(package_root, entrypoint)
    manifest: dict[str, JsonValue] = {
        "schema_version": MANIFEST_VERSION,
        "candidate": {
            "id": package_id,
            "layout": "onedir-freeze",
            "platform": sys.platform,
            "architecture": platform.machine().lower(),
            "python_version": platform.python_version(),
            "application_version": APPLICATION_VERSION,
        },
        "build": {
            "source_revision": revision,
            "source_tree_sha256": source_digest,
            "python_lock_sha256": python_lock_sha256,
            "npm_lock_sha256": npm_lock_sha256,
            "builder": f"PyInstaller {importlib.metadata.version('pyinstaller')} onedir",
        },
        "frontend": {
            "root": f"_internal/{PACKAGED_FRONTEND_RELATIVE.as_posix()}",
            "sha256": frontend_digest,
            "file_count": len(frontend_files),
        },
        "entrypoint": entrypoint,
        "entrypoint_args": [],
        "files": cast(JsonValue, files),
        "licenses": cast(JsonValue, licenses),
    }
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    summary: dict[str, JsonValue] = {
        "schema_version": "runtime-package-build/v1",
        "package_id": package_id,
        "application_version": APPLICATION_VERSION,
        "platform": sys.platform,
        "architecture": platform.machine().lower(),
        "source_revision": revision,
        "source_tree_sha256": source_digest,
        "python_lock_sha256": python_lock_sha256,
        "npm_lock_sha256": npm_lock_sha256,
        "frontend_dist_sha256": frontend_digest,
        "frontend_file_count": len(frontend_files),
        "manifest_sha256": file_sha256(manifest_path),
        "file_count": len(files),
        "size_bytes": sum(cast(int, item["size"]) for item in files),
        "license_count": len(licenses),
        "unknown_license_count": sum(1 for item in licenses if item["license"] == "UNKNOWN"),
    }
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    return summary


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--summary", type=Path, required=True)
    parser.add_argument("--source-revision")
    args = parser.parse_args(argv)
    workspace = Path.cwd().resolve()
    targets = tuple(value.resolve() for value in (args.output_root, args.manifest, args.summary))
    if any(target == workspace or workspace in target.parents for target in targets):
        parser.error("正式运行包输出必须位于仓库工作目录之外")
    summary = build_runtime_package(
        targets[0],
        targets[1],
        targets[2],
        source_revision=args.source_revision,
    )
    print(json.dumps(summary, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
