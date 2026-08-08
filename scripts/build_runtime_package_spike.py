"""构建运行包 spike 候选并生成逐文件可复核 manifest。"""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import cast

from packaging.markers import Marker
from pydantic import JsonValue

MANIFEST_VERSION = "runtime-package-manifest/v1"
APPLICATION_VERSION = importlib.metadata.version("tunnelminion")
SOURCE_INPUTS = (
    Path("pyproject.toml"),
    Path("uv.lock"),
    Path("src"),
    Path("scripts/runtime_package_fixture.py"),
    Path("scripts/build_runtime_package_spike.py"),
)


def file_sha256(path: Path) -> str:
    """流式计算构建输入和候选文件 SHA-256。"""
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _run(command: Sequence[str], *, cwd: Path | None = None) -> None:
    """运行构建命令并在失败时立即停止。"""
    subprocess.run(command, cwd=cwd, check=True)


def _git_revision(explicit: str | None = None) -> str:
    """读取或接收用于无 Git 隔离构建目录的源提交。"""
    revision = explicit or subprocess.check_output(("git", "rev-parse", "HEAD"), text=True).strip()
    if re.fullmatch(r"[0-9a-f]{40}", revision) is None:
        raise ValueError("源提交必须是 40 位小写十六进制 Git SHA")
    return revision


def _tree_sha256(paths: Sequence[Path]) -> str:
    """按稳定相对路径和内容计算源输入摘要。"""
    digest = hashlib.sha256()
    files: list[Path] = []
    for path in paths:
        files.extend(
            item
            for item in path.rglob("*")
            if item.is_file()
            and "__pycache__" not in item.parts
            and item.suffix not in {".pyc", ".pyo"}
        ) if path.is_dir() else files.append(path)
    for path in sorted(files, key=lambda item: item.as_posix()):
        digest.update(path.as_posix().encode("utf-8"))
        digest.update(b"\0")
        digest.update(bytes.fromhex(file_sha256(path)))
    return digest.hexdigest()


def _copy_python_runtime(source: Path, destination: Path) -> None:
    """复制完整基础 Python，排除缓存和已有第三方 site-packages。"""

    def ignore(directory: str, names: list[str]) -> set[str]:
        current = Path(directory)
        ignored = {name for name in names if name == "__pycache__" or name.endswith(".pyc")}
        if current.name in {"Lib", f"python{sys.version_info.major}.{sys.version_info.minor}"}:
            ignored.update(name for name in names if name == "site-packages")
        return ignored

    shutil.copytree(source, destination, ignore=ignore, copy_function=shutil.copy2)


def _target_python(root: Path) -> Path:
    if sys.platform == "win32":
        return root / "python" / "python.exe"
    return root / "python" / "bin" / f"python{sys.version_info.major}.{sys.version_info.minor}"


def _build_standalone(root: Path, work: Path, offline: bool) -> tuple[str, list[str], str]:
    """复制独立 CPython，并从锁文件安装普通 wheel 与项目 wheel。"""
    _copy_python_runtime(Path(sys.base_prefix), root / "python")
    target_python = _target_python(root)
    requirements = work / "requirements.txt"
    wheels = work / "wheels"
    wheels.mkdir()
    _run(
        (
            "uv",
            "export",
            "--frozen",
            "--no-dev",
            "--no-emit-project",
            "--format",
            "requirements.txt",
            "--output-file",
            str(requirements),
            "--quiet",
        )
    )
    build_command = ["uv", "build", "--wheel", "--out-dir", str(wheels), "--quiet"]
    if offline:
        build_command.append("--offline")
    _run(build_command)
    wheel = next(wheels.glob("tunnelminion-*.whl"))
    dependency_command = [
        "uv",
        "pip",
        "install",
        "--python",
        str(target_python),
        "--link-mode",
        "copy",
        "--break-system-packages",
        "--requirements",
        str(requirements),
        "--quiet",
    ]
    project_command = [
        "uv",
        "pip",
        "install",
        "--python",
        str(target_python),
        "--link-mode",
        "copy",
        "--break-system-packages",
        "--no-deps",
        str(wheel),
        "--quiet",
    ]
    if offline:
        dependency_command.append("--offline")
        project_command.append("--offline")
    _run(dependency_command)
    _run(project_command)
    shutil.copy2("scripts/runtime_package_fixture.py", root / "runtime_package_fixture.py")
    entrypoint = target_python.relative_to(root).as_posix()
    return entrypoint, ["runtime_package_fixture.py"], "CPython prefix copy + uv.lock wheels"


def _build_onedir(root: Path, work: Path, offline: bool) -> tuple[str, list[str], str]:
    """使用锁定 PyInstaller 构建 one-folder 候选。"""
    del offline
    dist = work / "dist"
    _run(
        (
            sys.executable,
            "-m",
            "PyInstaller",
            "--noconfirm",
            "--clean",
            "--onedir",
            "--name",
            "runtime-package-fixture",
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
            "scripts/runtime_package_fixture.py",
        )
    )
    built = dist / "runtime-package-fixture"
    shutil.copytree(built, root, dirs_exist_ok=True, copy_function=shutil.copy2)
    executable = (
        "runtime-package-fixture.exe" if sys.platform == "win32" else "runtime-package-fixture"
    )
    return executable, [], f"PyInstaller {importlib.metadata.version('pyinstaller')} onedir"


BUILDERS: dict[str, Callable[[Path, Path, bool], tuple[str, list[str], str]]] = {
    "onedir-freeze": _build_onedir,
    "standalone-cpython-wheel": _build_standalone,
}


def _license_label(distribution: importlib.metadata.PackageMetadata) -> str:
    """从标准元数据生成稳定且有界的许可标签。"""
    expression_values = distribution.get_all("License-Expression") or []
    expression = expression_values[0].strip() if expression_values else ""
    if expression:
        return expression
    classifiers = [
        value.removeprefix("License :: ")
        for value in distribution.get_all("Classifier", [])
        if value.startswith("License :: ")
    ]
    if classifiers:
        return " | ".join(classifiers)[:240]
    legacy_values = distribution.get_all("License") or []
    legacy = " ".join(legacy_values[0].split()) if legacy_values else ""
    if legacy and legacy.lower() not in {"none", "unknown"}:
        return legacy[:240]
    return "UNKNOWN"


def _license_inventory(work: Path) -> list[dict[str, JsonValue]]:
    """按当前平台的锁定运行时依赖生成许可清单。"""
    sbom = work / "runtime-sbom.cdx.json"
    _run(
        (
            "uv",
            "export",
            "--frozen",
            "--no-dev",
            "--no-emit-project",
            "--format",
            "cyclonedx1.5",
            "--output-file",
            str(sbom),
            "--quiet",
        )
    )
    payload = cast(dict[str, JsonValue], json.loads(sbom.read_text(encoding="utf-8")))
    components = cast(list[dict[str, JsonValue]], payload["components"])
    inventory: list[dict[str, JsonValue]] = []
    for component in components:
        properties = cast(list[dict[str, JsonValue]], component.get("properties", []))
        markers = [
            cast(str, item["value"])
            for item in properties
            if item.get("name") == "uv:package:marker"
        ]
        if markers and not all(Marker(marker).evaluate() for marker in markers):
            continue
        name = cast(str, component["name"])
        version = cast(str, component["version"])
        try:
            metadata = importlib.metadata.metadata(name)
            license_label = _license_label(metadata)
        except importlib.metadata.PackageNotFoundError:
            license_label = "UNKNOWN"
        inventory.append({"name": name, "version": version, "license": license_label})
    return sorted(inventory, key=lambda item: cast(str, item["name"]).lower())


def _files(root: Path) -> list[dict[str, JsonValue]]:
    """生成稳定排序的逐文件大小与 SHA-256。"""
    return [
        {
            "path": path.relative_to(root).as_posix(),
            "sha256": file_sha256(path),
            "size": path.stat().st_size,
        }
        for path in sorted(
            (item for item in root.rglob("*") if item.is_file()),
            key=lambda item: item.relative_to(root).as_posix(),
        )
    ]


# 正式构建器复用经过双平台 spike 验证的确定性清单函数。
git_revision = _git_revision
source_tree_sha256 = _tree_sha256
license_inventory = _license_inventory
package_files = _files


def build_candidate(
    layout: str,
    output_root: Path,
    manifest_path: Path,
    *,
    offline: bool = False,
    source_revision: str | None = None,
) -> dict[str, JsonValue]:
    """构建一个候选并保存 manifest。"""
    if output_root.exists():
        shutil.rmtree(output_root)
    output_root.parent.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    work_parent = Path("build/runtime-package-spike").resolve()
    work_parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="candidate-", dir=work_parent) as temporary:
        work = Path(temporary)
        output_root.mkdir()
        entrypoint, entrypoint_args, builder = BUILDERS[layout](output_root, work, offline)
        licenses = _license_inventory(work)
    files = _files(output_root)
    manifest: dict[str, JsonValue] = {
        "schema_version": MANIFEST_VERSION,
        "candidate": {
            "id": f"{layout}-{sys.platform}-{platform.machine().lower()}",
            "layout": layout,
            "platform": sys.platform,
            "architecture": platform.machine().lower(),
            "python_version": platform.python_version(),
            "application_version": APPLICATION_VERSION,
        },
        "build": {
            "source_revision": _git_revision(source_revision),
            "source_tree_sha256": _tree_sha256(SOURCE_INPUTS),
            "lock_sha256": file_sha256(Path("uv.lock")),
            "builder": builder,
        },
        "entrypoint": entrypoint,
        "entrypoint_args": cast(JsonValue, entrypoint_args),
        "files": cast(JsonValue, files),
        "licenses": cast(JsonValue, licenses),
    }
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    return {
        "layout": layout,
        "manifest": str(manifest_path.resolve()),
        "package_root": str(output_root.resolve()),
        "file_count": len(files),
        "size_bytes": sum(cast(int, item["size"]) for item in files),
        "build_duration_ms": round((time.monotonic() - started) * 1000, 3),
    }


def main(argv: Sequence[str] | None = None) -> int:
    """解析候选布局与隔离输出路径。"""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--layout", choices=tuple(BUILDERS), required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--source-revision")
    args = parser.parse_args(argv)
    output = args.output_root.resolve()
    manifest = args.manifest.resolve()
    if output == Path.cwd().resolve() or Path.cwd().resolve() in output.parents:
        parser.error("--output-root 必须位于仓库工作目录之外")
    if manifest == Path.cwd().resolve() or Path.cwd().resolve() in manifest.parents:
        parser.error("--manifest 必须位于仓库工作目录之外")
    result = build_candidate(
        args.layout,
        output,
        manifest,
        offline=args.offline,
        source_revision=args.source_revision,
    )
    print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
