"""在搬离源码与开发环境后验证 TunnelMinion 运行包候选。"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import cast

from pydantic import JsonValue

from tunnelminion.runtime.preflight import verify_runtime_package

MANIFEST_VERSION = "runtime-package-manifest/v1"
FORBIDDEN_PROGRAM_DATA = frozenset(
    {
        "gateway.json",
        "managed-node.json",
        "model.json",
        "node-id",
        "runtime.sqlite3",
    }
)
EXPECTED_NATIVE_EXTENSION_COUNT = 5
STARTUP_TIMEOUT_SECONDS = 30.0


def file_sha256(path: Path) -> str:
    """流式计算文件 SHA-256。"""
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _safe_package_path(root: Path, relative: str) -> Path:
    """解析 manifest 相对路径并拒绝逃逸包根目录。"""
    candidate = (root / Path(relative)).resolve()
    try:
        candidate.relative_to(root.resolve())
    except ValueError as exc:
        raise ValueError("manifest 路径逃逸运行包") from exc
    return candidate


def _resolve_entrypoint_args(
    package_root: Path,
    entrypoint_args: Sequence[str],
    package_files: set[str],
) -> list[str]:
    """把清单中指向包内文件的参数解析到搬迁后的绝对路径。"""
    return [
        str(_safe_package_path(package_root, argument)) if argument in package_files else argument
        for argument in entrypoint_args
    ]


def load_and_verify_manifest(
    package_root: Path,
    manifest_path: Path,
    schema_path: Path,
) -> dict[str, JsonValue]:
    """复用产品启动与安装的权威运行包校验，再返回清单。"""
    verify_runtime_package(package_root, manifest_path, schema_path, ())
    return cast(dict[str, JsonValue], json.loads(manifest_path.read_text(encoding="utf-8")))


def sanitized_environment(source: Mapping[str, str] | None = None) -> dict[str, str]:
    """移除会把开发解释器、项目或用户 site-packages 注入候选的环境变量。"""
    values = dict(os.environ if source is None else source)
    for name in tuple(values):
        if name in {"CONDA_PREFIX", "PYTHONHOME", "PYTHONPATH", "VIRTUAL_ENV"} or name.startswith(
            "UV_"
        ):
            values.pop(name, None)
    values["PYTHONNOUSERSITE"] = "1"
    return values


def _available_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return cast(int, listener.getsockname()[1])


def _read_json(url: str, timeout_seconds: float) -> tuple[int, dict[str, JsonValue]]:
    try:
        with urllib.request.urlopen(url, timeout=timeout_seconds) as response:
            return response.status, cast(dict[str, JsonValue], json.load(response))
    except urllib.error.HTTPError as exc:
        with exc:
            body = json.loads(exc.read().decode("utf-8"))
        return exc.code, cast(dict[str, JsonValue], body)


def _wait_for_fixture(port: int, timeout_seconds: float) -> dict[str, JsonValue]:
    deadline = time.monotonic() + timeout_seconds
    last_error: OSError | None = None
    while time.monotonic() < deadline:
        try:
            status, body = _read_json(
                f"http://127.0.0.1:{port}/__runtime_package_fixture__",
                min(1.0, timeout_seconds),
            )
            if status == 200:
                return body
        except OSError as exc:
            last_error = exc
        time.sleep(0.05)
    raise TimeoutError("运行包 fixture 未在预算内就绪") from last_error


def _component_probe(component: str, port: int) -> int:
    path = "/api/resources/health" if component == "local" else "/v1/capabilities"
    status, _body = _read_json(f"http://127.0.0.1:{port}{path}", 2.0)
    return status


def _path_hits(values: Sequence[str], forbidden_paths: Sequence[Path]) -> int:
    normalized = tuple(path.resolve() for path in forbidden_paths)
    hits = 0
    for value in values:
        if not value:
            continue
        candidate = Path(value).resolve()
        if any(candidate == root or root in candidate.parents for root in normalized):
            hits += 1
    return hits


def _is_native_keyring_backend(backend: str) -> bool:
    """判断当前平台是否发现系统原生凭据后端。"""
    prefix = "keyring.backends.Windows." if sys.platform == "win32" else "keyring.backends.macOS."
    return backend.startswith(prefix)


def run_component(
    entrypoint: Path,
    entrypoint_args: Sequence[str],
    component: str,
    data_dir: Path,
    working_dir: Path,
    forbidden_paths: Sequence[Path],
) -> dict[str, JsonValue]:
    """启动一个候选组件，验证真实端点和开发环境隔离后安全停止。"""
    port = _available_port()
    started = time.monotonic()
    process = subprocess.Popen(
        (
            str(entrypoint),
            *entrypoint_args,
            "--component",
            component,
            "--data-dir",
            str(data_dir),
            "--port",
            str(port),
        ),
        cwd=working_dir,
        env=sanitized_environment(),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        try:
            fixture = _wait_for_fixture(port, STARTUP_TIMEOUT_SECONDS)
        except TimeoutError:
            exit_code = process.poll()
            return {
                "component": component,
                "duration_ms": round((time.monotonic() - started) * 1000, 3),
                "error_code": (
                    "process-exited-before-ready" if exit_code is not None else "startup-timeout"
                ),
                "exit_code": exit_code,
                "passed": False,
            }
        sys_path = cast(list[str], fixture["sys_path"])
        keyring_backend = cast(str, fixture["keyring_backend"])
        native_extensions = cast(list[str], fixture["native_extensions"])
        probe_status = _component_probe(component, port)
        expected_status = 200 if component == "local" else 401
        passed = (
            fixture["component"] == component
            and fixture["pythonpath_present"] is False
            and fixture["user_site_enabled"] is False
            and _is_native_keyring_backend(keyring_backend)
            and len(native_extensions) == EXPECTED_NATIVE_EXTENSION_COUNT
            and _path_hits(sys_path, forbidden_paths) == 0
            and probe_status == expected_status
            and process.poll() is None
        )
        return {
            "component": component,
            "duration_ms": round((time.monotonic() - started) * 1000, 3),
            "error_code": None,
            "exit_code": None,
            "forbidden_path_hits": _path_hits(sys_path, forbidden_paths),
            "http_status": probe_status,
            "keyring_backend": keyring_backend,
            "native_extension_count": len(native_extensions),
            "passed": passed,
            "pythonpath_present": fixture["pythonpath_present"],
            "user_site_enabled": fixture["user_site_enabled"],
        }
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)


def run_acceptance(
    package_root: Path,
    manifest_path: Path,
    schema_path: Path,
    forbidden_paths: Sequence[Path],
) -> dict[str, JsonValue]:
    """复制候选后执行 local/Gateway 相同验收并返回脱敏证据。"""
    manifest = load_and_verify_manifest(package_root, manifest_path, schema_path)
    candidate = cast(dict[str, JsonValue], manifest["candidate"])
    files = cast(list[dict[str, JsonValue]], manifest["files"])
    with tempfile.TemporaryDirectory(prefix="tunnelminion-package-clean-") as temporary:
        sandbox = Path(temporary)
        relocated = sandbox / "program"
        shutil.copytree(package_root, relocated)
        entrypoint = _safe_package_path(relocated, cast(str, manifest["entrypoint"]))
        entrypoint_args = _resolve_entrypoint_args(
            relocated,
            cast(list[str], manifest["entrypoint_args"]),
            {cast(str, item["path"]) for item in files},
        )
        work = sandbox / "work"
        work.mkdir()
        results = [
            run_component(
                entrypoint,
                entrypoint_args,
                component,
                sandbox / f"data-{component}",
                work,
                forbidden_paths,
            )
            for component in ("local", "gateway")
        ]
        program_data_entries = sorted(
            path.name for path in relocated.rglob("*") if path.name in FORBIDDEN_PROGRAM_DATA
        )
    passed = all(result["passed"] is True for result in results) and not program_data_entries
    return {
        "schema_version": "runtime-package-clean-acceptance/v1",
        "candidate": candidate,
        "manifest_sha256": file_sha256(manifest_path),
        "package_file_count": len(files),
        "package_size_bytes": sum(cast(int, item["size"]) for item in files),
        "components": cast(JsonValue, results),
        "program_data_entries": cast(JsonValue, program_data_entries),
        "passed": passed,
    }


def main(argv: Sequence[str] | None = None) -> int:
    """解析候选目录并保存可复核 JSON 报告。"""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package-root", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument(
        "--schema",
        type=Path,
        default=Path("schemas/runtime-package-manifest-v1.schema.json"),
    )
    parser.add_argument("--forbid-path", type=Path, action="append", default=[])
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    report = run_acceptance(
        args.package_root,
        args.manifest,
        args.schema,
        tuple(args.forbid_path),
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False))
    return 0 if report["passed"] is True or not args.check else 1


if __name__ == "__main__":
    raise SystemExit(main())
