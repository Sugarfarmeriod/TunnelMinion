"""启动正式 PyInstaller 本机产品，供 Playwright 执行完整界面验收。"""

from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import signal
import subprocess
import time
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import cast
from uuid import uuid4

from pydantic import JsonValue

if __package__:
    from scripts.prepare_local_product_package_fixture import (
        ALLOWED_DATA_FILES,
        FIXTURE_SCHEMA,
        resolve_platform_name,
    )
    from scripts.run_runtime_package_clean_acceptance import (
        STARTUP_TIMEOUT_SECONDS,
        file_sha256,
        isolated_product_environment,
        load_and_verify_manifest,
        safe_package_path,
        wait_for_status,
    )
else:
    from prepare_local_product_package_fixture import (
        ALLOWED_DATA_FILES,
        FIXTURE_SCHEMA,
        resolve_platform_name,
    )
    from run_runtime_package_clean_acceptance import (
        STARTUP_TIMEOUT_SECONDS,
        file_sha256,
        isolated_product_environment,
        load_and_verify_manifest,
        safe_package_path,
        wait_for_status,
    )


def load_and_verify_fixture(data_dir: Path, receipt_path: Path) -> dict[str, JsonValue]:
    """验证夹具回执、平台和数据目录 closed set 后再交给正式包。"""
    receipt = cast(dict[str, JsonValue], json.loads(receipt_path.read_text(encoding="utf-8")))
    if receipt.get("schema_version") != FIXTURE_SCHEMA:
        raise ValueError("正式包浏览器夹具 schema 不受支持")
    if receipt.get("platform") != resolve_platform_name():
        raise ValueError("正式包浏览器夹具平台不匹配")
    if receipt.get("contains_secrets") is not False:
        raise ValueError("正式包浏览器夹具未证明无秘密")
    files = receipt.get("files")
    if not isinstance(files, list):
        raise ValueError("正式包浏览器夹具缺少文件清单")
    expected: dict[str, tuple[str, int]] = {}
    for value in files:
        if not isinstance(value, dict):
            raise ValueError("正式包浏览器夹具文件项无效")
        path = value.get("path")
        digest = value.get("sha256")
        size = value.get("size")
        if not isinstance(path, str) or not isinstance(digest, str) or not isinstance(size, int):
            raise ValueError("正式包浏览器夹具文件字段无效")
        expected[path] = (digest, size)
    if frozenset(expected) != ALLOWED_DATA_FILES:
        raise ValueError("正式包浏览器夹具文件清单不是 closed set")
    actual = tuple(sorted(data_dir.iterdir(), key=lambda item: item.name))
    if any(path.is_symlink() or not path.is_file() for path in actual):
        raise ValueError("正式包浏览器夹具只能包含普通文件")
    if {path.name for path in actual} != set(expected):
        raise ValueError("正式包浏览器夹具目录与回执不一致")
    for path in actual:
        digest, size = expected[path.name]
        if path.stat().st_size != size or file_sha256(path) != digest:
            raise ValueError("正式包浏览器夹具摘要不匹配")
    return receipt


def package_process_environment(
    work_dir: Path, source: Mapping[str, str] | None = None
) -> dict[str, str]:
    """让正式包子进程看不到 Node、源码注入变量和外部 HTTP 网络。"""
    return isolated_product_environment(work_dir / "empty-path", source)


def run_server(
    package_root: Path,
    manifest_path: Path,
    schema_path: Path,
    data_dir: Path,
    fixture_receipt: Path,
    host: str,
    port: int,
) -> int:
    """校验正式包与夹具，保持本机产品运行直到 Playwright 结束。"""
    if host != "127.0.0.1":
        raise ValueError("正式包浏览器验收只允许 IPv4 环回地址")
    manifest = load_and_verify_manifest(package_root, manifest_path, schema_path)
    load_and_verify_fixture(data_dir, fixture_receipt)
    relocated = data_dir.parent / "program"
    if relocated.exists():
        raise ValueError("正式包浏览器搬迁目录必须不存在")
    shutil.copytree(package_root, relocated)
    entrypoint = safe_package_path(relocated, cast(str, manifest["entrypoint"]))
    work_dir = data_dir.parent / "work"
    work_dir.mkdir(parents=True, exist_ok=True)
    log_file = data_dir / "runtime" / "logs" / "local.log"
    process = subprocess.Popen(
        (
            str(entrypoint),
            "runtime-child",
            "--runtime-component=local",
            f"--runtime-instance-id={uuid4()}",
            "--data-dir",
            str(data_dir),
            "--local-port",
            str(port),
            "--runtime-log-file",
            str(log_file),
        ),
        cwd=work_dir,
        env=package_process_environment(work_dir),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    stopping = False

    def stop(_signum: int, _frame: object) -> None:
        nonlocal stopping
        stopping = True
        if process.poll() is None:
            process.terminate()

    previous_handlers = {
        name: signal.signal(name, stop) for name in (signal.SIGINT, signal.SIGTERM)
    }
    try:
        wait_for_status(
            f"http://{host}:{port}/api/resources/health",
            200,
            STARTUP_TIMEOUT_SECONDS,
        )
        while process.poll() is None and not stopping:
            time.sleep(0.1)
        return 0 if stopping else cast(int, process.returncode)
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        for name, handler in previous_handlers.items():
            signal.signal(name, handler)


def _required_path(parser: argparse.ArgumentParser, name: str, explicit: Path | None) -> Path:
    """优先使用参数，否则读取 CI/Playwright 传入的绝对路径环境变量。"""
    if explicit is not None:
        return explicit
    value = os.environ.get(name)
    if value is None:
        parser.error(f"缺少 {name}")
    return Path(value)


def main(argv: Sequence[str] | None = None) -> int:
    """解析正式包、夹具和端口并启动产品子进程。"""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package-root", type=Path)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--schema", type=Path)
    parser.add_argument("--data-dir", type=Path)
    parser.add_argument("--fixture-receipt", type=Path)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=4175)
    args = parser.parse_args(argv)
    if platform.machine() == "":
        parser.error("无法识别当前架构")
    return run_server(
        _required_path(parser, "TUNNELMINION_PACKAGE_ROOT", args.package_root),
        _required_path(parser, "TUNNELMINION_PACKAGE_MANIFEST", args.manifest),
        _required_path(parser, "TUNNELMINION_PACKAGE_SCHEMA", args.schema),
        _required_path(parser, "TUNNELMINION_PACKAGE_DATA_DIR", args.data_dir),
        _required_path(parser, "TUNNELMINION_PACKAGE_FIXTURE", args.fixture_receipt),
        args.host,
        args.port,
    )


if __name__ == "__main__":
    raise SystemExit(main())
