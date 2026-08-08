"""生成 Python 全依赖漏洞与许可证证据，并在证据不完整时失败。"""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import subprocess
import sys
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any, cast

PIP_AUDIT_VERSION = "2.10.1"
PIP_LICENSES_VERSION = "5.5.5"
DENIED_LICENSE_MARKERS = (
    "AGPL",
    "GPL-3.0",
    "GNU GENERAL PUBLIC LICENSE VERSION 3",
    "SSPL",
    "BUSL",
    "UNKNOWN",
)
CommandRunner = Callable[[Sequence[str], Path], subprocess.CompletedProcess[str]]


def run_command(command: Sequence[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    """运行证据工具并完整捕获结构化输出。"""
    return subprocess.run(command, cwd=cwd, capture_output=True, text=True, check=False)


def normalize_licenses(value: Any) -> list[dict[str, str]]:
    """只保留依赖身份、版本、许可证和主页，避免上传许可证全文。"""
    if not isinstance(value, list):
        raise ValueError("pip-licenses 没有返回列表")
    normalized: list[dict[str, str]] = []
    for raw_item in cast(list[object], value):
        if not isinstance(raw_item, dict):
            raise ValueError("pip-licenses 包记录格式无效")
        item = cast(dict[str, object], raw_item)
        record = {
            field: str(item.get(field, "")).strip()
            for field in ("Name", "Version", "License", "URL")
        }
        if not record["Name"] or not record["Version"] or not record["License"]:
            raise ValueError("Python 依赖缺少名称、版本或许可证")
        upper = record["License"].upper()
        if any(marker in upper for marker in DENIED_LICENSE_MARKERS):
            raise ValueError(f"Python 依赖 {record['Name']} 使用未接受许可证")
        normalized.append(record)
    if not normalized:
        raise ValueError("pip-licenses 没有返回任何依赖")
    return sorted(normalized, key=lambda item: (item["Name"].lower(), item["Version"]))


def audit_vulnerability_count(value: Any) -> int:
    """读取 pip-audit JSON；格式不完整时不能当作零漏洞。"""
    if not isinstance(value, dict):
        raise ValueError("pip-audit 没有返回完整依赖列表")
    payload = cast(dict[str, object], value)
    dependencies_value = payload.get("dependencies")
    if not isinstance(dependencies_value, list):
        raise ValueError("pip-audit 没有返回完整依赖列表")
    dependencies = cast(list[object], dependencies_value)
    total = 0
    for raw_dependency in dependencies:
        if not isinstance(raw_dependency, dict):
            raise ValueError("pip-audit 依赖记录格式无效")
        dependency = cast(dict[str, object], raw_dependency)
        vulnerabilities = dependency.get("vulns")
        if not isinstance(vulnerabilities, list):
            raise ValueError("pip-audit 依赖记录格式无效")
        total += len(cast(list[object], vulnerabilities))
    return total


def sha256(path: Path) -> str:
    """计算锁文件摘要。"""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def generate_evidence(root: Path, output_dir: Path, run: CommandRunner = run_command) -> None:
    """执行固定版本工具并写入规范化、可归档的 JSON 证据。"""
    root = root.resolve()
    output_dir = output_dir.resolve()
    if output_dir != root and root not in output_dir.parents:
        raise ValueError("证据目录必须位于仓库内")
    lock = root / "uv.lock"
    if not lock.is_file():
        raise ValueError("仓库缺少 uv.lock")
    output_dir.mkdir(parents=True, exist_ok=True)
    requirements = output_dir / "python-requirements.txt"
    exported = run(
        (
            "uv",
            "export",
            "--locked",
            "--all-groups",
            "--no-emit-project",
            "--no-hashes",
            "--output-file",
            str(requirements),
        ),
        root,
    )
    if exported.returncode != 0:
        raise RuntimeError(f"uv export 证据未生成（exit {exported.returncode}）")

    audit = run(
        (
            "uvx",
            "--from",
            f"pip-audit=={PIP_AUDIT_VERSION}",
            "pip-audit",
            "--requirement",
            str(requirements),
            "--strict",
            "--progress-spinner",
            "off",
            "--format",
            "json",
        ),
        root,
    )
    try:
        audit_payload = json.loads(audit.stdout)
        vulnerability_count = audit_vulnerability_count(audit_payload)
        audit_status = "clean" if vulnerability_count == 0 else "vulnerable"
    except (json.JSONDecodeError, ValueError):
        audit_payload = None
        vulnerability_count = None
        audit_status = "unavailable"
    audit_evidence = {
        "schema": "tunnelminion/python-audit-evidence/v1",
        "tool": f"pip-audit=={PIP_AUDIT_VERSION}",
        "platform": platform.platform(),
        "lockSha256": sha256(lock),
        "status": audit_status,
        "vulnerabilityCount": vulnerability_count,
        "report": audit_payload,
    }
    (output_dir / "python-audit.json").write_text(
        json.dumps(audit_evidence, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    if audit.returncode != 0 or vulnerability_count != 0:
        raise RuntimeError(f"pip-audit 未通过（exit {audit.returncode}，status {audit_status}）")

    licenses = run(
        (
            "uvx",
            "--from",
            f"pip-licenses=={PIP_LICENSES_VERSION}",
            "pip-licenses",
            "--python",
            sys.executable,
            "--from",
            "mixed",
            "--format",
            "json",
            "--with-urls",
        ),
        root,
    )
    if licenses.returncode != 0:
        raise RuntimeError(f"pip-licenses 证据未生成（exit {licenses.returncode}）")
    normalized = normalize_licenses(json.loads(licenses.stdout))
    license_evidence = {
        "schema": "tunnelminion/python-license-evidence/v1",
        "tool": f"pip-licenses=={PIP_LICENSES_VERSION}",
        "platform": platform.platform(),
        "lockSha256": sha256(lock),
        "packageCount": len(normalized),
        "packages": normalized,
    }
    (output_dir / "python-licenses.json").write_text(
        json.dumps(license_evidence, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def main(argv: Sequence[str] | None = None) -> int:
    """命令行入口。"""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        generate_evidence(args.root, args.output_dir)
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
        print(f"Python supply-chain evidence failed: {exc}", file=sys.stderr)
        return 1
    print("Python supply chain: vulnerability and license evidence generated")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
