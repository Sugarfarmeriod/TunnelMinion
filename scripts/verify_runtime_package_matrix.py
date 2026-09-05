"""汇总 Windows 与 macOS 正式运行包，校验二者共享同一前端与锁定输入。"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections.abc import Sequence
from pathlib import Path
from typing import cast

EXPECTED_TARGETS = {("win32", "amd64"), ("darwin", "arm64")}
EXPECTED_COMMANDS = {
    "gateway-configure",
    "runtime-configure",
    "runtime-start",
    "runtime-start-repeat",
    "runtime-status",
    "runtime-stop",
    "runtime-status-stopped",
    "package-stage",
    "package-activate",
    "package-status",
    "package-remove",
}


def _load_object(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"JSON 根节点必须是对象：{path}")
    return cast(dict[str, object], value)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _nested_object(value: object, error: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ValueError(error)
    return cast(dict[str, object], value)


def _preserved_evidence(component: dict[str, object], name: str) -> bool:
    evidence = _nested_object(component.get(name), "运行包数据保留证据不完整")
    before = _nested_object(evidence.get("before"), "运行包数据保留证据不完整")
    after = _nested_object(evidence.get("after"), "运行包数据保留证据不完整")
    return (
        before == after
        and set(before) == {"file_count", "size_bytes", "sha256"}
        and type(before.get("file_count")) is int
        and cast(int, before["file_count"]) > 0
        and type(before.get("size_bytes")) is int
        and cast(int, before["size_bytes"]) > 0
        and isinstance(before.get("sha256"), str)
        and len(cast(str, before["sha256"])) == 64
        and all(character in "0123456789abcdef" for character in cast(str, before["sha256"]))
    )


def verify_runtime_package_matrix(evidence_root: Path, frontend_receipt: Path) -> dict[str, object]:
    """验证精确两平台证据及跨平台稳定字段。"""
    receipt = _load_object(frontend_receipt)
    receipt_digest = receipt.get("dist_sha256")
    receipt_count = receipt.get("file_count")
    if not isinstance(receipt_digest, str) or not isinstance(receipt_count, int):
        raise ValueError("前端回执缺少摘要或文件数")

    summary_paths = sorted(evidence_root.rglob("build-summary.json"))
    if len(summary_paths) != 2:
        raise ValueError("双平台汇总必须恰好包含两份构建摘要")
    targets: set[tuple[str, str]] = set()
    revisions: set[str] = set()
    python_locks: set[str] = set()
    npm_locks: set[str] = set()
    package_ids: set[str] = set()
    target_reports: list[dict[str, object]] = []
    for summary_path in summary_paths:
        directory = summary_path.parent
        manifest_path = directory / "manifest.json"
        acceptance_path = directory / "clean-acceptance.json"
        if not manifest_path.is_file() or not acceptance_path.is_file():
            raise ValueError("运行包证据缺少 manifest 或 clean acceptance")
        summary = _load_object(summary_path)
        manifest = _load_object(manifest_path)
        acceptance = _load_object(acceptance_path)
        candidate_value = manifest.get("candidate")
        build_value = manifest.get("build")
        frontend_value = manifest.get("frontend")
        licenses = manifest.get("licenses")
        if (
            manifest.get("schema_version") != "runtime-package-manifest/v2"
            or not isinstance(candidate_value, dict)
            or not isinstance(build_value, dict)
            or not isinstance(frontend_value, dict)
            or not isinstance(licenses, list)
        ):
            raise ValueError("运行包 manifest v2 结构不完整")
        platform_value = summary.get("platform")
        architecture = summary.get("architecture")
        if not isinstance(platform_value, str) or not isinstance(architecture, str):
            raise ValueError("运行包摘要缺少平台或架构")
        target = (platform_value, architecture)
        if target in targets:
            raise ValueError("运行包摘要包含重复平台")
        targets.add(target)
        if (
            summary.get("frontend_dist_sha256") != receipt_digest
            or summary.get("frontend_file_count") != receipt_count
        ):
            raise ValueError("运行包前端与唯一前端回执不一致")
        if summary.get("manifest_sha256") != _sha256(manifest_path):
            raise ValueError("运行包 manifest 摘要不一致")
        if summary.get("unknown_license_count") != 0:
            raise ValueError("运行包包含未知许可证")
        if (
            acceptance.get("schema_version") != "runtime-package-clean-acceptance/v1"
            or acceptance.get("passed") is not True
            or acceptance.get("manifest_sha256") != _sha256(manifest_path)
        ):
            raise ValueError("运行包 clean acceptance 未通过或证据错配")
        if acceptance.get("candidate") != candidate_value:
            raise ValueError("运行包 clean acceptance candidate 与 manifest 不一致")
        components = acceptance.get("components")
        if not isinstance(components, list) or len(cast(list[object], components)) != 1:
            raise ValueError("运行包缺少正式本地产品验收结果")
        component = _nested_object(cast(list[object], components)[0], "运行包隔离运行证据不完整")
        package = _nested_object(component.get("runtime_package"), "运行包总览缺少交付形态证据")
        commands = _nested_object(component.get("commands"), "运行包公开命令证据不完整")
        if set(commands) != EXPECTED_COMMANDS or any(
            _nested_object(value, "运行包公开命令证据不完整").get("exit_code") != 0
            or _nested_object(value, "运行包公开命令证据不完整").get("json_output") is not True
            for value in commands.values()
        ):
            raise ValueError("运行包公开命令证据不完整")
        if (
            component.get("component") != "public-runtime"
            or component.get("passed") is not True
            or component.get("health_status") != 200
            or component.get("app_status") != 200
            or component.get("node_available") is not False
            or component.get("source_environment_present") is not False
            or component.get("external_http_proxy_blocked") is not True
            or component.get("gateway_status") != 401
            or component.get("public_cli") is not True
            or component.get("idempotent_start") is not True
            or component.get("data_preserved") is not True
            or component.get("secret_store_preserved") is not True
            or component.get("secret_leak_detected") is not False
            or component.get("process_cleanup_confirmed") is not True
            or not _preserved_evidence(component, "data_evidence")
            or not _preserved_evidence(component, "secret_store_evidence")
            or package.get("kind") != "standalone"
            or package.get("manifest_schema") != "runtime-package-manifest/v2"
        ):
            raise ValueError("运行包隔离运行证据不完整")
        if acceptance.get("source_entries") != [] or acceptance.get("program_data_entries") != []:
            raise ValueError("运行包包含源码或程序目录运行数据")
        candidate = cast(dict[str, object], candidate_value)
        frontend = cast(dict[str, object], frontend_value)
        if (
            candidate.get("id") != summary.get("package_id")
            or candidate.get("platform") != platform_value
            or candidate.get("architecture") != architecture
            or frontend.get("sha256") != receipt_digest
            or frontend.get("file_count") != receipt_count
        ):
            raise ValueError("运行包 manifest 与构建摘要不一致")
        ecosystems = {
            cast(dict[str, object], item).get("ecosystem")
            for item in cast(list[object], licenses)
            if isinstance(item, dict)
        }
        if ecosystems != {"python", "npm"}:
            raise ValueError("运行包许可证来源不完整")
        revision = summary.get("source_revision")
        python_lock = summary.get("python_lock_sha256")
        npm_lock = summary.get("npm_lock_sha256")
        package_id = summary.get("package_id")
        if not all(
            isinstance(value, str) for value in (revision, python_lock, npm_lock, package_id)
        ):
            raise ValueError("运行包摘要缺少稳定构建字段")
        revisions.add(cast(str, revision))
        python_locks.add(cast(str, python_lock))
        npm_locks.add(cast(str, npm_lock))
        package_ids.add(cast(str, package_id))
        target_reports.append(
            {"platform": platform_value, "architecture": architecture, "passed": True}
        )
    if targets != EXPECTED_TARGETS:
        raise ValueError("运行包目标必须是 Windows amd64 与 macOS arm64")
    if len(revisions) != 1 or len(python_locks) != 1 or len(npm_locks) != 1:
        raise ValueError("双平台运行包没有使用同一源码与锁文件")
    if len(package_ids) != 2:
        raise ValueError("双平台运行包 ID 必须按平台区分")
    return {
        "schema_version": "runtime-package-matrix/v1",
        "frontend_dist_sha256": receipt_digest,
        "frontend_file_count": receipt_count,
        "source_revision": next(iter(revisions)),
        "python_lock_sha256": next(iter(python_locks)),
        "npm_lock_sha256": next(iter(npm_locks)),
        "targets": sorted(target_reports, key=lambda item: cast(str, item["platform"])),
        "passed": True,
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-root", type=Path, required=True)
    parser.add_argument("--frontend-receipt", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    summary = verify_runtime_package_matrix(args.evidence_root, args.frontend_receipt)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
