"""运行不依赖本地 lifecycle 的只读 A/B peer 验收。"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import cast

from tunnelminion.runtime.acceptance import (
    PeerAcceptanceProbe,
    PeerAcceptanceResult,
    package_entrypoint_summary,
)

REPORT_VERSION = "runtime-health-peer-acceptance/v1"
_FORBIDDEN_OUTPUT_MARKERS = (
    "tmn_",
    "bearer ",
    "private_key",
    "-----begin",
    "authorization:",
)


def run_acceptance(
    endpoint: str,
    manifest_path: Path,
    *,
    probe: PeerAcceptanceProbe | None = None,
) -> dict[str, object]:
    """读取 manifest 并返回独立 peer 结果，不写本地 runtime 状态。"""
    manifest_bytes = manifest_path.read_bytes()
    raw_manifest = json.loads(manifest_bytes.decode("utf-8"))
    if not isinstance(raw_manifest, Mapping):
        raise ValueError("package manifest 根节点必须是对象")
    manifest = cast(Mapping[str, object], raw_manifest)
    package = package_entrypoint_summary(manifest, manifest_bytes=manifest_bytes)
    result = (probe or PeerAcceptanceProbe()).probe(endpoint, package)
    report = _report(result, manifest_bytes)
    serialized = json.dumps(report, ensure_ascii=False, sort_keys=True)
    if any(marker in serialized.lower() for marker in _FORBIDDEN_OUTPUT_MARKERS):
        raise RuntimeError("peer acceptance 报告包含禁止秘密字段")
    return report


def _report(result: PeerAcceptanceResult, manifest_bytes: bytes) -> dict[str, object]:
    """组合独立结果与稳定输入摘要，不复制 manifest 正文。"""
    return {
        "schema_version": REPORT_VERSION,
        "mode": "independent_peer_probe",
        "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "peer": result.model_dump(mode="json"),
        "local_lifecycle_dependency": False,
        "runtime_state_written": False,
        "secret_store_read": False,
        "excluded": [
            "authorization_header",
            "gateway_token",
            "response_body",
            "full_endpoint",
            "local_process_state",
        ],
    }


def main(argv: Sequence[str] | None = None) -> int:
    """执行一次显式指定的只读 peer 验收并保存脱敏报告。"""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--endpoint", required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    report = run_acceptance(args.endpoint, args.manifest)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if cast(dict[str, object], report["peer"])["accepted"] is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
