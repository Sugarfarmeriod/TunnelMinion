"""真实 A/B 常规入口脚本的默认零副作用与授权清单测试。"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from scripts.run_managed_node_runtime_ab_acceptance import finalize_report, main


def test_default_mode_only_prints_explicit_approval_manifest(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main(["--ssh-target", "10.77.0.1"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["requires_explicit_execute_flag"] is True
    assert report["temporary_bindings"]["coordinator_agent"] == "10.77.0.2:8790"
    assert "HomeMac 或 B 手写 WireGuard 配置" in report["does_not_modify"]


def test_execute_mode_requires_output(tmp_path: Path) -> None:
    del tmp_path
    with pytest.raises(SystemExit, match="--output"):
        main(["--ssh-target", "10.77.0.1", "--execute-approved"])


def test_manual_murus_hash_finalizes_only_a_passing_automated_report(
    tmp_path: Path,
) -> None:
    report_path = tmp_path / "real-ab.json"
    report_path.write_text(
        json.dumps(
            {
                "schema_version": "managed-node-runtime-real-ab/v1",
                "automated_passed": True,
                "passed": False,
            }
        ),
        encoding="utf-8",
    )
    digest = "a" * 64
    assert finalize_report(report_path, digest, digest)["passed"] is True
    assert finalize_report(report_path, digest, "b" * 64)["passed"] is False

    report_path.write_text(
        json.dumps(
            {
                "schema_version": "managed-node-runtime-real-ab/v1",
                "automated_passed": False,
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="自动 A/B"):
        finalize_report(report_path, digest, digest)
