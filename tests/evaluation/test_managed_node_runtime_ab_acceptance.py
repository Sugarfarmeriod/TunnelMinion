"""真实 A/B 常规入口脚本的默认零副作用与授权清单测试。"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from scripts.run_managed_node_runtime_ab_acceptance import (
    main,
    preflight_failure_reasons,
)


def test_default_mode_only_prints_explicit_approval_manifest(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main(["--ssh-target", "10.77.0.1"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["requires_explicit_execute_flag"] is True
    assert report["temporary_bindings"]["coordinator_agent"] == "10.77.0.2:8790"
    assert "HomeMac 或 B 手写 WireGuard 配置" in report["does_not_modify"]
    assert "manual_evidence_required" not in report


def test_execute_mode_requires_output(tmp_path: Path) -> None:
    del tmp_path
    with pytest.raises(SystemExit, match="--output"):
        main(["--ssh-target", "10.77.0.1", "--execute-approved"])


def test_preflight_rejects_missing_production_baseline() -> None:
    assert preflight_failure_reasons(
        {"service": "Running", "adapter": "Up"},
        {"model_8082": False, "gateway_8787": False},
    ) == (
        "macos_model_8082_not_reachable",
        "macos_gateway_8787_not_reachable",
    )


def test_preflight_accepts_ready_production_baseline() -> None:
    assert not preflight_failure_reasons(
        {"service": "Running", "adapter": "Up"},
        {"model_8082": True, "gateway_8787": True},
    )
