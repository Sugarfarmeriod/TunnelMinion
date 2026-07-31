"""常规 managed node 入口的隔离 A/B 组装验收。"""

from __future__ import annotations

import json
from pathlib import Path

from scripts.run_managed_node_runtime_acceptance import main, run_acceptance


def test_isolated_windows_and_macos_regular_entries_pass(tmp_path: Path) -> None:
    report = run_acceptance(tmp_path)
    assert report["passed"] is True
    metrics = report["metrics"]
    assert isinstance(metrics, dict)
    assert metrics["identity_duplicate_count"] == 0
    assert metrics["security_block_rate"] == 1
    assert metrics["recovery_success_rate"] == 1
    assert metrics["model_invariance_rate"] == 1
    assert metrics["assembly_duration_ms"] > 0
    assert metrics["peak_memory_bytes"] > 0


def test_cli_writes_redacted_report(tmp_path: Path, capsys: object) -> None:
    del capsys
    output = tmp_path / "report.json"
    assert main(["--output", str(output), "--check"]) == 0
    report = json.loads(output.read_text(encoding="utf-8"))
    serialized = output.read_text(encoding="utf-8").lower()
    assert report["passed"] is True
    for forbidden in ("tmnr_", "private_key", "refresh_credential", "10.77."):
        assert forbidden not in serialized
