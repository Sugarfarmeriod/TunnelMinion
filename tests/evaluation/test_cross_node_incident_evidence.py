"""Windows/macOS 隔离跨节点回执与矩阵绑定测试。"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest
from scripts import run_cross_node_incident_platform_acceptance as acceptance_cli

from tunnelminion.domain.tools import Platform
from tunnelminion.evaluation.cross_node_evidence import (
    CrossNodePlatformReceipt,
    run_platform_acceptance,
    validate_platform_matrix,
)
from tunnelminion.evaluation.incidents import IncidentEvaluationDataset

DATASET = Path("evaluations/datasets/autonomous-incidents-v5.json")
REVISION = "a" * 40


def dataset() -> IncidentEvaluationDataset:
    return IncidentEvaluationDataset.model_validate_json(DATASET.read_text(encoding="utf-8"))


def receipt(platform: Platform) -> CrossNodePlatformReceipt:
    return asyncio.run(run_platform_acceptance(dataset(), platform, REVISION))


def test_platform_receipt_proves_isolated_gateway_and_zero_local_execution() -> None:
    result = receipt(Platform.WINDOWS)

    assert result.passed is True
    assert result.host_platform is Platform.WINDOWS
    assert result.source_revision == REVISION
    assert result.dataset_version == "v5"
    assert result.network_transport == "in-memory-asgi"
    assert result.secret_store_accesses == 0
    assert result.system_writes_performed is False
    assert result.remote_completion_rate == 1.0
    assert result.remote_local_tool_executions == 0
    assert {item.preflight_status for item in result.remote_scenarios} == {
        "success",
        "rejected",
    }
    success = next(
        item
        for item in result.remote_scenarios
        if item.scenario_id == "remote-macos-loopback-listener"
    )
    assert success.request_platform is Platform.WINDOWS
    assert success.target_platform is Platform.MACOS
    assert success.target_tool_attempts == (
        "get_node_summary",
        "list_network_listeners",
    )
    assert success.local_tool_attempts == ()


def test_platform_matrix_requires_two_matching_real_hosts() -> None:
    windows = receipt(Platform.WINDOWS)
    macos = receipt(Platform.MACOS)

    matrix = validate_platform_matrix((windows, macos))

    assert matrix.passed is True
    assert matrix.platforms == (Platform.WINDOWS, Platform.MACOS)
    assert matrix.violations == ()

    mismatch = validate_platform_matrix(
        (windows, macos.model_copy(update={"source_revision": "b" * 40}))
    )
    assert mismatch.passed is False
    assert mismatch.violations == ("source_revision_mismatch",)


def test_platform_cli_binds_trusted_revision_and_writes_no_secret(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = tmp_path / "windows.json"

    def revision(_output: Path) -> str:
        return REVISION

    monkeypatch.setattr(acceptance_cli, "_repository_revision", revision)
    monkeypatch.setattr(acceptance_cli, "_host_platform", lambda: Platform.WINDOWS)

    assert (
        acceptance_cli.main(
            [
                "run",
                "--platform",
                "windows",
                "--dataset",
                str(DATASET),
                "--output",
                str(output),
                "--check",
            ]
        )
        == 0
    )
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["source_revision"] == REVISION
    assert payload["secret_store_accesses"] == 0

    matrix_output = tmp_path / "matrix.json"
    macos_output = tmp_path / "macos.json"
    macos_output.write_text(
        receipt(Platform.MACOS).model_dump_json(indent=2),
        encoding="utf-8",
    )
    assert (
        acceptance_cli.main(
            [
                "validate",
                "--windows",
                str(output),
                "--macos",
                str(macos_output),
                "--output",
                str(matrix_output),
                "--check",
            ]
        )
        == 0
    )
    assert json.loads(matrix_output.read_text(encoding="utf-8"))["passed"] is True
