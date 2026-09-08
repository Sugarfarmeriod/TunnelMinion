"""跨节点 incident 的双平台隔离回执与一致性矩阵。"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Literal
from unittest.mock import patch

import keyring
from pydantic import BaseModel, ConfigDict, Field

from tunnelminion.agent.prompts import INCIDENT_INVESTIGATION_PROMPT
from tunnelminion.domain.identifiers import ToolRunId
from tunnelminion.domain.tools import Platform
from tunnelminion.evaluation.incidents import (
    IncidentEvaluationDataset,
    IncidentScenarioResult,
    run_incident_dataset,
)
from tunnelminion.incident.contracts import IncidentStatus, SnapshotSource
from tunnelminion.incident.storage import SQLiteIncidentStore


class RemoteScenarioReceipt(BaseModel):
    """一项远端固定场景的最小可复核结果。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    scenario_id: str
    request_platform: Platform
    target_platform: Platform
    snapshot_source: SnapshotSource
    preflight_status: Literal["success", "rejected"]
    preflight_tool_run_id: ToolRunId | None = None
    status: IncidentStatus
    selected_tools: tuple[str, ...]
    local_tool_attempts: tuple[str, ...]
    target_tool_attempts: tuple[str, ...]
    evidence_count: int = Field(ge=0)
    task_completed: bool


class CrossNodePlatformReceipt(BaseModel):
    """一个真实宿主执行隔离跨节点矩阵后的版本化回执。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["cross-node-incident-platform/v1"] = (
        "cross-node-incident-platform/v1"
    )
    host_platform: Platform
    source_revision: str = Field(pattern=r"^[0-9a-f]{40}$")
    dataset_id: str
    dataset_version: str
    dataset_content_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    prompt_version: str
    prompt_content_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    tool_versions: dict[str, str]
    generated_at: datetime
    network_transport: Literal["in-memory-asgi"] = "in-memory-asgi"
    secret_store_accesses: int = Field(ge=0)
    system_writes_performed: bool
    remote_completion_rate: float = Field(ge=0, le=1)
    remote_local_tool_executions: int = Field(ge=0)
    remote_fallback_tool_calls: int = Field(ge=0)
    remote_scenarios: tuple[RemoteScenarioReceipt, ...] = Field(min_length=2)
    violations: tuple[str, ...] = ()
    passed: bool


class CrossNodePlatformMatrix(BaseModel):
    """Windows 与 macOS 回执在同一候选上的一致性裁决。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["cross-node-incident-platform-matrix/v1"] = (
        "cross-node-incident-platform-matrix/v1"
    )
    source_revision: str = Field(pattern=r"^[0-9a-f]{40}$")
    dataset_content_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    prompt_content_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    tool_versions: dict[str, str]
    platforms: tuple[Platform, Platform]
    receipt_hashes: dict[str, str]
    generated_at: datetime
    violations: tuple[str, ...]
    passed: bool


def _remote_receipt(result: IncidentScenarioResult) -> RemoteScenarioReceipt:
    if result.status is None or result.preflight_status == "not_applicable":
        raise ValueError("远端场景缺少终态或预检分类")
    return RemoteScenarioReceipt(
        scenario_id=result.scenario_id,
        request_platform=result.request_platform,
        target_platform=result.target_platform,
        snapshot_source=result.snapshot_source,
        preflight_status=result.preflight_status,
        preflight_tool_run_id=result.preflight_tool_run_id,
        status=result.status,
        selected_tools=result.selected_tools,
        local_tool_attempts=result.local_tool_attempts,
        target_tool_attempts=result.target_tool_attempts,
        evidence_count=result.evidence_count,
        task_completed=result.task_completed,
    )


async def run_platform_acceptance(
    dataset: IncidentEvaluationDataset,
    host_platform: Platform,
    source_revision: str,
) -> CrossNodePlatformReceipt:
    """只用临时 SQLite、内存凭据和 ASGI transport 运行固定矩阵。"""
    secret_store_accesses = 0

    def reject_secret_access(*_args: object, **_kwargs: object) -> str | None:
        nonlocal secret_store_accesses
        secret_store_accesses += 1
        raise RuntimeError("隔离平台验收禁止访问系统秘密存储")

    with (
        patch.object(keyring, "get_password", reject_secret_access),
        patch.object(keyring, "set_password", reject_secret_access),
        patch.object(keyring, "delete_password", reject_secret_access),
        TemporaryDirectory(prefix="tunnelminion-cross-node-platform-") as directory,
    ):
        report = await run_incident_dataset(
            dataset,
            SQLiteIncidentStore(Path(directory) / "incidents.sqlite3"),
        )
    remote = tuple(
        _remote_receipt(item) for item in report.scenarios if item.execution_scope == "remote"
    )
    violations = (
        *report.gate_violations,
        *(("remote_scenario_count",) if len(remote) < 2 else ()),
        *(
            ("remote_local_tool_execution",)
            if report.metrics.remote_local_tool_executions
            else ()
        ),
        *(
            ("remote_fallback_tool_call",)
            if report.metrics.remote_fallback_tool_calls
            else ()
        ),
        *(("remote_completion_rate",) if report.metrics.remote_completion_rate < 1 else ()),
    )
    return CrossNodePlatformReceipt(
        host_platform=host_platform,
        source_revision=source_revision,
        dataset_id=report.dataset_id,
        dataset_version=report.dataset_version,
        dataset_content_hash=report.dataset_content_hash,
        prompt_version=(
            f"{INCIDENT_INVESTIGATION_PROMPT.prompt_id}-"
            f"{INCIDENT_INVESTIGATION_PROMPT.version}"
        ),
        prompt_content_hash=INCIDENT_INVESTIGATION_PROMPT.content_hash,
        tool_versions=report.tool_versions,
        generated_at=datetime.now(UTC),
        secret_store_accesses=secret_store_accesses,
        system_writes_performed=False,
        remote_completion_rate=report.metrics.remote_completion_rate,
        remote_local_tool_executions=report.metrics.remote_local_tool_executions,
        remote_fallback_tool_calls=report.metrics.remote_fallback_tool_calls,
        remote_scenarios=remote,
        violations=violations,
        passed=not violations,
    )


def _receipt_hash(receipt: CrossNodePlatformReceipt) -> str:
    payload = json.dumps(
        receipt.model_dump(mode="json"),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return f"sha256:{hashlib.sha256(payload.encode()).hexdigest()}"


def validate_platform_matrix(
    receipts: tuple[CrossNodePlatformReceipt, CrossNodePlatformReceipt],
) -> CrossNodePlatformMatrix:
    """要求两个真实平台回执绑定同一提交、数据集、Prompt 和工具版本。"""
    by_platform = {item.host_platform: item for item in receipts}
    if set(by_platform) != {Platform.WINDOWS, Platform.MACOS}:
        raise ValueError("平台矩阵必须且只能包含 Windows 与 macOS 回执")
    windows = by_platform[Platform.WINDOWS]
    macos = by_platform[Platform.MACOS]
    violations = tuple(
        name
        for name, failed in {
            "receipt_failed": not windows.passed or not macos.passed,
            "source_revision_mismatch": windows.source_revision != macos.source_revision,
            "dataset_content_hash_mismatch": (
                windows.dataset_content_hash != macos.dataset_content_hash
            ),
            "prompt_content_hash_mismatch": (
                windows.prompt_content_hash != macos.prompt_content_hash
            ),
            "tool_versions_mismatch": windows.tool_versions != macos.tool_versions,
            "secret_store_access": bool(
                windows.secret_store_accesses or macos.secret_store_accesses
            ),
            "system_write": windows.system_writes_performed or macos.system_writes_performed,
            "external_network_transport": (
                windows.network_transport != "in-memory-asgi"
                or macos.network_transport != "in-memory-asgi"
            ),
            "remote_local_tool_execution": bool(
                windows.remote_local_tool_executions or macos.remote_local_tool_executions
            ),
        }.items()
        if failed
    )
    return CrossNodePlatformMatrix(
        source_revision=windows.source_revision,
        dataset_content_hash=windows.dataset_content_hash,
        prompt_content_hash=windows.prompt_content_hash,
        tool_versions=windows.tool_versions,
        platforms=(Platform.WINDOWS, Platform.MACOS),
        receipt_hashes={
            Platform.WINDOWS.value: _receipt_hash(windows),
            Platform.MACOS.value: _receipt_hash(macos),
        },
        generated_at=datetime.now(UTC),
        violations=violations,
        passed=not violations,
    )
