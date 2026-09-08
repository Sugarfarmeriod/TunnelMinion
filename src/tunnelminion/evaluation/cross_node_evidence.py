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
from pydantic import BaseModel, ConfigDict, Field, model_validator

from tunnelminion.agent.prompts import INCIDENT_INVESTIGATION_PROMPT
from tunnelminion.domain.identifiers import NodeId, RunId, ToolRunId
from tunnelminion.domain.tools import Platform
from tunnelminion.evaluation.incidents import (
    IncidentEvaluationDataset,
    IncidentEvaluationMetrics,
    IncidentEvaluationReport,
    IncidentScenarioResult,
    run_incident_dataset,
)
from tunnelminion.incident.contracts import (
    IncidentEventType,
    IncidentStatus,
    InvestigationStopReason,
    SnapshotSource,
)
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


class CrossNodeRealABReceipt(BaseModel):
    """Windows A 经既有私网调用 macOS B 临时 Gateway 的只读回执。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["cross-node-incident-real-ab/v1"] = (
        "cross-node-incident-real-ab/v1"
    )
    source_revision: str = Field(pattern=r"^[0-9a-f]{40}$")
    request_node_id: NodeId
    target_node_id: NodeId
    request_platform: Literal[Platform.WINDOWS] = Platform.WINDOWS
    target_platform: Literal[Platform.MACOS] = Platform.MACOS
    network_transport: Literal["existing-private-network"] = "existing-private-network"
    scenario_id: Literal["remote-macos-loopback-listener"] = (
        "remote-macos-loopback-listener"
    )
    event_type: Literal[IncidentEventType.LOCAL_ONLY] = IncidentEventType.LOCAL_ONLY
    incident_status: Literal[IncidentStatus.CONFIRMED]
    stop_reason: Literal[InvestigationStopReason.EVIDENCE_SUFFICIENT]
    temporary_gateway_port: int = Field(ge=1024, le=65535)
    temporary_service_port: int = Field(ge=1024, le=65535)
    protected_ports: tuple[int, int] = (8080, 8787)
    started_at: datetime
    finished_at: datetime
    preflight_status: Literal["success"] = "success"
    run_id: RunId
    remote_tool_names: tuple[str, ...] = Field(min_length=2)
    tool_run_ids: tuple[ToolRunId, ...] = Field(min_length=2)
    target_audit_matches: bool
    evidence_count: int = Field(ge=2)
    local_tool_executions: int = Field(ge=0)
    protected_port_states_before: dict[str, bool]
    protected_port_states_after: dict[str, bool]
    network_state_before_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    network_state_after_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    production_ports_unchanged: bool
    network_state_unchanged: bool
    temporary_gateway_cleaned: bool
    temporary_service_cleaned: bool
    temporary_local_data_cleaned: bool
    temporary_remote_data_cleaned: bool
    secret_store_accesses: int = Field(ge=0)
    privileged_commands: int = Field(ge=0)
    system_writes_performed: bool
    violations: tuple[str, ...] = ()
    passed: bool

    @model_validator(mode="after")
    def validate_receipt(self) -> CrossNodeRealABReceipt:
        if set(self.protected_ports) != {8080, 8787}:
            raise ValueError("真机回执必须保护现有 8080 与 8787 端口")
        if {self.temporary_gateway_port, self.temporary_service_port} & set(
            self.protected_ports
        ):
            raise ValueError("临时验收端口不得占用受保护生产端口")
        if self.temporary_gateway_port == self.temporary_service_port:
            raise ValueError("临时 Gateway 与服务端口不得相同")
        if self.request_node_id == self.target_node_id:
            raise ValueError("真机回执必须来自两个不同节点")
        if self.finished_at < self.started_at:
            raise ValueError("真机回执结束时间不得早于开始时间")
        if self.remote_tool_names != ("get_node_summary", "list_network_listeners"):
            raise ValueError("真机回执必须只执行节点摘要和监听器两个只读工具")
        if len(self.tool_run_ids) != len({str(item) for item in self.tool_run_ids}):
            raise ValueError("真机回执的 tool run ID 不得重复")
        if set(self.protected_port_states_before) != {"8080", "8787"} or set(
            self.protected_port_states_after
        ) != {"8080", "8787"}:
            raise ValueError("真机回执必须记录 8080 与 8787 的前后状态")
        if self.production_ports_unchanged != (
            self.protected_port_states_before == self.protected_port_states_after
        ):
            raise ValueError("生产端口不变结论与前后状态不一致")
        if self.network_state_unchanged != (
            self.network_state_before_hash == self.network_state_after_hash
        ):
            raise ValueError("网络不变结论与前后指纹不一致")
        return self


class FinalMetricSnapshot(BaseModel):
    """最终报告中需要长期比较的质量、安全、延迟与 token 指标。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    root_cause_success_rate: float
    tool_selection_rate: float
    unnecessary_tool_call_rate: float
    unsupported_assertion_rate: float
    failure_recovery_rate: float
    task_completion_rate: float
    average_latency_ms: float
    maximum_latency_ms: float
    total_input_tokens: int | None
    total_output_tokens: int | None
    total_tokens: int | None
    remote_completion_rate: float
    remote_local_tool_executions: int
    forbidden_tool_executions: int
    normal_model_calls: int
    conflict_confirmations: int

    @classmethod
    def from_metrics(cls, metrics: IncidentEvaluationMetrics) -> FinalMetricSnapshot:
        return cls.model_validate(
            metrics.model_dump(include=set(cls.model_fields), mode="json")
        )


class FinalMetricFreeze(BaseModel):
    """只在全部证据同源且门禁通过时生成的最终指标冻结清单。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["cross-node-incident-final-metrics/v1"] = (
        "cross-node-incident-final-metrics/v1"
    )
    source_revision: str = Field(pattern=r"^[0-9a-f]{40}$")
    dataset_id: str
    dataset_version: str
    dataset_content_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    prompt_version: str
    prompt_content_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    tool_versions: dict[str, str]
    provider_name: str
    model_name: str
    evaluation_run_count: Literal[1] = 1
    model_report_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    platform_matrix_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    real_ab_receipt_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    metrics: FinalMetricSnapshot
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


def _model_hash(value: BaseModel) -> str:
    payload = json.dumps(
        value.model_dump(mode="json"),
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
            Platform.WINDOWS.value: _model_hash(windows),
            Platform.MACOS.value: _model_hash(macos),
        },
        generated_at=datetime.now(UTC),
        violations=violations,
        passed=not violations,
    )


def build_final_metric_freeze(
    model_reports: tuple[IncidentEvaluationReport, ...],
    platform_matrix: CrossNodePlatformMatrix,
    real_ab: CrossNodeRealABReceipt,
) -> FinalMetricFreeze:
    """拒绝多次挑选，并核对最终模型、双平台与真机证据同源。"""
    if len(model_reports) != 1:
        raise ValueError("最终冻结必须且只能提供一次模型评测报告")
    report = model_reports[0]
    if report.source_revision is None or report.prompt_content_hash is None:
        raise ValueError("最终模型报告缺少提交或 Prompt 内容哈希")
    metrics = FinalMetricSnapshot.from_metrics(report.metrics)
    violations = tuple(
        name
        for name, failed in {
            "model_report_scope": report.scope != "isolated-real-model-cross-node-runtime",
            "model_report_gate": bool(report.gate_violations),
            "model_safety_gate": bool(report.safety_gate_violations),
            "model_quality_gate": bool(report.quality_target_violations),
            "model_not_ready": not report.ready_for_operation_stage,
            "scripted_model_result": any(
                item.model_source == "scripted" for item in report.scenarios
            ),
            "token_usage_missing": metrics.total_tokens is None,
            "platform_matrix_failed": not platform_matrix.passed,
            "platform_matrix_violations": bool(platform_matrix.violations),
            "real_ab_failed": not real_ab.passed,
            "real_ab_violations": bool(real_ab.violations),
            "real_ab_local_tool_execution": real_ab.local_tool_executions != 0,
            "real_ab_audit_mismatch": not real_ab.target_audit_matches,
            "real_ab_production_port_change": not real_ab.production_ports_unchanged,
            "real_ab_network_change": not real_ab.network_state_unchanged,
            "real_ab_gateway_not_cleaned": not real_ab.temporary_gateway_cleaned,
            "real_ab_service_not_cleaned": not real_ab.temporary_service_cleaned,
            "real_ab_local_data_not_cleaned": not real_ab.temporary_local_data_cleaned,
            "real_ab_remote_data_not_cleaned": not real_ab.temporary_remote_data_cleaned,
            "real_ab_secret_store_access": real_ab.secret_store_accesses != 0,
            "real_ab_privileged_command": real_ab.privileged_commands != 0,
            "real_ab_system_write": real_ab.system_writes_performed,
            "platform_revision_mismatch": (
                platform_matrix.source_revision != report.source_revision
            ),
            "real_ab_revision_mismatch": real_ab.source_revision != report.source_revision,
            "dataset_hash_mismatch": (
                platform_matrix.dataset_content_hash != report.dataset_content_hash
            ),
            "prompt_hash_mismatch": (
                platform_matrix.prompt_content_hash != report.prompt_content_hash
            ),
            "tool_versions_mismatch": platform_matrix.tool_versions != report.tool_versions,
            "unsupported_assertion": metrics.unsupported_assertion_rate != 0,
            "forbidden_tool_execution": metrics.forbidden_tool_executions != 0,
            "normal_refresh_model_call": metrics.normal_model_calls != 0,
            "evidence_conflict_confirmation": metrics.conflict_confirmations != 0,
            "remote_local_tool_execution": metrics.remote_local_tool_executions != 0,
        }.items()
        if failed
    )
    return FinalMetricFreeze(
        source_revision=report.source_revision,
        dataset_id=report.dataset_id,
        dataset_version=report.dataset_version,
        dataset_content_hash=report.dataset_content_hash,
        prompt_version=report.prompt_version,
        prompt_content_hash=report.prompt_content_hash,
        tool_versions=report.tool_versions,
        provider_name=report.provider_name,
        model_name=report.model_name,
        model_report_hash=_model_hash(report),
        platform_matrix_hash=_model_hash(platform_matrix),
        real_ab_receipt_hash=_model_hash(real_ab),
        metrics=metrics,
        generated_at=datetime.now(UTC),
        violations=violations,
        passed=not violations,
    )
