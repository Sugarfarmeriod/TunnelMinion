"""从最新跨节点诊断证据生成无权限的结构化候选操作计划。"""

from __future__ import annotations

import hashlib
import ipaddress
import json
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from pydantic import BaseModel, ConfigDict, Field, JsonValue, ValidationError

from tunnelminion.agent.context_contracts import (
    ContextContentKind,
    ContextRequest,
    ContextTaskType,
    ContextTrust,
)
from tunnelminion.agent.context_runtime import ContextModelRuntime, make_context_reference
from tunnelminion.agent.prompts import TEMPORARY_SERVICE_PLAN_PROMPT
from tunnelminion.agent.services import (
    CrossNodeReachability,
    CrossNodeServiceDiagnostic,
    ServiceAccessibility,
)
from tunnelminion.model.contracts import (
    CancellationToken,
    ModelMessage,
    ModelProvider,
    ModelUsage,
    ProviderError,
)
from tunnelminion.operation.contracts import (
    AccessScope,
    OperationLevel,
    OperationPlan,
    PlanFailureAttribution,
    PlanGenerationTrace,
    ServiceEvidence,
    compute_service_fingerprint,
)
from tunnelminion.operation.workflow import build_operation_plan

if TYPE_CHECKING:
    from tunnelminion.agent.diagnostics import CrossNodeDiagnosticReport
    from tunnelminion.tools.contracts import ToolCallContext

PLAN_PROMPT_ID = TEMPORARY_SERVICE_PLAN_PROMPT.prompt_id
PLAN_PROMPT_VERSION = TEMPORARY_SERVICE_PLAN_PROMPT.version
PLAN_CONTEXT_SCHEMA_VERSION = "candidate-plan-context/v1"
PLAN_TOOL_SCHEMA_VERSION = "share-local-http-service/v1"
PLAN_TOOL_NAME = "share_local_http_service"
_PROVIDER_RESPONSE_SCHEMA: dict[str, JsonValue] = {
    "type": "object",
    "properties": {
        "expected_change": {"type": "string"},
        "risk_summary": {"type": "string"},
        "verification_method": {"type": "string"},
        "rollback_method": {"type": "string"},
    },
    "required": [
        "expected_change",
        "risk_summary",
        "verification_method",
        "rollback_method",
    ],
    "additionalProperties": False,
}


class CandidatePlanIntent(BaseModel):
    """用户在界面中逐项确认的候选计划输入。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    confirmed: bool
    service_port: int = Field(ge=1, le=65535)
    bind_host: str = Field(min_length=1, max_length=255)
    bind_port: int = Field(ge=1024, le=65535)
    duration_seconds: int = Field(ge=1, le=86_400)


class PlanNarrative(BaseModel):
    """模型只能填写的非授权说明字段。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    expected_change: str = Field(min_length=1, max_length=2_000)
    risk_summary: str = Field(min_length=1, max_length=2_000)
    verification_method: str = Field(min_length=1, max_length=2_000)
    rollback_method: str = Field(min_length=1, max_length=2_000)


class CandidatePlanFailure(BaseModel):
    """计划生成失败的脱敏归因。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    code: str = Field(min_length=1, max_length=128)
    attribution: PlanFailureAttribution
    message: str = Field(min_length=1, max_length=512)


class CandidatePlanResult(BaseModel):
    """候选计划或可诊断失败；失败时绝不创建 OperationPlan。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    plan: OperationPlan | None = None
    failure: CandidatePlanFailure | None = None


class CandidateOperationPlanner:
    """让模型只写说明，确定性代码负责证据、权限与计划结构。"""

    def __init__(
        self,
        provider: ModelProvider,
        *,
        provider_name: str = "configured-provider",
        model_name: str = "configured-model",
    ) -> None:
        self._provider = provider
        self._provider_name = provider_name
        self._model_name = model_name

    async def generate(
        self,
        *,
        question: str,
        report: CrossNodeDiagnosticReport,
        context: ToolCallContext,
        intent: CandidatePlanIntent,
        cancellation: CancellationToken | None = None,
    ) -> CandidatePlanResult:
        """基于明确意图与最新诊断快照生成一份 L2 候选计划。"""
        governance_failure = self._validate_intent(intent)
        if governance_failure is not None:
            return CandidatePlanResult(failure=governance_failure)
        diagnostic = self._select_service(report, intent.service_port)
        if isinstance(diagnostic, CandidatePlanFailure):
            return CandidatePlanResult(failure=diagnostic)

        evidence = self._operation_evidence(diagnostic)
        tool_run_ids = tuple(
            {str(item.tool_run_id): item.tool_run_id for item in diagnostic.evidence}.values()
        )
        snapshot_version = self._snapshot_version(report, diagnostic)
        user_content = self._user_context(question, report, diagnostic, intent)
        request = ContextRequest(
            task_type=ContextTaskType.OPERATION_PLAN,
            current_intent=question,
            thread_id=context.thread_id,
            run_id=context.run_id,
            prompt_id=PLAN_PROMPT_ID,
            prompt_version=PLAN_PROMPT_VERSION,
            messages=(
                ModelMessage(role="system", content=TEMPORARY_SERVICE_PLAN_PROMPT.template),
                ModelMessage(role="user", content=user_content),
            ),
            # llama.cpp grammar 不接受 Pydantic 的长度和展示注解；完整约束仍在响应后校验。
            response_schema=_PROVIDER_RESPONSE_SCHEMA,
            evidence=(
                make_context_reference(
                    ContextContentKind.EVIDENCE,
                    f"diagnostic:{snapshot_version}",
                    user_content,
                    ContextTrust.VERIFIED_EVIDENCE,
                ),
            ),
        )
        if not self._provider.capabilities.structured_output:
            return CandidatePlanResult(
                failure=CandidatePlanFailure(
                    code="structured_output_unavailable",
                    attribution=PlanFailureAttribution.PROMPT_OR_MODEL,
                    message="当前模型 Provider 不支持候选计划结构化输出",
                )
            )
        try:
            invocation = await ContextModelRuntime(
                self._provider,
                provider_name=self._provider_name,
                model_name=self._model_name,
                tool_schema_version=PLAN_TOOL_SCHEMA_VERSION,
            ).invoke(request, cancellation)
            response = invocation.response
            if response.tool_calls or response.structured_output is None:
                raise ValueError("模型没有返回唯一的结构化候选计划说明")
            narrative = PlanNarrative.model_validate(response.structured_output)
        except ProviderError as exc:
            return CandidatePlanResult(
                failure=CandidatePlanFailure(
                    code=exc.code.value,
                    attribution=PlanFailureAttribution.PROMPT_OR_MODEL,
                    message="模型 Provider 无法生成新的候选计划",
                )
            )
        except (ValidationError, ValueError):
            return CandidatePlanResult(
                failure=CandidatePlanFailure(
                    code="invalid_plan_response",
                    attribution=PlanFailureAttribution.PROMPT_OR_MODEL,
                    message="模型返回的候选计划说明未通过结构校验",
                )
            )

        trace = self._trace(
            snapshot_version=snapshot_version,
            user_content=user_content,
            evidence_count=len(tool_run_ids),
            result_count=len(report.diagnostics),
            usage=response.usage,
        )
        plan = build_operation_plan(
            request_node_id=context.caller_node_id,
            target_node_id=context.execution_node_id,
            thread_id=context.thread_id,
            run_id=context.run_id,
            tool_run_ids=tool_run_ids,
            tool_name=PLAN_TOOL_NAME,
            level=OperationLevel.L2,
            service=evidence,
            expected_change=narrative.expected_change,
            access_scope=AccessScope(
                allowed_peer_id=context.caller_node_id,
                bind_host=intent.bind_host,
                bind_port=intent.bind_port,
                duration_seconds=intent.duration_seconds,
            ),
            risk_summary=narrative.risk_summary,
            verification_method=narrative.verification_method,
            rollback_method=narrative.rollback_method,
            created_at=datetime.now(UTC),
            generation_trace=trace,
        )
        return CandidatePlanResult(plan=plan)

    @staticmethod
    def _validate_intent(intent: CandidatePlanIntent) -> CandidatePlanFailure | None:
        if not intent.confirmed:
            return CandidatePlanFailure(
                code="explicit_intent_required",
                attribution=PlanFailureAttribution.GOVERNANCE,
                message="用户尚未明确确认生成临时共享候选计划",
            )
        try:
            address = ipaddress.ip_address(intent.bind_host)
        except ValueError:
            address = None
        if (
            address is None
            or not address.is_private
            or address.is_loopback
            or address.is_unspecified
        ):
            return CandidatePlanFailure(
                code="private_bind_address_required",
                attribution=PlanFailureAttribution.GOVERNANCE,
                message="候选入口必须使用显式私网地址",
            )
        return None

    @staticmethod
    def _select_service(
        report: CrossNodeDiagnosticReport,
        port: int,
    ) -> CrossNodeServiceDiagnostic | CandidatePlanFailure:
        matches = tuple(item for item in report.diagnostics if item.service.port == port)
        if len(matches) != 1:
            return CandidatePlanFailure(
                code="service_evidence_ambiguous",
                attribution=PlanFailureAttribution.CONTEXT,
                message="最新诊断中没有唯一匹配的目标服务证据",
            )
        selected = matches[0]
        if (
            selected.reachability is not CrossNodeReachability.LOCAL_ONLY
            or selected.service.accessibility is not ServiceAccessibility.LOCAL_ONLY
            or selected.service.protocol != "tcp"
        ):
            return CandidatePlanFailure(
                code="service_not_local_http_candidate",
                attribution=PlanFailureAttribution.GOVERNANCE,
                message="目标服务不是已确认的仅本机 HTTP 候选",
            )
        if not selected.evidence:
            return CandidatePlanFailure(
                code="verified_evidence_required",
                attribution=PlanFailureAttribution.HARNESS_OR_TOOL,
                message="目标服务缺少可引用的最新工具证据",
            )
        return selected

    @staticmethod
    def _operation_evidence(diagnostic: CrossNodeServiceDiagnostic) -> ServiceEvidence:
        service = diagnostic.service
        owner = service.container_name or service.process_name or "unknown-service"
        service_id = f"http:{service.address}:{service.port}:{owner}"[:128]
        return ServiceEvidence(
            service_id=service_id,
            scheme="http",
            host=service.address,
            port=service.port,
            process_or_container=owner[:256],
            fingerprint=compute_service_fingerprint(
                node_id=service.node_id,
                protocol=service.protocol,
                address=service.address,
                port=service.port,
                process_pid=service.process_pid,
                process_name=service.process_name,
            ),
            observed_at=max(item.observed_at for item in diagnostic.evidence),
        )

    @staticmethod
    def _snapshot_version(
        report: CrossNodeDiagnosticReport,
        diagnostic: CrossNodeServiceDiagnostic,
    ) -> str:
        payload = {
            "local_node_id": str(report.local_node_id),
            "remote_node_id": str(report.remote_node_id),
            "target_host": report.target_host,
            "service": diagnostic.service.model_dump(mode="json"),
            "reachability": diagnostic.reachability.value,
            "evidence": [item.model_dump(mode="json") for item in diagnostic.evidence],
        }
        canonical = json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        return f"sha256:{hashlib.sha256(canonical.encode()).hexdigest()}"

    @staticmethod
    def _user_context(
        question: str,
        report: CrossNodeDiagnosticReport,
        diagnostic: CrossNodeServiceDiagnostic,
        intent: CandidatePlanIntent,
    ) -> str:
        payload = {
            "trust": "untrusted-tool-data",
            "user_intent": {
                "question": question,
                "request_node_id": str(report.local_node_id),
                "target_node_id": str(report.remote_node_id),
                "service_port": intent.service_port,
                "bind_host": intent.bind_host,
                "bind_port": intent.bind_port,
                "duration_seconds": intent.duration_seconds,
            },
            "latest_verified_diagnostic": diagnostic.model_dump(mode="json"),
            "fixed_policy": {
                "tool_name": PLAN_TOOL_NAME,
                "operation_level": "L2",
                "requires_target_authorization": True,
                "model_may_execute": False,
            },
        }
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":"))

    def _trace(
        self,
        *,
        snapshot_version: str,
        user_content: str,
        evidence_count: int,
        result_count: int,
        usage: ModelUsage,
    ) -> PlanGenerationTrace:
        return PlanGenerationTrace(
            prompt_id=PLAN_PROMPT_ID,
            prompt_version=PLAN_PROMPT_VERSION,
            provider_name=self._provider_name,
            model_name=self._model_name,
            tool_schema_version=PLAN_TOOL_SCHEMA_VERSION,
            evidence_snapshot_version=snapshot_version,
            context_schema_version=PLAN_CONTEXT_SCHEMA_VERSION,
            message_count=2,
            tool_count=0,
            result_count=result_count,
            evidence_count=evidence_count,
            input_chars=len(TEMPORARY_SERVICE_PLAN_PROMPT.template) + len(user_content),
            truncated_items=0,
            realtime_evidence_precedence=True,
            input_tokens=usage.input_tokens,
            output_tokens=usage.output_tokens,
            total_tokens=usage.total_tokens,
        )
