"""请求端连接只读诊断、候选计划和固定 Gateway 的产品编排。"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from datetime import datetime
from typing import Protocol

from pydantic import ValidationError

from tunnelminion.agent.diagnostics import CrossNodeAgentAnswer
from tunnelminion.agent.planning import CandidatePlanIntent
from tunnelminion.domain.errors import ErrorCode
from tunnelminion.domain.identifiers import NodeId, OperationId, RunId, ThreadId
from tunnelminion.gateway.client import RemoteGatewayError
from tunnelminion.gateway.configuration import (
    GatewayConfigurationService,
    GatewayOperationPeer,
    GatewayPeerView,
)
from tunnelminion.gateway.contracts import (
    GATEWAY_PROTOCOL,
    RemoteOperationResult,
    RequesterVerificationCallback,
)
from tunnelminion.model.contracts import CancellationToken, ProviderError
from tunnelminion.operation.contracts import OperationLevel, OperationPlan
from tunnelminion.operation.definitions import SAFE_HTTP_SHARING_OPERATION
from tunnelminion.operation.requester import (
    RequesterOperationInput,
    RequesterOperationRecord,
    RequesterOperationStore,
)
from tunnelminion.tools.contracts import ToolCallContext, ToolCancellationToken


class RequesterDiagnosticAgent(Protocol):
    """请求服务使用的现有跨节点诊断 Agent 子集。"""

    async def answer(
        self,
        question: str,
        context: ToolCallContext,
        target_host: str,
        *,
        port: int | None = None,
        plan_intent: CandidatePlanIntent | None = None,
        tool_cancellation: ToolCancellationToken | None = None,
        model_cancellation: CancellationToken | None = None,
    ) -> CrossNodeAgentAnswer: ...


class RequesterGatewayClient(Protocol):
    """请求服务使用的固定 Gateway 客户端子集。"""

    async def submit_operation(self, plan: OperationPlan) -> RemoteOperationResult: ...

    async def execute_operation(
        self,
        plan: OperationPlan,
        *,
        verification_callback: RequesterVerificationCallback | None = None,
    ) -> RemoteOperationResult: ...

    async def get_operation(self, operation_id: OperationId) -> RemoteOperationResult: ...


class RequesterOperationFailure(RuntimeError):
    """只向产品暴露稳定错误码，不携带远端正文或秘密。"""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


DiagnosticAgentFactory = Callable[[GatewayOperationPeer], RequesterDiagnosticAgent]
GatewayClientFactory = Callable[[GatewayOperationPeer], RequesterGatewayClient]
_UNKNOWN_WRITE_ERRORS = frozenset(
    {
        ErrorCode.CANCELLED,
        ErrorCode.INTERNAL,
        ErrorCode.NODE_UNREACHABLE,
        ErrorCode.REMOTE_TIMEOUT,
        ErrorCode.RESULT_TOO_LARGE,
        ErrorCode.TIMEOUT,
    }
)


class RequesterOperationService:
    """连接现有诊断、计划和固定 Gateway 操作协议的请求端主路径。"""

    def __init__(
        self,
        *,
        node_id: NodeId,
        store: RequesterOperationStore,
        configuration: GatewayConfigurationService,
        diagnostic_agent_factory: DiagnosticAgentFactory,
        gateway_client_factory: GatewayClientFactory,
        clock: Callable[[], datetime],
    ) -> None:
        self._node_id = node_id
        self._store = store
        self._configuration = configuration
        self._diagnostic_agent_factory = diagnostic_agent_factory
        self._gateway_client_factory = gateway_client_factory
        self._clock = clock

    def eligible_peers(self) -> tuple[GatewayPeerView, ...]:
        """返回能完成固定临时 HTTP 共享的已配置对端。"""
        return self._configuration.eligible_operation_peers(SAFE_HTTP_SHARING_OPERATION)

    def list_operations(self) -> tuple[RequesterOperationRecord, ...]:
        return self._store.list_all()

    def get_operation(self, operation_id: OperationId) -> RequesterOperationRecord:
        record = self._store.get(operation_id)
        if record is None:
            raise KeyError("requester_operation_not_found")
        return record

    async def create_operation(
        self,
        value: RequesterOperationInput,
    ) -> RequesterOperationRecord:
        """生成最新候选计划，先保存，再向固定目标节点提交一次。"""
        if not value.confirmed:
            raise RequesterOperationFailure("explicit_intent_required")
        try:
            peer = self._configuration.resolve_operation_peer(
                value.target_node_id,
                SAFE_HTTP_SHARING_OPERATION,
            )
        except (KeyError, RuntimeError) as exc:
            raise RequesterOperationFailure("gateway_operation_peer_unavailable") from exc
        try:
            agent = self._diagnostic_agent_factory(peer)
        except ProviderError as exc:
            raise RequesterOperationFailure(exc.code.value) from exc

        context = ToolCallContext(
            thread_id=ThreadId.new(),
            run_id=RunId.new(),
            caller_node_id=self._node_id,
            execution_node_id=peer.node_id,
        )
        answer = await agent.answer(
            "请为目标节点上的本机 HTTP 服务生成临时私网访问候选计划。",
            context,
            peer.target_host,
            port=value.service_port,
            plan_intent=CandidatePlanIntent(
                confirmed=True,
                service_port=value.service_port,
                bind_host=peer.target_host,
                bind_port=value.bind_port,
                duration_seconds=value.duration_seconds,
            ),
        )
        plan = answer.candidate_plan
        if plan is None:
            raise RequesterOperationFailure(
                answer.plan_error_code
                or answer.remote_error_code
                or answer.model_error_code
                or "candidate_plan_unavailable"
            )
        self._validate_plan(plan, value, context, peer)
        record = RequesterOperationRecord.planned(plan)
        self._store.put(record)
        try:
            result = await self._gateway_client_factory(peer).submit_operation(plan)
        except asyncio.CancelledError:
            self._store_error(
                record,
                code="submission_result_unknown",
                submission_result_unknown=True,
            )
            raise
        except RemoteGatewayError as exc:
            return self._store_error(
                record,
                code=exc.code.value,
                submission_result_unknown=exc.code in _UNKNOWN_WRITE_ERRORS,
            )
        return self._store_remote_result(
            record,
            result,
            unknown_field="submission_result_unknown",
        )

    async def refresh_operation(
        self,
        operation_id: OperationId,
    ) -> RequesterOperationRecord:
        """只读取原操作；成功查询后清除先前写结果未知标记。"""
        record = self.get_operation(operation_id)
        try:
            peer = self._configuration.resolve_operation_peer(
                record.plan.target_node_id,
                SAFE_HTTP_SHARING_OPERATION,
            )
            result = await self._gateway_client_factory(peer).get_operation(operation_id)
        except RemoteGatewayError as exc:
            return self._store_error(record, code=exc.code.value)
        except (KeyError, RuntimeError):
            return self._store_error(record, code="gateway_operation_peer_unavailable")
        return self._store_remote_result(record, result)

    @staticmethod
    def _validate_plan(
        plan: OperationPlan,
        value: RequesterOperationInput,
        context: ToolCallContext,
        peer: GatewayOperationPeer,
    ) -> None:
        expected = (
            context.caller_node_id,
            context.execution_node_id,
            context.thread_id,
            context.run_id,
            SAFE_HTTP_SHARING_OPERATION,
            OperationLevel.L2,
            value.service_port,
            peer.target_host,
            value.bind_port,
            value.duration_seconds,
        )
        actual = (
            plan.request_node_id,
            plan.target_node_id,
            plan.thread_id,
            plan.run_id,
            plan.tool_name,
            plan.level,
            plan.service.port,
            plan.access_scope.bind_host,
            plan.access_scope.bind_port,
            plan.access_scope.duration_seconds,
        )
        if actual != expected:
            raise RequesterOperationFailure("candidate_plan_mismatch")

    def _store_remote_result(
        self,
        record: RequesterOperationRecord,
        result: RemoteOperationResult,
        *,
        unknown_field: str | None = None,
    ) -> RequesterOperationRecord:
        now = self._clock()
        updates: dict[str, object] = {
            "remote_summary": result.summary,
            "submission_result_unknown": False,
            "execution_result_unknown": False,
            "last_checked_at": now,
            "error_code": None,
            "updated_at": now,
        }
        try:
            if result.execution_node_id != record.plan.target_node_id:
                raise ValueError("远端执行节点不匹配")
            if not GATEWAY_PROTOCOL.is_compatible_with(result.protocol):
                raise ValueError("远端操作协议不兼容")
            updated = self._updated(record, **updates)
        except (ValidationError, ValueError):
            return self._store_error(
                record,
                code="remote_integrity_error",
                submission_result_unknown=(
                    True if unknown_field == "submission_result_unknown" else None
                ),
                execution_result_unknown=(
                    True if unknown_field == "execution_result_unknown" else None
                ),
            )
        self._store.put(updated)
        return updated

    def _store_error(
        self,
        record: RequesterOperationRecord,
        *,
        code: str,
        submission_result_unknown: bool | None = None,
        execution_result_unknown: bool | None = None,
    ) -> RequesterOperationRecord:
        updates: dict[str, object] = {"error_code": code, "updated_at": self._clock()}
        if submission_result_unknown is not None:
            updates["submission_result_unknown"] = submission_result_unknown
        if execution_result_unknown is not None:
            updates["execution_result_unknown"] = execution_result_unknown
        updated = self._updated(record, **updates)
        self._store.put(updated)
        return updated

    @staticmethod
    def _updated(record: RequesterOperationRecord, **updates: object) -> RequesterOperationRecord:
        values = record.model_dump()
        values.update(updates)
        return RequesterOperationRecord.model_validate(values)
