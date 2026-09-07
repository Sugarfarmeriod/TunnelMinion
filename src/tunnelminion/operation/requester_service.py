"""请求端连接只读诊断、候选计划和固定 Gateway 的产品编排。"""

from __future__ import annotations

import asyncio
import hashlib
import secrets
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Protocol

import httpx
from fastapi import FastAPI
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
from tunnelminion.gateway.operations import (
    GatewayRequesterVerifier,
    RequesterVerificationConfig,
    create_requester_verification_router,
)
from tunnelminion.model.contracts import CancellationToken, ProviderError
from tunnelminion.operation.contracts import (
    LeaseRecord,
    OperationLevel,
    OperationPlan,
    OperationStatus,
    VerificationRecord,
    VerificationResult,
)
from tunnelminion.operation.definitions import SAFE_HTTP_SHARING_OPERATION
from tunnelminion.operation.http_sharing import (
    SHARE_TOKEN_HEADER,
    HTTPProxyLimits,
    ProxyRuntime,
)
from tunnelminion.operation.requester import (
    RequesterExecutionInput,
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
_CALLBACK_LIFETIME = timedelta(seconds=45)


@dataclass(frozen=True)
class RequesterAccessResponse:
    """本机同源路由可安全转发的有限上游响应。"""

    status_code: int
    content: bytes = field(repr=False)
    content_type: str | None = None


@dataclass(frozen=True)
class _AccessSession:
    plan: OperationPlan
    lease: LeaseRecord
    token: str = field(repr=False)


class _CapturingRequesterVerifier:
    """只在同一计划首次独立验证通过后保存内存凭据。"""

    def __init__(
        self,
        plan: OperationPlan,
        delegate: GatewayRequesterVerifier,
        save_session: Callable[[_AccessSession], None],
        clock: Callable[[], datetime],
    ) -> None:
        self._plan = plan
        self._delegate = delegate
        self._save_session = save_session
        self._clock = clock
        self._used = False
        self._lock = threading.Lock()

    async def verify(
        self,
        plan: OperationPlan,
        lease: LeaseRecord,
        access_token: str,
    ) -> VerificationRecord:
        with self._lock:
            if self._used:
                return self._failure("验证回调已使用")
            self._used = True
        if (
            plan != self._plan
            or lease.operation_id != plan.operation_id
            or lease.expires_at <= self._clock()
            or lease.expires_at - lease.starts_at
            > timedelta(seconds=plan.access_scope.duration_seconds)
        ):
            return self._failure("验证回调计划或租约不匹配")
        result = await self._delegate.verify(plan, lease, access_token)
        if result.result is VerificationResult.PASSED:
            self._save_session(_AccessSession(plan, lease, access_token))
        return result

    def _failure(self, message: str) -> VerificationRecord:
        return VerificationRecord(
            operation_id=self._plan.operation_id,
            verifier_node_id=self._plan.request_node_id,
            result=VerificationResult.FAILED,
            evidence_summary=message,
            verified_at=self._clock(),
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
        callback_runtime: ProxyRuntime,
        clock: Callable[[], datetime],
        verification_transport: httpx.AsyncBaseTransport | None = None,
        access_transport: httpx.AsyncBaseTransport | None = None,
        proxy_limits: HTTPProxyLimits | None = None,
    ) -> None:
        self._node_id = node_id
        self._store = store
        self._configuration = configuration
        self._diagnostic_agent_factory = diagnostic_agent_factory
        self._gateway_client_factory = gateway_client_factory
        self._callback_runtime = callback_runtime
        self._clock = clock
        self._verification_transport = verification_transport
        self._access_transport = access_transport
        self._proxy_limits = proxy_limits or HTTPProxyLimits()
        self._sessions: dict[str, _AccessSession] = {}
        self._session_lock = threading.Lock()
        self._access_semaphore = asyncio.Semaphore(self._proxy_limits.max_concurrent_requests)

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

    async def execute_operation(
        self,
        operation_id: OperationId,
        value: RequesterExecutionInput,
    ) -> RequesterOperationRecord:
        """重新查询授权后，用短时回调执行同一计划一次。"""
        if not value.confirmed:
            raise RequesterOperationFailure("explicit_execution_required")
        before_refresh = self.get_operation(operation_id)
        was_unknown = before_refresh.execution_result_unknown
        record = await self.refresh_operation(operation_id)
        if was_unknown or record.error_code is not None:
            return record
        if (
            record.remote_summary is None
            or record.remote_summary.status is not OperationStatus.AUTHORIZED
        ):
            return self._store_error(record, code="operation_not_authorized")
        try:
            peer = self._configuration.resolve_operation_peer(
                record.plan.target_node_id,
                SAFE_HTTP_SHARING_OPERATION,
            )
        except (KeyError, RuntimeError):
            return self._store_error(record, code="gateway_operation_peer_unavailable")

        callback_token = secrets.token_urlsafe(32)
        verifier = _CapturingRequesterVerifier(
            record.plan,
            GatewayRequesterVerifier(
                RequesterVerificationConfig(
                    allowed_target_addresses=frozenset({record.plan.access_scope.bind_host})
                ),
                transport=self._verification_transport,
            ),
            self._save_session,
            self._clock,
        )
        callback_app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
        callback_app.include_router(
            create_requester_verification_router(
                local_node_id=self._node_id,
                target_node_id=peer.node_id,
                callback_token=callback_token,
                verifier=verifier,
                expected_plan=record.plan,
            )
        )
        owner_fingerprint = f"sha256:{hashlib.sha256(callback_token.encode()).hexdigest()}"
        try:
            self._callback_runtime.start(
                callback_app,
                host=peer.requester_host,
                port=peer.requester_callback_port,
                owner_fingerprint=owner_fingerprint,
                expires_at=self._clock() + _CALLBACK_LIFETIME,
                graceful_shutdown_seconds=1,
            )
        except (OSError, RuntimeError):
            return self._store_error(record, code="callback_bind_failed")

        try:
            try:
                result = await self._gateway_client_factory(peer).execute_operation(
                    record.plan,
                    verification_callback=RequesterVerificationCallback(
                        endpoint=f"http://{peer.requester_host}:{peer.requester_callback_port}",
                        token=callback_token,
                    ),
                )
            except asyncio.CancelledError:
                self._drop_session(operation_id)
                self._store_error(
                    record,
                    code="execution_result_unknown",
                    execution_result_unknown=True,
                )
                raise
            except RemoteGatewayError as exc:
                self._drop_session(operation_id)
                return self._store_error(
                    record,
                    code=exc.code.value,
                    execution_result_unknown=exc.code in _UNKNOWN_WRITE_ERRORS,
                )
        finally:
            self._callback_runtime.stop(
                host=peer.requester_host,
                port=peer.requester_callback_port,
                owner_fingerprint=owner_fingerprint,
            )
        updated = self._store_remote_result(
            record,
            result,
            unknown_field="execution_result_unknown",
        )
        if (
            updated.remote_summary is None
            or updated.remote_summary.status is not OperationStatus.SUCCEEDED
        ):
            self._drop_session(operation_id)
        return updated

    def access_expires_at(self, operation_id: OperationId) -> datetime | None:
        """返回不含凭据的本机访问状态，并顺手清除失效会话。"""
        record = self.get_operation(operation_id)
        with self._session_lock:
            session = self._sessions.get(str(operation_id))
            if (
                session is None
                or session.plan != record.plan
                or session.lease.expires_at <= self._clock()
                or record.remote_summary is None
                or record.remote_summary.status is not OperationStatus.SUCCEEDED
            ):
                self._sessions.pop(str(operation_id), None)
                return None
            return session.lease.expires_at

    async def access_operation(
        self,
        operation_id: OperationId,
        *,
        method: str,
        path: str,
        query: str = "",
    ) -> RequesterAccessResponse:
        """以固定目标和内存 token 转发有界 GET/HEAD。"""
        verb = method.upper()
        if verb not in {"GET", "HEAD"}:
            raise RequesterOperationFailure("access_method_not_allowed")
        if self.access_expires_at(operation_id) is None:
            raise RequesterOperationFailure("access_session_unavailable")
        with self._session_lock:
            session = self._sessions[str(operation_id)]
        url = httpx.URL(
            f"http://{session.plan.access_scope.bind_host}:{session.plan.access_scope.bind_port}"
        ).copy_with(
            path=f"/{path.lstrip('/')}",
            query=str(httpx.QueryParams(query)).encode() if query else None,
        )
        try:
            async with (
                self._access_semaphore,
                httpx.AsyncClient(
                    transport=self._access_transport,
                    timeout=self._proxy_limits.request_timeout_seconds,
                    trust_env=False,
                ) as client,
                client.stream(
                    verb,
                    url,
                    headers={SHARE_TOKEN_HEADER: session.token},
                ) as response,
            ):
                chunks: list[bytes] = []
                size = 0
                async for chunk in response.aiter_bytes():
                    size += len(chunk)
                    if size > self._proxy_limits.max_response_bytes:
                        raise RequesterOperationFailure("access_response_too_large")
                    chunks.append(chunk)
                return RequesterAccessResponse(
                    status_code=response.status_code,
                    content=b"".join(chunks),
                    content_type=response.headers.get("content-type"),
                )
        except httpx.TimeoutException as exc:
            raise RequesterOperationFailure("access_upstream_timeout") from exc
        except httpx.RequestError as exc:
            raise RequesterOperationFailure("access_upstream_unavailable") from exc

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
        if result.summary.status is not OperationStatus.SUCCEEDED:
            self._drop_session(record.plan.operation_id)
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

    def _save_session(self, session: _AccessSession) -> None:
        with self._session_lock:
            self._sessions[str(session.plan.operation_id)] = session

    def _drop_session(self, operation_id: OperationId) -> None:
        with self._session_lock:
            self._sessions.pop(str(operation_id), None)
