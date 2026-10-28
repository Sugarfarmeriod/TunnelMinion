"""A→B 固定版本客户端、取消传播和跨节点关联审计。"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from typing import Literal, cast

import httpx
from opentelemetry.trace import SpanKind
from pydantic import JsonValue, ValidationError

from tunnelminion.domain.delegation import DelegationRecord, DelegationRequest
from tunnelminion.domain.errors import ErrorCode, ToolError
from tunnelminion.domain.identifiers import DelegationId, NodeId, OperationId, ToolRunId
from tunnelminion.domain.invites import InviteAcceptance, InviteAccepted, InviteCode
from tunnelminion.domain.model_borrowing import (
    MAX_MODEL_CALL_SECONDS,
    BorrowedModelCall,
    BorrowedModelResult,
)
from tunnelminion.domain.versioning import ProtocolVersion
from tunnelminion.gateway.contracts import (
    GATEWAY_PROTOCOL,
    GatewayCapabilities,
    GatewayErrorCode,
    GatewayErrorResponse,
    GatewayServices,
    PeerRepairView,
    RemoteOperationExecution,
    RemoteOperationResult,
    RemoteOperationSubmission,
    RemoteToolCall,
    RemoteToolResult,
    RequesterVerificationCallback,
)
from tunnelminion.gateway.credentials import (
    GatewayCredential,
    GatewayCredentials,
    GatewayRequestAuth,
)
from tunnelminion.operation.contracts import OperationPlan
from tunnelminion.telemetry import inject_headers, set_status, span
from tunnelminion.tools.audit import AuditRecord, AuditSink
from tunnelminion.tools.contracts import (
    ToolCallContext,
    ToolCancellationToken,
    ToolExecutionStatus,
)


class InviteHandshakeError(RuntimeError):
    """邀请码握手失败，不包含令牌或远端响应正文。"""

    def __init__(
        self, reason: Literal["invalid", "rate_limited", "unreachable", "bad_response"]
    ) -> None:
        super().__init__(reason)
        self.reason = reason


async def accept_invite(
    code: InviteCode,
    acceptance: InviteAcceptance,
    *,
    transport: httpx.AsyncBaseTransport | None = None,
) -> InviteAccepted:
    """用邀请码令牌向邀请方报到，尚不依赖本机 peer 配置。"""
    try:
        async with httpx.AsyncClient(
            base_url=httpx.URL(scheme="http", host=code.host, port=code.port),
            headers={"Authorization": f"Bearer {code.token}"},
            timeout=15,
            transport=transport,
            trust_env=False,
        ) as client:
            response = await client.post(
                "/v1/invites:accept",
                content=acceptance.model_dump_json(),
                headers={"Content-Type": "application/json"},
            )
    except httpx.RequestError as exc:
        raise InviteHandshakeError("unreachable") from exc
    except httpx.InvalidURL as exc:
        raise InviteHandshakeError("bad_response") from exc
    if len(response.content) > 512_000:
        raise InviteHandshakeError("bad_response")
    try:
        if response.status_code == 200:
            accepted = InviteAccepted.model_validate_json(response.content)
            if accepted.inviter_node_id != code.node_id:
                raise InviteHandshakeError("bad_response")
            return accepted
        error = GatewayErrorResponse.model_validate_json(response.content).error.code
    except ValidationError as exc:
        raise InviteHandshakeError("bad_response") from exc
    if response.status_code == 401 and error is GatewayErrorCode.INVITE_INVALID:
        raise InviteHandshakeError("invalid")
    if response.status_code == 429 and error is GatewayErrorCode.RATE_LIMITED:
        raise InviteHandshakeError("rate_limited")
    raise InviteHandshakeError("bad_response")


class RemoteGatewayError(RuntimeError):
    """能力、认证或协议失败；消息永不包含 token 或响应正文。"""

    def __init__(
        self, code: ErrorCode, message: str, *, gateway_code: GatewayErrorCode | None = None
    ) -> None:
        super().__init__(message)
        self.code = code
        self.gateway_code = gateway_code


_GATEWAY_ERROR_MAP = {
    GatewayErrorCode.PROTOCOL_VERSION_UNSUPPORTED: ErrorCode.VERSION_INCOMPATIBLE,
    GatewayErrorCode.TOOL_VERSION_UNSUPPORTED: ErrorCode.VERSION_INCOMPATIBLE,
    GatewayErrorCode.TOOL_NOT_FOUND: ErrorCode.TOOL_NOT_FOUND,
    GatewayErrorCode.UNAUTHENTICATED: ErrorCode.UNAUTHENTICATED,
    GatewayErrorCode.TRUST_SYNC_REQUIRED: ErrorCode.UNAUTHENTICATED,
    GatewayErrorCode.FORBIDDEN: ErrorCode.FORBIDDEN,
    GatewayErrorCode.RATE_LIMITED: ErrorCode.RATE_LIMITED,
    GatewayErrorCode.OPERATION_NOT_ALLOWED: ErrorCode.FORBIDDEN,
    GatewayErrorCode.OPERATION_NOT_FOUND: ErrorCode.INVALID_ARGUMENT,
    GatewayErrorCode.OPERATION_STATE_CONFLICT: ErrorCode.INVALID_ARGUMENT,
    GatewayErrorCode.PLAN_TAMPERED: ErrorCode.FORBIDDEN,
    GatewayErrorCode.RESPONSE_TOO_LARGE: ErrorCode.RESULT_TOO_LARGE,
    GatewayErrorCode.DELEGATION_NOT_ALLOWED: ErrorCode.FORBIDDEN,
    GatewayErrorCode.DELEGATION_BUSY: ErrorCode.RATE_LIMITED,
    GatewayErrorCode.DELEGATION_NOT_FOUND: ErrorCode.INVALID_ARGUMENT,
    GatewayErrorCode.DELEGATION_UNAVAILABLE: ErrorCode.OPERATION_NOT_SUPPORTED,
    GatewayErrorCode.MODEL_BORROWING_NOT_ALLOWED: ErrorCode.FORBIDDEN,
    GatewayErrorCode.MODEL_BORROWING_UNAVAILABLE: ErrorCode.OPERATION_NOT_SUPPORTED,
    GatewayErrorCode.MODEL_QUOTA_EXCEEDED: ErrorCode.RATE_LIMITED,
    GatewayErrorCode.MODEL_BUSY: ErrorCode.RATE_LIMITED,
    GatewayErrorCode.MODEL_CALL_FAILED: ErrorCode.INTERNAL,
    GatewayErrorCode.INVITE_INVALID: ErrorCode.UNAUTHENTICATED,
    GatewayErrorCode.REPAIR_APPROVAL_NOT_ALLOWED: ErrorCode.FORBIDDEN,
    GatewayErrorCode.REPAIR_NOT_FOUND: ErrorCode.INVALID_ARGUMENT,
    GatewayErrorCode.REPAIR_STATE_CONFLICT: ErrorCode.INVALID_ARGUMENT,
    GatewayErrorCode.REPAIR_UNAVAILABLE: ErrorCode.OPERATION_NOT_SUPPORTED,
}


class FixedGatewayClient:
    """仅调用显式 peer endpoint 和版本化只读工具，不支持动态 URL。"""

    def __init__(
        self,
        endpoint: str,
        token: GatewayCredential,
        local_node_id: NodeId,
        remote_node_id: NodeId,
        audit_sink: AuditSink,
        *,
        max_response_bytes: int = 512_000,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        if not endpoint.startswith("http://"):
            raise ValueError("MVP 网关 endpoint 必须是 WireGuard 私网 HTTP 地址")
        if isinstance(token, str) and len(token) < 32:
            raise ValueError("节点认证 token 过短")
        if max_response_bytes < 512:
            raise ValueError("客户端响应预算过小")
        self._endpoint = endpoint.rstrip("/")
        self._token = token
        self._local_node_id = local_node_id
        self._remote_node_id = remote_node_id
        self._audit = audit_sink
        self._max_response_bytes = max_response_bytes
        self._transport = transport

    async def get_repair(self, repair_id: OperationId | str) -> PeerRepairView:
        """只读取固定对端的一件修复，不从服务清单推测执行进度。"""
        return await self._request_repair(repair_id)

    async def approve_repair(self, repair_id: OperationId | str) -> PeerRepairView:
        """只传修复编号，具体修法始终由对端本机保存。"""
        return await self._request_repair(repair_id, "approve")

    async def reject_repair(self, repair_id: OperationId | str) -> PeerRepairView:
        """只传修复编号，不向对端提交拒绝理由。"""
        return await self._request_repair(repair_id, "reject")

    async def _request_repair(
        self, repair_id: OperationId | str, action: Literal["approve", "reject"] | None = None
    ) -> PeerRepairView:
        identifier = OperationId(str(repair_id))
        path = f"/v1/repairs/{identifier}" + (f":{action}" if action else "")
        async with self._http_client(f"repair_{action or 'status'}") as client:
            try:
                response = await client.request("POST" if action else "GET", path, timeout=10)
            except httpx.TimeoutException as exc:
                raise RemoteGatewayError(ErrorCode.REMOTE_TIMEOUT, "远端修复请求超时") from exc
            except httpx.RequestError as exc:
                raise RemoteGatewayError(ErrorCode.NODE_UNREACHABLE, "远端节点不可达") from exc
        self._check_response_size(response)
        if not response.is_success:
            error = self._protocol_error(response)
            if response.status_code == 404 and error.gateway_code is None:
                raise RemoteGatewayError(
                    ErrorCode.FORBIDDEN,
                    "对方尚不支持代批准修复",
                    gateway_code=GatewayErrorCode.REPAIR_APPROVAL_NOT_ALLOWED,
                )
            raise error
        try:
            result = PeerRepairView.model_validate_json(response.content)
        except ValidationError as exc:
            raise RemoteGatewayError(ErrorCode.INTERNAL, "远端修复响应格式无效") from exc
        if result.repair_id != identifier or result.node_id != self._remote_node_id:
            raise RemoteGatewayError(ErrorCode.FORBIDDEN, "远端修复响应身份不匹配")
        return result

    async def discover(self) -> GatewayCapabilities:
        """认证并协商能力清单，同时验证响应来源节点。"""
        async with self._http_client("capabilities") as client:
            try:
                response = await client.get(
                    "/v1/capabilities",
                    params={
                        "protocol_major": GATEWAY_PROTOCOL.major,
                        "protocol_minor": GATEWAY_PROTOCOL.minor,
                    },
                )
            except httpx.TimeoutException as exc:
                raise RemoteGatewayError(ErrorCode.REMOTE_TIMEOUT, "远端能力发现超时") from exc
            except httpx.RequestError as exc:
                raise RemoteGatewayError(ErrorCode.NODE_UNREACHABLE, "远端节点不可达") from exc
        self._check_response_size(response)
        if not response.is_success:
            raise self._protocol_error(response)
        try:
            capabilities = GatewayCapabilities.model_validate_json(response.content)
        except ValidationError as exc:
            raise RemoteGatewayError(ErrorCode.INTERNAL, "远端能力响应格式无效") from exc
        if capabilities.node_id != self._remote_node_id:
            raise RemoteGatewayError(ErrorCode.FORBIDDEN, "远端节点身份与 peer 配置不一致")
        if not GATEWAY_PROTOCOL.is_compatible_with(capabilities.protocol):
            raise RemoteGatewayError(ErrorCode.VERSION_INCOMPATIBLE, "远端网关协议不兼容")
        return capabilities

    async def call(
        self,
        tool_name: str,
        tool_version: ProtocolVersion,
        context: ToolCallContext,
        arguments: dict[str, JsonValue],
        timeout_seconds: float,
        cancellation: ToolCancellationToken | None = None,
        tool_run_id: ToolRunId | None = None,
    ) -> RemoteToolResult:
        """调用固定远端工具，并无论成功失败都写入 A 端关联审计。"""
        if context.caller_node_id != self._local_node_id:
            raise ValueError("调用上下文 caller 与本地节点不一致")
        if context.execution_node_id != self._remote_node_id:
            raise ValueError("调用上下文 execution 与远端 peer 不一致")
        identifier = tool_run_id or ToolRunId.new()
        started_at = datetime.now(UTC)
        token = cancellation or ToolCancellationToken()
        request = RemoteToolCall(
            protocol=GATEWAY_PROTOCOL,
            tool_version=tool_version,
            thread_id=context.thread_id,
            run_id=context.run_id,
            tool_run_id=identifier,
            caller_node_id=self._local_node_id,
            arguments=arguments,
            timeout_seconds=timeout_seconds,
        )
        if token.cancelled:
            result = self._local_failure(
                context,
                identifier,
                ToolExecutionStatus.CANCELLED,
                ErrorCode.CANCELLED,
                "远端工具调用已取消",
            )
            self._audit_result(context, tool_name, tool_version, arguments, started_at, result)
            return result
        result = await self._send_call(tool_name, request, token, context)
        self._audit_result(context, tool_name, tool_version, arguments, started_at, result)
        return result

    async def submit_operation(self, plan: OperationPlan) -> RemoteOperationResult:
        """把完整计划提交到固定目标节点重新校验。"""
        self._validate_operation_nodes(plan)
        request = RemoteOperationSubmission(protocol=GATEWAY_PROTOCOL, plan=plan)
        result = await self._request_operation(
            "POST",
            "/v1/operations:submit",
            content=request.model_dump_json(
                exclude={"plan": {"source_incident_id"}}
                if plan.source_incident_id is None
                else None
            ),
        )
        if result.summary.operation_id != plan.operation_id:
            raise RemoteGatewayError(ErrorCode.INTERNAL, "远端操作响应 ID 不匹配")
        return result

    async def execute_operation(
        self,
        plan: OperationPlan,
        *,
        verification_callback: RequesterVerificationCallback | None = None,
    ) -> RemoteOperationResult:
        """请求目标节点执行原计划；目标节点仍拥有最终授权权。"""
        self._validate_operation_nodes(plan)
        request = RemoteOperationExecution(
            protocol=GATEWAY_PROTOCOL,
            operation_id=plan.operation_id,
            plan_version=plan.plan_version,
            idempotency_key=plan.idempotency_key,
            request_node_id=plan.request_node_id,
            target_node_id=plan.target_node_id,
            thread_id=plan.thread_id,
            run_id=plan.run_id,
            tool_run_ids=plan.tool_run_ids,
            verification_callback=verification_callback,
        )
        return await self._request_operation(
            "POST",
            "/v1/operations:execute",
            content=request.model_dump_json(),
        )

    async def get_operation(self, operation_id: OperationId) -> RemoteOperationResult:
        """读取固定 peer 上属于本请求节点的脱敏操作状态。"""
        result = await self._request_operation(
            "GET",
            f"/v1/operations/{operation_id}",
        )
        if result.summary.operation_id != operation_id:
            raise RemoteGatewayError(ErrorCode.INTERNAL, "远端操作响应 ID 不匹配")
        return result

    async def get_services(self) -> GatewayServices:
        """读取固定对端已经筛选的服务清单。"""
        async with self._http_client("services") as client:
            try:
                response = await client.get("/v1/services", timeout=10)
            except httpx.TimeoutException as exc:
                raise RemoteGatewayError(ErrorCode.REMOTE_TIMEOUT, "远端服务清单请求超时") from exc
            except httpx.RequestError as exc:
                raise RemoteGatewayError(ErrorCode.NODE_UNREACHABLE, "远端节点不可达") from exc
        self._check_response_size(response)
        if not response.is_success:
            raise self._protocol_error(response)
        try:
            result = GatewayServices.model_validate_json(response.content)
        except ValidationError as exc:
            raise RemoteGatewayError(ErrorCode.INTERNAL, "远端服务清单格式无效") from exc
        if result.node_id != self._remote_node_id:
            raise RemoteGatewayError(ErrorCode.FORBIDDEN, "远端响应节点身份不匹配")
        return result

    async def submit_delegation(
        self, question: str, service_key: str | None = None
    ) -> DelegationRecord:
        """把一个问题交给对端的 Agent；只发问题和相关服务，不发命令。"""
        request = DelegationRequest(
            caller_node_id=self._local_node_id, question=question, service_key=service_key
        )
        return await self._request_delegation(
            "POST", "/v1/delegations", content=request.model_dump_json()
        )

    async def get_delegation(self, delegation_id: DelegationId) -> DelegationRecord:
        """读取对端对这次委派的处理进度和结论。"""
        return await self._request_delegation("GET", f"/v1/delegations/{delegation_id}")

    async def cancel_delegation(self, delegation_id: DelegationId) -> DelegationRecord:
        """请对端停止处理这次委派。"""
        return await self._request_delegation("DELETE", f"/v1/delegations/{delegation_id}")

    async def complete_model(self, call: BorrowedModelCall) -> BorrowedModelResult:
        """向固定对端借用一次模型调用。"""
        if call.caller_node_id != self._local_node_id:
            raise ValueError("调用上下文 caller 与本地节点不一致")
        async with self._http_client("model_complete") as client:
            try:
                response = await client.post(
                    "/v1/model:complete",
                    content=call.model_dump_json(),
                    headers={"Content-Type": "application/json"},
                    timeout=MAX_MODEL_CALL_SECONDS + 10,
                )
            except httpx.TimeoutException as exc:
                raise RemoteGatewayError(ErrorCode.REMOTE_TIMEOUT, "连不上对方电脑") from exc
            except httpx.RequestError as exc:
                raise RemoteGatewayError(ErrorCode.NODE_UNREACHABLE, "连不上对方电脑") from exc
        self._check_response_size(response, max_response_bytes=2_000_000)
        if not response.is_success:
            raise self._protocol_error(response)
        try:
            result = BorrowedModelResult.model_validate_json(response.content)
        except ValidationError as exc:
            raise RemoteGatewayError(ErrorCode.INTERNAL, "对方电脑的模型调用失败") from exc
        if result.provider_node_id != self._remote_node_id:
            raise RemoteGatewayError(ErrorCode.FORBIDDEN, "远端响应节点身份不匹配")
        return result

    async def _request_delegation(
        self, method: str, path: str, *, content: str | None = None
    ) -> DelegationRecord:
        action = {
            "POST": "submit_delegation",
            "GET": "delegation_status",
            "DELETE": "cancel_delegation",
        }
        async with self._http_client(action[method]) as client:
            try:
                response = await client.request(
                    method,
                    path,
                    content=content,
                    headers={"Content-Type": "application/json"} if content is not None else None,
                    timeout=30,
                )
            except httpx.TimeoutException as exc:
                raise RemoteGatewayError(ErrorCode.REMOTE_TIMEOUT, "远端委派请求超时") from exc
            except httpx.RequestError as exc:
                raise RemoteGatewayError(ErrorCode.NODE_UNREACHABLE, "远端节点不可达") from exc
        self._check_response_size(response)
        if not response.is_success:
            raise self._protocol_error(response)
        try:
            record = DelegationRecord.model_validate_json(response.content)
        except ValidationError as exc:
            raise RemoteGatewayError(ErrorCode.INTERNAL, "远端委派响应格式无效") from exc
        if (
            record.executing_node_id != self._remote_node_id
            or record.caller_node_id != self._local_node_id
        ):
            raise RemoteGatewayError(ErrorCode.FORBIDDEN, "远端委派响应节点身份不匹配")
        return record

    def _validate_operation_nodes(self, plan: OperationPlan) -> None:
        if plan.request_node_id != self._local_node_id:
            raise ValueError("操作计划 request_node_id 与本地节点不一致")
        if plan.target_node_id != self._remote_node_id:
            raise ValueError("操作计划 target_node_id 与远端节点不一致")

    async def _request_operation(
        self,
        method: str,
        path: str,
        *,
        content: str | None = None,
    ) -> RemoteOperationResult:
        action = "operation_status" if method == "GET" else path.rsplit(":", 1)[1] + "_operation"
        async with self._http_client(action) as client:
            try:
                response = await client.request(
                    method,
                    path,
                    content=content,
                    headers={"Content-Type": "application/json"} if content is not None else None,
                    timeout=30,
                )
            except httpx.TimeoutException as exc:
                raise RemoteGatewayError(ErrorCode.REMOTE_TIMEOUT, "远端操作请求超时") from exc
            except httpx.RequestError as exc:
                raise RemoteGatewayError(ErrorCode.NODE_UNREACHABLE, "远端节点不可达") from exc
        self._check_response_size(response)
        if not response.is_success:
            raise self._protocol_error(response)
        try:
            result = RemoteOperationResult.model_validate_json(response.content)
        except ValidationError as exc:
            raise RemoteGatewayError(ErrorCode.INTERNAL, "远端操作响应格式无效") from exc
        if result.execution_node_id != self._remote_node_id:
            raise RemoteGatewayError(ErrorCode.FORBIDDEN, "远端操作响应节点身份不匹配")
        if not GATEWAY_PROTOCOL.is_compatible_with(result.protocol):
            raise RemoteGatewayError(ErrorCode.VERSION_INCOMPATIBLE, "远端操作协议不兼容")
        return result

    async def _send_call(
        self,
        tool_name: str,
        request: RemoteToolCall,
        cancellation: ToolCancellationToken,
        context: ToolCallContext,
    ) -> RemoteToolResult:
        async with self._http_client("call_tool") as client:
            task = asyncio.create_task(
                client.post(
                    f"/v1/tools/{tool_name}:call",
                    content=request.model_dump_json(),
                    headers={"Content-Type": "application/json"},
                    timeout=request.timeout_seconds + 1,
                )
            )
            cancelled = asyncio.create_task(cancellation.wait())
            done, _pending = await asyncio.wait(
                {task, cancelled}, return_when=asyncio.FIRST_COMPLETED
            )
            if cancelled in done:
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
                return self._local_failure(
                    context,
                    request.tool_run_id,
                    ToolExecutionStatus.CANCELLED,
                    ErrorCode.CANCELLED,
                    "远端工具调用已取消",
                )
            cancelled.cancel()
            await asyncio.gather(cancelled, return_exceptions=True)
            try:
                response = await task
            except httpx.TimeoutException:
                return self._local_failure(
                    context,
                    request.tool_run_id,
                    ToolExecutionStatus.FAILED,
                    ErrorCode.REMOTE_TIMEOUT,
                    "远端工具调用超时",
                )
            except httpx.RequestError:
                return self._local_failure(
                    context,
                    request.tool_run_id,
                    ToolExecutionStatus.FAILED,
                    ErrorCode.NODE_UNREACHABLE,
                    "远端节点不可达",
                )
        try:
            self._check_response_size(response)
        except RemoteGatewayError as exc:
            return self._local_failure(
                context,
                request.tool_run_id,
                ToolExecutionStatus.FAILED,
                exc.code,
                str(exc),
            )
        if not response.is_success:
            error = self._protocol_error(response)
            return self._local_failure(
                context,
                request.tool_run_id,
                ToolExecutionStatus.FAILED,
                error.code,
                str(error),
            )
        try:
            result = RemoteToolResult.model_validate_json(response.content)
        except ValidationError:
            return self._local_failure(
                context,
                request.tool_run_id,
                ToolExecutionStatus.FAILED,
                ErrorCode.INTERNAL,
                "远端工具响应格式无效",
            )
        if result.run_id != context.run_id or result.tool_run_id != request.tool_run_id:
            return self._local_failure(
                context,
                request.tool_run_id,
                ToolExecutionStatus.FAILED,
                ErrorCode.INTERNAL,
                "远端响应关联 ID 不匹配",
            )
        if result.execution_node_id != self._remote_node_id:
            return self._local_failure(
                context,
                request.tool_run_id,
                ToolExecutionStatus.FAILED,
                ErrorCode.FORBIDDEN,
                "远端响应节点身份不匹配",
            )
        return result

    @asynccontextmanager
    async def _http_client(self, action: str) -> AsyncGenerator[httpx.AsyncClient]:
        with span(f"gateway.client.{action}", kind=SpanKind.CLIENT) as current:

            async def record_response(response: httpx.Response) -> None:
                current.set_attribute("http.response.status_code", response.status_code)
                set_status(current, "error" if response.status_code >= 400 else "success")

            async with httpx.AsyncClient(
                base_url=self._endpoint,
                headers={
                    **(
                        {"Authorization": f"Bearer {self._token}"}
                        if isinstance(self._token, str)
                        else {}
                    ),
                    **inject_headers(),
                },
                auth=(
                    GatewayRequestAuth(self._token)
                    if isinstance(self._token, GatewayCredentials)
                    else None
                ),
                transport=self._transport
                or (
                    httpx.AsyncHTTPTransport(local_address=self._token.source_host)
                    if isinstance(self._token, GatewayCredentials)
                    else None
                ),
                trust_env=False,
                event_hooks={"response": [record_response]},
            ) as client:
                yield client

    def _check_response_size(
        self, response: httpx.Response, *, max_response_bytes: int | None = None
    ) -> None:
        budget = self._max_response_bytes if max_response_bytes is None else max_response_bytes
        if len(response.content) > budget:
            raise RemoteGatewayError(ErrorCode.RESULT_TOO_LARGE, "远端响应超过客户端预算")

    @staticmethod
    def _protocol_error(response: httpx.Response) -> RemoteGatewayError:
        try:
            value = GatewayErrorResponse.model_validate_json(response.content)
        except ValidationError:
            return RemoteGatewayError(ErrorCode.INTERNAL, "远端网关错误格式无效")
        return RemoteGatewayError(
            _GATEWAY_ERROR_MAP[value.error.code], value.error.message, gateway_code=value.error.code
        )

    def _local_failure(
        self,
        context: ToolCallContext,
        tool_run_id: ToolRunId,
        status: ToolExecutionStatus,
        code: ErrorCode,
        message: str,
    ) -> RemoteToolResult:
        return RemoteToolResult(
            protocol=GATEWAY_PROTOCOL,
            execution_node_id=context.execution_node_id,
            run_id=context.run_id,
            tool_run_id=tool_run_id,
            status=status,
            error=ToolError(
                code=code,
                message=message,
                retryable=code
                in {
                    ErrorCode.NODE_UNREACHABLE,
                    ErrorCode.REMOTE_TIMEOUT,
                    ErrorCode.RATE_LIMITED,
                },
            ),
        )

    def _audit_result(
        self,
        context: ToolCallContext,
        tool_name: str,
        tool_version: ProtocolVersion,
        arguments: dict[str, JsonValue],
        started_at: datetime,
        result: RemoteToolResult,
    ) -> None:
        self._audit.append(
            AuditRecord(
                thread_id=context.thread_id,
                run_id=context.run_id,
                tool_run_id=result.tool_run_id,
                caller_node_id=context.caller_node_id,
                execution_node_id=context.execution_node_id,
                tool_name=tool_name,
                tool_version=tool_version,
                arguments_summary=cast(dict[str, JsonValue], self._sanitize(arguments)),
                started_at=started_at,
                finished_at=datetime.now(UTC),
                status=result.status,
                error_code=result.error.code if result.error is not None else None,
            )
        )

    @classmethod
    def _sanitize(cls, value: JsonValue, key: str = "") -> JsonValue:
        if any(marker in key.lower() for marker in ("token", "secret", "password", "key")):
            return "[REDACTED]"
        if isinstance(value, dict):
            return {name: cls._sanitize(item, name) for name, item in value.items()}
        if isinstance(value, list):
            return [cls._sanitize(item) for item in value[:20]]
        if isinstance(value, str) and len(value) > 128:
            return f"{value[:128]}…"
        return value
