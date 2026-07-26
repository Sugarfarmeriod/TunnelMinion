"""无状态版本化 HTTP/RPC Tool Gateway。"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import Annotated
from urllib.parse import urlsplit

from fastapi import APIRouter, Header, Query, Request, status
from fastapi.responses import JSONResponse

from tunnelminion.domain.errors import ErrorCode, ToolError
from tunnelminion.domain.identifiers import NodeId
from tunnelminion.domain.tools import Platform, RiskLevel
from tunnelminion.domain.versioning import ProtocolVersion, VersionCompatibility
from tunnelminion.gateway.audit import GatewaySecurityAuditSink, security_event
from tunnelminion.gateway.contracts import (
    GATEWAY_PROTOCOL,
    GatewayCapabilities,
    GatewayError,
    GatewayErrorCode,
    GatewayErrorResponse,
    RemoteOperationExecution,
    RemoteOperationResult,
    RemoteOperationSubmission,
    RemoteToolCall,
    RemoteToolResult,
)
from tunnelminion.gateway.operations import CallbackRequesterVerifier, TargetOperationGatewayService
from tunnelminion.gateway.security import GatewayPeerPolicy, GatewaySecurityPolicy
from tunnelminion.operation.contracts import OperationSummary
from tunnelminion.tools.contracts import (
    ToolCallContext,
    ToolCancellationToken,
    ToolExecutionRequest,
    ToolExecutionResult,
    ToolExecutionStatus,
)
from tunnelminion.tools.registry import ToolRegistry
from tunnelminion.tools.runtime import ToolRuntime


def _error(status_code: int, code: GatewayErrorCode, message: str) -> JSONResponse:
    body = GatewayErrorResponse(error=GatewayError(code=code, message=message))
    return JSONResponse(status_code=status_code, content=body.model_dump(mode="json"))


async def execute_bounded(
    runtime: ToolRuntime,
    request: ToolExecutionRequest,
    timeout_seconds: float,
    is_disconnected: Callable[[], Awaitable[bool]],
) -> ToolExecutionResult:
    """在网关截止时间或客户端断连时传播取消到 Tool Runtime。"""
    cancellation = ToolCancellationToken()
    execution = asyncio.create_task(runtime.execute(request, cancellation))
    deadline = asyncio.get_running_loop().time() + timeout_seconds
    was_disconnected = False
    while not execution.done():
        remaining = deadline - asyncio.get_running_loop().time()
        if remaining <= 0:
            break
        try:
            return await asyncio.wait_for(asyncio.shield(execution), timeout=min(0.01, remaining))
        except TimeoutError:
            pass
        try:
            was_disconnected = await asyncio.wait_for(is_disconnected(), timeout=0.01)
        except TimeoutError:
            was_disconnected = False
        if was_disconnected:
            break
    if execution.done():
        return await execution
    cancellation.cancel()
    cancelled_result = await execution
    return ToolExecutionResult(
        tool_run_id=cancelled_result.tool_run_id,
        status=(ToolExecutionStatus.CANCELLED if was_disconnected else ToolExecutionStatus.FAILED),
        error=ToolError(
            code=ErrorCode.CANCELLED if was_disconnected else ErrorCode.REMOTE_TIMEOUT,
            message=(
                "远端客户端已断开，工具调用已取消"
                if was_disconnected
                else "远端工具调用超过请求截止时间"
            ),
            retryable=not was_disconnected,
        ),
    )


def limit_result(result: RemoteToolResult, max_bytes: int) -> RemoteToolResult:
    """超过网关外层响应预算时只返回关联信息和结构化截断错误。"""
    serialized = json.dumps(
        result.model_dump(mode="json"), ensure_ascii=False, separators=(",", ":")
    ).encode()
    if len(serialized) <= max_bytes:
        return result
    return result.model_copy(
        update={
            "status": ToolExecutionStatus.PARTIAL,
            "output": "[远端结果超过网关响应预算，正文已省略]",
            "truncated": True,
            "error": ToolError(
                code=ErrorCode.RESULT_TOO_LARGE,
                message="远端结果超过网关响应预算",
                details={"original_bytes": len(serialized)},
            ),
        }
    )


def create_gateway_router(
    node_id: NodeId,
    platform: Platform,
    registry: ToolRegistry,
    runtime: ToolRuntime,
    security_policy: GatewaySecurityPolicy,
    security_audit_sink: GatewaySecurityAuditSink,
    operation_service: TargetOperationGatewayService | None = None,
) -> APIRouter:
    """创建带节点认证、允许列表和外层资源预算的只读网关。"""
    router = APIRouter()

    def reject(
        status_code: int,
        code: GatewayErrorCode,
        message: str,
        action: str,
        peer: GatewayPeerPolicy | None = None,
    ) -> JSONResponse:
        security_audit_sink.append(
            security_event(action, code, None if peer is None else peer.node_id)
        )
        return _error(status_code, code, message)

    def authenticate(authorization: str | None, action: str) -> GatewayPeerPolicy | JSONResponse:
        audience = "operation-gateway" if action.startswith("operation_") else "tool-gateway"
        peer = security_policy.authenticate(authorization, audience=audience)
        if peer is None:
            return reject(
                status.HTTP_401_UNAUTHORIZED,
                GatewayErrorCode.UNAUTHENTICATED,
                "节点认证失败",
                action,
            )
        if not security_policy.consume(peer):
            return reject(
                status.HTTP_429_TOO_MANY_REQUESTS,
                GatewayErrorCode.RATE_LIMITED,
                "节点请求速率超过限制",
                action,
                peer,
            )
        return peer

    async def capabilities(
        protocol_major: int = Query(default=1, ge=0),
        protocol_minor: int = Query(default=0, ge=0),
        authorization: Annotated[str | None, Header()] = None,
    ) -> GatewayCapabilities | JSONResponse:
        peer = authenticate(authorization, "capabilities")
        if isinstance(peer, JSONResponse):
            return peer
        requested = ProtocolVersion(major=protocol_major, minor=protocol_minor)
        compatibility = VersionCompatibility.evaluate(GATEWAY_PROTOCOL, requested)
        if not compatibility.compatible:
            return reject(
                status.HTTP_409_CONFLICT,
                GatewayErrorCode.PROTOCOL_VERSION_UNSUPPORTED,
                "网关协议主版本不兼容",
                "capabilities",
                peer,
            )
        return GatewayCapabilities(
            protocol=compatibility.negotiated or GATEWAY_PROTOCOL,
            node_id=node_id,
            platform=platform,
            tools=tuple(
                item for item in registry.model_tools(platform) if item.name in peer.allowed_tools
            ),
            operations=(
                tuple(sorted(peer.allowed_operations)) if operation_service is not None else ()
            ),
        )

    async def call_tool(
        tool_name: str,
        request: RemoteToolCall,
        http_request: Request,
        authorization: Annotated[str | None, Header()] = None,
    ) -> RemoteToolResult | JSONResponse:
        peer = authenticate(authorization, "tool_call")
        if isinstance(peer, JSONResponse):
            return peer
        if request.caller_node_id != peer.node_id:
            return reject(
                status.HTTP_403_FORBIDDEN,
                GatewayErrorCode.FORBIDDEN,
                "调用节点身份与认证凭据不一致",
                "tool_call",
                peer,
            )
        if not GATEWAY_PROTOCOL.is_compatible_with(request.protocol):
            return reject(
                status.HTTP_409_CONFLICT,
                GatewayErrorCode.PROTOCOL_VERSION_UNSUPPORTED,
                "网关协议主版本不兼容",
                "tool_call",
                peer,
            )
        entry = registry.lookup(tool_name)
        if (
            entry is None
            or platform not in entry.definition.platforms
            or entry.definition.risk_level is not RiskLevel.READ_ONLY
        ):
            return reject(
                status.HTTP_404_NOT_FOUND,
                GatewayErrorCode.TOOL_NOT_FOUND,
                "远端只读工具不存在或未授权暴露",
                "tool_call",
                peer,
            )
        if tool_name not in peer.allowed_tools:
            return reject(
                status.HTTP_403_FORBIDDEN,
                GatewayErrorCode.FORBIDDEN,
                "该 peer 未获准调用此工具",
                "tool_call",
                peer,
            )
        if not entry.definition.version.is_compatible_with(request.tool_version):
            return reject(
                status.HTTP_409_CONFLICT,
                GatewayErrorCode.TOOL_VERSION_UNSUPPORTED,
                "工具主版本不兼容",
                "tool_call",
                peer,
            )
        execution_request = ToolExecutionRequest(
            context=ToolCallContext(
                thread_id=request.thread_id,
                run_id=request.run_id,
                caller_node_id=request.caller_node_id,
                execution_node_id=node_id,
            ),
            tool_run_id=request.tool_run_id,
            tool_name=tool_name,
            arguments=request.arguments,
        )
        result = await execute_bounded(
            runtime,
            execution_request,
            min(request.timeout_seconds, security_policy.limits.max_timeout_seconds),
            http_request.is_disconnected,
        )
        response = RemoteToolResult(
            protocol=GATEWAY_PROTOCOL,
            execution_node_id=node_id,
            run_id=request.run_id,
            tool_run_id=result.tool_run_id,
            status=result.status,
            output=result.output,
            truncated=result.truncated,
            error=result.error,
        )
        return limit_result(response, security_policy.limits.max_response_bytes)

    def operation_response(record: object) -> RemoteOperationResult | JSONResponse:
        from tunnelminion.operation.contracts import OperationRecord

        validated = OperationRecord.model_validate(record)
        response = RemoteOperationResult(
            protocol=GATEWAY_PROTOCOL,
            execution_node_id=node_id,
            summary=OperationSummary.from_record(validated),
        )
        serialized = json.dumps(
            response.model_dump(mode="json"),
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode()
        if len(serialized) > security_policy.limits.max_response_bytes:
            return _error(
                status.HTTP_413_CONTENT_TOO_LARGE,
                GatewayErrorCode.RESPONSE_TOO_LARGE,
                "操作状态超过网关响应预算",
            )
        return response

    async def submit_operation(
        request: RemoteOperationSubmission,
        authorization: Annotated[str | None, Header()] = None,
    ) -> RemoteOperationResult | JSONResponse:
        peer = authenticate(authorization, "operation_submit")
        if isinstance(peer, JSONResponse):
            return peer
        if operation_service is None:
            return reject(
                status.HTTP_404_NOT_FOUND,
                GatewayErrorCode.OPERATION_NOT_ALLOWED,
                "目标节点未启用操作协议",
                "operation_submit",
                peer,
            )
        plan = request.plan
        if not GATEWAY_PROTOCOL.is_compatible_with(request.protocol):
            return reject(
                status.HTTP_409_CONFLICT,
                GatewayErrorCode.PROTOCOL_VERSION_UNSUPPORTED,
                "网关协议主版本不兼容",
                "operation_submit",
                peer,
            )
        if plan.request_node_id != peer.node_id or plan.target_node_id != node_id:
            return reject(
                status.HTTP_403_FORBIDDEN,
                GatewayErrorCode.FORBIDDEN,
                "操作计划节点身份与认证 peer 不一致",
                "operation_submit",
                peer,
            )
        if plan.tool_name not in peer.allowed_operations:
            return reject(
                status.HTTP_403_FORBIDDEN,
                GatewayErrorCode.OPERATION_NOT_ALLOWED,
                "该 peer 未获准请求此操作",
                "operation_submit",
                peer,
            )
        record = operation_service.submit(plan, at=datetime.now(UTC))
        return operation_response(record)

    async def execute_operation(
        request: RemoteOperationExecution,
        authorization: Annotated[str | None, Header()] = None,
    ) -> RemoteOperationResult | JSONResponse:
        peer = authenticate(authorization, "operation_execute")
        if isinstance(peer, JSONResponse):
            return peer
        if operation_service is None:
            return reject(
                status.HTTP_404_NOT_FOUND,
                GatewayErrorCode.OPERATION_NOT_ALLOWED,
                "目标节点未启用操作协议",
                "operation_execute",
                peer,
            )
        if not GATEWAY_PROTOCOL.is_compatible_with(request.protocol):
            return reject(
                status.HTTP_409_CONFLICT,
                GatewayErrorCode.PROTOCOL_VERSION_UNSUPPORTED,
                "网关协议主版本不兼容",
                "operation_execute",
                peer,
            )
        existing = operation_service.get(request.operation_id)
        if existing is None:
            return reject(
                status.HTTP_404_NOT_FOUND,
                GatewayErrorCode.OPERATION_NOT_FOUND,
                "操作不存在",
                "operation_execute",
                peer,
            )
        if (
            existing.plan.request_node_id != peer.node_id
            or existing.plan.tool_name not in peer.allowed_operations
        ):
            return reject(
                status.HTTP_403_FORBIDDEN,
                GatewayErrorCode.FORBIDDEN,
                "认证 peer 不能执行该操作",
                "operation_execute",
                peer,
            )
        verifier = None
        if request.verification_callback is not None:
            callback_url = urlsplit(request.verification_callback.endpoint)
            if peer.source_host is None or callback_url.hostname != peer.source_host:
                return reject(
                    status.HTTP_403_FORBIDDEN,
                    GatewayErrorCode.FORBIDDEN,
                    "验证回调必须指向认证 peer 的显式 WireGuard 地址",
                    "operation_execute",
                    peer,
                )
            verifier = CallbackRequesterVerifier(request.verification_callback)
        try:
            record = await operation_service.execute(
                operation_id=request.operation_id,
                plan_version=request.plan_version,
                idempotency_key=request.idempotency_key,
                request_node_id=request.request_node_id,
                target_node_id=request.target_node_id,
                thread_id=request.thread_id,
                run_id=request.run_id,
                tool_run_ids=request.tool_run_ids,
                at=datetime.now(UTC),
                verifier=verifier,
            )
        except ValueError as exc:
            code = (
                GatewayErrorCode.PLAN_TAMPERED
                if str(exc) == "plan_tampered"
                else GatewayErrorCode.OPERATION_STATE_CONFLICT
            )
            return reject(
                status.HTTP_409_CONFLICT,
                code,
                "操作计划不匹配或当前状态不可执行",
                "operation_execute",
                peer,
            )
        return operation_response(record)

    async def operation_status(
        operation_id: str,
        authorization: Annotated[str | None, Header()] = None,
    ) -> RemoteOperationResult | JSONResponse:
        from pydantic import ValidationError

        from tunnelminion.domain.identifiers import OperationId

        peer = authenticate(authorization, "operation_status")
        if isinstance(peer, JSONResponse):
            return peer
        if operation_service is None:
            return reject(
                status.HTTP_404_NOT_FOUND,
                GatewayErrorCode.OPERATION_NOT_ALLOWED,
                "目标节点未启用操作协议",
                "operation_status",
                peer,
            )
        try:
            identifier = OperationId(operation_id)
        except ValidationError:
            return reject(
                status.HTTP_404_NOT_FOUND,
                GatewayErrorCode.OPERATION_NOT_FOUND,
                "操作不存在",
                "operation_status",
                peer,
            )
        record = operation_service.get(identifier)
        if record is None:
            return reject(
                status.HTTP_404_NOT_FOUND,
                GatewayErrorCode.OPERATION_NOT_FOUND,
                "操作不存在",
                "operation_status",
                peer,
            )
        if (
            record.plan.request_node_id != peer.node_id
            or record.plan.tool_name not in peer.allowed_operations
        ):
            return reject(
                status.HTTP_403_FORBIDDEN,
                GatewayErrorCode.FORBIDDEN,
                "认证 peer 不能查看该操作",
                "operation_status",
                peer,
            )
        return operation_response(record)

    router.add_api_route("/v1/capabilities", capabilities, methods=["GET"], response_model=None)
    router.add_api_route(
        "/v1/tools/{tool_name}:call", call_tool, methods=["POST"], response_model=None
    )
    router.add_api_route(
        "/v1/operations:submit",
        submit_operation,
        methods=["POST"],
        response_model=None,
    )
    router.add_api_route(
        "/v1/operations:execute",
        execute_operation,
        methods=["POST"],
        response_model=None,
    )
    router.add_api_route(
        "/v1/operations/{operation_id}",
        operation_status,
        methods=["GET"],
        response_model=None,
    )
    return router
