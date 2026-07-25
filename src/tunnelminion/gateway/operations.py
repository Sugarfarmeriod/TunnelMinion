"""目标节点操作入口与请求节点独立 HTTP 验证器。"""

from __future__ import annotations

import ipaddress
import secrets
from datetime import UTC, datetime

import httpx
from fastapi import APIRouter, Header, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field

from tunnelminion.domain.identifiers import NodeId, OperationId, RunId, ThreadId, ToolRunId
from tunnelminion.gateway.contracts import (
    GATEWAY_PROTOCOL,
    RemoteVerificationRequest,
    RemoteVerificationResult,
    RequesterVerificationCallback,
)
from tunnelminion.operation.contracts import (
    LeaseRecord,
    OperationPlan,
    OperationRecord,
    OperationStore,
    VerificationRecord,
    VerificationResult,
)
from tunnelminion.operation.policy import AuthorizationService
from tunnelminion.operation.workflow import OperationWorkflow, RequesterVerifier, WorkflowUsage


class TargetOperationGatewayService:
    """在目标节点组合计划策略、持久化状态和固定执行工作流。"""

    def __init__(
        self,
        operations: OperationStore,
        authorization: AuthorizationService,
        workflow: OperationWorkflow,
    ) -> None:
        self._operations = operations
        self._authorization = authorization
        self._workflow = workflow

    def submit(self, plan: OperationPlan, *, at: datetime) -> OperationRecord:
        """重复计划返回已有操作，未授权 L2 只进入等待状态。"""
        return self._authorization.submit(
            OperationRecord.planned(plan, occurred_at=at),
            at=at,
        )

    def get(self, operation_id: OperationId) -> OperationRecord | None:
        return self._operations.get(operation_id)

    async def execute(
        self,
        *,
        operation_id: OperationId,
        plan_version: int,
        idempotency_key: str,
        request_node_id: NodeId,
        target_node_id: NodeId,
        thread_id: ThreadId,
        run_id: RunId,
        tool_run_ids: tuple[ToolRunId, ...],
        at: datetime,
        verifier: RequesterVerifier | None = None,
    ) -> OperationRecord:
        """执行请求必须与目标节点持久化的原计划逐字段一致。"""
        record = self._operations.get(operation_id)
        if record is None:
            raise KeyError("operation_not_found")
        plan = record.plan
        expected = (
            plan.plan_version,
            plan.idempotency_key,
            plan.request_node_id,
            plan.target_node_id,
            plan.thread_id,
            plan.run_id,
            plan.tool_run_ids,
        )
        supplied = (
            plan_version,
            idempotency_key,
            request_node_id,
            target_node_id,
            thread_id,
            run_id,
            tool_run_ids,
        )
        if supplied != expected:
            raise ValueError("plan_tampered")
        return await self._workflow.execute_authorized(
            operation_id,
            at=at,
            usage=WorkflowUsage(tool_call_count=len(plan.tool_run_ids)),
            verifier=verifier,
        )


class RequesterVerificationConfig(BaseModel):
    """请求节点验证入口时使用的固定网络与响应预算。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    allowed_target_addresses: frozenset[str] = Field(min_length=1)
    timeout_seconds: float = Field(default=5, gt=0, le=30)
    max_response_bytes: int = Field(default=65_536, ge=1, le=1_048_576)
    accepted_statuses: frozenset[int] = frozenset(range(200, 400))


class GatewayRequesterVerifier(RequesterVerifier):
    """从请求节点沿配置的 WireGuard 地址验证临时入口。"""

    def __init__(
        self,
        config: RequesterVerificationConfig,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._config = config
        self._transport = transport

    async def verify(
        self,
        plan: OperationPlan,
        lease: LeaseRecord,
        access_token: str,
    ) -> VerificationRecord:
        if plan.access_scope.bind_host not in self._config.allowed_target_addresses:
            return self._result(
                plan,
                VerificationResult.FAILED,
                "入口地址不在请求节点允许的 WireGuard 目标集合",
                lease.starts_at,
            )
        address = ipaddress.ip_address(plan.access_scope.bind_host)
        if not address.is_private or address.is_loopback or address.is_unspecified:
            return self._result(
                plan,
                VerificationResult.FAILED,
                "入口地址不是显式私网地址",
                lease.starts_at,
            )
        url = (
            f"http://{plan.access_scope.bind_host}:{plan.access_scope.bind_port}"
            "/__tunnelminion_health"
        )
        try:
            async with (
                httpx.AsyncClient(
                    transport=self._transport,
                    timeout=self._config.timeout_seconds,
                    trust_env=False,
                ) as client,
                client.stream(
                    "GET",
                    url,
                    headers={"X-TunnelMinion-Share-Token": access_token},
                ) as response,
            ):
                size = 0
                async for chunk in response.aiter_bytes():
                    size += len(chunk)
                    if size > self._config.max_response_bytes:
                        return self._result(
                            plan,
                            VerificationResult.FAILED,
                            "验证响应超过请求节点预算",
                            datetime.now(UTC),
                            status_code=response.status_code,
                        )
                accepted = response.status_code in self._config.accepted_statuses
                return self._result(
                    plan,
                    (VerificationResult.PASSED if accepted else VerificationResult.FAILED),
                    (
                        "请求节点沿 WireGuard 路径验证通过"
                        if accepted
                        else "入口状态码不满足健康判据"
                    ),
                    datetime.now(UTC),
                    status_code=response.status_code,
                )
        except httpx.TimeoutException:
            return self._result(
                plan,
                VerificationResult.TIMEOUT,
                "请求节点访问临时入口超时",
                datetime.now(UTC),
            )
        except httpx.RequestError:
            return self._result(
                plan,
                VerificationResult.REQUESTER_OFFLINE,
                "请求节点无法访问临时入口",
                datetime.now(UTC),
            )

    @staticmethod
    def _result(
        plan: OperationPlan,
        result: VerificationResult,
        summary: str,
        at: datetime,
        *,
        status_code: int | None = None,
    ) -> VerificationRecord:
        return VerificationRecord(
            operation_id=plan.operation_id,
            verifier_node_id=plan.request_node_id,
            result=result,
            status_code=status_code,
            evidence_summary=summary,
            verified_at=at,
        )


class CallbackRequesterVerifier(RequesterVerifier):
    """由目标节点调用请求节点的一次性验证回调。"""

    def __init__(
        self,
        callback: RequesterVerificationCallback,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._callback = callback
        self._transport = transport

    async def verify(
        self,
        plan: OperationPlan,
        lease: LeaseRecord,
        access_token: str,
    ) -> VerificationRecord:
        request = RemoteVerificationRequest(
            plan=plan,
            lease=lease,
            access_token=access_token,
        )
        try:
            async with httpx.AsyncClient(
                transport=self._transport,
                timeout=self._callback.timeout_seconds,
                trust_env=False,
            ) as client:
                response = await client.post(
                    f"{self._callback.endpoint}/v1/operations:verify-callback",
                    content=request.model_dump_json(),
                    headers={
                        "Authorization": f"Bearer {self._callback.token}",
                        "Content-Type": "application/json",
                    },
                )
            response.raise_for_status()
            result = RemoteVerificationResult.model_validate_json(response.content)
            verification = result.verification
            if (
                not GATEWAY_PROTOCOL.is_compatible_with(result.protocol)
                or verification.operation_id != plan.operation_id
                or verification.verifier_node_id != plan.request_node_id
            ):
                raise ValueError("验证回调关联信息不匹配")
            return verification
        except httpx.TimeoutException:
            result = VerificationResult.TIMEOUT
            summary = "请求节点验证回调超时"
        except (httpx.HTTPError, ValueError):
            result = VerificationResult.REQUESTER_OFFLINE
            summary = "请求节点验证回调不可用或响应无效"
        return VerificationRecord(
            operation_id=plan.operation_id,
            verifier_node_id=plan.request_node_id,
            result=result,
            evidence_summary=summary,
            verified_at=datetime.now(UTC),
        )


def create_requester_verification_router(
    *,
    local_node_id: NodeId,
    target_node_id: NodeId,
    callback_token: str,
    verifier: RequesterVerifier,
) -> APIRouter:
    """创建只在一次验收期间监听请求节点 WireGuard 地址的回调路由。"""
    if len(callback_token) < 43:
        raise ValueError("验证回调 token 熵不足")
    router = APIRouter()

    async def verify_callback(
        request: RemoteVerificationRequest,
        authorization: str | None = Header(default=None),
    ) -> RemoteVerificationResult:
        supplied = (
            authorization.removeprefix("Bearer ")
            if authorization is not None and authorization.startswith("Bearer ")
            else ""
        )
        if not secrets.compare_digest(supplied, callback_token):
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "验证回调认证失败")
        if (
            request.plan.request_node_id != local_node_id
            or request.plan.target_node_id != target_node_id
            or request.lease.operation_id != request.plan.operation_id
        ):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "验证回调节点或操作不匹配")
        verification = await verifier.verify(
            request.plan,
            request.lease,
            request.access_token,
        )
        return RemoteVerificationResult(verification=verification)

    router.add_api_route(
        "/v1/operations:verify-callback",
        verify_callback,
        methods=["POST"],
    )
    return router
