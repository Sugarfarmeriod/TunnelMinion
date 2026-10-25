"""通过固定对端借用模型，Agent 与工具仍在本机执行。"""

from __future__ import annotations

import asyncio

from tunnelminion.domain.errors import ErrorCode
from tunnelminion.domain.identifiers import NodeId
from tunnelminion.domain.model_borrowing import BorrowedModelCall
from tunnelminion.gateway.client import FixedGatewayClient, RemoteGatewayError
from tunnelminion.gateway.contracts import GatewayErrorCode
from tunnelminion.model.contracts import (
    CancellationToken,
    ModelCapabilities,
    ModelRequest,
    ModelResponse,
    ProviderError,
    ProviderErrorCode,
)
from tunnelminion.telemetry import model_attributes, record_usage, span

_ERRORS: dict[GatewayErrorCode | ErrorCode, tuple[ProviderErrorCode, str, bool]] = {
    GatewayErrorCode.MODEL_BORROWING_NOT_ALLOWED: (
        ProviderErrorCode.AUTHENTICATION_FAILED,
        "对方电脑没有允许借用模型",
        False,
    ),
    ErrorCode.UNAUTHENTICATED: (
        ProviderErrorCode.AUTHENTICATION_FAILED,
        "对方电脑没有允许借用模型",
        False,
    ),
    ErrorCode.FORBIDDEN: (
        ProviderErrorCode.AUTHENTICATION_FAILED,
        "对方电脑没有允许借用模型",
        False,
    ),
    GatewayErrorCode.MODEL_QUOTA_EXCEEDED: (
        ProviderErrorCode.QUOTA_EXCEEDED,
        "今天借用的额度已用完",
        False,
    ),
    GatewayErrorCode.MODEL_BUSY: (ProviderErrorCode.BUSY, "对方电脑的模型正忙，请稍后再试", True),
    ErrorCode.RATE_LIMITED: (ProviderErrorCode.BUSY, "对方电脑的模型正忙，请稍后再试", True),
    GatewayErrorCode.MODEL_BORROWING_UNAVAILABLE: (
        ProviderErrorCode.MODEL_NOT_FOUND,
        "对方电脑还没有配置模型",
        False,
    ),
    ErrorCode.REMOTE_TIMEOUT: (ProviderErrorCode.TIMEOUT, "连不上对方电脑", True),
    ErrorCode.NODE_UNREACHABLE: (ProviderErrorCode.NETWORK_UNREACHABLE, "连不上对方电脑", True),
}


class RemoteModelProvider:
    """把一轮模型请求交给已认证的固定对端。"""

    def __init__(self, client: FixedGatewayClient, local_node_id: NodeId) -> None:
        self._client = client
        self._local_node_id = local_node_id

    @property
    def capabilities(self) -> ModelCapabilities:
        """借用方支持传输工具定义和结构化输出要求。"""
        return ModelCapabilities(tool_calls=True, structured_output=True)

    async def complete(
        self, request: ModelRequest, cancellation: CancellationToken | None = None
    ) -> ModelResponse:
        """传输模型请求并在取消时收回 HTTP 任务。"""
        with span("model.call", model_attributes(self)) as current:
            token = cancellation or CancellationToken()
            if token.cancelled:
                raise ProviderError(ProviderErrorCode.CANCELLED, "模型调用已取消")
            task = asyncio.create_task(
                self._client.complete_model(
                    BorrowedModelCall.from_request(self._local_node_id, request)
                )
            )
            cancelled = asyncio.create_task(token.wait())
            try:
                done, _ = await asyncio.wait({task, cancelled}, return_when=asyncio.FIRST_COMPLETED)
                if cancelled in done:
                    raise ProviderError(ProviderErrorCode.CANCELLED, "模型调用已取消")
                response = (await task).to_response()
                record_usage(current, response.usage)
                return response
            except RemoteGatewayError as exc:
                code, message, retryable = _ERRORS.get(
                    exc.gateway_code or exc.code,
                    (ProviderErrorCode.INVALID_RESPONSE, "对方电脑的模型调用失败", False),
                )
                raise ProviderError(code, message, retryable=retryable) from exc
            finally:
                task.cancel()
                cancelled.cancel()
                await asyncio.gather(task, cancelled, return_exceptions=True)
