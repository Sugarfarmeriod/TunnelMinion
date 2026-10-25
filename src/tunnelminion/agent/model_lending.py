"""提供方的一轮模型调用与每日用量记账。"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from datetime import date
from typing import Protocol

from pydantic import ValidationError

from tunnelminion.domain.identifiers import NodeId
from tunnelminion.domain.model_borrowing import (
    MAX_CONCURRENT_CALLS_PER_PEER,
    MAX_MODEL_CALL_SECONDS,
    BorrowedModelCall,
    BorrowedModelResult,
    ModelUsageRecord,
)
from tunnelminion.gateway.contracts import GatewayErrorCode
from tunnelminion.gateway.security import GatewayPeerPolicy
from tunnelminion.model.contracts import CancellationToken, ModelProvider, ProviderError
from tunnelminion.telemetry import model_attributes, record_usage, span


class ModelUsageStore(Protocol):
    """只记录对端、日期、调用次数和 token 数。"""

    def add(self, peer: NodeId, day: date, calls: int, tokens: int) -> None: ...

    def get(self, peer: NodeId, day: date) -> ModelUsageRecord: ...

    def list(self, day: date | None = None) -> tuple[ModelUsageRecord, ...]: ...


class InMemoryModelUsageStore:
    """内存中的每日用量。"""

    def __init__(self) -> None:
        self._records: dict[tuple[str, date], ModelUsageRecord] = {}

    def add(self, peer: NodeId, day: date, calls: int, tokens: int) -> None:
        current = self.get(peer, day)
        self._records[str(peer), day] = ModelUsageRecord(
            peer_node_id=peer, day=day, calls=current.calls + calls, tokens=current.tokens + tokens
        )

    def get(self, peer: NodeId, day: date) -> ModelUsageRecord:
        return self._records.get(
            (str(peer), day), ModelUsageRecord(peer_node_id=peer, day=day, calls=0, tokens=0)
        )

    def list(self, day: date | None = None) -> tuple[ModelUsageRecord, ...]:
        return tuple(
            record
            for _, record in sorted(self._records.items())
            if day is None or record.day == day
        )


class ModelLendingError(Exception):
    """可安全返回给借用方的调用错误。"""

    def __init__(
        self,
        status_code: int,
        code: GatewayErrorCode,
        message: str,
        *,
        retryable: bool = False,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.retryable = retryable


class ModelLendingService:
    """限制每个对端的配额与并发，不保存调用内容。"""

    def __init__(
        self,
        node_id: NodeId,
        provider_factory: Callable[[], ModelProvider],
        store: ModelUsageStore,
        *,
        clock: Callable[[], date] = date.today,
    ) -> None:
        self._node_id = node_id
        self._provider_factory = provider_factory
        self._store = store
        self._clock = clock
        self._running: dict[str, int] = {}

    async def complete(
        self, peer: GatewayPeerPolicy, call: BorrowedModelCall
    ) -> BorrowedModelResult:
        with span("model.call") as current:
            day = self._clock()
            if self._store.get(peer.node_id, day).tokens >= peer.daily_quota:
                raise ModelLendingError(
                    429, GatewayErrorCode.MODEL_QUOTA_EXCEEDED, "今日模型额度已用完"
                )
            key = str(peer.node_id)
            if self._running.get(key, 0) >= MAX_CONCURRENT_CALLS_PER_PEER:
                raise ModelLendingError(
                    429, GatewayErrorCode.MODEL_BUSY, "该对端的模型调用并发已达上限"
                )
            try:
                request = call.to_request()
            except ValidationError:
                raise ModelLendingError(
                    422, GatewayErrorCode.MODEL_CALL_FAILED, "模型消息格式不正确"
                ) from None
            self._running[key] = self._running.get(key, 0) + 1
            cancellation = CancellationToken()
            tokens = 0
            try:
                try:
                    provider = self._provider_factory()
                    current.set_attributes(model_attributes(provider))
                except ProviderError as exc:
                    raise ModelLendingError(
                        503, GatewayErrorCode.MODEL_BORROWING_UNAVAILABLE, exc.code.value
                    ) from None
                try:
                    response = await asyncio.wait_for(
                        provider.complete(request, cancellation),
                        timeout=MAX_MODEL_CALL_SECONDS,
                    )
                except TimeoutError:
                    cancellation.cancel()
                    raise ModelLendingError(
                        504, GatewayErrorCode.MODEL_CALL_FAILED, "模型调用超时", retryable=True
                    ) from None
                except ProviderError as exc:
                    raise ModelLendingError(
                        502,
                        GatewayErrorCode.MODEL_CALL_FAILED,
                        exc.code.value,
                        retryable=exc.retryable,
                    ) from None
                except asyncio.CancelledError:
                    cancellation.cancel()
                    raise
                record_usage(current, response.usage)
                usage = response.usage
                tokens = (
                    usage.total_tokens
                    if usage.total_tokens is not None
                    else (usage.input_tokens or 0) + (usage.output_tokens or 0)
                )
                return BorrowedModelResult.from_response(self._node_id, response)
            finally:
                self._running[key] -= 1
                self._store.add(peer.node_id, day, 1, tokens)
