"""假工具行为与平台状态不变护栏测试。"""

from __future__ import annotations

import asyncio
from collections.abc import Coroutine
from typing import Any, TypeVar

import pytest

from tunnelminion.domain.errors import ErrorCode
from tunnelminion.tools.contracts import ToolAdapterError, ToolCancellationToken
from tunnelminion.tools.fakes import FakeToolAdapter, FakeToolBehavior
from tunnelminion.tools.state_guard import (
    PlatformStateSnapshot,
    ReadOnlyStateGuard,
    StateMutationDetected,
)

T = TypeVar("T")


def run(coroutine: Coroutine[Any, Any, T]) -> T:
    """运行一个异步测试动作。"""
    return asyncio.run(coroutine)


def snapshot(value: str = "stable") -> PlatformStateSnapshot:
    """返回四类受保护状态的摘要。"""
    return PlatformStateSnapshot(
        wireguard_digest=value,
        routes_digest=value,
        containers_digest=value,
        services_digest=value,
    )


class SnapshotProvider:
    """按顺序返回状态摘要。"""

    def __init__(self, values: list[PlatformStateSnapshot]) -> None:
        self._values = values

    async def capture(self) -> PlatformStateSnapshot:
        return self._values.pop(0)


def test_full_fake_read_only_sequence_keeps_platform_state_unchanged() -> None:
    provider = SnapshotProvider([snapshot(), snapshot()])

    async def execute_sequence() -> None:
        token = ToolCancellationToken()
        async with ReadOnlyStateGuard(provider):
            for _ in range(6):
                result = await FakeToolAdapter().execute({}, token)
                assert result == {"ok": True, "arguments": {}}

    run(execute_sequence())


def test_state_guard_detects_mutation_and_preserves_inner_errors() -> None:
    changed = SnapshotProvider([snapshot("before"), snapshot("after")])

    async def mutate() -> None:
        async with ReadOnlyStateGuard(changed):
            pass

    with pytest.raises(StateMutationDetected):
        run(mutate())

    stable = SnapshotProvider([snapshot(), snapshot()])

    async def fail_inside() -> None:
        async with ReadOnlyStateGuard(stable):
            raise ValueError("inner")

    with pytest.raises(ValueError, match="inner"):
        run(fail_inside())


def test_fake_adapter_observes_pre_cancel_and_all_fixed_results() -> None:
    token = ToolCancellationToken()
    token.cancel()
    with pytest.raises(ToolAdapterError) as cancelled:
        run(FakeToolAdapter().execute({}, token))
    assert cancelled.value.error.code is ErrorCode.CANCELLED

    large = run(
        FakeToolAdapter(FakeToolBehavior.LARGE_RESULT, large_result_size=5).execute(
            {}, ToolCancellationToken()
        )
    )
    assert large == {"payload": "xxxxx"}

    injection = run(
        FakeToolAdapter(FakeToolBehavior.PROMPT_INJECTION).execute({}, ToolCancellationToken())
    )
    assert "外部数据" in str(injection)

    for behavior, code in (
        (FakeToolBehavior.ADAPTER_ERROR, ErrorCode.INVALID_ARGUMENT),
        (FakeToolBehavior.PLATFORM_UNSUPPORTED, ErrorCode.OPERATION_NOT_SUPPORTED),
    ):
        with pytest.raises(ToolAdapterError) as caught:
            run(FakeToolAdapter(behavior).execute({}, ToolCancellationToken()))
        assert caught.value.error.code is code
