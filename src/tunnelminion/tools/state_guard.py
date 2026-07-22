"""证明只读工具序列不改变平台状态的测试护栏。"""

from __future__ import annotations

from types import TracebackType
from typing import Protocol

from pydantic import BaseModel, ConfigDict


class PlatformStateSnapshot(BaseModel):
    """不含秘密正文的平台状态摘要。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    wireguard_digest: str
    routes_digest: str
    containers_digest: str
    services_digest: str


class StateSnapshotProvider(Protocol):
    """测试环境提供的平台状态摘要读取边界。"""

    async def capture(self) -> PlatformStateSnapshot:
        """读取当前状态摘要，不修改平台。"""
        ...


class StateMutationDetected(AssertionError):
    """只读工具序列意外改变受保护状态。"""


class ReadOnlyStateGuard:
    """在工具序列前后比较平台摘要。"""

    def __init__(self, provider: StateSnapshotProvider) -> None:
        self._provider = provider
        self._before: PlatformStateSnapshot | None = None

    async def __aenter__(self) -> ReadOnlyStateGuard:
        self._before = await self._provider.capture()
        return self

    async def __aexit__(
        self,
        exception_type: type[BaseException] | None,
        exception: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool:
        del exception_type, exception, traceback
        after = await self._provider.capture()
        if self._before != after:
            raise StateMutationDetected("只读工具序列改变了受保护的平台状态")
        return False
