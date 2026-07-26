"""macOS Provider 对共享受管网络 saga 的平台绑定。"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Protocol

from tunnelminion.network.contracts import ProviderKind
from tunnelminion.network.ledger import SQLiteManagedResourceLedger
from tunnelminion.platforms.windows.network_provider import (
    SQLiteWindowsOperationJournal,
    WindowsBackendError,
    WindowsManagedBackend,
    WindowsNetworkProvider,
)

MacOSBackendError = WindowsBackendError


class MacOSManagedBackend(WindowsManagedBackend, Protocol):
    """macOS 固定命令后端；共享同一结构化 saga 契约。"""


class SQLiteMacOSOperationJournal(SQLiteWindowsOperationJournal):
    """复用经过恢复测试的逐步日志格式，实例使用独立 macOS 数据库路径。"""


class MacOSNetworkProvider(WindowsNetworkProvider):
    """只管理账本可证明自有的独立 macOS 测试资源。"""

    def __init__(
        self,
        backend: MacOSManagedBackend,
        ledger: SQLiteManagedResourceLedger,
        journals: SQLiteMacOSOperationJournal,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        super().__init__(
            backend,
            ledger,
            journals,
            clock=clock,
            provider_kind=ProviderKind.MACOS,
            protected_interfaces=frozenset({"utun4"}),
            platform_label="macOS",
        )


def macos_operation_journal(path: Path) -> SQLiteMacOSOperationJournal:
    """用显式构造器强调 macOS 与 Windows journal 文件必须隔离。"""
    return SQLiteMacOSOperationJournal(path)
