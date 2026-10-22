"""用户对服务的标记："是我的服务"或"隐藏"。

标记挂在一个稳定的身份上，而不是进程号：程序重启后进程号会变，身份不变。
标记一次，对同一身份下的所有端口生效。标记保存在服务所在的那台电脑上。
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Protocol

from tunnelminion.agent.services import RemoteServiceSummary
from tunnelminion.domain.service_marks import MARK_KEY_PATTERN, ServiceMark, is_mark_key
from tunnelminion.platforms.process_origin import normalize_process_name
from tunnelminion.platforms.python_entrypoint import is_python_process

__all__ = [
    "MARK_KEY_PATTERN",
    "InMemoryServiceMarkStore",
    "ServiceMark",
    "ServiceMarkStore",
    "is_mark_key",
    "service_mark_key",
]


def service_mark_key(item: RemoteServiceSummary) -> str:
    """一个端口所属服务的稳定身份。"""
    if item.container_running is not None:
        if item.compose_project:
            return f"docker:compose:{item.compose_project}"
        if (item.container_name or "").strip():
            return f"docker:{(item.container_name or '').strip()}"
    elif is_python_process(item.process_name) and item.python_entrypoint:
        return f"python:{item.python_entrypoint}"
    elif (
        item.process_pid is not None
        and item.process_name
        and not is_python_process(item.process_name)
    ):
        # 没有进程号时名字对应不到真实进程，与分档规则一致，不拿它当身份。
        return f"program:{normalize_process_name(item.process_name)}"
    # 读不出更稳定的身份时只能按端口区分。
    return f"port:{item.protocol}:{item.port}"


class ServiceMarkStore(Protocol):
    """标记的读写。"""

    def all(self) -> Mapping[str, ServiceMark]: ...

    def set(self, key: str, mark: ServiceMark) -> None: ...

    def clear(self, key: str) -> None: ...


class InMemoryServiceMarkStore:
    """不落盘的标记存储，用于测试和只读预览。"""

    def __init__(self) -> None:
        self._marks: dict[str, ServiceMark] = {}

    def all(self) -> Mapping[str, ServiceMark]:
        return dict(self._marks)

    def set(self, key: str, mark: ServiceMark) -> None:
        self._marks[key] = mark

    def clear(self, key: str) -> None:
        self._marks.pop(key, None)
