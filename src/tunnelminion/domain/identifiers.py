"""本地与远端 Agent 操作共享的不透明标识符。"""

from __future__ import annotations

import re
from typing import ClassVar, Self
from uuid import uuid4

from pydantic import RootModel, model_validator

_IDENTIFIER_BODY = re.compile(r"^[0-9a-f]{32}$")


class _Identifier(RootModel[str]):
    """具有稳定实体前缀且经过校验的不透明标识符。"""

    prefix: ClassVar[str]

    @model_validator(mode="after")
    def validate_identifier(self) -> Self:
        expected_prefix = f"{self.prefix}_"
        body = self.root.removeprefix(expected_prefix)
        if not self.root.startswith(expected_prefix) or not _IDENTIFIER_BODY.fullmatch(body):
            msg = f"标识符必须符合 {expected_prefix}<32 位小写十六进制字符>"
            raise ValueError(msg)
        return self

    @classmethod
    def new(cls) -> Self:
        """生成新的不透明标识符，不向外暴露 UUID 语义。"""
        return cls(f"{cls.prefix}_{uuid4().hex}")

    def __str__(self) -> str:
        return self.root


class NodeId(_Identifier):
    """TunnelMinion 节点的持久身份标识。"""

    prefix = "node"


class ThreadId(_Identifier):
    """本地对话线程的身份标识。"""

    prefix = "thread"


class RunId(_Identifier):
    """一次有界 Agent 执行的身份标识。"""

    prefix = "run"


class ToolRunId(_Identifier):
    """一次本地或远端工具执行的身份标识。"""

    prefix = "toolrun"


class ArtifactId(_Identifier):
    """大型工具结果 artifact 的稳定身份标识。"""

    prefix = "artifact"


class MemoryId(_Identifier):
    """一条可查看和删除的长期记忆标识。"""

    prefix = "memory"


class OperationId(_Identifier):
    """一次持久化副作用操作的稳定标识。"""

    prefix = "operation"


class AuthorizationId(_Identifier):
    """逐次授权或预授权决策的稳定标识。"""

    prefix = "authorization"


class LeaseId(_Identifier):
    """限制临时资源生命周期的稳定标识。"""

    prefix = "lease"


class ResourceId(_Identifier):
    """TunnelMinion 自有临时资源的稳定标识。"""

    prefix = "resource"
