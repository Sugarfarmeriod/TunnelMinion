"""Agent 节点共享的协议版本兼容模型。"""

from __future__ import annotations

from typing import Self

from pydantic import BaseModel, ConfigDict, Field, model_validator


class ProtocolVersion(BaseModel):
    """由主版本和次版本组成的协议版本；主版本变化表示不兼容。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    major: int = Field(ge=0)
    minor: int = Field(ge=0)

    def is_compatible_with(self, other: ProtocolVersion) -> bool:
        """判断两个节点能否交换该协议族的数据。"""
        return self.major == other.major


class VersionCompatibility(BaseModel):
    """比较本地与远端协议后得到的确定性结果。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    local: ProtocolVersion
    remote: ProtocolVersion
    compatible: bool
    negotiated: ProtocolVersion | None

    @model_validator(mode="after")
    def validate_result(self) -> Self:
        expected_compatible = self.local.is_compatible_with(self.remote)
        expected_version = (
            ProtocolVersion(major=self.local.major, minor=min(self.local.minor, self.remote.minor))
            if expected_compatible
            else None
        )
        if self.compatible != expected_compatible or self.negotiated != expected_version:
            msg = "兼容性结果与提供的协议版本不一致"
            raise ValueError(msg)
        return self

    @classmethod
    def evaluate(cls, local: ProtocolVersion, remote: ProtocolVersion) -> Self:
        """协商两个节点都能理解的最新次版本。"""
        compatible = local.is_compatible_with(remote)
        negotiated = (
            ProtocolVersion(major=local.major, minor=min(local.minor, remote.minor))
            if compatible
            else None
        )
        return cls(
            local=local,
            remote=remote,
            compatible=compatible,
            negotiated=negotiated,
        )
