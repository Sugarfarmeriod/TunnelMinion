"""邀请码：一边生成、一边粘贴，让两台电脑的 Agent 互相认识。

邀请码只解决"Agent 之间怎么认识"，组网本身（WireGuard 或 n2n）仍然假定已经通了。
邀请码里带着一次性令牌，24 小时内有效、只能用一次；加入成功后，这个令牌就是两台电脑之间
长期使用的配对令牌。
"""

from __future__ import annotations

import base64
import binascii
from datetime import datetime, timedelta
from typing import Annotated

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, ValidationError

from tunnelminion.domain.identifiers import NodeId
from tunnelminion.domain.model_borrowing import DEFAULT_DAILY_TOKEN_QUOTA
from tunnelminion.domain.tools import Platform

# 邀请码的固定前缀，方便一眼认出、也方便拒绝粘错的内容。
INVITE_CODE_PREFIX = "tmi1_"
# 邀请码的有效期。
INVITE_LIFETIME = timedelta(hours=24)


def validate_display_name(value: str) -> str:
    """显示名只能是非空的单行可打印文本。"""
    if not value.strip() or not value.isprintable():
        raise ValueError("显示名须为 1-40 个字符的单行纯文本")
    return value


DisplayName = Annotated[
    str, Field(min_length=1, max_length=40), AfterValidator(validate_display_name)
]


def platform_display_name(platform: Platform | None) -> str:
    """默认名字只取平台，不读取主机名。"""
    return {
        Platform.WINDOWS: "Windows 电脑",
        Platform.MACOS: "Mac",
        Platform.LINUX: "Linux 电脑",
        None: "电脑",
    }[platform]


class InvalidInviteCodeError(ValueError):
    """粘贴的内容不是有效的邀请码。"""


class InvitePermissions(BaseModel):
    """邀请方允许加入方做什么；加入后就是邀请方对这台电脑的对端设置。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    allow_delegation: bool = False
    allow_model_borrowing: bool = False
    daily_quota: int = Field(default=DEFAULT_DAILY_TOKEN_QUOTA, ge=1, le=100_000_000)


class InviteCode(BaseModel):
    """邀请码里的全部内容。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    node_id: NodeId
    platform: Platform
    host: str
    port: int = Field(ge=1024, le=65535)
    token: str = Field(min_length=36, max_length=512, repr=False)
    permissions: InvitePermissions
    expires_at: datetime

    def encode(self) -> str:
        """编码成可以复制粘贴的一行文字。"""
        raw = self.model_dump_json().encode()
        return INVITE_CODE_PREFIX + base64.urlsafe_b64encode(raw).decode().rstrip("=")

    @classmethod
    def decode(cls, value: str) -> InviteCode:
        """解析粘贴进来的邀请码；首尾空白会被忽略。"""
        text = value.strip()
        if not text.startswith(INVITE_CODE_PREFIX):
            raise InvalidInviteCodeError("这不是 TunnelMinion 邀请码")
        body = text.removeprefix(INVITE_CODE_PREFIX)
        try:
            raw = base64.urlsafe_b64decode(body + "=" * (-len(body) % 4))
            return cls.model_validate_json(raw)
        except (binascii.Error, ValueError, ValidationError) as exc:
            raise InvalidInviteCodeError("邀请码不完整或已损坏") from exc


class InviteAcceptance(BaseModel):
    """`POST /v1/invites:accept` 的请求体：加入方报上自己的身份和地址。

    请求头 `Authorization: Bearer <邀请码里的令牌>`。
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    node_id: NodeId
    platform: Platform
    display_name: DisplayName | None = None
    host: str
    port: int = Field(ge=1024, le=65535)


class InviteAccepted(BaseModel):
    """`POST /v1/invites:accept` 成功时的响应体。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    inviter_node_id: NodeId
    inviter_display_name: DisplayName | None = None
    permissions: InvitePermissions
