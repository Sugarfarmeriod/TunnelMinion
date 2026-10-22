"""用户对服务的标记取值与标记身份格式；不依赖其他模块，存储层和 Agent 层都可引用。"""

from __future__ import annotations

import re
from enum import StrEnum

MARK_KEY_PATTERN = r"^(docker|python|program|port):[^\x00-\x1f\x7f/\\]{1,150}$"
_MARK_KEY = re.compile(MARK_KEY_PATTERN)


class ServiceMark(StrEnum):
    """用户对一个服务的选择。"""

    MINE = "mine"
    HIDDEN = "hidden"


def is_mark_key(value: str) -> bool:
    """标记身份必须是本模块定义的格式。"""
    return _MARK_KEY.fullmatch(value) is not None
