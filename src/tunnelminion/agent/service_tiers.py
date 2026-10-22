"""决定一个监听端口在首页上直接显示、放进"可能是服务"，还是不显示。

规则只看程序的来历和监听方式，不为任何具体程序或机器写特例。
"""

from __future__ import annotations

from enum import StrEnum

from tunnelminion.platforms.process_origin import (
    ProcessOrigin,
    is_interpreter,
    normalize_process_name,
)


class ServiceTier(StrEnum):
    """首页上的三档。"""

    SHOW = "show"
    REVIEW = "review"
    HIDE = "hide"


_WILDCARD_ADDRESSES = frozenset({"0.0.0.0", "::"})


def is_wildcard_address(address: str) -> bool:
    """监听所有网卡，意味着有意让别的电脑连。"""
    return address in _WILDCARD_ADDRESSES


def decide_tier(
    *,
    protocol: str,
    address: str,
    process_name: str | None,
    origin: ProcessOrigin | None,
    container_running: bool | None = None,
) -> ServiceTier:
    """按固定顺序决定分档。

    `container_running` 为 None 表示端口不属于任何容器。
    """
    if container_running is not None:
        return ServiceTier.SHOW if container_running else ServiceTier.HIDE
    if protocol != "tcp":
        # UDP 端口多是发现、DNS、组网等底层通信，不是用户会打开的服务。
        return ServiceTier.HIDE
    if process_name and normalize_process_name(process_name).startswith("tunnelminion"):
        return ServiceTier.HIDE
    if origin in {ProcessOrigin.TERMINAL, ProcessOrigin.USER_INSTALL}:
        return ServiceTier.SHOW
    if origin is None and is_interpreter(process_name):
        # 读不到来历（例如对端版本较旧）时，脚本解释器按用户脚本处理，与来历判断一致。
        return ServiceTier.SHOW
    if origin is ProcessOrigin.UNKNOWN:
        return ServiceTier.REVIEW
    if origin is ProcessOrigin.APP_SERVICE or origin is None:
        # 应用自启服务或读不到来历的程序：只有监听所有网卡时才值得让用户看一眼。
        return ServiceTier.REVIEW if is_wildcard_address(address) else ServiceTier.HIDE
    return ServiceTier.HIDE
