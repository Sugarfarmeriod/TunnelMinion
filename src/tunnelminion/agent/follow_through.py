"""模型准备收尾时的一次确定性查漏：关键的下一步还没做，就提醒它再走一步。

只看用户问题和本轮工具结果里的结构化字段，不读工具结果里的文字说明，也不替模型决定修法；
提醒只说缺了哪一步，做不做、怎么做仍由模型按证据决定，修复仍要主人批准。
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from pydantic import JsonValue

from tunnelminion.tools.contracts import (
    ToolExecutionRequest,
    ToolExecutionResult,
    ToolExecutionStatus,
)

# 提醒消息的固定开头；评测靠它统计提醒次数。
FOLLOW_THROUGH_MARK = "收尾前查漏（程序生成）："

# 用户明确要修；巡检自动提问也带“能修的话提出修法”。只说“打不开”不算要修。
_REPAIR_REQUEST = re.compile(
    r"修|重启|拉起|重新(?:跑|运行|启动)|propose_repair|\bfix|\brepair|\brestart",
    re.IGNORECASE,
)

_LISTENER_STEP = (
    "还没有用 list_network_listeners 核对所选服务的连接入口；程序要用这次的监听结果确认入口，"
    "请先调用它。"
)
_REPAIR_STEP = (
    "用户要修，本轮检查结果里有容器、脚本或程序没在运行，但还没有提出修法。请按剧本把下一步做完："
    "是容器而还没读日志，先用 read_container_logs；是脚本或程序而还没查启动记录，先用 "
    "list_launch_records。查明能用固定修法解决时，用 propose_repair 提出修法交给主人批准；"
    "日志显示重启解决不了、没有启动记录，或者没在运行的不是用户问的服务，就照实说明，不要硬提。"
)


def wants_repair(question: str) -> bool:
    """用户这次是否明确要修。"""
    return bool(_REPAIR_REQUEST.search(question))


def _items(output: JsonValue, key: str) -> Iterable[dict[str, JsonValue]]:
    if not isinstance(output, dict):
        return ()
    items = output.get(key)
    if not isinstance(items, list):
        return ()
    return (item for item in items if isinstance(item, dict))


def _container_down(item: dict[str, JsonValue]) -> bool:
    status = item.get("status")
    if isinstance(status, str):
        return not status.startswith("Up")
    state = item.get("state")
    return isinstance(state, str) and state != "running"


def shows_not_running(
    results: Iterable[tuple[ToolExecutionRequest, ToolExecutionResult]],
) -> bool:
    """本轮成功的检查里，是否有容器、脚本或程序明确没在运行。"""
    for request, result in results:
        if result.status is not ToolExecutionStatus.SUCCESS:
            continue
        output = result.output
        if request.tool_name == "list_docker_services" and any(
            _container_down(item) for item in _items(output, "items")
        ):
            return True
        if request.tool_name == "read_container_logs" and any(
            item.get("running") is False for item in _items(output, "containers")
        ):
            return True
        if request.tool_name == "list_launch_records" and any(
            item.get("running") is False for item in _items(output, "records")
        ):
            return True
    return False


def missing_steps(
    question: str,
    results: list[tuple[ToolExecutionRequest, ToolExecutionResult]],
    *,
    check_listener: bool,
    can_propose: bool,
) -> tuple[str, ...]:
    """模型想收尾时还缺的关键步骤；空元组表示不用提醒。"""
    called = {request.tool_name for request, _ in results}
    steps: list[str] = []
    if check_listener and "list_network_listeners" not in called:
        steps.append(_LISTENER_STEP)
    if (
        can_propose
        and "propose_repair" not in called
        and wants_repair(question)
        and shows_not_running(results)
    ):
        steps.append(_REPAIR_STEP)
    return tuple(steps)


def reminder(steps: tuple[str, ...]) -> str:
    """一次性提醒的正文，只由程序生成，不含工具结果里的文字。"""
    return FOLLOW_THROUGH_MARK + "".join(steps) + "做完再回答；确实做不了就照实说明原因。"
