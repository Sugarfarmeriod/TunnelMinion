"""按问题和所选服务挑出给模型看的工具；只在本次允许的集合内收窄，从不扩大。"""

from __future__ import annotations

import re
from dataclasses import dataclass

from pydantic import BaseModel, ConfigDict, Field

REQUEST_MORE_TOOLS = "request_more_tools"
MIN_TOOL_LIMIT = 3
MAX_TOOL_LIMIT = 12

# 每个诊断工具“什么时候用”，交给模型时接在原说明后面；两个平台共用同一份。
TOOL_USAGE: dict[str, str] = {
    "list_docker_services": (
        "问到容器、Docker、compose、镜像，或服务是容器时，先用它看容器是否在跑。"
    ),
    "read_container_logs": "容器停了、反复重启或网页没反应时，读最后几十行日志找原因。",
    "list_network_listeners": (
        "问端口、网页打不开、某个程序有没有在听时用；服务是脚本或普通程序时先用它。"
    ),
    "probe_service_reachability": "程序在听，但要确认这台电脑能不能连上某个地址和端口时用。",
    "get_process_summary": "问进程、内存、CPU 或“哪个程序”时用。",
    "list_launch_records": "Python 脚本退出了、想知道能不能按原来的方式重新拉起时用。",
    "get_wireguard_status": "只在问到 WireGuard、隧道、组网时用。",
    "get_node_summary": "问这台电脑整体状态、模型、有哪些工具时用。",
    "propose_repair": "已经查明容器停了或脚本退出了、需要修时用；只生成待批准的修复。",
}

# 认不出话题或需要截断时的基础顺序：越靠前越常用。
_BASE_ORDER = (
    "list_network_listeners",
    "list_docker_services",
    "get_process_summary",
    "probe_service_reachability",
    "read_container_logs",
    "list_launch_records",
    "propose_repair",
    "get_node_summary",
    "get_wireguard_status",
)


@dataclass(frozen=True)
class _Topic:
    name: str
    pattern: re.Pattern[str]
    tools: tuple[str, ...]


_TOPICS = (
    _Topic(
        "container",
        re.compile(r"容器|docker|compose|镜像|orbstack|\bimage"),
        (
            "list_docker_services",
            "read_container_logs",
            "list_network_listeners",
            "probe_service_reachability",
        ),
    ),
    _Topic(
        "script",
        re.compile(r"脚本|python|\.py\b|启动记录|\bscript"),
        ("list_network_listeners", "list_launch_records", "get_process_summary"),
    ),
    _Topic(
        "port-web",
        re.compile(
            r"端口|网页|网址|网站|监听|访问|连不上|打不开|localhost|https?\b|\bport|\bweb|\burl"
        ),
        ("list_network_listeners", "probe_service_reachability"),
    ),
    _Topic(
        "process",
        re.compile(r"进程|内存|cpu|占用|卡顿|很卡|哪个程序|\bprocess|\bmemory"),
        ("get_process_summary", "list_network_listeners"),
    ),
    _Topic(
        "network",
        re.compile(r"wireguard|\bwg\b|隧道|组网|\bpeer|\btunnel"),
        ("get_wireguard_status", "get_node_summary"),
    ),
    _Topic(
        "overview",
        re.compile(
            r"概况|整体|总体|状态怎么样|情况怎么样|有哪些服务|什么服务|模型|overview|summary"
        ),
        ("get_node_summary", "list_network_listeners", "list_docker_services"),
    ),
    _Topic(
        "repair",
        re.compile(
            r"挂了|打不开|用不了|停了|退出|报错|崩|坏了|不正常|修|重启|拉起|恢复"
            r"|\bdown\b|\bcrash|\bfix|\brestart|\brepair"
        ),
        ("propose_repair", "list_network_listeners"),
    ),
)
_KIND_TOPICS = {"docker": "container", "python": "script"}
# 要修但看不出是容器还是脚本时，两份排查剧本的工具都留下，但不加分，免得挤掉修法本身。
_PLAYBOOK_TOOLS = ("list_docker_services", "read_container_logs", "list_launch_records")
_KNOWN_TOOLS = frozenset(_BASE_ORDER)


class ToolSelectionSettings(BaseModel):
    """挑工具的开关和给小模型的工具上限；上限留空表示只按话题挑、不截断。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    focus: bool = True
    max_tools: int | None = Field(default=None, ge=MIN_TOOL_LIMIT, le=MAX_TOOL_LIMIT)


class ToolSelection(BaseModel):
    """一次提问的挑选结果；visible 总是 allowed 的子集，保持 allowed 的原有顺序。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    allowed: tuple[str, ...]
    visible: tuple[str, ...]
    topics: tuple[str, ...]

    @property
    def hidden(self) -> tuple[str, ...]:
        """被藏起来、可以通过 request_more_tools 恢复的工具。"""
        shown = set(self.visible)
        return tuple(name for name in self.allowed if name not in shown)


def detect_topics(question: str, application_kind: str | None = None) -> tuple[str, ...]:
    """只用用户问题和所选服务类型认话题，不读工具结果。"""
    text = question.lower()
    matched = {topic.name for topic in _TOPICS if topic.pattern.search(text)}
    if application_kind in _KIND_TOPICS:
        matched.add(_KIND_TOPICS[application_kind])
    return tuple(topic.name for topic in _TOPICS if topic.name in matched)


def select_tools(
    question: str,
    allowed: tuple[str, ...],
    *,
    settings: ToolSelectionSettings,
    application_kind: str | None = None,
    required: tuple[str, ...] = (),
) -> ToolSelection:
    """在允许的工具里挑出本次给模型看的一组；认不出话题时全部保留。"""
    if not settings.focus:
        return ToolSelection(allowed=allowed, visible=allowed, topics=())
    topics = detect_topics(question, application_kind)
    scores: dict[str, int] = {}
    for topic in _TOPICS:
        if topic.name in topics:
            for name in topic.tools:
                scores[name] = scores.get(name, 0) + 1
    if "repair" in topics and "container" not in topics and "script" not in topics:
        for name in _PLAYBOOK_TOOLS:
            scores.setdefault(name, 0)
    # 规则不认识的工具和委派工具认不出用途，一律不藏，也不占上限。
    uncounted = {name for name in allowed if name not in _KNOWN_TOOLS}
    keep = uncounted | {name for name in allowed if name in required}
    candidates = [name for name in allowed if not topics or name in scores or name in keep]
    counted = [name for name in candidates if name not in uncounted]
    if settings.max_tools is not None and len(counted) > settings.max_tools:
        ranked = sorted(
            counted,
            key=lambda name: (name not in keep, -scores.get(name, 0), _BASE_ORDER.index(name)),
        )
        chosen = uncounted | set(ranked[: max(settings.max_tools, len(keep - uncounted))])
        candidates = [name for name in candidates if name in chosen]
    return ToolSelection(allowed=allowed, visible=tuple(candidates), topics=topics)


def usage_description(name: str, description: str) -> str:
    """在原工具说明后补一句“什么时候用”。"""
    usage = TOOL_USAGE.get(name)
    return f"{description}什么时候用：{usage}" if usage else description


def request_more_tools_description(hidden: tuple[str, ...]) -> str:
    """列出被藏起来的工具和用途，让模型知道它们存在。"""
    listing = "；".join(f"{name}：{TOOL_USAGE.get(name, '')}".rstrip("：") for name in hidden)
    return (
        "本次只列出了和问题相关的工具。需要的工具不在列表里时调用本工具，之后每一轮都能看到本次允许的"
        "全部工具；它不执行检查、不产生证据、不扩大权限。还可以用的工具：" + listing
    )[:1000]
