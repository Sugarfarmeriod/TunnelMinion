"""在模型之前处理不需要推理的只读边界请求。"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict

SECRET_ACCESS_REFUSAL = (
    "这个我不能提供：密码、API Key、令牌、私钥这些都属于秘密，"
    "TunnelMinion 不会读取，也不会显示出来。"
    "你可以问我：某个服务为什么打不开、某个端口被哪个程序占着、两台电脑之间连不连得通。"
)
WRITE_OPERATION_REFUSAL = (
    "这件事我不能直接去做：删除文件、关防火墙、改系统设置、执行任意命令都不在我能做的范围里。"
    "我能做的是先把问题查清楚；如果是容器停了或脚本退出了，我会提出修法，"
    "由你在地图上点感叹号批准后再执行。你可以说：“帮我看看某某服务为什么打不开，能修就修”。"
)
OFF_TOPIC_REFUSAL = (
    "这个问题超出了我的范围：我只负责查看这几台电脑上的服务和网络状况，"
    "不写文章、不写代码，也不回答一般知识问题。你可以问我：这台电脑上跑着哪些服务、"
    "某个网页为什么打不开、另一台电脑连得上吗。"
)


class RequestPolicyDecision(BaseModel):
    """请求把关后无需调用主模型或工具的最终决定。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    code: str
    answer: str


_PORT_PATTERNS = (
    re.compile(r"(?<!\d)(?P<port>\d{1,6})\s*(?:号)?端口"),
    re.compile(r"端口\s*(?P<port>\d{1,6})(?!\d)"),
)
_SECRET_NAME = re.compile(
    r"api[\s_-]*key|authorization|access[\s_-]*token|完整\s*token|密码|私钥|密钥",
    re.IGNORECASE,
)
_SECRET_READ = re.compile(r"告诉|查看|读取|显示|给我|导出|返回|是什么|多少|完整", re.IGNORECASE)
_WRITE_ACTION = re.compile(r"开放|放行|重启|停止|删除|修改|写入|执行|启动", re.IGNORECASE)
_WRITE_TARGET = re.compile(
    r"端口|服务|容器|docker|防火墙|配置|文件|命令|shell|进程",
    re.IGNORECASE,
)
_WRITE_COMMAND = re.compile(
    r"^(?:(?:请(?:你)?|帮我|麻烦(?:你)?|调用工具|直接|立即)\s*)*"
    rf"(?:{_WRITE_ACTION.pattern}|(?:把|将).*(?:{_WRITE_ACTION.pattern}))",
    re.IGNORECASE,
)
_DIAGNOSTIC_REQUEST = re.compile(
    r"为什么|为何|原因|^(?:请(?:你)?|帮我)?\s*(?:检查|查看|查一下|分析|解释|诊断|核对)"
)


def evaluate_request_policy(question: str) -> RequestPolicyDecision | None:
    """识别无须交给模型的非法参数、秘密读取和写操作请求。"""
    invalid_port = _invalid_port(question)
    if invalid_port is not None:
        return RequestPolicyDecision(
            code="invalid_port",
            answer=(
                f"端口 {invalid_port} 超出有效范围 1-65535，参数校验已拒绝请求，没有发起网络连接。"
            ),
        )
    if _SECRET_NAME.search(question) and _SECRET_READ.search(question):
        return RequestPolicyDecision(
            code="secret_access_refused",
            answer=SECRET_ACCESS_REFUSAL,
        )
    # 诊断问题交给只读 Agent 理解，写工具权限仍由注册表和 Runtime 拒绝。
    if (
        _WRITE_COMMAND.match(question.lstrip())
        and _WRITE_TARGET.search(question)
        and not _DIAGNOSTIC_REQUEST.search(question)
    ):
        return RequestPolicyDecision(
            code="write_operation_refused",
            answer=WRITE_OPERATION_REFUSAL,
        )
    return None


def _invalid_port(question: str) -> int | None:
    for pattern in _PORT_PATTERNS:
        for match in pattern.finditer(question):
            port = int(match.group("port"))
            if not 1 <= port <= 65535:
                return port
    return None
