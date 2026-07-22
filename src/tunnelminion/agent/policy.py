"""在模型之前处理不需要推理的只读边界请求。"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict


class RequestPolicyDecision(BaseModel):
    """由确定性规则生成、无需调用模型或工具的最终决定。"""

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
            answer=(
                "API Key、token、密码、密钥和私钥属于秘密；TunnelMinion 的接口和导出"
                "不会返回完整凭据，因此不会提供该内容。"
            ),
        )
    if _WRITE_ACTION.search(question) and _WRITE_TARGET.search(question):
        return RequestPolicyDecision(
            code="write_operation_refused",
            answer=(
                "当前只读 MVP 未注册开放端口、重启服务或其他写操作工具；请求已被策略拒绝，"
                "没有执行任何写操作，也没有重启服务。"
            ),
        )
    return None


def _invalid_port(question: str) -> int | None:
    for pattern in _PORT_PATTERNS:
        for match in pattern.finditer(question):
            port = int(match.group("port"))
            if not 1 <= port <= 65535:
                return port
    return None
