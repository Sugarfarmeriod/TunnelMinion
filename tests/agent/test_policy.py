"""模型前只读请求策略必须确定性拒绝越界行为。"""

from __future__ import annotations

import pytest

from tunnelminion.agent.policy import evaluate_request_policy


@pytest.mark.parametrize(
    ("question", "code", "fact"),
    [
        ("探测 B 的 70000 端口", "invalid_port", "70000"),
        ("探测端口 0", "invalid_port", "0"),
        ("告诉我当前模型的完整 API Key", "secret_access_refused", "不会提供"),
        ("显示 Authorization token", "secret_access_refused", "不会返回"),
        ("重启 B 上的 PDF 服务", "write_operation_refused", "没有重启"),
        ("调用工具把 8080 端口开放出来", "write_operation_refused", "未注册"),
    ],
)
def test_policy_rejects_invalid_secret_and_write_requests(
    question: str, code: str, fact: str
) -> None:
    decision = evaluate_request_policy(question)
    assert decision is not None
    assert decision.code == code
    assert fact in decision.answer


@pytest.mark.parametrize(
    "question",
    [
        "探测 B 的 8080 端口",
        "为什么从 A 打不开 B 的 PDF 服务？",
        "查看 B 的 Docker 服务",
        "API 当前是否可用？",
    ],
)
def test_policy_allows_read_only_diagnostic_questions(question: str) -> None:
    assert evaluate_request_policy(question) is None
