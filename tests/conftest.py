"""全部测试共用的夹具。"""

from __future__ import annotations

import logging
from collections.abc import Iterator

import pytest

from tunnelminion.model import secrets
from tunnelminion.runtime.logging import AUDIT_LOGGER_NAME


@pytest.fixture(autouse=True)
def isolated_keyring_access(monkeypatch: pytest.MonkeyPatch) -> None:
    """每个测试用自己的钥匙串队列，缓存不会把上一个测试替换的密钥环带进来。"""
    monkeypatch.setattr(secrets, "_shared_access", secrets.KeyringAccess())


@pytest.fixture
def audit_log(monkeypatch: pytest.MonkeyPatch) -> Iterator[list[str]]:
    """直接从审计通道收集留痕，不受别的测试套用过的运行日志配置影响。"""
    messages: list[str] = []

    class _Collect(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            messages.append(record.getMessage())

    audit = logging.getLogger(AUDIT_LOGGER_NAME)
    monkeypatch.setattr(audit, "disabled", False)
    monkeypatch.setattr(audit, "level", logging.INFO)
    handler = _Collect(logging.INFO)
    audit.addHandler(handler)
    try:
        yield messages
    finally:
        audit.removeHandler(handler)
