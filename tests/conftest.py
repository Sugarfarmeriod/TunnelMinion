"""全部测试共用的夹具。"""

from __future__ import annotations

import importlib
import logging
from collections.abc import Generator, Iterator

import pytest
from tests.process_identity import OWN_PID_MODULES, OsWithFixedPid

from tunnelminion.model import secrets
from tunnelminion.runtime.logging import AUDIT_LOGGER_NAME

_LoggerState = tuple[int, tuple[logging.Handler, ...], bool, bool]
_DEFAULT_LOGGER_STATE: _LoggerState = (logging.NOTSET, (), True, False)
_LOGGING_BEFORE = pytest.StashKey[dict[str, _LoggerState]]()


def _logging_state() -> dict[str, _LoggerState]:
    """记录根日志器和项目日志器的级别、处理器、是否向上传递和是否禁用；pytest 自己的处理器不算。"""
    names = [""] + [
        name for name in logging.root.manager.loggerDict if name.startswith("tunnelminion")
    ]
    state: dict[str, _LoggerState] = {}
    for name in names:
        logger = logging.getLogger(name or None)
        handlers = tuple(
            handler
            for handler in logger.handlers
            if not type(handler).__module__.startswith("_pytest")
        )
        state[name] = (logger.level, handlers, logger.propagate, logger.disabled)
    return state


@pytest.hookimpl(wrapper=True)
def pytest_runtest_setup(item: pytest.Item) -> Generator[None]:
    item.stash[_LOGGING_BEFORE] = _logging_state()
    return (yield)


@pytest.hookimpl(wrapper=True)
def pytest_runtest_teardown(item: pytest.Item) -> Generator[None]:
    """测试改了全局日志配置却没还原时直接报错，避免后面依赖日志的测试随运行顺序时好时坏。"""
    result = yield
    before = item.stash.get(_LOGGING_BEFORE, None)
    if before is not None:
        changed = sorted(
            name or "root"
            for name, value in _logging_state().items()
            if value != before.get(name, _DEFAULT_LOGGER_STATE)
        )
        assert not changed, f"测试改动了全局日志配置且没有还原：{changed}"
    return result


@pytest.fixture(autouse=True)
def isolated_keyring_access(monkeypatch: pytest.MonkeyPatch) -> None:
    """每个测试用自己的钥匙串队列，缓存不会把上一个测试替换的密钥环带进来。"""
    monkeypatch.setattr(secrets, "_shared_access", secrets.KeyringAccess())


@pytest.fixture(autouse=True)
def unprivileged_host(monkeypatch: pytest.MonkeyPatch) -> None:
    """默认按普通账户运行：开发机即使是管理员或 root，用真实默认值的代码也不会走到托管模式。

    需要管理员分支的测试显式注入 `is_administrator` 或 `effective_uid`。
    """
    monkeypatch.setattr(
        "tunnelminion.platforms.windows.managed_system._native_windows_is_administrator",
        lambda: False,
    )
    monkeypatch.setattr(
        "tunnelminion.platforms.macos.managed_system.macos_effective_uid",
        lambda: 501,
    )


@pytest.fixture(autouse=True)
def fixed_own_pid(monkeypatch: pytest.MonkeyPatch) -> None:
    """产品代码判断“本进程”时看到固定的 `OWN_PID`，测试里的假进程号不会碰巧等于测试进程号。"""
    shim = OsWithFixedPid()
    for name in OWN_PID_MODULES:
        monkeypatch.setattr(importlib.import_module(name), "os", shim)


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
