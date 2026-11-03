"""有界轮转 runtime 日志测试。"""

from __future__ import annotations

import logging
import logging.config
from pathlib import Path
from typing import cast

import pytest

from tunnelminion.runtime import logging as runtime_logging
from tunnelminion.runtime.logging import runtime_log_config, write_runtime_event


def test_runtime_log_config_uses_bounded_file_handler_without_access_output(
    tmp_path: Path,
) -> None:
    path = tmp_path / "runtime" / "local.log"
    config = runtime_log_config(path)
    handlers = cast(dict[str, dict[str, object]], config["handlers"])
    loggers = cast(dict[str, dict[str, object]], config["loggers"])
    handler = handlers["runtime"]
    access = loggers["uvicorn.access"]
    assert handler["class"] == "logging.handlers.RotatingFileHandler"
    assert handler["maxBytes"] == runtime_logging.MAX_RUNTIME_LOG_BYTES
    assert handler["backupCount"] == runtime_logging.RUNTIME_LOG_BACKUPS
    assert access["level"] == "WARNING"
    assert path.exists()


def test_runtime_log_config_keeps_audit_info_but_not_other_app_info(tmp_path: Path) -> None:
    path = tmp_path / "gateway.log"
    config = runtime_log_config(path)
    audit = logging.getLogger(runtime_logging.AUDIT_LOGGER_NAME)
    # 配置会改动 root 和 uvicorn、审计这几个全局日志器；测完原样恢复，不影响后面的测试。
    touched = [
        logging.getLogger(),
        *(logging.getLogger(name) for name in cast(dict[str, object], config["loggers"])),
    ]
    saved = [
        (logger, logger.level, list(logger.handlers), logger.propagate, logger.disabled)
        for logger in touched
    ]
    try:
        logging.config.dictConfig(config)
        audit.info("为委派自动借用：测试")
        logging.getLogger("tunnelminion.gateway.api").info("普通信息")
        for logger in touched:
            for handler in logger.handlers:
                handler.flush()
        text = path.read_text(encoding="utf-8")
    finally:
        for logger, level, handlers, propagate, disabled in saved:
            for handler in logger.handlers:
                if handler not in handlers:
                    handler.close()
            logger.handlers[:] = handlers
            logger.setLevel(level)
            logger.propagate = propagate
            logger.disabled = disabled
    assert "为委派自动借用：测试" in text
    assert "普通信息" not in text


def test_runtime_event_rotates_and_writes_only_stable_code(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "gateway.log"
    monkeypatch.setattr(runtime_logging, "MAX_RUNTIME_LOG_BYTES", 30)
    monkeypatch.setattr(runtime_logging, "RUNTIME_LOG_BACKUPS", 2)
    for _index in range(5):
        write_runtime_event(path, "component_start_failed")
    combined = "".join(item.read_text(encoding="utf-8") for item in tmp_path.glob("gateway.log*"))
    assert "component_start_failed" in combined
    assert "token" not in combined
    assert len(tuple(tmp_path.glob("gateway.log*"))) <= 3
