"""逐组件有界轮转与零秘密运行日志。"""

from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path

from tunnelminion.runtime.profile import prepare_private_directory, restrict_file_permissions

MAX_RUNTIME_LOG_BYTES = 5_000_000
RUNTIME_LOG_BACKUPS = 3


def runtime_log_config(path: Path) -> dict[str, object]:
    """生成 uvicorn/root 共用的有界文件日志配置，不启用访问日志。"""
    prepare_private_directory(path.parent)
    path.touch(exist_ok=True)
    restrict_file_permissions(path)
    formatter = {
        "format": "%(asctime)s %(levelname)s %(name)s %(message)s",
    }
    handler = {
        "class": "logging.handlers.RotatingFileHandler",
        "filename": str(path),
        "maxBytes": MAX_RUNTIME_LOG_BYTES,
        "backupCount": RUNTIME_LOG_BACKUPS,
        "encoding": "utf-8",
        "formatter": "runtime",
    }
    return {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {"runtime": formatter},
        "handlers": {"runtime": handler},
        "loggers": {
            "uvicorn": {"handlers": ["runtime"], "level": "INFO", "propagate": False},
            "uvicorn.error": {
                "handlers": ["runtime"],
                "level": "INFO",
                "propagate": False,
            },
            "uvicorn.access": {
                "handlers": ["runtime"],
                "level": "WARNING",
                "propagate": False,
            },
        },
        "root": {"handlers": ["runtime"], "level": "WARNING"},
    }


def write_runtime_event(path: Path, code: str) -> None:
    """只写允许的稳定事件码，不接受异常或远端正文。"""
    prepare_private_directory(path.parent)
    handler = RotatingFileHandler(
        path,
        maxBytes=MAX_RUNTIME_LOG_BYTES,
        backupCount=RUNTIME_LOG_BACKUPS,
        encoding="utf-8",
    )
    try:
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
        record = logging.LogRecord(
            name="tunnelminion.runtime",
            level=logging.ERROR,
            pathname="",
            lineno=0,
            msg=code,
            args=(),
            exc_info=None,
        )
        handler.emit(record)
    finally:
        handler.close()
    restrict_file_permissions(path)
