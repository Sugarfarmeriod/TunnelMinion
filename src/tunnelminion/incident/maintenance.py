"""事件库后台清理：按保留规则分批删除，删完后把空间还给磁盘。"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable
from contextlib import suppress
from datetime import UTC, datetime

from tunnelminion.incident.storage import SQLiteIncidentStore

logger = logging.getLogger(__name__)

# 启动后先清一遍，之后每小时清一次；两批之间让出一小会儿，观察和网页读写不用排长队。
MAINTENANCE_INTERVAL_SECONDS = 3600.0
MAINTENANCE_PAUSE_SECONDS = 0.05


async def maintain_incident_store(
    store: SQLiteIncidentStore,
    stop: asyncio.Event,
    *,
    clock: Callable[[], datetime] | None = None,
    interval_seconds: float = MAINTENANCE_INTERVAL_SECONDS,
    pause_seconds: float = MAINTENANCE_PAUSE_SECONDS,
) -> None:
    """一直运行到 `stop`：每轮分批清理，再按需整理文件；某轮失败只记日志，下一轮再试。"""
    now = clock or (lambda: datetime.now(UTC))
    while not stop.is_set():
        try:
            await _maintain_once(store, stop, now, pause_seconds)
        except Exception as exc:
            # 只记异常类型和栈，不记可能带路径或数据的异常正文。
            logger.error(
                "事件库清理失败，下一轮再试",
                exc_info=(RuntimeError, RuntimeError(type(exc).__name__), exc.__traceback__),
            )
        with suppress(TimeoutError):
            await asyncio.wait_for(stop.wait(), timeout=interval_seconds)


async def _maintain_once(
    store: SQLiteIncidentStore,
    stop: asyncio.Event,
    now: Callable[[], datetime],
    pause_seconds: float,
) -> None:
    total = 0
    while not stop.is_set():
        deleted = await asyncio.to_thread(store.prune_batch, now=now())
        if deleted == 0:
            break
        total += deleted
        await asyncio.sleep(pause_seconds)
    if stop.is_set():
        return
    reclaimed = await asyncio.to_thread(store.reclaim_space)
    if total or reclaimed:
        logger.info("事件库清理删除 %d 行，%s整理文件", total, "已" if reclaimed else "未")
