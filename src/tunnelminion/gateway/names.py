"""本机显示名配置：默认取系统里的电脑名，用户可以改。"""

import os
import socket
import threading
import time
from pathlib import Path
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, ValidationError

from tunnelminion.domain.invites import DisplayName, platform_display_name
from tunnelminion.domain.tools import Platform


class NodeNameConfiguration(BaseModel):
    """供邀请和地图共用的本机名字。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    display_name: DisplayName


NODE_NAME_FILE = "node-name.json"
# 同一个进程里的几个请求同时保存名字时排队写；不同进程之间靠唯一临时文件加原子替换。
_WRITE_LOCK = threading.Lock()
# Windows 上目标文件正被别的读写占着时替换会报 PermissionError，稍等再试。
_REPLACE_ATTEMPTS = 5
_REPLACE_RETRY_SECONDS = 0.05


def _read_saved(path: Path) -> str | None:
    """读已保存的名字；文件不存在返回 None。正被替换的那一刻读不到时稍等再读。"""
    attempt = 1
    while True:
        try:
            return NodeNameConfiguration.model_validate_json(
                path.read_text(encoding="utf-8")
            ).display_name
        except FileNotFoundError:
            return None
        except PermissionError:
            if attempt >= _REPLACE_ATTEMPTS:
                raise
            attempt += 1
            time.sleep(_REPLACE_RETRY_SECONDS)


def _replace(temporary: Path, path: Path, expected: str) -> None:
    attempt = 1
    while True:
        try:
            os.replace(temporary, path)
            return
        except PermissionError:
            if attempt >= _REPLACE_ATTEMPTS:
                if _read_saved(path) == expected:
                    return
                raise
            attempt += 1
            time.sleep(_REPLACE_RETRY_SECONDS)


def save_node_name(root: Path, name: str) -> str:
    """验证后原子保存显示名；内容没变就不写。

    每次写入用自己的临时文件再原子替换，并发保存不会互相踩同一个临时文件，也不会留下临时文件。
    Windows 上替换一直被占用时，磁盘上已经是同样的名字就算保存成功，否则把错误抛给调用方。
    """
    value = NodeNameConfiguration(display_name=name)
    root.mkdir(parents=True, exist_ok=True)
    path = root / NODE_NAME_FILE
    with _WRITE_LOCK:
        if _read_saved(path) == value.display_name:
            return value.display_name
        temporary = root / f".{NODE_NAME_FILE}.{os.getpid()}.{uuid4().hex}.tmp"
        try:
            temporary.write_text(value.model_dump_json(), encoding="utf-8")
            _replace(temporary, path, value.display_name)
        finally:
            temporary.unlink(missing_ok=True)
    return value.display_name


def system_display_name(platform: Platform) -> str:
    """取系统里的电脑名，去掉 `.local` 之类的域名后缀；取不到或不合法时退回平台名。"""
    try:
        name = socket.gethostname().split(".", 1)[0].strip()
        return NodeNameConfiguration(display_name=name).display_name
    except (OSError, ValidationError):
        return platform_display_name(platform)


def load_node_name(root: Path, platform: Platform, *, persist_default: bool = True) -> str:
    """首次使用时保存系统电脑名。

    旧版本保存的平台默认名（如“Windows 电脑”）不是用户起的，同样换成系统电脑名，
    免得几台同类电脑在地图上同名。
    """
    saved = _read_saved(root / NODE_NAME_FILE)
    if saved is not None and saved != platform_display_name(platform):
        return saved
    default = system_display_name(platform)
    return save_node_name(root, default) if persist_default else default
