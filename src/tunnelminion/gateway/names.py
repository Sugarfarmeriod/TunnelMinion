"""本机显示名配置：默认取系统里的电脑名，用户可以改。"""

import socket
from pathlib import Path

from pydantic import BaseModel, ConfigDict, ValidationError

from tunnelminion.domain.invites import DisplayName, platform_display_name
from tunnelminion.domain.tools import Platform


class NodeNameConfiguration(BaseModel):
    """供邀请和地图共用的本机名字。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    display_name: DisplayName


def save_node_name(root: Path, name: str) -> str:
    """验证后原子保存显示名。"""
    value = NodeNameConfiguration(display_name=name)
    root.mkdir(parents=True, exist_ok=True)
    path = root / "node-name.json"
    temporary = path.with_suffix(".tmp")
    temporary.write_text(value.model_dump_json(), encoding="utf-8")
    temporary.replace(path)
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
    path = root / "node-name.json"
    if path.exists():
        saved = NodeNameConfiguration.model_validate_json(
            path.read_text(encoding="utf-8")
        ).display_name
        if saved != platform_display_name(platform):
            return saved
    default = system_display_name(platform)
    return save_node_name(root, default) if persist_default else default
