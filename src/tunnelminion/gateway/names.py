"""本机显示名配置，不依赖网关地址或系统主机名。"""

from pathlib import Path

from pydantic import BaseModel, ConfigDict

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


def load_node_name(root: Path, platform: Platform, *, persist_default: bool = True) -> str:
    """首次使用时保存平台默认名。"""
    path = root / "node-name.json"
    if path.exists():
        return NodeNameConfiguration.model_validate_json(
            path.read_text(encoding="utf-8")
        ).display_name
    default = platform_display_name(platform)
    return save_node_name(root, default) if persist_default else default
