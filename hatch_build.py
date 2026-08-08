"""只在正式 wheel 中收集已经验真的唯一前端暂存目录。"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from hatchling.builders.hooks.plugin.interface import BuildHookInterface


class FrontendWheelBuildHook(BuildHookInterface):
    """避免开发态 editable 安装依赖尚未生成的前端产物。"""

    def initialize(self, version: str, build_data: dict[str, Any]) -> None:
        """正式 wheel 缺少前端时失败；editable wheel 只指向源码。"""
        if version != "standard":
            return
        frontend = Path(self.root) / "build" / "frontend-dist"
        if not (frontend / "index.html").is_file():
            raise FileNotFoundError("正式 wheel 构建缺少 build/frontend-dist/index.html")
        build_data["force_include"][str(frontend)] = "tunnelminion/web/ui"
