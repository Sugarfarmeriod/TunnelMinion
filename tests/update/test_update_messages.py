"""一键更新的错误码说明检查。

更新流程里能抛出的每个 `UpdateRejected`/`ReleaseFeedError` 错误码都必须在本机接口的
`_MESSAGES` 里有专门说明，不能掉到"现在不能更新，请稍后重试"的兜底文案；同一错误码在
网页 `UpdatePanel.tsx` 里的说法也必须和后端一致。
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

from tunnelminion.update.service import UnsupportedReason
from tunnelminion.web.update import _MESSAGES  # pyright: ignore[reportPrivateUsage]

_ROOT = Path(__file__).resolve().parents[2]
_UPDATE_PACKAGE = _ROOT / "src/tunnelminion/update"
_PANEL = _ROOT / "frontend/src/features/settings/UpdatePanel.tsx"
_ERROR_TYPES = {"UpdateRejected", "ReleaseFeedError"}


def _is_passthrough(node: ast.expr) -> bool:
    """`UpdateRejected(exc.code)` 转交上游错误码，`UpdateRejected(reason.value)` 来自枚举。"""
    return isinstance(node, ast.Attribute) and node.attr in {"code", "value"}


def _raised_codes() -> set[str]:
    codes: set[str] = set()
    unknown: list[str] = []
    for path in sorted(_UPDATE_PACKAGE.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id in _ERROR_TYPES
            ):
                continue
            arg = node.args[0] if node.args else None
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                codes.add(arg.value)
            elif arg is None or not _is_passthrough(arg):
                unknown.append(f"{path.name}:{node.lineno}")
    # 错误码必须写成字面量，否则这里核对不到
    assert unknown == [], f"错误码不是字符串字面量，无法核对说明：{unknown}"
    return codes | {reason.value for reason in UnsupportedReason}


def _frontend_map(name: str) -> dict[str, str]:
    source = _PANEL.read_text(encoding="utf-8")
    block = re.search(rf"const {name}\b[^=]*=\s*\{{(.*?)\n\}};", source, re.DOTALL)
    assert block is not None, f"UpdatePanel.tsx 里找不到 {name}"
    entries = dict(re.findall(r'(\w+):\s*"([^"]*)"', block.group(1)))
    assert entries, f"UpdatePanel.tsx 的 {name} 没解析出任何条目"
    return entries


def test_every_raised_code_has_dedicated_message() -> None:
    codes = _raised_codes()
    # 防止扫描范围失效后测试空跑
    assert {"network_unreachable", "github_rate_limited", "release_changed"} <= codes
    missing = sorted(codes - _MESSAGES.keys())
    assert missing == [], f"这些错误码没有专门说明，会显示兜底文案：{missing}"


def test_backend_and_frontend_wording_agree() -> None:
    frontend = {**_frontend_map("unsupportedText"), **_frontend_map("errorText")}
    shared = sorted(_MESSAGES.keys() & frontend.keys())
    assert "network_unreachable" in shared
    mismatched = {
        code: (_MESSAGES[code], frontend[code])
        for code in shared
        if frontend[code] != f"{_MESSAGES[code]}。"
    }
    assert mismatched == {}, f"同一错误码前后端说法不一致：{mismatched}"
