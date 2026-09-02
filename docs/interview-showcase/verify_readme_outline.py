"""离线验证面试展示 README 结构稿和证据插槽。"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent
OUTLINE_PATH = ROOT / "readme-outline.md"
REQUIRED_HEADINGS = (
    "## 1. 一句话定位",
    "## 2. 闭环动图",
    "## 3. 五步主流程",
    "## 4. 证据表",
    "## 5. 生命周期图",
    "## 6. 安全边界",
    "## 7. 降级矩阵",
    "## 8. 技术深挖链接",
    "## 9. 明确未交付",
    "## 10. 发布前替换清单",
)
REQUIRED_ASSET_IDS = {
    "recording-main-flow",
    "screenshot-overview",
    "screenshot-operation",
    "diagram-lifecycle",
    "diagram-security-approval",
    "claim-manifest",
    "evaluation-report",
}
REQUIRED_STATES = {
    "main-verified",
    "draft-pr-verified",
    "planned",
    "prohibited-claim",
}
REQUIRED_BOUNDARIES = {
    "目标节点本地批准",
    "请求节点、Coordinator 和模型不能自批",
    "Provider verify",
    "path/service verify",
    "owned resources",
    "不播放录屏并称为当前成功",
    "OpenSpec 3.1 已完成",
}
LINK_PATTERN = re.compile(r"\[[^\]]+\]\(([^)]+)\)")


def _ordered_headings(text: str) -> None:
    positions = [text.find(heading) for heading in REQUIRED_HEADINGS]
    if any(position < 0 for position in positions):
        missing = [
            heading
            for heading, position in zip(REQUIRED_HEADINGS, positions, strict=True)
            if position < 0
        ]
        raise ValueError(f"README 结构缺少章节：{missing}")
    if positions != sorted(positions):
        raise ValueError("README 章节顺序与展示叙事不一致")


def _validate_local_links(text: str) -> None:
    for raw_target in LINK_PATTERN.findall(text):
        if raw_target.startswith(("http://", "https://")):
            raise ValueError(f"结构稿不得依赖外部链接：{raw_target}")
        target = raw_target.split("#", 1)[0]
        if not target:
            continue
        resolved = (ROOT / target).resolve()
        if ROOT.resolve() not in resolved.parents or not resolved.is_file():
            raise ValueError(f"README 结构稿链接越界或不存在：{raw_target}")


def main() -> None:
    text = OUTLINE_PATH.read_text(encoding="utf-8")
    metadata = {
        "status: planned",
        "target: repository-root README.md",
        "publication: false",
        "stable-main-required: true",
    }
    if not metadata <= set(text.splitlines()):
        raise ValueError("README 结构稿缺少 planned / 非发布元数据")
    if "本文件不是根 README" not in text:
        raise ValueError("README 结构稿缺少非最终材料声明")

    _ordered_headings(text)
    _validate_local_links(text)

    missing_assets = REQUIRED_ASSET_IDS - set(re.findall(r"`([a-z0-9-]+)`", text))
    if missing_assets:
        raise ValueError(f"README 结构稿缺少资产插槽：{sorted(missing_assets)}")
    missing_states = REQUIRED_STATES - set(re.findall(r"`([a-z-]+)`", text))
    if missing_states:
        raise ValueError(f"README 结构稿缺少声明状态：{sorted(missing_states)}")
    missing_boundaries = {item for item in REQUIRED_BOUNDARIES if item not in text}
    if missing_boundaries:
        raise ValueError(f"README 结构稿缺少安全边界：{sorted(missing_boundaries)}")

    if re.search(r"<img\b|https?://", text, flags=re.IGNORECASE):
        raise ValueError("README 结构稿不得嵌入外部图片或链接")
    print(f"README 结构稿离线验证通过：{len(REQUIRED_HEADINGS)} 个章节")


if __name__ == "__main__":
    main()
