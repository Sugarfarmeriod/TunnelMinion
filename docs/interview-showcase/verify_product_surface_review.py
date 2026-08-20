"""离线验证 PR #40 产品页面承载预审的证据边界。"""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parent
REVIEW_PATH = ROOT / "product-surface-review.md"
REQUIRED_METADATA = {
    "status: draft-pr-verified",
    "publication: false",
    "pull-request: 40",
    "source-head: 61398b76d01b3836dc6023f74b0ba3d17ef7cbb4",
    "task-3.2-complete: false",
}
REQUIRED_PAGES = {"Overview", "Chat", "Operations", "Memories", "Settings"}
REQUIRED_STAGES = {
    "设备、服务与状态入口",
    "只读诊断与证据",
    "候选、批准和执行状态",
    "验证、恢复与清理",
}
REQUIRED_HEADINGS = {
    "## 主流程承载结论",
    "## 已确认的候选缺口",
    "### 完整访问地址",
    "### Chat 到 Operation 的可追溯过渡",
    "## 聚合视图决策门",
}
REQUIRED_BOUNDARIES = {
    "完整访问地址未被当前服务摘要公开",
    "不能把端口冒充地址",
    "当前不规划、不实现最小只读聚合视图",
    "任务 3.2 保持未完成",
    "不是稳定 `main` 证据",
    "`accessibility` 是契约字段，页面未展示",
    "Chat 已显示 tool run ID 和 Evidence 引用",
}
FORBIDDEN_CLAIMS = {
    "status: main-verified",
    "publication: true",
    "task-3.2-complete: true",
    "PR #40 已经进入稳定 main",
    "任务 3.2 已完成",
    "立即实现最小只读聚合视图",
}


def _validate_text(text: str) -> None:
    lines = set(text.splitlines())

    missing_metadata = REQUIRED_METADATA - lines
    if missing_metadata:
        raise ValueError(f"产品承载预审缺少元数据：{sorted(missing_metadata)}")

    for label, required in (
        ("页面", REQUIRED_PAGES),
        ("故事阶段", REQUIRED_STAGES),
        ("章节", REQUIRED_HEADINGS),
        ("证据边界", REQUIRED_BOUNDARIES),
    ):
        missing = {item for item in required if item not in text}
        if missing:
            raise ValueError(f"产品承载预审缺少{label}：{sorted(missing)}")

    present_forbidden = {item for item in FORBIDDEN_CLAIMS if item in text}
    if present_forbidden:
        raise ValueError(f"产品承载预审包含越权声明：{sorted(present_forbidden)}")

    if "docs/questions/" in text:
        raise ValueError("产品承载预审不得引用禁止目录")


def _run_negative_regressions(text: str) -> None:
    missing_chat_gap = text.replace(
        "### Chat 到 Operation 的可追溯过渡",
        "### 被错误删除的追溯章节",
        1,
    )
    contradictory = (
        text
        + "\n结论：PR #40 已经进入稳定 main，任务 3.2 已完成，"
        + "立即实现最小只读聚合视图。\n"
    )
    for label, candidate in (
        ("删除 Chat→Operation 缺口章节", missing_chat_gap),
        ("追加越权完成与实现声明", contradictory),
    ):
        try:
            _validate_text(candidate)
        except ValueError:
            continue
        raise ValueError(f"负向回归未拒绝：{label}")


def main() -> None:
    text = REVIEW_PATH.read_text(encoding="utf-8")
    _validate_text(text)
    _run_negative_regressions(text)

    print("PR #40 产品页面承载预审离线验证通过：5 个页面、4 个主流程阶段、2 个负向回归")


if __name__ == "__main__":
    main()
