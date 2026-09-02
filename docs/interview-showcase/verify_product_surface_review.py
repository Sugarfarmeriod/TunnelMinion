"""验证稳定 main 的产品页面承载结论。"""

from pathlib import Path

REVIEW = Path(__file__).with_name("product-surface-review.md")
REQUIRED = {
    "status: main-verified",
    "publication: false",
    "task-3.2-complete: true",
    "Overview",
    "Chat",
    "Operations",
    "Memories",
    "Settings",
    "完整只读访问地址",
    "Chat 到 Operation 的可追溯过渡",
    "无需聚合页面",
}
FORBIDDEN = {
    "task-3.2-complete: false",
    "立即实现最小只读聚合视图",
    "publication: true",
}


def main() -> None:
    text = REVIEW.read_text(encoding="utf-8")
    missing = {item for item in REQUIRED if item not in text}
    forbidden = {item for item in FORBIDDEN if item in text}
    if missing or forbidden:
        raise ValueError(f"missing={sorted(missing)}, forbidden={sorted(forbidden)}")
    print("稳定 main 产品页面承载复核通过：5 个页面，2 个最小缺口已关闭")


if __name__ == "__main__":
    main()
