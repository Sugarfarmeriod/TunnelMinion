"""TunnelMinion 跨平台开发质量门禁入口。"""

from __future__ import annotations

import argparse
import subprocess
import sys
from collections.abc import Sequence


def run(command: Sequence[str]) -> None:
    """运行一条质量命令，并在失败时立即停止。"""
    subprocess.run(command, check=True)


def format_code() -> None:
    """格式化 Python 文件并应用安全的 lint 修复。"""
    run(("ruff", "format", "."))
    run(("ruff", "check", "--fix", "."))


def lint() -> None:
    """检查格式与静态 lint 规则。"""
    run(("ruff", "format", "--check", "."))
    run(("ruff", "check", "."))


def typecheck() -> None:
    """运行严格的静态类型检查。"""
    run(("pyright",))


def test() -> None:
    """运行确定性单元测试套件。"""
    run(("pytest",))


def all_checks() -> None:
    """运行与持续集成一致的全部检查。"""
    lint()
    typecheck()
    test()


COMMANDS = {
    "all": all_checks,
    "format": format_code,
    "lint": lint,
    "test": test,
    "typecheck": typecheck,
}


def main(argv: Sequence[str] | None = None) -> int:
    """解析并执行指定的质量命令。"""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=COMMANDS)
    args = parser.parse_args(argv)
    COMMANDS[args.command]()
    return 0


if __name__ == "__main__":
    sys.exit(main())
