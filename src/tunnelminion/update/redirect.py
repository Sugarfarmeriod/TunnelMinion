"""`runtime start` 转交给当前版本：换过包以后，从旧的解包目录启动也会起来新版。"""

from __future__ import annotations

import os
import subprocess
import sys
from collections.abc import Callable, Sequence
from pathlib import Path

from tunnelminion.runtime.install import RuntimePackageInstaller, node_install_root
from tunnelminion.update.apply import NO_REDIRECT_ENV

Runner = Callable[..., subprocess.CompletedProcess[bytes]]


def forward_to_current_version(
    data_dir: Path,
    argv: Sequence[str],
    *,
    executable: Path | None = None,
    frozen: bool | None = None,
    install_root: Path | None = None,
    runner: Runner = subprocess.run,
) -> int | None:
    """版本指针指向别的版本时，用那个版本执行同一条命令并返回它的退出码；否则返回 None。"""
    if os.environ.get(NO_REDIRECT_ENV) == "1":
        return None
    if not (bool(getattr(sys, "frozen", False)) if frozen is None else frozen):
        return None
    current = (executable or Path(sys.executable)).resolve()
    try:
        installer = RuntimePackageInstaller(install_root or node_install_root(data_dir), data_dir)
        state = installer.load()
        if state.current_package_id is None:
            return None
        target = installer.executable(state.current_package_id)
    except (OSError, ValueError, KeyError):
        return None
    if not target.is_file() or target == current:
        return None
    print(f"这台电脑已经换到新版本，转交给 {target} 启动", file=sys.stderr)
    environment = dict(os.environ)
    environment[NO_REDIRECT_ENV] = "1"
    completed = runner((str(target), *argv), env=environment, check=False)
    return completed.returncode
