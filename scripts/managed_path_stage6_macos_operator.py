"""由 macOS 普通用户读取 Keychain，并启动可见的交互式 sudo 验收。"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import cast

from scripts.managed_path_stage6_apply import (
    _assert_existing_identity,  # pyright: ignore[reportPrivateUsage]
)
from scripts.managed_path_stage6_identity import (
    _CONFIGS,  # pyright: ignore[reportPrivateUsage]
    _NETWORK_ID,  # pyright: ignore[reportPrivateUsage]
)

from tunnelminion.model.secrets import KeyringSecretStore


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("apply", "recover", "rollback"))
    parser.add_argument("barrier_id")
    args = parser.parse_args(argv)
    if len(args.barrier_id) != 32 or any(
        char not in "0123456789abcdef" for char in args.barrier_id
    ):
        raise SystemExit("barrier id 必须是 32 位小写十六进制")
    if sys.platform != "darwin":
        raise SystemExit("macOS Stage 6 operator 只能在 macOS 运行")
    effective_uid = cast(Callable[[], int], getattr(os, "geteuid", lambda: -1))
    if effective_uid() == 0:
        raise SystemExit("请以普通登录用户运行；脚本会显示系统 sudo 提示")
    store = _assert_existing_identity("macos", backend=KeyringSecretStore())
    name = f"wireguard/{_NETWORK_ID}/{_CONFIGS['macos'].node_id}"
    private_text = store.get(name)
    if private_text is None:
        raise SystemExit("macOS Stage 6 身份不可用")
    script = Path(__file__).with_name("run_managed_path_stage6_operator.sh").resolve()
    process = subprocess.Popen(
        ("/usr/bin/sudo", str(script), "--root", args.mode, args.barrier_id),
        stdin=subprocess.PIPE,
        text=True,
        encoding="utf-8",
    )
    if process.stdin is None:  # pragma: no cover - Popen 契约保护
        private_text = ""
        process.kill()
        raise SystemExit("无法建立 Stage 6 匿名身份管道")
    try:
        process.stdin.write(private_text + "\n")
        process.stdin.flush()
    finally:
        private_text = ""
        process.stdin.close()
    return process.wait()


if __name__ == "__main__":
    raise SystemExit(main())
