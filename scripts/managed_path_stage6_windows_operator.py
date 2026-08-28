"""让普通 Windows 用户把固定身份一次性转交给已批准的管理员进程。"""

from __future__ import annotations

import argparse
import ctypes
import multiprocessing.connection
import secrets
import subprocess
import sys
from pathlib import Path

from scripts.managed_path_stage6_apply import (
    _assert_existing_identity,  # pyright: ignore[reportPrivateUsage]
)
from scripts.managed_path_stage6_identity import (
    _CONFIGS,  # pyright: ignore[reportPrivateUsage]
    _NETWORK_ID,  # pyright: ignore[reportPrivateUsage]
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("apply", "recover", "rollback"))
    parser.add_argument("barrier_id")
    parser.add_argument("--serve", action="store_true")
    parser.add_argument("--elevated", action="store_true")
    parser.add_argument("--pipe-name")
    args = parser.parse_args(argv)
    if sys.platform != "win32":
        raise SystemExit("Windows Stage 6 operator 只能在 Windows 运行")
    if len(args.barrier_id) != 32 or any(
        char not in "0123456789abcdef" for char in args.barrier_id
    ):
        raise SystemExit("barrier id 必须是 32 位小写十六进制")
    if args.serve:
        if args.elevated or args.pipe_name:
            raise SystemExit("身份服务模式参数无效")
        return _serve_identity(args.mode, args.barrier_id)
    if not args.elevated or not args.pipe_name:
        raise SystemExit("管理员 Stage 6 进程缺少一次性身份管道")
    return _run_elevated(args.mode, args.barrier_id, args.pipe_name)


def _serve_identity(mode: str, barrier_id: str) -> int:
    store = _assert_existing_identity("windows")
    name = f"wireguard/{_NETWORK_ID}/{_CONFIGS['windows'].node_id}"
    private_text = store.get(name)
    if private_text is None:
        raise SystemExit("Windows Stage 6 身份不可用")
    pipe_name = rf"\\.\pipe\tunnelminion-stage6-{secrets.token_hex(16)}"
    listener = multiprocessing.connection.Listener(pipe_name, family="AF_PIPE", authkey=b"")
    try:
        script = Path(__file__).with_name("run_managed_path_stage6_operator.ps1")
        print("请在新的管理员 PowerShell 窗口中执行：", flush=True)
        print(
            f"& '{script}' -Mode {mode} -BarrierId {barrier_id} -IdentityPipeName '{pipe_name}'",
            flush=True,
        )
        print("保持本窗口开启，等待管理员窗口连接一次性身份管道。", flush=True)
        connection = listener.accept()
        try:
            connection.send(private_text)
        finally:
            connection.close()
            private_text = ""
        return 0
    finally:
        listener.close()
        private_text = ""


def _run_elevated(mode: str, barrier_id: str, pipe_name: str) -> int:
    if not _is_admin():
        raise SystemExit("Windows Stage 6 管理员子流程必须使用已提升令牌")
    connection = multiprocessing.connection.Client(pipe_name, family="AF_PIPE", authkey=b"")
    try:
        private_text = connection.recv()
    finally:
        connection.close()
    if not isinstance(private_text, str):
        raise SystemExit("Windows Stage 6 身份管道内容无效")
    action = {
        "apply": "--apply",
        "recover": "--recover",
        "rollback": "--rollback-create",
    }[mode]
    repo_root = Path(__file__).resolve().parent.parent
    python = repo_root / ".venv" / "Scripts" / "python.exe"
    if not python.is_file():
        raise SystemExit(f"Project virtual-environment Python was not found: {python}")
    process = subprocess.Popen(
        [
            str(python),
            "-m",
            "scripts.managed_path_stage6_apply",
            "--platform",
            "windows",
            "--barrier-id",
            barrier_id,
            "--identity-stdin",
            action,
        ],
        stdin=subprocess.PIPE,
        text=True,
        encoding="utf-8",
    )
    if process.stdin is None:
        private_text = ""
        process.kill()
        raise SystemExit("无法建立 Windows 匿名身份管道")
    try:
        process.stdin.write(private_text + "\n")
        process.stdin.flush()
    finally:
        private_text = ""
        process.stdin.close()
    return process.wait()


def _is_admin() -> bool:
    windll = getattr(ctypes, "windll", None)
    return windll is not None and bool(windll.shell32.IsUserAnAdmin())


if __name__ == "__main__":
    raise SystemExit(main())
