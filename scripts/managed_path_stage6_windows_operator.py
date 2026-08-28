"""让普通 Windows 用户把固定身份一次性转交给已批准的管理员进程。"""

from __future__ import annotations

import argparse
import ctypes
import multiprocessing.connection
import secrets
import subprocess
import sys
from pathlib import Path
from typing import cast

from scripts.managed_path_stage6_apply import (
    _assert_existing_identity,  # pyright: ignore[reportPrivateUsage]
)
from scripts.managed_path_stage6_identity import (
    _identity_secret_name,  # pyright: ignore[reportPrivateUsage]
)

_MAX_PUBLIC_OUTPUT = 64 * 1024


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
    name = _identity_secret_name("windows")
    private_text = store.get(name)
    if private_text is None:
        raise SystemExit("Windows Stage 6 身份不可用")
    pipe_name = rf"\\.\pipe\tunnelminion-stage6-{secrets.token_hex(16)}"
    listener = multiprocessing.connection.Listener(pipe_name, family="AF_PIPE", authkey=b"")
    try:
        script = Path(__file__).with_name("run_managed_path_stage6_operator.ps1")
        command = (
            f"$script = '{_quote_powershell(str(script))}'; "
            f"$pipe = '{_quote_powershell(pipe_name)}'; "
            "$arguments = @("
            "'-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "
            "('\"' + $script + '\"'), "
            f"'-Mode', '{mode}', '-BarrierId', '{barrier_id}', "
            "'-IdentityPipeName', $pipe"
            "); "
            "$process = Start-Process powershell.exe -Verb RunAs "
            "-ArgumentList $arguments -PassThru -Wait; "
            "exit $process.ExitCode"
        )
        print("正在打开 Windows UAC；请批准一次管理员运行。", flush=True)
        elevated = subprocess.Popen(
            (
                "powershell.exe",
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                command,
            )
        )
        connection = listener.accept()
        try:
            connection.send(private_text)
            try:
                result = connection.recv()
            except (EOFError, OSError) as exc:
                elevated_returncode = elevated.wait()
                raise SystemExit(
                    "Windows Stage 6 管理员子流程未回传结果 "
                    f"(exit code {elevated_returncode})"
                ) from exc
        finally:
            connection.close()
            private_text = ""
        elevated_returncode = elevated.wait()
        if not isinstance(result, dict):
            raise SystemExit("Windows Stage 6 管理员结果管道无效")
        public_result = cast(dict[object, object], result)
        returncode = public_result.get("returncode")
        stdout = public_result.get("stdout")
        stderr = public_result.get("stderr")
        if (
            set(public_result) != {"returncode", "stdout", "stderr"}
            or not isinstance(returncode, int)
            or not isinstance(stdout, str)
            or not isinstance(stderr, str)
            or len(stdout) > _MAX_PUBLIC_OUTPUT
            or len(stderr) > _MAX_PUBLIC_OUTPUT
        ):
            raise SystemExit("Windows Stage 6 管理员结果管道无效")
        if stdout:
            print(stdout, end="" if stdout.endswith("\n") else "\n")
        if stderr:
            print(
                stderr,
                end="" if stderr.endswith("\n") else "\n",
                file=sys.stderr,
            )
        return returncode if elevated_returncode == 0 else elevated_returncode
    finally:
        listener.close()
        private_text = ""


def _quote_powershell(value: str) -> str:
    """转义 PowerShell 单引号字符串，不把值解释成命令。"""
    return value.replace("'", "''")


def _run_elevated(mode: str, barrier_id: str, pipe_name: str) -> int:
    if not _is_admin():
        raise SystemExit("Windows Stage 6 管理员子流程必须使用已提升令牌")
    connection = multiprocessing.connection.Client(pipe_name, family="AF_PIPE", authkey=b"")
    private_text = connection.recv()
    if not isinstance(private_text, str):
        connection.send(
            {
                "returncode": 1,
                "stdout": "",
                "stderr": "Windows Stage 6 身份管道内容无效。\n",
            }
        )
        connection.close()
        return 1
    action = {
        "apply": "--apply",
        "recover": "--recover",
        "rollback": "--rollback-create",
    }[mode]
    try:
        repo_root = Path(__file__).resolve().parent.parent
        python = repo_root / ".venv" / "Scripts" / "python.exe"
        if not python.is_file():
            raise RuntimeError(f"Project virtual-environment Python was not found: {python}")
        completed = subprocess.run(
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
            input=private_text + "\n",
            capture_output=True,
            text=True,
            encoding="utf-8",
        )
        if private_text in completed.stdout or private_text in completed.stderr:
            connection.send(
                {
                    "returncode": 1,
                    "stdout": "",
                    "stderr": "Windows Stage 6 管理员输出包含禁止的身份材料，已拒绝回传。\n",
                }
            )
            return 1
        connection.send(
            {
                "returncode": completed.returncode,
                "stdout": completed.stdout[-_MAX_PUBLIC_OUTPUT:],
                "stderr": completed.stderr[-_MAX_PUBLIC_OUTPUT:],
            }
        )
        return completed.returncode
    except Exception as exc:
        message = str(exc).replace(private_text, "<redacted>")
        connection.send(
            {
                "returncode": 1,
                "stdout": "",
                "stderr": (
                    "Windows Stage 6 管理员子流程异常："
                    f"{type(exc).__name__}: {message}\n"
                )[-_MAX_PUBLIC_OUTPUT:],
            }
        )
        return 1
    finally:
        private_text = ""
        connection.close()


def _is_admin() -> bool:
    windll = getattr(ctypes, "windll", None)
    return windll is not None and bool(windll.shell32.IsUserAnAdmin())


if __name__ == "__main__":
    raise SystemExit(main())
