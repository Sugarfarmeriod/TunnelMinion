"""清理更早版本在 macOS 上留下的本机签名钥匙串。

更早的版本在 `runtime start` 时生成过一张本机自签名证书，放在
`~/.tunnelminion/code-signing/tunnelminion-signing.keychain-db`，并把这个钥匙串加进了当前用户的
钥匙串搜索列表。没有 Apple 开发者证书的程序，钥匙串按程序指纹授权，自签名解决不了换包弹框，
所以现在不再签名，启动时把这一项清掉：`security delete-keychain` 删掉这个钥匙串文件并把它从搜索
列表里移除，再删掉整个目录。只动这一个路径，不碰搜索列表里的其他钥匙串。
"""

from __future__ import annotations

import logging
import shutil
import subprocess
import sys
from collections.abc import Callable, Sequence
from pathlib import Path

logger = logging.getLogger(__name__)

SECURITY = "/usr/bin/security"
LEGACY_SIGNING_KEYCHAIN = "tunnelminion-signing.keychain-db"
_COMMAND_TIMEOUT_SECONDS = 30.0


def _run(command: Sequence[str]) -> bool:
    try:
        completed = subprocess.run(
            list(command), check=False, capture_output=True, timeout=_COMMAND_TIMEOUT_SECONDS
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return completed.returncode == 0


def legacy_signing_directory(home: Path | None = None) -> Path:
    return (home or Path.home()) / ".tunnelminion" / "code-signing"


def remove_legacy_signing(
    *,
    home: Path | None = None,
    platform_name: str | None = None,
    run: Callable[[Sequence[str]], bool] = _run,
) -> bool:
    """有旧的签名钥匙串就清掉，返回是否清理过；任何失败都只记日志，不影响启动。

    `delete-keychain` 失败而钥匙串文件还在时保留目录，下次启动再试，免得搜索列表里留下一个指向
    已删除文件的条目。
    """
    if (platform_name or sys.platform) != "darwin":
        return False
    directory = legacy_signing_directory(home)
    if not directory.is_dir():
        return False
    keychain = directory / LEGACY_SIGNING_KEYCHAIN
    removed = run((SECURITY, "delete-keychain", str(keychain)))
    if not removed and keychain.exists():
        logger.warning("旧的本机签名钥匙串没能删掉，下次启动再试")
        return False
    shutil.rmtree(directory, ignore_errors=True)
    logger.info("已清理旧的本机签名钥匙串")
    return True
