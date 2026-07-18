"""扫描仓库与评估材料中的可重放秘密和私钥。"""

from __future__ import annotations

import argparse
import re
import subprocess
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class SecretPattern:
    """一个高置信秘密格式。"""

    name: str
    expression: re.Pattern[str]


@dataclass(frozen=True)
class Finding:
    """不包含匹配正文的秘密扫描结果。"""

    path: Path
    line: int
    pattern: str


PATTERNS = (
    SecretPattern(
        "private-key-pem",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    ),
    SecretPattern(
        "wireguard-private-key",
        re.compile(r"(?im)^\s*PrivateKey\s*=\s*[A-Za-z0-9+/]{42}="),
    ),
    SecretPattern("gateway-token", re.compile(r"tmn_[A-Za-z0-9_-]{30,}")),
    SecretPattern(
        "openai-style-key",
        re.compile(r"(?<![A-Za-z0-9_-])sk-[A-Za-z0-9_-]{16,}"),
    ),
    SecretPattern(
        "bearer-credential",
        re.compile(r"(?i)Bearer\s+[A-Za-z0-9._~+/-]{16,}"),
    ),
)

PLACEHOLDER_MARKERS = (
    "test",
    "fake",
    "example",
    "placeholder",
    "must-not-leak",
    "forbidden",
    "should-not-be-here",
    "wrong-token",
    "secret-value",
    "abcdefghijklmnop",
    "with-more-than-32-characters",
)

SKIPPED_PARTS = {".git", ".venv", ".runtime", "__pycache__"}
SKIPPED_SUFFIXES = {".db", ".pyc", ".pyo", ".png", ".jpg", ".jpeg", ".gif"}


def repository_files(root: Path) -> tuple[Path, ...]:
    """列出 Git 已跟踪和未忽略的未跟踪文件。"""
    completed = subprocess.run(
        ("git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"),
        cwd=root,
        check=True,
        capture_output=True,
    )
    return tuple(
        root / Path(value.decode("utf-8")) for value in completed.stdout.split(b"\0") if value
    )


def scan_files(paths: Iterable[Path]) -> tuple[Finding, ...]:
    """扫描文本文件；已知显式测试占位符不作为真实秘密报告。"""
    findings: list[Finding] = []
    for path in paths:
        if SKIPPED_PARTS.intersection(path.parts) or path.suffix.lower() in SKIPPED_SUFFIXES:
            continue
        try:
            content = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        for line_number, line in enumerate(content.splitlines(), start=1):
            lowered = line.lower()
            for pattern in PATTERNS:
                if pattern.expression.search(line) and not any(
                    marker in lowered for marker in PLACEHOLDER_MARKERS
                ):
                    findings.append(Finding(path, line_number, pattern.name))
    return tuple(findings)


def main(argv: Sequence[str] | None = None) -> int:
    """运行扫描，只输出位置和类型，不回显可能的秘密正文。"""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    args = parser.parse_args(argv)
    root = args.root.resolve()
    findings = scan_files(repository_files(root))
    for finding in findings:
        relative = finding.path.relative_to(root)
        print(f"{relative}:{finding.line}: {finding.pattern}")
    if findings:
        print(f"安全扫描失败：发现 {len(findings)} 个疑似秘密；正文已隐藏。")
        return 1
    print("安全扫描通过：未发现 API key、网关 token、Bearer 凭据或私钥。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
